"""The scan pipeline: prepare → map → navigate → validate → summarize.

A HYBRID two-LLM loop:

  1. NAVIGATE — a fast tool-calling model drives a read-only filesystem loop
     (list_dir / read_file / grep) scoped to the repo. It walks the code map,
     traces untrusted input toward dangerous sinks, and records *candidate*
     findings. Wide net; over-reporting is fine.

  2. VALIDATE — a stronger model judges each candidate against the real code
     slice (re-read from disk, ground truth) and is prompted to *refute* it:
     confirm reachability, score confidence, set severity, write repro. What it
     can't stand up is culled (and kept with a reason, never silently dropped).
     This is what keeps the false-positive flood out.

The scan is READ-ONLY: it never writes the repo, opens a PR, or patches.
Isolation is via an ephemeral docker jail by default (``sandbox="auto"``); a
guarded in-process path is the fallback. Both LLMs are injected by the caller —
see ``refutescan.providers``.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .fileaccess import LocalFileAccess, SandboxFileAccess
from .models import ScanConfig, ScanResult, Verdict
from .providers import JudgeFactory, NavigatorFactory
from .safety import GIT_ALLOWED_PROTOCOLS, within_allowed_roots
from .vulns import SEVERITIES, VALID_CLASSES

logger = logging.getLogger(__name__)

ProgressFn = Callable[[str], None]


# ── Public entry point ──────────────────────────────────────────────────────────

def scan(source: str, *,
         navigator_factory: NavigatorFactory,
         judge_factory: JudgeFactory,
         branch: str = "",
         config: Optional[ScanConfig] = None,
         progress: Optional[ProgressFn] = None) -> ScanResult:
    """Scan a repo and return validated findings.

    source             a local directory path, or a git URL to clone.
    navigator_factory  () -> tool-capable chat model (the wide-net pass).
    judge_factory      () -> judge(prompt, schema) -> instance (refute pass).
    branch             git branch to clone (ignored for local paths).
    config             ScanConfig; defaults if omitted.
    progress           optional callback invoked with each phase label.
    """
    cfg = config or ScanConfig()
    source = (source or "").strip()
    if not source:
        raise ValueError("source is required (a local path or a git URL)")
    source_kind = "git" if looks_like_git_url(source) else "path"

    def _phase(label: str) -> None:
        if progress:
            try:
                progress(label)
            except Exception:
                logger.debug("[refutescan] progress callback raised", exc_info=True)

    workdir: Optional[Path] = None
    sandbox = None
    try:
        from .sandbox.docker import DockerSandbox, sandbox_enabled
        use_sandbox = sandbox_enabled(cfg)
        _phase("Preparing source" + (" (sandboxed)" if use_sandbox else ""))

        if use_sandbox:
            sandbox = DockerSandbox(cfg)
            if source_kind == "git":
                _phase("Cloning repo in an isolated container")
                sandbox.start_git(source, branch)
            else:
                sandbox.start_local(_resolve_local_path(source, cfg))
            fa = SandboxFileAccess(sandbox)
        else:
            root, workdir = _prepare_source(source, source_kind, branch, cfg)
            fa = LocalFileAccess(root, cfg)

        _phase("Mapping the codebase")
        code_map, files = fa.build_map()
        if not files:
            raise RuntimeError("No scannable source files found under the target "
                               "(checked common source extensions). Point at a code repo.")

        sb_tag = " · sandboxed" if use_sandbox else ""
        _phase(f"Scanning {len(files)} source files with the navigator{sb_tag}")
        candidates = _navigate(fa, files, code_map, navigator_factory, cfg)
        logger.info("[refutescan] navigator produced %d candidate(s) (sandbox=%s)",
                    len(candidates), use_sandbox)

        _phase(f"Validating {len(candidates)} candidate(s)")
        findings, culled = _validate(fa, candidates, judge_factory, cfg)

        _phase("Summarizing")
        summary = _summarize(code_map, findings, culled, len(candidates))

        return ScanResult(
            code_map=code_map,
            findings=findings,
            culled=culled,
            summary=summary,
            candidate_count=len(candidates),
            sandboxed=use_sandbox,
        )
    finally:
        # Tear down the sandbox (container + any clone volume) if we created one.
        # Keyed on `sandbox`, NOT the file-access wrapper: start_git/start_local
        # can raise after allocating the volume/container but before the wrapper
        # exists, and that half-built sandbox still has resources to reclaim.
        if sandbox is not None:
            try:
                sandbox.stop()
            except Exception:
                logger.warning("[refutescan] sandbox teardown failed")
        # Only ever remove a directory WE created (a host clone). Never touch a
        # local path the caller pointed us at.
        if workdir is not None:
            try:
                shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                logger.warning("[refutescan] failed to clean workdir %s", workdir)


# ── Source helpers ──────────────────────────────────────────────────────────────

def derive_title(source: str) -> str:
    s = (source or "").rstrip("/")
    base = s.rsplit("/", 1)[-1] or s
    base = base[:-4] if base.endswith(".git") else base
    return (base[:90] or "Untitled scan")


def looks_like_git_url(source: str) -> bool:
    s = (source or "").strip()
    return (s.startswith(("http://", "https://", "git@", "ssh://", "git://"))
            or s.endswith(".git"))


def _prepare_source(source: str, source_kind: str, branch: str,
                    cfg: ScanConfig) -> Tuple[Path, Optional[Path]]:
    """Return (repo_root, workdir_to_clean). workdir is None for a local path.

    Used only by the in-process fallback — the docker path clones in-container.
    """
    if source_kind == "git":
        workdir = Path(tempfile.mkdtemp(prefix="refutescan-"))
        # Hardened clone: no submodules (kills the submodule+symlink hook-exec CVE
        # class, e.g. CVE-2024-32002), repo-supplied hooks/fsmonitor neutralized,
        # and a protocol allowlist so ext::/fd:: transports can't run shell.
        cmd = ["git",
               "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false",
               "clone", "--depth", "1", "--no-recurse-submodules", "--no-tags"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [source, str(workdir / "repo")]
        clone_env = {**os.environ,
                     "GIT_ALLOW_PROTOCOL": cfg.git_allowed_protocols or GIT_ALLOWED_PROTOCOLS,
                     "GIT_TERMINAL_PROMPT": "0"}
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=cfg.clone_timeout, env=clone_env)
        except subprocess.TimeoutExpired:
            shutil.rmtree(workdir, ignore_errors=True)
            raise RuntimeError(f"git clone timed out after {cfg.clone_timeout}s — the repo may be "
                               "unreachable.")
        if proc.returncode != 0:
            shutil.rmtree(workdir, ignore_errors=True)
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or ["unknown error"]
            raise RuntimeError(f"git clone failed: {tail[0][:200]}")
        return (workdir / "repo"), workdir

    return _resolve_local_path(source, cfg), None


def _resolve_local_path(source: str, cfg: ScanConfig) -> Path:
    """Validate + resolve a local scan target (exists, dir, within allowed roots)."""
    p = Path(os.path.expanduser(source)).resolve()
    if not p.exists():
        raise RuntimeError(f"Path not found: {p}")
    if not p.is_dir():
        raise RuntimeError(f"Not a directory: {p}")
    if not within_allowed_roots(p, cfg.allowed_roots):
        allowed = ", ".join(str(r) for r in cfg.allowed_roots) or "(none configured)"
        raise RuntimeError(
            f"Path is outside the allowed scan roots ({allowed}). Set "
            "ScanConfig.allowed_roots to permit it.")
    return p


# ── Navigator (tool-calling loop) ───────────────────────────────────────────────

def _navigate(fa, files: List[str], code_map: dict,
              navigator_factory: NavigatorFactory, cfg: ScanConfig) -> List[Dict[str, Any]]:
    """The navigator walks the repo via read-only tools and records candidates.

    Never raises — a navigator failure degrades to an empty candidate list
    (logged), so the scan still completes.
    """
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
    from langchain_core.tools import tool

    findings: List[Dict[str, Any]] = []
    file_set = set(files)

    @tool
    def list_dir(path: str = "") -> str:
        """List files and subdirectories under a path (relative to the repo root)."""
        return fa.list_dir(path)

    @tool
    def read_file(path: str, start_line: int = 1, max_lines: int = 200) -> str:
        """Read a source file (relative to repo root), returning numbered lines.
        Use start_line/max_lines to page through large files."""
        return fa.read_file(path, start_line, max_lines)

    @tool
    def grep(pattern: str, path_contains: str = "") -> str:
        """Regex-search across the mapped source files. Optionally restrict to files
        whose path contains `path_contains`. Returns file:line: matched-line."""
        return fa.grep(pattern, files, path_contains)

    @tool
    def record_finding(vuln_class: str, title: str, file: str, line: int,
                       source: str, sink: str, snippet: str, rationale: str,
                       severity_guess: str = "medium") -> str:
        """Record a candidate vulnerability. Call once per distinct issue.
        vuln_class: one of the classes from the brief. file: repo-relative path.
        line: the line of the dangerous sink. source: where untrusted input enters.
        sink: the dangerous operation. rationale: the source->sink data flow."""
        vc = (vuln_class or "").strip().lower()
        if vc not in VALID_CLASSES:
            vc = "injection" if "inj" in vc else (vc or "other")
        sev = (severity_guess or "medium").strip().lower()
        if sev not in SEVERITIES:
            sev = "medium"
        try:
            ln = int(line)
        except (TypeError, ValueError):
            ln = 0
        rec = {
            "vuln_class": vc,
            "title": (title or "Untitled finding").strip()[:200],
            "file": (file or "").strip().lstrip("/"),
            "line": ln,
            "source": (source or "").strip()[:600],
            "sink": (sink or "").strip()[:600],
            "snippet": (snippet or "").strip()[:1200],
            "rationale": (rationale or "").strip()[:1500],
            "severity_guess": sev,
        }
        key = (rec["file"], rec["line"], rec["vuln_class"])
        if any((f["file"], f["line"], f["vuln_class"]) == key for f in findings):
            return "duplicate — already recorded"
        if rec["file"] and rec["file"] not in file_set:
            return f"warning: {rec['file']} is not a mapped source file — recorded anyway"
        findings.append(rec)
        return f"recorded candidate #{len(findings)}: {rec['title']}"

    tools = [list_dir, read_file, grep, record_finding]
    tool_map = {t.name: t for t in tools}

    try:
        llm = navigator_factory().bind_tools(tools)
    except Exception:
        logger.exception("[refutescan] navigator LLM init failed")
        return []

    messages: List[Any] = [SystemMessage(content=_NAV_SYSTEM),
                           HumanMessage(content=_nav_brief(code_map, files))]

    deadline = time.monotonic() + cfg.nav_deadline
    for turn in range(cfg.nav_max_iters):
        if time.monotonic() > deadline:
            logger.info("[refutescan] navigator hit %.0fs deadline at turn %d (%d candidate(s))",
                        cfg.nav_deadline, turn, len(findings))
            break
        try:
            ai: "AIMessage" = llm.invoke(messages)
        except Exception as e:
            logger.warning("[refutescan] navigator invoke failed on turn %d: %s", turn, e)
            break
        messages.append(ai)
        tool_calls = getattr(ai, "tool_calls", None) or []
        if not tool_calls:
            break  # model is done
        for tc in tool_calls:
            name = tc.get("name")
            args = tc.get("args") or {}
            fn = tool_map.get(name)
            if fn is None:
                result = f"error: unknown tool {name}"
            else:
                try:
                    result = fn.invoke(args)
                except Exception as e:
                    result = f"error: {type(e).__name__}: {e}"
            messages.append(ToolMessage(content=str(result)[:6000],
                                        tool_call_id=tc.get("id", "")))
        if len(findings) >= cfg.max_candidates:
            logger.info("[refutescan] navigator hit candidate cap (%d)", cfg.max_candidates)
            break

    return findings[:cfg.max_candidates]


_NAV_SYSTEM = (
    "You are a senior application security researcher auditing a code repository for "
    "exploitable vulnerabilities. You have read-only tools: list_dir, read_file, grep, and "
    "record_finding.\n\n"
    "Your method:\n"
    "1. Use the code map and file list to find where UNTRUSTED INPUT enters the app "
    "(HTTP handlers/routes, request params, headers, CLI args, file uploads, message queues).\n"
    "2. Follow that data toward DANGEROUS SINKS — SQL/command/template execution, file paths, "
    "outbound requests, deserializers, response rendering, auth/session checks.\n"
    "3. When a concrete source→sink data flow looks exploitable, call record_finding ONCE for it, "
    "citing the exact file and the line of the sink.\n\n"
    "Hunt these classes: SQL/command/template injection, broken authz/IDOR, SSRF, path traversal, "
    "unsafe deserialization, hardcoded secrets, weak crypto/randomness, XSS, and auth/session flaws.\n\n"
    "Be thorough — read the files that handle input, grep for risky function calls. Cast a wide net: "
    "it is fine to record a candidate you are only moderately sure about (a separate validation step "
    "will confirm or reject each one). But do NOT report style nits, formatting, or non-security "
    "issues. Record the SINK line precisely; a wrong line wastes the validator. When you have "
    "reviewed the input-handling code paths, stop calling tools and reply with a one-line summary."
)


def _nav_brief(code_map: dict, files: List[str]) -> str:
    langs = ", ".join(f"{k}×{v}" for k, v in (code_map.get("languages") or {}).items())
    parts = [
        f"Repository: {code_map.get('root_name')}",
        f"Source files: {code_map.get('source_files_scanned')} "
        f"({code_map.get('total_loc')} LOC){'  [file list truncated]' if code_map.get('truncated') else ''}",
        f"Languages: {langs or 'unknown'}",
    ]
    if code_map.get("entrypoints"):
        parts.append("Likely entrypoints: " + ", ".join(code_map["entrypoints"]))
    if code_map.get("manifests"):
        parts.append("Dependency manifests: " + ", ".join(code_map["manifests"][:10]))
    parts.append("\nScannable source files:\n" + "\n".join(files))
    parts.append("\nBegin the audit. Read input-handling code first, then trace toward sinks. "
                 "Record each candidate vulnerability with record_finding.")
    return "\n".join(parts)


# ── Validator (refute-first judge) ──────────────────────────────────────────────

def _validate(fa, candidates: List[Dict[str, Any]],
              judge_factory: JudgeFactory, cfg: ScanConfig) -> Tuple[List[dict], List[dict]]:
    """Judge each candidate on the real code slice. Returns (findings, culled)."""
    if not candidates:
        return [], []

    findings: List[dict] = []
    culled: List[dict] = []

    for cand in candidates[:cfg.max_candidates]:
        slice_text = fa.read_slice(cand.get("file", ""), cand.get("line", 0))
        try:
            verdict = _judge_one(cand, slice_text, judge_factory, cfg)
        except _FTimeout:
            culled.append({**cand, "cull_reason": "validation timed out", "confidence": 0.0})
            continue
        except Exception as e:
            logger.warning("[refutescan] judge failed for %s: %s", cand.get("file"), e)
            # Conservative: a judge failure does NOT auto-promote — cull with reason.
            culled.append({**cand, "cull_reason": f"validation error: {type(e).__name__}", "confidence": 0.0})
            continue

        enriched = {
            **cand,
            "confidence": verdict.get("confidence", 0.0),
            "severity": verdict.get("severity", cand.get("severity_guess", "medium")),
            "reachable": verdict.get("reachable", False),
            "reasoning": verdict.get("reasoning", ""),
            "repro": verdict.get("repro", ""),
            "recommendation": verdict.get("recommendation", ""),
        }
        if verdict.get("is_real"):
            findings.append(enriched)
        else:
            culled.append({**enriched, "cull_reason": verdict.get("reasoning") or "judged not exploitable"})

    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (sev_rank.get(f.get("severity"), 99), -float(f.get("confidence") or 0)))
    return findings, culled


def _judge_one(cand: Dict[str, Any], slice_text: str,
               judge_factory: JudgeFactory, cfg: ScanConfig) -> Dict[str, Any]:
    """One refute-first judge call, bounded by a hard timeout."""
    prompt = (
        "You are a skeptical senior application-security reviewer doing FALSE-POSITIVE TRIAGE on a "
        "candidate finding produced by an automated scanner. Your job is to REFUTE it unless the "
        "evidence is concrete. Default to is_real=false when the data flow is not clearly "
        "demonstrable in the code shown.\n\n"
        "CANDIDATE\n"
        f"- class: {cand.get('vuln_class')}\n"
        f"- title: {cand.get('title')}\n"
        f"- file: {cand.get('file')}  (sink ~line {cand.get('line')})\n"
        f"- claimed untrusted source: {cand.get('source')}\n"
        f"- claimed dangerous sink: {cand.get('sink')}\n"
        f"- scanner rationale: {cand.get('rationale')}\n\n"
        f"ACTUAL CODE (re-read from disk around the sink):\n```\n{slice_text}\n```\n\n"
        "Decide: is this a real, exploitable vulnerability? Confirm the untrusted source actually "
        "reaches the sink unsanitized. If sanitization, parameterization, an allowlist, or an auth "
        "check neutralizes it, mark is_real=false and say so. Be concrete and brief."
    )

    judge = judge_factory()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="refutescan-judge") as ex:
        resp: Verdict = ex.submit(judge, prompt, Verdict).result(timeout=cfg.judge_timeout)

    return {
        "is_real": bool(resp.is_real),
        "reachable": bool(resp.reachable),
        "confidence": max(0.0, min(1.0, float(resp.confidence))),
        "severity": resp.severity,
        "reasoning": resp.reasoning,
        "repro": resp.repro,
        "recommendation": resp.recommendation,
    }


# ── Summary (deterministic) ─────────────────────────────────────────────────────

def _summarize(code_map: dict, findings: List[dict], culled: List[dict],
               candidate_count: int) -> Dict[str, Any]:
    by_sev = {s: 0 for s in SEVERITIES}
    by_class: Dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity", "medium")] = by_sev.get(f.get("severity", "medium"), 0) + 1
        vc = f.get("vuln_class", "other")
        by_class[vc] = by_class.get(vc, 0) + 1

    max_sev = next((s for s in SEVERITIES if by_sev.get(s)), None)
    return {
        "total_findings": len(findings),
        "candidate_count": candidate_count,
        "culled_count": len(culled),
        "by_severity": by_sev,
        "by_class": by_class,
        "max_severity": max_sev,
        "files_scanned": code_map.get("source_files_scanned", 0),
        "total_loc": code_map.get("total_loc", 0),
        "languages": code_map.get("languages", {}),
    }
