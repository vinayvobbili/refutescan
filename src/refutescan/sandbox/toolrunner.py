#!/usr/bin/env python3
"""Read-only file tools, executed INSIDE the refutescan sandbox container.

The scanner's LLM orchestration runs on the host, but every file touch is
delegated here via `docker exec ... python /toolrunner.py <command>` with a JSON
args object on stdin and a JSON result on stdout. The container mounts only the
target repo at /repo (read-only) with --network none, so this code physically
cannot see the host filesystem — the _safe()/secret-denylist checks below are
defense-in-depth, not the only boundary.

Stdlib only (runs in a minimal python:alpine image). This mirrors the pure
file-access logic in refutescan; keep it in sync with safety.py / codemap.py.
"""

import fnmatch
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("REFUTESCAN_REPO_ROOT", os.environ.get("CODE_SEC_REPO_ROOT", "/repo"))).resolve()

# ── Bounds (mirror refutescan defaults) ─────────────────────────────────────────
_MAX_MAP_FILES = 400
_MAX_FILE_BYTES = 200_000
_MAX_READ_LINES = 600
_MAX_GREP_HITS = 80

_SOURCE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".kt", ".scala", ".swift", ".sh",
    ".bash", ".pl", ".pm", ".sql", ".html", ".vue", ".lua", ".groovy", ".tf",
}
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
    "site-packages", "target", ".idea", ".vscode", ".gradle", "bin", "obj",
    "coverage", ".tox", ".cache", "bower_components",
}
_MANIFESTS = {
    "requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "package.json",
    "go.mod", "pom.xml", "build.gradle", "Gemfile", "composer.json", "Cargo.toml",
    "pom.xml", "csproj",
}
_ENTRY_HINTS = {
    "app.py", "main.py", "manage.py", "wsgi.py", "asgi.py", "server.py",
    "index.js", "server.js", "app.js", "main.go", "main.rs", "index.php",
    "application.java",
}
_SECRET_DIR_NAMES = {
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".secrets", "secrets",
    ".git",
}
_SECRET_FILE_GLOBS = (
    "*.key", "*.pem", "*.age", "*.p12", "*.pfx", "*.keystore", "*.jks",
    ".env", ".env.*", "*.env", "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
    ".netrc", ".pgpass", ".htpasswd", "credentials", "*.secret", "*.secrets",
)


def _deny_secret(p: Path) -> None:
    try:
        rel = p.relative_to(ROOT)
    except ValueError:
        rel = p
    for part in rel.parts:
        if part in _SECRET_DIR_NAMES:
            raise ValueError(f"refusing to read sensitive path '{part}/'")
    for glob in _SECRET_FILE_GLOBS:
        if fnmatch.fnmatch(p.name, glob):
            raise ValueError(f"refusing to read sensitive file '{p.name}'")


def _safe(rel: str) -> Path:
    p = (ROOT / (rel or "").lstrip("/")).resolve()
    if ROOT != p and ROOT not in p.parents:
        raise ValueError("path escapes the repository root")
    _deny_secret(p)
    return p


def build_map() -> dict:
    langs: dict = {}
    manifests: list = []
    entrypoints: list = []
    source_files: list = []
    total_files = 0
    total_loc = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            total_files += 1
            ext = os.path.splitext(fn)[1].lower()
            full = Path(dirpath) / fn
            rel = str(full.relative_to(ROOT))
            if fn in _MANIFESTS or fn.endswith(".csproj"):
                manifests.append(rel)
            if fn in _ENTRY_HINTS:
                entrypoints.append(rel)
            if ext in _SOURCE_EXTS and len(source_files) < _MAX_MAP_FILES:
                source_files.append(rel)
                langs[ext] = langs.get(ext, 0) + 1
                try:
                    if full.stat().st_size <= _MAX_FILE_BYTES:
                        with open(full, "r", errors="ignore") as fh:
                            total_loc += sum(1 for _ in fh)
                except Exception:
                    pass
    code_map = {
        "root_name": ROOT.name,
        "total_files": total_files,
        "source_files_scanned": len(source_files),
        "truncated": len(source_files) >= _MAX_MAP_FILES,
        "total_loc": total_loc,
        "languages": dict(sorted(langs.items(), key=lambda kv: -kv[1])),
        "manifests": manifests[:30],
        "entrypoints": entrypoints[:30],
    }
    return {"map": code_map, "files": source_files}


def list_dir(path: str = "") -> str:
    p = _safe(path)
    if not p.is_dir():
        return f"error: not a directory: {path}"
    entries = []
    for child in sorted(p.iterdir()):
        if child.name in _SKIP_DIRS:
            continue
        entries.append(child.name + ("/" if child.is_dir() else ""))
    return "\n".join(entries[:300]) or "(empty)"


def read_file(path: str, start_line: int = 1, max_lines: int = 200) -> str:
    p = _safe(path)
    with open(p, "r", errors="ignore") as fh:
        lines = fh.readlines()
    start = max(1, int(start_line or 1))
    n = min(int(max_lines or 200), _MAX_READ_LINES)
    chunk = lines[start - 1: start - 1 + n]
    body = "".join(f"{start+i:>5}  {ln.rstrip()}\n" for i, ln in enumerate(chunk))
    return body[:_MAX_FILE_BYTES] or "(no lines in range)"


def grep(pattern: str, files: list, path_contains: str = "") -> str:
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return f"error: bad regex: {e}"
    hits: list = []
    for rel in files:
        if path_contains and path_contains not in rel:
            continue
        try:
            p = _safe(rel)
            with open(p, "r", errors="ignore") as fh:
                for i, ln in enumerate(fh, 1):
                    if rx.search(ln):
                        hits.append(f"{rel}:{i}: {ln.strip()[:200]}")
                        if len(hits) >= _MAX_GREP_HITS:
                            return "\n".join(hits) + "\n…(truncated)"
        except Exception:
            continue
    return "\n".join(hits) or "(no matches)"


def read_slice(path: str, line: int, ctx: int = 25) -> str:
    try:
        p = _safe(path)
        with open(p, "r", errors="ignore") as fh:
            lines = fh.readlines()
    except Exception as e:
        return f"<could not read {path}: {type(e).__name__}>"
    if line and line > 0:
        lo = max(0, line - ctx - 1)
        hi = min(len(lines), line + ctx)
    else:
        lo, hi = 0, min(len(lines), 2 * ctx)
    numbered = [f"{i+1:>5}  {lines[i].rstrip()}" for i in range(lo, hi)]
    return "\n".join(numbered)[:8000]


_COMMANDS = {
    "build_map": lambda a: build_map(),
    "list_dir": lambda a: {"result": list_dir(a.get("path", ""))},
    "read_file": lambda a: {"result": read_file(a.get("path", ""), a.get("start_line", 1), a.get("max_lines", 200))},
    "grep": lambda a: {"result": grep(a.get("pattern", ""), a.get("files", []), a.get("path_contains", ""))},
    "read_slice": lambda a: {"result": read_slice(a.get("path", ""), a.get("line", 0), a.get("ctx", 25))},
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in _COMMANDS:
        print(json.dumps({"error": f"unknown command; expected one of {list(_COMMANDS)}"}))
        return 2
    cmd = sys.argv[1]
    raw = sys.stdin.read()
    try:
        args = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"bad json args: {e}"}))
        return 2
    try:
        out = _COMMANDS[cmd](args)
    except Exception as e:
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        return 1
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
