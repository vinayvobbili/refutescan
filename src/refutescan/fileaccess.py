"""File access behind one interface, two backends.

The navigator's tools and the validator's slice re-reads go through a
``FileAccess`` object, so the same scan logic runs either in-process (guarded
host) or via the docker sandbox without branching all over the pipeline.

  • ``LocalFileAccess``   — reads the host filesystem, confined by safe_path()
                            + the secret denylist (defense-in-depth fallback).
  • ``SandboxFileAccess`` — delegates every touch to the toolrunner inside the
                            locked-down container via the sandbox handle.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .codemap import SKIP_DIRS, build_map
from .models import ScanConfig
from .safety import safe_path


class LocalFileAccess:
    """In-process file access on the host, confined by safe_path() + denylist."""

    def __init__(self, root: Path, config: ScanConfig) -> None:
        self.root = root.resolve()
        self.cfg = config

    def build_map(self) -> Tuple[Dict[str, Any], List[str]]:
        return build_map(self.root, self.cfg.max_map_files, self.cfg.max_file_bytes)

    def list_dir(self, path: str = "") -> str:
        try:
            p = safe_path(self.root, path)
        except Exception as e:
            return f"error: {e}"
        if not p.is_dir():
            return f"error: not a directory: {path}"
        entries = []
        for child in sorted(p.iterdir()):
            if child.name in SKIP_DIRS:
                continue
            entries.append(child.name + ("/" if child.is_dir() else ""))
        return "\n".join(entries[:300]) or "(empty)"

    def read_file(self, path: str, start_line: int = 1, max_lines: int = 200) -> str:
        try:
            p = safe_path(self.root, path)
            with open(p, "r", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as e:
            return f"error: {e}"
        start = max(1, int(start_line or 1))
        n = min(int(max_lines or 200), self.cfg.max_read_lines)
        chunk = lines[start - 1: start - 1 + n]
        body = "".join(f"{start+i:>5}  {ln.rstrip()}\n" for i, ln in enumerate(chunk))
        return body[:self.cfg.max_file_bytes] or "(no lines in range)"

    def grep(self, pattern: str, files: List[str], path_contains: str = "") -> str:
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return f"error: bad regex: {e}"
        hits: List[str] = []
        for rel in files:
            if path_contains and path_contains not in rel:
                continue
            try:
                p = safe_path(self.root, rel)
                with open(p, "r", errors="ignore") as fh:
                    for i, ln in enumerate(fh, 1):
                        if rx.search(ln):
                            hits.append(f"{rel}:{i}: {ln.strip()[:200]}")
                            if len(hits) >= self.cfg.max_grep_hits:
                                return "\n".join(hits) + "\n…(truncated)"
            except Exception:
                continue
        return "\n".join(hits) or "(no matches)"

    def read_slice(self, rel: str, line: int, ctx: int = 25) -> str:
        try:
            p = safe_path(self.root, rel)
            with open(p, "r", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception as e:
            return f"<could not read {rel}: {type(e).__name__}>"
        if line and line > 0:
            lo = max(0, line - ctx - 1)
            hi = min(len(lines), line + ctx)
        else:
            lo, hi = 0, min(len(lines), 2 * ctx)
        numbered = [f"{i+1:>5}  {lines[i].rstrip()}" for i in range(lo, hi)]
        return "\n".join(numbered)[:8000]

    def stop(self) -> None:
        pass


class SandboxFileAccess:
    """File access delegated to the docker sandbox via the toolrunner."""

    def __init__(self, sandbox) -> None:
        self.sb = sandbox

    def build_map(self) -> Tuple[Dict[str, Any], List[str]]:
        out = self.sb.call("build_map", {})
        if "error" in out:
            raise RuntimeError(f"sandbox build_map: {out['error']}")
        return out["map"], out["files"]

    def list_dir(self, path: str = "") -> str:
        try:
            out = self.sb.call("list_dir", {"path": path})
        except Exception as e:
            return f"error: {e}"
        return out.get("error") and f"error: {out['error']}" or out.get("result", "")

    def read_file(self, path: str, start_line: int = 1, max_lines: int = 200) -> str:
        try:
            out = self.sb.call("read_file", {"path": path, "start_line": start_line, "max_lines": max_lines})
        except Exception as e:
            return f"error: {e}"
        return out.get("error") and f"error: {out['error']}" or out.get("result", "")

    def grep(self, pattern: str, files: List[str], path_contains: str = "") -> str:
        try:
            out = self.sb.call("grep", {"pattern": pattern, "files": files, "path_contains": path_contains})
        except Exception as e:
            return f"error: {e}"
        return out.get("error") and f"error: {out['error']}" or out.get("result", "")

    def read_slice(self, rel: str, line: int, ctx: int = 25) -> str:
        try:
            out = self.sb.call("read_slice", {"path": rel, "line": line, "ctx": ctx})
        except Exception as e:
            return f"<could not read {rel}: {type(e).__name__}>"
        return out.get("result") or f"<could not read {rel}>"

    def stop(self) -> None:
        self.sb.stop()
