"""Deterministic, LLM-free repository map.

A single os.walk that classifies files (source / manifest / entrypoint), counts
LOC, and returns the relative source-file list the navigator will reach. Cheap,
reproducible, and the same logic that runs inside the sandbox toolrunner.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Source file extensions worth scanning. Anything else (assets, lockfiles,
# binaries, minified bundles) is counted as context, not handed to the LLM.
SOURCE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".kt", ".scala", ".swift", ".sh",
    ".bash", ".pl", ".pm", ".sql", ".html", ".vue", ".lua", ".groovy", ".tf",
}
# Directories never worth walking — vendored / generated / VCS metadata.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
    "site-packages", "target", ".idea", ".vscode", ".gradle", "bin", "obj",
    "coverage", ".tox", ".cache", "bower_components",
}
# Dependency manifests we surface in the map (signal for what the app is).
MANIFESTS = {
    "requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "package.json",
    "go.mod", "pom.xml", "build.gradle", "Gemfile", "composer.json", "Cargo.toml",
    "csproj",
}
# Entry-point filename hints (heuristic — where untrusted input often lands).
ENTRY_HINTS = {
    "app.py", "main.py", "manage.py", "wsgi.py", "asgi.py", "server.py",
    "index.js", "server.js", "app.js", "main.go", "main.rs", "index.php",
    "application.java",
}


def build_map(root: Path, max_map_files: int = 400,
              max_file_bytes: int = 200_000) -> Tuple[Dict[str, Any], List[str]]:
    """Walk the tree once. Returns (map_dict, relative_source_file_paths)."""
    root = root.resolve()
    langs: Dict[str, int] = {}
    manifests: List[str] = []
    entrypoints: List[str] = []
    source_files: List[str] = []
    total_files = 0
    total_loc = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            total_files += 1
            ext = os.path.splitext(fn)[1].lower()
            full = Path(dirpath) / fn
            rel = str(full.relative_to(root))
            if fn in MANIFESTS or fn.endswith(".csproj"):
                manifests.append(rel)
            if fn in ENTRY_HINTS:
                entrypoints.append(rel)
            if ext in SOURCE_EXTS and len(source_files) < max_map_files:
                source_files.append(rel)
                langs[ext] = langs.get(ext, 0) + 1
                try:
                    if full.stat().st_size <= max_file_bytes:
                        with open(full, "r", errors="ignore") as fh:
                            total_loc += sum(1 for _ in fh)
                except Exception:
                    pass

    code_map = {
        "root_name": root.name,
        "total_files": total_files,
        "source_files_scanned": len(source_files),
        "truncated": len(source_files) >= max_map_files,
        "total_loc": total_loc,
        "languages": dict(sorted(langs.items(), key=lambda kv: -kv[1])),
        "manifests": manifests[:30],
        "entrypoints": entrypoints[:30],
    }
    return code_map, source_files
