"""Path-safety and secret-denylist guards shared by every file-access backend.

These are defense-in-depth. The real isolation boundary is the docker sandbox
(``--network none``, read-only, non-root, only the target mounted). But the
in-process backend reads files as the host user, so the same guards run there —
and they run *inside* the container too (see ``sandbox/toolrunner.py``), so a
single bypassed layer never exposes credentials.

The constants here are deliberately conservative defaults. ``toolrunner.py``
keeps its own copies because it ships into a minimal image with no refutescan
install; keep the two in sync.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Iterable, List, Optional

# Path components we never descend into or read — credential & VCS/runtime stores.
SECRET_DIR_NAMES = {
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".secrets", "secrets",
    ".git",
}

# Basename globs we never read, even inside an allowed root — keys, certs, env files.
SECRET_FILE_GLOBS = (
    "*.key", "*.pem", "*.age", "*.p12", "*.pfx", "*.keystore", "*.jks",
    ".env", ".env.*", "*.env", "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
    ".netrc", ".pgpass", ".htpasswd", "credentials", "*.secret", "*.secrets",
)

# Transports git may use when cloning — excludes ext::/fd:: (command execution).
GIT_ALLOWED_PROTOCOLS = "http:https:ssh:git"


def parse_roots(spec: Optional[str]) -> List[Path]:
    """Parse a colon-separated roots string into resolved Paths ([] if falsy)."""
    if not spec:
        return []
    return [
        Path(os.path.expanduser(p)).resolve()
        for p in spec.split(":")
        if p.strip()
    ]


def within_allowed_roots(p: Path, roots: Optional[Iterable[Path]]) -> bool:
    """True iff p resolves inside one of the configured roots.

    An empty/None roots list means "unrestricted" — the right default for a
    library running on the user's own machine, where the docker jail (or the
    user's own intent) is the boundary, not a host allowlist.
    """
    roots = list(roots or [])
    if not roots:
        return True
    p = p.resolve()
    return any(p == r or r in p.parents for r in roots)


def deny_secret(p: Path, root: Path) -> None:
    """Refuse credential/key/env paths even within an allowed root. Raises ValueError."""
    try:
        rel = p.relative_to(root)
    except ValueError:
        rel = p
    for part in rel.parts:
        if part in SECRET_DIR_NAMES:
            raise ValueError(f"refusing to read sensitive path '{part}/'")
    name = p.name
    for glob in SECRET_FILE_GLOBS:
        if fnmatch.fnmatch(name, glob):
            raise ValueError(f"refusing to read sensitive file '{name}'")


def safe_path(root: Path, rel: str) -> Path:
    """Resolve rel under root; reject path escapes and secret-shaped files.

    The single choke point every navigator tool (list_dir / read_file / grep)
    and the judge's slice re-read go through, so the denylist covers them all.
    """
    root = root.resolve()
    p = (root / (rel or "").lstrip("/")).resolve()
    if root != p and root not in p.parents:
        raise ValueError("path escapes the repository root")
    deny_secret(p, root)
    return p
