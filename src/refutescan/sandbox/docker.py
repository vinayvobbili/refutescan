"""Ephemeral, locked-down docker jail for one scan.

The LLM orchestration stays in the host process; every file touch is delegated
via ``docker exec ... python /toolrunner.py`` into a container that mounts only
the target read-only, with no network, no caps, a non-root uid, and resource
limits.

For a git URL the clone happens in a SEPARATE network-enabled container with no
host mounts (into a docker volume), so untrusted git never runs on the host; the
audit container then mounts that volume read-only with ``--network none``. This
"clone-in-container" pattern means a malicious repo (hostile submodule, hook,
symlink) can touch neither the host filesystem nor, during the audit, the
network.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import ScanConfig

logger = logging.getLogger(__name__)


def docker_usable(docker_bin: str = "docker") -> bool:
    """True if a docker daemon is reachable."""
    try:
        r = subprocess.run([docker_bin, "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def sandbox_enabled(config: ScanConfig) -> bool:
    """Resolve the sandbox mode to a concrete on/off for this run."""
    mode = (config.sandbox or "auto").strip().lower()
    if mode == "inprocess":
        return False
    if mode == "docker":
        return True
    return docker_usable(config.docker_bin)  # auto


class DockerSandbox:
    """Lifecycle for a scan's jail container(s). Not thread-safe; one per scan."""

    def __init__(self, config: ScanConfig) -> None:
        self.cfg = config
        self.docker = config.docker_bin or "docker"
        self.cid: Optional[str] = None
        self.volume: Optional[str] = None

    def _run(self, args: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run([self.docker, *args], capture_output=True, text=True, timeout=timeout)

    def _start_audit(self, mount_spec: str) -> None:
        """Start the read-only, network-less audit container holding the repo."""
        c = self.cfg
        proc = self._run([
            "run", "-d", "--rm",
            "--network", "none", "--read-only", "--tmpfs", "/tmp",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", c.sandbox_uid, "--pids-limit", c.sandbox_pids,
            "--memory", c.sandbox_memory, "--cpus", c.sandbox_cpus,
            "-v", mount_spec,
            c.sandbox_image, "sleep", str(c.container_ttl),
        ], timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"sandbox start failed: {(proc.stderr or proc.stdout).strip()[:200]}")
        self.cid = proc.stdout.strip()

    def start_local(self, target: Path) -> None:
        self._start_audit(f"{target}:/repo:ro")

    def start_git(self, source: str, branch: str = "") -> None:
        """Clone an untrusted URL inside a throwaway networked container (no host
        mounts) into a volume, then mount that volume read-only for the audit."""
        c = self.cfg
        vol = self._run(["volume", "create"], timeout=30)
        if vol.returncode != 0:
            raise RuntimeError(f"could not create scan volume: {vol.stderr.strip()[:200]}")
        self.volume = vol.stdout.strip()
        # A fresh volume is root-owned; chown it to the sandbox uid with a trusted
        # init container (root runs only our own `chown`) so the untrusted git
        # clone itself can run NON-root.
        init = self._run(["run", "--rm", "--network", "none", "--user", "0",
                          "-v", f"{self.volume}:/out", "--entrypoint", "chown",
                          c.sandbox_image, "-R", f"{c.sandbox_uid}:{c.sandbox_uid}", "/out"],
                         timeout=30)
        if init.returncode != 0:
            raise RuntimeError(f"could not prepare scan volume: {(init.stderr or init.stdout).strip()[:200]}")
        cmd = ["run", "--rm", "--network", "bridge",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--user", c.sandbox_uid, "--memory", c.sandbox_memory,
               "--pids-limit", c.sandbox_pids, "--tmpfs", "/tmp",
               "-e", "HOME=/tmp",
               "-e", "GIT_ALLOW_PROTOCOL=" + c.git_allowed_protocols,
               "-e", "GIT_TERMINAL_PROMPT=0",
               "-v", f"{self.volume}:/out",
               "--entrypoint", "git", c.sandbox_image,
               "clone", "--depth", "1", "--no-recurse-submodules", "--no-tags"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [source, "/out/repo"]
        proc = self._run(cmd, timeout=c.clone_timeout + 30)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or ["unknown error"]
            raise RuntimeError(f"git clone (sandboxed) failed: {tail[0][:200]}")
        self._start_audit(f"{self.volume}:/repo:ro")

    def call(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.cid:
            raise RuntimeError("sandbox not started")
        proc = subprocess.run(
            [self.docker, "exec", "-i", self.cid, "python", "/toolrunner.py", command],
            input=json.dumps(args), capture_output=True, text=True, timeout=self.cfg.exec_timeout)
        if proc.returncode not in (0, 1):  # 2 = bad command/args; others = infra
            raise RuntimeError(f"sandbox exec failed ({proc.returncode}): {proc.stderr.strip()[:200]}")
        try:
            return json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            raise RuntimeError(f"sandbox returned non-JSON: {proc.stdout[:200]}")

    def stop(self) -> None:
        if self.cid:
            try:
                self._run(["rm", "-f", self.cid], timeout=30)
            except Exception:
                logger.warning("[refutescan] failed to remove sandbox container %s", self.cid)
            self.cid = None
        if self.volume:
            try:
                self._run(["volume", "rm", "-f", self.volume], timeout=30)
            except Exception:
                logger.warning("[refutescan] failed to remove scan volume %s", self.volume)
            self.volume = None


def sandbox_dir() -> Path:
    """Directory holding the image source (Dockerfile, toolrunner.py, build.sh)."""
    return Path(__file__).resolve().parent
