"""Docker sandbox for jailed scans.

The image source (Dockerfile + toolrunner.py + build.sh) ships inside this
package directory. Build it once with ``refutescan-build-sandbox`` (or run
``build.sh`` here) before using ``sandbox="docker"``.
"""

from .docker import DockerSandbox, docker_usable, sandbox_enabled

__all__ = ["DockerSandbox", "docker_usable", "sandbox_enabled"]
