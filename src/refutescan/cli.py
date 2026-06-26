"""Command-line entry points.

  refutescan <path-or-git-url> [options]   — run a scan, print findings
  refutescan-build-sandbox                 — build the docker jail image

The scan CLI uses the OpenAI adapter by default (needs the ``openai`` extra and
OPENAI_API_KEY, or --base-url for a compatible gateway). For other providers,
call ``refutescan.scan`` directly with your own factories.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

from . import __version__
from .models import ScanConfig


def _sev_marker(sev: str) -> str:
    return {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]",
            "low": "[LOW ]", "info": "[INFO]"}.get(sev, "[????]")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="refutescan",
        description="Two-LLM, refute-first agentic source-code vulnerability scanner.")
    ap.add_argument("source", help="a local directory path or a git URL to clone")
    ap.add_argument("--branch", default="", help="git branch to clone (git sources only)")
    ap.add_argument("--sandbox", default="auto", choices=["auto", "docker", "inprocess"],
                    help="isolation backend (default: auto)")
    ap.add_argument("--navigator-model", default="gpt-4o-mini",
                    help="navigator (wide-net) model (default: gpt-4o-mini)")
    ap.add_argument("--judge-model", default="gpt-4o",
                    help="judge (refute) model (default: gpt-4o)")
    ap.add_argument("--base-url", default=None,
                    help="OpenAI-compatible base URL (vLLM, Azure, local proxy, …)")
    ap.add_argument("--json", action="store_true", help="emit the full result as JSON")
    ap.add_argument("--version", action="version", version=f"refutescan {__version__}")
    args = ap.parse_args(argv)

    try:
        from .adapters import openai_judge_factory, openai_navigator_factory
    except Exception as e:  # pragma: no cover
        print(f"error: {e}", file=sys.stderr)
        return 2

    kw = {"base_url": args.base_url} if args.base_url else {}
    from . import scan

    def _progress(phase: str) -> None:
        if not args.json:
            print(f"  … {phase}", file=sys.stderr)

    try:
        result = scan(
            args.source,
            navigator_factory=openai_navigator_factory(args.navigator_model, **kw),
            judge_factory=openai_judge_factory(args.judge_model, **kw),
            branch=args.branch,
            config=ScanConfig(sandbox=args.sandbox),
            progress=_progress,
        )
    except Exception as e:
        print(f"scan failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(result.model_dump_json(indent=2))
        return 0 if not result.findings else 1

    s = result.summary
    print(f"\nScanned {s.get('files_scanned')} files / {s.get('total_loc')} LOC"
          f"  ·  {'sandboxed' if result.sandboxed else 'in-process'}")
    print(f"{result.candidate_count} candidate(s) → {len(result.findings)} confirmed, "
          f"{len(result.culled)} culled\n")
    if not result.findings:
        print("No confirmed findings.")
        return 0
    for f in result.findings:
        conf = f.get("confidence")
        conf_s = f" (conf {conf:.2f})" if isinstance(conf, (int, float)) else ""
        print(f"{_sev_marker(f.get('severity', ''))} {f.get('title')}{conf_s}")
        print(f"        {f.get('file')}:{f.get('line')}  [{f.get('vuln_class')}]")
        if f.get("reasoning"):
            print(f"        {f['reasoning']}")
        print()
    return 1  # non-zero exit when findings exist (CI-friendly)


def build_sandbox(argv=None) -> int:
    """Build the docker jail image (refutescan-build-sandbox)."""
    from .sandbox.docker import sandbox_dir
    ap = argparse.ArgumentParser(
        prog="refutescan-build-sandbox",
        description="Build the refutescan docker sandbox image.")
    ap.add_argument("--image", default="refutescan-sandbox:current", help="image tag to build")
    args = ap.parse_args(argv)
    d = sandbox_dir()
    print(f"Building {args.image} from {d} ...")
    try:
        subprocess.run(["docker", "build", "-t", args.image, str(d)], check=True)
    except FileNotFoundError:
        print("error: docker not found on PATH", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as e:
        print(f"docker build failed ({e.returncode})", file=sys.stderr)
        return e.returncode
    print(f"Done. Image: {args.image}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
