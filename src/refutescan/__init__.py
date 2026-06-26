"""refutescan — a two-LLM, refute-first agentic source-code vulnerability scanner.

A fast model NAVIGATES the repo with read-only tools and casts a wide net of
candidate findings; a stronger model then REFUTES each one against the real code
slice before it surfaces — so you get the recall of an agentic scanner without
the false-positive flood. Scans run jailed in an ephemeral docker sandbox
(clone-in-container, no network, read-only, non-root) by default. Bring your own
LLMs.

    from refutescan import scan
    from refutescan.adapters import openai_navigator_factory, openai_judge_factory

    result = scan(
        "https://github.com/owner/repo",
        navigator_factory=openai_navigator_factory(),
        judge_factory=openai_judge_factory(),
    )
    for f in result.findings:
        print(f["severity"], f["title"], f["file"], f["line"])
"""

from .models import ScanConfig, ScanResult, Verdict
from .scanner import derive_title, looks_like_git_url, scan
from .vulns import SEVERITIES, VULN_CLASSES

__version__ = "0.1.0"

__all__ = [
    "scan",
    "ScanConfig",
    "ScanResult",
    "Verdict",
    "VULN_CLASSES",
    "SEVERITIES",
    "looks_like_git_url",
    "derive_title",
    "__version__",
]
