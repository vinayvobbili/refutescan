"""The vulnerability taxonomy the navigator hunts and the judge scores.

Kept in one place so the navigator brief, the judge, and any UI render the same
classes. Extend ``VULN_CLASSES`` to teach the scanner new classes — the navigator
is steered by the brief, not by hard-coded pattern matching.
"""

from __future__ import annotations

from typing import List, Tuple

# (key, human label). The key is what record_finding stores; the label is for
# the brief and any UI.
VULN_CLASSES: List[Tuple[str, str]] = [
    ("injection", "SQL / command / template injection"),
    ("authz", "Broken authz / IDOR / missing access control"),
    ("ssrf", "Server-side request forgery (SSRF)"),
    ("path_traversal", "Path traversal / arbitrary file read-write"),
    ("deserialization", "Unsafe deserialization / pickle / yaml.load"),
    ("secrets", "Hardcoded secrets / credentials in source"),
    ("crypto", "Weak crypto / bad randomness / hashing misuse"),
    ("xss", "Cross-site scripting (reflected / stored / DOM)"),
    ("auth", "Auth flaws — weak session, missing checks, JWT misuse"),
]

VALID_CLASSES = {k for k, _ in VULN_CLASSES}

# Worst → least; used to rank findings and to pick a scan's max severity.
SEVERITIES: Tuple[str, ...] = ("critical", "high", "medium", "low", "info")
