"""Typed data shapes for the scan pipeline.

``ScanConfig`` is a plain dataclass (bounds + isolation knobs). The finding/
verdict shapes are pydantic so the judge's structured-output call validates and
retries on a malformed model response. ``Verdict`` is the schema the kernel
hands to the injected judge; everything else is what the kernel returns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field


# ── Configuration ───────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """Bounds and isolation settings for a scan. Defaults are sane for a typical
    web-app repo; raise the bounds for larger codebases at the cost of more LLM
    calls and wall-clock."""

    # Walk / read bounds — keep a scan from running away on a huge repo.
    max_map_files: int = 400          # source files the map tracks / navigator can reach
    max_file_bytes: int = 200_000     # per-file read ceiling
    max_read_lines: int = 600         # per read_file call
    max_grep_hits: int = 80           # per grep call

    # Navigator (the wide-net pass).
    nav_max_iters: int = 40           # tool-loop turns
    nav_deadline: float = 300.0       # wall-clock budget (seconds)
    max_candidates: int = 60          # candidates handed to the judge

    # Validator (the refute-first pass).
    judge_timeout: float = 60.0       # per-candidate judge deadline

    # Source preparation.
    clone_timeout: int = 120          # git clone budget (seconds)
    git_allowed_protocols: str = "http:https:ssh:git"

    # Isolation. sandbox: "auto" (docker if available, else in-process),
    # "docker" (force; error if unavailable), "inprocess" (force guarded host).
    sandbox: str = "auto"
    sandbox_image: str = "refutescan-sandbox:current"
    sandbox_uid: str = "10001"
    sandbox_pids: str = "256"
    sandbox_memory: str = "2g"
    sandbox_cpus: str = "2"
    docker_bin: str = "docker"
    exec_timeout: int = 90            # per docker-exec tool call
    container_ttl: int = 1200         # audit container sleep budget (> nav_deadline)

    # In-process backend only: confine local-path scans to these roots. Empty =
    # unrestricted (the docker jail is the boundary). Secret denylist always on.
    allowed_roots: List[Path] = field(default_factory=list)


# ── Judge I/O ───────────────────────────────────────────────────────────────────

class Verdict(BaseModel):
    """The structured verdict the judge returns for one candidate. This is the
    schema the kernel hands to the injected judge callable."""

    is_real: bool = Field(description="True ONLY if the code shown demonstrates a real, "
                                      "exploitable vulnerability with a concrete untrusted "
                                      "source reaching a dangerous sink. Default to false when unsure.")
    reachable: bool = Field(description="True if untrusted input can actually reach this sink "
                                        "(not gated by validation/auth that neutralizes it).")
    confidence: float = Field(description="0.0–1.0 confidence that this is a true positive.")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        description="Impact severity if exploitable.")
    reasoning: str = Field(description="2–4 sentences: the data flow you confirmed, or precisely "
                                       "why this is a false positive.")
    repro: str = Field(description="If real: concrete repro / exploitation steps. Else: empty.")
    recommendation: str = Field(description="If real: the targeted fix. Else: empty.")


# ── Result shapes (returned to the caller) ──────────────────────────────────────

class ScanResult(BaseModel):
    """Everything one scan produced. The consumer persists/renders this."""

    code_map: Dict[str, Any]
    findings: List[Dict[str, Any]]   # confirmed, sorted worst-first
    culled: List[Dict[str, Any]]     # refuted/timed-out candidates, with reasons
    summary: Dict[str, Any]
    candidate_count: int
    sandboxed: bool
