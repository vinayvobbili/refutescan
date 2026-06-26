"""Kernel tests that need no LLM and no docker — they exercise the deterministic
spine (code map, path safety, summary, the navigate/validate plumbing) with
fakes injected through the same seams a real model would use."""

from pathlib import Path

import pytest

from refutescan import ScanConfig, Verdict, scan
from refutescan.codemap import build_map
from refutescan.fileaccess import LocalFileAccess
from refutescan.safety import deny_secret, safe_path, within_allowed_roots
from refutescan.scanner import _summarize


# ── A tiny vulnerable repo on disk ──────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import sqlite3\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/u')\n"
        "def u():\n"
        "    uid = request.args.get('id')\n"
        "    db = sqlite3.connect('x.db')\n"
        "    return db.execute('SELECT * FROM users WHERE id=' + uid).fetchall()\n"
    )
    (tmp_path / "safe.py").write_text("def add(a, b):\n    return a + b\n")
    secrets = tmp_path / ".ssh"
    secrets.mkdir()
    (secrets / "id_rsa").write_text("PRIVATE KEY")
    return tmp_path


def test_build_map_finds_sources_and_entrypoint(repo: Path):
    code_map, files = build_map(repo)
    assert "app.py" in files
    assert "safe.py" in files
    assert "app.py" in code_map["entrypoints"]
    assert code_map["total_loc"] > 0


def test_safe_path_blocks_escape(repo: Path):
    with pytest.raises(ValueError):
        safe_path(repo, "../../../etc/passwd")


def test_secret_denylist(repo: Path):
    with pytest.raises(ValueError):
        deny_secret(repo / ".ssh" / "id_rsa", repo)
    with pytest.raises(ValueError):
        deny_secret(repo / "app.key", repo)


def test_local_file_access_refuses_secret_dir(repo: Path):
    fa = LocalFileAccess(repo, ScanConfig())
    out = fa.read_file(".ssh/id_rsa")
    assert out.startswith("error:")
    assert "sensitive" in out


def test_allowed_roots(tmp_path: Path):
    assert within_allowed_roots(tmp_path / "a", [tmp_path])
    assert not within_allowed_roots(Path("/etc"), [tmp_path])
    assert within_allowed_roots(Path("/etc"), [])  # empty = unrestricted


def test_summary_ranks_max_severity():
    findings = [{"severity": "low", "vuln_class": "xss"},
                {"severity": "critical", "vuln_class": "injection"}]
    s = _summarize({"source_files_scanned": 2, "total_loc": 10}, findings, [], 5)
    assert s["max_severity"] == "critical"
    assert s["total_findings"] == 2
    assert s["culled_count"] == 0


# ── End-to-end with fake models (no network, in-process backend) ────────────────

class _FakeNavigator:
    """Stands in for a tool-calling chat model: one turn that records the SQLi,
    then a turn with no tool calls (done)."""

    def __init__(self):
        self._tools = {}
        self._turn = 0

    def bind_tools(self, tools):
        self._tools = {t.name: t for t in tools}
        return self

    def invoke(self, messages):
        from langchain_core.messages import AIMessage
        self._turn += 1
        if self._turn == 1:
            self._tools["record_finding"].invoke({
                "vuln_class": "injection", "title": "SQLi in /u",
                "file": "app.py", "line": 8,
                "source": "request.args.get('id')", "sink": "db.execute(... + uid)",
                "snippet": "db.execute('... id=' + uid)",
                "rationale": "user id concatenated into SQL",
            })
            return AIMessage(content="", tool_calls=[
                {"name": "list_dir", "args": {}, "id": "t1"}])
        return AIMessage(content="done")


def _fake_judge_factory():
    def factory():
        def judge(prompt: str, schema):
            assert schema is Verdict
            return Verdict(is_real=True, reachable=True, confidence=0.95,
                           severity="critical", reasoning="uid flows unsanitized into execute()",
                           repro="GET /u?id=1 OR 1=1", recommendation="use parameterized query")
        return judge
    return factory


def test_end_to_end_in_process(repo: Path):
    result = scan(
        str(repo),
        navigator_factory=lambda: _FakeNavigator(),
        judge_factory=_fake_judge_factory(),
        config=ScanConfig(sandbox="inprocess", allowed_roots=[repo]),
    )
    assert result.candidate_count == 1
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["vuln_class"] == "injection"
    assert f["severity"] == "critical"
    assert f["confidence"] == pytest.approx(0.95)
    assert result.summary["max_severity"] == "critical"
    assert result.sandboxed is False
