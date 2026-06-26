# refutescan

**A two-LLM, refute-first agentic source-code vulnerability scanner.**

Most LLM code scanners have the same problem: they hallucinate. Point a model at
a repo and it will confidently report SQL injection in a parameterized query and
SSRF behind an allowlist. The noise buries the real bugs.

refutescan splits the job across two models:

1. **Navigate (wide net).** A fast tool-calling model explores the repo with
   read-only tools (`list_dir` / `read_file` / `grep`), traces untrusted input
   toward dangerous sinks, and records *candidate* findings. It's cheap and it
   over-reports on purpose.
2. **Refute (skeptic).** A stronger model re-reads the actual code slice around
   each candidate from disk — ground truth, not the navigator's paraphrase — and
   is prompted to **refute** it. Sanitized? Parameterized? Gated by auth? Not
   reachable? It's culled, with the reason kept. Only what survives is reported.

You get the recall of an agentic scanner without the false-positive flood.

Every scan runs **jailed in an ephemeral docker sandbox** by default: git URLs
are cloned *inside a container* (no host mounts), then audited in a second
container with **no network, read-only, no capabilities, non-root**, and only
the repo mounted. A hostile repo (malicious submodule, hook, symlink) touches
neither your filesystem nor the network.

## Install

```
pip install refutescan            # core kernel
pip install 'refutescan[openai]'  # + the OpenAI adapter for the CLI
```

For sandboxed scans (recommended), build the jail image once:

```
refutescan-build-sandbox
```

(Requires Docker. Without it, refutescan falls back to a guarded in-process scan.)

## CLI

```
export OPENAI_API_KEY=sk-...
refutescan https://github.com/owner/repo
refutescan ./path/to/local/repo --judge-model gpt-4o --json
```

Exit code is non-zero when confirmed findings exist, so it drops straight into CI.

## Library

```python
from refutescan import scan, ScanConfig
from refutescan.adapters import openai_navigator_factory, openai_judge_factory

result = scan(
    "https://github.com/owner/repo",
    navigator_factory=openai_navigator_factory("gpt-4o-mini"),
    judge_factory=openai_judge_factory("gpt-4o"),
    config=ScanConfig(sandbox="docker"),       # auto | docker | inprocess
    progress=lambda phase: print(phase),
)

for f in result.findings:
    print(f["severity"], f["title"], f"{f['file']}:{f['line']}")
    print("  ", f["reasoning"])
    print("  fix:", f["recommendation"])
```

`result.culled` holds the refuted candidates with the reason each was rejected —
useful for tuning and for trusting the tool.

## Bring your own model

refutescan never imports a provider SDK in its core. Pass any LangChain-style
chat model through two factories:

- `navigator_factory() -> chat_model` — supports `.bind_tools(...)` + `.invoke(...)`
- `judge_factory() -> judge(prompt, schema) -> instance` — one structured-output call

So a local model (vLLM/Ollama via the OpenAI shim, `--base-url`), Anthropic,
Azure OpenAI, or a corporate gateway all work — wire the factory and go. See
`refutescan/providers.py`.

## What it is and isn't

- **Is:** an agentic, read-only, false-positive-resistant first-pass auditor for
  the common web-app vuln classes (injection, authz/IDOR, SSRF, path traversal,
  unsafe deserialization, hardcoded secrets, weak crypto, XSS, auth flaws).
- **Isn't:** a replacement for a full SAST suite, a proof of exploitability, or a
  patch generator. It finds and explains; a human confirms and fixes.

## License

MIT.
