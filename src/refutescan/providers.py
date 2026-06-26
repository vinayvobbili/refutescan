"""The model-injection seam — how a caller plugs its own LLMs into the scan.

refutescan is model-agnostic: it never imports a provider SDK in the core. The
caller passes two factories.

navigator_factory() -> a chat model
    A LangChain-style chat model that supports ``.bind_tools(tools)`` and
    ``.invoke(messages)`` returning a message whose ``.tool_calls`` the loop
    reads. This drives the wide-net pass. A fast/cheap tool-calling model is the
    right fit (it is fine that it over-reports — the judge culls).

judge_factory() -> judge(prompt: str, schema: type[BaseModel]) -> BaseModel
    A callable that runs ONE structured-output completion: given a prompt and a
    pydantic model, return a validated instance. This is the refute-first pass;
    a stronger model is the right fit. The kernel wraps each call in a hard
    timeout, so the callable itself need not.

See ``refutescan.adapters`` for ready-made factories (e.g. OpenAI).
"""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel

# A factory returning a tool-capable chat model (bind_tools + invoke).
NavigatorFactory = Callable[[], Any]

# A factory returning a judge callable: (prompt, schema) -> validated instance.
JudgeCallable = Callable[[str, type], BaseModel]
JudgeFactory = Callable[[], JudgeCallable]
