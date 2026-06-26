"""OpenAI (or any OpenAI-compatible endpoint) model factories.

Requires ``langchain-openai`` (the ``openai`` extra). Set ``OPENAI_API_KEY``, or
pass ``base_url`` to point at a compatible gateway (vLLM, Ollama's OpenAI shim,
Azure OpenAI, a local proxy, …).

    from refutescan import scan
    from refutescan.adapters import openai_navigator_factory, openai_judge_factory

    result = scan(
        "https://github.com/owner/repo",
        navigator_factory=openai_navigator_factory("gpt-4o-mini"),
        judge_factory=openai_judge_factory("gpt-4o"),
    )
"""

from __future__ import annotations

from typing import Any

from ..providers import JudgeFactory, NavigatorFactory


def _chat(model: str, **kwargs: Any):
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "refutescan's OpenAI adapter needs langchain-openai. "
            "Install it with: pip install 'refutescan[openai]'"
        ) from e
    return ChatOpenAI(model=model, temperature=0, **kwargs)


def openai_navigator_factory(model: str = "gpt-4o-mini", **kwargs: Any) -> NavigatorFactory:
    """A navigator factory using a fast OpenAI tool-calling model (the wide-net pass)."""
    def factory():
        return _chat(model, **kwargs)
    return factory


def openai_judge_factory(model: str = "gpt-4o", **kwargs: Any) -> JudgeFactory:
    """A judge factory using a stronger OpenAI model with structured output (refute pass)."""
    def factory():
        llm = _chat(model, **kwargs)

        def judge(prompt: str, schema: type):
            return llm.with_structured_output(schema).invoke(prompt)

        return judge
    return factory
