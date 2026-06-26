"""Ready-made model factories for common providers.

These are thin conveniences over LangChain chat models so you don't have to wire
the injection seam yourself. Import the one you want; each needs its provider
extra installed (e.g. ``pip install refutescan[openai]``). Bring your own by
passing any LangChain-style chat model — see ``refutescan.providers``.
"""

from .openai_chat import openai_judge_factory, openai_navigator_factory

__all__ = ["openai_navigator_factory", "openai_judge_factory"]
