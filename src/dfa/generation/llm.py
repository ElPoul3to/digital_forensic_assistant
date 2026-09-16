"""Thin LLM client (Ollama by default)."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from functools import lru_cache

from dfa.config import get_settings

log = logging.getLogger(__name__)


class LLM:
    def __init__(self) -> None:
        cfg = get_settings().generator
        import ollama

        self.model = cfg.model
        self.client = ollama.Client(host=cfg.base_url)
        self.options = {"num_ctx": cfg.num_ctx, "temperature": cfg.temperature}
        self.keep_alive = cfg.keep_alive
        self.think = cfg.think

    def complete(self, prompt: str, system: str | None = None, max_tokens: int | None = None) -> str:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        opts = dict(self.options)
        if max_tokens:
            opts["num_predict"] = max_tokens
        res = self.client.chat(model=self.model, messages=msgs, options=opts, keep_alive=self.keep_alive, think=self.think)
        return res["message"]["content"]

    def stream(self, messages: list[dict], max_tokens: int | None = None) -> Iterator[str]:
        opts = dict(self.options)
        if max_tokens:
            opts["num_predict"] = max_tokens
        for part in self.client.chat(
            model=self.model, messages=messages, options=opts, keep_alive=self.keep_alive, stream=True, think=self.think
        ):
            yield part["message"]["content"]


@lru_cache(maxsize=1)
def get_llm() -> LLM:
    return LLM()
