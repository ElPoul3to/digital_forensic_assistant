"""Cross-encoder reranking with Qwen3-Reranker (yes/no logit scoring)."""

from __future__ import annotations

import logging
from functools import lru_cache

import torch

from dfa.config import get_settings

log = logging.getLogger(__name__)
_DTYPES = {"float16": torch.float16, "bfloat16": torch.bfloat16, "float32": torch.float32}

_PREFIX = (
    "<|im_start|>system\nJudge whether the Document meets the requirements based on the Query and the "
    'Instruct provided. Note that the answer can only be "yes" or "no".<|im_end|>\n<|im_start|>user\n'
)
_SUFFIX = "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
_INSTRUCTION = (
    "Given a question from a cyber incident response analyst, judge whether the document (a log excerpt, "
    "forensic artefact or threat-intelligence passage) contains information that helps answer it"
)


class Reranker:
    def __init__(self) -> None:
        cfg = get_settings().reranker
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.device = cfg.device if torch.cuda.is_available() else "cpu"
        self.tok = AutoTokenizer.from_pretrained(cfg.model, padding_side="left")
        self.model = AutoModelForCausalLM.from_pretrained(
            cfg.model, torch_dtype=_DTYPES[cfg.dtype] if self.device == "cuda" else torch.float32
        ).to(self.device).eval()
        self.max_length = cfg.max_length
        self.batch_size = cfg.batch_size
        self.yes = self.tok.convert_tokens_to_ids("yes")
        self.no = self.tok.convert_tokens_to_ids("no")
        self.prefix_ids = self.tok.encode(_PREFIX, add_special_tokens=False)
        self.suffix_ids = self.tok.encode(_SUFFIX, add_special_tokens=False)
        self.name = cfg.model

    def _format(self, query: str, doc: str) -> str:
        return f"<Instruct>: {_INSTRUCTION}\n<Query>: {query}\n<Document>: {doc}"

    @torch.no_grad()
    def score(self, query: str, docs: list[str]) -> list[float]:
        if not docs:
            return []
        out: list[float] = []
        body_max = self.max_length - len(self.prefix_ids) - len(self.suffix_ids)
        for i in range(0, len(docs), self.batch_size):
            texts = [self._format(query, d) for d in docs[i : i + self.batch_size]]
            enc = self.tok(texts, padding=False, truncation="longest_first", max_length=body_max, add_special_tokens=False)
            ids = [self.prefix_ids + x + self.suffix_ids for x in enc["input_ids"]]
            batch = self.tok.pad({"input_ids": ids}, padding=True, return_tensors="pt").to(self.device)
            # Only the last position is needed; full-sequence logits (batch x seq x 152k vocab) would cost ~10 GB.
            logits = self.model(**batch, logits_to_keep=1).logits[:, -1, :]
            pair = torch.stack([logits[:, self.no], logits[:, self.yes]], dim=1).float()
            out.extend(torch.log_softmax(pair, dim=1)[:, 1].exp().tolist())
        return out


@lru_cache(maxsize=1)
def get_reranker() -> Reranker:
    return Reranker()
