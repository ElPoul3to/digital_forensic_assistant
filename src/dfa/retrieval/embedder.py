"""Dense embeddings with Qwen3-Embedding via sentence-transformers."""

from __future__ import annotations

import logging
from functools import lru_cache

import torch

from dfa.config import get_settings

log = logging.getLogger(__name__)

_DTYPES = {"float16": torch.float16, "bfloat16": torch.bfloat16, "float32": torch.float32}

# Qwen3-Embedding is instruction-aware: queries get a task prefix, documents do not.
_QUERY_INSTRUCTION = (
    "Instruct: Given a question from a cyber incident response analyst, retrieve log "
    "events, forensic artefacts or threat-intelligence passages that answer it\nQuery: "
)


class Embedder:
    def __init__(self) -> None:
        cfg = get_settings().embedding
        from sentence_transformers import SentenceTransformer

        device = cfg.device if torch.cuda.is_available() else "cpu"
        if device != cfg.device:
            log.warning("CUDA unavailable, embedding on CPU")
        self.model = SentenceTransformer(
            cfg.model,
            device=device,
            model_kwargs={"torch_dtype": _DTYPES[cfg.dtype]} if device == "cuda" else {},
            tokenizer_kwargs={"padding_side": "left"},
        )
        self.model.max_seq_length = cfg.max_length
        self.batch_size = cfg.batch_size
        self.dim = (self.model.get_embedding_dimension() if hasattr(self.model, "get_embedding_dimension") else self.model.get_sentence_embedding_dimension())
        self.name = cfg.model

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        vecs = self.model.encode(
            texts, batch_size=self.batch_size, normalize_embeddings=True, show_progress_bar=False
        )
        return vecs.tolist()

    def embed_queries(self, queries: list[str]) -> list[list[float]]:
        if not queries:
            return []
        vecs = self.model.encode(
            [_QUERY_INSTRUCTION + q for q in queries],
            batch_size=self.batch_size,
            normalize_embeddings=True,
        )
        return vecs.tolist()

    def warmup(self) -> None:
        self.embed_documents(["warmup"])
        log.info("embedder ready: %s dim=%d", self.name, self.dim)


@lru_cache(maxsize=1)
def get_embedder() -> Embedder:
    return Embedder()
