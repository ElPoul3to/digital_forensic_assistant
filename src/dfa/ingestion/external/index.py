"""Embed and upsert external chunks (ATT&CK)."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from dfa.ingestion.schema import Chunk
from dfa.retrieval.embedder import get_embedder
from dfa.retrieval.store import get_store

log = logging.getLogger(__name__)
BATCH = 256


def index_chunks(chunks: Iterable[Chunk]) -> dict[str, int]:
    emb = get_embedder()
    store = get_store()
    n = 0
    batch: list[Chunk] = []
    for c in chunks:
        batch.append(c)
        if len(batch) >= BATCH:
            n += store.upsert(batch, emb.embed_documents([b.text for b in batch]))
            log.info("indexed %d external chunks", n)
            batch = []
    if batch:
        n += store.upsert(batch, emb.embed_documents([b.text for b in batch]))
    return {"chunks": n}
