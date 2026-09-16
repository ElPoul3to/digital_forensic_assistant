"""Qdrant wrapper: one collection per case plus shared external collections.

Every collection holds a dense vector (``dense``) and a sparse BM25 vector
(``sparse``) so hybrid search works out of the box.
"""

from __future__ import annotations

import atexit
import logging
from collections.abc import Iterable
from functools import lru_cache
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client import models as qm

from dfa.config import get_settings
from dfa.ingestion.schema import Chunk
from dfa.retrieval import sparse
from dfa.security import crypto

log = logging.getLogger(__name__)

DENSE = "dense"
SPARSE = "sparse"
EXTERNAL_COLLECTIONS = ("attack",)


def case_collection(case_id: str) -> str:
    return f"case_{case_id}"


class VectorStore:
    def __init__(self, dim: int | None = None) -> None:
        cfg = get_settings().vector_store
        self.local = not cfg.url
        if cfg.url:
            self.client = QdrantClient(url=cfg.url)
            log.info("qdrant server: %s", cfg.url)
        else:
            path = get_settings().resolve(cfg.path or "data/qdrant")
            path.mkdir(parents=True, exist_ok=True)
            self.client = QdrantClient(path=str(path))
            log.info("qdrant embedded: %s", path)
            atexit.register(self.close)  # flush + avoid the noisy __del__ during interpreter shutdown
        self._dim = dim

    @property
    def dim(self) -> int:
        """Embedding size; the embedder is loaded only when a collection has to be created."""
        if self._dim is None:
            from dfa.retrieval.embedder import get_embedder

            self._dim = get_embedder().dim
        return self._dim

    def close(self) -> None:
        try:
            self.client.close()
        except Exception as e:  # noqa: BLE001
            log.debug("qdrant close failed: %s", e)

    # ---- collections -------------------------------------------------
    def ensure_collection(self, name: str) -> None:
        if self.client.collection_exists(name):
            return
        self.client.create_collection(
            collection_name=name,
            vectors_config={DENSE: qm.VectorParams(size=self.dim, distance=qm.Distance.COSINE)},
            sparse_vectors_config={SPARSE: qm.SparseVectorParams(modifier=qm.Modifier.IDF)},
        )
        self.create_payload_indexes(name)
        log.info("created collection %s", name)

    def create_payload_indexes(self, name: str) -> None:
        """Keyword / integer indexes on the filterable payload fields (server only; a no-op in embedded mode)."""
        if self.local:
            return
        for field, schema in (
            ("granularity", qm.PayloadSchemaType.KEYWORD),
            ("host", qm.PayloadSchemaType.KEYWORD),
            ("user", qm.PayloadSchemaType.KEYWORD),
            ("source", qm.PayloadSchemaType.KEYWORD),
            ("category", qm.PayloadSchemaType.KEYWORD),
            ("ts", qm.PayloadSchemaType.INTEGER),
            ("attack_id", qm.PayloadSchemaType.KEYWORD),
        ):
            self.client.create_payload_index(name, field_name=field, field_schema=schema)

    def drop_collection(self, name: str) -> None:
        if self.client.collection_exists(name):
            self.client.delete_collection(name)

    def list_collections(self) -> list[str]:
        return [c.name for c in self.client.get_collections().collections]

    def count(self, name: str) -> int:
        if not self.client.collection_exists(name):
            return 0
        return self.client.count(name, exact=True).count

    # ---- write -------------------------------------------------------
    def upsert(self, chunks: Iterable[Chunk], dense_vectors: list[list[float]]) -> int:
        chunks = list(chunks)
        if not chunks:
            return 0
        by_collection: dict[str, list[qm.PointStruct]] = {}
        for chunk, vec in zip(chunks, dense_vectors, strict=True):
            idx, val = sparse.encode(chunk.text)
            payload: dict[str, Any] = {
                "text": chunk.text,
                "granularity": chunk.granularity.value,
                **chunk.metadata,
            }
            case_id = crypto.case_of_collection(chunk.collection)
            if case_id and crypto.is_encrypted(case_id):
                payload = crypto.encrypt_payload(case_id, payload)
            by_collection.setdefault(chunk.collection, []).append(
                qm.PointStruct(
                    id=chunk.chunk_id,
                    vector={DENSE: vec, SPARSE: qm.SparseVector(indices=idx, values=val)},
                    payload=payload,
                )
            )
        n = 0
        for name, points in by_collection.items():
            self.ensure_collection(name)
            for i in range(0, len(points), 256):
                self.client.upsert(name, points[i : i + 256], wait=True)
            n += len(points)
        return n

    # ---- read --------------------------------------------------------
    def hybrid_search(
        self,
        collection: str,
        query_text: str,
        query_vector: list[float],
        dense_k: int,
        sparse_k: int,
        rrf_k: int,
        limit: int,
        filters: qm.Filter | None = None,
    ) -> list[qm.ScoredPoint]:
        """Dense + sparse prefetch fused with Reciprocal Rank Fusion inside Qdrant."""
        if not self.client.collection_exists(collection):
            return []
        idx, val = sparse.encode(query_text)
        prefetch = [
            qm.Prefetch(query=query_vector, using=DENSE, limit=dense_k, filter=filters),
        ]
        if idx and get_settings().retrieval.sparse:
            prefetch.append(
                qm.Prefetch(
                    query=qm.SparseVector(indices=idx, values=val),
                    using=SPARSE,
                    limit=sparse_k,
                    filter=filters,
                )
            )
        res = self.client.query_points(
            collection_name=collection,
            prefetch=prefetch,
            query=qm.FusionQuery(fusion=qm.Fusion.RRF),
            limit=limit,
            with_payload=True,
        )
        return self._decrypt(collection, res.points)

    def get(self, collection: str, ids: list[str]) -> list[qm.Record]:
        return self._decrypt(collection, self.client.retrieve(collection, ids=ids, with_payload=True))

    @staticmethod
    def _decrypt(collection: str, points):
        case_id = crypto.case_of_collection(collection)
        if case_id:
            for p in points:
                if p.payload and p.payload.get("encrypted"):
                    p.payload = crypto.decrypt_payload(case_id, p.payload)
        return points


@lru_cache(maxsize=1)
def get_store() -> VectorStore:
    return VectorStore()
