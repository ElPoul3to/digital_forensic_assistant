"""Hybrid retrieval + RRF across rewritten queries + cross-encoder reranking + timeline enrichment."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from qdrant_client import models as qm

from dfa.config import get_settings
from dfa.retrieval.store import case_collection, get_store
from dfa.router.router import Filters, Route

log = logging.getLogger(__name__)


@dataclass
class Hit:
    id: str
    collection: str
    text: str
    payload: dict[str, Any]
    score: float  # fused score
    rerank: float | None = None
    neighbours: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_external(self) -> bool:
        return not self.collection.startswith("case_")


@dataclass
class RetrievalResult:
    evidence: list[Hit]
    attack: list[Hit]
    queries: list[str]


def _qdrant_filter(f: Filters) -> qm.Filter | None:
    must: list[qm.Condition] = []
    if f.host:
        must.append(qm.FieldCondition(key="host", match=qm.MatchValue(value=f.host)))
    if f.user:
        must.append(qm.FieldCondition(key="user", match=qm.MatchValue(value=f.user)))
    if f.ts_from or f.ts_to:
        must.append(qm.FieldCondition(key="ts", range=qm.Range(
            gte=int(f.ts_from.timestamp()) if f.ts_from else None,
            lte=int(f.ts_to.timestamp()) if f.ts_to else None,
        )))
    return qm.Filter(must=must) if must else None


def _search_collection(collection: str, queries: list[str], vectors: list[list[float]], limit: int,
                       filters: qm.Filter | None) -> list[Hit]:
    """Run hybrid search for every query variant and fuse the lists with RRF."""
    cfg = get_settings().retrieval
    store = get_store()
    fused: dict[str, Hit] = {}
    for q, v in zip(queries, vectors, strict=True):
        pts = store.hybrid_search(collection, q, v, dense_k=cfg.dense_k, sparse_k=cfg.bm25_k, rrf_k=cfg.rrf_k, limit=limit, filters=filters)
        for rank, p in enumerate(pts):
            pid = str(p.id)
            h = fused.get(pid)
            if h is None:
                h = fused[pid] = Hit(id=pid, collection=collection, text=p.payload["text"], payload=p.payload, score=0.0)
            h.score += 1.0 / (cfg.rrf_k + rank + 1)
    return sorted(fused.values(), key=lambda h: -h.score)[:limit]


def _rerank(query: str, hits: list[Hit], keep: int) -> list[Hit]:
    if not hits:
        return []
    if not get_settings().retrieval.rerank:  # baseline: fused order only
        return sorted(hits, key=lambda h: -h.score)[:keep]
    from dfa.retrieval.reranker import get_reranker

    scores = get_reranker().score(query, [h.text for h in hits])
    for h, s in zip(hits, scores):
        h.rerank = s
    return sorted(hits, key=lambda h: -(h.rerank or 0))[:keep]


_NUM = re.compile(r"\d+")
_WS = re.compile(r"\s+")


def _shape(text: str) -> str:
    """Near-duplicate key: same line with every number masked (IPs, ports, timestamps, sizes, pids)."""
    return _WS.sub(" ", _NUM.sub("0", text.lower())).strip()[:400]


def collapse_duplicates(hits: list[Hit], per_shape: int) -> list[Hit]:
    """Keep at most ``per_shape`` candidates per line shape, best fused score first.

    Brute-force noise (thousands of near-identical failed logins, repeated probes) otherwise fills
    the whole candidate list and the reranker never sees the one different line that answers the question.
    """
    if per_shape <= 0:
        return hits
    seen: dict[str, int] = {}
    out: list[Hit] = []
    for h in sorted(hits, key=lambda h: -h.score):
        k = _shape(h.text) if h.payload.get("granularity") == "event" else h.id
        n = seen.get(k, 0)
        if n < per_shape:
            seen[k] = n + 1
            out.append(h)
    return out


def _ip_boost(hits: list[Hit], ip: str | None) -> None:
    """An IP given explicitly in the question is a strong exact-match signal."""
    if not ip:
        return
    for h in hits:
        if ip in h.text:
            h.score += 0.05


def retrieve(case_id: str, question: str, route: Route, filters: Filters, queries: list[str] | None = None,
             enrich: bool = True) -> RetrievalResult:
    from dfa.retrieval.embedder import get_embedder

    cfg = get_settings().retrieval
    queries = queries or [question]
    vectors = get_embedder().embed_queries(queries)
    qf = _qdrant_filter(filters)

    evidence: list[Hit] = []
    if route.evidence:
        limit = max(cfg.dense_k, cfg.bm25_k)
        cand = _search_collection(case_collection(case_id), queries, vectors, limit=limit, filters=None)
        if qf is not None:
            # Filters come from regex heuristics over the question, so they boost rather than exclude:
            # filtered hits are merged with the unfiltered candidates and get a score bonus.
            seen = {h.id: h for h in cand}
            for h in _search_collection(case_collection(case_id), queries, vectors, limit=limit, filters=qf):
                if h.id in seen:
                    seen[h.id].score += 0.02
                else:
                    h.score += 0.02
                    cand.append(h)
                    seen[h.id] = h
        _ip_boost(cand, filters.ip)
        cand = collapse_duplicates(cand, cfg.dedup_per_shape)
        evidence = _rerank(question, cand, cfg.rerank_keep_evidence)

    attack: list[Hit] = []
    if route.attack:
        cand = _search_collection("attack", queries, vectors, limit=30, filters=None)
        if filters.ids:  # explicitly mentioned technique ids always come along
            store = get_store()
            for aid in filters.ids:
                pts, _ = store.client.scroll("attack", scroll_filter=qm.Filter(must=[qm.FieldCondition(key="attack_id", match=qm.MatchValue(value=aid))]), limit=1, with_payload=True) if store.client.collection_exists("attack") else ([], None)
                for p in pts:
                    if str(p.id) not in {h.id for h in cand}:
                        cand.append(Hit(id=str(p.id), collection="attack", text=p.payload["text"], payload=p.payload, score=1.0))
        attack = _rerank(question, cand, cfg.rerank_keep_external)

    if enrich and evidence:
        _enrich(case_id, evidence, cfg.timeline_neighbours)
    return RetrievalResult(evidence=evidence, attack=attack, queries=queries)


def _enrich(case_id: str, hits: list[Hit], n: int) -> None:
    from dfa.timeline.store import get_timeline

    tl = get_timeline(case_id)
    for h in hits:
        if h.payload.get("granularity") == "event" and (eid := h.payload.get("event_id")):
            try:
                h.neighbours = [r for r in tl.neighbours(eid, n=n) if r["event_id"] != eid]
            except Exception as e:  # noqa: BLE001
                log.debug("neighbour lookup failed: %s", e)
