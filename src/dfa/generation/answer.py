"""End-to-end: route -> rewrite -> retrieve -> build context -> generate -> validate."""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from dfa.config import get_settings
from dfa.generation.audit import record as audit_record
from dfa.generation.citations import validate
from dfa.generation.llm import get_llm
from dfa.generation.prompts import SYSTEM, build_context, user_prompt
from dfa.retrieval.hops import run_hops
from dfa.retrieval.retriever import Hit, retrieve
from dfa.retrieval.rewriter import rewrite
from dfa.router.router import decide
from dfa.timeline.query import timeline_query

log = logging.getLogger(__name__)


@dataclass
class Answer:
    question: str
    answer: str
    route: str
    route_reason: str
    filters: dict[str, Any]
    queries: list[str]
    citations: list[dict[str, Any]]
    invalid_citations: list[str]
    retrieved: list[dict[str, Any]]
    attack_techniques: list[str]
    context: str = ""  # the full CONTEXT block sent to the LLM (for eval / drill-down)
    unverified_attack: list[str] = field(default_factory=list)  # ATT&CK ids named without an entry in context
    timeline_query: dict[str, Any] | None = None  # SQL + result of the structured query (aggregate questions)
    hops: list[dict[str, Any]] = field(default_factory=list)  # follow-up lookups of the multi-hop round (query, why, added)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def navigator_layer(self, case_id: str) -> dict[str, Any]:
        """ATT&CK Navigator layer (format 4.5) of the techniques cited in this answer."""
        from dfa.generation.navigator import LayerBuilder

        b = LayerBuilder(case_id)
        b.add(self)
        return b.build()


def _cite(label: str, h: Hit) -> dict[str, Any]:
    p = h.payload
    if h.collection == "timeline":
        return {"label": label, "kind": "timeline", "sql": p.get("sql"), "note": p.get("note"), "rows": p.get("total"), "rerank": None}
    if h.is_external:
        return {"label": label, "kind": h.collection, "id": p.get("attack_id"), "name": p.get("name") or p.get("title"),
                "source": p.get("source"), "url": p.get("url"), "rerank": h.rerank}
    return {"label": label, "kind": "evidence", "source_file": p.get("source_file"), "record_ref": p.get("record_ref"),
            "host": p.get("host"), "ts": p.get("ts_iso"), "granularity": p.get("granularity"), "raw": (p.get("raw") or h.text)[:500],
            "rerank": h.rerank}


def _messages(question: str, ctx_text: str, history: list[dict] | None) -> list[dict]:
    msgs = [{"role": "system", "content": SYSTEM}]
    msgs.extend((history or [])[-6:])
    msgs.append({"role": "user", "content": question if ctx_text is None else ctx_text})
    return msgs


def ask(case_id: str, question: str, route: str = "auto", history: list[dict] | None = None,
        use_rewriter: bool = True, stream_cb=None, interface: str = "cli", user: str | None = None) -> Answer:
    t0 = time.time()
    s = get_settings()
    dec = decide(question, route=route)
    tq = timeline_query(case_id, question) if dec.aggregate else None
    if tq is not None and not tq.ok:
        log.warning("timeline query skipped: %s", tq.error)
    queries = rewrite(question) if use_rewriter else [question]
    res = retrieve(case_id, question, dec.route, dec.filters, queries=queries)
    ctx = build_context(res, s.generation.max_context_tokens, structured=tq)
    hops = run_hops(case_id, question, dec.filters, res, ctx.text) if dec.route.evidence and res.evidence else []
    if any(h.added for h in hops):
        ctx = build_context(res, s.generation.max_context_tokens, structured=tq)
    msgs = _messages(question, user_prompt(question, ctx), history)

    llm = get_llm()
    if stream_cb:
        chunks: list[str] = []
        for tok in llm.stream(msgs):
            chunks.append(tok)
            stream_cb(tok)
        raw = "".join(chunks)
    else:
        raw = "".join(llm.stream(msgs))
    val = validate(raw, set(ctx.labels))
    cited = [_cite(lbl, ctx.labels[lbl]) for lbl in val.valid]
    ans = Answer(
        question=question, answer=val.answer, route=dec.route.value, route_reason=dec.reason,
        filters={k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in asdict(dec.filters).items() if v},
        queries=res.queries, citations=cited, invalid_citations=val.invalid,
        retrieved=[_cite(lbl, h) for lbl, h in ctx.labels.items()],
        attack_techniques=sorted({c["id"] for c in cited if c["kind"] == "attack" and c.get("id")}),
        context=ctx.text,
        unverified_attack=val.unverified_attack,
        timeline_query=tq.to_dict() if tq is not None else None,
        hops=[h.to_dict() for h in hops],
    )
    audit_record(case_id, ans, interface=interface, latency_s=round(time.time() - t0, 1), user=user)
    return ans
