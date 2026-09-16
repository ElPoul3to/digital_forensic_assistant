"""Multi-hop retrieval: a second round of lookups for facts the first round could not reach.

Questions such as "creation time of the parent of powershell.exe" need a record (the parent
process row) that shares no words with the question: the first retrieval finds the child, which
names the parent's PID, but the reranker scores the parent row low against the original question.
After the first context is built, the model is asked whether the context is sufficient and, if not,
which follow-up lookups are needed, phrased with the exact identifiers it saw (PIDs, IPs, hashes,
users, file names).  Each follow-up is retrieved and reranked against its own text and the new hits
are merged into the context before the answer is generated.  Bounded by ``retrieval.hops`` rounds
and ``retrieval.hop_followups`` lookups per round.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from typing import Any

from dfa.config import get_settings
from dfa.retrieval.retriever import RetrievalResult, retrieve
from dfa.router.router import Filters, Route

log = logging.getLogger(__name__)

_PROMPT = """You check whether the retrieved CONTEXT is enough to answer an incident-response analyst's question, \
and if not, which follow-up lookups would retrieve the missing records.

CONTEXT:
{ctx}

QUESTION: {q}

Rules:
- If the CONTEXT already holds every fact the answer needs, reply {{"complete": true, "followups": []}}.
- Otherwise list up to {n} follow-up lookups. Each "query" is a short search string in raw-log vocabulary that \
would retrieve the missing record, built from exact identifiers that appear in the CONTEXT: PIDs and PPIDs, IPs, \
ports, hashes, users, hostnames, file names, event ids, service names. Example: the question asks about the \
parent of a process and the CONTEXT shows "PPID=4352" -> {{"query": "pslist PID 4352 ImageFileName CreateTime", \
"why": "row of the parent process 4352"}}.
- Do not repeat the original question; do not ask for records that are already in the CONTEXT.
JSON only: {{"complete": false, "followups": [{{"query": "...", "why": "..."}}]}}"""


@dataclass
class Hop:
    query: str
    why: str
    added: int = 0  # evidence hits merged into the context from this lookup

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def plan_followups(question: str, ctx_text: str, n: int) -> list[Hop]:
    """Ask the model which lookups are missing; [] when the context is complete or the reply is unusable."""
    from dfa.generation.llm import get_llm

    try:
        raw = get_llm().complete(_PROMPT.format(ctx=ctx_text, q=question, n=n), max_tokens=300)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        data = json.loads(m.group(0)) if m else {}
    except Exception as e:  # noqa: BLE001
        log.warning("follow-up planning failed, single hop only: %s", e)
        return []
    if data.get("complete") or not isinstance(data.get("followups"), list):
        return []
    hops: list[Hop] = []
    for f in data["followups"][:n]:
        q = (f.get("query") if isinstance(f, dict) else f) if f else None
        if isinstance(q, str) and q.strip() and q.strip().lower() != question.strip().lower():
            hops.append(Hop(query=q.strip(), why=str(f.get("why", "") if isinstance(f, dict) else "")[:200]))
    return hops


def run_hops(case_id: str, question: str, filters: Filters, res: RetrievalResult, ctx_text: str) -> list[Hop]:
    """Plan follow-ups on the current context and merge their evidence into ``res`` (in place)."""
    cfg = get_settings().retrieval
    if cfg.hops <= 0:
        return []
    hops = plan_followups(question, ctx_text, cfg.hop_followups)
    seen = {h.id for h in res.evidence}
    for hop in hops:
        # reranked against the follow-up text, not the original question: that is the whole point
        r2 = retrieve(case_id, hop.query, Route.EVIDENCE_ONLY, filters, queries=[hop.query])
        for h in r2.evidence[: cfg.hop_keep]:
            if h.id not in seen:
                seen.add(h.id)
                res.evidence.append(h)
                hop.added += 1
        log.info("hop %r: %d new evidence hits (%s)", hop.query, hop.added, hop.why)
    return hops
