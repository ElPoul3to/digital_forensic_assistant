"""Append-only audit log: one JSON line per question, per case (chain-of-custody friendly).

Records what was asked, how it was routed, which records were shown to the model
(file + record reference), the SQL that was executed and a hash of the answer,
so an analyst can later show exactly which evidence a conclusion rested on.
Written to ``data/audit/<case>.jsonl``; never overwritten by the tool.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dfa.config import get_settings
from dfa.security import crypto

log = logging.getLogger(__name__)


def audit_path(case_id: str) -> Path:
    return get_settings().data_dir / "audit" / f"{case_id}.jsonl"


def record(case_id: str, answer, *, interface: str = "cli", latency_s: float | None = None, user: str | None = None) -> Path | None:
    """Append the audit entry for ``answer`` (dfa.generation.answer.Answer)."""
    if not get_settings().audit.enabled:
        return None
    try:
        path = audit_path(case_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        entry: dict[str, Any] = {
            "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "case": case_id,
            "user": user or os.environ.get("USER") or os.environ.get("USERNAME"),
            "interface": interface,
            "question": answer.question,
            "route": answer.route,
            "route_reason": answer.route_reason,
            "filters": answer.filters,
            "queries": answer.queries,
            "hops": getattr(answer, "hops", []),
            "timeline_query": {k: (answer.timeline_query or {}).get(k) for k in ("sql", "total", "error")} if answer.timeline_query else None,
            "retrieved": [_ref(c) for c in answer.retrieved],
            "cited": [c["label"] for c in answer.citations],
            "invalid_citations": answer.invalid_citations,
            "attack_techniques": answer.attack_techniques,
            "answer_sha256": hashlib.sha256(answer.answer.encode("utf-8")).hexdigest(),
            "answer_chars": len(answer.answer),
            "latency_s": latency_s,
        }
        if get_settings().audit.store_answer:
            entry["answer"] = answer.answer
        line = json.dumps(entry, ensure_ascii=False, default=str)
        key = crypto.case_key(case_id)
        if key:
            line = crypto.encrypt_str(key, line)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return path
    except Exception as e:  # noqa: BLE001  never break an answer because of the log
        log.warning("audit log failed: %s", e)
        return None


def _ref(c: dict[str, Any]) -> dict[str, Any]:
    if c.get("kind") == "evidence":
        return {"label": c["label"], "kind": "evidence", "source_file": c.get("source_file"), "record_ref": c.get("record_ref"),
                "ts": c.get("ts"), "rerank": c.get("rerank")}
    if c.get("kind") == "timeline":
        return {"label": c["label"], "kind": "timeline", "sql": c.get("sql"), "rows": c.get("rows")}
    return {"label": c["label"], "kind": c.get("kind"), "id": c.get("id"), "name": c.get("name")}


def read(case_id: str, limit: int = 50) -> list[dict[str, Any]]:
    p = audit_path(case_id)
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").splitlines()
    key = crypto.case_key(case_id)
    out = []
    for ln in lines[-limit:]:
        if not ln.strip():
            continue
        if crypto.is_token(ln):
            if not key:
                raise RuntimeError(f"audit log of case {case_id} is encrypted and no key is available")
            ln = crypto.decrypt_str(key, ln)
        out.append(json.loads(ln))
    return out
