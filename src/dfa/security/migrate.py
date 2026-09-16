"""Turn encryption on for an existing case, in place (``dfa case encrypt``)."""

from __future__ import annotations

import logging
from typing import Any

import duckdb

from dfa.config import get_settings
from dfa.generation.audit import audit_path
from dfa.security import crypto

log = logging.getLogger(__name__)


def _encrypt_timeline(case_id: str, key_hex: str) -> bool:
    from dfa.timeline.store import _DDL

    path = get_settings().timeline_dir / f"{case_id}.duckdb"
    if not path.exists():
        return False
    tmp = path.with_suffix(".duckdb.enc")
    if tmp.exists():
        tmp.unlink()
    conn = duckdb.connect()
    conn.execute(f"ATTACH '{path}' AS src (READ_ONLY)")
    conn.execute(f"ATTACH '{tmp}' AS dst (ENCRYPTION_KEY '{key_hex}')")
    conn.execute("USE dst")
    conn.execute(_DDL)
    conn.execute("INSERT INTO dst.events SELECT * FROM src.events")
    n = conn.execute("SELECT count(*) FROM dst.events").fetchone()[0]
    conn.execute("USE memory")
    conn.execute("DETACH dst")
    conn.execute("DETACH src")
    conn.close()
    wal = path.with_suffix(".duckdb.wal")
    if wal.exists():
        wal.unlink()
    tmp.replace(path)
    log.info("timeline of %s re-encrypted (%d events)", case_id, n)
    return True


def _encrypt_points(case_id: str) -> int:
    from dfa.retrieval.store import case_collection, get_store

    store = get_store()
    coll = case_collection(case_id)
    if not store.client.collection_exists(coll):
        return 0
    n = 0
    offset = None
    while True:
        points, offset = store.client.scroll(coll, limit=512, offset=offset, with_payload=True, with_vectors=False)
        for p in points:
            if p.payload and not p.payload.get("encrypted"):
                store.client.set_payload(coll, payload=crypto.encrypt_payload(case_id, p.payload), points=[p.id], wait=True)
                n += 1
        if offset is None:
            break
    return n


def _encrypt_audit(case_id: str, key: bytes) -> int:
    p = audit_path(case_id)
    if not p.exists():
        return 0
    lines = p.read_text(encoding="utf-8").splitlines()
    out = [ln if crypto.is_token(ln) or not ln.strip() else crypto.encrypt_str(key, ln) for ln in lines]
    p.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")
    return sum(1 for a, b in zip(lines, out, strict=True) if a != b)


def encrypt_case(case_id: str) -> dict[str, Any]:
    crypto.create_case_key(case_id)
    key = crypto.case_key(case_id)
    assert key is not None
    return {"key": str(crypto.key_path(case_id)), "timeline": _encrypt_timeline(case_id, key.hex()), "points": _encrypt_points(case_id),
            "audit": _encrypt_audit(case_id, key)}
