"""Contextual window chunks over normalised events.

Events are grouped by (host, source_file), sorted by time, and windowed into
blocks of at most ``window_events`` events or ``window_seconds`` seconds.  Each
window gets a self-describing header so it embeds well on its own.  Events
without a timestamp are windowed by count only.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import timedelta

from dfa.config import get_settings
from dfa.ingestion.schema import Chunk, Event, Granularity


def _header(events: list[Event]) -> str:
    first, last = events[0], events[-1]
    host = first.host or "unknown-host"
    span = f"{first.ts_iso} .. {last.ts_iso}" if first.timestamp else "no timestamps"
    cats = Counter(e.category.value for e in events)
    top = ", ".join(f"{c}×{n}" for c, n in cats.most_common(3))
    users = sorted({e.user for e in events if e.user})[:5]
    ips = sorted({ip for e in events for ip in e.ioc.ip})[:8]
    parts = [f"host={host}", f"source={first.source.value}:{first.source_file}", f"time={span}", f"events={len(events)}", f"categories={top}"]
    if users:
        parts.append("users=" + ",".join(users))
    if ips:
        parts.append("ips=" + ",".join(ips))
    return "## " + " | ".join(parts)


def window_events(events: Iterable[Event], collection: str) -> Iterator[Chunk]:
    cfg = get_settings().chunking
    groups: dict[tuple[str | None, str], list[Event]] = {}
    for ev in events:
        groups.setdefault((ev.host, ev.source_file), []).append(ev)
    for evs in groups.values():
        evs.sort(key=lambda e: (e.timestamp is None, e.timestamp or 0, e.record_ref))
        cur: list[Event] = []
        for ev in evs:
            if cur:
                too_many = len(cur) >= cfg.window_events
                too_long = (
                    ev.timestamp is not None and cur[0].timestamp is not None
                    and ev.timestamp - cur[0].timestamp > timedelta(seconds=cfg.window_seconds)
                )
                if too_many or too_long:
                    yield _emit(cur, collection)
                    cur = []
            cur.append(ev)
        if cur:
            yield _emit(cur, collection)


def _emit(events: list[Event], collection: str) -> Chunk:
    lines = [_header(events)] + [f"[{e.ts_iso}] {e.summary}" for e in events]
    first, last = events[0], events[-1]
    key = f"win|{first.host}|{first.source_file}|{first.record_ref}|{last.record_ref}"
    return Chunk(
        chunk_id=Chunk.make_id(collection, key),
        collection=collection,
        text="\n".join(lines),
        granularity=Granularity.WINDOW,
        metadata={
            "case_id": first.case_id,
            "host": first.host,
            "source": first.source.value,
            "source_file": first.source_file,
            "ts": int(first.timestamp.timestamp()) if first.timestamp else None,
            "ts_end": int(last.timestamp.timestamp()) if last.timestamp else None,
            "ts_iso": first.ts_iso,
            "record_ref": f"{first.record_ref} .. {last.record_ref}",
            "event_ids": [e.stable_id() for e in events],
            "n_events": len(events),
            "category": Counter(e.category.value for e in events).most_common(1)[0][0],
            "users": sorted({e.user for e in events if e.user}),
            "ips": sorted({ip for e in events for ip in e.ioc.ip}),
        },
    )
