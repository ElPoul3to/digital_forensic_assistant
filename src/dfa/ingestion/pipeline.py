"""Event -> (timeline row, event chunk, window chunk) -> embed -> store."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable

from dfa.ingestion import progress
from dfa.ingestion.chunker import window_events
from dfa.ingestion.schema import Chunk, Event, Granularity
from dfa.retrieval.embedder import get_embedder
from dfa.retrieval.store import case_collection, get_store
from dfa.timeline.store import get_timeline

log = logging.getLogger(__name__)

BATCH = 512
WINDOW_FLUSH = 5000  # events buffered before windowing (windows never span a flush boundary)


def event_to_chunk(ev: Event, collection: str) -> Chunk:
    ts = int(ev.timestamp.timestamp()) if ev.timestamp else None
    return Chunk(
        chunk_id=Chunk.make_id(collection, ev.stable_id()),
        collection=collection,
        text=f"[{ev.ts_iso}] {ev.host or '?'} {ev.source.value}: {ev.summary}",
        granularity=Granularity.EVENT,
        metadata={
            "event_id": ev.stable_id(),
            "case_id": ev.case_id,
            "ts": ts,
            "ts_iso": ev.ts_iso,
            "source": ev.source.value,
            "source_file": ev.source_file,
            "record_ref": ev.record_ref,
            "host": ev.host,
            "user": ev.user,
            "process": ev.process,
            "category": ev.category.value,
            "action": ev.action,
            "ioc": ev.ioc.model_dump(),
            "raw": ev.raw[:4000],
        },
    )


def index_events(case_id: str, events: Iterable[Event], windows: bool = True) -> dict[str, int]:
    progress.say("loading embedding model ...")
    emb = get_embedder()
    store = get_store()
    tl = get_timeline(case_id)
    coll = case_collection(case_id)
    store.ensure_collection(coll)
    progress.say("indexing into %s (%s) and timeline %s", coll, "qdrant server" if not store.local else "embedded qdrant", case_id)
    n_events = n_chunks = n_batches = 0
    t_start = time.time()
    batch: list[Chunk] = []
    pending_events: list[Event] = []

    def flush_chunks() -> None:
        nonlocal n_chunks, n_batches
        if not batch:
            return
        vecs = emb.embed_documents([c.text for c in batch])
        n_chunks += store.upsert(batch, vecs)
        n_batches += 1
        if n_batches % 10 == 0:
            rate = n_chunks / max(time.time() - t_start, 1e-6)
            progress.say("    indexed %d chunks from %d events (%.0f chunks/s)", n_chunks, n_events, rate)
        log.debug("indexed %d chunks (total %d)", len(batch), n_chunks)
        batch.clear()

    def flush_events() -> None:
        if not pending_events:
            return
        tl.insert(pending_events)
        if windows:
            for w in window_events(pending_events, coll):
                batch.append(w)
                if len(batch) >= BATCH:
                    flush_chunks()
        pending_events.clear()

    for ev in events:
        n_events += 1
        batch.append(event_to_chunk(ev, coll))
        pending_events.append(ev)
        if len(batch) >= BATCH:
            flush_chunks()
        if len(pending_events) >= WINDOW_FLUSH:
            flush_events()
    flush_events()
    flush_chunks()
    progress.say("indexed %d chunks from %d events in %.0fs", n_chunks, n_events, time.time() - t_start)
    return {"events": n_events, "chunks": n_chunks}
