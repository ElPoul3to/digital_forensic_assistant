"""JSON and JSON-lines logs with automatic field mapping."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from dfa.ingestion.fieldmap import guess_fields, record_to_event
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Event, Source

log = logging.getLogger(__name__)
SAMPLE = 200
_LIST_KEYS = ("records", "events", "hits", "data", "logs", "items", "results", "entries", "value", "messages")


def _iter_jsonl(path: Path) -> Iterator[tuple[str, dict[str, Any], str]]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                log.debug("%s line %d: invalid JSON", path.name, n)
                continue
            if isinstance(obj, dict):
                yield f"line {n}", obj, line


def _iter_json(path: Path) -> Iterator[tuple[str, dict[str, Any], str]]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        doc = json.load(fh)
    items: list[Any]
    if isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        items = []
        lower = {k.lower(): k for k in doc}
        for k in _LIST_KEYS:
            v = doc.get(lower.get(k, k))
            if isinstance(v, dict) and isinstance(v.get("hits"), list):  # elasticsearch
                v = v["hits"]
            if isinstance(v, list):
                items = v
                break
        if not items:
            lists = [v for v in doc.values() if isinstance(v, list) and v and isinstance(v[0], dict)]
            items = max(lists, key=len) if lists else [doc]
    else:
        items = []
    for i, obj in enumerate(items):
        if isinstance(obj, dict):
            if "_source" in obj and isinstance(obj["_source"], dict):  # elasticsearch hit
                obj = obj["_source"]
            yield f"item {i}", obj, json.dumps(obj, separators=(",", ":"))


class JSONParser:
    kinds = ("jsonl", "json")

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        src = Source.JSON
        it = _iter_jsonl if _looks_jsonl(path) else _iter_json
        buffered: list[tuple[str, dict, str]] = []
        fm = None
        for ref, obj, raw in it(path):
            if fm is None:
                buffered.append((ref, obj, raw))
                if len(buffered) < SAMPLE:
                    continue
                fm = guess_fields(o for _, o, _ in buffered)
                log.info("%s: field map %s", path.name, fm.describe())
                for b in buffered:
                    yield record_to_event(b[1], fm, case_id=ctx.case_id, source=src, source_file=path.name, record_ref=b[0], host_hint=ctx.host_hint, raw=b[2])
                buffered = []
                continue
            yield record_to_event(obj, fm, case_id=ctx.case_id, source=src, source_file=path.name, record_ref=ref, host_hint=ctx.host_hint, raw=raw)
        if fm is None and buffered:
            fm = guess_fields(o for _, o, _ in buffered)
            log.info("%s: field map %s", path.name, fm.describe())
            for b in buffered:
                yield record_to_event(b[1], fm, case_id=ctx.case_id, source=src, source_file=path.name, record_ref=b[0], host_hint=ctx.host_hint, raw=b[2])


def _looks_jsonl(path: Path) -> bool:
    """JSONL = at least two lines that each parse as a JSON object (a one-line file is a document)."""
    lines: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                lines.append(line)
            if len(lines) >= 2:
                break
    if len(lines) < 2 or not all(ln.startswith("{") for ln in lines):
        return False
    try:
        return all(isinstance(json.loads(ln), dict) for ln in lines)
    except json.JSONDecodeError:
        return False


register(JSONParser())
