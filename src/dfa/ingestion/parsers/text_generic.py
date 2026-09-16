"""Fallback parser: one event per non-empty line, best-effort timestamp."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from dfa.ingestion import ioc, timeutil
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Category, Event, Source

_LEADING_TS = re.compile(
    r"^\[?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\d{2}/\d{2}/\d{4}[ ,]+\d{2}:\d{2}:\d{2}"
    r"|\d{10}(?:\.\d+)?)\]?"
)


class GenericTextParser:
    kinds = ("text", "xml", "apt_term")

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        case_id, host_hint = ctx.case_id, ctx.host_hint
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                if not line.strip():
                    continue
                ts = None
                if m := _LEADING_TS.match(line):
                    ts = timeutil.parse_any(m.group(1))
                yield Event(
                    case_id=case_id, timestamp=ts, source=Source.OTHER, source_file=path.name,
                    record_ref=f"line {n}", host=host_hint, category=Category.OTHER,
                    ioc=ioc.extract(line), summary=f"{path.name}: {line[:500]}", raw=line[:4000],
                )


register(GenericTextParser())
