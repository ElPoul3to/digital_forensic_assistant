"""Delimited text (CSV / TSV / W3C) with automatic field mapping."""

from __future__ import annotations

import csv
import logging
from collections.abc import Iterator
from pathlib import Path

from dfa.ingestion.detect import detect
from dfa.ingestion.fieldmap import guess_fields, record_to_event
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Event, Source

log = logging.getLogger(__name__)
SAMPLE = 200
csv.field_size_limit(10_000_000)


def _w3c_rows(path: Path) -> Iterator[tuple[int, dict]]:
    fields: list[str] | None = None
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\r\n")
            if line.startswith("#Fields:"):
                fields = line.split(":", 1)[1].split()
                continue
            if line.startswith("#") or not line.strip() or fields is None:
                continue
            vals = line.split(" ") if "\t" not in line else line.split("\t")
            row = dict(zip(fields, vals))
            if "date" in row and "time" in row:
                row["datetime"] = f"{row['date']} {row['time']}"
            yield n, row


def _csv_rows(path: Path, delimiter: str) -> Iterator[tuple[int, dict]]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh, delimiter=delimiter)
        for n, row in enumerate(reader, 2):
            yield n, {k: v for k, v in row.items() if k is not None}


class CSVParser:
    kinds = ("csv", "w3c", "zeek")

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        det = detect(path)
        if det.kind == "w3c":
            rows = _w3c_rows(path)
        elif det.kind == "zeek":
            rows = _zeek_rows(path)
        else:
            rows = _csv_rows(path, det.details.get("delimiter", ","))
        buffered: list[tuple[int, dict]] = []
        fm = None
        for n, row in rows:
            raw = "|".join(str(v) for v in row.values())
            if fm is None:
                buffered.append((n, row))
                if len(buffered) < SAMPLE:
                    continue
                fm = guess_fields(r for _, r in buffered)
                log.info("%s: field map %s", path.name, fm.describe())
                for bn, br in buffered:
                    yield record_to_event(br, fm, case_id=ctx.case_id, source=Source.CSV, source_file=path.name, record_ref=f"line {bn}", host_hint=ctx.host_hint, raw="|".join(str(v) for v in br.values()))
                buffered = []
                continue
            yield record_to_event(row, fm, case_id=ctx.case_id, source=Source.CSV, source_file=path.name, record_ref=f"line {n}", host_hint=ctx.host_hint, raw=raw)
        if fm is None and buffered:
            fm = guess_fields(r for _, r in buffered)
            log.info("%s: field map %s", path.name, fm.describe())
            for bn, br in buffered:
                yield record_to_event(br, fm, case_id=ctx.case_id, source=Source.CSV, source_file=path.name, record_ref=f"line {bn}", host_hint=ctx.host_hint, raw="|".join(str(v) for v in br.values()))


def _zeek_rows(path: Path) -> Iterator[tuple[int, dict]]:
    fields: list[str] | None = None
    sep = "\t"
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\r\n")
            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
                continue
            if line.startswith("#fields"):
                fields = line.split(sep)[1:]
                continue
            if line.startswith("#") or not line.strip() or fields is None:
                continue
            yield n, dict(zip(fields, line.split(sep)))


register(CSVParser())
