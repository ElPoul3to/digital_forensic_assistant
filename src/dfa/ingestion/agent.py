"""Ingestion agent.

Walks any set of paths, sniffs each file's real format (magic bytes /
content), unpacks containers (gzip, bz2, xz, zip, tar), dispatches to the
matching parser and reports what could and could not be handled.
"""

from __future__ import annotations

import bz2
import gzip
import logging
import lzma
import shutil
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from dfa.ingestion import progress
from dfa.ingestion.detect import Detection, detect
from dfa.ingestion.parsers.base import ParseContext, load_all, parser_for
from dfa.ingestion.schema import Event
from dfa.ingestion.triage import triage

log = logging.getLogger(__name__)

MAX_ARCHIVE_DEPTH = 3


@dataclass
class FileReport:
    path: str
    detection: Detection
    events: int = 0
    status: str = "pending"  # parsed | unsupported | error | skipped
    error: str | None = None


@dataclass
class IngestReport:
    files: list[FileReport] = field(default_factory=list)

    @property
    def events(self) -> int:
        return sum(f.events for f in self.files)

    def by_status(self, status: str) -> list[FileReport]:
        return [f for f in self.files if f.status == status]


def _walk(paths: list[Path]) -> Iterator[Path]:
    for p in paths:
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file():
                    yield f
        elif p.is_file():
            yield p
        else:
            log.warning("skipping %s (not found)", p)


def _unpack(path: Path, det: Detection, workdir: Path) -> list[Path]:
    """Extract a container into workdir and return the extracted file paths."""
    out = workdir / path.name.replace(".", "_")
    out.mkdir(parents=True, exist_ok=True)
    try:
        if det.container in ("gzip", "bz2", "xz"):
            opener = {"gzip": gzip.open, "bz2": bz2.open, "xz": lzma.open}[det.container]
            target = out / (path.stem if path.suffix in (".gz", ".bz2", ".xz") else path.name + ".out")
            with opener(path, "rb") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            return [target]
        if det.container == "zip":
            with zipfile.ZipFile(path) as z:
                z.extractall(out)
        elif det.container == "tar":
            with tarfile.open(path) as t:
                t.extractall(out, filter="data")
        else:
            return []
    except Exception as e:  # noqa: BLE001
        log.warning("failed to unpack %s: %s", path, e)
        return []
    return [f for f in sorted(out.rglob("*")) if f.is_file()]


class IngestionAgent:
    def __init__(self, case_id: str, host_hint: str | None = None, year_hint: int | None = None, triage: bool = True) -> None:
        load_all()
        self.ctx = ParseContext(case_id=case_id, host_hint=host_hint, year_hint=year_hint)
        self.report = IngestReport()
        self.triage = triage  # skip known-noise files of full disk / triage collections (see triage.py)

    def detect_all(self, paths: list[Path]) -> list[tuple[Path, Detection]]:
        return [(p, detect(p)) for p in _walk(paths)]

    def events(self, paths: list[Path]) -> Iterator[Event]:
        self._roots = [p.resolve() for p in paths]
        files = list(_walk(paths))
        progress.say("ingest: %d files under %s", len(files), ", ".join(str(p) for p in paths))
        t0 = time.time()
        with tempfile.TemporaryDirectory(prefix="dfa_ingest_") as tmp:
            yield from self._process(files, Path(tmp), depth=0, display_prefix="")
        progress.say("ingest: parsed %d events from %d files in %.0fs (%d skipped, %d unsupported, %d errors)",
                     self.report.events, len(self.report.by_status("parsed")), time.time() - t0,
                     len(self.report.by_status("skipped")), len(self.report.by_status("unsupported")), len(self.report.by_status("error")))

    def _short(self, f: Path, display_prefix: str) -> str:
        """Path relative to the ingested root, for progress lines."""
        if display_prefix:
            return f"{display_prefix}{f.name}"
        rf = f.resolve()
        for r in getattr(self, "_roots", []):
            if rf == r:
                return f.name
            if rf.is_relative_to(r):
                return str(rf.relative_to(r))
        return str(f)

    def _process(self, files: list[Path], workdir: Path, depth: int, display_prefix: str) -> Iterator[Event]:
        total = len(files)
        for i, f in enumerate(files, 1):
            display = f"{display_prefix}{f}"
            short = self._short(f, display_prefix)
            tag = f"[{i}/{total}] {short}"
            try:
                det = detect(f)
            except Exception as e:  # noqa: BLE001 - one odd file must not abort the whole ingest
                log.warning("detection failed on %s: %s", f, e)
                det = Detection("unreadable", 1.0, f"detection failed: {type(e).__name__}: {e}")
            rep = FileReport(path=display, detection=det)
            self.report.files.append(rep)

            if det.kind in ("empty", "unreadable", "directory"):
                rep.status = "skipped"
                rep.error = det.description
                progress.detail("%s: skipped (%s)", tag, det.description)
                continue
            if self.triage and (skip := triage(f, det)):
                rep.status, rep.error = "skipped", skip.reason
                progress.detail("%s: skipped (%s)", tag, skip.reason)
                continue

            if det.container:
                if depth >= MAX_ARCHIVE_DEPTH:
                    rep.status, rep.error = "skipped", "archive nesting too deep"
                    progress.detail("%s: skipped (archive nesting too deep)", tag)
                    continue
                inner = _unpack(f, det, workdir / f"d{depth}")
                rep.status = "parsed" if inner else "error"
                rep.error = None if inner else "could not unpack"
                progress.say("%s: %s, unpacked %d files", tag, det.description, len(inner))
                yield from self._process(inner, workdir, depth + 1, f"{display}!/")
                continue

            parser = parser_for(det.kind)
            if parser is None:
                rep.status = "unsupported"
                progress.detail("%s: %s, no parser", tag, det.description)
                continue
            try:
                size = f.stat().st_size
            except OSError:
                size = 0
            progress.say("%s: %s, %s", tag, det.description, progress.human_size(size))
            t0 = time.time()
            try:
                for ev in parser.parse(f, self.ctx):
                    rep.events += 1
                    yield ev
                rep.status = "parsed"
                progress.say("    -> %d events in %.1fs", rep.events, time.time() - t0)
            except Exception as e:
                log.exception("parser %s failed on %s", det.kind, f)
                rep.status, rep.error = "error", f"{type(e).__name__}: {e}"
                progress.say("    -> failed after %d events: %s", rep.events, rep.error)
