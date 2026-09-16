"""dmesg (relative kernel timestamps) and dpkg package logs."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from dfa.ingestion import ioc
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Category, Event, Source

_DMESG = re.compile(r"^\[ *(?P<uptime>\d+\.\d+)\] (?P<msg>.*)$")
_DPKG = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<action>\S+) (?P<rest>.*)$")


class DmesgParser:
    kinds = ("dmesg",)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                if not line.strip():
                    continue
                m = _DMESG.match(line)
                msg = m["msg"] if m else line
                uptime = float(m["uptime"]) if m else None
                yield Event(
                    case_id=ctx.case_id, timestamp=None, source=Source.DMESG, source_file=path.name,
                    record_ref=f"line {n}", host=ctx.host_hint, process="kernel", category=Category.KERNEL,
                    ioc=ioc.extract(msg), summary=f"kernel (+{uptime:.3f}s): {msg}" if uptime is not None else f"kernel: {msg}",
                    raw=line[:4000], extra={"uptime_s": uptime},
                )


class DpkgParser:
    kinds = ("dpkg",)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                m = _DPKG.match(line)
                if not m:
                    continue
                ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
                action, rest = m["action"], m["rest"]
                if action == "status":
                    parts = rest.split(" ", 2)
                    state, pkg = parts[0], parts[1] if len(parts) > 1 else "?"
                    summary = f"dpkg status {state}: {pkg}"
                    action = f"pkg_status_{state}"
                elif action in ("install", "upgrade", "remove", "purge", "configure", "trigproc"):
                    pkg = rest.split(" ", 1)[0]
                    summary = f"dpkg {action}: {pkg} ({rest})"
                    action = f"pkg_{action}"
                else:
                    summary = f"dpkg {action}: {rest}"
                    action = f"pkg_{action}"
                yield Event(
                    case_id=ctx.case_id, timestamp=ts, source=Source.DPKG, source_file=path.name,
                    record_ref=f"line {n}", host=ctx.host_hint, process="dpkg", category=Category.PACKAGE,
                    action=action, ioc=ioc.extract(rest), summary=summary[:1000], raw=line[:4000],
                )


register(DmesgParser())
register(DpkgParser())
