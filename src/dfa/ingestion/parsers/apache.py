"""Apache / Nginx access (common & combined) and Apache error logs."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from dfa.ingestion import ioc
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Category, Event, Source

_ACCESS = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?(?P<tail>.*)$'
)
_ERROR = re.compile(
    r"^\[(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[(?P<level>[^\]]+)\]"
    r"(?: \[pid (?P<pid>[^\]]+)\])?(?: \[client (?P<client>[^\]]+)\])? (?P<msg>.*)$"
)
_SUSPICIOUS = re.compile(r"(\.\./|/etc/passwd|union\s+select|<script|cmd=|/bin/sh|wget\s|curl\s|\.php\?|%00|base64_decode|eval\()", re.IGNORECASE)


def _parse_access_ts(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


class ApacheAccessParser:
    kinds = ("apache_access",)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                m = _ACCESS.match(line)
                if not m:
                    if line.strip():
                        yield Event(case_id=ctx.case_id, source=Source.APACHE, source_file=path.name, record_ref=f"line {n}",
                                    host=ctx.host_hint, category=Category.WEB, summary=f"unparsed: {line[:300]}", raw=line[:4000])
                    continue
                req = m["req"].split(" ")
                method, target = (req[0], req[1]) if len(req) >= 2 else ("?", m["req"])
                status = int(m["status"])
                user = None if m["user"] == "-" else m["user"]
                flags = []
                if method == "CONNECT":
                    flags.append("proxy_scan")  # CONNECT through a web server = open-proxy scanner (e.g. pxyscand)
                elif re.match(r"https?://", target, re.IGNORECASE):
                    flags.append("open_proxy_probe")  # absolute URL to a foreign host = client testing us as a proxy
                if _SUSPICIOUS.search(target):
                    flags.append("suspicious_request")
                if status in (401, 403):
                    flags.append("access_denied")
                if method in ("POST", "PUT") and "upload" in target.lower():
                    flags.append("upload")
                summary = f"HTTP {method} {target} -> {status} from {m['ip']}"
                if m["ua"]:
                    summary += f' UA="{m["ua"][:120]}"'
                if user:
                    summary += f" user={user}"
                if flags:
                    summary += f" [{' '.join(flags)}]"
                ev_ioc = ioc.extract(summary)
                if m["ip"] not in ev_ioc.ip and not m["ip"].startswith("-"):
                    ev_ioc.ip.append(m["ip"])
                yield Event(
                    case_id=ctx.case_id, timestamp=_parse_access_ts(m["ts"]), source=Source.APACHE,
                    source_file=path.name, record_ref=f"line {n}", host=ctx.host_hint, user=user,
                    process="httpd", category=Category.WEB, action=f"http_{method.lower()}",
                    ioc=ev_ioc, summary=summary, raw=line[:4000],
                    extra={"status": status, "method": method, "path": target, "ua": m["ua"], "referer": m["referer"], "flags": flags},
                )


class ApacheErrorParser:
    kinds = ("apache_error",)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                m = _ERROR.match(line)
                if not m:
                    if line.strip():
                        yield Event(case_id=ctx.case_id, source=Source.APACHE, source_file=path.name, record_ref=f"line {n}",
                                    host=ctx.host_hint, category=Category.WEB, summary=f"unparsed: {line[:300]}", raw=line[:4000])
                    continue
                ts = None
                for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S.%f %Y"):
                    try:
                        ts = datetime.strptime(m["ts"], fmt).replace(tzinfo=__import__("datetime").timezone.utc)
                        break
                    except ValueError:
                        pass
                client = m["client"].split(":")[0] if m["client"] else None
                summary = f"httpd {m['level']}: {m['msg']}" + (f" (client {client})" if client else "")
                ev_ioc = ioc.extract(summary)
                if client and client not in ev_ioc.ip:
                    ev_ioc.ip.append(client)
                yield Event(
                    case_id=ctx.case_id, timestamp=ts, source=Source.APACHE, source_file=path.name,
                    record_ref=f"line {n}", host=ctx.host_hint, process="httpd", category=Category.WEB,
                    action=f"httpd_{m['level'].split(':')[-1]}", ioc=ev_ioc, summary=summary[:1000], raw=line[:4000],
                )


register(ApacheAccessParser())
register(ApacheErrorParser())
