"""Heuristic field mapping for record-oriented logs (JSON, CSV, ...).

Given sample records, guess which columns carry the timestamp, host, user,
process, message, event id and category, then turn each record into an Event.
Nested objects are flattened to dotted keys (``host.name``) first.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from dfa.ingestion import ioc, timeutil
from dfa.ingestion.schema import IOC, Category, Event, Source

_TS_KEYS = [
    "@timestamp", "timestamp", "datetime", "timecreated", "timecreated.systemtime", "event.created", "utctime",
    "eventtime", "event_time", "time", "_time", "date", "ts", "systemtime", "starttime",
    "timegenerated", "timestamp_utc", "eventreceivedtime", "creationtime", "created_at", "createdat",
    "logged_at", "occurred_at", "event.start", "receipt_time", "rt", "start", "eventdate",
]
_HOST_KEYS = ["host.name", "host.hostname", "hostname", "host", "computer", "computer_name", "computername",
              "agent.hostname", "winlog.computer_name", "system.computer", "device", "devicename", "dvchost",
              "src_host", "machine", "node"]
_USER_KEYS = ["user.name", "username", "user", "user_name", "subjectusername", "targetusername",
              "winlog.event_data.subjectusername", "winlog.event_data.targetusername", "account", "accountname",
              "useridentity.username", "useridentity.arn", "suser", "duser", "login", "logonname", "principal"]
_PROC_KEYS = ["process.name", "process.executable", "image", "processname", "process_name", "exe",
              "winlog.event_data.image", "newprocessname", "commandline", "process.command_line", "sourceimage"]
_MSG_KEYS = ["message", "msg", "event.original", "log", "log.original", "description", "text", "summary",
             "rendered_message", "event_description", "details", "raw", "line", "eventname", "activity"]
_EVENTID_KEYS = ["event.code", "eventid", "event_id", "winlog.event_id", "system.eventid", "eventcode", "id", "rule.name", "signature"]
_CAT_KEYS = ["event.category", "category", "event.kind", "event.action", "action", "logtype", "log_type", "eventtype", "type"]
_SRCIP_KEYS = ["source.ip", "src_ip", "srcip", "src", "sourceip", "sourceaddress", "ipaddress", "client_ip", "clientip",
               "remote_addr", "sourceipaddress", "c-ip", "id.orig_h"]
_DSTIP_KEYS = ["destination.ip", "dst_ip", "dstip", "dst", "destinationip", "destinationaddress", "server_ip", "id.resp_h"]

_CATEGORY_WORDS = {
    Category.AUTHENTICATION: ("authentication", "logon", "login", "auth", "signin", "sign-in", "credential"),
    Category.PROCESS: ("process", "execution", "command", "cmd"),
    Category.NETWORK: ("network", "connection", "dns", "http", "flow", "firewall", "traffic"),
    Category.FILE: ("file", "download", "write", "delete", "create"),
    Category.PRIVILEGE: ("privilege", "sudo", "escalat", "admin"),
    Category.PACKAGE: ("package", "install", "software"),
    Category.KERNEL: ("kernel", "driver"),
    Category.WEB: ("web", "iis", "apache", "nginx", "url"),
    Category.SERVICE: ("service", "daemon", "scheduled", "task"),
    Category.USER_MGMT: ("account", "user_mgmt", "group"),
}


@dataclass
class FieldMap:
    ts: str | None = None
    ts_hint: str | None = None
    host: str | None = None
    user: str | None = None
    process: str | None = None
    message: str | None = None
    event_id: str | None = None
    category: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    keys: list[str] = field(default_factory=list)

    def describe(self) -> str:
        return ", ".join(f"{k}={v}" for k, v in self.__dict__.items() if v and k != "keys")


def flatten(obj: Any, prefix: str = "", out: dict[str, Any] | None = None, depth: int = 0) -> dict[str, Any]:
    out = {} if out is None else out
    if isinstance(obj, dict) and depth < 6:
        for k, v in obj.items():
            if isinstance(v, dict):
                flatten(v, f"{prefix}{k}.", out, depth + 1)
            else:
                out[f"{prefix}{k}"] = v
    else:
        out[prefix.rstrip(".")] = obj
    return out


def _pick(keys_lower: dict[str, str], candidates: list[str]) -> str | None:
    for c in candidates:
        if c in keys_lower:
            return keys_lower[c]
    # suffix match: e.g. "winlog.event_data.TargetUserName"
    for c in candidates:
        for kl, orig in keys_lower.items():
            if kl.endswith("." + c):
                return orig
    return None


def guess_fields(samples: Iterable[dict[str, Any]]) -> FieldMap:
    samples = [flatten(s) for s in samples]
    fm = FieldMap()
    if not samples:
        return fm
    all_keys: dict[str, None] = {}
    for s in samples:
        for k in s:
            all_keys.setdefault(k, None)
    fm.keys = list(all_keys)
    kl = {k.lower(): k for k in fm.keys}

    fm.host = _pick(kl, _HOST_KEYS)
    fm.user = _pick(kl, _USER_KEYS)
    fm.process = _pick(kl, _PROC_KEYS)
    fm.message = _pick(kl, _MSG_KEYS)
    fm.event_id = _pick(kl, _EVENTID_KEYS)
    fm.category = _pick(kl, _CAT_KEYS)
    fm.src_ip = _pick(kl, _SRCIP_KEYS)
    fm.dst_ip = _pick(kl, _DSTIP_KEYS)

    # timestamp: preferred names first, then any column whose values parse as dates
    candidates = [c for c in (_pick(kl, [k]) for k in _TS_KEYS) if c]
    candidates += [k for k in fm.keys if timeutil.looks_like_time_column(k) and k not in candidates]
    best, best_n = None, 0
    for c in candidates:
        vals = [s.get(c) for s in samples if s.get(c) not in (None, "")]
        if not vals:
            continue
        n = sum(1 for v in vals if timeutil.parse_any(v))
        if n > best_n:
            best, best_n = c, n
    if best and best_n >= max(1, len(samples) // 3):
        fm.ts = best
        vals = [samples[i].get(best) for i in range(len(samples)) if samples[i].get(best) not in (None, "")]
        nums = [v for v in vals if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d+(\.\d+)?", v))]
        if nums and len(nums) >= len(vals) // 2:
            fm.ts_hint = _best_epoch_hint([float(v) for v in nums])
    return fm


def _best_epoch_hint(nums: list[float]) -> str | None:
    best, best_n = None, 0
    for hint in ("unix", "unix_ms", "unix_us", "webkit", "filetime", "unix_ns"):
        n = sum(1 for v in nums if timeutil.from_epoch(v, hint))
        if n > best_n:
            best, best_n = hint, n
    return best


def _category(value: Any) -> Category:
    if value is None:
        return Category.OTHER
    v = str(value).lower()
    for cat, words in _CATEGORY_WORDS.items():
        if any(w in v for w in words):
            return cat
    return Category.OTHER


def _s(v: Any, n: int = 200) -> str:
    if isinstance(v, (list, tuple)):
        v = ",".join(str(x) for x in v[:10])
    s = str(v)
    return s if len(s) <= n else s[: n - 1] + "…"


def record_to_event(rec: dict[str, Any], fm: FieldMap, *, case_id: str, source: Source, source_file: str,
                    record_ref: str, host_hint: str | None, raw: str) -> Event:
    r = flatten(rec)
    ts: datetime | None = timeutil.parse_any(r.get(fm.ts), fm.ts_hint) if fm.ts else None
    host = _s(r[fm.host], 100) if fm.host and r.get(fm.host) not in (None, "") else host_hint
    user = _s(r[fm.user], 100) if fm.user and r.get(fm.user) not in (None, "") else None
    process = _s(r[fm.process], 200) if fm.process and r.get(fm.process) not in (None, "") else None
    eid = _s(r[fm.event_id], 50) if fm.event_id and r.get(fm.event_id) not in (None, "") else None
    cat = _category(r.get(fm.category)) if fm.category else Category.OTHER
    action = _s(r[fm.category], 60) if fm.category and r.get(fm.category) not in (None, "") else None

    used = {fm.ts, fm.host, fm.user, fm.process, fm.message, fm.event_id, fm.category}
    if fm.message and r.get(fm.message) not in (None, ""):
        body = _s(r[fm.message], 600)
    else:
        parts = [f"{k}={_s(v, 80)}" for k, v in r.items() if k not in used and v not in (None, "", [], {})]
        body = " ".join(parts[:25])
    prefix = " ".join(p for p in (f"EventID={eid}" if eid else "", f"[{action}]" if action else "") if p)
    summary = f"{prefix} {body}".strip()
    extra_scalars = {k: v for k, v in r.items() if isinstance(v, (str, int, float, bool)) and k not in used}
    ev_ioc: IOC = ioc.extract(summary + " " + " ".join(str(v) for v in extra_scalars.values())[:2000])
    for key in (fm.src_ip, fm.dst_ip):
        if key and (v := r.get(key)) and isinstance(v, str) and v not in ev_ioc.ip and re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", v):
            ev_ioc.ip.append(v)
    if user and user not in ev_ioc.user:
        ev_ioc.user.append(user)
    return Event(
        case_id=case_id, timestamp=ts, source=source, source_file=source_file, record_ref=record_ref,
        host=host, user=user, process=process, category=cat, action=action, ioc=ev_ioc,
        summary=summary[:1500], raw=raw[:4000], extra={"event_id": eid, **{k: v for k, v in list(extra_scalars.items())[:40]}},
    )
