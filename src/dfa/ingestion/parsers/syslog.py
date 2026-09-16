"""Syslog parser: RFC 3164 (BSD, no year), RFC 5424, and ISO-timestamped variants.

Year inference for BSD lines: ``ctx.year_hint`` > file mtime year (if the
resulting dates are not in the future) > current year.  Month roll-backs while
scanning forward (Dec -> Jan) bump the year.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from dfa.ingestion import ioc, timeutil
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Category, Event, Source

log = logging.getLogger(__name__)

_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_BSD = re.compile(
    r"^(?:<\d{1,3}>)?(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<rest>.*)$"
)
_5424 = re.compile(
    r"^<\d{1,3}>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) (?P<sd>-|\[.*?\]) ?(?P<msg>.*)$"
)
_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?) (?P<host>\S+) (?P<rest>.*)$")
_PROG = re.compile(r"^(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")

# message -> (category, action, user-group-name)
_RULES: list[tuple[re.Pattern, Category, str]] = [
    (re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+)"), Category.AUTHENTICATION, "ssh_login_success"),
    (re.compile(r"Failed (?:password|publickey|none) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"), Category.AUTHENTICATION, "ssh_login_failure"),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"), Category.AUTHENTICATION, "ssh_invalid_user"),
    (re.compile(r"authentication failure;.*user=(?P<user>\S*)"), Category.AUTHENTICATION, "auth_failure"),
    (re.compile(r"session opened for user (?P<user>\S+) by"), Category.AUTHENTICATION, "session_opened"),
    (re.compile(r"session closed for user (?P<user>\S+)"), Category.AUTHENTICATION, "session_closed"),
    (re.compile(r"^\s*(?P<user>\S+) : TTY=.*; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$"), Category.PRIVILEGE, "sudo_command"),
    (re.compile(r"Successful su for (?P<target>\S+) by (?P<user>\S+)"), Category.PRIVILEGE, "su_success"),
    (re.compile(r"FAILED su for (?P<target>\S+) by (?P<user>\S+)"), Category.PRIVILEGE, "su_failure"),
    (re.compile(r"\+ (?P<tty>\S+) (?P<user>\S+):(?P<target>\S+)"), Category.PRIVILEGE, "su_success"),
    (re.compile(r"new user: name=(?P<user>[^,]+)"), Category.USER_MGMT, "user_created"),
    (re.compile(r"new group: name=(?P<group>[^,]+)"), Category.USER_MGMT, "group_created"),
    (re.compile(r"delete user '(?P<user>[^']+)'"), Category.USER_MGMT, "user_deleted"),
    (re.compile(r"password changed for (?P<user>\S+)"), Category.USER_MGMT, "password_changed"),
    (re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'"), Category.USER_MGMT, "group_membership_added"),
    (re.compile(r"\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)"), Category.PROCESS, "cron_command"),
    (re.compile(r"Received disconnect from (?P<ip>\S+)"), Category.NETWORK, "ssh_disconnect"),
    (re.compile(r"reverse mapping checking getaddrinfo for \S+ \[(?P<ip>[^\]]+)\] failed"), Category.NETWORK, "ssh_reverse_dns_mismatch"),
    (re.compile(r"POSSIBLE BREAK-IN ATTEMPT"), Category.NETWORK, "ssh_possible_breakin"),
    (re.compile(r"Did not receive identification string from (?P<ip>\S+)"), Category.NETWORK, "ssh_scan"),
]
_KERNEL_PROGS = {"kernel"}
_SERVICE_PROGS = {"init", "syslog-ng", "rsyslogd", "systemd", "cron", "CRON", "anacron", "ntpd", "dhclient", "sshd"}


def _classify(prog: str | None, msg: str) -> tuple[Category, str | None, str | None, dict]:
    for rx, cat, action in _RULES:
        if m := rx.search(msg):
            d = m.groupdict()
            user = d.get("user") or None
            return cat, action, user, {k: v for k, v in d.items() if v}
    if prog in _KERNEL_PROGS:
        return Category.KERNEL, None, None, {}
    if prog in _SERVICE_PROGS:
        return Category.SERVICE, None, None, {}
    return Category.OTHER, None, None, {}


class SyslogParser:
    kinds = ("syslog",)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        now = datetime.now(UTC)
        year = ctx.year_hint
        if year is None:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
            year = mtime.year if mtime < now else now.year
        last_month = 0
        future_checked = False
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                if not line.strip():
                    continue
                ts = host = rest = None
                if m := _BSD.match(line):
                    mon = _MONTHS.get(m["mon"])
                    if mon:
                        if mon < last_month and last_month == 12:
                            year += 1
                        last_month = max(last_month, mon) if mon >= last_month else mon
                        try:
                            ts = datetime.strptime(f"{year}-{mon:02d}-{int(m['day']):02d} {m['time']}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
                        except ValueError:
                            ts = None
                        if ts and not future_checked and ts > now:
                            year -= 1
                            ts = ts.replace(year=year)
                        future_checked = True
                    host, rest = m["host"], m["rest"]
                elif m := _5424.match(line):
                    ts = timeutil.parse_any(m["ts"])
                    host = m["host"]
                    rest = f"{m['app']}[{m['pid']}]: {m['msg']}" if m["pid"] != "-" else f"{m['app']}: {m['msg']}"
                elif m := _ISO.match(line):
                    ts = timeutil.parse_any(m["ts"])
                    host, rest = m["host"], m["rest"]
                else:
                    rest = line

                prog = pid = None
                msg = rest or ""
                if pm := _PROG.match(msg):
                    prog, pid, msg = pm["prog"], pm["pid"], pm["msg"]
                cat, action, user, extra = _classify(prog, msg)
                ev_ioc = ioc.extract(msg)
                if (ip := extra.get("ip")) and ip not in ev_ioc.ip:
                    ev_ioc.ip.append(ip)
                if user and user not in ev_ioc.user:
                    ev_ioc.user.append(user)
                if (t := extra.get("target")) and t not in ev_ioc.user:
                    ev_ioc.user.append(t)
                summary = f"{prog or 'syslog'}: {msg}" if prog else msg
                yield Event(
                    case_id=ctx.case_id, timestamp=ts, source=Source.SYSLOG, source_file=path.name,
                    record_ref=f"line {n}", host=host or ctx.host_hint, user=user, process=prog,
                    category=cat, action=action, ioc=ev_ioc, summary=summary[:1000], raw=line[:4000],
                    extra={"pid": pid, **{k: v for k, v in extra.items() if k not in ("user", "ip")}},
                )


register(SyslogParser())
