"""Structured timeline queries for aggregate questions.

The vector store returns the top-k most similar chunks, which is a *sample* of
the evidence.  Questions such as "how many lines are in www-access.log" or
"which IPs logged in as root" need the *whole* timeline.  For those the LLM
writes one read-only DuckDB ``SELECT`` over the ``events`` table, the query is
validated and executed, and the result table is placed in the context as an
authoritative ``[S1]`` block next to the retrieved evidence.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from dfa.config import get_settings
from dfa.timeline.store import Timeline, get_timeline

log = logging.getLogger(__name__)

SCHEMA = """CREATE TABLE events (
    event_id    VARCHAR,      -- unique id
    ts          TIMESTAMPTZ,  -- event time (UTC), NULL when the line had no timestamp
    source      VARCHAR,      -- parser: syslog | apache | dpkg | dmesg | evtx | json | csv | pcap | sqlite | other
    source_file VARCHAR,      -- file name the event came from, e.g. 'auth.log', 'www-access.log'
    record_ref  VARCHAR,      -- 'line 42' / 'record 48213' / 'row 7'
    host        VARCHAR,
    "user"      VARCHAR,      -- primary user of the event (quote the name: "user")
    process     VARCHAR,      -- daemon / program name, e.g. 'sshd', 'sudo'
    category    VARCHAR,      -- authentication | privilege | user_management | network | web | package | kernel | service | other
    action      VARCHAR,      -- normalised action, see the list below
    ips         VARCHAR[],    -- every IP in the event
    domains     VARCHAR[],
    hashes      VARCHAR[],
    users       VARCHAR[],    -- every user name in the event
    summary     VARCHAR,      -- one-line human summary
    raw         VARCHAR,      -- original log line
    extra       JSON          -- parser specific fields; the keys that exist per source/action are listed below
);
-- record_ref is the position in the source: 'line N' (text logs), 'record N' (EVTX), 'row N' (databases),
-- 'frame N' (pcap: the packet number as shown by Wireshark; for HTTP responses the packet where the response completed).
-- JSON access: json_extract_string(extra, '$.ua'), json_extract_string(extra, '$.status')::INT, json_extract_string(extra, '$.flags') ILIKE '%script%'
-- (always json_extract_string(); do not use the -> / ->> operators). Only use extra keys listed below for that source/action."""

_PROMPT = """You translate an incident-response analyst's question into ONE DuckDB SQL SELECT over the case timeline.

{schema}

This case currently contains:
{summary}

Rules:
- Output JSON only: {{"sql": "<query>", "note": "<one line: what the query counts or lists>"}}.
- One SELECT (or WITH ... SELECT). No DDL/DML, no file functions, no semicolons.
- Match file names with exact equality on source_file (use the names listed above). "Lines of a file" = rows with that source_file.
- When the question asks for a line / record / packet number, return record_ref (and the summary) rather than a count.
- Use the listed action / category values; when unsure, add a fallback on summary ILIKE '%keyword%'.
- Filter on IPs with list_contains(ips, '1.2.3.4') or expand them with unnest(ips).
- "user" must be double-quoted. Group and aggregate when the question asks for counts, lists, distinct values or per-X breakdowns.
- Always include helpful columns: counts, the accounts / users involved (list(DISTINCT \"user\")), min(ts) AS first_seen, max(ts) AS last_seen where applicable. Order by the most useful column. Do not add LIMIT unless the question asks for a top-N.
- Memory images (source 'memory', actions 'mem_<plugin>'): every Volatility plugin is a different view of the SAME system state, so never count or list across several mem_* actions, pick the one plugin that answers the question:
    network connections -> action = 'mem_netscan' (complete pool scan); filter on json_extract_string(extra, '$.State') = 'ESTABLISHED' / 'LISTENING'; 'mem_netstat' lists the same sockets from kernel lists and would double-count.
    running processes -> 'mem_pslist'; hidden or terminated processes -> 'mem_psscan' with flags 'hidden_process' / 'terminated'; parent/child -> 'mem_pstree'; command lines -> 'mem_cmdline'.
    services -> 'mem_svcscan'; loaded DLLs -> 'mem_ldrmodules'; injected code -> 'mem_malfind'; users/SIDs -> 'mem_getsids'; a process appears once per plugin, so count(DISTINCT json_extract_string(extra, '$.PID')) when counting processes.

Examples:
Q: How many lines does www-access.log have?
{{"sql": "SELECT count(*) AS lines FROM events WHERE source_file = 'www-access.log'", "note": "rows ingested from www-access.log"}}
Q: Which IPs successfully logged in as root over SSH?
{{"sql": "SELECT ip, count(*) AS logins, list(DISTINCT \\"user\\") AS accounts, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT unnest(ips) AS ip, \\"user\\", ts FROM events WHERE action = 'ssh_login_success' AND \\"user\\" = 'root') GROUP BY ip ORDER BY logins DESC", "note": "successful root SSH logins per source IP"}}
Q: Which user-agents did the proxy scanners use?
{{"sql": "SELECT json_extract_string(extra, '$.ua') AS ua, count(*) AS requests, count(DISTINCT ips[1]) AS client_ips FROM events WHERE category = 'web' AND json_extract_string(extra, '$.flags') ILIKE '%proxy%' GROUP BY ua ORDER BY requests DESC", "note": "user-agents of proxy-related web requests"}}
Q: Which packet carries the HTTP response to show.php without any script?
{{"sql": "SELECT record_ref, summary FROM events WHERE action = 'http_response' AND json_extract_string(extra, '$.uri') ILIKE '%show.php%' ORDER BY ts", "note": "all HTTP responses to show.php with their flags; record_ref is the packet number"}}
Q: How many established network connections were there at the time of acquisition?
{{"sql": "SELECT count(*) AS established, list(DISTINCT process) AS processes FROM events WHERE action = 'mem_netscan' AND json_extract_string(extra, '$.State') = 'ESTABLISHED'", "note": "ESTABLISHED sockets found by windows.netscan (netstat rows are the same sockets and are not added)"}}
Q: What is the creation time of the parent process of powershell.exe?
{{"sql": "SELECT c.process AS child, json_extract_string(c.extra, '$.PID') AS child_pid, p.process AS parent, json_extract_string(p.extra, '$.PID') AS parent_pid, json_extract_string(p.extra, '$.CreateTime') AS parent_created FROM events c JOIN events p ON json_extract_string(c.extra, '$.PPID') = json_extract_string(p.extra, '$.PID') AND p.action = 'mem_pslist' WHERE c.action = 'mem_pslist' AND lower(c.process) LIKE 'powershell%'", "note": "parent of every powershell.exe from windows.pslist, joined on PPID = PID (extra.ParentImage / ParentCreateTime hold the same without a join)"}}
Q: Which processes were running, with their parent?
{{"sql": "SELECT json_extract_string(extra, '$.PID') AS pid, process, json_extract_string(extra, '$.PPID') AS ppid, min(ts) AS created FROM events WHERE action = 'mem_pslist' GROUP BY 1, 2, 3 ORDER BY created", "note": "process list from windows.pslist"}}
Q: Which packages were installed on 2010-04-24?
{{"sql": "SELECT ts, summary FROM events WHERE action = 'pkg_install' AND ts >= '2010-04-24' AND ts < '2010-04-25' ORDER BY ts", "note": "dpkg install actions on 2010-04-24"}}

Question: {q}
{feedback}"""

_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|create|alter|attach|detach|copy|export|import|install|load|pragma|call|"
    r"set|reset|truncate|vacuum|checkpoint|begin|commit|rollback|read_\w+|\w+_scan|glob|getenv|"
    r"sniff_csv|read_text|read_blob|httpfs|force)\b",
    re.IGNORECASE,
)


@dataclass
class TimelineQuery:
    question: str
    sql: str | None = None
    note: str = ""
    columns: list[str] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    total: int = 0  # rows the query produced (may exceed len(rows) when truncated)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.sql is not None and self.error is None

    @property
    def truncated(self) -> bool:
        return self.total > len(self.rows)

    def to_text(self) -> str:
        """Compact table for the LLM context."""
        head = f"SQL: {self.sql}"
        if self.note:
            head += f"\n({self.note})"
        if not self.rows:
            return f"{head}\nResult: 0 rows"
        lines = [" | ".join(self.columns)]
        for r in self.rows:
            lines.append(" | ".join(_fmt(v) for v in r))
        tail = f"Result: {self.total} row(s)" + (f", first {len(self.rows)} shown" if self.truncated else "")
        return f"{head}\n{tail}\n" + "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {"sql": self.sql, "note": self.note, "columns": self.columns, "rows": [[_fmt(v) for v in r] for r in self.rows],
                "total": self.total, "truncated": self.truncated, "error": self.error}


def _fmt(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, (list, tuple)):
        return ",".join(_fmt(x) for x in v)
    s = str(v)
    return s if len(s) <= 200 else s[:197] + "..."


# ---- schema summary -----------------------------------------------------

def case_summary(tl: Timeline, max_actions: int = 60) -> str:
    """Distinct values the LLM needs to write a correct WHERE clause."""
    c = tl.conn
    n, lo, hi = c.execute("SELECT count(*), min(ts), max(ts) FROM events").fetchone()
    files = c.execute("SELECT source_file, source, count(*) FROM events GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 40").fetchall()
    hosts = [r[0] for r in c.execute("SELECT host FROM events WHERE host IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 20").fetchall()]
    users = [r[0] for r in c.execute('SELECT "user" FROM events WHERE "user" IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 25').fetchall()]
    acts = c.execute(
        "SELECT category, action, count(*), any_value(summary), any_value(record_ref) FROM events WHERE action IS NOT NULL "
        "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT ?", [max_actions]).fetchall()
    keys = c.execute(
        "SELECT source, action, any_value(json_keys(extra)) FROM events WHERE extra IS NOT NULL AND json_keys(extra) != [] "
        "GROUP BY 1, 2 ORDER BY count(*) DESC LIMIT ?", [max_actions]).fetchall()
    flags = c.execute(
        "SELECT source, action, list(DISTINCT f) FROM (SELECT source, action, unnest(json_extract_string(extra, '$.flags[*]')) AS f "
        "FROM events WHERE json_extract_string(extra, '$.flags[*]') IS NOT NULL) GROUP BY 1, 2").fetchall()
    out = [f"- events: {n}, time range: {_fmt(lo)} .. {_fmt(hi)}",
           "- source_file (source, rows): " + ", ".join(f"'{f}' ({s}, {k})" for f, s, k in files),
           "- host: " + ", ".join(f"'{h}'" for h in hosts),
           "- \"user\" (most frequent): " + ", ".join(f"'{u}'" for u in users),
           "- category / action (rows) with an example summary and record_ref:"]
    out += [f"    {cat} / '{act}' ({k}, e.g. record_ref '{ref}'): {_fmt(ex)[:110]}" for cat, act, k, ex, ref in acts]
    if keys:
        out.append("- extra JSON keys by source / action:")
        out += [f"    {src} / '{act}': {', '.join(k)}" for src, act, k in keys if k]
    if flags:
        out.append("- values seen in extra.flags by source / action:")
        out += [f"    {src} / '{act}': {', '.join(sorted(x for x in fl if x))}" for src, act, fl in flags if fl]
    return "\n".join(out)


# ---- SQL safety -----------------------------------------------------------

def validate_sql(sql: str) -> str:
    """Return the cleaned query or raise ValueError."""
    q = sql.strip().rstrip(";").strip()
    q = re.sub(r"^```(?:sql)?\s*|\s*```$", "", q, flags=re.IGNORECASE).strip()
    if not q:
        raise ValueError("empty query")
    if ";" in q:
        raise ValueError("only a single statement is allowed")
    if not re.match(r"^(select|with)\b", q, re.IGNORECASE):
        raise ValueError("query must start with SELECT or WITH")
    if m := _FORBIDDEN.search(q):
        raise ValueError(f"forbidden keyword: {m.group(0)}")
    return q


def run_sql(tl: Timeline, sql: str, max_rows: int) -> tuple[list[str], list[list[Any]], int]:
    sql = validate_sql(sql)
    cur = tl.conn.execute(f"SELECT * FROM ({sql}) AS q LIMIT {int(max_rows) + 1}")
    cols = [d[0] for d in cur.description]
    rows = [list(r) for r in cur.fetchall()]
    total = len(rows)
    if total > max_rows:
        rows = rows[:max_rows]
        total = tl.conn.execute(f"SELECT count(*) FROM ({sql}) AS q").fetchone()[0]
    return cols, rows, total


# ---- LLM text-to-SQL ------------------------------------------------------

def _generate(question: str, summary: str, feedback: str = "") -> tuple[str, str]:
    from dfa.generation.llm import get_llm

    prompt = _PROMPT.format(schema=SCHEMA, summary=summary, q=question, feedback=feedback)
    raw = get_llm().complete(prompt, max_tokens=400)
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        raise ValueError(f"no JSON in LLM output: {raw[:200]!r}")
    data = json.loads(m.group(0))
    sql = data.get("sql")
    if not isinstance(sql, str):
        raise TypeError("LLM output has no 'sql' string")
    return sql, str(data.get("note") or "")


def timeline_query(case_id: str, question: str, max_rows: int | None = None, retries: int = 1) -> TimelineQuery:
    """Ask the LLM for a SQL query, validate it, run it. Never raises: errors land in ``.error``."""
    max_rows = max_rows or get_settings().router.timeline_query_rows
    tq = TimelineQuery(question=question)
    try:
        tl = get_timeline(case_id)
        summary = case_summary(tl)
    except Exception as e:  # noqa: BLE001
        tq.error = f"timeline unavailable: {e}"
        return tq
    feedback = ""
    for attempt in range(retries + 1):
        last_sql = ""
        try:
            last_sql, note = _generate(question, summary, feedback)
            tq.sql, tq.note = validate_sql(last_sql), note
            tq.columns, tq.rows, tq.total = run_sql(tl, tq.sql, max_rows)
            tq.error = None
            log.info("timeline query (%d rows): %s", tq.total, tq.sql)
            return tq
        except Exception as e:  # noqa: BLE001
            tq.error = str(e)
            feedback = f"\nYour previous query failed: {last_sql}\nError: {e}\nFix it."
            log.warning("timeline query attempt %d failed: %s", attempt + 1, e)
    return tq
