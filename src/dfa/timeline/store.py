"""DuckDB timeline: every event of a case in one table, for neighbour lookups,
stats, and exact filters that a vector store is bad at."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from collections.abc import Iterable
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, ClassVar

import duckdb

from dfa.config import get_settings
from dfa.ingestion.schema import Event

log = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    event_id    VARCHAR PRIMARY KEY,
    ts          TIMESTAMPTZ,
    source      VARCHAR,
    source_file VARCHAR,
    record_ref  VARCHAR,
    host        VARCHAR,
    "user"      VARCHAR,
    process     VARCHAR,
    category    VARCHAR,
    action      VARCHAR,
    ips         VARCHAR[],
    domains     VARCHAR[],
    hashes      VARCHAR[],
    users       VARCHAR[],
    summary     VARCHAR,
    raw         VARCHAR,
    extra       JSON
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_host ON events (host);
"""


class Timeline:
    def __init__(self, case_id: str) -> None:
        d = get_settings().timeline_dir
        d.mkdir(parents=True, exist_ok=True)
        self.path = d / f"{case_id}.duckdb"
        self.case_id = case_id
        from dfa.security import crypto

        crypto.ensure_case_key(case_id)
        key = crypto.duckdb_key(case_id)
        if key:  # whole-file encryption by DuckDB; the key never appears in the SQL log because it is bound as a literal here only
            self.conn = duckdb.connect()
            self.conn.execute(f"ATTACH '{self.path}' AS tl (ENCRYPTION_KEY '{key}')")
            self.conn.execute("USE tl")
            self.encrypted = True
        else:
            self.conn = duckdb.connect(str(self.path))
            self.encrypted = False
        self.conn.execute("SET TimeZone = 'UTC'")  # TIMESTAMPTZ values come back as UTC, not machine-local time
        self.conn.execute(_DDL)

    def close(self) -> None:
        self.conn.close()

    # ---- write ---------------------------------------------------------
    _COLS = ("event_id", "ts", "source", "source_file", "record_ref", "host", "user", "process", "category",
             "action", "ips", "domains", "hashes", "users", "summary", "raw", "extra")
    _COL_TYPES: ClassVar[dict[str, str]] = {c: "VARCHAR[]" if c in ("ips", "domains", "hashes", "users") else "VARCHAR" for c in _COLS}

    def insert(self, events: Iterable[Event]) -> int:
        """Bulk upsert via DuckDB's JSON reader.

        ``executemany`` costs ~60 rows/s on this table (per-row transactions + list
        columns + primary key); staging the batch as newline-delimited JSON and
        ``INSERT OR REPLACE ... SELECT FROM read_json`` does ~40k rows/s.
        """
        n = 0
        fd, tmp = tempfile.mkstemp(prefix="dfa-timeline-", suffix=".jsonl")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for e in events:
                    ts = e.timestamp
                    if ts is not None and ts.tzinfo is None:
                        ts = ts.replace(tzinfo=UTC)
                    fh.write(json.dumps({
                        "event_id": e.stable_id(), "ts": ts.isoformat() if ts else None, "source": e.source.value,
                        "source_file": e.source_file, "record_ref": e.record_ref, "host": e.host, "user": e.user,
                        "process": e.process, "category": e.category.value, "action": e.action,
                        "ips": e.ioc.ip, "domains": e.ioc.domain, "hashes": e.ioc.hash, "users": e.ioc.user,
                        "summary": e.summary, "raw": e.raw, "extra": json.dumps(e.extra, default=str),
                    }, ensure_ascii=False) + "\n")
                    n += 1
            if n:
                cols = ", ".join(f'"{c}"' if c == "user" else c for c in self._COLS)
                select = cols.replace("ts,", "ts::TIMESTAMPTZ,").replace(", extra", ", extra::JSON")
                self.conn.execute(
                    f"INSERT OR REPLACE INTO events ({cols}) SELECT {select} FROM read_json(?, format='newline_delimited', columns=?)",
                    [tmp, self._COL_TYPES],
                )
        finally:
            os.unlink(tmp)
        return n

    # ---- read ----------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        c = self.conn
        n = c.execute("SELECT count(*) FROM events").fetchone()[0]
        span = c.execute("SELECT min(ts), max(ts) FROM events WHERE ts IS NOT NULL").fetchone()
        hosts = [r[0] for r in c.execute("SELECT host FROM events WHERE host IS NOT NULL GROUP BY host ORDER BY count(*) DESC LIMIT 50").fetchall()]
        by_source = dict(c.execute("SELECT source_file, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC").fetchall())
        by_cat = dict(c.execute("SELECT category, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC").fetchall())
        users = [r[0] for r in c.execute('SELECT "user" FROM events WHERE "user" IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 30').fetchall()]
        top_ips = c.execute("SELECT ip, count(*) FROM (SELECT unnest(ips) AS ip FROM events) GROUP BY 1 ORDER BY 2 DESC LIMIT 20").fetchall()
        return {"events": n, "time_min": span[0], "time_max": span[1], "hosts": hosts, "by_source": by_source,
                "by_category": by_cat, "users": users, "top_ips": top_ips}

    def get(self, event_ids: list[str]) -> list[dict[str, Any]]:
        if not event_ids:
            return []
        q = f"SELECT * FROM events WHERE event_id IN ({','.join('?' * len(event_ids))})"
        return self._rows(q, event_ids)

    def neighbours(self, event_id: str, n: int = 5, same_host: bool = True) -> list[dict[str, Any]]:
        """n events before and after the given event, ordered by time."""
        row = self.conn.execute("SELECT ts, host FROM events WHERE event_id = ?", [event_id]).fetchone()
        if not row or row[0] is None:
            return []
        ts, host = row
        cond = "AND host = ?" if same_host and host else ""
        args_before = [ts] + ([host] if cond else []) + [n]
        before = self._rows(f"SELECT * FROM events WHERE ts < ? {cond} ORDER BY ts DESC LIMIT ?", args_before)
        after = self._rows(f"SELECT * FROM events WHERE ts >= ? {cond} ORDER BY ts ASC LIMIT ?", [ts] + ([host] if cond else []) + [n + 1])
        return list(reversed(before)) + after

    @staticmethod
    def _where(*, host=None, user=None, ip=None, category=None, action=None, source_file=None,
               ts_from=None, ts_to=None, text=None) -> tuple[str, list]:
        where, args = [], []
        if host:
            where.append("host = ?"); args.append(host)
        if user:
            where.append('("user" = ? OR list_contains(users, ?))'); args += [user, user]
        if ip:
            where.append("list_contains(ips, ?)"); args.append(ip)
        if category:
            where.append("category = ?"); args.append(category)
        if action:
            where.append("action = ?"); args.append(action)
        if source_file:
            where.append("source_file = ?"); args.append(source_file)
        if ts_from:
            where.append("ts >= ?"); args.append(ts_from)
        if ts_to:
            where.append("ts <= ?"); args.append(ts_to)
        if text:
            where.append("(summary ILIKE ? OR raw ILIKE ?)"); args += [f"%{text}%", f"%{text}%"]
        return (" WHERE " + " AND ".join(where) if where else ""), args

    def search(self, *, host: str | None = None, user: str | None = None, ip: str | None = None,
               category: str | None = None, action: str | None = None, source_file: str | None = None,
               ts_from: datetime | None = None, ts_to: datetime | None = None,
               text: str | None = None, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        """Exact-filter browse over the timeline, oldest first (events without a timestamp come last)."""
        w, args = self._where(host=host, user=user, ip=ip, category=category, action=action, source_file=source_file,
                              ts_from=ts_from, ts_to=ts_to, text=text)
        q = f"SELECT * FROM events{w} ORDER BY ts NULLS LAST, source_file, record_ref LIMIT ? OFFSET ?"
        return self._rows(q, args + [limit, offset])

    def count(self, **filters) -> int:
        w, args = self._where(**filters)
        return self.conn.execute(f"SELECT count(*) FROM events{w}", args).fetchone()[0]

    def histogram(self, bucket: str = "hour", **filters) -> list[dict[str, Any]]:
        """Events per time bucket and category: [{bucket, category, n}], oldest first."""
        if bucket not in ("minute", "hour", "day", "week", "month"):
            raise ValueError(f"bucket must be minute|hour|day|week|month, not {bucket!r}")
        w, args = self._where(**filters)
        w = (w + " AND ts IS NOT NULL") if w else " WHERE ts IS NOT NULL"
        q = (f"SELECT date_trunc('{bucket}', ts) AS bucket, category, count(*) AS n FROM events{w} "
             "GROUP BY 1, 2 ORDER BY 1, 3 DESC")
        return self._rows(q, args)

    def around(self, when: datetime, n: int = 10, **filters) -> list[dict[str, Any]]:
        """n events before and n after a point in time, oldest first."""
        w, args = self._where(**filters)
        w_before = (w + " AND ts < ?") if w else " WHERE ts < ?"
        w_after = (w + " AND ts >= ?") if w else " WHERE ts >= ?"
        before = self._rows(f"SELECT * FROM events{w_before} ORDER BY ts DESC LIMIT ?", args + [when, n])
        after = self._rows(f"SELECT * FROM events{w_after} ORDER BY ts ASC LIMIT ?", args + [when, n])
        return list(reversed(before)) + after

    def distinct(self, column: str, limit: int = 100) -> list[tuple[Any, int]]:
        if column not in ("host", "user", "category", "action", "source_file", "source"):
            raise ValueError(column)
        col = '"user"' if column == "user" else column
        return self.conn.execute(f"SELECT {col}, count(*) FROM events WHERE {col} IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT ?", [limit]).fetchall()

    def _rows(self, q: str, args: list) -> list[dict[str, Any]]:
        cur = self.conn.execute(q, args)
        cols = [d[0] for d in cur.description]
        return [{c: _utc(v) for c, v in zip(cols, r)} for r in cur.fetchall()]


def _utc(v: Any) -> Any:
    return v.astimezone(UTC) if isinstance(v, datetime) and v.tzinfo is not None else v


@lru_cache(maxsize=8)
def get_timeline(case_id: str) -> Timeline:
    return Timeline(case_id)
