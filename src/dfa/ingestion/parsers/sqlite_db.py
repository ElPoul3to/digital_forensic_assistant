"""SQLite database parser.

Recognises common forensic databases (Chromium / Firefox / Safari history,
downloads, cookies, logins) and falls back to a generic per-table row dump
with automatic timestamp column detection for anything else.

Forensic hygiene: the database is copied to a temp dir together with its
``-wal`` / ``-journal`` side files and opened read-only, so the original
evidence is never modified.
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from dfa.ingestion import ioc, timeutil
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Category, Event, Source

log = logging.getLogger(__name__)

MAX_ROWS_PER_TABLE = 100_000


@dataclass
class KnownSchema:
    name: str
    required_tables: set[str]
    handler: Callable[[sqlite3.Connection, Path, str, str | None], Iterator[Event]]


def _open_readonly(path: Path) -> tuple[sqlite3.Connection, tempfile.TemporaryDirectory]:
    tmp = tempfile.TemporaryDirectory(prefix="dfa_sqlite_")
    dst = Path(tmp.name) / path.name
    shutil.copy2(path, dst)
    for suffix in ("-wal", "-journal", "-shm"):
        side = path.with_name(path.name + suffix)
        if side.exists():
            shutil.copy2(side, dst.with_name(dst.name + suffix))
    conn = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.text_factory = lambda b: b.decode("utf-8", errors="replace")  # browser DBs store binary in TEXT columns
    return conn, tmp


def _tables(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]


def _mk(case_id: str, path: Path, ref: str, ts, summary: str, raw: str, category: Category,
        action: str, host: str | None, user: str | None = None, extra: dict | None = None) -> Event:
    return Event(
        case_id=case_id, timestamp=ts, source=Source.OTHER, source_file=path.name, record_ref=ref,
        host=host, user=user, category=category, action=action, ioc=ioc.extract(summary),
        summary=summary, raw=raw, extra={"db": path.name, **(extra or {})},
    )


# ---- Chromium ------------------------------------------------------------
def _chromium_history(conn, path, case_id, host):
    q = """SELECT v.id, v.visit_time, u.url, u.title, v.transition, v.from_visit
           FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time"""
    for r in conn.execute(q):
        ts = timeutil.from_epoch(r["visit_time"], "webkit")
        summary = f"Browser visit (Chromium): {r['url']}" + (f" title=\"{r['title']}\"" if r["title"] else "")
        yield _mk(case_id, path, f"visits.id={r['id']}", ts, summary, dict(r).__repr__(),
                  Category.WEB, "browser_visit", host, extra={"table": "visits"})
    if "downloads" in _tables(conn):
        cols = _columns(conn, "downloads")
        url_col = "tab_url" if "tab_url" in cols else "url" if "url" in cols else None
        for r in conn.execute("SELECT * FROM downloads ORDER BY start_time"):
            ts = timeutil.from_epoch(r["start_time"], "webkit")
            summary = (f"Browser download (Chromium): {r['target_path'] if 'target_path' in cols else r['full_path']}"
                       + (f" from {r[url_col]}" if url_col and r[url_col] else "")
                       + f" bytes={r['received_bytes'] if 'received_bytes' in cols else '?'}")
            yield _mk(case_id, path, f"downloads.id={r['id']}", ts, summary, repr(dict(r)),
                      Category.FILE, "browser_download", host, extra={"table": "downloads"})


def _chromium_cookies(conn, path, case_id, host):
    cols = _columns(conn, "cookies")
    ts_col = "creation_utc"
    for i, r in enumerate(conn.execute(f"SELECT * FROM cookies ORDER BY {ts_col}")):
        ts = timeutil.from_epoch(r[ts_col], "webkit")
        summary = f"Cookie (Chromium): host={r['host_key']} name={r['name']}" + (f" path={r['path']}" if "path" in cols else "")
        yield _mk(case_id, path, f"cookies.row={i}", ts, summary, repr(dict(r)), Category.WEB, "cookie", host)


def _chromium_logins(conn, path, case_id, host):
    for i, r in enumerate(conn.execute("SELECT * FROM logins ORDER BY date_created")):
        ts = timeutil.from_epoch(r["date_created"], "webkit")
        summary = f"Saved credential (Chromium): origin={r['origin_url']} user={r['username_value']}"
        yield _mk(case_id, path, f"logins.row={i}", ts, summary, "<redacted>", Category.AUTHENTICATION,
                  "saved_credential", host, user=r["username_value"])


# ---- Firefox -------------------------------------------------------------
def _firefox_places(conn, path, case_id, host):
    q = """SELECT hv.id, hv.visit_date, p.url, p.title, hv.visit_type
           FROM moz_historyvisits hv JOIN moz_places p ON p.id = hv.place_id ORDER BY hv.visit_date"""
    for r in conn.execute(q):
        ts = timeutil.from_epoch(r["visit_date"], "unix_us")
        summary = f"Browser visit (Firefox): {r['url']}" + (f" title=\"{r['title']}\"" if r["title"] else "")
        yield _mk(case_id, path, f"moz_historyvisits.id={r['id']}", ts, summary, repr(dict(r)),
                  Category.WEB, "browser_visit", host, extra={"table": "moz_historyvisits"})
    if "moz_annos" in _tables(conn):
        q = """SELECT a.id, a.dateAdded, a.content, p.url FROM moz_annos a
               JOIN moz_anno_attributes aa ON aa.id = a.anno_attribute_id
               JOIN moz_places p ON p.id = a.place_id WHERE aa.name = 'downloads/destinationFileURI'"""
        for r in conn.execute(q):
            ts = timeutil.from_epoch(r["dateAdded"], "unix_us")
            summary = f"Browser download (Firefox): {r['content']} from {r['url']}"
            yield _mk(case_id, path, f"moz_annos.id={r['id']}", ts, summary, repr(dict(r)),
                      Category.FILE, "browser_download", host)


def _firefox_cookies(conn, path, case_id, host):
    for r in conn.execute("SELECT * FROM moz_cookies ORDER BY creationTime"):
        ts = timeutil.from_epoch(r["creationTime"], "unix_us")
        summary = f"Cookie (Firefox): host={r['host']} name={r['name']}"
        yield _mk(case_id, path, f"moz_cookies.id={r['id']}", ts, summary, repr(dict(r)), Category.WEB, "cookie", host)


# ---- Safari --------------------------------------------------------------
def _safari_history(conn, path, case_id, host):
    q = """SELECT v.id, v.visit_time, v.title, i.url FROM history_visits v
           JOIN history_items i ON i.id = v.history_item ORDER BY v.visit_time"""
    for r in conn.execute(q):
        ts = timeutil.from_epoch(r["visit_time"], "mac")
        summary = f"Browser visit (Safari): {r['url']}" + (f" title=\"{r['title']}\"" if r["title"] else "")
        yield _mk(case_id, path, f"history_visits.id={r['id']}", ts, summary, repr(dict(r)), Category.WEB, "browser_visit", host)


KNOWN: list[KnownSchema] = [
    KnownSchema("chromium_history", {"urls", "visits"}, _chromium_history),
    KnownSchema("chromium_cookies", {"cookies", "meta"}, _chromium_cookies),
    KnownSchema("chromium_logins", {"logins"}, _chromium_logins),
    KnownSchema("firefox_places", {"moz_places", "moz_historyvisits"}, _firefox_places),
    KnownSchema("firefox_cookies", {"moz_cookies"}, _firefox_cookies),
    KnownSchema("safari_history", {"history_items", "history_visits"}, _safari_history),
]


# ---- generic fallback ----------------------------------------------------
def _guess_ts_hint(values: list[object]) -> str | None:
    """Pick the epoch interpretation that makes most sampled values plausible."""
    nums = [v for v in values if isinstance(v, (int, float)) and v]
    if not nums:
        return None
    best, best_n = None, 0
    for hint in ("unix", "unix_ms", "unix_us", "webkit", "filetime", "mac", "unix_ns"):
        n = sum(1 for v in nums if timeutil.from_epoch(v, hint))
        if n > best_n:
            best, best_n = hint, n
    return best if best_n >= max(1, len(nums) // 2) else None


def _generic(conn: sqlite3.Connection, path: Path, case_id: str, host: str | None) -> Iterator[Event]:
    for table in _tables(conn):
        if table.startswith("sqlite_"):
            continue
        cols = _columns(conn, table)
        if not cols:
            continue
        ts_cols = [c for c in cols if timeutil.looks_like_time_column(c)]
        hint: str | None = None
        ts_col: str | None = None
        if ts_cols:
            cols = ", ".join(f'"{c}"' for c in ts_cols)
            sample = conn.execute(f'SELECT {cols} FROM "{table}" LIMIT 200').fetchall()
            for c in ts_cols:
                vals = [row[c] for row in sample]
                if any(isinstance(v, str) for v in vals):
                    parsed = sum(1 for v in vals if timeutil.parse_any(v))
                    if parsed >= max(1, len(vals) // 2):
                        ts_col, hint = c, None
                        break
                h = _guess_ts_hint(vals)
                if h:
                    ts_col, hint = c, h
                    break
        order = f' ORDER BY "{ts_col}"' if ts_col else ""
        n = 0
        try:
            cursor = conn.execute(f'SELECT rowid AS __rowid, * FROM "{table}"{order} LIMIT {MAX_ROWS_PER_TABLE}')
        except sqlite3.OperationalError:  # WITHOUT ROWID table: number the rows ourselves
            cursor = conn.execute(f'SELECT NULL AS __rowid, * FROM "{table}"{order} LIMIT {MAX_ROWS_PER_TABLE}')
        for i, row in enumerate(cursor, 1):
            d = {k: row[k] for k in row.keys() if k != "__rowid"}  # noqa: SIM118 - sqlite3.Row iterates values
            ts = timeutil.parse_any(d[ts_col], hint) if ts_col else None
            fields = ", ".join(f"{k}={_short(v)}" for k, v in d.items() if v not in (None, "", b""))
            summary = f"{path.name}:{table}: {fields}"
            ref = f"{table}.rowid={row['__rowid']}" if row["__rowid"] is not None else f"{table}.row={i}"
            yield _mk(case_id, path, ref, ts, summary[:2000], repr(d)[:4000],
                      Category.OTHER, f"db_row:{table}", host, extra={"table": table})
            n += 1
        log.debug("%s: table %s -> %d rows (ts=%s/%s)", path.name, table, n, ts_col, hint)


def _short(v: object, n: int = 120) -> str:
    if isinstance(v, bytes):
        return f"<blob {len(v)}B>"
    s = str(v)
    return s if len(s) <= n else s[: n - 1] + "…"


class SQLiteParser:
    kinds = ("sqlite",)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        case_id, host_hint = ctx.case_id, ctx.host_hint
        conn, tmp = _open_readonly(path)
        try:
            tables = set(_tables(conn))
            handled = False
            for schema in KNOWN:
                if schema.required_tables <= tables:
                    log.info("%s: recognised as %s", path.name, schema.name)
                    yield from schema.handler(conn, path, case_id, host_hint)
                    handled = True
            if not handled:
                log.info("%s: unknown schema, generic row dump of %d tables", path.name, len(tables))
                yield from _generic(conn, path, case_id, host_hint)
        finally:
            conn.close()
            tmp.cleanup()


register(SQLiteParser())
