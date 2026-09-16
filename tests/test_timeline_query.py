from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dfa.generation.citations import validate
from dfa.generation.prompts import build_context
from dfa.ingestion.schema import Category, Event, Source
from dfa.retrieval.retriever import RetrievalResult
from dfa.timeline import query as tq_mod
from dfa.timeline.query import (
    TimelineQuery,
    case_summary,
    run_sql,
    timeline_query,
    validate_sql,
)


def _ev(i: int, src="www-access.log", source=Source.APACHE, cat=Category.WEB, action="http_get", user=None, dt=None, ip=None):
    e = Event(case_id="c1", timestamp=dt, source=source, source_file=src, record_ref=f"line {i}", host="app-1", user=user,
              category=cat, action=action, summary=f"event {i}", raw=f"raw {i}")
    if ip:
        e.ioc.ip.append(ip)
    return e


@pytest.fixture
def timeline(tmp_path: Path, monkeypatch):
    import dfa.timeline.store as ts_mod
    from dfa.config import get_settings

    monkeypatch.setattr(get_settings(), "data_dir", tmp_path)
    ts_mod.get_timeline.cache_clear()
    tl = ts_mod.get_timeline("c1")
    t0 = datetime(2010, 4, 20, 4, 0, tzinfo=UTC)
    evs = [_ev(i, dt=t0 + timedelta(seconds=i)) for i in range(365)]
    evs += [_ev(1000 + i, src="auth.log", source=Source.SYSLOG, cat=Category.AUTHENTICATION, action="ssh_login_success",
                user="root", dt=t0, ip=ip) for i, ip in enumerate(["219.150.161.20", "219.150.161.20", "188.131.23.37"])]
    tl.insert(evs)
    yield tl
    tl.close()
    ts_mod.get_timeline.cache_clear()


def test_validate_sql_rejects_writes_and_files():
    assert validate_sql("SELECT 1;") == "SELECT 1"
    assert validate_sql("```sql\nselect count(*) from events\n```").startswith("select")
    for bad in ("DROP TABLE events", "SELECT 1; DROP TABLE events", "SELECT * FROM read_csv('/etc/passwd')",
                "COPY events TO '/tmp/x'", "INSERT INTO events VALUES (1)", "", "SELECT * FROM glob('*')",
                "ATTACH 'x.db'", "SET threads=1"):
        with pytest.raises(ValueError):
            validate_sql(bad)


def test_run_sql_counts_whole_file(timeline):
    cols, rows, total = run_sql(timeline, "SELECT count(*) AS lines FROM events WHERE source_file = 'www-access.log'", 60)
    assert cols == ["lines"] and rows == [[365]] and total == 1
    cols, rows, total = run_sql(timeline, "SELECT record_ref FROM events WHERE source_file = 'www-access.log' ORDER BY ts", 10)
    assert len(rows) == 10 and total == 365
    cols, rows, total = run_sql(
        timeline, 'SELECT ip, count(*) AS n FROM (SELECT unnest(ips) AS ip FROM events WHERE action = \'ssh_login_success\' AND "user" = \'root\') GROUP BY ip ORDER BY n DESC', 60)
    assert rows == [["219.150.161.20", 2], ["188.131.23.37", 1]]


def test_case_summary_lists_files_and_actions(timeline):
    s = case_summary(timeline)
    assert "'www-access.log' (apache, 365)" in s and "'auth.log' (syslog, 3)" in s
    assert "authentication / 'ssh_login_success' (3, e.g. record_ref 'line 100" in s and "'root'" in s


def test_timeline_query_with_stub_llm_and_retry(timeline, monkeypatch):
    class Stub:
        calls = 0

        def complete(self, prompt, max_tokens=None, **kw):
            Stub.calls += 1
            if Stub.calls == 1:  # first attempt: bad column -> DuckDB error -> retried with feedback
                return '{"sql": "SELECT count(*) AS lines FROM events WHERE filename = \'www-access.log\'", "note": "x"}'
            assert "Your previous query failed" in prompt and "filename" in prompt
            return '{"sql": "SELECT count(*) AS lines FROM events WHERE source_file = \'www-access.log\'", "note": "rows of www-access.log"}'

    import dfa.generation.llm as llm_mod
    monkeypatch.setattr(llm_mod, "get_llm", lambda: Stub())
    res = timeline_query("c1", "How many lines are in www-access.log?")
    assert res.ok and res.rows == [[365]] and Stub.calls == 2
    assert res.to_text().startswith("SQL: SELECT count(*)") and "Result: 1 row(s)" in res.to_text() and "365" in res.to_text()

    # a query that stays broken is reported, never raised
    monkeypatch.setattr(llm_mod, "get_llm", lambda: type("Bad", (), {"complete": lambda self, *a, **k: '{"sql": "SELECT * FROM read_csv(\'/etc/passwd\')"}'})())
    res = timeline_query("c1", "read a file")
    assert not res.ok and "forbidden keyword" in res.error
    assert run_sql(timeline, "SELECT count(*) FROM events", 5)[1] == [[368]]


def test_context_and_citation_for_structured_block():
    tq = TimelineQuery(question="q", sql="SELECT count(*) AS lines FROM events", note="n", columns=["lines"], rows=[[365]], total=1)
    ctx = build_context(RetrievalResult(evidence=[], attack=[], queries=["q"]), 4000, structured=tq)
    assert "=== TIMELINE QUERY" in ctx.text and "[S1] SQL:" in ctx.text and set(ctx.labels) == {"S1"}
    assert ctx.labels["S1"].collection == "timeline" and ctx.labels["S1"].payload["total"] == 1
    v = validate("The file has 365 lines [S1].", set(ctx.labels))
    assert v.valid == ["S1"] and not v.invalid
    # a failed query adds nothing
    bad = TimelineQuery(question="q", sql=None, error="boom")
    assert "TIMELINE" not in build_context(RetrievalResult(evidence=[], attack=[], queries=["q"]), 4000, structured=bad).text
    assert tq_mod.TimelineQuery(question="q").ok is False


def test_prompt_guides_memory_plugin_choice():
    from dfa.timeline.query import _PROMPT

    assert "mem_netscan" in _PROMPT and "double-count" in _PROMPT
    assert "'$.State') = 'ESTABLISHED'" in _PROMPT
