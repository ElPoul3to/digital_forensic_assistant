import sqlite3
from pathlib import Path

from dfa.ingestion.parsers.base import ParseContext, load_all, parser_for


def _chromium(path: Path):
    c = sqlite3.connect(path)
    c.executescript("""
      create table urls(id integer primary key, url text, title text);
      create table visits(id integer primary key, url integer, visit_time integer, transition integer, from_visit integer);
      insert into urls values (1, 'http://evil.example/payload.exe', 'dl');
      insert into visits values (1, 1, 13272796800000000, 0, 0);
    """)
    c.commit(); c.close()


def _generic(path: Path):
    c = sqlite3.connect(path)
    c.executescript("""
      create table sessions(id integer primary key, username text, login_time integer, ip text);
      insert into sessions values (1, 'bob', 1272796800, '190.166.87.164');
    """)
    c.commit(); c.close()


def test_chromium_history(tmp_path: Path):
    load_all()
    _chromium(tmp_path / "History")
    evs = list(parser_for("sqlite").parse(tmp_path / "History", ParseContext("c1")))
    assert len(evs) == 1
    assert evs[0].action == "browser_visit"
    assert evs[0].ts_iso == "2021-08-07T08:00:00Z"
    assert "evil.example" in evs[0].ioc.domain


def test_generic_schema(tmp_path: Path):
    load_all()
    _generic(tmp_path / "app.db")
    evs = list(parser_for("sqlite").parse(tmp_path / "app.db", ParseContext("c1")))
    assert len(evs) == 1
    assert evs[0].ts_iso == "2010-05-02T10:40:00Z"
    assert "190.166.87.164" in evs[0].ioc.ip
    assert "sessions" in evs[0].summary
