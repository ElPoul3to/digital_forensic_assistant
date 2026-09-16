import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dfa.ingestion.schema import Category, Event, Source
from dfa.timeline import export


def _ev(i, cat=Category.AUTHENTICATION, action="ssh_login_failure", user=None, dt=None, src="auth.log", ip=None):
    e = Event(case_id="c1", timestamp=dt, source=Source.SYSLOG, source_file=src, record_ref=f"line {i}", host="app-1",
              user=user, category=cat, action=action, summary=f"event {i} <b>", raw=f"raw {i} </script>")
    if ip:
        e.ioc.ip.append(ip)
    return e


@pytest.fixture
def tl(tmp_path: Path, monkeypatch):
    import dfa.timeline.store as ts_mod
    from dfa.config import get_settings

    monkeypatch.setattr(get_settings(), "data_dir", tmp_path)
    ts_mod.get_timeline.cache_clear()
    t = ts_mod.get_timeline("c1")
    t0 = datetime(2010, 4, 20, 4, 0, tzinfo=UTC)
    evs = [_ev(i, dt=t0 + timedelta(minutes=i)) for i in range(90)]                       # 04:00 .. 05:29
    evs += [_ev(100 + i, Category.WEB, "http_get", dt=t0 + timedelta(hours=3, minutes=i)) for i in range(5)]  # 07:00 ..
    evs.append(_ev(200, action="ssh_login_success", user="root", dt=t0 + timedelta(minutes=30), ip="203.0.113.5"))
    evs.append(_ev(300, dt=None))  # no timestamp
    t.insert(evs)
    yield t
    t.close()
    ts_mod.get_timeline.cache_clear()


def test_search_paging_and_count(tl):
    assert tl.count() == 97 and tl.count(category="web") == 5 and tl.count(action="ssh_login_success") == 1
    page1 = tl.search(limit=10)
    page2 = tl.search(limit=10, offset=10)
    assert [r["record_ref"] for r in page1] == [f"line {i}" for i in range(10)]
    assert page2[0]["record_ref"] == "line 10"
    assert tl.search(limit=200)[-1]["record_ref"] == "line 300"  # untimed events sort last
    assert [r["record_ref"] for r in tl.search(text="EVENT 200")] == ["line 200"]
    assert [r["record_ref"] for r in tl.search(ip="203.0.113.5")] == ["line 200"]
    assert len(tl.search(ts_from=datetime(2010, 4, 20, 7, tzinfo=UTC))) == 5


def test_histogram_and_around(tl):
    h = tl.histogram("hour")
    assert [(r["bucket"].hour, r["category"], r["n"]) for r in h] == [(4, "authentication", 61), (5, "authentication", 30), (7, "web", 5)]
    assert tl.histogram("hour", category="web")[0]["n"] == 5
    with pytest.raises(ValueError):
        tl.histogram("fortnight")
    ctx = tl.around(datetime(2010, 4, 20, 4, 30, tzinfo=UTC), n=2)
    assert [r["record_ref"] for r in ctx] == ["line 28", "line 29", "line 30", "line 200"]  # two events at 04:30
    assert tl.distinct("action")[0] == ("ssh_login_failure", 91)  # 90 timed + the untimed one


def test_html_export(tl, tmp_path: Path):
    rows = tl.search(limit=50)
    out = export.write(tmp_path / "t.html", "c1", rows, total=97, filters={"category": None, "text": "x"})
    page = out.read_text()
    assert page.startswith("<!doctype html>") and "Timeline c1" in page
    assert "<\\/script>" in page and "</script>\"" not in page  # raw lines cannot break out of the data element
    m = re.search(r'<script id="data-json" type="application/json">(.*?)</script>', page, re.DOTALL)
    data = json.loads(m.group(1).replace("<\\/", "</"))
    assert data["columns"][:2] == ["event_id", "ts"] and len(data["rows"]) == 50
    assert data["rows"][0][data["columns"].index("ts")] == "2010-04-20T04:00:00Z"
    meta = json.loads(re.search(r'<script id="meta-json" type="application/json">(.*?)</script>', page).group(1))
    assert meta["total"] == 97 and meta["exported"] == 50 and meta["filters"] == {"text": "x"}
    assert "http://" not in page and "https://" not in page  # fully offline
