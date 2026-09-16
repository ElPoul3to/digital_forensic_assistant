from datetime import UTC, datetime, timedelta
from pathlib import Path

from dfa.ingestion.chunker import window_events
from dfa.ingestion.schema import Category, Event, Granularity, Source


def _ev(i: int, host="app-1", src="auth.log", dt=None, user=None):
    return Event(case_id="c1", timestamp=dt, source=Source.SYSLOG, source_file=src, record_ref=f"line {i}",
                 host=host, user=user, category=Category.AUTHENTICATION, summary=f"event {i}", raw=f"raw {i}")


def test_windows_by_count_and_time():
    t0 = datetime(2010, 4, 20, 4, 0, tzinfo=UTC)
    evs = [_ev(i, dt=t0 + timedelta(seconds=10 * i)) for i in range(25)]      # 25 events over 240 s
    evs += [_ev(100, dt=t0 + timedelta(hours=1))]                              # far away -> own window
    evs += [_ev(200, host="db-1", dt=t0)]                                     # other host -> own group
    chunks = list(window_events(evs, "case_c1"))
    assert all(c.granularity == Granularity.WINDOW for c in chunks)
    sizes = sorted(c.metadata["n_events"] for c in chunks)
    assert sizes == [1, 1, 12, 13]  # 0..120 s = 13 events, 130..240 s = 12, then two singletons
    assert chunks[0].text.startswith("## host=app-1")


def test_timeline_roundtrip(tmp_path: Path, monkeypatch):
    import dfa.timeline.store as ts_mod
    from dfa.config import get_settings

    monkeypatch.setattr(get_settings(), "data_dir", tmp_path)
    ts_mod.get_timeline.cache_clear()
    tl = ts_mod.Timeline("c1")
    t0 = datetime(2010, 4, 20, 4, 0, tzinfo=UTC)
    evs = [_ev(i, dt=t0 + timedelta(seconds=i), user="root" if i == 3 else None) for i in range(10)]
    evs[5].ioc.ip.append("190.166.87.164")
    assert tl.insert(evs) == 10
    assert tl.insert(evs) == 10  # idempotent upsert
    st = tl.stats()
    assert st["events"] == 10 and st["hosts"] == ["app-1"] and st["users"] == ["root"]
    assert st["top_ips"][0][0] == "190.166.87.164"
    nb = tl.neighbours(evs[5].stable_id(), n=2)
    assert [r["record_ref"] for r in nb] == ["line 3", "line 4", "line 5", "line 6", "line 7"]
    assert len(tl.search(ip="190.166.87.164")) == 1
    assert len(tl.search(user="root")) == 1
    tl.close()
