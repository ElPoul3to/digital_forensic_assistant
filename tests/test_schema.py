from datetime import UTC, datetime

from dfa.ingestion.schema import Event, Source


def test_event_stable_id_and_ts():
    e = Event(case_id="c1", source=Source.SYSLOG, source_file="auth.log", record_ref="line 1",
              timestamp=datetime(2010, 3, 16, 8, 12, 4, tzinfo=UTC), summary="s", raw="r")
    assert e.stable_id() == Event(case_id="c1", source=Source.SYSLOG, source_file="auth.log",
                                  record_ref="line 1", summary="x", raw="r").stable_id()
    assert e.ts_iso == "2010-03-16T08:12:04Z"
