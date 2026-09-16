import json
from pathlib import Path

from dfa.generation.answer import Answer
from dfa.generation.audit import audit_path, read, record


def test_audit_appends_one_line_per_question(tmp_path: Path, monkeypatch):
    from dfa.config import get_settings

    monkeypatch.setattr(get_settings(), "data_dir", tmp_path)
    a = Answer(question="who?", answer="root [E1]", route="evidence_only", route_reason="default + timeline query", filters={},
               queries=["who?"], citations=[{"label": "E1", "kind": "evidence"}], invalid_citations=[],
               retrieved=[{"label": "E1", "kind": "evidence", "source_file": "auth.log", "record_ref": "line 7", "ts": None, "rerank": 0.9},
                          {"label": "S1", "kind": "timeline", "sql": "SELECT 1", "rows": 1}],
               attack_techniques=[], timeline_query={"sql": "SELECT 1", "total": 1, "error": None})
    p = record("c1", a, interface="api", latency_s=3.2)
    record("c1", a)
    assert p == audit_path("c1") == tmp_path / "audit" / "c1.jsonl"
    lines = [json.loads(x) for x in p.read_text().splitlines()]
    assert len(lines) == 2 and lines[0]["interface"] == "api" and lines[1]["interface"] == "cli"
    e = lines[0]
    assert e["question"] == "who?" and e["cited"] == ["E1"] and e["timeline_query"]["sql"] == "SELECT 1"
    assert e["retrieved"][0] == {"label": "E1", "kind": "evidence", "source_file": "auth.log", "record_ref": "line 7", "ts": None, "rerank": 0.9}
    assert e["retrieved"][1]["sql"] == "SELECT 1" and len(e["answer_sha256"]) == 64 and e["answer"] == "root [E1]"
    assert read("c1", limit=1)[0]["latency_s"] is None
    monkeypatch.setattr(get_settings().audit, "store_answer", False)
    record("c1", a)
    assert "answer" not in read("c1", limit=1)[0]
    monkeypatch.setattr(get_settings().audit, "enabled", False)
    assert record("c1", a) is None and len(read("c1")) == 3
