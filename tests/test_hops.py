"""Multi-hop retrieval: follow-up lookups planned by the model and merged into the evidence."""

from dfa.retrieval import hops as hops_mod
from dfa.retrieval.hops import plan_followups, run_hops
from dfa.retrieval.retriever import Hit, RetrievalResult
from dfa.router.router import Filters


def _hit(i: str, text: str) -> Hit:
    return Hit(id=i, collection="case_t", text=text, payload={"text": text, "granularity": "event"}, score=1.0)


class _Stub:
    def __init__(self, reply: str):
        self.reply = reply

    def complete(self, *a, **k):
        return self.reply


def test_plan_followups_parses_and_filters(monkeypatch):
    from dfa.generation import llm as llm_mod

    q = "What is the creation time of the parent process of powershell.exe?"
    monkeypatch.setattr(llm_mod, "get_llm", lambda: _Stub(
        'text before {"complete": false, "followups": [{"query": "pslist PID 4352 CreateTime", "why": "parent row"}, '
        '{"query": "What is the creation time of the parent process of powershell.exe?"}, {"query": ""}]} after'))
    hops = plan_followups(q, "ctx", 3)
    assert [h.query for h in hops] == ["pslist PID 4352 CreateTime"] and hops[0].why == "parent row"
    monkeypatch.setattr(llm_mod, "get_llm", lambda: _Stub('{"complete": true, "followups": []}'))
    assert plan_followups(q, "ctx", 3) == []
    monkeypatch.setattr(llm_mod, "get_llm", lambda: _Stub("not json at all"))
    assert plan_followups(q, "ctx", 3) == []


def test_run_hops_merges_new_evidence_only(monkeypatch):
    from dfa.generation import llm as llm_mod

    monkeypatch.setattr(llm_mod, "get_llm", lambda: _Stub(
        '{"complete": false, "followups": [{"query": "pslist PID 4352", "why": "parent"}, {"query": "psscan 4352", "why": "scan"}]}'))
    calls = []

    def fake_retrieve(case_id, question, route, filters, queries=None, enrich=True):
        calls.append((question, queries, route.value))
        return RetrievalResult(evidence=[_hit("p1", "pslist PID 4352 explorer.exe"), _hit("c1", "pslist PID 5096 powershell.exe PPID=4352")], attack=[], queries=queries or [question])

    monkeypatch.setattr(hops_mod, "retrieve", fake_retrieve)
    res = RetrievalResult(evidence=[_hit("c1", "pslist PID 5096 powershell.exe PPID=4352")], attack=[], queries=["q"])
    hops = run_hops("t", "parent of powershell?", Filters(), res, "ctx")
    # reranked against the follow-up text, evidence-only route, duplicates of the first round not re-added
    assert [c[0] for c in calls] == ["pslist PID 4352", "psscan 4352"] and all(c[1] == [c[0]] and c[2] == "evidence_only" for c in calls)
    assert [h.id for h in res.evidence] == ["c1", "p1"]
    assert [(h.query, h.added) for h in hops] == [("pslist PID 4352", 1), ("psscan 4352", 0)]


def test_hops_disabled(monkeypatch):
    from dfa.config import get_settings

    monkeypatch.setattr(get_settings().retrieval, "hops", 0)
    res = RetrievalResult(evidence=[_hit("c1", "x")], attack=[], queries=["q"])
    assert run_hops("t", "q", Filters(), res, "ctx") == [] and len(res.evidence) == 1
