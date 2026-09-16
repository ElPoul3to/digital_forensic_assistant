from dfa.generation.answer import Answer
from dfa.generation.navigator import LayerBuilder, layer
from dfa.retrieval.retriever import Hit, _rerank


def _answer(q, techs, names=None):
    cites = [{"label": t, "kind": "attack", "id": t, "name": (names or {}).get(t)} for t in techs]
    return Answer(question=q, answer="x", route="evidence+attack", route_reason="", filters={}, queries=[q], citations=cites,
                  invalid_citations=[], retrieved=[], attack_techniques=list(techs))


def test_layer_builder_accumulates_and_adds_parents():
    b = LayerBuilder("c1")
    b.add(_answer("uid 0 accounts?", ["T1136.001", "T1078"], {"T1136.001": "Create Account: Local Account"}))
    b.add(_answer("brute force?", ["T1110.001", "T1078"]))
    lay = b.build()
    ids = {t["techniqueID"]: t for t in lay["techniques"]}
    assert set(ids) == {"T1136.001", "T1136", "T1078", "T1110.001", "T1110"}
    assert ids["T1078"]["score"] == 2 and "uid 0 accounts?" in ids["T1078"]["comment"] and "brute force?" in ids["T1078"]["comment"]
    assert "Create Account: Local Account" in ids["T1136.001"]["comment"] and ids["T1136.001"]["showSubtechniques"]
    assert ids["T1136"]["comment"] == "via T1136.001" and ids["T1136"]["score"] == 0
    assert lay["versions"]["layer"] == "4.5" and lay["domain"] == "enterprise-attack" and lay["gradient"]["maxValue"] == 2
    assert _answer("q", ["T1059"]).navigator_layer("c1")["techniques"][0]["techniqueID"] == "T1059"
    assert layer({}, "empty")["techniques"] == []


def test_rerank_switch_keeps_fused_order(monkeypatch):
    from dfa.config import get_settings

    hits = [Hit(id=str(i), collection="case_c", text=f"t{i}", payload={}, score=s) for i, s in enumerate([0.1, 0.9, 0.5])]
    monkeypatch.setattr(get_settings().retrieval, "rerank", False)
    assert [h.id for h in _rerank("q", hits, 2)] == ["1", "2"]
    assert all(h.rerank is None for h in hits)  # the cross-encoder was never loaded
