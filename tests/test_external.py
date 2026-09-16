from dfa.ingestion.external.attack_stix import chunks_from_bundle
from dfa.ingestion.external.textsplit import windows


def test_textsplit():
    w = windows("\n\n".join(f"paragraph {i} " + "x" * 300 for i in range(10)), max_tokens=200, overlap_tokens=80)
    assert len(w) > 3 and all(len(x) // 4 + 1 <= 260 for x in w)
    assert "paragraph 1" in w[1]  # overlap carries the previous paragraph


def _bundle():
    return [
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Persistence", "x_mitre_shortname": "persistence"},
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Valid Accounts: Domain Accounts",
         "description": "Adversaries may obtain domain accounts.(Citation: X) See [docs](http://x).",
         "x_mitre_detection": "Monitor logon events.", "x_mitre_platforms": ["Windows", "Linux"],
         "x_mitre_is_subtechnique": True, "x_mitre_version": "1.3",
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1078.002", "url": "https://attack.mitre.org/techniques/T1078/002"}]},
        {"type": "attack-pattern", "id": "attack-pattern--2", "name": "Old", "revoked": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "APT99", "aliases": ["APT99", "Fancy Badger"], "description": "A group.",
         "external_references": [{"source_name": "mitre-attack", "external_id": "G0099", "url": "u"}]},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1"},
    ]


def test_attack_chunks():
    chunks = list(chunks_from_bundle(_bundle()))
    ids = {c.metadata["attack_id"] for c in chunks}
    assert ids == {"T1078.002", "G0099"}
    t = next(c for c in chunks if c.metadata["attack_id"] == "T1078.002")
    assert "(Citation" not in t.text and "docs" in t.text and "Detection: Monitor logon events." in t.text
    assert t.metadata["tactics"] == ["Persistence"] and t.metadata["platforms"] == ["Windows", "Linux"]
    g = next(c for c in chunks if c.metadata["attack_id"] == "G0099")
    assert "Techniques used: Valid Accounts: Domain Accounts" in g.text and "Fancy Badger" in g.text
    assert not any(c.metadata["attack_id"] == "T9999" for c in chunks)
