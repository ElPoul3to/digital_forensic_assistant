"""ATT&CK Navigator layer export (layer format 4.5).

A layer lists technique ids with a score; Navigator (https://mitre-attack.github.io/attack-navigator/)
colours the matrix from it.  We export the techniques cited in one or more answers, with the
question(s) as comment, so an investigation's ATT&CK coverage can be shown or shared.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def layer(techniques: dict[str, dict[str, Any]], name: str, description: str = "", domain: str = "enterprise-attack") -> dict[str, Any]:
    """techniques: {technique_id: {"score": int, "comment": str}}."""
    return {
        "name": name,
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": domain,
        "description": description,
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": [
            {"techniqueID": tid, "score": int(t.get("score", 1)), "comment": t.get("comment", ""), "enabled": True,
             "showSubtechniques": "." in tid}
            for tid, t in sorted(techniques.items())
        ],
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": max([t.get("score", 1) for t in techniques.values()] + [1])},
        "legendItems": [{"label": "cited in answers", "color": "#ff6666"}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


class LayerBuilder:
    """Accumulates cited techniques over several answers (e.g. a chat session)."""

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self.techniques: dict[str, dict[str, Any]] = {}

    def add(self, answer) -> None:  # dfa.generation.answer.Answer
        names = {c.get("id"): c.get("name") for c in answer.citations if c.get("kind") == "attack"}
        for tid in answer.attack_techniques:
            t = self.techniques.setdefault(tid, {"score": 0, "comment": ""})
            t["score"] += 1
            line = f"Q: {answer.question}" + (f" ({names[tid]})" if names.get(tid) else "")
            t["comment"] = (t["comment"] + "\n" + line).strip()
        # sub-technique implies the parent technique
        for tid in list(self.techniques):
            if "." in tid:
                parent = self.techniques.setdefault(tid.split(".")[0], {"score": 0, "comment": ""})
                parent["comment"] = (parent["comment"] + f"\nvia {tid}").strip() if f"via {tid}" not in parent["comment"] else parent["comment"]

    def build(self) -> dict[str, Any]:
        return layer(self.techniques, name=f"case {self.case_id}", description=f"ATT&CK techniques cited by the Digital Forensic Assistant for case {self.case_id}")

    def write(self, path: Path) -> Path:
        path.write_text(json.dumps(self.build(), indent=2))
        return path
