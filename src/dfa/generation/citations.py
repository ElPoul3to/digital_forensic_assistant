"""Validate citation labels in an answer against the context that was provided."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_LABEL = re.compile(r"\[((?:E|S)\d+|T\d{4}(?:\.\d{3})?)\]")


_ATTACK_LABEL = re.compile(r"T\d{4}(?:\.\d{3})?")


@dataclass
class Validation:
    valid: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)  # evidence / timeline labels that do not exist in the context
    unverified_attack: list[str] = field(default_factory=list)  # ATT&CK ids cited without an ATT&CK entry in context
    answer: str = ""


def validate(answer: str, known: set[str]) -> Validation:
    v = Validation()
    seen: dict[str, None] = {}
    for m in _LABEL.finditer(answer):
        seen.setdefault(m.group(1), None)
    for label in seen:
        if label in known:
            v.valid.append(label)
        elif _ATTACK_LABEL.fullmatch(label):
            v.unverified_attack.append(label)  # model knowledge, not fabricated evidence: keep but mark
        else:
            v.invalid.append(label)
    out = answer
    for bad in v.invalid:
        out = out.replace(f"[{bad}]", f"[{bad}?invalid]")
    for aid in v.unverified_attack:
        out = out.replace(f"[{aid}]", f"[{aid}?unverified]")
    v.answer = out
    return v
