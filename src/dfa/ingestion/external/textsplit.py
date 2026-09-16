"""Paragraph-packing text splitter for external documents (ATT&CK entries)."""

from __future__ import annotations

import re


def _tok(s: str) -> int:
    return len(s) // 4 + 1


def windows(text: str, max_tokens: int, overlap_tokens: int) -> list[str]:
    """Greedy paragraph packing into ~max_tokens windows with paragraph-level overlap."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    # very long paragraphs are cut on sentence boundaries
    pieces: list[str] = []
    for p in paras:
        if _tok(p) <= max_tokens:
            pieces.append(p)
            continue
        cur = ""
        for sent in re.split(r"(?<=[.!?])\s+", p):
            if cur and _tok(cur + " " + sent) > max_tokens:
                pieces.append(cur)
                cur = sent
            else:
                cur = f"{cur} {sent}".strip()
        if cur:
            pieces.append(cur)
    out: list[str] = []
    cur_parts: list[str] = []
    cur_tok = 0
    for piece in pieces:
        t = _tok(piece)
        if cur_parts and cur_tok + t > max_tokens:
            out.append("\n\n".join(cur_parts))
            # keep trailing paragraphs as overlap
            keep: list[str] = []
            kt = 0
            for prev in reversed(cur_parts):
                if kt + _tok(prev) > overlap_tokens:
                    break
                keep.insert(0, prev)
                kt += _tok(prev)
            cur_parts, cur_tok = keep, kt
        cur_parts.append(piece)
        cur_tok += t
    if cur_parts:
        out.append("\n\n".join(cur_parts))
    return out
