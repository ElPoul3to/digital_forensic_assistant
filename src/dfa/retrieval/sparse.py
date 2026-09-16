"""Sparse (BM25-style) encoding for hybrid search.

Qdrant applies IDF server-side when the sparse vector is configured with
``Modifier.IDF``; we only need per-document term frequencies keyed by a stable
hashed token id.  The tokenizer is IR-aware: IPs, hashes, hostnames, paths and
event ids are kept intact *and* split into sub-tokens so both exact and partial
matches work.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@\\/\-]*[A-Za-z0-9]|[A-Za-z0-9]")
_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")

_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "by", "is", "at", "with",
    "from", "as", "it", "this", "that", "was", "be", "are", "were", "has", "have",
}


def tokenize(text: str) -> list[str]:
    out: list[str] = []
    for tok in _TOKEN_RE.findall(text):
        low = tok.lower()
        if low in _STOP:
            continue
        out.append(low)
        parts = [p for p in _SPLIT_RE.split(low) if p and p != low and len(p) > 1]
        out.extend(p for p in parts if p not in _STOP)
    return out


def token_id(tok: str) -> int:
    return int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=4).digest(), "big")


def encode(text: str) -> tuple[list[int], list[float]]:
    """Return (indices, values) with raw term frequencies (BM25 TF saturation is applied by Qdrant)."""
    counts = Counter(tokenize(text))
    if not counts:
        return [], []
    idx = [token_id(t) for t in counts]
    val = [float(c) for c in counts.values()]
    return idx, val
