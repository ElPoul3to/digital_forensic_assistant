"""Multi-query rewriting + HyDE (a hypothetical log line that would answer the question)."""

from __future__ import annotations

import json
import logging
import re

log = logging.getLogger(__name__)

_PROMPT = """You help retrieve log events and forensic artefacts for an incident-response analyst.

Question: {q}

Produce JSON with:
- "queries": up to 3 short alternative phrasings using the vocabulary that would appear in raw logs
  (daemon names, event names, field names, exact IPs/users/hosts from the question).
- "hyde": one plausible raw log line (syslog, Windows event, web access log, ...) that would directly answer the question.

JSON only."""


def rewrite(q: str, n: int = 3) -> list[str]:
    from dfa.generation.llm import get_llm

    out = [q]
    try:
        raw = get_llm().complete(_PROMPT.format(q=q), max_tokens=300)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        data = json.loads(m.group(0)) if m else {}
        for alt in (data.get("queries") or [])[:n]:
            if isinstance(alt, str) and alt.strip() and alt.strip() not in out:
                out.append(alt.strip())
        if isinstance(data.get("hyde"), str) and data["hyde"].strip():
            out.append(data["hyde"].strip())
    except Exception as e:  # noqa: BLE001
        log.warning("query rewrite failed, using original only: %s", e)
    return out
