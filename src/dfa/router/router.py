"""Query router: decides which knowledge tiers to search and extracts filters."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from dfa.config import get_settings
from dfa.ingestion import timeutil

log = logging.getLogger(__name__)


class Route(str, Enum):
    EVIDENCE_ONLY = "evidence_only"
    EVIDENCE_ATTACK = "evidence+attack"
    ATTACK_ONLY = "attack_only"

    @property
    def evidence(self) -> bool:
        return self != Route.ATTACK_ONLY

    @property
    def attack(self) -> bool:
        return self in (Route.EVIDENCE_ATTACK, Route.ATTACK_ONLY)


@dataclass
class Filters:
    host: str | None = None
    user: str | None = None
    ip: str | None = None
    ts_from: datetime | None = None
    ts_to: datetime | None = None
    ids: list[str] = field(default_factory=list)  # ATT&CK ids mentioned explicitly

    def is_empty(self) -> bool:
        return not any((self.host, self.user, self.ip, self.ts_from, self.ts_to))


@dataclass
class Decision:
    route: Route
    filters: Filters
    reason: str
    aggregate: bool = False  # counting / listing question -> also run a structured timeline query


_ATTACK_WORDS = re.compile(
    r"\b(att&?ck|mitre|techniques?|sub-?techniques?|tactics?|ttps?|t1\d{3}(?:\.\d{3})?|kill ?chain|"
    r"lateral movement|persistence|privilege escalation|defen[cs]e evasion|credential access|discovery|"
    r"collection|exfiltration|command and control|c2|initial access|execution|impact|map(?:ped|ping)? to)\b",
    re.IGNORECASE,
)
# Questions whose answer is a number or an exhaustive list. The top-k chunks the vector store returns are only
# a sample, so these also get an exact SQL query over the timeline (timeline/query.py).
_AGGREGATE_WORDS = re.compile(
    r"\b(count|how many|how often|how much|total(?: number)?|number of|sum of|average|mean|median|"
    r"(?:list|show|give|enumerate|name) (?:me )?(?:all|every|each|the distinct|the unique)|all (?:the )?(?:distinct|unique)?\s?"
    r"(?:ips?|ip addresses|addresses|users?|accounts?|hosts?|files?|packages?|commands?|requests?|logins?|sessions?|"
    r"events?|lines?|entries|records?|connections?)|distinct|unique|per (?:host|user|ip|day|hour|minute|file|source)|"
    r"top \d+|most (?:frequent|common|active)|least (?:frequent|common)|busiest|breakdown|statistics|stats|volume|"
    r"user[- ]?agents?|the most|"
    r"(?:parent|child|children) (?:process(?:es)?|of)|creation (?:date|time)|(?:start|create|exit) time|"
    r"which (?:\w+ ){0,2}(?:ips?|ip addresses|users?|accounts?|hosts?|packages?|files?|commands?|processes))\b",
    re.IGNORECASE,
)
_EVIDENCE_WORDS = re.compile(
    r"\b(logs?|events?|hosts?|evidence|timeline|when|who|which (?:account|user|ip|host|process)|first|last|"
    r"ssh|logon|login|sudo|auth|apache|http|process|command|file|ip|\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HOST = re.compile(r"\b(?:on|from|host|server|machine|workstation)\s+(?:host\s+)?([A-Za-z][\w.-]*\d[\w.-]*|[A-Z]{2,}[\w-]*\d*)\b")
_USER = re.compile(r"\b(?:user|account|username|login)\s+[\"']?([A-Za-z_][\w.\\-]*)[\"']?", re.IGNORECASE)
_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Words that follow "user"/"account" in ordinary English and must not become a username filter.
_USER_STOP = frozenset({
    "account", "accounts", "user", "users", "name", "names", "id", "ids", "login", "logins", "logon", "logons",
    "created", "creation", "added", "deleted", "removed", "modified", "was", "were", "is", "are", "has", "have",
    "had", "did", "do", "does", "that", "which", "who", "whose", "with", "without", "the", "a", "an", "and", "or",
    "from", "on", "in", "to", "of", "for", "by", "at", "called", "named", "activity", "actions", "sessions",
    "session", "password", "passwords", "credentials", "privileges", "root", "admin", "administrator",
})
_BETWEEN = re.compile(r"\bbetween\s+(.+?)\s+and\s+(.+?)(?:[.,;]|$)", re.IGNORECASE)
_AFTER = re.compile(r"\b(?:after|since|from)\s+(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?)", re.IGNORECASE)
_BEFORE = re.compile(r"\b(?:before|until|up to)\s+(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?)", re.IGNORECASE)
_ON_DATE = re.compile(r"\bon\s+(\d{4}-\d{2}-\d{2})\b", re.IGNORECASE)


def extract_filters(q: str) -> Filters:
    f = Filters()
    if m := _IP.search(q):
        f.ip = m.group(0)
    if m := _HOST.search(q):
        cand = m.group(1)
        if not _IP.fullmatch(cand):
            f.host = cand
    for m in _USER.finditer(q):
        cand = m.group(1)
        if cand.lower() not in _USER_STOP:
            f.user = cand
            break
    f.ids = _ATTACK_ID.findall(q)
    if m := _BETWEEN.search(q):
        a, b = timeutil.parse_any(m.group(1)), timeutil.parse_any(m.group(2))
        if a and b:
            f.ts_from, f.ts_to = a, b
    if m := _AFTER.search(q):
        f.ts_from = timeutil.parse_any(m.group(1)) or f.ts_from
    if m := _BEFORE.search(q):
        f.ts_to = timeutil.parse_any(m.group(1)) or f.ts_to
    if not f.ts_from and (m := _ON_DATE.search(q)):
        d = timeutil.parse_any(m.group(1))
        if d:
            f.ts_from = d.replace(hour=0, minute=0, second=0)
            f.ts_to = d.replace(hour=23, minute=59, second=59)
    return f


def heuristic_route(q: str) -> tuple[Route, str] | None:
    a, e = bool(_ATTACK_WORDS.search(q)), bool(_EVIDENCE_WORDS.search(q))
    if a and not e:
        return Route.ATTACK_ONLY, "keywords: attack, no evidence terms"
    if a:
        return Route.EVIDENCE_ATTACK, "keywords: attack"
    return None


def is_aggregate(q: str) -> bool:
    """True for questions that need a count or an exhaustive list rather than a few example events."""
    return bool(_AGGREGATE_WORDS.search(q))


_LLM_PROMPT = """You are a router for an incident-response assistant. Classify the analyst question into exactly one label.

Labels:
{labels}

Question: {q}

Answer with JSON only: {{"label": "<one of the labels>"}}"""


def llm_route(q: str) -> tuple[Route, str] | None:
    from dfa.generation.llm import get_llm

    cfg = get_settings().router
    labels = "\n".join(f"- {k}: {v}" for k, v in cfg.labels.items())
    try:
        raw = get_llm().complete(_LLM_PROMPT.format(labels=labels, q=q), max_tokens=64)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        label = json.loads(m.group(0))["label"] if m else raw.strip().strip('"')
        return Route(label), "llm"
    except Exception as e:  # noqa: BLE001
        log.warning("llm router failed: %s", e)
        return None


def decide(q: str, route: str | None = None, use_llm: bool = True) -> Decision:
    cfg = get_settings().router
    filters = extract_filters(q)
    if route and route != "auto":
        r = Route(route)
        reason = "explicit"
    else:
        picked = heuristic_route(q) or (llm_route(q) if use_llm else None) or (Route.EVIDENCE_ONLY, "default")
        r, reason = picked
    if not cfg.allow_external and r != Route.EVIDENCE_ONLY:
        r, reason = Route.EVIDENCE_ONLY, reason + " (external disabled)"
    agg = r.evidence and cfg.timeline_queries and is_aggregate(q)
    if agg:
        reason += " + timeline query"
    return Decision(route=r, filters=filters, reason=reason, aggregate=agg)
