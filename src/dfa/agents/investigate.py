"""Agentic investigation loop: the model chooses which artefacts to extract
from a disk image, a memory image or an evidence directory, the events are
indexed into the case, the question is answered, and the model may ask for
one more round of extraction when the answer is not grounded enough.

The catalogue of extractors is built from the disk and memory agents' plugin
lists (per detected OS) and from the loose-file parsers.  What has already
been extracted for a case is remembered in ``data/cases/<case>/extracted.json``
so repeated questions do not re-run the same plugins.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dfa.config import get_settings
from dfa.ingestion.detect import detect
from dfa.ingestion.parsers.base import ParseContext, load_all, parser_for
from dfa.ingestion.schema import Event

log = logging.getLogger(__name__)

_SYSTEM = ("You are a digital forensics lead planning evidence extraction. You answer with one JSON object only, no prose, no markdown fences.")


@dataclass
class Extractor:
    key: str  # "disk:<artefact>:<plugin>" | "memory:<artefact>:<plugin>" | "file:<artefact>"
    kind: str
    artefact: Path
    plugin: str
    description: str
    run: Callable[[], Iterator[Event]]


@dataclass
class Round:
    chosen: list[str]
    reason: str
    events: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    answer: str = ""
    citations: int = 0
    seconds: float = 0.0


@dataclass
class Investigation:
    case_id: str
    question: str
    catalogue: list[Extractor]
    rounds: list[Round] = field(default_factory=list)
    answer: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "question": self.question, "catalogue": [e.key for e in self.catalogue],
                "rounds": [{"chosen": r.chosen, "reason": r.reason, "events": r.events, "errors": r.errors, "citations": r.citations,
                            "seconds": r.seconds, "answer": r.answer} for r in self.rounds],
                "answer": self.answer.to_dict() if self.answer is not None and hasattr(self.answer, "to_dict") else None}


# ---- catalogue ------------------------------------------------------------------

def build_catalogue(paths: list[Path], ctx: ParseContext) -> list[Extractor]:
    """One extractor per (artefact, plugin) for disk / memory images, one per loose file."""
    from dfa.agents.disk import DiskAgent
    from dfa.agents.memory import DEFAULT_SKIP as MEM_DEFAULT_SKIP
    from dfa.agents.memory import PLUGINS as MEM_PLUGINS
    from dfa.agents.memory import MemoryAgent

    load_all()
    out: list[Extractor] = []
    for p in paths:
        kind = "dir_target" if p.is_dir() else detect(p).kind
        if kind == "dir_target" or kind in DiskAgent.kinds:
            probe = DiskAgent()
            try:
                info = probe.describe(probe.open(p))
            except Exception as e:  # noqa: BLE001
                log.warning("cannot open %s as a disk target: %s", p, e)
                continue
            for plug in probe.plugin_list(info.get("os")):
                out.append(Extractor(f"disk:{p.name}:{plug.name}", "disk", p, plug.name, f"[{info.get('os', '?')} disk {p.name}] {plug.description}",
                                     _disk_runner(p, plug.name, ctx)))
        elif kind in MemoryAgent.kinds:
            probe = MemoryAgent()
            os_name = probe.detect_os(p)
            if not os_name:
                log.warning("cannot identify the OS of memory image %s (missing symbols?)", p)
                continue
            for plug in MEM_PLUGINS.get(os_name, []):  # the full list, including the slow ones skipped by default
                slow = ", slow" if plug.name in MEM_DEFAULT_SKIP else ""
                out.append(Extractor(f"memory:{p.name}:{plug.name}", "memory", p, plug.name, f"[{os_name} memory {p.name}{slow}] {plug.description}",
                                     _memory_runner(p, plug.name, ctx)))
        else:
            parser = parser_for(kind)
            if parser is None:
                log.info("no parser for %s (%s)", p, kind)
                continue
            out.append(Extractor(f"file:{p.name}", "file", p, kind, f"[{kind} file {p.name}] parse the whole file", _file_runner(p, parser, ctx)))
    return out


def _disk_runner(path: Path, plugin: str, ctx: ParseContext) -> Callable[[], Iterator[Event]]:
    def run() -> Iterator[Event]:
        from dfa.agents.disk import DiskAgent

        agent = DiskAgent(plugins=[plugin])
        for ev in agent.parse(path, ctx):
            if ev.action != "disk_image_info":
                yield ev
        for r in agent.results:
            if r.status in ("error", "missing"):
                raise RuntimeError(f"{r.name}: {r.status} {r.error or ''}".strip())
    return run


def _memory_runner(path: Path, plugin: str, ctx: ParseContext) -> Callable[[], Iterator[Event]]:
    def run() -> Iterator[Event]:
        from dfa.agents.memory import MemoryAgent

        agent = MemoryAgent(plugins=[plugin])
        for ev in agent.parse(path, ctx):
            if ev.action != "memory_image_info":
                yield ev
        for r in agent.runs:
            if r.status in ("error", "timeout"):
                raise RuntimeError(f"{r.name}: {r.status} {r.error or ''}".strip())
    return run


def _file_runner(path: Path, parser, ctx: ParseContext) -> Callable[[], Iterator[Event]]:
    return lambda: parser.parse(path, ctx)


# ---- state ------------------------------------------------------------------------

def _state_path(case_id: str) -> Path:
    return get_settings().cases_dir / case_id / "extracted.json"


def load_state(case_id: str) -> dict[str, Any]:
    p = _state_path(case_id)
    try:
        return json.loads(p.read_text()) if p.exists() else {}
    except json.JSONDecodeError:
        return {}


def save_state(case_id: str, state: dict[str, Any]) -> None:
    p = _state_path(case_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=1, default=str))


# ---- model decisions --------------------------------------------------------------

def _json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}


def choose(llm, question: str, catalogue: list[Extractor], done: set[str], limit: int, previous_answer: str | None = None) -> tuple[list[str], str]:
    """Ask the model which extractors to run next. Returns (keys, reason)."""
    lines = []
    for i, e in enumerate(catalogue, 1):
        mark = " (already extracted)" if e.key in done else ""
        lines.append(f"{i}. {e.key}{mark}: {e.description}")
    prompt = (f"Question from the analyst: {question}\n\n"
              + (f"Answer produced so far (may be incomplete or ungrounded):\n{previous_answer[:2500]}\n\n" if previous_answer else "")
              + "Available extractors (artefact plugins that turn evidence into searchable events):\n" + "\n".join(lines)
              + f"\n\nPick at most {limit} extractors, not yet extracted, whose output is most likely to answer the question. "
              + ("If the current answer already rests on the evidence and nothing more is needed, pick none. " if previous_answer else "")
              + 'Reply with JSON: {"extractors": ["<key>", ...], "reason": "<one sentence>"}')
    raw = llm.complete(prompt, system=_SYSTEM, max_tokens=400)
    obj = _json_object(raw)
    keys = [k for k in obj.get("extractors", []) if isinstance(k, str)]
    valid = {e.key for e in catalogue}
    picked = []
    for k in keys:
        k2 = k.strip()
        if k2 not in valid:  # accept "3" or "3." style references
            m = re.fullmatch(r"(\d+)\.?", k2)
            if m and 0 < int(m.group(1)) <= len(catalogue):
                k2 = catalogue[int(m.group(1)) - 1].key
        if k2 in valid and k2 not in done and k2 not in picked:
            picked.append(k2)
        if len(picked) >= limit:
            break
    return picked, str(obj.get("reason", ""))[:300]


# ---- loop ---------------------------------------------------------------------------

def investigate(case_id: str, paths: list[Path], question: str, *, max_rounds: int = 2, per_round: int = 4, host: str | None = None,
                llm=None, indexer=None, asker=None, progress: Callable[[str], None] | None = None) -> Investigation:
    from dfa.generation.answer import ask as _ask
    from dfa.generation.llm import get_llm
    from dfa.ingestion.pipeline import index_events

    llm = llm or get_llm()
    indexer = indexer or index_events
    asker = asker or _ask
    say = progress or (lambda msg: log.info(msg))
    ctx = ParseContext(case_id=case_id, host_hint=host)
    catalogue = build_catalogue(paths, ctx)
    inv = Investigation(case_id=case_id, question=question, catalogue=catalogue)
    if not catalogue:
        say("nothing to extract from the given paths")
        return inv
    by_key = {e.key: e for e in catalogue}
    state = load_state(case_id)
    done = set(state)
    previous = None
    for rnd in range(1, max_rounds + 1):
        t0 = time.time()
        chosen, reason = choose(llm, question, catalogue, done, per_round, previous_answer=previous)
        say(f"round {rnd}: {len(chosen)} extractor(s) chosen" + (f" ({reason})" if reason else ""))
        if not chosen and rnd > 1:
            break
        r = Round(chosen=chosen, reason=reason)
        inv.rounds.append(r)
        for key in chosen:
            ex = by_key[key]
            say(f"  extracting {key}")
            n = 0

            def counted(ex=ex):
                nonlocal n
                for ev in ex.run():
                    n += 1
                    yield ev
            try:
                indexer(case_id, counted())
                r.events[key] = n
            except Exception as e:  # noqa: BLE001
                r.errors[key] = f"{type(e).__name__}: {e}"[:300]
                r.events[key] = n
                say(f"  {key} failed: {r.errors[key]}")
            state[key] = {"events": n, "ts": datetime.now(UTC).isoformat(), "error": r.errors.get(key)}
            done.add(key)
            save_state(case_id, state)
        say(f"  answering (round {rnd})")
        ans = asker(case_id, question, interface="investigate")
        inv.answer = ans
        r.answer = getattr(ans, "answer", str(ans))
        r.citations = len(getattr(ans, "citations", []) or [])
        r.seconds = round(time.time() - t0, 1)
        previous = r.answer
        if not any(e.key not in done for e in catalogue):
            break
    return inv
