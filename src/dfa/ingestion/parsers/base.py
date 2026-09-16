"""Parser protocol and registry."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from dfa.ingestion.schema import Event


@dataclass
class ParseContext:
    case_id: str
    host_hint: str | None = None
    year_hint: int | None = None  # for timestamp formats without a year (BSD syslog)
    tz: str = "UTC"


class Parser(Protocol):
    kinds: tuple[str, ...]

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]: ...


_REGISTRY: dict[str, Parser] = {}


def register(parser: Parser) -> Parser:
    for k in parser.kinds:
        _REGISTRY[k] = parser
    return parser


def parser_for(kind: str) -> Parser | None:
    return _REGISTRY.get(kind)


def registered_kinds() -> list[str]:
    return sorted(_REGISTRY)


def load_all() -> None:
    """Import every parser module so they register themselves."""
    import importlib
    import pkgutil

    import dfa.ingestion.parsers as pkg

    for m in pkgutil.iter_modules(pkg.__path__):
        if m.name != "base":
            importlib.import_module(f"{pkg.__name__}.{m.name}")
    from dfa import agents  # disk / memory agents register themselves as parsers too

    for m in pkgutil.iter_modules(agents.__path__):
        importlib.import_module(f"{agents.__name__}.{m.name}")

