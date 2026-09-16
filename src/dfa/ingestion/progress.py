"""Progress messages of an ingest run.

Everything user-facing about *what is going on* goes through the ``dfa.progress`` logger so the
CLI (Rich handler) and the API (plain logging) render it the same way.  ``say`` is for the lines an
analyst wants to see by default (one per parsed file, per Volatility / dissect plugin, per batch of
indexed chunks); ``detail`` is for the noise that only ``--verbose`` shows (skipped and unsupported
files, per-table row counts).
"""

from __future__ import annotations

import logging

log = logging.getLogger("dfa.progress")


def say(msg: str, *args: object) -> None:
    log.info(msg, *args)


def detail(msg: str, *args: object) -> None:
    log.debug(msg, *args)


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
