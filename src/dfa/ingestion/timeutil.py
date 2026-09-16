"""Timestamp helpers: epoch-format guessing and lenient string parsing."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from dateutil import parser as du

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)
_EPOCH_2001 = datetime(2001, 1, 1, tzinfo=UTC)
_UNIX = datetime(1970, 1, 1, tzinfo=UTC)

# Plausible range for an artefact timestamp: 1995 .. 2040
_MIN = datetime(1995, 1, 1, tzinfo=UTC)
_MAX = datetime(2040, 1, 1, tzinfo=UTC)


def _ok(dt: datetime | None) -> datetime | None:
    return dt if dt and _MIN <= dt <= _MAX else None


def from_epoch(value: float, hint: str | None = None) -> datetime | None:
    """Convert a numeric timestamp in an unknown epoch format.

    ``hint`` may be ``"webkit"`` (Chrome, µs since 1601), ``"filetime"`` (100 ns since 1601),
    ``"mac"`` (seconds since 2001), ``"unix"``, ``"unix_ms"``, ``"unix_us"``, ``"unix_ns"``.
    Without a hint the magnitude decides.
    """
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    try:
        if hint == "webkit":
            return _ok(_EPOCH_1601 + timedelta(microseconds=v))
        if hint == "filetime":
            return _ok(_EPOCH_1601 + timedelta(microseconds=v / 10))
        if hint == "mac":
            return _ok(_EPOCH_2001 + timedelta(seconds=v))
        if hint == "unix":
            return _ok(_UNIX + timedelta(seconds=v))
        if hint == "unix_ms":
            return _ok(_UNIX + timedelta(milliseconds=v))
        if hint == "unix_us":
            return _ok(_UNIX + timedelta(microseconds=v))
        if hint == "unix_ns":
            return _ok(_UNIX + timedelta(microseconds=v / 1000))
        # magnitude heuristics
        if 7.8e8 <= v < 2.3e9:  # 1994..2042 unix seconds
            return _ok(_UNIX + timedelta(seconds=v))
        if 7.8e11 <= v < 2.3e12:  # unix ms
            return _ok(_UNIX + timedelta(milliseconds=v))
        if 7.8e14 <= v < 2.3e15:  # unix µs
            return _ok(_UNIX + timedelta(microseconds=v))
        if 1.24e16 <= v < 1.39e16:  # webkit µs since 1601 (1994..2041)
            return _ok(_EPOCH_1601 + timedelta(microseconds=v))
        if 1.24e17 <= v < 1.39e17:  # FILETIME
            return _ok(_EPOCH_1601 + timedelta(microseconds=v / 10))
        if 7.8e17 <= v < 2.3e18:  # unix ns
            return _ok(_UNIX + timedelta(microseconds=v / 1000))
    except (OverflowError, ValueError):
        return None
    return None


_NUMERIC = re.compile(r"^\d+(\.\d+)?$")
_TIME_ONLY = re.compile(r"^\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?\s*(am|pm)?$", re.IGNORECASE)


def parse_any(value: object, hint: str | None = None) -> datetime | None:
    """Parse an int/float epoch or an ISO / RFC / free-form date string."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        return from_epoch(value, hint)
    s = str(value).strip()
    if not s:
        return None
    if _NUMERIC.match(s):
        return from_epoch(float(s), hint)
    if _TIME_ONLY.match(s):  # "13:00:00" would silently become today
        return None
    try:
        dt = du.parse(s)
    except (ValueError, OverflowError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return _ok(dt)


_TS_COLUMN_HINTS = (
    "time", "date", "_ts", "ts_", "timestamp", "created", "modified", "accessed", "visited",
    "expires", "last_", "start", "end", "epoch", "when", "at",
)


def looks_like_time_column(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _TS_COLUMN_HINTS) or n in {"ts", "at"}
