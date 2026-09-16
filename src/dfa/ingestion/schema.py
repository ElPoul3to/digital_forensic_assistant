"""Normalised event and chunk models shared by every parser and the retriever."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Source(str, Enum):
    JSON = "json"
    SYSLOG = "syslog"
    EVTX = "evtx"
    CSV = "csv"
    PCAP = "pcap"
    APACHE = "apache"
    DMESG = "dmesg"
    DPKG = "dpkg"
    DISK = "disk"
    MEMORY = "memory"
    OTHER = "other"


class Category(str, Enum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    PRIVILEGE = "privilege"
    PACKAGE = "package"
    KERNEL = "kernel"
    WEB = "web"
    SERVICE = "service"
    USER_MGMT = "user_management"
    OTHER = "other"


class IOC(BaseModel):
    ip: list[str] = Field(default_factory=list)
    domain: list[str] = Field(default_factory=list)
    hash: list[str] = Field(default_factory=list)
    user: list[str] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    url: list[str] = Field(default_factory=list)

    def merge(self, other: IOC) -> IOC:
        out = IOC()
        for f in IOC.model_fields:
            seen: dict[str, None] = {}
            for v in getattr(self, f) + getattr(other, f):
                seen.setdefault(v, None)
            setattr(out, f, list(seen))
        return out

    def is_empty(self) -> bool:
        return not any(getattr(self, f) for f in IOC.model_fields)


class Event(BaseModel):
    """One normalised event produced by a parser."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    timestamp: datetime | None = None
    source: Source = Source.OTHER
    source_file: str
    record_ref: str  # e.g. "line 4821", "record 48213", "frame 1023"
    host: str | None = None
    user: str | None = None
    process: str | None = None
    category: Category = Category.OTHER
    action: str | None = None
    ioc: IOC = Field(default_factory=IOC)
    summary: str
    raw: str
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def ts_iso(self) -> str:
        if self.timestamp is None:
            return "unknown-time"
        ts = self.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def stable_id(self) -> str:
        """Deterministic id so re-ingesting the same file upserts instead of duplicating."""
        key = f"{self.case_id}|{self.source_file}|{self.record_ref}|{self.raw}"
        return str(uuid.UUID(hashlib.sha1(key.encode()).hexdigest()[:32]))


class Granularity(str, Enum):
    EVENT = "event"
    WINDOW = "window"
    DOCUMENT = "document"  # external knowledge


class Chunk(BaseModel):
    """What actually gets embedded and stored."""

    chunk_id: str
    collection: str
    text: str
    granularity: Granularity
    metadata: dict[str, Any] = Field(default_factory=dict)

    @staticmethod
    def make_id(collection: str, key: str) -> str:
        return str(uuid.UUID(hashlib.sha1(f"{collection}|{key}".encode()).hexdigest()[:32]))
