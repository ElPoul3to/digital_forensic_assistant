"""Lightweight IOC extraction from free text."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from dfa.ingestion.schema import IOC

_IPV4 = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
)
# IPv6: either all eight groups or a "::"-compressed form.  A looser "2..7 groups" pattern also
# matched clock times (11:32:42), MAC addresses and GUID fragments.
_H = r"[0-9a-fA-F]{1,4}"
_IPV6 = re.compile(
    rf"(?<![:\w.])(?:"
    rf"(?:{_H}:){{7}}{_H}"  # 2001:db8:0:0:0:0:0:1
    rf"|(?:{_H}:){{1,7}}:(?:{_H}(?::{_H}){{0,6}})?"  # fe80::1, 2001:db8::, 2001:db8::8a2e:370:7334
    rf"|::(?:{_H}(?::{_H}){{0,6}})?"  # ::1, ::
    rf"|::ffff:(?:\d{{1,3}}\.){{3}}\d{{1,3}}"  # ::ffff:192.0.2.1
    rf")(?![:\w])"
)
# Dotted quads that are version numbers, not addresses: "Version=4.0.0.0", ".NET 2.0.0.0", "v1.0.0.1".
_VERSION_CTX = re.compile(
    r"(?i)(?:version|ver|v|build|release|framework|assembly|runtime|sdk|kit)\s*[=:]?\s*$"
)
# x.0.y.z with a single-digit first octet (4.0.0.0, 2.0.0.0, 1.0.0.1) or ending in .0 with a first
# octet <= 10 (10.0.0.0, 4.6.0.0, 6.2.1.0): assembly / product versions, never a usable indicator.
_VERSION_LIKE = re.compile(r"^(?:\d\.0\.\d{1,3}\.\d{1,3}|(?:\d|10)\.\d{1,3}\.\d{1,3}\.0)$")

# Top-level labels a real domain can end with.  The bare regex also matched dotted identifiers such as
# "windows.backgroundtasks", "icon.png" or "fiber.scheduler"; any 2-letter label is accepted as a ccTLD.
_TLD_OK = frozenset(
    [
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "info",
        "biz",
        "name",
        "pro",
        "aero",
        "coop",
        "museum",
        "jobs",
        "mobi",
        "travel",
        "tel",
        "asia",
        "cat",
        "xxx",
        "post",
        "io",
        "co",
        "ai",
        "app",
        "dev",
        "cloud",
        "tech",
        "online",
        "site",
        "website",
        "store",
        "shop",
        "xyz",
        "top",
        "club",
        "live",
        "news",
        "blog",
        "page",
        "link",
        "me",
        "tv",
        "cc",
        "ws",
        "fm",
        "to",
        "ly",
        "gg",
        "sh",
        "nu",
        "su",
        "онлайн",
        "onion", "example", "test", "invalid",
        "local",
        "localhost",
        "internal",
        "intranet",
        "lan",
        "corp",
        "home",
        "arpa",
    ]
)
_MIN_DISTINCT_HEX = 8  # "0000...0000" or "0102000000000f03..." are binary blobs, not digests
_MD5 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
_SHA1 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
_SHA256 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+")
_DOMAIN = re.compile(
    r"(?<![\w.\-@/])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})(?![\w\-])",
    re.IGNORECASE,
)
_WIN_PATH = re.compile(r"(?<![\w])[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
_NIX_PATH = re.compile(r"(?<![\w.])/(?:[\w.\-]+/)+[\w.\-]*")

_LOCAL_TLD_SKIP = {
    "log",
    "txt",
    "exe",
    "dll",
    "so",
    "py",
    "sh",
    "conf",
    "cfg",
    "json",
    "xml",
    "csv",
}


def _is_version(text: str, m: re.Match) -> bool:
    """True for dotted quads that are version numbers (Version=4.0.0.0, v1.0.0.1, 2.0.0.0)."""
    if _VERSION_CTX.search(text[max(0, m.start() - 12) : m.start()]):
        return True
    return _VERSION_LIKE.match(m.group(0)) is not None and m.group(0) != "0.0.0.0"


def extract(text: str) -> IOC:
    ioc = IOC()
    ioc.ip = _uniq(
        [m.group(0) for m in _IPV4.finditer(text) if not _is_version(text, m)] + _IPV6.findall(text)
    )
    ioc.hash = _uniq(
        [
            h.lower()
            for h in _SHA256.findall(text) + _SHA1.findall(text) + _MD5.findall(text)
            if len(set(h.lower())) >= _MIN_DISTINCT_HEX
        ]
    )
    ioc.url = _uniq(_URL.findall(text))
    doms = []
    for u in ioc.url:
        try:
            host = urlparse(u).hostname
        except ValueError:  # e.g. "Invalid IPv6 URL" on a malformed bracket in the text
            continue
        if host and not _IPV4.fullmatch(host):
            doms.append(host.lower())
    for d in _DOMAIN.findall(text):
        tld = d.rsplit(".", 1)[-1].lower()
        if tld in _LOCAL_TLD_SKIP or _IPV4.fullmatch(d):
            continue
        if tld not in _TLD_OK and len(tld) != 2:
            continue
        doms.append(d.lower())
    ioc.domain = _uniq(doms)
    ioc.path = _uniq(_WIN_PATH.findall(text) + _NIX_PATH.findall(text))
    return ioc


def _uniq(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for i in items:
        seen.setdefault(i, None)
    return list(seen)
