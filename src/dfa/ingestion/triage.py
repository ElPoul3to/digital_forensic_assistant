"""Triage filter: skip the files of a full disk / KAPE-style collection that can only add noise.

A Windows triage image holds thousands of fonts, UI bundles, dictionaries, caches and
scripting modules.  Fed to the generic line parser they become hundreds of thousands of
timestamp-less "events" that cost hours of embedding and drown the real artefacts.  The rules
below are deliberately conservative: only well-known noise locations and extensions, plus a
size/timestamp gate for large text files that carry no timestamps at all (word lists, data
tables, minified bundles).  ``dfa ingest --no-triage`` disables the filter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from dfa.ingestion.detect import Detection

# Directory names (case-insensitive, matched against every path component) that never hold
# evidence on their own.  Kept narrow: e.g. ``wbem`` is *not* listed because
# ``wbem/Repository/OBJECTS.DATA`` is a WMI persistence artefact; its .mof files go by extension.
NOISE_DIRS: frozenset[str] = frozenset(
    d.lower()
    for d in (
        "Fonts", "SystemApps", "WinSxS", "BitLockerDiscoveryVolumeContents", "schemas", "WindowsApps",
        "WindowsPowerShell", "Speech", "Speech_OneCore", "Cursors", "Help", "Media", "Web", "IME",
        "Microsoft.NET", "assembly", "servicing", "PolicyDefinitions", "diagnostics", "InputMethod",
        # browser / app data that is code, dictionaries or cache, not user activity
        "ZxcvbnData", "Edge Wallet", "Typosquatting", "pnacl", "OnDeviceHeadSuggestModel", "SmartScreen",
        "ConstraintIndex", "AutofillStates", "tzdata", "qml", "Cache_Data", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache",
        "DawnWebGPUCache", "ShaderCache", "GrShaderCache", "Service Worker", "blob_storage", "Crashpad",
        "OptimizationGuidePredictionModels", "optimization_guide_model_store", "component_crx_cache",
        "WidevineCdm", "MEIPreload", "Subresource Filter", "FileTypePolicies", "SafetyTips", "TrustTokenKeyCommitments",
        "CertificateRevocation", "Safe Browsing", "CookieReadinessList", "hyphen-data",
    )
)

# Extensions (lower-case) that are code, UI, fonts, media or build artefacts.  They are only skipped
# when the detector saw *text* or an image: a ``.js`` that is really a zip is still unpacked.
NOISE_EXT: frozenset[str] = frozenset({
    ".js", ".mjs", ".css", ".scss", ".html", ".htm", ".svg", ".xsl", ".xslt", ".xsd", ".dtd",
    ".mof", ".mfl", ".cdxml", ".ps1xml", ".psm1", ".psd1", ".qmltypes", ".qml", ".adml", ".admx",
    ".manifest", ".mui", ".pri", ".winmd", ".ttf", ".ttc", ".otf", ".fon", ".pb", ".lock", ".map",
    ".md", ".rst", ".nls", ".hyb", ".dic", ".aff", ".ico", ".cur", ".ani", ".wav", ".mp3", ".mp4",
    ".resjson", ".resx", ".strings", ".po", ".mo", ".pak", ".dat.bak",
})
# Exact file names (lower-case) that are never evidence even though their format is parseable:
# the COMPONENTS hive is the servicing store (tens of thousands of keys about installed packages).
NOISE_FILES: frozenset[str] = frozenset({"components", "components.log1", "components.log2", "bcd-template"})

# File kinds the extension rule applies to (binary artefacts are never dropped by extension).
_EXT_RULE_KINDS = frozenset({"text", "xml", "json", "jsonl", "csv", "png", "jpeg", "binary"})

# Large timestamp-less text: word lists, data tables, minified bundles.  A file of ``TEXT_GATE_LINES``
# or more lines is kept only if at least ``TEXT_GATE_TS_RATIO`` of its first lines carry a timestamp.
TEXT_GATE_LINES = 1000
TEXT_GATE_TS_RATIO = 0.01
_GATE_SAMPLE = 2000
_TS_RE = re.compile(
    r"\d{4}[-/]\d{2}[-/]\d{2}[ T,]\d{2}:\d{2}"  # 2023-07-12 06:18 / 2023/07/12T06:18
    r"|\d{2}[-/]\d{2}[-/]\d{4}[ ,T]+\d{2}:\d{2}"  # 12/07/2023 06:18
    r"|^[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}"  # BSD syslog
    r"|\b1[5-9]\d{8}(\.\d+)?\b"  # epoch seconds 2017..2033
)
_GATED_KINDS = frozenset({"text", "xml", "json", "jsonl", "csv"})


@dataclass(frozen=True)
class Skip:
    reason: str


def _ext(path: Path) -> str:
    name = path.name.lower()
    return name[name.rfind(".") :] if "." in name[1:] else ""


def noise_dir(path: Path) -> str | None:
    """Name of the first path component that is a known noise directory, else None."""
    for part in path.parts[:-1]:
        if part.lower() in NOISE_DIRS:
            return part
    return None


def timestamp_ratio(path: Path, sample: int = _GATE_SAMPLE) -> tuple[int, float]:
    """(lines counted, share of sampled lines with a timestamp).  Counts every line, samples the first ones."""
    n = hits = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            n += 1
            if n <= sample and _TS_RE.search(line):
                hits += 1
    return n, (hits / min(n, sample) if n else 0.0)


def triage(path: Path, det: Detection) -> Skip | None:
    """Return a :class:`Skip` with the reason when the file should not be parsed, else None."""
    if det.kind in ("empty", "unreadable", "directory"):
        return None
    if d := noise_dir(path):
        return Skip(f"triage: noise directory '{d}'")
    if det.container:  # unpacked and re-triaged file by file
        return None
    if path.name.lower() in NOISE_FILES:
        return Skip(f"triage: {path.name} (servicing / boot store, no evidence)")
    ext = _ext(path)
    if ext in NOISE_EXT and det.kind in _EXT_RULE_KINDS:
        return Skip(f"triage: {ext} file ({det.kind})")
    if det.kind in _GATED_KINDS:
        try:
            n, ratio = timestamp_ratio(path)
        except OSError:
            return None
        if n >= TEXT_GATE_LINES and ratio < TEXT_GATE_TS_RATIO:
            return Skip(f"triage: {n} lines, no timestamps (data file, not a log)")
    return None
