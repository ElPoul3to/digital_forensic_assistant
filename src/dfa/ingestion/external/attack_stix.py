"""MITRE ATT&CK ingestion from STIX 2.1 bundles (attack-stix-data).

One chunk per technique / sub-technique / group / software / mitigation / tactic,
keyed by ATT&CK id so re-running upserts instead of duplicating.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from dfa.config import get_settings
from dfa.ingestion.external.textsplit import windows
from dfa.ingestion.schema import Chunk, Granularity

log = logging.getLogger(__name__)

COLLECTION = "attack"
URLS = {
    "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
}
_TYPES = {"attack-pattern": "technique", "intrusion-set": "group", "malware": "software", "tool": "software",
          "course-of-action": "mitigation", "x-mitre-tactic": "tactic", "campaign": "campaign"}
_CITATION = re.compile(r"\(Citation: [^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def _clean(s: str | None) -> str:
    if not s:
        return ""
    s = _CITATION.sub("", s)
    s = _MD_LINK.sub(r"\1", s)
    return re.sub(r"[ \t]+", " ", s).strip()


def _attack_id(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack") and ref.get("external_id"):
            return ref["external_id"], ref.get("url")
    return None, None


def download(domain: str, dest: Path) -> Path:
    import httpx

    url = URLS[domain]
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("downloading %s", url)
    with httpx.stream("GET", url, follow_redirects=True, timeout=120) as r:
        r.raise_for_status()
        with dest.open("wb") as fh:
            for part in r.iter_bytes():
                fh.write(part)
    return dest


def load_bundle(path: Path) -> list[dict[str, Any]]:
    with path.open() as fh:
        return json.load(fh).get("objects", [])


def chunks_from_bundle(objects: list[dict[str, Any]], domain: str = "enterprise") -> Iterator[Chunk]:
    cfg = get_settings().chunking
    by_id = {o["id"]: o for o in objects if "id" in o}
    tactic_names = {o["x_mitre_shortname"]: o["name"] for o in objects if o.get("type") == "x-mitre-tactic"}
    version = next((o.get("x_mitre_version") or o.get("spec_version", "") for o in objects if o.get("type") == "x-mitre-collection"), "")

    # relationships: who uses which technique, what mitigates what
    uses: dict[str, list[str]] = defaultdict(list)
    mitigates: dict[str, list[str]] = defaultdict(list)
    for o in objects:
        if o.get("type") != "relationship" or o.get("revoked"):
            continue
        src, tgt = by_id.get(o.get("source_ref")), by_id.get(o.get("target_ref"))
        if not src or not tgt:
            continue
        if o.get("relationship_type") == "uses" and tgt.get("type") == "attack-pattern":
            uses[src["id"]].append(tgt["name"])
        elif o.get("relationship_type") == "mitigates":
            mitigates[src["id"]].append(tgt["name"])

    n = 0
    for o in objects:
        kind = _TYPES.get(o.get("type", ""))
        if not kind or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        aid, url = _attack_id(o)
        if not aid:
            continue
        name = o.get("name", "")
        tactics = [tactic_names.get(p["phase_name"], p["phase_name"]) for p in o.get("kill_chain_phases", [])]
        platforms = o.get("x_mitre_platforms", [])
        header = f"ATT&CK {kind} {aid}: {name}"
        meta_line = []
        if tactics:
            meta_line.append("Tactics: " + ", ".join(tactics))
        if platforms:
            meta_line.append("Platforms: " + ", ".join(platforms))
        if o.get("x_mitre_is_subtechnique"):
            meta_line.append("Sub-technique")
        aliases = o.get("aliases") or o.get("x_mitre_aliases") or []
        if aliases and len(aliases) > 1:
            meta_line.append("Aliases: " + ", ".join(a for a in aliases if a != name))
        body = [_clean(o.get("description"))]
        if det := _clean(o.get("x_mitre_detection")):
            body.append("Detection: " + det)
        if o.get("x_mitre_data_sources"):
            body.append("Data sources: " + ", ".join(o["x_mitre_data_sources"]))
        if kind in ("group", "software", "campaign") and uses.get(o["id"]):
            body.append("Techniques used: " + ", ".join(sorted(set(uses[o["id"]]))[:60]))
        if kind == "mitigation" and mitigates.get(o["id"]):
            body.append("Mitigates: " + ", ".join(sorted(set(mitigates[o["id"]]))[:60]))
        full = "\n".join([header] + (["; ".join(meta_line)] if meta_line else []) + [b for b in body if b])
        parts = windows(full, cfg.external_chunk_tokens, cfg.external_overlap_tokens)
        for i, text in enumerate(parts):
            if i > 0:
                text = f"{header} (part {i + 1})\n{text}"
            n += 1
            yield Chunk(
                chunk_id=Chunk.make_id(COLLECTION, f"{aid}|{i}"),
                collection=COLLECTION,
                text=text,
                granularity=Granularity.DOCUMENT,
                metadata={
                    "attack_id": aid, "name": name, "kind": kind, "domain": domain, "tactics": tactics,
                    "platforms": platforms, "url": url, "version": str(o.get("x_mitre_version", version)),
                    "part": i, "source": "MITRE ATT&CK",
                },
            )
    log.info("ATT&CK %s: %d chunks", domain, n)


def update(domain: str = "enterprise", file: Path | None = None) -> dict[str, int]:
    from dfa.ingestion.external.index import index_chunks

    s = get_settings()
    path = file or s.data_dir / "external" / "attack" / f"{domain}-attack.json"
    if file is None:
        download(domain, path)
    objects = load_bundle(path)
    return index_chunks(chunks_from_bundle(objects, domain))
