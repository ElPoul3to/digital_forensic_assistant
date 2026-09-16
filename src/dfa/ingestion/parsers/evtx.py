"""Windows event logs: binary EVTX (python-evtx) and EVTX exported as XML.

Both paths produce the same XML per record, which is flattened into a dict
(System.* and EventData.*) and mapped to an Event with EventID-aware summaries
for the most common Security / Sysmon / PowerShell events.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from dfa.ingestion import ioc, timeutil
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Category, Event, Source

log = logging.getLogger(__name__)
_NS = re.compile(r"\{[^}]+\}")

# (provider substring, event id) -> (category, action, summary template)
_KNOWN: dict[tuple[str, int], tuple[Category, str, str]] = {
    ("Security", 4624): (Category.AUTHENTICATION, "logon_success", "Logon type {LogonType} for {TargetDomainName}\\{TargetUserName} from {IpAddress} ({WorkstationName}) via {LogonProcessName}/{AuthenticationPackageName}"),
    ("Security", 4625): (Category.AUTHENTICATION, "logon_failure", "Failed logon type {LogonType} for {TargetDomainName}\\{TargetUserName} from {IpAddress} status {Status}/{SubStatus}"),
    ("Security", 4634): (Category.AUTHENTICATION, "logoff", "Logoff {TargetDomainName}\\{TargetUserName} logon type {LogonType}"),
    ("Security", 4648): (Category.AUTHENTICATION, "logon_explicit_creds", "{SubjectUserName} used explicit credentials {TargetDomainName}\\{TargetUserName} to {TargetServerName} process {ProcessName}"),
    ("Security", 4672): (Category.PRIVILEGE, "special_privileges", "Special privileges assigned to {SubjectDomainName}\\{SubjectUserName}: {PrivilegeList}"),
    ("Security", 4688): (Category.PROCESS, "process_create", "Process created {NewProcessName} (parent {ParentProcessName}) by {SubjectDomainName}\\{SubjectUserName} cmd: {CommandLine}"),
    ("Security", 4689): (Category.PROCESS, "process_exit", "Process exited {ProcessName} by {SubjectUserName}"),
    ("Security", 4698): (Category.SERVICE, "scheduled_task_created", "Scheduled task created {TaskName} by {SubjectUserName}"),
    ("Security", 4720): (Category.USER_MGMT, "user_created", "User account created {TargetDomainName}\\{TargetUserName} by {SubjectUserName}"),
    ("Security", 4722): (Category.USER_MGMT, "user_enabled", "User account enabled {TargetUserName} by {SubjectUserName}"),
    ("Security", 4724): (Category.USER_MGMT, "password_reset", "Password reset attempted on {TargetUserName} by {SubjectUserName}"),
    ("Security", 4726): (Category.USER_MGMT, "user_deleted", "User account deleted {TargetUserName} by {SubjectUserName}"),
    ("Security", 4728): (Category.USER_MGMT, "group_member_added", "{MemberName} added to global group {TargetUserName} by {SubjectUserName}"),
    ("Security", 4732): (Category.USER_MGMT, "group_member_added", "{MemberName} added to local group {TargetUserName} by {SubjectUserName}"),
    ("Security", 4756): (Category.USER_MGMT, "group_member_added", "{MemberName} added to universal group {TargetUserName} by {SubjectUserName}"),
    ("Security", 4768): (Category.AUTHENTICATION, "kerberos_tgt", "Kerberos TGT requested for {TargetUserName} from {IpAddress} status {Status}"),
    ("Security", 4769): (Category.AUTHENTICATION, "kerberos_tgs", "Kerberos service ticket for {ServiceName} by {TargetUserName} from {IpAddress} enc {TicketEncryptionType}"),
    ("Security", 4771): (Category.AUTHENTICATION, "kerberos_preauth_failed", "Kerberos pre-auth failed for {TargetUserName} from {IpAddress} status {Status}"),
    ("Security", 4776): (Category.AUTHENTICATION, "ntlm_auth", "NTLM auth for {TargetUserName} from {Workstation} status {Status}"),
    ("Security", 5140): (Category.FILE, "share_access", "Network share {ShareName} accessed by {SubjectUserName} from {IpAddress}"),
    ("Security", 5145): (Category.FILE, "share_object_access", "Share object {ShareName}{RelativeTargetName} accessed by {SubjectUserName} from {IpAddress}"),
    ("Security", 7045): (Category.SERVICE, "service_installed", "Service installed {ServiceName} image {ImagePath} by {SubjectUserName}"),
    ("Security", 1102): (Category.OTHER, "audit_log_cleared", "Security audit log cleared by {SubjectDomainName}\\{SubjectUserName}"),
    ("System", 7045): (Category.SERVICE, "service_installed", "Service installed {ServiceName} image {ImagePath} start {StartType} account {AccountName}"),
    ("System", 7036): (Category.SERVICE, "service_state", "Service {param1} entered state {param2}"),
    ("System", 104): (Category.OTHER, "log_cleared", "Event log cleared: {Channel} by {SubjectUserName}"),
    ("Sysmon", 1): (Category.PROCESS, "process_create", "Process create {Image} (parent {ParentImage}) user {User} cmd: {CommandLine} hashes {Hashes}"),
    ("Sysmon", 3): (Category.NETWORK, "network_connect", "Network {Protocol} {SourceIp}:{SourcePort} -> {DestinationIp}:{DestinationPort} ({DestinationHostname}) by {Image} user {User}"),
    ("Sysmon", 7): (Category.PROCESS, "image_load", "Image loaded {ImageLoaded} into {Image} signed={Signed}"),
    ("Sysmon", 8): (Category.PROCESS, "create_remote_thread", "Remote thread from {SourceImage} into {TargetImage}"),
    ("Sysmon", 10): (Category.PROCESS, "process_access", "Process access {SourceImage} -> {TargetImage} rights {GrantedAccess}"),
    ("Sysmon", 11): (Category.FILE, "file_create", "File created {TargetFilename} by {Image}"),
    ("Sysmon", 12): (Category.OTHER, "registry_object", "Registry {EventType} {TargetObject} by {Image}"),
    ("Sysmon", 13): (Category.OTHER, "registry_set", "Registry set {TargetObject} = {Details} by {Image}"),
    ("Sysmon", 22): (Category.NETWORK, "dns_query", "DNS query {QueryName} -> {QueryResults} by {Image}"),
    ("Sysmon", 23): (Category.FILE, "file_delete", "File deleted {TargetFilename} by {Image} hashes {Hashes}"),
    ("PowerShell", 4104): (Category.PROCESS, "powershell_scriptblock", "PowerShell script block {ScriptBlockId} path {Path}: {ScriptBlockText}"),
    ("PowerShell", 4103): (Category.PROCESS, "powershell_module", "PowerShell module logging: {Payload}"),
    ("PowerShell", 400): (Category.PROCESS, "powershell_engine_start", "PowerShell engine started: {HostApplication}"),
    ("TerminalServices", 21): (Category.AUTHENTICATION, "rdp_logon", "RDP session logon {User} from {Address}"),
    ("TerminalServices", 25): (Category.AUTHENTICATION, "rdp_reconnect", "RDP session reconnect {User} from {Address}"),
    ("TerminalServices", 1149): (Category.AUTHENTICATION, "rdp_auth_success", "RDP user authentication succeeded {Param1}\\{Param2} from {Param3}"),
    ("TaskScheduler", 106): (Category.SERVICE, "scheduled_task_registered", "Task registered {TaskName} by {UserContext}"),
    ("Windows Defender", 1116): (Category.OTHER, "defender_detection", "Defender detected {Threat Name} in {Path} action {Action Name}"),
    ("WinRM", 91): (Category.NETWORK, "winrm_session", "WinRM session created for {UserName}"),
    ("BITS", 59): (Category.NETWORK, "bits_transfer", "BITS job {jobTitle} url {url}"),
}
_USER_KEYS = ("TargetUserName", "SubjectUserName", "User", "AccountName", "UserName", "UserContext", "Param2")
_IP_KEYS = ("IpAddress", "SourceIp", "DestinationIp", "Address", "Workstation", "ClientAddress", "Param3")


class _Missing(dict):
    def __missing__(self, key: str) -> str:
        return "?"


def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        el.tag = _NS.sub("", el.tag)


def record_to_fields(xml: str) -> dict[str, Any] | None:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    _strip_ns(root)
    d: dict[str, Any] = {}
    sysm = root.find("System")
    if sysm is not None:
        for el in sysm:
            if el.tag == "Provider":
                d["Provider"] = el.get("Name") or el.get("Guid") or ""
            elif el.tag == "TimeCreated":
                d["TimeCreated"] = el.get("SystemTime")
            elif el.tag == "Execution":
                d["ProcessID"] = el.get("ProcessID")
            elif el.tag == "Security":
                d["SecurityUserID"] = el.get("UserID")
            else:
                d[el.tag] = (el.text or "").strip()
    for section in ("EventData", "UserData"):
        sec = root.find(section)
        if sec is None:
            continue
        for el in sec.iter():
            if el is sec:
                continue
            name = el.get("Name") or el.tag
            if el.text and el.text.strip():
                d[name] = el.text.strip()
            elif not len(el):
                d.setdefault(name, "")
    return d


def fields_to_event(d: dict[str, Any], *, ctx: ParseContext, source_file: str, record_ref: str, raw: str) -> Event:
    provider = str(d.get("Provider") or "")
    try:
        eid = int(str(d.get("EventID", "")).strip() or -1)
    except ValueError:
        eid = -1
    cat, action, template = Category.OTHER, None, None
    for (prov, e), spec in _KNOWN.items():
        if e == eid and prov.lower() in provider.lower():
            cat, action, template = spec
            break
    if template is None and eid == 7045:
        cat, action, template = _KNOWN[("System", 7045)]
    fields = _Missing(d)
    if template:
        body = template.format_map(fields)
    else:
        skip = {"Provider", "EventID", "TimeCreated", "Computer", "Channel", "Version", "Level", "Task", "Opcode", "Keywords", "EventRecordID", "Correlation", "ProcessID", "SecurityUserID"}
        body = " ".join(f"{k}={str(v)[:120]}" for k, v in d.items() if k not in skip and v not in ("", None, "-"))[:800]
    channel = d.get("Channel") or provider
    summary = f"EventID {eid} {channel}: {body}"
    user = next((str(d[k]) for k in _USER_KEYS if d.get(k) and str(d[k]) not in ("-", "?")), None)
    ev_ioc = ioc.extract(summary)
    for k in _IP_KEYS:
        v = str(d.get(k) or "")
        if v and v not in ("-", "::1", "127.0.0.1") and re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", v) and v not in ev_ioc.ip:
            ev_ioc.ip.append(v)
    if user and user not in ev_ioc.user:
        ev_ioc.user.append(user)
    if (h := d.get("Hashes")) and isinstance(h, str):
        for part in h.split(","):
            if "=" in part:
                val = part.split("=", 1)[1].strip().lower()
                if val and val not in ev_ioc.hash:
                    ev_ioc.hash.append(val)
    return Event(
        case_id=ctx.case_id, timestamp=timeutil.parse_any(d.get("TimeCreated")), source=Source.EVTX, source_file=source_file,
        record_ref=record_ref, host=str(d.get("Computer") or ctx.host_hint or "") or None, user=user,
        process=str(d.get("Image") or d.get("NewProcessName") or d.get("ProcessName") or "") or None,
        category=cat, action=action, ioc=ev_ioc, summary=summary[:1500], raw=raw[:4000],
        extra={"event_id": eid, "provider": provider, "channel": channel,
               **{k: str(v)[:300] for k, v in d.items() if k not in ("Provider", "EventID", "TimeCreated", "Computer", "Channel")}},
    )


class EvtxParser:
    kinds = ("evtx",)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        import Evtx.Evtx as evtx

        with evtx.Evtx(str(path)) as log_file:
            for rec in log_file.records():
                try:
                    xml = rec.xml()
                except Exception as e:  # noqa: BLE001
                    log.debug("%s record %s unreadable: %s", path.name, rec.record_num(), e)
                    continue
                d = record_to_fields(xml)
                if d is None:
                    continue
                yield fields_to_event(d, ctx=ctx, source_file=path.name, record_ref=f"record {rec.record_num()}", raw=xml)


class EvtxXmlParser:
    kinds = ("evtx_xml",)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        text = path.read_text(encoding="utf-8", errors="replace")
        n = 0
        for m in re.finditer(r"<Event[\s>].*?</Event>", text, re.DOTALL):
            n += 1
            xml = m.group(0)
            d = record_to_fields(xml)
            if d is None:
                continue
            ref = f"record {d.get('EventRecordID') or n}"
            yield fields_to_event(d, ctx=ctx, source_file=path.name, record_ref=ref, raw=xml)


register(EvtxParser())
register(EvtxXmlParser())
