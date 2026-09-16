"""Disk agent: a disk image (E01, raw, VMDK, VHDX, qcow2, ...) or an evidence
directory (KAPE / velociraptor style ``C/Windows/...`` layout, or a mounted
root) is opened with ``dissect.target``; the OS is identified and a curated
list of artefact plugins is run.  Every record they return becomes a
normalised :class:`Event`, so a whole image is asked about the same way as a
log file.

Plugins are selected per OS (``PLUGINS``); each can be capped so an
``$MFT`` or an event log with millions of rows does not swamp the index.  The
``investigate`` loop uses the same catalogue to let the model pick which
artefacts to extract next.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dfa.ingestion import ioc, progress
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Category, Event, Source

log = logging.getLogger(__name__)

DEFAULT_CAP = 250_000  # records per plugin
SMALL_CAP = 50_000


@dataclass(frozen=True)
class Plugin:
    name: str  # dissect function, dotted for namespaces ("browser.history")
    description: str
    cap: int = DEFAULT_CAP
    kwargs: dict = field(default_factory=dict)


WINDOWS: list[Plugin] = [
    Plugin("users", "local and domain user profiles (SID, home directory)"),
    Plugin("prefetch", "program execution from prefetch files (run times, run count, loaded files)", kwargs={"compact": True}),
    Plugin("amcache.application_files", "Amcache: executed / installed binaries with SHA-1, path, size, link date"),
    Plugin("amcache.applications", "Amcache: installed applications"),
    Plugin("amcache.shortcuts", "Amcache: shortcut (LNK) inventory"),
    Plugin("shimcache", "AppCompatCache (ShimCache): executables seen by the OS with last-modified times"),
    Plugin("userassist", "UserAssist: GUI program launches per user with run count and last run"),
    Plugin("bam", "Background Activity Moderator: last execution time per program per user"),
    Plugin("runkeys", "Run / RunOnce autostart entries"),
    Plugin("startupinfo", "StartupInfo XML: processes started at logon"),
    Plugin("services", "installed services (image path, start type, account)"),
    Plugin("tasks", "scheduled tasks (XML and registry task cache)"),
    Plugin("lnk", "shortcut files: target path, arguments, machine id, timestamps"),
    Plugin("jumplist", "jump lists: recently opened documents per application"),
    Plugin("recyclebin", "recycle bin: deleted files with original path and deletion time"),
    Plugin("shellbags", "shellbags: folders browsed in Explorer"),
    Plugin("powershell_history", "PowerShell console history (ConsoleHost_history.txt)"),
    Plugin("activitiescache", "Windows Timeline (ActivitiesCache.db): application use and clipboard"),
    Plugin("browser.history", "browser history (Chrome, Edge, Firefox, IE)"),
    Plugin("browser.downloads", "browser downloads"),
    Plugin("sru.network_data", "SRUM network usage per application"),
    Plugin("sru.network_connectivity", "SRUM network connectivity (interfaces, connect / disconnect times)"),
    Plugin("sru.application", "SRUM application resource usage (CPU, I/O per process)"),
    Plugin("wer", "Windows Error Reporting crash reports"),
    Plugin("ual", "User Access Logging (servers): logons per role and client IP"),
    Plugin("firewall", "Windows Firewall rules"),
    Plugin("sam", "SAM: local accounts with last logon, password set time, logon count and NT hash"),
    Plugin("evtx", "Windows event logs (all channels) as one record per event", cap=DEFAULT_CAP),
    Plugin("usnjrnl", "NTFS USN journal: file create / rename / delete operations", cap=DEFAULT_CAP),
    Plugin("mft", "NTFS $MFT: every file with $STANDARD_INFORMATION and $FILE_NAME timestamps", cap=DEFAULT_CAP, kwargs={"compact": True}),
]
UNIX: list[Plugin] = [
    Plugin("users", "accounts from /etc/passwd"),
    Plugin("commandhistory", "shell histories (.bash_history, .zsh_history, ...) per user"),
    Plugin("cronjobs", "cron jobs (system and per user)"),
    Plugin("services", "systemd / init services"),
    Plugin("packages", "installed packages (dpkg, rpm, ...)"),
    Plugin("authlog", "/var/log/auth.log and secure: logins, sudo, PAM"),
    Plugin("messages", "/var/log/messages and syslog"),
    Plugin("journal", "systemd journal entries", cap=DEFAULT_CAP),
    Plugin("wtmp", "login records (wtmp)"),
    Plugin("btmp", "failed login records (btmp)"),
    Plugin("lastlog", "last login per user"),
    Plugin("ssh.authorized_keys", "SSH authorized_keys entries per user"),
    Plugin("ssh.known_hosts", "SSH known_hosts entries per user"),
    Plugin("sudoers", "sudoers rules"),
    Plugin("network.interfaces", "network interfaces and addresses"),
    Plugin("docker.containers", "Docker containers"),
    Plugin("docker.images", "Docker images"),
    Plugin("browser.history", "browser history"),
    Plugin("browser.downloads", "browser downloads"),
]
MAC: list[Plugin] = [
    Plugin("users", "accounts"),
    Plugin("commandhistory", "shell histories per user"),
    Plugin("cronjobs", "cron jobs"),
    Plugin("browser.history", "browser history"),
    Plugin("browser.downloads", "browser downloads"),
]
PLUGINS = {"windows": WINDOWS, "unix": UNIX, "linux": UNIX, "osx": MAC, "macos": MAC}

# record descriptor prefix -> (action, category)
_DESC_MAP: list[tuple[str, str, Category]] = [
    ("windows/prefetch", "prefetch_execution", Category.PROCESS),
    ("windows/appcompat/amcache", "amcache_entry", Category.PROCESS),
    ("windows/amcache", "amcache_entry", Category.PROCESS),
    ("windows/appcompat/shimcache", "shimcache_entry", Category.PROCESS),
    ("windows/shimcache", "shimcache_entry", Category.PROCESS),
    ("windows/registry/userassist", "userassist_execution", Category.PROCESS),
    ("windows/registry/bam", "bam_execution", Category.PROCESS),
    ("windows/registry/run", "autostart_entry", Category.PROCESS),
    ("windows/startupinfo", "startup_process", Category.PROCESS),
    ("windows/service", "service_installed", Category.SERVICE),
    ("windows/task", "scheduled_task", Category.PROCESS),
    ("windows/shortcut", "lnk_shortcut", Category.FILE),
    ("windows/lnk", "lnk_shortcut", Category.FILE),
    ("windows/jumplist", "jumplist_entry", Category.FILE),
    ("windows/recyclebin", "recycle_bin_entry", Category.FILE),
    ("windows/shellbag", "shellbag", Category.FILE),
    ("windows/powershell", "powershell_history", Category.PROCESS),
    ("windows/activitiescache", "activity_cache", Category.PROCESS),
    ("windows/sru/network", "srum_network", Category.NETWORK),
    ("windows/sru/", "srum_application", Category.PROCESS),
    ("windows/wer", "crash_report", Category.PROCESS),
    ("windows/ual", "ual_access", Category.AUTHENTICATION),
    ("windows/firewall", "firewall_rule", Category.NETWORK),
    ("windows/sam", "sam_account", Category.USER_MGMT),
    ("windows/user", "user_profile", Category.USER_MGMT),
    ("windows/evtx", "evtx_event", Category.OTHER),
    ("windows/evt", "evt_event", Category.OTHER),
    ("filesystem/ntfs/usnjrnl", "usn_record", Category.FILE),
    ("filesystem/ntfs/mft", "mft_entry", Category.FILE),
    ("filesystem/", "file_entry", Category.FILE),
    ("browser/", "browser_history", Category.WEB),
    ("unix/user", "user_account", Category.USER_MGMT),
    ("unix/history", "shell_command", Category.PROCESS),
    ("unix/cronjob", "cron_job", Category.PROCESS),
    ("unix/service", "service_installed", Category.SERVICE),
    ("linux/service", "service_installed", Category.SERVICE),
    ("unix/package", "package", Category.PACKAGE),
    ("linux/package", "package", Category.PACKAGE),
    ("linux/log/auth", "auth_log", Category.AUTHENTICATION),
    ("unix/log/auth", "auth_log", Category.AUTHENTICATION),
    ("linux/log/journal", "journal", Category.OTHER),
    ("linux/log/", "syslog", Category.OTHER),
    ("unix/log/", "syslog", Category.OTHER),
    ("unix/utmp", "login_record", Category.AUTHENTICATION),
    ("linux/utmp", "login_record", Category.AUTHENTICATION),
    ("unix/lastlog", "login_record", Category.AUTHENTICATION),
    ("unix/ssh", "ssh_config", Category.AUTHENTICATION),
    ("linux/ssh", "ssh_config", Category.AUTHENTICATION),
    ("unix/sudoers", "sudoers_rule", Category.PRIVILEGE),
    ("unix/network", "network_interface", Category.NETWORK),
    ("linux/network", "network_interface", Category.NETWORK),
    ("windows/network", "network_interface", Category.NETWORK),
    ("linux/docker", "docker", Category.PROCESS),
    ("apps/", "application_record", Category.OTHER),
]
# EventIDs of the Security / System channels that deserve a category
_EVTX_CATEGORY = {4624: Category.AUTHENTICATION, 4625: Category.AUTHENTICATION, 4634: Category.AUTHENTICATION, 4648: Category.AUTHENTICATION,
                  4768: Category.AUTHENTICATION, 4769: Category.AUTHENTICATION, 4771: Category.AUTHENTICATION, 4776: Category.AUTHENTICATION,
                  4688: Category.PROCESS, 4689: Category.PROCESS, 1: Category.PROCESS, 4697: Category.SERVICE, 7045: Category.SERVICE,
                  7036: Category.SERVICE, 4720: Category.USER_MGMT, 4722: Category.USER_MGMT, 4724: Category.USER_MGMT, 4726: Category.USER_MGMT,
                  4728: Category.USER_MGMT, 4732: Category.USER_MGMT, 4756: Category.USER_MGMT, 4672: Category.PRIVILEGE, 4673: Category.PRIVILEGE,
                  1102: Category.PRIVILEGE, 104: Category.PRIVILEGE, 4698: Category.PROCESS, 4702: Category.PROCESS, 3: Category.NETWORK,
                  5156: Category.NETWORK, 5140: Category.FILE, 5145: Category.FILE, 4663: Category.FILE, 11: Category.FILE}
_SKIP_FIELDS = {"hostname", "domain", "_source", "_classification", "_generated", "_version"}
_USER_FIELDS = ("username", "user", "user_name", "owner", "account", "target_user", "TargetUserName")
_PROCESS_FIELDS = ("filename", "image", "path", "command", "commandline", "cmdline", "exe", "executable", "name", "linkedfile", "lnk_full_path")


def _fmt(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if v.tzinfo else v.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, bytes | bytearray | memoryview):
        b = bytes(v)
        return f"<{len(b)} bytes {b[:12].hex()}>"
    if isinstance(v, list | tuple):
        return ", ".join(_fmt(x) for x in v[:20])
    s = str(v)
    return s if len(s) <= 300 else s[:300] + "..."


def _first_datetime(d: dict[str, Any]) -> datetime | None:
    for k in ("ts", "start", "timestamp", "time", "mtime", "last_seen", "last_run", "last_modified", "creation_time", "ts_mtime", "ts_created"):
        v = d.get(k)
        if isinstance(v, datetime):
            return v
    for k, v in d.items():
        if isinstance(v, datetime) and k not in _SKIP_FIELDS:
            return v
    return None


def record_to_event(rec, ctx: ParseContext, source_name: str, plugin: str, index: int, host_hint: str | None) -> Event:
    """Generic flow.record -> Event mapping used for every dissect plugin."""
    desc = getattr(getattr(rec, "_desc", None), "name", plugin.replace(".", "/"))
    try:
        d = dict(rec._asdict())
    except Exception:  # noqa: BLE001
        d = {k: getattr(rec, k, None) for k in getattr(rec, "_field_types", {})}
    action, cat = plugin.replace(".", "_"), Category.OTHER
    for prefix, act, c in _DESC_MAP:
        if desc.startswith(prefix):
            action, cat = act, c
            break
    ts = _first_datetime(d)
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    host = d.get("hostname") or host_hint or ctx.host_hint
    user = next((str(d[k]) for k in _USER_FIELDS if d.get(k)), None)
    process = next((str(d[k]) for k in _PROCESS_FIELDS if d.get(k)), None) if cat in (Category.PROCESS, Category.SERVICE) else None
    if desc.startswith(("windows/evtx", "windows/evt")):
        eid = d.get("EventID") or d.get("event_id")
        try:
            cat = _EVTX_CATEGORY.get(int(eid), Category.OTHER)
        except (TypeError, ValueError):
            pass
        chan = d.get("Channel") or d.get("channel") or ""
        action = f"evtx_{eid}" if eid is not None else action
        user = user or next((str(d[k]) for k in ("TargetUserName", "SubjectUserName") if d.get(k)), None)
        process = process or next((str(d[k]) for k in ("NewProcessName", "Image", "ProcessName") if d.get(k)), None)
        head = f"Event {eid} {d.get('Provider_Name', d.get('Provider', ''))} ({chan})"
    else:
        head = desc.split("/")[-1].replace("_", " ")
        head = f"{desc.split('/')[0]} {head}" if "/" in desc else head
    body = "; ".join(f"{k}={_fmt(v)}" for k, v in d.items() if k not in _SKIP_FIELDS and v not in (None, "", [], b"") and not k.startswith("_"))
    summary = f"{head}: {body}"[:1000]
    src = d.get("source") or d.get("_source")
    ref = f"{plugin} #{index}" + (f" ({src})" if src else "")
    return Event(case_id=ctx.case_id, timestamp=ts, source=Source.DISK, source_file=source_name, record_ref=ref, host=str(host) if host else None,
                 user=user, process=process, category=cat, action=action, ioc=ioc.extract(summary), summary=summary,
                 raw=repr(rec)[:2000], extra={"plugin": plugin, "record_type": desc, **{k: _fmt(v) for k, v in d.items() if k not in _SKIP_FIELDS and not k.startswith("_")}})


def _resolve(target, dotted: str):
    obj = target
    for part in dotted.split("."):
        obj = getattr(obj, part)
    return obj


@dataclass
class PluginResult:
    name: str
    records: int = 0
    status: str = "ok"  # ok | missing | error | capped
    error: str | None = None


class DiskAgent:
    """Parser for disk images and evidence directories; also used directly by ``dfa disk`` / ``dfa investigate``."""

    kinds = ("e01", "disk_image")

    def __init__(self, plugins: list[str] | None = None, caps: dict[str, int] | None = None) -> None:
        self.only = plugins
        self.caps = caps or {}
        self.results: list[PluginResult] = []
        self.info: dict[str, Any] = {}

    def open(self, path: Path):
        try:
            from dissect.target import Target
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("disk images need the 'disk' extra: uv sync --extra disk") from e
        return Target.open(str(path))

    def describe(self, target) -> dict[str, Any]:
        info: dict[str, Any] = {}
        for attr in ("os", "hostname", "version", "domain", "ips", "timezone", "install_date", "language", "architecture"):
            try:
                v = getattr(target, attr)
                info[attr] = _fmt(v) if not isinstance(v, str) else v
            except Exception as e:  # noqa: BLE001
                log.debug("skipped: %s", e)
                continue
        try:
            info["filesystems"] = [str(fs) for fs in target.filesystems][:10]
        except Exception as e:  # noqa: BLE001
            log.debug("ignored: %s", e)
        return info

    def plugin_list(self, os_name: str | None) -> list[Plugin]:
        base = PLUGINS.get((os_name or "").lower(), UNIX if os_name else [])
        if self.only is None:
            return base
        known = {p.name: p for p in base}
        return [known.get(n, Plugin(n, n)) for n in self.only]

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        target = self.open(path)
        self.info = info = self.describe(target)
        os_name = info.get("os")
        host = info.get("hostname") or ctx.host_hint
        summ = f"Disk image {path.name}: " + "; ".join(f"{k}={v}" for k, v in info.items() if v)
        yield Event(case_id=ctx.case_id, timestamp=None, source=Source.DISK, source_file=path.name, record_ref="image", host=host,
                    category=Category.OTHER, action="disk_image_info", ioc=ioc.extract(summ), summary=summ[:1000], raw=summ[:2000], extra=info)
        plugins = self.plugin_list(os_name)
        progress.say("    disk image %s: %s, %d dissect plugins: %s", path.name,
                     ", ".join(f"{k}={v}" for k, v in info.items() if v and k in ("os", "hostname", "version")) or "os unknown",
                     len(plugins), ", ".join(p.name for p in plugins))
        for k, plugin in enumerate(plugins, 1):
            res = PluginResult(plugin.name)
            self.results.append(res)
            try:
                fn = _resolve(target, plugin.name)
            except Exception as e:  # noqa: BLE001
                res.status, res.error = "missing", f"{type(e).__name__}: {e}"[:200]
                log.info("plugin %s not available: %s", plugin.name, res.error)
                progress.say("    [%d/%d] %s: not available on this image", k, len(plugins), plugin.name)
                continue
            cap = self.caps.get(plugin.name, plugin.cap)
            progress.say("    [%d/%d] %s ...", k, len(plugins), plugin.name)
            t0 = time.time()
            try:
                it = fn(**plugin.kwargs) if plugin.kwargs else fn()
                for i, rec in enumerate(it, 1):
                    if i > cap:
                        res.status = "capped"
                        log.warning("plugin %s: capped at %d records", plugin.name, cap)
                        break
                    res.records += 1
                    try:
                        yield record_to_event(rec, ctx, path.name, plugin.name, i, host)
                    except Exception as e:  # noqa: BLE001
                        log.debug("record %d of %s unmappable: %s", i, plugin.name, e)
                progress.say("    [%d/%d] %s: %d records in %.1fs%s", k, len(plugins), plugin.name, res.records, time.time() - t0,
                             " (capped)" if res.status == "capped" else "")
            except Exception as e:  # noqa: BLE001
                res.status, res.error = "error", f"{type(e).__name__}: {e}"[:300]
                log.warning("plugin %s failed: %s", plugin.name, res.error)
                progress.say("    [%d/%d] %s: failed after %d records (%s)", k, len(plugins), plugin.name, res.records, res.error[:120])


register(DiskAgent())
