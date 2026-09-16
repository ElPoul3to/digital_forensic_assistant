"""Windows binary artefacts handed in as loose files: registry hives, prefetch,
shortcuts (LNK), ``$MFT`` and ESE databases (SRUM, WebCache, ...).

Parsing is done with the ``dissect`` libraries (optional extra ``disk``); when
they are missing the parser raises and the ingest report shows the reason.

What becomes an event:

- **Registry hive**: one event per key that carries values or matches a
  forensic pattern (Run keys, services, USB devices, UserAssist, RecentDocs,
  network profiles, installed software, BAM, Amcache, scheduled tasks, SAM
  users, Winlogon, IFEO, LSA, ...).  UserAssist and BAM values become one
  event per program with the decoded run count / last-run time.  Timestamp is
  the key's last-write time.
- **Prefetch**: one event per run (latest + previous runs) with the executable,
  run count and the files it loaded.
- **LNK**: one event per shortcut with the target path, arguments, working
  dir, the machine that created it and the link-creation time recovered from
  the tracker UUID (version-1 UUIDs carry a timestamp and a MAC address).
- **$MFT**: one event per record with $STANDARD_INFORMATION and $FILE_NAME
  timestamps, size, deleted state, alternate data streams and a
  ``si_before_fn`` flag when the $SI creation time precedes the $FN one (the
  classic timestomping indicator).
- **ESE**: SRUM tables decoded (network usage, application resource usage,
  ...); other ESE databases (WebCache, Windows Search) get one event per row.
"""

from __future__ import annotations

import codecs
import logging
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from dfa.ingestion import ioc, progress
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Category, Event, Source

log = logging.getLogger(__name__)

REGISTRY_MAX_KEYS = 300_000
MFT_MAX_RECORDS = 250_000
ESE_MAX_ROWS = 100_000
_VALUES_PER_KEY = 40
_VALUE_CHARS = 600
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_UUID_EPOCH = datetime(1582, 10, 15, tzinfo=UTC)


def _need_dissect(what: str):
    try:
        import dissect.regf  # noqa: F401
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(f"{what} needs the 'disk' extra: uv sync --extra disk (dissect libraries)") from e


def _wintime(v: int | None) -> datetime | None:
    if not v:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=int(v) // 10)
    except (OverflowError, ValueError):
        return None


def _iso(d: datetime | None) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else "?"


def _mk(ctx: ParseContext, path: Path, ref: str, ts: datetime | None, cat: Category, action: str, summary: str, raw: str,
        extra: dict | None = None, user: str | None = None, process: str | None = None, source: Source = Source.DISK) -> Event:
    return Event(case_id=ctx.case_id, timestamp=ts, source=source, source_file=path.name, record_ref=ref, host=ctx.host_hint,
                 user=user, process=process, category=cat, action=action, ioc=ioc.extract(summary), summary=summary[:1000],
                 raw=raw[:2000], extra=extra or {})


def _user_from_path(path: Path) -> str | None:
    m = re.search(r"(?:Users|Documents and Settings)[\\/]+([^\\/]+)[\\/]", str(path), re.IGNORECASE)
    return m.group(1) if m else None


# --- registry -----------------------------------------------------------------

_HIVE_LABELS = {"NTUSER.DAT": "HKCU", "USRCLASS.DAT": "HKCU\\Software\\Classes", "SYSTEM": "HKLM\\SYSTEM", "SOFTWARE": "HKLM\\SOFTWARE",
                "SAM": "HKLM\\SAM", "SECURITY": "HKLM\\SECURITY", "DEFAULT": "HKU\\.DEFAULT", "AMCACHE.HVE": "Amcache",
                "BCD": "BCD", "COMPONENTS": "HKLM\\COMPONENTS", "DRIVERS": "HKLM\\DRIVERS"}
# (pattern on the lower-cased key path, action, category)
_NOTABLE: list[tuple[re.Pattern, str, Category]] = [
    (re.compile(r"\\currentversion\\run(once|onceex|services|servicesonce)?$"), "registry_autostart", Category.PROCESS),
    (re.compile(r"\\currentversion\\policies\\explorer\\run$"), "registry_autostart", Category.PROCESS),
    (re.compile(r"controlset\d+\\services\\[^\\]+$"), "registry_service", Category.SERVICE),
    (re.compile(r"controlset\d+\\enum\\usb(stor)?\\[^\\]+\\[^\\]+$"), "registry_usb_device", Category.OTHER),
    (re.compile(r"\\explorer\\userassist\\\{[^}]+\}\\count$"), "registry_userassist", Category.PROCESS),
    (re.compile(r"\\explorer\\recentdocs(\\[^\\]+)?$"), "registry_recent_docs", Category.FILE),
    (re.compile(r"\\explorer\\typedpaths$"), "registry_typed_paths", Category.FILE),
    (re.compile(r"\\internet explorer\\typedurls$"), "registry_typed_urls", Category.WEB),
    (re.compile(r"\\explorer\\wordwheelquery$"), "registry_search_terms", Category.FILE),
    (re.compile(r"\\explorer\\comdlg32\\(opensavemru|opensavepidlmru|lastvisitedmru|lastvisitedpidlmru)(\\[^\\]+)?$"), "registry_open_save_mru", Category.FILE),
    (re.compile(r"\\explorer\\runmru$"), "registry_run_mru", Category.PROCESS),
    (re.compile(r"\\explorer\\mountpoints2\\[^\\]+$"), "registry_mount_point", Category.FILE),
    (re.compile(r"\\networklist\\profiles\\\{[^}]+\}$"), "registry_network_profile", Category.NETWORK),
    (re.compile(r"\\networklist\\signatures\\(managed|unmanaged)\\[^\\]+$"), "registry_network_signature", Category.NETWORK),
    (re.compile(r"\\currentversion\\uninstall\\[^\\]+$"), "registry_installed_software", Category.PACKAGE),
    (re.compile(r"\\currentversion\\winlogon$"), "registry_winlogon", Category.PROCESS),
    (re.compile(r"\\image file execution options\\[^\\]+$"), "registry_ifeo", Category.PROCESS),
    (re.compile(r"controlset\d+\\control\\computername\\computername$"), "registry_computer_name", Category.OTHER),
    (re.compile(r"controlset\d+\\control\\timezoneinformation$"), "registry_timezone", Category.OTHER),
    (re.compile(r"\\terminal server client\\(servers|default)(\\[^\\]+)?$"), "registry_rdp_client", Category.NETWORK),
    (re.compile(r"controlset\d+\\services\\tcpip\\parameters\\interfaces\\\{[^}]+\}$"), "registry_interface", Category.NETWORK),
    (re.compile(r"\\sam\\domains\\account\\users\\names\\[^\\]+$"), "registry_sam_user", Category.USER_MGMT),
    (re.compile(r"\\sam\\domains\\builtin\\aliases\\names\\[^\\]+$"), "registry_sam_group", Category.USER_MGMT),
    (re.compile(r"\\(shell|shellnoroam|bags|bagmru)(\\|$)"), "registry_shellbag", Category.FILE),
    (re.compile(r"\\inventoryapplicationfile\\[^\\]+$"), "registry_amcache_file", Category.PROCESS),
    (re.compile(r"\\inventoryapplication\\[^\\]+$"), "registry_amcache_app", Category.PACKAGE),
    (re.compile(r"\\bam\\(state\\)?usersettings\\[^\\]+$"), "registry_bam", Category.PROCESS),
    (re.compile(r"\\mounteddevices$"), "registry_mounted_devices", Category.OTHER),
    (re.compile(r"\\schedule\\taskcache\\tree\\.+$"), "registry_scheduled_task", Category.PROCESS),
    (re.compile(r"\\schedule\\taskcache\\tasks\\\{[^}]+\}$"), "registry_scheduled_task", Category.PROCESS),
    (re.compile(r"controlset\d+\\control\\securityproviders\\wdigest$"), "registry_wdigest", Category.PRIVILEGE),
    (re.compile(r"controlset\d+\\control\\lsa$"), "registry_lsa", Category.PRIVILEGE),
    (re.compile(r"\\currentversion\\windows$"), "registry_appinit", Category.PROCESS),
    (re.compile(r"\\microsoft\\windows defender\\exclusions\\[^\\]+$"), "registry_defender_exclusion", Category.PRIVILEGE),
    (re.compile(r"\\policies\\system$"), "registry_uac_policy", Category.PRIVILEGE),
    (re.compile(r"\\currentversion\\explorer\\shell folders$"), "registry_shell_folders", Category.OTHER),
    (re.compile(r"\\terminal server\\winstations\\rdp-tcp$"), "registry_rdp_server", Category.NETWORK),
    (re.compile(r"controlset\d+\\control\\session manager$"), "registry_session_manager", Category.PROCESS),
    (re.compile(r"\\powershell\\1\\shellids\\microsoft\.powershell$"), "registry_powershell_policy", Category.PROCESS),
    (re.compile(r"\\sysinternals\\[^\\]+$"), "registry_sysinternals_eula", Category.PROCESS),
    (re.compile(r"\\currentversion\\appcompatflags\\compatibility assistant\\store$"), "registry_pca_store", Category.PROCESS),
    (re.compile(r"controlset\d+\\control\\session manager\\appcompatcache$"), "registry_shimcache", Category.PROCESS),
]
_ROT13 = codecs.getencoder("rot13")


def _reg_type_names() -> dict[int, str]:
    import dissect.regf.regf as r

    return {int(getattr(r, n)): n for n in dir(r) if n.startswith("REG_") and isinstance(getattr(r, n), int)}


def _fmt_value(val: Any, limit: int = 160) -> str:
    if isinstance(val, bytes):
        return f"<{len(val)} bytes: {val[:16].hex()}{'...' if len(val) > 16 else ''}>"
    if isinstance(val, list | tuple):
        return "; ".join(str(x) for x in val)[:limit]
    s = str(val)
    return s[:limit] + ("..." if len(s) > limit else "")


def _key_values(key) -> list[tuple[str, Any, str]]:
    out = []
    try:
        for v in key.values():
            out.append((getattr(v, "name", "?"), getattr(v, "value", None), _reg_type_names().get(int(getattr(v, "type", -1)), "?")))
            if len(out) >= _VALUES_PER_KEY:
                break
    except Exception as e:  # noqa: BLE001
        log.debug("registry values unreadable at %s: %s", getattr(key, "path", "?"), e)
    return out


def _decode_userassist(name: str, data: bytes) -> tuple[str, int | None, datetime | None, int | None]:
    prog = _ROT13(name)[0]
    if isinstance(data, bytes) and len(data) >= 68:  # Win7+ layout
        count = int.from_bytes(data[4:8], "little")
        focus = int.from_bytes(data[8:12], "little")
        last = _wintime(int.from_bytes(data[60:68], "little"))
        return prog, count, last, focus
    if isinstance(data, bytes) and len(data) >= 16:  # XP layout
        return prog, int.from_bytes(data[4:8], "little") - 5, _wintime(int.from_bytes(data[8:16], "little")), None
    return prog, None, None, None


def _decode_systemtime(data: bytes) -> datetime | None:
    if not isinstance(data, bytes) or len(data) < 16:
        return None
    y, mo, _, d, h, mi, s, ms = (int.from_bytes(data[i:i + 2], "little") for i in range(0, 16, 2))
    try:
        return datetime(y, mo, d, h, mi, s, ms * 1000, tzinfo=UTC)
    except ValueError:
        return None


def _hive_label(path: Path, root_name: str) -> str:
    return _HIVE_LABELS.get(path.name.upper(), root_name or path.name)


def _parse_registry(path: Path, ctx: ParseContext) -> Iterator[Event]:
    _need_dissect("registry parsing")
    from dissect.regf import RegistryHive

    user = _user_from_path(path)
    with path.open("rb") as fh:
        hive = RegistryHive(fh)
        root = hive.root()
        root_name = getattr(root, "name", "") or ""
        label = _hive_label(path, root_name)
        current_cs = None
        if path.name.upper() == "SYSTEM":
            try:
                current_cs = int(root.subkey("Select").value("Current").value)
            except Exception:  # noqa: BLE001
                current_cs = None
        n = 0
        stack = [(root, "")]
        while stack:
            key, rel = stack.pop()
            try:
                subs = list(key.subkeys())
            except Exception as e:  # noqa: BLE001
                log.debug("subkeys unreadable at %s: %s", rel, e)
                subs = []
            for sk in subs:
                nm = getattr(sk, "name", "?")
                stack.append((sk, f"{rel}\\{nm}" if rel else nm))
            if key is root:
                continue
            low = rel.lower()
            action, cat = "registry_key", Category.OTHER
            for rx, act, c in _NOTABLE:
                if rx.search(low):
                    action, cat = act, c
                    break
            values = _key_values(key)
            if action == "registry_key" and not values:
                continue
            n += 1
            if n > REGISTRY_MAX_KEYS:
                log.warning("%s: more than %d keys, the rest is skipped", path.name, REGISTRY_MAX_KEYS)
                return
            if n % 50_000 == 0:
                progress.say("    %s: %d keys so far ...", label, n)
            ts = getattr(key, "timestamp", None)
            full = f"{label}\\{rel}"
            is_current = current_cs is not None and f"controlset{current_cs:03d}\\" in low
            if action == "registry_userassist":
                for vname, vdata, _ in values:
                    if vname.startswith(("UEME_", "HRZR_")):  # session counters, not programs
                        continue
                    prog, count, last, focus = _decode_userassist(vname, vdata)
                    if not prog:
                        continue
                    summ = (f"UserAssist: {prog} run {count if count is not None else '?'} times, last run {_iso(last)}"
                            + (f", focus {focus}" if focus else "") + f" (key {full})")
                    yield _mk(ctx, path, f"key {rel}\\{vname}", last or ts, Category.PROCESS, action, summ, summ,
                              {"key": full, "program": prog, "run_count": count, "last_run": _iso(last), "hive": label}, user=user, process=prog)
                continue
            if action == "registry_bam":
                bam_user = rel.rsplit("\\", 1)[-1]
                for vname, vdata, _ in values:
                    if not isinstance(vdata, bytes) or len(vdata) < 8 or vname in ("Version", "SequenceNumber"):
                        continue
                    last = _wintime(int.from_bytes(vdata[:8], "little"))
                    summ = f"BAM: {vname} last executed {_iso(last)} by SID {bam_user} (key {full})"
                    yield _mk(ctx, path, f"key {rel}\\{vname}", last or ts, Category.PROCESS, action, summ, summ,
                              {"key": full, "program": vname, "sid": bam_user, "hive": label}, user=user, process=vname)
                continue
            vals_txt = "; ".join(f"{vn}={_fmt_value(vv)}" for vn, vv, _ in values)[:_VALUE_CHARS]
            extra: dict[str, Any] = {"key": full, "hive": label, "values": {vn: (_fmt_value(vv, 400) if isinstance(vv, bytes) else vv) for vn, vv, _ in values},
                                     "value_types": {vn: vt for vn, _, vt in values}, "last_write": _iso(ts)}
            head = {"registry_service": "Service", "registry_autostart": "Autostart entry", "registry_usb_device": "USB device",
                    "registry_installed_software": "Installed software", "registry_network_profile": "Network profile",
                    "registry_sam_user": "Local account", "registry_scheduled_task": "Scheduled task", "registry_amcache_file": "Amcache file",
                    "registry_shellbag": "Shellbag", "registry_rdp_client": "RDP client history", "registry_defender_exclusion": "Defender exclusion",
                    "registry_shimcache": "ShimCache"}.get(action, "Registry key")
            if action == "registry_network_profile":
                for vn, vv, _ in values:
                    if vn in ("DateCreated", "DateLastConnected"):
                        extra[vn] = _iso(_decode_systemtime(vv))
                extra_txt = f" created={extra.get('DateCreated', '?')} last_connected={extra.get('DateLastConnected', '?')}"
            else:
                extra_txt = ""
            if is_current:
                extra["current_control_set"] = True
            name = rel.rsplit("\\", 1)[-1]
            summ = f"{head} {name} ({full}, last written {_iso(ts)}{extra_txt}): {vals_txt}" if vals_txt else f"{head} {name} ({full}, last written {_iso(ts)})"
            process = None
            if action in ("registry_service", "registry_autostart", "registry_amcache_file", "registry_ifeo"):
                for vn, vv, _ in values:
                    if vn.lower() in ("imagepath", "lowercaselongpath") and isinstance(vv, str):
                        process = vv
                        break
                if action == "registry_autostart" and values and isinstance(values[0][1], str):
                    process = process or values[0][1]
            u = user
            if action == "registry_sam_user":
                u = name
            yield _mk(ctx, path, f"key {rel}", ts, cat, action, summ, summ, extra, user=u, process=process)


# --- prefetch -----------------------------------------------------------------

def _parse_prefetch(path: Path, ctx: ParseContext) -> Iterator[Event]:
    _need_dissect("prefetch parsing")
    from dissect.target.plugins.os.windows.prefetch import Prefetch

    with path.open("rb") as fh:
        pf = Prefetch(fh)
        exe = pf.header.name.decode("utf-16-le", errors="ignore").split("\x00")[0]
        run_count = int(getattr(pf.fn, "run_count", 0) or 0)
        latest = pf.latest_timestamp
        previous = [t for t in pf.previous_timestamps if t]
        files = list(pf.metrics or [])
        dlls = [f for f in files if f.lower().endswith(".dll")]
        others = [f for f in files if not f.lower().endswith(".dll")]
        loaded = ", ".join(others[:20] + dlls[:10])
        runs = [latest, *previous]
        for i, ts in enumerate(runs):
            summ = (f"Prefetch: {exe} executed at {_iso(ts)} (run {i + 1} of {len(runs)} recorded, total run count {run_count}, "
                    f"prefetch {path.name}, hash {pf.header.hash:08X}); loaded {len(files)} files: {loaded}")
            yield _mk(ctx, path, f"run {i + 1}/{len(runs)}", ts, Category.PROCESS, "prefetch_execution", summ, "\n".join(files[:200]),
                      {"executable": exe, "run_count": run_count, "run_index": i + 1, "runs": [_iso(t) for t in runs], "files": files[:200],
                       "prefetch_version": pf.version, "hash": f"{pf.header.hash:08X}"}, process=exe)


# --- lnk ------------------------------------------------------------------------

def _uuid_v1(raw) -> tuple[datetime | None, str | None]:
    try:
        u = raw if isinstance(raw, uuid.UUID) else uuid.UUID(bytes_le=bytes(raw))
    except (ValueError, TypeError):
        return None, None
    if u.version != 1:
        return None, None
    ts = _UUID_EPOCH + timedelta(microseconds=u.time // 10)
    mac = ":".join(f"{(u.node >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6)))
    return ts, mac


def _str(obj, attr: str) -> str | None:
    v = getattr(obj, attr, None)
    v = getattr(v, "string", v)
    if isinstance(v, bytes):
        v = v.decode("utf-8", errors="replace")
    return v.strip("\x00") if isinstance(v, str) and v else None


def _parse_lnk(path: Path, ctx: ParseContext) -> Iterator[Event]:
    _need_dissect("LNK parsing")
    from dissect.shellitem.lnk import Lnk

    with path.open("rb") as fh:
        lnk = Lnk(fh)
    h = lnk.link_header
    if h is None:
        return
    flag = lnk.flag
    sd, li, ed = lnk.stringdata, lnk.linkinfo, lnk.extradata
    name = _str(sd, "name_string") if flag("has_name") else None
    relative = _str(sd, "relative_path") if flag("has_relative_path") else None
    workdir = _str(sd, "working_dir") if flag("has_working_dir") else None
    args = _str(sd, "command_line_arguments") if flag("has_arguments") else None
    icon = _str(sd, "icon_location") if flag("has_icon_location") else None
    base = suffix = None
    volume_label = serial = drive_type = net_name = None
    if flag("has_link_info"):
        base = _str(li, "local_base_path")
        suffix = _str(li, "common_path_suffix")
        vol = getattr(li, "volumeid", None) or getattr(li, "volume_id", None)
        if vol is not None:
            volume_label = _str(vol, "volume_label") or _str(vol, "data")
            sn = getattr(vol, "drive_serial_number", None)
            serial = f"{int(sn):08X}" if isinstance(sn, int) else None
            dt = getattr(vol, "drive_type", None)
            drive_type = str(dt) if dt is not None else None
        try:
            if li.flag("common_network_relative_link_and_pathsuffix"):
                net_name = _str(li.common_network_relative_link, "net_name")
        except Exception as e:  # noqa: BLE001
            log.debug("ignored: %s", e)
    target = (base or "") + (suffix or "") if base or suffix else None
    blocks = getattr(ed, "extradata", None) or {}
    tracker = blocks.get("TRACKER_PROPS") if isinstance(blocks, dict) else None
    machine = _str(tracker, "machine_id") if tracker is not None else None
    created, mac = (_uuid_v1(getattr(tracker, "file_droid", b"")) if tracker is not None else (None, None))
    t_write, t_access, t_create = _wintime(h.write_time), _wintime(h.access_time), _wintime(h.creation_time)
    st = path.stat()
    exe_like = (target or relative or "").lower().endswith((".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".lnk", ".msi"))
    summ = (f"Shortcut {path.name} -> {target or relative or '?'}" + (f" args=\"{args}\"" if args else "") + (f" workdir={workdir}" if workdir else "")
            + (f" name=\"{name}\"" if name else "") + (f" icon={icon}" if icon else "") + (f" size={h.filesize}" if h.filesize else "")
            + f" target times: created {_iso(t_create)} modified {_iso(t_write)} accessed {_iso(t_access)}"
            + (f"; link created {_iso(created)} on machine {machine or '?'}" + (f" (MAC {mac})" if mac else "") if created or machine else "")
            + (f"; volume {volume_label or ''} serial {serial or '?'}" if volume_label or serial else "") + (f"; network share {net_name}" if net_name else "")
            + (" [executable_target]" if exe_like else ""))
    yield _mk(ctx, path, "lnk", created or t_write or datetime.fromtimestamp(st.st_mtime, tz=UTC), Category.FILE, "lnk_shortcut", summ, summ,
              {"target": target, "relative_path": relative, "arguments": args, "working_dir": workdir, "name": name, "icon": icon,
               "target_size": h.filesize, "target_created": _iso(t_create), "target_modified": _iso(t_write), "target_accessed": _iso(t_access),
               "link_created": _iso(created), "machine_id": machine, "mac": mac, "volume_label": volume_label, "volume_serial": serial,
               "drive_type": drive_type, "network_share": net_name, "file_mtime": datetime.fromtimestamp(st.st_mtime, tz=UTC).isoformat(),
               "flags": ["executable_target"] if exe_like else []},
              user=_user_from_path(path), process=target if exe_like else None)


# --- $MFT -----------------------------------------------------------------------

def _parse_mft(path: Path, ctx: ParseContext) -> Iterator[Event]:
    _need_dissect("$MFT parsing")
    from dissect.ntfs import Mft

    with path.open("rb") as fh:
        mft = Mft(fh)
        n = 0
        for rec in mft.segments():
            try:
                si_list = list(rec.attributes.STANDARD_INFORMATION)
                fn_list = list(rec.attributes.FILE_NAME)
            except Exception as e:  # noqa: BLE001
                log.debug("skipped: %s", e)
                continue
            if not fn_list:
                continue
            n += 1
            if n > MFT_MAX_RECORDS:
                log.warning("%s: more than %d records, the rest is skipped", path.name, MFT_MAX_RECORDS)
                return
            seg = getattr(rec, "segment", None)
            try:
                paths = list(rec.full_paths())
            except Exception:  # noqa: BLE001
                paths = []
            try:
                fp = paths[0] if paths else fn_list[0].full_path()
            except Exception:  # noqa: BLE001
                fp = getattr(fn_list[0], "filename", "?")
            si = si_list[0] if si_list else None
            fn = fn_list[-1]  # the long name comes last when a DOS 8.3 name is present
            flags = []
            try:
                in_use = bool(rec.header.Flags & 1)
                is_dir = bool(rec.header.Flags & 2)
            except Exception:  # noqa: BLE001
                in_use, is_dir = True, False
            if not in_use:
                flags.append("deleted")
            si_c = getattr(si, "creation_time", None)
            fn_c = getattr(fn, "creation_time", None)
            if si_c and fn_c and si_c < fn_c - timedelta(seconds=1):
                flags.append("si_before_fn")  # $SI creation earlier than $FN: timestomping indicator
            if si_c and si_c.microsecond == 0 and getattr(si, "last_modification_time", None) and si.last_modification_time.microsecond == 0 and fn_c and fn_c.microsecond:
                flags.append("si_zero_fraction")  # whole-second $SI times with sub-second $FN: SetFileTime-style stomping
            ads = []
            try:
                ads = [a.name for a in rec.attributes.DATA if getattr(a, "name", "")]
            except Exception as e:  # noqa: BLE001
                log.debug("ignored: %s", e)
            if ads:
                flags.append("ads")
            try:
                size = rec.size() if not is_dir else 0
            except Exception:  # noqa: BLE001
                size = None
            summ = (f"MFT record {seg}: {'directory' if is_dir else 'file'} {fp}" + (f" ({size} bytes)" if size else "")
                    + f" $SI created {_iso(si_c)} modified {_iso(getattr(si, 'last_modification_time', None))} changed {_iso(getattr(si, 'last_change_time', None))} accessed {_iso(getattr(si, 'last_access_time', None))}"
                    + f"; $FN created {_iso(fn_c)} modified {_iso(getattr(fn, 'last_modification_time', None))}"
                    + (f"; ADS: {', '.join(ads[:5])}" if ads else "") + (f" [{' '.join(flags)}]" if flags else ""))
            yield _mk(ctx, path, f"record {seg}", si_c or fn_c, Category.FILE, "mft_entry", summ, summ,
                      {"segment": seg, "path": fp, "paths": paths[:5], "is_dir": is_dir, "in_use": in_use, "size": size, "ads": ads[:20],
                       "si_created": _iso(si_c), "si_modified": _iso(getattr(si, "last_modification_time", None)),
                       "si_changed": _iso(getattr(si, "last_change_time", None)), "si_accessed": _iso(getattr(si, "last_access_time", None)),
                       "fn_created": _iso(fn_c), "fn_modified": _iso(getattr(fn, "last_modification_time", None)), "flags": flags})


# --- ESE (SRUM, WebCache, ...) --------------------------------------------------

def _parse_ese(path: Path, ctx: ParseContext) -> Iterator[Event]:
    _need_dissect("ESE parsing")
    from dissect.database.ese import ESE

    with path.open("rb") as fh:
        if path.name.lower() == "srudb.dat":
            from dissect.database.ese.tools.sru import SRU

            sru = SRU(fh)
            n = 0
            for entry in sru.entries():
                try:
                    d = entry.as_dict()
                except Exception as e:  # noqa: BLE001
                    log.debug("skipped: %s", e)
                    continue
                n += 1
                if n > ESE_MAX_ROWS:
                    log.warning("%s: more than %d rows, the rest is skipped", path.name, ESE_MAX_ROWS)
                    return
                table = getattr(entry, "provider", "?")
                ts = d.get("TimeStamp")
                app = d.get("AppId")
                user = d.get("UserId")
                nice = {"{973F5D5C-1D90-4944-BE8E-24B94231A174}": "network usage", "{DD6636C4-8929-4683-974E-22C046A43763}": "network connectivity",
                        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "application resource usage", "{5C8CF1C7-7257-4F13-B223-970EF5939312}": "application timeline",
                        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": "push notification", "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "energy usage"}.get(table, table)
                cols = {k: v for k, v in d.items() if k not in ("TimeStamp", "AppId", "UserId", "AutoIncId") and v not in (None, 0, "")}
                body = "; ".join(f"{k}={_fmt_value(v, 80)}" for k, v in list(cols.items())[:14])
                summ = f"SRUM {nice}: {app or '?'} user {user or '?'} at {_iso(ts) if isinstance(ts, datetime) else ts}: {body}"
                cat = Category.NETWORK if "network" in nice else Category.PROCESS
                yield _mk(ctx, path, f"{table} row {n}", ts if isinstance(ts, datetime) else None, cat, f"srum_{nice.replace(' ', '_')}", summ, summ,
                          {"table": table, "app": app, "user": user, **{k: (v if isinstance(v, int | float | str) else _fmt_value(v)) for k, v in cols.items()}},
                          user=str(user) if user else None, process=str(app) if app else None)
            return
        db = ESE(fh)
        n = 0
        for table in db.tables():
            tname = getattr(table, "name", "?")
            if tname.startswith("MSys"):
                continue
            try:
                for rec in table.records():
                    try:
                        d = rec.as_dict()
                    except Exception as e:  # noqa: BLE001
                        log.debug("skipped: %s", e)
                        continue
                    n += 1
                    if n > ESE_MAX_ROWS:
                        log.warning("%s: more than %d rows, the rest is skipped", path.name, ESE_MAX_ROWS)
                        return
                    cols = {k: v for k, v in d.items() if v not in (None, "", b"")}
                    ts = None
                    for k, v in cols.items():
                        if isinstance(v, int) and k.lower().endswith(("time", "date")) and v > 10**17:
                            ts = _wintime(v)
                            if ts:
                                cols[k] = _iso(ts)
                                break
                    body = "; ".join(f"{k}={_fmt_value(v, 100)}" for k, v in list(cols.items())[:16])
                    summ = f"ESE {path.name} table {tname} row {n}: {body}"
                    yield _mk(ctx, path, f"{tname} row {n}", ts, Category.OTHER, "ese_row", summ, summ, {"table": tname, "columns": {k: _fmt_value(v, 200) for k, v in list(cols.items())[:40]}})
            except Exception as e:  # noqa: BLE001
                log.warning("%s: table %s unreadable: %s", path.name, tname, e)


class WinArtefactParser:
    kinds = ("registry_hive", "prefetch", "lnk", "mft", "ese")

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        from dfa.ingestion.detect import detect

        kind = detect(path).kind
        fn = {"registry_hive": _parse_registry, "prefetch": _parse_prefetch, "lnk": _parse_lnk, "mft": _parse_mft, "ese": _parse_ese}.get(kind)
        if fn is None:
            return
        yield from fn(path, ctx)


register(WinArtefactParser())
