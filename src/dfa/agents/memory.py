"""Memory agent: runs Volatility 3 plugins on a memory image and turns every
output row into an :class:`Event`.

The ``vol`` command line (optional extra ``memory``) is driven with the JSON
renderer, one plugin per subprocess with a timeout, so one plugin hanging or
crashing does not lose the others.  The OS is identified by trying
``windows.info``, then the Linux and macOS banners.  Windows symbol tables are
fetched by Volatility from Microsoft's symbol server on first use; set
``DFA_VOL_OFFLINE=1`` and ``DFA_VOL_SYMBOLS=<dir>`` on an air-gapped host (the
install bundle carries the symbol cache).

Cross-plugin checks add flags an analyst looks for: processes only found by
``psscan`` (hidden / terminated), ``malfind`` hits, hollowed processes,
unusual parent-child pairs and listening or established sockets.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from dfa.ingestion import ioc, progress
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import Category, Event, Source

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class VolPlugin:
    name: str
    description: str
    cap: int = 200_000


WINDOWS: list[VolPlugin] = [
    VolPlugin("windows.info", "kernel version, build, system time and layer information"),
    VolPlugin("windows.pslist", "running processes from the active process list"),
    VolPlugin("windows.psscan", "processes found by pool scanning (also terminated / unlinked ones)"),
    VolPlugin("windows.pstree", "process tree with parent-child relationships"),
    VolPlugin("windows.cmdline", "command line of every process"),
    VolPlugin("windows.netscan", "network connections and listening sockets (scan)"),
    VolPlugin("windows.netstat", "network connections from kernel structures"),
    VolPlugin("windows.svcscan", "services with state, binary path and start type"),
    VolPlugin("windows.malfind", "injected code: private executable memory regions with a disassembly preview"),
    VolPlugin("windows.hollowprocesses", "process hollowing indicators"),
    VolPlugin("windows.ldrmodules", "DLLs unlinked from one of the loader lists (injection / hiding)"),
    VolPlugin("windows.malware.suspicious_threads", "threads starting outside known modules"),
    VolPlugin("windows.malware.psxview", "cross-view process listing (hidden processes)"),
    VolPlugin("windows.getsids", "SIDs (accounts) each process runs as"),
    VolPlugin("windows.sessions", "logon sessions and their processes"),
    VolPlugin("windows.scheduled_tasks", "scheduled tasks from the in-memory registry"),
    VolPlugin("windows.registry.userassist", "UserAssist program execution from in-memory hives"),
    VolPlugin("windows.registry.hivelist", "registry hives present in memory"),
    VolPlugin("windows.cmdscan", "command history of console processes"),
    VolPlugin("windows.consoles", "console input / output buffers"),
    VolPlugin("windows.modules", "loaded kernel modules"),
    VolPlugin("windows.driverscan", "drivers found by scanning"),
    VolPlugin("windows.callbacks", "kernel callbacks (rootkit hooks)"),
    VolPlugin("windows.ssdt", "system service descriptor table hooks"),
    VolPlugin("windows.mutantscan", "mutexes (malware markers)"),
    VolPlugin("windows.amcache", "Amcache entries from memory"),
    VolPlugin("windows.shimcachemem", "ShimCache entries from memory"),
    VolPlugin("windows.filescan", "file objects in memory (paths of open / cached files)", cap=200_000),
    VolPlugin("windows.dlllist", "DLLs loaded by every process", cap=200_000),
    VolPlugin("windows.handles", "open handles per process", cap=200_000),
    VolPlugin("windows.envars", "environment variables per process", cap=200_000),
]
LINUX: list[VolPlugin] = [
    VolPlugin("linux.pslist", "running processes"),
    VolPlugin("linux.psscan", "processes found by scanning"),
    VolPlugin("linux.pstree", "process tree"),
    VolPlugin("linux.psaux", "processes with full command line"),
    VolPlugin("linux.bash", "bash command history recovered from memory"),
    VolPlugin("linux.sockstat", "open sockets per process"),
    VolPlugin("linux.lsmod", "loaded kernel modules"),
    VolPlugin("linux.hidden_modules", "kernel modules hidden from lsmod"),
    VolPlugin("linux.check_syscall", "syscall table hooks"),
    VolPlugin("linux.malfind", "injected code regions"),
    VolPlugin("linux.mountinfo", "mounted filesystems"),
    VolPlugin("linux.kmsg", "kernel log buffer"),
    VolPlugin("linux.lsof", "open files per process", cap=200_000),
    VolPlugin("linux.envars", "environment variables per process", cap=200_000),
]
MAC: list[VolPlugin] = [
    VolPlugin("mac.pslist", "running processes"),
    VolPlugin("mac.pstree", "process tree"),
    VolPlugin("mac.psaux", "processes with command line"),
    VolPlugin("mac.bash", "bash history from memory"),
    VolPlugin("mac.netstat", "network connections"),
    VolPlugin("mac.lsmod", "kernel extensions"),
    VolPlugin("mac.malfind", "injected code regions"),
    VolPlugin("mac.mount", "mounted filesystems"),
]
PLUGINS = {"windows": WINDOWS, "linux": LINUX, "mac": MAC}
# heavy plugins not run by default; ``dfa memory --plugins`` or the investigate loop can ask for them
DEFAULT_SKIP = {"windows.filescan", "windows.dlllist", "windows.handles", "windows.envars", "linux.lsof", "linux.envars"}

_CATEGORY = [
    (("netscan", "netstat", "sockstat", "sockscan", "ip."), Category.NETWORK),
    (("svcscan", "svcdiff"), Category.SERVICE),
    (("filescan", "dumpfiles", "pagecache", "lsof", "mountinfo", "mount"), Category.FILE),
    (("modules", "modscan", "driverscan", "callbacks", "ssdt", "lsmod", "check_syscall", "hidden_modules", "kmsg", "driverirp", "drivermodule"), Category.KERNEL),
    (("sessions", "getsids", "privileges"), Category.PRIVILEGE),
    (("registry.hivelist", "info", "banners"), Category.OTHER),
]
_SUSPICIOUS = ("malfind", "hollowprocesses", "ldrmodules", "suspicious_threads", "psxview", "hidden_modules", "check_syscall", "callbacks",
               "ssdt", "processghosting", "pebmasquerade", "unhooked_system_calls", "skeleton_key")
_TIME_COLS = ("CreateTime", "Created", "Create Time", "Start", "StartTime", "Last Write Time", "LastWriteTime", "Timestamp", "Time", "Date",
              "Last Updated", "Last Modified", "ExitTime", "Exit Time")
_NAME_COLS = ("ImageFileName", "Process", "Owner", "Name", "COMM", "Args", "Command", "Image", "Path", "Binary", "Service", "Module")
_SUSPICIOUS_PARENTS = {"svchost.exe": {"services.exe"}, "lsass.exe": {"wininit.exe"}, "services.exe": {"wininit.exe"}, "csrss.exe": {"smss.exe"},
                       "winlogon.exe": {"smss.exe"}, "wininit.exe": {"smss.exe"}, "smss.exe": {"System", "smss.exe"},
                       "taskhostw.exe": {"svchost.exe"}, "spoolsv.exe": {"services.exe"}, "lsm.exe": {"wininit.exe"}}
_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}


@dataclass
class PluginRun:
    name: str
    rows: int = 0
    status: str = "ok"  # ok | error | timeout | capped | skipped
    error: str | None = None
    seconds: float = 0.0


@dataclass
class MemoryAgent:
    """Parser for memory images; also used directly by ``dfa memory`` / ``dfa investigate``."""

    kinds = ("lime", "crashdump", "hiberfil", "memory_image")

    plugins: list[str] | None = None  # explicit selection (dotted vol names); None = OS default minus DEFAULT_SKIP
    timeout: int = 1800
    vol_bin: str | None = None
    symbols: str | None = None
    offline: bool | None = None
    runs: list[PluginRun] = field(default_factory=list)
    os_name: str | None = None

    # ---- volatility driver ------------------------------------------------
    def _vol(self) -> str:
        if self.vol_bin:
            return self.vol_bin
        cand = shutil.which("vol") or shutil.which("vol3") or str(Path(sys.executable).with_name("vol"))
        if not Path(cand).exists():
            raise RuntimeError("Volatility 3 not found: uv sync --extra memory (or set DFA_VOL_BIN)")
        return cand

    def _run(self, image: Path, plugin: str, extra_args: list[str] | None = None) -> list[dict]:
        """Run one plugin with the JSON renderer and return its rows (children flattened later)."""
        cmd = [self._vol(), "-q", "-r", "json", "-f", str(image)]
        symbols = self.symbols or os.environ.get("DFA_VOL_SYMBOLS")
        if symbols:
            cmd += ["-s", symbols]
        offline = self.offline if self.offline is not None else os.environ.get("DFA_VOL_OFFLINE", "") not in ("", "0", "false")
        if offline:
            cmd.append("--offline")
        cmd.append(plugin)
        cmd += extra_args or []
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, check=False)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise RuntimeError(err[-1][:300] if err else f"exit {proc.returncode}")
        out = proc.stdout.strip()
        start = out.find("[")
        if start < 0:
            return []
        try:
            data = json.loads(out[start:])
        except json.JSONDecodeError as e:
            raise RuntimeError(f"unparseable JSON output: {e}") from e
        return data if isinstance(data, list) else []

    def detect_os(self, image: Path) -> str | None:
        progress.say("    memory image %s (%s): Volatility 3 at %s", image.name, progress.human_size(image.stat().st_size), self._vol())
        for os_name, probe in (("windows", "windows.info"), ("linux", "linux.pslist"), ("mac", "mac.pslist")):
            progress.say("    probing for %s with %s (symbols may be downloaded on first use)...", os_name, probe)
            t0 = time.time()
            try:
                rows = self._run(image, probe)
                if rows:
                    self._probe_rows = (probe, rows)
                    progress.say("    %s identified in %.0fs", os_name, time.time() - t0)
                    return os_name
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                log.info("%s: %s", probe, str(e)[:200])
                progress.say("    not %s (%s)", os_name, str(e)[:120])
        progress.say("    OS not identified: no plugin will run (missing symbols? try DFA_VOL_SYMBOLS)")
        return None

    def plugin_list(self, os_name: str | None) -> list[VolPlugin]:
        base = PLUGINS.get(os_name or "", [])
        if self.plugins is None:
            return [p for p in base if p.name not in DEFAULT_SKIP]
        known = {p.name: p for p in base}
        return [known.get(n, VolPlugin(n, n)) for n in self.plugins]

    # ---- rows -> events --------------------------------------------------
    @staticmethod
    def _flatten(rows: list[dict], depth: int = 0) -> Iterator[tuple[int, dict]]:
        for r in rows:
            kids = r.get("__children") or []
            yield depth, {k: v for k, v in r.items() if k != "__children"}
            yield from MemoryAgent._flatten(kids, depth + 1)

    @staticmethod
    def _ts(row: dict) -> datetime | None:
        for c in _TIME_COLS:
            v = row.get(c)
            if isinstance(v, str) and len(v) >= 19 and v[4] == "-":
                try:
                    d = datetime.fromisoformat(v)
                    return d if d.tzinfo else d.replace(tzinfo=UTC)
                except ValueError:
                    continue
        return None

    def _event(self, ctx: ParseContext, image: Path, plugin: str, i: int, row: dict, depth: int, flags: list[str]) -> Event:
        short = plugin.split(".", 1)[-1]
        cat = Category.PROCESS
        for keys, c in _CATEGORY:
            if any(k in short for k in keys):
                cat = c
                break
        if short in ("bash", "cmdscan", "consoles", "registry.userassist", "amcache", "shimcachemem", "scheduled_tasks"):
            cat = Category.PROCESS
        name = next((str(row[c]) for c in _NAME_COLS if row.get(c) not in (None, "", "N/A")), None)
        pid = row.get("PID")
        ts = self._ts(row)
        body = "; ".join(f"{k}={v}" for k, v in row.items() if v not in (None, "", "N/A", [], "-") and k not in ("__children",))
        head = f"Memory {short}" + (f" PID {pid}" if pid is not None else "") + (f" {name}" if name else "")
        summ = f"{head}: {body}" + (f" [{' '.join(flags)}]" if flags else "")
        return Event(case_id=ctx.case_id, timestamp=ts, source=Source.MEMORY, source_file=image.name, record_ref=f"{plugin} #{i}",
                     host=ctx.host_hint, user=str(row.get("User") or row.get("Owner") or "") or None,
                     process=name if cat in (Category.PROCESS, Category.SERVICE, Category.NETWORK) else None, category=cat, action=f"mem_{short.replace('.', '_')}",
                     ioc=ioc.extract(summ), summary=summ[:1000], raw=json.dumps(row, default=str)[:2000],
                     extra={"plugin": plugin, "depth": depth, "flags": flags, **{k: v for k, v in row.items() if k != "__children"}})

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        self._probe_rows = None
        self.os_name = os_name = self.detect_os(path)
        info = {"os": os_name, "size_bytes": path.stat().st_size}
        if self._probe_rows and self._probe_rows[0] == "windows.info":
            info.update({r.get("Variable"): r.get("Value") for r in self._probe_rows[1] if r.get("Variable")})
        summ = f"Memory image {path.name}: " + ("; ".join(f"{k}={v}" for k, v in info.items() if v is not None) if os_name else "OS not identified (no matching symbols?)")
        yield Event(case_id=ctx.case_id, timestamp=None, source=Source.MEMORY, source_file=path.name, record_ref="image", host=ctx.host_hint,
                    category=Category.OTHER, action="memory_image_info", ioc=ioc.extract(summ), summary=summ[:1000], raw=summ, extra=info)
        if not os_name:
            return
        pslist: dict[int, dict] = {}
        psscan: dict[int, dict] = {}
        procs: dict[int, dict] = {}  # PID -> first row seen for it (pslist, then psscan, then pstree)
        plugins = self.plugin_list(os_name)
        progress.say("    %d plugins to run: %s", len(plugins), ", ".join(p.name.split(".", 1)[-1] for p in plugins))
        for k, plugin in enumerate(plugins, 1):
            run = PluginRun(plugin.name)
            self.runs.append(run)
            t0 = datetime.now(UTC)
            progress.say("    [%d/%d] %s ...", k, len(plugins), plugin.name)
            try:
                if self._probe_rows and self._probe_rows[0] == plugin.name:
                    rows = self._probe_rows[1]
                else:
                    rows = self._run(path, plugin.name)
            except subprocess.TimeoutExpired:
                run.status, run.error = "timeout", f"exceeded {self.timeout}s"
                log.warning("%s timed out", plugin.name)
                progress.say("    [%d/%d] %s: timed out after %ds", k, len(plugins), plugin.name, self.timeout)
                continue
            except RuntimeError as e:
                run.status, run.error = "error", str(e)[:300]
                log.warning("%s failed: %s", plugin.name, run.error)
                progress.say("    [%d/%d] %s: failed (%s)", k, len(plugins), plugin.name, run.error[:120])
                continue
            finally:
                run.seconds = round((datetime.now(UTC) - t0).total_seconds(), 1)
            progress.say("    [%d/%d] %s: %d rows in %.1fs", k, len(plugins), plugin.name, len(rows), run.seconds)
            short = plugin.name.split(".", 1)[-1]
            if short in ("pslist", "psscan", "pstree"):
                # index the whole plugin output first so a child can carry its parent's name and creation
                # time even when the parent comes later in the list (one-hop answers to "parent of X" questions)
                for _, r in self._flatten(rows):
                    if isinstance(r.get("PID"), int):
                        procs.setdefault(r["PID"], r)
            for i, (depth, row) in enumerate(self._flatten(rows), 1):
                if i > plugin.cap:
                    run.status = "capped"
                    break
                run.rows += 1
                if short in ("pslist", "psscan", "pstree") and (parent := procs.get(row.get("PPID"))) is not None:
                    row = {**row, "ParentImage": parent.get("ImageFileName") or parent.get("COMM"), "ParentCreateTime": parent.get("CreateTime")}
                flags: list[str] = []
                if any(s in short for s in _SUSPICIOUS):
                    flags.append("suspicious")
                pid = row.get("PID")
                img = str(row.get("ImageFileName") or row.get("COMM") or "").lower()
                if short == "pslist" and isinstance(pid, int):
                    pslist[pid] = row
                if short == "psscan" and isinstance(pid, int):
                    psscan[pid] = row
                    if pslist and pid not in pslist and not row.get("ExitTime"):
                        flags.append("hidden_process")
                    elif pslist and pid not in pslist:
                        flags.append("terminated")
                if short in ("pslist", "psscan", "pstree") and img:
                    ppid = row.get("PPID")
                    parent = str((pslist.get(ppid) or psscan.get(ppid) or {}).get("ImageFileName") or "").lower()
                    if img in _SUSPICIOUS_PARENTS and parent and parent not in _SUSPICIOUS_PARENTS[img]:
                        flags.append(f"unexpected_parent:{parent}")
                    if parent in _OFFICE and img in _SHELLS:
                        flags.append("office_spawned_shell")
                if short in ("netscan", "netstat") and str(row.get("State", "")).upper() in ("LISTENING", "ESTABLISHED"):
                    flags.append(str(row.get("State")).lower())
                yield self._event(ctx, path, plugin.name, i, row, depth, flags)


register(MemoryAgent())
