"""Format detection by magic bytes and content sniffing (never by extension alone).

The detector returns a :class:`Detection` whose ``kind`` is the key used by the
parser registry.  Compressed containers are reported with ``container`` set so
the ingestion agent can unpack and re-detect the contents.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

HEAD_BYTES = 8192
TEXT_SAMPLE_LINES = 200


@dataclass
class Detection:
    kind: str  # parser key, e.g. "syslog", "sqlite", "evtx", "pcap", "unknown"
    confidence: float  # 0..1
    description: str
    container: str | None = None  # "gzip" | "zip" | "tar" | "bz2" | "xz" | "7z"
    details: dict = field(default_factory=dict)
    text: bool = False


# ---- binary signatures -------------------------------------------------
# (magic, offset, kind, description, container)
_MAGIC: list[tuple[bytes, int, str, str, str | None]] = [
    (b"SQLite format 3\x00", 0, "sqlite", "SQLite 3 database", None),
    (b"ElfFile\x00", 0, "evtx", "Windows XML event log (EVTX)", None),
    (b"LfLe", 0, "evt", "Legacy Windows event log (EVT)", None),
    (b"\xd4\xc3\xb2\xa1", 0, "pcap", "libpcap capture (little-endian, µs)", None),
    (b"\xa1\xb2\xc3\xd4", 0, "pcap", "libpcap capture (big-endian, µs)", None),
    (b"\x4d\x3c\xb2\xa1", 0, "pcap", "libpcap capture (little-endian, ns)", None),
    (b"\xa1\xb2\x3c\x4d", 0, "pcap", "libpcap capture (big-endian, ns)", None),
    (b"\x0a\x0d\x0d\x0a", 0, "pcapng", "pcapng capture", None),
    (b"regf", 0, "registry_hive", "Windows registry hive", None),
    (b"MAM\x04", 0, "prefetch", "Windows prefetch (compressed, Win8+)", None),
    (b"SCCA", 4, "prefetch", "Windows prefetch", None),
    (b"\xef\xcd\xab\x89", 4, "ese", "Extensible Storage Engine DB (SRUM, WebCache, NTDS)", None),
    (b"FILE0", 0, "mft", "NTFS $MFT", None),
    (b"RCRD", 0, "ntfs_logfile", "NTFS $LogFile", None),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "lnk", "Windows shortcut (LNK)", None),
    (b"EVF\x09\x0d\x0a\xff\x00", 0, "e01", "Expert Witness Format disk image (E01)", None),
    (b"KDMV", 0, "disk_image", "VMware virtual disk (VMDK)", None),
    (b"# Disk DescriptorFile", 0, "disk_image", "VMware virtual disk descriptor (VMDK)", None),
    (b"vhdxfile", 0, "disk_image", "Hyper-V virtual disk (VHDX)", None),
    (b"conectix", 0, "disk_image", "Virtual PC / Hyper-V disk (VHD)", None),
    (b"QFI\xfb", 0, "disk_image", "QEMU copy-on-write disk (qcow2)", None),
    (b"<<< Oracle VM VirtualBox Disk Image >>>", 0, "disk_image", "VirtualBox disk image (VDI)", None),
    (b"EFI PART", 512, "disk_image", "GPT-partitioned raw disk image", None),
    (b"NTFS    ", 3, "disk_image", "NTFS volume image", None),
    (b"MSDOS5.0", 3, "disk_image", "FAT volume image", None),
    (b"MSWIN4.1", 3, "disk_image", "FAT volume image", None),
    (b"mkfs.fat", 3, "disk_image", "FAT volume image", None),
    (b"\x53\xef", 1080, "disk_image", "ext2/3/4 volume image", None),
    (b"XFSB", 0, "disk_image", "XFS volume image", None),
    (b"CD001", 32769, "disk_image", "ISO 9660 image", None),
    (b"LVF\x09\x0d\x0a\xff\x00", 0, "l01", "EWF logical evidence file (L01)", None),
    (b"EMiL", 0, "lime", "LiME Linux memory dump", None),
    (b"PAGEDU64", 0, "crashdump", "Windows 64-bit crash dump", None),
    (b"PAGEDUMP", 0, "crashdump", "Windows 32-bit crash dump", None),
    (b"hibr", 0, "hiberfil", "Windows hibernation file", None),
    (b"HIBR", 0, "hiberfil", "Windows hibernation file", None),
    (b"\x7fELF", 0, "elf", "ELF executable", None),
    (b"MZ", 0, "pe", "PE executable", None),
    (b"%PDF", 0, "pdf", "PDF document", None),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole", "OLE2 compound document (Office 97-2003, MSI)", None),
    (b"\x1f\x8b", 0, "gzip", "gzip", "gzip"),
    (b"BZh", 0, "bzip2", "bzip2", "bz2"),
    (b"\xfd7zXZ\x00", 0, "xz", "xz", "xz"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", "7-Zip archive", "7z"),
    (b"PK\x03\x04", 0, "zip", "zip archive", "zip"),
    (b"ustar", 257, "tar", "tar archive", "tar"),
    (b"\x4a\x46\x49\x46", 6, "jpeg", "JPEG image", None),
    (b"\x89PNG", 0, "png", "PNG image", None),
]

# ---- text patterns -----------------------------------------------------
_RE_SYSLOG_BSD = re.compile(r"^[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \S+ ")
_RE_SYSLOG_5424 = re.compile(r"^<\d{1,3}>1 \d{4}-\d{2}-\d{2}T")
_RE_SYSLOG_PRI_BSD = re.compile(r"^<\d{1,3}>[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} ")
_RE_SYSLOG_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)? \S+ \S+")
_RE_APACHE_ACCESS = re.compile(r'^\S+ \S+ \S+ \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "')
_RE_APACHE_ERROR = re.compile(r"^\[[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}(\.\d+)? \d{4}\] \[")
_RE_DMESG = re.compile(r"^\[ *\d+\.\d+\] ")
_RE_DPKG = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (startup|install|status|configure|upgrade|remove|purge|trigproc|update-alternatives)")
_RE_APT_TERM = re.compile(r"^Log started: \d{4}-\d{2}-\d{2}", re.MULTILINE)
_RE_IIS = re.compile(r"^#Software: Microsoft Internet Information Services")
_RE_W3C = re.compile(r"^#Fields: ")
_RE_ZEEK = re.compile(r"^#separator ")
_RE_XML = re.compile(r"^\s*<\?xml")
_RE_EVTX_XML = re.compile(r"<Event xmlns=['\"]http://schemas\.microsoft\.com/win/2004/08/events/event['\"]")
_RE_AUDITD = re.compile(r"^type=\w+ msg=audit\(\d+\.\d+:\d+\):")
_RE_WINDOWS_FW = re.compile(r"^#Software: Microsoft Windows Firewall")
_RE_BASH_HISTORY = re.compile(r"^#\d{10}$")
_RE_JSON_KEY = re.compile(r'"[^"\n]{1,64}"\s*:')


# Extension-only guess for raw memory images (no magic).  ``.bin`` is deliberately absent: on a
# Windows triage image it is almost always an application blob, and a false positive launches
# Volatility on it.  Generic extensions (.raw, .dmp, .img, ...) additionally need a plausible size.
_MEMORY_EXT = {".vmem", ".mem", ".lime", ".vmsn", ".vmss"}
_MEMORY_EXT_LOOSE = {".raw", ".dmp", ".core", ".sav", ".img", ".dd"}
MEMORY_MIN_BYTES = 32 * 1024 * 1024


def _mbr_partitions(head: bytes) -> bool:
    """True when the MBR partition table holds at least one plausible entry."""
    for i in range(4):
        e = head[446 + i * 16: 446 + (i + 1) * 16]
        boot, ptype = e[0], e[4]
        sectors = int.from_bytes(e[12:16], "little")
        if boot in (0x00, 0x80) and ptype and sectors:
            return True
    return False


def _read_head(path: Path) -> bytes:
    with path.open("rb") as fh:
        return fh.read(HEAD_BYTES)


def _is_text(head: bytes) -> bool:
    if not head:
        return True
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
        return True
    except UnicodeDecodeError:
        try:
            head.decode("latin-1")
            printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
            return printable / len(head) > 0.9
        except UnicodeDecodeError:
            return False


def _sample_lines(path: Path, n: int = TEXT_SAMPLE_LINES) -> list[str]:
    lines: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if line.strip():
                lines.append(line)
            if len(lines) >= n:
                break
    return lines


def _ratio(regex: re.Pattern, lines: list[str]) -> float:
    if not lines:
        return 0.0
    return sum(1 for ln in lines if regex.search(ln)) / len(lines)


def _try_json(lines: list[str], head_text: str) -> Detection | None:
    stripped = head_text.lstrip()
    if stripped.startswith(("{", "[")):
        # JSONL: every sampled line is an object
        obj_lines = [ln for ln in lines if ln.lstrip().startswith("{")]
        if obj_lines and len(obj_lines) / len(lines) > 0.9:
            ok = 0
            for ln in obj_lines[:50]:
                try:
                    json.loads(ln)
                    ok += 1
                except json.JSONDecodeError:
                    pass
            if ok / min(50, len(obj_lines)) > 0.9:
                return Detection("jsonl", 0.95, "JSON lines log", text=True)
        # single JSON document (array of events or object)
        if len(head_text) < HEAD_BYTES - 1:
            try:
                json.loads(head_text)
                return Detection("json", 0.9, "JSON document", text=True)
            except json.JSONDecodeError:
                return None
        # large document: only the head is available, require real JSON structure
        if _RE_JSON_KEY.search(head_text):
            return Detection("json", 0.6, "JSON document (large, header only)", text=True)
    return None


def _try_csv(lines: list[str]) -> Detection | None:
    if len(lines) < 2:
        return None
    sample = "\n".join(lines[:50])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return None
    try:
        rows = list(csv.reader(io.StringIO(sample), dialect))
    except csv.Error:  # e.g. a minified single-line file: "field larger than field limit"
        return None
    widths = [len(r) for r in rows if r]
    if not widths or widths[0] < 2:
        return None
    consistent = sum(1 for w in widths if w == widths[0]) / len(widths)
    if consistent < 0.9:
        return None
    has_header = csv.Sniffer().has_header(sample) if len(rows) > 2 else True
    return Detection(
        "csv", 0.7 + 0.2 * consistent, f"delimited text ({dialect.delimiter!r}, {widths[0]} cols)",
        details={"delimiter": dialect.delimiter, "columns": widths[0], "has_header": has_header}, text=True,
    )


def detect(path: str | Path) -> Detection:
    path = Path(path)
    if path.is_dir():
        return Detection("directory", 1.0, "directory")
    try:
        head = _read_head(path)
    except OSError as e:
        return Detection("unreadable", 1.0, f"cannot read: {e}")
    if not head:
        return Detection("empty", 1.0, "empty file")

    for magic, off, kind, desc, container in _MAGIC:
        if head[off : off + len(magic)] == magic:
            if kind == "registry_hive" and len(head) >= 0x20 and int.from_bytes(head[0x1C:0x20], "little") != 0:
                # same "regf" header, but file type != 0 (1 = legacy log, 6 = Win8.1+ log) is a transaction
                # log (.LOG1/.LOG2): dirty pages, not a parseable hive
                return Detection("registry_log", 0.99, "Windows registry transaction log (.LOG1/.LOG2)")
            return Detection(kind, 0.99, desc, container=container)

    if len(head) >= 512 and head[510:512] == b"\x55\xaa" and _mbr_partitions(head):
        return Detection("disk_image", 0.9, "MBR-partitioned raw disk image")

    if not _is_text(head):
        ext = path.suffix.lower()
        if ext in _MEMORY_EXT or (ext in _MEMORY_EXT_LOOSE and path.stat().st_size >= MEMORY_MIN_BYTES):
            return Detection("memory_image", 0.6, f"raw memory image (by extension {ext})")
        return Detection("binary", 0.5, "unknown binary")

    head_text = head.decode("utf-8", errors="replace")
    lines = _sample_lines(path)

    if _RE_XML.match(head_text):
        if _RE_EVTX_XML.search(head_text):
            return Detection("evtx_xml", 0.95, "Windows event log exported as XML", text=True)
        return Detection("xml", 0.7, "XML document", text=True)

    checks: list[tuple[re.Pattern, str, str]] = [
        (_RE_SYSLOG_5424, "syslog", "syslog RFC 5424"),
        (_RE_SYSLOG_PRI_BSD, "syslog", "syslog with PRI header"),
        (_RE_SYSLOG_BSD, "syslog", "syslog RFC 3164 (BSD)"),
        (_RE_SYSLOG_ISO, "syslog", "syslog with ISO 8601 timestamps"),
        (_RE_APACHE_ACCESS, "apache_access", "Apache/Nginx access log"),
        (_RE_APACHE_ERROR, "apache_error", "Apache error log"),
        (_RE_DMESG, "dmesg", "kernel ring buffer (dmesg)"),
        (_RE_DPKG, "dpkg", "dpkg log"),
        (_RE_AUDITD, "auditd", "Linux audit log"),
    ]
    best: tuple[float, str, str] | None = None
    for rx, kind, desc in checks:
        r = _ratio(rx, lines)
        if r >= 0.5 and (best is None or r > best[0]):
            best = (r, kind, desc)
    if best:
        return Detection(best[1], round(best[0], 2), best[2], text=True)

    if d := _try_json(lines, head_text):
        return d

    first = lines[0] if lines else ""
    if _RE_IIS.match(first) or (_RE_W3C.match(first) or any(_RE_W3C.match(ln) for ln in lines[:5])):
        if any(_RE_WINDOWS_FW.match(ln) for ln in lines[:5]):
            return Detection("w3c", 0.9, "Windows Firewall log (W3C)", text=True)
        return Detection("w3c", 0.9, "W3C extended log (IIS / Exchange / firewall)", text=True)
    if _RE_ZEEK.match(first):
        return Detection("zeek", 0.95, "Zeek/Bro TSV log", text=True)
    if _RE_APT_TERM.search(head_text):
        return Detection("apt_term", 0.9, "apt terminal log", text=True)
    if _ratio(_RE_BASH_HISTORY, lines) > 0.3:
        return Detection("bash_history", 0.8, "bash history with timestamps", text=True)

    if d := _try_csv(lines):
        return d

    return Detection("text", 0.3, "plain text (generic line parser)", text=True)
