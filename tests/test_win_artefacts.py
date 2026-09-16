"""Loose Windows artefacts: prefetch and LNK on synthetic binaries, registry / $MFT / SRUM through fake dissect objects."""

from __future__ import annotations

import struct
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfa.ingestion.detect import detect
from dfa.ingestion.parsers.base import ParseContext, load_all, parser_for

pytest.importorskip("dissect.regf")
_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _ft(d: datetime) -> int:
    return int((d - _EPOCH).total_seconds() * 10**7)


def _prefetch_v23(exe: str, files: list[str], last_run: datetime, run_count: int) -> bytes:
    from dissect.target.plugins.os.windows.prefetch import c_prefetch

    strings = b""
    offsets = []
    for f in files:
        offsets.append((len(strings), len(f)))
        strings += f.encode("utf-16-le") + b"\x00\x00"
    metrics_off = 84 + 160
    metrics = b"".join(c_prefetch.FILE_METRICS_ARRAY_ENTRY_23(start_time=0, duration=0, average_duration=0, filename_string_offset=off,
                                                              filename_string_number_of_characters=n, flags=0x200, ntfs_reference=0).dumps()
                       for off, n in offsets)
    str_off = metrics_off + len(metrics)
    fi = c_prefetch.FILE_INFORMATION_23(metrics_array_offset=metrics_off, number_of_file_metrics_entries=len(files), trace_chain_array_offset=0,
                                        number_of_trace_chain_array_entries=0, filename_strings_offset=str_off, filename_strings_size=len(strings),
                                        volumes_information_offset=str_off + len(strings), number_of_volumes=0, volumes_information_size=0,
                                        last_run_time=_ft(last_run), run_count=run_count).dumps()
    name = exe.encode("utf-16-le").ljust(60, b"\x00")
    body = struct.pack("<I", 23) + b"SCCA" + struct.pack("<II", 0x11, 0) + name + struct.pack("<II", 0xC0FFEE, 0) + fi + metrics + strings
    return body[:8] + struct.pack("<I", len(body)) + body[12:]


def _lnk(target: str, args: str, machine: str, node: int) -> bytes:
    flags = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 7)  # link_info, name, relative_path, arguments, unicode
    t = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
    header = (struct.pack("<I", 76) + uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le + struct.pack("<II", flags, 0x20)
              + struct.pack("<QQQ", _ft(t), _ft(t), _ft(t)) + struct.pack("<IIIH", 4096, 0, 1, 0) + b"\x00" * 10)
    base = target.encode() + b"\x00"
    vol = struct.pack("<IIII", 17, 3, 0x1234ABCD, 16) + b"\x00"
    li_hdr = 28
    volid_off = li_hdr
    base_off = volid_off + len(vol)
    suffix_off = base_off + len(base)
    link_info = struct.pack("<IIIIIII", li_hdr + len(vol) + len(base) + 1, li_hdr, 1, volid_off, base_off, 0, suffix_off) + vol + base + b"\x00"

    def s(x: str) -> bytes:
        return struct.pack("<H", len(x)) + x.encode("utf-16-le")

    strings = s("Evil shortcut") + s("..\\Downloads\\evil.exe") + s(args)
    u1 = uuid.uuid1(node=node)
    tracker = (struct.pack("<II", 0x60, 0xA0000003) + struct.pack("<II", 0x58, 0) + machine.encode().ljust(16, b"\x00")
               + uuid.UUID(int=0).bytes_le + u1.bytes_le + uuid.UUID(int=0).bytes_le + u1.bytes_le)
    return header + link_info + strings + tracker + struct.pack("<I", 0)


def test_prefetch(tmp_path: Path):
    load_all()
    f = tmp_path / "MIMIKATZ.EXE-00C0FFEE.pf"
    f.write_bytes(_prefetch_v23("MIMIKATZ.EXE", ["\\VOLUME{1}\\WINDOWS\\SYSTEM32\\NTDLL.DLL", "\\VOLUME{1}\\USERS\\BOB\\DOWNLOADS\\MIMIKATZ.EXE"],
                                datetime(2026, 9, 1, 13, 47, 2, tzinfo=UTC), 7))
    assert detect(f).kind == "prefetch"
    evs = list(parser_for("prefetch").parse(f, ParseContext("c1", host_hint="WS042")))
    assert len(evs) == 1
    e = evs[0]
    assert e.action == "prefetch_execution" and e.category.value == "process" and e.process == "MIMIKATZ.EXE" and e.host == "WS042"
    assert e.ts_iso == "2026-09-01T13:47:02Z" and e.extra["run_count"] == 7 and e.extra["hash"] == "00C0FFEE"
    assert "MIMIKATZ.EXE executed at 2026-09-01T13:47:02Z" in e.summary and "DOWNLOADS\\MIMIKATZ.EXE" in e.summary
    assert e.summary.index("MIMIKATZ.EXE, ") < e.summary.index("NTDLL.DLL")  # non-DLL files listed first


def test_lnk(tmp_path: Path):
    load_all()
    f = tmp_path / "Users" / "bob" / "Recent" / "evil.lnk"
    f.parent.mkdir(parents=True)
    f.write_bytes(_lnk("C:\\Users\\bob\\Downloads\\evil.exe", "-k persist", "WS042", 0x001122334455))
    assert detect(f).kind == "lnk"
    (e,) = parser_for("lnk").parse(f, ParseContext("c1"))
    assert e.action == "lnk_shortcut" and e.category.value == "file" and e.user == "bob"
    x = e.extra
    assert x["target"] == "C:\\Users\\bob\\Downloads\\evil.exe" and x["arguments"] == "-k persist" and x["machine_id"] == "WS042"
    assert x["mac"] == "00:11:22:33:44:55" and x["volume_serial"] == "1234ABCD" and x["flags"] == ["executable_target"]
    assert x["link_created"].startswith("20") and e.ts_iso == x["link_created"]  # UUIDv1 time of the tracker droid
    assert "link created" in e.summary and "on machine WS042 (MAC 00:11:22:33:44:55)" in e.summary and e.process.endswith("evil.exe")


# ---- registry through a fake hive -------------------------------------------------

class _Val:
    def __init__(self, name, value, type_=1):
        self.name, self.value, self.type = name, value, type_


class _Key:
    def __init__(self, name, ts=None, values=(), subkeys=()):
        self.name, self.timestamp, self._values, self._subkeys = name, ts, list(values), list(subkeys)

    def subkeys(self):
        return iter(self._subkeys)

    def values(self):
        return iter(self._values)

    def subkey(self, name):
        for k in self._subkeys:
            if k.name.lower() == name.lower():
                return k
        raise KeyError(name)

    def value(self, name):
        for v in self._values:
            if v.name.lower() == name.lower():
                return v
        raise KeyError(name)


class _Hive:
    def __init__(self, fh):
        self.fh = fh

    def root(self):
        return _ROOT


_T = datetime(2026, 9, 1, 13, 0, tzinfo=UTC)
_ua_blob = b"\x00" * 4 + (5).to_bytes(4, "little") + (2).to_bytes(4, "little") + b"\x00" * 48 + _ft(datetime(2026, 9, 1, 14, 5, tzinfo=UTC)).to_bytes(8, "little") + b"\x00" * 4
_ROOT = _Key("ROOT", _T, subkeys=[
    _Key("Software", _T, subkeys=[_Key("Microsoft", _T, subkeys=[_Key("Windows", _T, subkeys=[_Key("CurrentVersion", _T, subkeys=[
        _Key("Run", _T, values=[_Val("Updater", "C:\\Users\\bob\\AppData\\Roaming\\svchost.exe -boot"), _Val("OneDrive", "C:\\Program Files\\OneDrive.exe")]),
        _Key("Explorer", _T, subkeys=[_Key("UserAssist", _T, subkeys=[_Key("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", _T, subkeys=[
            _Key("Count", _T, values=[_Val("P:\\Hfref\\obo\\Qbjaybnqf\\zvzvxngm.rkr", _ua_blob, 3), _Val("UEME_CTLSESSION", b"\x00" * 8, 3)])])])]),
        _Key("Uninstall", _T, subkeys=[_Key("7-Zip", _T, values=[_Val("DisplayName", "7-Zip 23.01"), _Val("InstallDate", "20260801")])]),
    ])])])]),
    _Key("Empty", _T),  # no values, not notable -> skipped
    _Key("Select", _T, values=[_Val("Current", 1, 4)]),
    _Key("ControlSet001", _T, subkeys=[_Key("Services", _T, subkeys=[
        _Key("EvilSvc", _T, values=[_Val("ImagePath", "C:\\Windows\\Temp\\evil.exe"), _Val("Start", 2, 4), _Val("Type", 16, 4)]),
        _Key("bam", _T, subkeys=[_Key("State", _T, subkeys=[_Key("UserSettings", _T, subkeys=[
            _Key("S-1-5-21-1-2-3-1001", _T, values=[_Val("\\Device\\HarddiskVolume2\\Windows\\Temp\\evil.exe", _ft(datetime(2026, 9, 1, 14, 10, tzinfo=UTC)).to_bytes(8, "little") + b"\x00" * 16, 3),
                                                    _Val("Version", 1, 4)])])])])])]),
])


def test_registry_fake_hive(tmp_path: Path, monkeypatch):
    import dissect.regf

    load_all()
    monkeypatch.setattr(dissect.regf, "RegistryHive", _Hive)
    f = tmp_path / "Users" / "bob" / "NTUSER.DAT"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"regf" + b"\x00" * 100)
    assert detect(f).kind == "registry_hive"
    evs = list(parser_for("registry_hive").parse(f, ParseContext("c1")))
    by = {e.action: [x for x in evs if x.action == e.action] for e in evs}
    run = by["registry_autostart"][0]
    assert run.category.value == "process" and run.user == "bob" and run.process.endswith("svchost.exe -boot") and run.extra["key"].startswith("HKCU\\Software")
    assert "Updater=C:\\Users\\bob\\AppData\\Roaming\\svchost.exe -boot" in run.summary and run.ts_iso == "2026-09-01T13:00:00Z"
    ua = by["registry_userassist"]
    assert len(ua) == 1 and ua[0].extra["program"] == "C:\\Users\\bob\\Downloads\\mimikatz.exe" and ua[0].extra["run_count"] == 5
    assert ua[0].ts_iso == "2026-09-01T14:05:00Z" and ua[0].process.endswith("mimikatz.exe")
    svc = next(e for e in by["registry_service"] if "EvilSvc" in e.summary)
    assert svc.category.value == "service" and svc.process == "C:\\Windows\\Temp\\evil.exe" and "EvilSvc" in svc.summary
    bam = by["registry_bam"]
    assert len(bam) == 1 and bam[0].ts_iso == "2026-09-01T14:10:00Z" and bam[0].extra["sid"] == "S-1-5-21-1-2-3-1001" and "evil.exe" in bam[0].summary
    sw = by["registry_installed_software"][0]
    assert sw.category.value == "package" and "7-Zip 23.01" in sw.summary
    assert "registry_key" in by and all("Empty" not in e.summary for e in by["registry_key"])


# ---- $MFT through fake records ------------------------------------------------------

class _Attr:
    def __init__(self, c, m, ch, a, path=None, name=""):
        self.creation_time, self.last_modification_time, self.last_change_time, self.last_access_time = c, m, ch, a
        self._path, self.name = path, name

    def full_path(self):
        return self._path


class _Attrs:
    def __init__(self, si, fn, data=()):
        self.STANDARD_INFORMATION, self.FILE_NAME, self.DATA = si, fn, list(data)


class _Hdr:
    def __init__(self, flags):
        self.Flags = flags


class _Rec:
    def __init__(self, seg, path, si, fn, flags=1, size=10, ads=()):
        self.segment, self._path, self.attributes, self.header, self._size = seg, path, _Attrs(si, fn, [_Attr(None, None, None, None, name=a) for a in ads]), _Hdr(flags), size

    def full_paths(self):
        return [self._path]

    def size(self):
        return self._size


class _Mft:
    def __init__(self, fh):
        pass

    def segments(self):
        t0, t1 = datetime(2026, 9, 1, 10, 0, tzinfo=UTC), datetime(2026, 9, 1, 11, 0, tzinfo=UTC)
        old = datetime(2020, 1, 1, tzinfo=UTC)
        yield _Rec(5, "Windows\\Temp\\evil.exe", [_Attr(old, old, t1, t1)], [_Attr(t1, t1, t1, t1, "Windows\\Temp\\evil.exe")], ads=["Zone.Identifier"])
        yield _Rec(6, "Users\\bob\\gone.txt", [_Attr(t0, t0, t0, t0)], [_Attr(t0, t0, t0, t0, "Users\\bob\\gone.txt")], flags=0)
        yield _Rec(7, "Users\\bob", [_Attr(t0, t0, t0, t0)], [_Attr(t0, t0, t0, t0, "Users\\bob")], flags=3)


def test_mft_fake(tmp_path: Path, monkeypatch):
    import dissect.ntfs

    load_all()
    monkeypatch.setattr(dissect.ntfs, "Mft", _Mft)
    f = tmp_path / "$MFT"
    f.write_bytes(b"FILE0" + b"\x00" * 1019)
    assert detect(f).kind == "mft"
    evs = list(parser_for("mft").parse(f, ParseContext("c1")))
    assert [e.extra["segment"] for e in evs] == [5, 6, 7]
    evil, gone, home = evs
    assert set(evil.extra["flags"]) == {"si_before_fn", "ads"} and evil.extra["ads"] == ["Zone.Identifier"] and evil.ts_iso == "2020-01-01T00:00:00Z"
    assert "[si_before_fn ads]" in evil.summary and "$FN created 2026-09-01T11:00:00Z" in evil.summary
    assert gone.extra["flags"] == ["deleted"] and gone.extra["in_use"] is False
    assert home.extra["is_dir"] is True and "directory Users\\bob" in home.summary and evil.category.value == "file"


# ---- SRUM through fake entries -------------------------------------------------------

class _Entry:
    def __init__(self, provider, d):
        self.provider, self._d = provider, d

    def as_dict(self):
        return dict(self._d)


class _SRU:
    def __init__(self, fh):
        pass

    def entries(self):
        yield _Entry("{973F5D5C-1D90-4944-BE8E-24B94231A174}", {"TimeStamp": datetime(2026, 9, 1, 14, 0, tzinfo=UTC), "AppId": "C:\\Windows\\Temp\\evil.exe",
                                                                "UserId": "S-1-5-21-1-2-3-1001", "BytesSent": 123456, "BytesRecvd": 789, "InterfaceLuid": 1689399632855040})


def test_srum_fake(tmp_path: Path, monkeypatch):
    import dissect.database.ese.tools.sru as srumod

    load_all()
    monkeypatch.setattr(srumod, "SRU", _SRU)
    f = tmp_path / "SRUDB.dat"
    f.write_bytes(b"\x00" * 4 + b"\xef\xcd\xab\x89" + b"\x00" * 100)
    assert detect(f).kind == "ese"
    (e,) = parser_for("ese").parse(f, ParseContext("c1"))
    assert e.action == "srum_network_usage" and e.category.value == "network" and e.ts_iso == "2026-09-01T14:00:00Z"
    assert e.process == "C:\\Windows\\Temp\\evil.exe" and e.extra["BytesSent"] == 123456 and "BytesSent=123456" in e.summary
