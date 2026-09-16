"""Triage filter and the detector fixes that came with it."""

from pathlib import Path

from dfa.ingestion.agent import IngestionAgent
from dfa.ingestion.detect import Detection, detect
from dfa.ingestion.triage import TEXT_GATE_LINES, noise_dir, triage

SYSLOG = "Mar 16 08:12:04 app-1 sshd[4659]: Accepted password for root from 10.0.0.5 port 4000 ssh2\n"


def _text(p: Path, content: str) -> Detection:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return detect(p)


def test_noise_directory(tmp_path: Path):
    f = tmp_path / "Windows" / "Fonts" / "arial.ttf"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"\x00\x01\x00\x00" + b"\x00" * 100)
    assert noise_dir(f) == "Fonts"
    assert triage(f, detect(f)).reason == "triage: noise directory 'Fonts'"
    # a gzip inside a noise directory is not unpacked either
    assert triage(f, Detection("gzip", 0.99, "gzip", container="gzip")) is not None
    # the directory rule is case-insensitive and applies to every component
    g = tmp_path / "users" / "x" / "appdata" / "local" / "google" / "chrome" / "user data" / "zxcvbndata" / "3" / "passwords.txt"
    assert triage(g, _text(g, "password\n123456\n")).reason.endswith("'zxcvbndata'")
    # a log next to it is kept
    h = tmp_path / "Windows" / "Logs" / "CBS" / "CBS.log"
    assert triage(h, _text(h, "2023-07-12 06:18:47, Info CBS Starting TrustedInstaller initialization.\n")) is None


def test_noise_extension_only_for_text_kinds(tmp_path: Path):
    js = tmp_path / "bundle.js"
    assert triage(js, _text(js, "function a(){return 1}\n")).reason == "triage: .js file (text)"
    mof = tmp_path / "wbem" / "x.mof"
    assert triage(mof, _text(mof, "#pragma namespace\n")) is not None
    # a file that merely has a noise extension but is a real artefact (e.g. an EVTX renamed .js) is kept
    assert triage(js, Detection("evtx", 0.99, "EVTX")) is None
    # the COMPONENTS servicing hive is skipped by name, SOFTWARE next to it is kept
    for name, skipped in (("COMPONENTS", True), ("SOFTWARE", False)):
        h = tmp_path / "config" / name
        h.parent.mkdir(exist_ok=True)
        h.write_bytes(b"regf" + b"\x00" * 60)
        assert (triage(h, detect(h)) is not None) is skipped
    # and the WMI repository next to the .mof files is not dropped
    objs = tmp_path / "wbem" / "Repository" / "OBJECTS.DATA"
    objs.parent.mkdir(parents=True)
    objs.write_bytes(b"\x00\x01" * 50)
    assert triage(objs, detect(objs)) is None


def test_large_timestampless_text_is_skipped(tmp_path: Path):
    words = tmp_path / "english_wikipedia.txt"
    d = _text(words, "".join(f"word{i}\n" for i in range(TEXT_GATE_LINES + 500)))
    assert d.kind == "text"
    assert "no timestamps" in triage(words, d).reason
    # same size with timestamps: a log, kept
    log = tmp_path / "setup.log"
    assert triage(log, _text(log, "".join(f"2023-07-12 06:{i % 60:02d}:00 step {i}\n" for i in range(TEXT_GATE_LINES + 500)))) is None
    # small timestamp-less text (notes on the desktop, a ransom note) is kept
    note = tmp_path / "READ_ME.txt"
    assert triage(note, _text(note, "your files are encrypted\ncontact us\n")) is None
    # JSON data tables are gated the same way
    data = tmp_path / "wallet.json"
    assert triage(data, _text(data, "[\n" + ",\n".join(f'{{"site": "s{i}"}}' for i in range(TEXT_GATE_LINES + 100)) + "\n]\n")) is not None


def test_agent_applies_triage_and_survives_bad_files(tmp_path: Path):
    (tmp_path / "auth.log").write_text(SYSLOG)
    (tmp_path / "Fonts").mkdir()
    (tmp_path / "Fonts" / "x.fon").write_bytes(b"MZ" + b"\x00" * 64)
    # a minified single-line file used to crash the CSV sniffer inside detect()
    (tmp_path / "edge_driver.js").write_text("a," * 100_000 + "\n")
    agent = IngestionAgent(case_id="t")
    evs = list(agent.events([tmp_path]))
    assert len(evs) == 1 and evs[0].action == "ssh_login_success"
    st = {Path(f.path).name: (f.status, f.error) for f in agent.report.files}
    assert st["x.fon"][0] == "skipped" and "Fonts" in st["x.fon"][1]
    assert st["edge_driver.js"][0] == "skipped" and ".js" in st["edge_driver.js"][1]
    assert st["auth.log"][0] == "parsed"
    # --no-triage parses everything
    agent = IngestionAgent(case_id="t", triage=False)
    evs = list(agent.events([tmp_path]))
    assert len(evs) == 2  # syslog line + the one-line js
    assert all(f.status in ("parsed", "unsupported") for f in agent.report.files)


def test_detect_fixes(tmp_path: Path):
    # registry transaction logs share the regf magic but carry file type 1 at 0x1C
    hive = bytearray(b"regf" + b"\x00" * 60)
    (tmp_path / "SOFTWARE").write_bytes(bytes(hive))
    assert detect(tmp_path / "SOFTWARE").kind == "registry_hive"
    for ftype in (1, 6):  # legacy and Windows 8.1+ transaction log formats
        hive[0x1C] = ftype
        (tmp_path / "SOFTWARE.LOG1").write_bytes(bytes(hive))
        assert detect(tmp_path / "SOFTWARE.LOG1").kind == "registry_log"
    # .bin is no longer a memory image; generic memory extensions need a plausible size
    blob = b"\x80\xff\x00\x13\xfe" * 300
    (tmp_path / "ReactNativeBundle.bin").write_bytes(blob)
    assert detect(tmp_path / "ReactNativeBundle.bin").kind == "binary"
    (tmp_path / "small.raw").write_bytes(blob)
    assert detect(tmp_path / "small.raw").kind == "binary"
    big = tmp_path / "big.raw"
    with big.open("wb") as fh:
        fh.write(blob)
        fh.seek(64 * 1024 * 1024)
        fh.write(b"\x00")
    assert detect(big).kind == "memory_image"
    (tmp_path / "ws.vmem").write_bytes(blob)
    assert detect(tmp_path / "ws.vmem").kind == "memory_image"


def test_progress_messages(tmp_path: Path, caplog):
    import logging

    (tmp_path / "auth.log").write_text(SYSLOG)
    (tmp_path / "Fonts").mkdir()
    (tmp_path / "Fonts" / "x.fon").write_bytes(b"MZ" + b"\x00" * 64)
    with caplog.at_level(logging.DEBUG, logger="dfa.progress"):
        list(IngestionAgent(case_id="t").events([tmp_path]))
    msgs = [r.getMessage() for r in caplog.records if r.name == "dfa.progress"]
    assert msgs[0].startswith("ingest: 2 files under")
    assert any(m.startswith("[2/2] auth.log: syslog") for m in msgs), msgs
    assert any(m.startswith("    -> 1 events in") for m in msgs), msgs
    assert any("x.fon: skipped (triage: noise directory 'Fonts')" in m and r.levelno == logging.DEBUG
               for m, r in zip(msgs, [r for r in caplog.records if r.name == "dfa.progress"], strict=True)), msgs
    assert msgs[-1].startswith("ingest: parsed 1 events from 1 files")
