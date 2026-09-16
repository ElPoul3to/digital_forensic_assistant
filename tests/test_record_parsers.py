import json
from pathlib import Path

from dfa.ingestion.parsers.base import ParseContext, load_all, parser_for


def test_jsonl_ecs(tmp_path: Path):
    load_all()
    f = tmp_path / "sysmon.jsonl"
    rows = [
        {"@timestamp": "2026-09-01T13:47:02.000Z", "host": {"name": "WS042"}, "winlog": {"event_id": 1, "event_data": {"SubjectUserName": "svc_backup", "Image": "C:\\Windows\\System32\\wbem\\wmic.exe", "DestinationIp": "10.0.4.17"}}, "event": {"category": "process"}, "message": "Process Create"},
        {"@timestamp": "2026-09-01T13:48:02.000Z", "host": {"name": "WS042"}, "winlog": {"event_id": 3, "event_data": {"SubjectUserName": "svc_backup", "Image": "C:\\Windows\\System32\\cmd.exe", "DestinationIp": "8.8.8.8"}}, "event": {"category": "network"}, "message": "Network connection"},
    ]
    f.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    evs = list(parser_for("jsonl").parse(f, ParseContext("c1")))
    assert len(evs) == 2
    e = evs[0]
    assert e.ts_iso == "2026-09-01T13:47:02Z" and e.host == "WS042" and e.user == "svc_backup"
    assert e.process.endswith("wmic.exe") and e.category.value == "process"
    assert e.extra["event_id"] == "1"
    assert evs[1].category.value == "network"


def test_json_array_epoch_ms(tmp_path: Path):
    load_all()
    f = tmp_path / "edr.json"
    f.write_text(json.dumps({"Records": [
        {"eventTime": 1756734422000, "hostname": "DC01", "username": "bob", "src_ip": "10.0.4.17", "action": "logon"},
        {"eventTime": 1756734482000, "hostname": "DC01", "username": "bob", "src_ip": "10.0.4.17", "action": "logoff"},
    ]}))
    evs = list(parser_for("json").parse(f, ParseContext("c1")))
    assert len(evs) == 2 and evs[0].ts_iso == "2025-09-01T13:47:02Z"
    assert evs[0].host == "DC01" and "10.0.4.17" in evs[0].ioc.ip and evs[0].action == "logon"


def test_csv_and_w3c(tmp_path: Path):
    load_all()
    c = tmp_path / "autoruns.csv"
    c.write_text("Time,Entry Location,Entry,Image Path,MD5\n"
                 "2026-09-01 13:00:00,HKLM\\Run,Updater,c:\\users\\bob\\appdata\\upd.exe,d41d8cd98f00b204e9800998ecf8427e\n"
                 "2026-09-01 13:01:00,HKLM\\Run,Java,c:\\java\\bin\\jusched.exe,d41d8cd98f00b204e9800998ecf8427f\n")
    evs = list(parser_for("csv").parse(c, ParseContext("c1", host_hint="WS042")))
    assert len(evs) == 2 and evs[0].ts_iso == "2026-09-01T13:00:00Z" and evs[0].host == "WS042"
    assert "d41d8cd98f00b204e9800998ecf8427e" in evs[0].ioc.hash
    w = tmp_path / "u_ex.log"
    w.write_text("#Software: Microsoft Internet Information Services 10.0\n#Fields: date time c-ip cs-method cs-uri-stem sc-status\n"
                 "2026-09-01 13:00:00 203.0.113.5 POST /upload.aspx 200\n")
    evs = list(parser_for("w3c").parse(w, ParseContext("c1")))
    assert evs[0].ts_iso == "2026-09-01T13:00:00Z" and "203.0.113.5" in evs[0].ioc.ip
