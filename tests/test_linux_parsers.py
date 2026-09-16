from pathlib import Path

from dfa.ingestion.parsers.base import ParseContext, load_all, parser_for


def test_syslog_rules(tmp_path: Path):
    load_all()
    f = tmp_path / "auth.log"
    f.write_text(
        "Apr 20 04:31:11 app-1 sshd[9021]: Accepted password for root from 190.166.87.164 port 41113 ssh2\n"
        "Apr 20 04:32:00 app-1 sudo:     user3 : TTY=tty1 ; PWD=/home/user3 ; USER=root ; COMMAND=/bin/su\n"
        "Apr 20 04:33:00 app-1 useradd[1]: new user: name=wind3str0y, UID=1001, GID=1001, home=/home/wind3str0y, shell=/bin/bash\n"
        "Dec 31 23:59:59 app-1 cron[2]: (root) CMD (run-parts /etc/cron.hourly)\n"
        "Jan 01 00:00:01 app-1 cron[2]: (root) CMD (run-parts /etc/cron.hourly)\n"
    )
    evs = list(parser_for("syslog").parse(f, ParseContext("c1", year_hint=2010)))
    assert [e.action for e in evs] == ["ssh_login_success", "sudo_command", "user_created", "cron_command", "cron_command"]
    assert evs[0].user == "root" and "190.166.87.164" in evs[0].ioc.ip and evs[0].host == "app-1"
    assert evs[0].ts_iso == "2010-04-20T04:31:11Z"
    assert evs[2].user == "wind3str0y"
    assert evs[4].ts_iso.startswith("2011-01-01")  # year rollover


def test_apache_and_dpkg(tmp_path: Path):
    load_all()
    a = tmp_path / "access.log"
    a.write_text('10.0.1.2 - - [19/Apr/2010:06:36:15 -0700] "GET /wp-admin/../../etc/passwd HTTP/1.1" 403 16605 "-" "curl/7.1"\n')
    evs = list(parser_for("apache_access").parse(a, ParseContext("c1")))
    assert evs[0].ts_iso == "2010-04-19T13:36:15Z"
    assert "suspicious_request" in evs[0].extra["flags"] and "access_denied" in evs[0].extra["flags"]
    a.write_text('193.109.122.56 - - [20/Apr/2010:00:00:01 -0700] "CONNECT 72.51.18.254:6677 HTTP/1.0" 301 - "-" "pxyscand/2.1"\n'
                 '123.4.59.174 - - [19/Apr/2010:08:26:30 -0700] "GET http://proxyjudge1.proxyfire.net/fastenv HTTP/1.1" 404 1466 "-" "Mozilla/4.0"\n')
    evs = list(parser_for("apache_access").parse(a, ParseContext("c1")))
    assert evs[0].action == "http_connect" and evs[0].extra["flags"] == ["proxy_scan"] and "[proxy_scan]" in evs[0].summary
    assert evs[1].extra["flags"] == ["open_proxy_probe"] and evs[1].extra["ua"] == "Mozilla/4.0"
    e = tmp_path / "error.log"
    e.write_text("[Tue Apr 20 00:00:35 2010] [error] [client 193.109.122.33] request failed: error reading the headers\n")
    evs = list(parser_for("apache_error").parse(e, ParseContext("c1")))
    assert evs[0].ts_iso == "2010-04-20T00:00:35Z" and "193.109.122.33" in evs[0].ioc.ip
    d = tmp_path / "dpkg.log"
    d.write_text("2010-04-19 12:00:30 install python-tz <none> 2007k-0ubuntu2\n2010-04-19 12:00:31 status installed python-tz 2007k-0ubuntu2\n")
    evs = list(parser_for("dpkg").parse(d, ParseContext("c1")))
    assert evs[0].action == "pkg_install" and evs[1].action == "pkg_status_installed"


def _synthetic_varlog(root: Path) -> int:
    """Write a small Linux /var/log tree and return the number of events the parsers should produce."""
    ips = ["190.166.87.164", "10.0.1.2", "203.0.113.10", "198.51.100.7"]
    auth = [f"Apr {1 + i % 28:2d} {i % 24:02d}:{i % 60:02d}:{(i * 7) % 60:02d} app-1 sshd[{9000 + i}]: "
            + (f"Failed password for invalid user test{i} from {ips[i % 4]} port {40000 + i} ssh2" if i % 3 else
               f"Accepted password for root from {ips[i % 4]} port {40000 + i} ssh2")
            for i in range(300)]
    auth.append("Apr 20 04:33:00 app-1 useradd[1]: new user: name=wind3str0y, UID=1001, GID=1001, home=/home/wind3str0y, shell=/bin/bash")
    syslog = [f"Apr {1 + i % 28:2d} {i % 24:02d}:00:00 app-1 cron[2]: (root) CMD (run-parts /etc/cron.hourly)" for i in range(200)]
    dpkg = [f"2010-04-19 12:{i:02d}:30 install pkg{i} <none> 1.0-{i}" for i in range(50)]
    access = [f'{ips[i % 4]} - - [19/Apr/2010:06:{i % 60:02d}:15 -0700] "GET /page{i} HTTP/1.1" 200 {1000 + i} "-" "curl/7.1"' for i in range(100)]
    dmesg = [f"[  {i:3d}.000000] usb 1-{i}: new device" for i in range(30)]
    files = {"auth.log": auth, "syslog": syslog, "dpkg.log": dpkg, "apache2/access.log": access, "dmesg": dmesg}
    for rel, lines in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("\n".join(lines) + "\n")
    # a large timestamp-less monitor dump (udevmonitor output) is data, not a log: the triage filter skips it
    (root / "udev").write_text("".join(f"UDEV  add      /devices/pci0000:00/0000:00:1d.{i % 8}/usb{i} (usb)\n" for i in range(1500)))
    (root / "secure").write_text("")  # empty, skipped
    return sum(len(v) for v in files.values())


def test_varlog_end_to_end_parse(tmp_path: Path):
    from dfa.ingestion.agent import IngestionAgent

    expected = _synthetic_varlog(tmp_path)
    agent = IngestionAgent("synthetic", year_hint=2010)
    evs = list(agent.events([tmp_path]))
    assert len(evs) == expected
    assert any(f.path.endswith("udev") and f.status == "skipped" and "no timestamps" in (f.error or "") for f in agent.report.files)
    assert any(f.path.endswith("secure") and f.status == "skipped" for f in agent.report.files)
    assert not agent.report.by_status("error"), [f.error for f in agent.report.by_status("error")]
    assert not agent.report.by_status("unsupported")
    actions = {e.action for e in evs}
    assert {"ssh_login_success", "user_created", "cron_command", "pkg_install"} <= actions and actions & {"ssh_login_failure", "ssh_invalid_user"}, actions
    assert sum(1 for e in evs if e.action == "ssh_login_success") == 100
    assert all(e.timestamp is not None for e in evs if e.source_file != "dmesg")
    assert {e.host for e in evs if e.source_file in ("auth.log", "syslog")} == {"app-1"}
