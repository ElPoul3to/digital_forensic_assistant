import gzip
import sqlite3
from pathlib import Path

from dfa.ingestion.detect import detect


def test_magic_bytes(tmp_path: Path):
    (tmp_path / "a.bin").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    assert detect(tmp_path / "a.bin").kind == "pcap"
    (tmp_path / "b").write_bytes(b"ElfFile\x00" + b"\x00" * 100)
    assert detect(tmp_path / "b").kind == "evtx"
    (tmp_path / "c.dat").write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    assert detect(tmp_path / "c.dat").kind == "pcapng"


def test_sqlite_and_gzip(tmp_path: Path):
    db = tmp_path / "history"  # no extension on purpose
    sqlite3.connect(db).execute("create table t(x)").connection.commit()
    assert detect(db).kind == "sqlite"
    gz = tmp_path / "auth.log.gz"
    with gzip.open(gz, "wb") as fh:
        fh.write(b"Mar 16 08:12:04 app-1 login[4659]: hello\n")
    d = detect(gz)
    assert d.kind == "gzip" and d.container == "gzip"


def test_text_formats(tmp_path: Path):
    (tmp_path / "x.log").write_text('{"a": 1}\n{"a": 2}\n')
    assert detect(tmp_path / "x.log").kind == "jsonl"
    (tmp_path / "y.txt").write_text("ts,host,msg\n1,a,b\n2,c,d\n3,e,f\n")
    assert detect(tmp_path / "y.txt").kind == "csv"
    (tmp_path / "z").write_text("just some prose\nwithout structure\n")
    assert detect(tmp_path / "z").kind == "text"


def test_linux_varlog_samples(tmp_path: Path):
    """A synthetic /var/log export: every file must be recognised from its content, never from its name."""
    files = {
        "auth.log": "Apr 20 04:31:11 app-1 sshd[9021]: Accepted password for root from 190.166.87.164 port 41113 ssh2\n" * 3,
        "messages": "Apr 20 04:31:12 app-1 kernel: [  120.000000] eth0: link up\n" * 3,
        "kern.log": "Apr 20 04:31:13 app-1 kernel: [  121.000000] usb 1-1: new device\n" * 3,
        "daemon.log": "Apr 20 04:31:14 app-1 cron[2]: (root) CMD (run-parts /etc/cron.hourly)\n" * 3,
        "dmesg": "[    0.000000] Linux version 2.6.32 (buildd@host)\n[    0.100000] Command line: root=/dev/sda1\n",
        "dpkg.log": "2010-04-19 12:00:30 install python-tz <none> 2007k-0ubuntu2\n2010-04-19 12:00:31 status installed python-tz 2007k-0ubuntu2\n",
        "apache2/www-access.log": '10.0.1.2 - - [19/Apr/2010:06:36:15 -0700] "GET /feed/ HTTP/1.1" 200 16605 "-" "curl/7.1"\n' * 3,
        "apache2/www-error.log": "[Tue Apr 20 00:00:35 2010] [error] [client 193.109.122.33] request failed: error reading the headers\n" * 2,
        "apt/term.log": "Log started: 2010-04-19  12:00:30\nSelecting previously deselected package python-tz.\nLog ended: 2010-04-19  12:00:31\n",
        "secure": "",
    }
    expect = {"auth.log": "syslog", "messages": "syslog", "kern.log": "syslog", "daemon.log": "syslog", "dmesg": "dmesg",
              "dpkg.log": "dpkg", "apache2/www-access.log": "apache_access", "apache2/www-error.log": "apache_error",
              "apt/term.log": "apt_term", "secure": "empty"}
    for rel, content in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
    for rel, kind in expect.items():
        assert detect(tmp_path / rel).kind == kind, rel
