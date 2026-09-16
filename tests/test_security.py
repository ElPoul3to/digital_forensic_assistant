"""Phase 8: API users and tokens, case-level encryption (timeline, payloads, audit log), bundle manifest."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import duckdb
import pytest
from fastapi.testclient import TestClient

from dfa.config import get_settings


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "data_dir", tmp_path / "data")
    monkeypatch.setattr(s.security, "api_auth", "auto")
    monkeypatch.setattr(s.security, "encrypt_new_cases", False)
    monkeypatch.setenv("DFA_MASTER_KEY", "test-master-passphrase")
    from dfa.security import crypto

    crypto.case_key.cache_clear()
    return tmp_path / "data"


def test_users_and_tokens(data_dir: Path):
    from dfa.api import auth

    tok = auth.add_user("alice", "analyst", ["case-a"])
    assert auth.users_path().exists() and tok not in auth.users_path().read_text()
    u = auth.verify_token(tok)
    assert u and u.name == "alice" and u.role == "analyst" and u.can_access("case-a") and not u.can_access("case-b")
    assert u.has_role("reader") and u.has_role("analyst") and not u.has_role("admin")
    assert auth.verify_token("wrong") is None
    with pytest.raises(ValueError):
        auth.add_user("alice", "reader")
    tok2 = auth.add_user("alice", "admin", rotate=True)
    assert auth.verify_token(tok) is None and auth.verify_token(tok2).role == "admin"
    with pytest.raises(ValueError):
        auth.add_user("bad name!", "reader")
    assert [x["name"] for x in auth.list_users()] == ["alice"] and "token_sha256" not in auth.list_users()[0]
    assert auth.remove_user("alice") and not auth.remove_user("alice")


def test_api_auth_modes(data_dir: Path, monkeypatch):
    from dfa.api import auth
    from dfa.api.app import app

    c = TestClient(app)  # client host "testclient" counts as local
    assert c.get("/health").status_code == 200
    assert c.get("/whoami").json() == {"user": "local", "role": "admin", "cases": ["*"]}  # auto mode, no users yet
    reader = auth.add_user("bob", "reader", ["case-a"])
    admin = auth.add_user("root", "admin")
    assert c.get("/whoami").status_code == 401  # a user exists -> token required
    assert c.get("/whoami", headers={"Authorization": "Bearer nope"}).status_code == 401
    r = c.get("/whoami", headers={"Authorization": f"Bearer {reader}"})
    assert r.status_code == 200 and r.json()["role"] == "reader"
    assert c.get("/whoami", headers={"X-API-Key": reader}).status_code == 200
    assert c.get("/users", headers={"Authorization": f"Bearer {reader}"}).status_code == 403
    assert {u["name"] for u in c.get("/users", headers={"Authorization": f"Bearer {admin}"}).json()} == {"bob", "root"}
    assert c.post("/ingest", json={"case_id": "case-a", "paths": ["/x"]}, headers={"Authorization": f"Bearer {reader}"}).status_code == 403
    assert c.get("/cases/case-b/stats", headers={"Authorization": f"Bearer {reader}"}).status_code == 403
    assert c.post("/chat", json={"case_id": "case-b", "message": "hi"}, headers={"Authorization": f"Bearer {reader}"}).status_code == 403
    monkeypatch.setattr(get_settings().security, "api_auth", "off")
    assert c.get("/whoami").json()["user"] == "anonymous"
    monkeypatch.setattr(get_settings().security, "api_auth", "required")
    auth.remove_user("bob")
    auth.remove_user("root")
    assert c.get("/whoami").status_code == 401


def test_crypto_roundtrip(data_dir: Path):
    from dfa.security import crypto

    assert not crypto.is_encrypted("c1") and crypto.case_key("c1") is None
    p = crypto.create_case_key("c1")
    assert p.exists() and crypto.is_encrypted("c1") and (p.stat().st_mode & 0o777) == 0o600
    key = crypto.case_key("c1")
    assert key and len(key) == 32
    tok = crypto.encrypt_str(key, "Accepted password for root from 10.0.0.1")
    assert tok.startswith("enc:v1:") and "root" not in tok and crypto.decrypt_str(key, tok) == "Accepted password for root from 10.0.0.1"
    assert crypto.decrypt_str(key, "plain") == "plain"
    payload = {"text": "secret line", "raw": "raw line", "host": "srv"}
    enc = crypto.encrypt_payload("c1", payload)
    assert enc["encrypted"] is True and enc["host"] == "srv" and enc["text"] != "secret line"
    assert crypto.decrypt_payload("c1", enc)["text"] == "secret line" and crypto.decrypt_payload("c1", payload) == payload
    assert crypto.encrypt_payload("other", payload) == payload  # not encrypted case: untouched


def test_wrong_master_key(data_dir: Path, monkeypatch):
    from dfa.security import crypto

    crypto.create_case_key("c2")
    crypto.case_key.cache_clear()
    monkeypatch.setenv("DFA_MASTER_KEY", "another-passphrase")
    with pytest.raises(RuntimeError, match="wrong or missing master key"):
        crypto.case_key("c2")


def test_master_key_file_generated(data_dir: Path, monkeypatch, tmp_path: Path):
    from dfa.security import crypto

    monkeypatch.delenv("DFA_MASTER_KEY")
    monkeypatch.setattr(get_settings().security, "master_key_file", str(tmp_path / "keys" / "master.key"))
    crypto.create_case_key("c3")
    f = tmp_path / "keys" / "master.key"
    assert f.exists() and (f.stat().st_mode & 0o777) == 0o600 and crypto.case_key("c3")


def test_encrypted_timeline(data_dir: Path):
    from dfa.ingestion.schema import Event
    from dfa.security import crypto
    from dfa.timeline.store import Timeline

    crypto.create_case_key("enc-case")
    tl = Timeline("enc-case")
    assert tl.encrypted
    tl.insert([Event(case_id="enc-case", timestamp=datetime(2026, 9, 1, tzinfo=UTC), source_file="f", record_ref="line 1", summary="secret event", raw="raw")])
    assert tl.stats()["events"] == 1
    tl.close()
    path = get_settings().timeline_dir / "enc-case.duckdb"
    with pytest.raises(duckdb.Error):
        duckdb.connect(str(path)).execute("select count(*) from events")  # unreadable without the key
    assert b"secret event" not in path.read_bytes()
    tl2 = Timeline("enc-case")
    assert tl2.stats()["events"] == 1
    tl2.close()
    plain = Timeline("plain-case")
    assert not plain.encrypted
    plain.close()


def test_encrypted_audit(data_dir: Path):
    from dfa.generation import audit
    from dfa.security import crypto

    crypto.create_case_key("enc-case")
    ans = SimpleNamespace(question="who?", answer="root did it", route="evidence", route_reason="r", filters={}, queries=["who?"], timeline_query=None,
                          retrieved=[], citations=[], invalid_citations=[], attack_techniques=[])
    p = audit.record("enc-case", ans, interface="api", user="alice")
    assert p and p.read_text().startswith("enc:v1:") and "root did it" not in p.read_text()
    entries = audit.read("enc-case")
    assert len(entries) == 1 and entries[0]["answer"] == "root did it" and entries[0]["user"] == "alice" and entries[0]["interface"] == "api"


def test_migrate_timeline_and_audit(data_dir: Path, monkeypatch):
    from dfa.generation import audit
    from dfa.ingestion.schema import Event
    from dfa.security import crypto, migrate
    from dfa.timeline.store import Timeline

    tl = Timeline("mig")
    tl.insert([Event(case_id="mig", timestamp=datetime(2026, 9, 1, tzinfo=UTC), source_file="f", record_ref=f"line {i}", summary=f"ev {i}", raw="") for i in range(5)])
    tl.close()
    ans = SimpleNamespace(question="q", answer="a", route="evidence", route_reason="r", filters={}, queries=[], timeline_query=None, retrieved=[], citations=[],
                          invalid_citations=[], attack_techniques=[])
    audit.record("mig", ans)
    monkeypatch.setattr(migrate, "_encrypt_points", lambda case_id: 0)  # no vector store in this test
    res = migrate.encrypt_case("mig")
    assert res["timeline"] is True and res["audit"] == 1 and crypto.is_encrypted("mig")
    tl2 = Timeline("mig")
    assert tl2.encrypted and tl2.stats()["events"] == 5
    tl2.close()
    assert audit.read("mig")[0]["answer"] == "a"


def test_bundle_manifest_verify(tmp_path: Path):
    from dfa.bundle import _sha256, verify

    b = tmp_path / "bundle"
    b.mkdir()
    (b / "a.txt").write_text("hello")
    (b / "MANIFEST.json").write_text(json.dumps({"files": {"a.txt": {"sha256": _sha256(b / "a.txt"), "bytes": 5}}}))
    assert verify(b) == []
    (b / "a.txt").write_text("tampered")
    assert verify(b) == ["a.txt"]
