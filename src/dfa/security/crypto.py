"""Case-level encryption at rest.

Each encrypted case has a random 256-bit key stored wrapped (AES-256-GCM) in
``data/keys/<case>.key``.  The wrapping key is derived with scrypt from a
master secret: the ``DFA_MASTER_KEY`` environment variable (a passphrase) or,
failing that, the file ``security.master_key_file`` (generated on first need,
mode 0600).  Move that file to removable media or a secrets manager on a
shared host; without it, encrypted cases cannot be opened.

What the case key protects:

- the DuckDB timeline (``ATTACH ... (ENCRYPTION_KEY ...)``, whole-file
  encryption by DuckDB itself),
- the ``text`` and ``raw`` payload fields of every vector-store point (the
  readable evidence), and
- the audit log lines.

Not covered: the dense and sparse vectors themselves (Qdrant has no payload
encryption and vectors must stay searchable) and the model caches.  Put
``data/qdrant`` on an encrypted volume (LUKS, gocryptfs) when that matters.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from functools import lru_cache
from pathlib import Path

from dfa.config import PROJECT_ROOT, get_settings

log = logging.getLogger(__name__)

PREFIX = "enc:v1:"
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024}


def keys_dir() -> Path:
    return get_settings().data_dir / "keys"


def key_path(case_id: str) -> Path:
    return keys_dir() / f"{case_id}.key"


def is_encrypted(case_id: str) -> bool:
    return key_path(case_id).exists()


def _master_secret(create: bool) -> bytes:
    env = os.environ.get("DFA_MASTER_KEY")
    if env:
        return env.encode("utf-8")
    s = get_settings()
    f = Path(s.security.master_key_file)
    f = f if f.is_absolute() else PROJECT_ROOT / f
    if f.exists():
        return f.read_bytes().strip()
    if not create:
        raise RuntimeError(f"no master key: set DFA_MASTER_KEY or restore {f}")
    f.parent.mkdir(parents=True, exist_ok=True)
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32))
    f.write_bytes(secret + b"\n")
    f.chmod(0o600)
    log.warning("generated master key %s - back it up; encrypted cases are unreadable without it", f)
    return secret


def _kek(salt: bytes, create: bool) -> bytes:
    return hashlib.scrypt(_master_secret(create), salt=salt, dklen=32, **_SCRYPT)


def _aesgcm(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key)


def create_case_key(case_id: str) -> Path:
    """Generate and wrap a new key for ``case_id`` (no-op when one exists)."""
    p = key_path(case_id)
    if p.exists():
        return p
    salt = secrets.token_bytes(16)
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    wrapped = _aesgcm(_kek(salt, create=True)).encrypt(nonce, key, case_id.encode())
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"v": 1, "case": case_id, "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
                             "wrapped": base64.b64encode(wrapped).decode()}))
    p.chmod(0o600)
    case_key.cache_clear()
    return p


@lru_cache(maxsize=64)
def case_key(case_id: str) -> bytes | None:
    """The unwrapped case key, or None when the case is not encrypted."""
    p = key_path(case_id)
    if not p.exists():
        return None
    d = json.loads(p.read_text())
    salt, nonce, wrapped = (base64.b64decode(d[k]) for k in ("salt", "nonce", "wrapped"))
    try:
        return _aesgcm(_kek(salt, create=False)).decrypt(nonce, wrapped, case_id.encode())
    except Exception as e:
        raise RuntimeError(f"cannot unwrap the key of case {case_id}: wrong or missing master key ({type(e).__name__})") from e


def ensure_case_key(case_id: str) -> bytes | None:
    """Create the key when ``encrypt_new_cases`` is on and the case has none yet."""
    if is_encrypted(case_id):
        return case_key(case_id)
    if get_settings().security.encrypt_new_cases:
        create_case_key(case_id)
        return case_key(case_id)
    return None


def duckdb_key(case_id: str) -> str | None:
    k = case_key(case_id)
    return k.hex() if k else None


def encrypt_str(key: bytes, text: str) -> str:
    nonce = secrets.token_bytes(12)
    ct = _aesgcm(key).encrypt(nonce, text.encode("utf-8"), None)
    return PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt_str(key: bytes, token: str) -> str:
    if not isinstance(token, str) or not token.startswith(PREFIX):
        return token
    raw = base64.b64decode(token[len(PREFIX):])
    return _aesgcm(key).decrypt(raw[:12], raw[12:], None).decode("utf-8")


def is_token(value) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def case_of_collection(name: str) -> str | None:
    return name.removeprefix("case_") if name.startswith("case_") else None


def encrypt_payload(case_id: str, payload: dict, fields=("text", "raw")) -> dict:
    key = case_key(case_id)
    if not key:
        return payload
    out = dict(payload)
    for f in fields:
        if isinstance(out.get(f), str) and not is_token(out[f]):
            out[f] = encrypt_str(key, out[f])
    out["encrypted"] = True
    return out


def decrypt_payload(case_id: str, payload: dict, fields=("text", "raw")) -> dict:
    if not payload or not payload.get("encrypted"):
        return payload
    key = case_key(case_id)
    if not key:
        raise RuntimeError(f"case {case_id} is encrypted but no key is available")
    out = dict(payload)
    for f in fields:
        if is_token(out.get(f)):
            out[f] = decrypt_str(key, out[f])
    return out
