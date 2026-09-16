"""Multi-user authentication for the REST API.

Users live in ``data/auth/users.json`` (git-ignored) with a role and the
cases they may see; only the SHA-256 of each API token is stored.  Tokens are
generated once by ``dfa user add`` and sent as ``Authorization: Bearer <token>``
or ``X-API-Key: <token>``.

Modes (``security.api_auth``):

- ``auto`` (default): tokens are required as soon as one user exists or the
  request does not come from the loopback interface; a fresh single-analyst
  install keeps working locally without any setup.
- ``required``: tokens always required.
- ``off``: everyone is an anonymous admin (only for isolated test setups).

Roles: ``reader`` (ask questions, browse cases), ``analyst`` (+ ingest),
``admin`` (+ manage users, delete cases).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, HTTPException, Request

from dfa.config import get_settings

ROLES = {"reader": 0, "analyst": 1, "admin": 2}


@dataclass
class User:
    name: str
    role: str = "reader"
    cases: list[str] = field(default_factory=lambda: ["*"])

    def has_role(self, role: str) -> bool:
        return ROLES.get(self.role, -1) >= ROLES[role]

    def can_access(self, case_id: str) -> bool:
        return "*" in self.cases or case_id in self.cases


def users_path() -> Path:
    return get_settings().data_dir / "auth" / "users.json"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_users() -> dict[str, dict[str, Any]]:
    p = users_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {u["name"]: u for u in data.get("users", []) if "name" in u}


def _save(users: dict[str, dict[str, Any]]) -> None:
    p = users_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"users": list(users.values())}, indent=1), encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(p)


def add_user(name: str, role: str = "reader", cases: list[str] | None = None, rotate: bool = False) -> str:
    """Create (or rotate the token of) a user and return the clear-text token, shown exactly once."""
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}; one of {', '.join(ROLES)}")
    if not name or not name.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise ValueError("user name must be alphanumeric (plus - _ .)")
    users = load_users()
    if name in users and not rotate:
        raise ValueError(f"user {name!r} exists (use --rotate to issue a new token)")
    token = secrets.token_urlsafe(32)
    rec = users.get(name, {"name": name, "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")})
    rec.update({"role": role, "cases": cases or ["*"], "token_sha256": _hash(token), "rotated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")})
    users[name] = rec
    _save(users)
    return token


def remove_user(name: str) -> bool:
    users = load_users()
    if name not in users:
        return False
    del users[name]
    _save(users)
    return True


def list_users() -> list[dict[str, Any]]:
    return [{k: v for k, v in u.items() if k != "token_sha256"} for u in load_users().values()]


def verify_token(token: str) -> User | None:
    h = _hash(token)
    for u in load_users().values():
        if hmac.compare_digest(u.get("token_sha256", ""), h):
            return User(name=u["name"], role=u.get("role", "reader"), cases=list(u.get("cases") or ["*"]))
    return None


def _is_loopback(request: Request) -> bool:
    host = request.client.host if request.client else ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "testclient")


def _token_from(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-api-key")


def current_user(request: Request) -> User:
    mode = get_settings().security.api_auth
    if mode == "off":
        return User("anonymous", "admin")
    users = load_users()
    token = _token_from(request)
    if token:
        u = verify_token(token)
        if u is None:
            raise HTTPException(401, "invalid token")
        return u
    if mode == "auto" and not users and _is_loopback(request):
        return User("local", "admin")
    if not users:
        raise HTTPException(401, "no API users configured: run `dfa user add <name> --role admin` and send the token as a Bearer header")
    raise HTTPException(401, "missing token (Authorization: Bearer <token>)")


def require(role: str):
    """FastAPI dependency: the caller must hold at least ``role``."""

    def dep(user: User = Depends(current_user)) -> User:
        if not user.has_role(role):
            raise HTTPException(403, f"role {role} required")
        return user

    return dep


def check_case(user: User, case_id: str) -> None:
    if not user.can_access(case_id):
        raise HTTPException(403, f"no access to case {case_id}")
