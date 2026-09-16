"""FastAPI surface: /chat, /ingest, /cases. Start with ``dfa serve``."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from dfa.api.auth import User, check_case, current_user, list_users, require

log = logging.getLogger(__name__)
app = FastAPI(title="digital-forensic-assistant", version="0.1.0")


class ChatRequest(BaseModel):
    case_id: str
    message: str
    route: str = "auto"
    history: list[dict[str, str]] = Field(default_factory=list)
    rewrite: bool = True


class IngestRequest(BaseModel):
    case_id: str
    paths: list[str]
    host: str | None = None
    year: int | None = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/whoami")
def whoami(user: User = Depends(current_user)) -> dict[str, Any]:
    return {"user": user.name, "role": user.role, "cases": user.cases}


@app.get("/users")
def users(user: User = Depends(require("admin"))) -> list[dict[str, Any]]:
    return list_users()


@app.get("/cases")
def cases(user: User = Depends(current_user)) -> list[dict[str, Any]]:
    from dfa.retrieval.store import get_store

    store = get_store()
    return [{"case_id": c.removeprefix("case_"), "chunks": store.count(c)} for c in store.list_collections()
            if c.startswith("case_") and user.can_access(c.removeprefix("case_"))]


@app.get("/cases/{case_id}/stats")
def case_stats(case_id: str, user: User = Depends(current_user)) -> dict[str, Any]:
    from dfa.timeline.store import get_timeline

    check_case(user, case_id)
    st = get_timeline(case_id).stats()
    st["time_min"] = st["time_min"].isoformat() if st["time_min"] else None
    st["time_max"] = st["time_max"].isoformat() if st["time_max"] else None
    return st


@app.post("/ingest")
def ingest(req: IngestRequest, user: User = Depends(require("analyst"))) -> dict[str, Any]:
    check_case(user, req.case_id)
    paths = [Path(p) for p in req.paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise HTTPException(400, f"not found: {missing}")
    from dfa.ingestion.agent import IngestionAgent
    from dfa.ingestion.pipeline import index_events

    agent = IngestionAgent(req.case_id, host_hint=req.host, year_hint=req.year)
    stats = index_events(req.case_id, agent.events(paths))
    return {**stats, "files": [{"path": f.path, "kind": f.detection.kind, "status": f.status, "events": f.events, "error": f.error} for f in agent.report.files]}


@app.post("/chat")
def chat(req: ChatRequest, user: User = Depends(current_user)) -> dict[str, Any]:
    from dfa.generation.answer import ask

    check_case(user, req.case_id)
    try:
        a = ask(req.case_id, req.message, route=req.route, history=req.history, use_rewriter=req.rewrite, interface="api", user=user.name)
        return {**a.to_dict(), "navigator_layer": a.navigator_layer(req.case_id) if a.attack_techniques else None}
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
