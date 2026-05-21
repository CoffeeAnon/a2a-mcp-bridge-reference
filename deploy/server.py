"""Starlette ASGI server for the A2A↔MCP bridge reference.

Mounts:
  - /health
  - A2A protocol routes (/.well-known/agent.json, /.well-known/agent-card.json, /)
  - MCP protocol routes (/mcp)

Run with: uvicorn deploy.server:app --host 0.0.0.0 --port 8080
Or directly: python deploy/server.py (uses uvicorn programmatically).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    force=True,
)
logging.getLogger("bridge.agent").setLevel(logging.INFO)

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

import bridge.commands  # noqa: F401 — triggers @command registration into REGISTRY
from bridge.a2a.agent_card import build_agent_card
from bridge.a2a.auth import TokenStore, default_token_file
from bridge.a2a.executor import AgentExecutorImpl
from bridge.a2a.server import build_a2a_app
from bridge.agent.audit import AuditSink
from bridge.agent.graph import build_graph, _default_llm
from bridge.agent.invoker import InProcessInvoker
from bridge.agent.persistence import build_async_checkpointer
from bridge.mcp.auth import default_mcp_token_file
from bridge.mcp.server import build_mcp_app


_SYSTEM_PROMPT = (
    "You are a task-tracker assistant. You can list, read, create, update, "
    "and delete tasks via the provided tools. Destructive actions (delete) "
    "require human approval — the approval is bound to the exact parameters "
    "you propose, so once a human approves a delete of task X you cannot then "
    "delete task Y without a fresh approval."
)


# ── Shared infrastructure (module-level, built once) ─────────────────────────

_PERSISTENCE_URL = os.environ.get("PERSISTENCE_URL", "sqlite:///./data/bridge_agent.db")
_saver = build_async_checkpointer(_PERSISTENCE_URL)
_audit = AuditSink(_PERSISTENCE_URL.removeprefix("sqlite:///"))
_invoker = InProcessInvoker()
_llm = _default_llm()
_graph = build_graph(checkpointer=_saver, llm=_llm, invoker=_invoker)

_A2A_SECRET = os.environ.get("BRIDGE_A2A_SECRET", "")
_APPROVAL_SECRET = os.environ.get("BRIDGE_APPROVAL_SECRET", "")
_MCP_SECRET = os.environ.get("BRIDGE_MCP_SECRET", _A2A_SECRET)
if not _A2A_SECRET:
    raise SystemExit("BRIDGE_A2A_SECRET must be set")
if not _APPROVAL_SECRET:
    raise SystemExit("BRIDGE_APPROVAL_SECRET must be set")

_a2a_token_store = TokenStore(default_token_file())
_mcp_token_store = TokenStore(default_mcp_token_file())


# ── A2A surface ──────────────────────────────────────────────────────────────

_base_url = os.environ.get("BRIDGE_BASE_URL", "http://localhost:8080")
_a2a_executor = AgentExecutorImpl(
    graph=_graph,
    audit=_audit,
    a2a_secret=_A2A_SECRET,
    a2a_token_store=_a2a_token_store,
    approval_secret=_APPROVAL_SECRET,
    system_prompt=_SYSTEM_PROMPT,
)
_a2a_app = build_a2a_app(
    agent_card=build_agent_card(_base_url),
    executor=_a2a_executor,
    token_store=_a2a_token_store,
    secret=_A2A_SECRET,
)

# ── MCP surface ──────────────────────────────────────────────────────────────

_mcp_app = build_mcp_app(
    invoker=_invoker,
    audit=_audit,
    token_store=_mcp_token_store,
    secret=_MCP_SECRET,
)


# ── /health ──────────────────────────────────────────────────────────────────

async def _health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


# ── Composed Starlette app ───────────────────────────────────────────────────

app = Starlette(
    routes=[
        Route("/health", _health),
        *_a2a_app.routes(),
        *_mcp_app.routes(),
    ],
    lifespan=_mcp_app.starlette.router.lifespan_context,
)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
