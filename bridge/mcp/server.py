"""MCP server: build_mcp_app() returns a mountable Starlette sub-app.

Uses mcp.server.lowlevel.Server with explicit Tool definitions so each
ToolSpec's JSON Schema travels through verbatim — no signature inference.

SDK version: mcp 1.27.0
Import paths confirmed against that version:
  - mcp.server.lowlevel.Server
  - mcp.server.streamable_http_manager.StreamableHTTPSessionManager
  - mcp.types (Tool, etc.)
"""
from __future__ import annotations

import contextlib
import logging
from contextvars import ContextVar
from dataclasses import dataclass
from typing import AsyncIterator

from mcp import types as mcp_types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount

from bridge.agent.audit import AuditRow, AuditSink
from bridge.agent.invoker import ToolInvoker
from bridge.auth.hmac import CallerIdentity, TokenStore
from bridge.mcp.auth import AuthError, verify_bearer
from bridge.mcp.tools import mcp_tool_specs

logger = logging.getLogger(__name__)


# ContextVar used by the tool-call handler to attribute calls to the right caller.
_CURRENT_CALLER: ContextVar[CallerIdentity | None] = ContextVar("mcp_current_caller", default=None)


class _ToolCallError(Exception):
    """Raised by the tool handler when the underlying tool reports ok=False.

    The MCP SDK's lowlevel Server converts exceptions inside @call_tool() into
    tool results with isError=true.
    """


@dataclass
class McpApp:
    """Adapter holding the lowlevel Server + the Starlette mount."""
    starlette: Starlette

    def starlette_app(self) -> Starlette:
        return self.starlette

    def routes(self) -> list:
        return list(self.starlette.routes)


def build_mcp_app(
    *,
    invoker: ToolInvoker,
    audit: AuditSink,
    token_store: TokenStore,
    secret: str,
) -> McpApp:
    """Construct a Starlette app exposing /mcp with bearer auth.

    The session manager is started/stopped via Starlette's lifespan mechanism.
    Wrap TestClient usage in a `with` block to trigger the lifespan:
        with TestClient(app.starlette_app()) as client: ...
    """
    server = Server("task-tracker-mcp", version="0.1.0")

    @server.list_tools()
    async def _list_tools() -> list[mcp_types.Tool]:
        return [
            mcp_types.Tool(
                name=spec.name,
                description=spec.description,
                inputSchema=spec.parameters,
            )
            for spec in mcp_tool_specs()
        ]

    specs_by_name = {s.name: s for s in mcp_tool_specs()}

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> list[mcp_types.TextContent]:
        spec = specs_by_name.get(name)
        if spec is None:
            raise ValueError(f"Unknown tool: {name}")

        caller = _CURRENT_CALLER.get()
        actor = f"mcp:{caller.display_name}" if caller else "mcp:unknown"
        thread_id = f"mcp:{caller.caller_id}" if caller else "mcp:anon"

        result = invoker.invoke(spec, arguments)
        full_content = result.content or ""
        snippet = full_content[:500]

        audit.write(AuditRow(
            thread_id=thread_id,
            tenant_id="mcp",
            kind="tool_call",
            tool_name=name,
            tool_args=str(arguments)[:500],
            result_snippet=snippet,
            actor=actor,
        ))

        if not result.ok:
            raise _ToolCallError(full_content)

        return [mcp_types.TextContent(type="text", text=full_content)]

    session_manager = StreamableHTTPSessionManager(app=server, json_response=True, stateless=True)

    async def _handle_mcp(scope, receive, send):
        """ASGI callable: bearer-auth wrapper around the MCP session manager."""
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth_header = headers.get("authorization", "")
        try:
            caller = verify_bearer(auth_header, token_store, secret)
        except AuthError as e:
            logger.warning("mcp_auth_reject reason=%s remote=%s", e.reason, scope.get("client"))
            response = JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32001, "message": f"unauthorized: {e.reason}"}, "id": None},
                status_code=401,
            )
            await response(scope, receive, send)
            return
        token = _CURRENT_CALLER.set(caller)
        try:
            await session_manager.handle_request(scope, receive, send)
        finally:
            _CURRENT_CALLER.reset(token)

    @contextlib.asynccontextmanager
    async def _lifespan(app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    starlette = Starlette(
        routes=[Mount("/mcp", app=_handle_mcp)],
        lifespan=_lifespan,
    )
    return McpApp(starlette=starlette)
