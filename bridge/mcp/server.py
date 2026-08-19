"""MCP server: build_mcp_app() returns a mountable Starlette sub-app.

Uses mcp.server.lowlevel.Server with explicit Tool definitions so each
ToolSpec's JSON Schema travels through verbatim without signature inference.

SDK version: mcp 2.0.0
Import paths confirmed against that version:
  - mcp.server.lowlevel.Server
  - mcp.server.streamable_http_manager.StreamableHTTPSessionManager
  - mcp.types (Tool, ListToolsResult, CallToolResult, etc.)
"""
from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator
from contextvars import ContextVar
from dataclasses import dataclass

from mcp import types as mcp_types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import UrlElicitationRequiredError
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount

from bridge.audit import AuditRow, AuditSink
from bridge.auth.hmac import CallerIdentity, TokenStore
from bridge.consent.url_mode import ConsentStore
from bridge.mcp.auth import AuthError, verify_bearer
from bridge.mcp.hitl import McpHitlGate
from bridge.mcp.invoker import ToolInvoker
from bridge.mcp.tools import mcp_tool_specs
from bridge.vault import Vault

logger = logging.getLogger(__name__)


# ContextVar used by the tool-call handler to attribute calls to the right caller.
_CURRENT_CALLER: ContextVar[CallerIdentity | None] = ContextVar("mcp_current_caller", default=None)


class _ToolCallError(Exception):
    """Raised by the tool handler when the underlying tool reports ok=False.

    The MCP SDK's lowlevel Server converts exceptions inside request handlers
    into tool results with is_error=true.
    """


def _binding_message(command: str, args: dict) -> str:
    """Human-readable summary of the proposed action, rendered on the consent
    page and bound into the signed canonical bytes. Demo-grade: production
    sources this from a per-tool renderer, not string interpolation."""
    arg_text = ", ".join(f"{k}={v}" for k, v in sorted(args.items()))
    return f"Approve action: {command} ({arg_text})" if arg_text else f"Approve action: {command}"


@dataclass
class McpApp:
    """Adapter holding the lowlevel Server + the Starlette mount."""
    starlette: Starlette
    server: Server

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
    consent_store: ConsentStore | None = None,
    vault: Vault | None = None,
    rar_type: str = "tasktracker_task_action",
    bridge_base_url: str = "https://bridge.invalid",
) -> McpApp:
    """Construct a Starlette app exposing /mcp with bearer auth.

    The session manager is started/stopped via Starlette's lifespan mechanism.
    Wrap TestClient usage in a `with` block to trigger the lifespan:
        with TestClient(app.starlette_app()) as client: ...

    HITL (single-agent path): when ``consent_store`` and ``vault`` are
    supplied, a HITL-gated ``tools/call`` emits a URL-mode elicitation
    pointing at the independent consent surface (``bridge.consent.url_mode``)
    and resumes on retry once the human has approved - no A2A. Omit them and
    the surface stays read-only (HITL-gated tools are not exposed),
    preserving the prior behaviour.
    """
    server = Server("task-tracker-mcp", version="0.1.0")

    gate = (
        McpHitlGate(
            consent_store=consent_store,
            bridge_base_url=bridge_base_url,
            rar_type=rar_type,
            vault=vault,
        )
        if consent_store is not None and vault is not None
        else None
    )

    async def _list_tools(ctx, req: mcp_types.PaginatedRequestParams) -> mcp_types.ListToolsResult:
        return mcp_types.ListToolsResult(
            tools=[
                mcp_types.Tool(
                    name=spec.name,
                    description=spec.description,
                    inputSchema=spec.parameters,
                )
                for spec in mcp_tool_specs(include_hitl=gate is not None)
            ]
        )

    server.add_request_handler("tools/list", mcp_types.PaginatedRequestParams, _list_tools)

    specs_by_name = {s.name: s for s in mcp_tool_specs(include_hitl=gate is not None)}

    async def _call_tool(ctx, req: mcp_types.CallToolRequestParams) -> mcp_types.CallToolResult:
        name = req.name
        arguments = req.arguments or {}
        spec = specs_by_name.get(name)
        if spec is None:
            raise ValueError(f"Unknown tool: {name}")

        caller = _CURRENT_CALLER.get()
        actor = f"mcp:{caller.display_name}" if caller else "mcp:unknown"
        thread_id = f"mcp:{caller.caller_id}" if caller else "mcp:anon"
        caller_id = caller.caller_id if caller else "mcp:anon"

        result = invoker.invoke(spec, arguments, caller=caller)

        # HITL via URL-mode elicitation (single-agent path). On an
        # approval-required outcome: if the human has already approved this
        # exact action at the consent surface, resume by minting the
        # credential and re-dispatching with it; otherwise emit a URL-mode
        # elicitation and let the client complete it out-of-band, then retry.
        if result.approval_required and gate is not None:
            payload = result.approval_payload or {}
            cmd, cmd_args = payload.get("command"), payload.get("args", {})
            token = gate.try_resume(command=cmd, args=cmd_args, caller_id=caller_id)
            if token is not None:
                result = invoker.invoke(spec, arguments, approval_token=token, caller=caller)
            else:
                binding = _binding_message(cmd, cmd_args)
                elicit = gate.begin(
                    command=cmd, args=cmd_args, caller_id=caller_id, binding_message=binding,
                )
                raise UrlElicitationRequiredError([elicit], message=binding)

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

        return mcp_types.CallToolResult(content=[mcp_types.TextContent(type="text", text=full_content)])

    server.add_request_handler("tools/call", mcp_types.CallToolRequestParams, _call_tool)

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
    return McpApp(starlette=starlette, server=server)
