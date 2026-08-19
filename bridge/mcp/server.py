"""MCP server: build_mcp_app() returns a mountable Starlette sub-app.

Uses mcp.server.lowlevel.Server with explicit Tool definitions so each
ToolSpec's JSON Schema travels through verbatim without signature inference.

Requires mcp >= 2.0, enforced by the ``mcp`` extra in pyproject.toml rather
than asserted here: a version written in prose goes stale silently, whereas a
dependency floor fails the install.
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
from mcp.shared.exceptions import MCPError, UrlElicitationRequiredError
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


def _authenticated_mcp_asgi(session_manager, token_store: TokenStore, secret: str):
    """ASGI callable: bearer-auth gate in front of the MCP session manager.

    Authentication happens here rather than inside a tool handler because it is
    a property of the connection, not of any one call: an unauthenticated
    request must never reach the protocol layer at all. The verified identity
    travels to the handlers through ``_CURRENT_CALLER``, reset in a ``finally``
    so a caller can never leak into the next request on the same task.
    """
    async def handle(scope, receive, send):
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        try:
            caller = verify_bearer(headers.get("authorization", ""), token_store, secret)
        except AuthError as exc:
            logger.warning("mcp_auth_reject reason=%s remote=%s", exc.reason, scope.get("client"))
            response = JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32001, "message": f"unauthorized: {exc.reason}"},
                    "id": None,
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        token = _CURRENT_CALLER.set(caller)
        try:
            await session_manager.handle_request(scope, receive, send)
        finally:
            _CURRENT_CALLER.reset(token)

    return handle


def _caller_labels(caller: CallerIdentity | None) -> tuple[str, str, str]:
    """(actor, thread_id, caller_id) for an authenticated caller, or the
    anonymous placeholders. One place, so the three strings cannot drift
    apart into three different notions of "who is calling"."""
    if caller is None:
        return "mcp:unknown", "mcp:anon", "mcp:anon"
    return f"mcp:{caller.display_name}", f"mcp:{caller.caller_id}", caller.caller_id


def _resolve_hitl(result, gate, invoker, spec, arguments, caller):
    """Resume an approval-required call, or pause it by raising.

    Two outcomes and no third: either the human has already approved this exact
    action at the consent surface, in which case we mint the credential and
    re-dispatch, or they have not, in which case we raise
    ``UrlElicitationRequiredError`` pointing at the consent surface and the
    client retries after approving.

    The raise is the one place in this handler where raising is right. It is an
    ``MCPError`` subclass, so it survives the protocol's error mapping intact
    and carries the elicitation payload the client needs; a plain exception here
    would reach the client as "Internal server error" and the HITL loop would
    simply never complete.
    """
    _, _, caller_id = _caller_labels(caller)
    payload = result.approval_payload or {}
    command, args = payload.get("command"), payload.get("args", {})

    token = gate.try_resume(command=command, args=args, caller_id=caller_id)
    if token is not None:
        return invoker.invoke(spec, arguments, approval_token=token, caller=caller)

    binding = _binding_message(command, args)
    elicitation = gate.begin(
        command=command, args=args, caller_id=caller_id, binding_message=binding,
    )
    raise UrlElicitationRequiredError([elicitation], message=binding)


def _write_audit_row(audit: AuditSink, caller, tool_name: str, arguments: dict, result) -> None:
    """One audit row per tool call, success or failure alike."""
    actor, thread_id, _ = _caller_labels(caller)
    audit.write(AuditRow(
        thread_id=thread_id,
        tenant_id="mcp",
        kind="tool_call",
        tool_name=tool_name,
        tool_args=str(arguments)[:500],
        result_snippet=(result.content or "")[:500],
        actor=actor,
    ))


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
        """Run one tool call. Returns tool failures; raises protocol faults.

        That split is the contract, and it is not cosmetic. A tool that ran and
        failed is a *result* the model can act on. A malformed request is a
        transport-level fault with nothing for the model to do about it.

        Raising is easy to reach for because both read as "an error", and under
        mcp 1.x the ``@server.call_tool()`` decorator hid the difference by
        converting every handler exception into an is_error result. Registering
        handlers directly removes that safety net, and on the modern
        2026-07-28 envelope a raised non-``MCPError`` is replaced wholesale by
        "Internal server error", losing the message. Return failures. Raise only
        ``MCPError`` subclasses, which carry their own wire data.
        """
        arguments = req.arguments or {}
        spec = specs_by_name.get(req.name)
        if spec is None:
            raise MCPError(
                code=mcp_types.INVALID_PARAMS,
                message=f"Unknown tool: {req.name}",
            )

        caller = _CURRENT_CALLER.get()
        result = invoker.invoke(spec, arguments, caller=caller)
        if result.approval_required and gate is not None:
            result = _resolve_hitl(result, gate, invoker, spec, arguments, caller)

        _write_audit_row(audit, caller, req.name, arguments, result)

        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=result.content or "")],
            is_error=not result.ok,
        )

    server.add_request_handler("tools/call", mcp_types.CallToolRequestParams, _call_tool)

    session_manager = StreamableHTTPSessionManager(app=server, json_response=True, stateless=True)

    @contextlib.asynccontextmanager
    async def _lifespan(app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    starlette = Starlette(
        routes=[Mount("/mcp", app=_authenticated_mcp_asgi(session_manager, token_store, secret))],
        lifespan=_lifespan,
    )
    return McpApp(starlette=starlette, server=server)
