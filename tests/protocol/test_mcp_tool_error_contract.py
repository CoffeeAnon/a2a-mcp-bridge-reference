"""A failed tool is a RESULT; a malformed request is an ERROR.

MCP separates the two on purpose. A tool that ran and failed returns a
``CallToolResult`` with ``isError=true``, so the caller's model receives the
failure text as tool output and can act on it. A request naming a tool that was
never offered is a protocol fault: the call never happened, so it belongs in the
JSON-RPC ``error`` member where the client's transport surfaces it.

This file pins both shapes over the REAL transport -- the Starlette app and the
streamable-HTTP session manager the deployment serves -- rather than the SDK's
in-memory client/server harness. That distinction is load-bearing. The in-memory
harness negotiates the legacy handshake era, whose catch-all passes an
exception's message through with ``code=0``; the modern 2026-07-28 envelope
routes handler exceptions through ``runner.modern_error_data()``, which replaces
any non-``MCPError`` with a bare "Internal server error" and drops the message
entirely. A test that only drove the in-memory harness would stay green while
every tool failure reached production as a contentless internal error.

Regression guarded: under mcp 1.x the ``@server.call_tool()`` decorator caught
handler exceptions and converted them to ``isError`` results. mcp 2.0's
``add_request_handler`` has no such safety net, so the handler must return the
failure rather than raise it.
"""
import json

import pytest

pytest.importorskip("starlette")
pytest.importorskip("mcp")

from mcp import types as mcp_types  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

import bridge.commands  # noqa: F401, E402
from bridge.audit import AuditSink  # noqa: E402
from bridge.auth.hmac import TokenStore  # noqa: E402
from bridge.core.client import InMemoryTaskStore  # noqa: E402
from bridge.core.dispatcher import Dispatcher  # noqa: E402
from bridge.mcp.invoker import InProcessInvoker  # noqa: E402
from bridge.mcp.server import build_mcp_app  # noqa: E402
from bridge.vault import InProcessVault  # noqa: E402

SECRET = "mcp-tool-error-contract-secret-32bytes"


@pytest.fixture
def client_and_headers(tmp_path):
    token_store = TokenStore(str(tmp_path / "tokens.json"))
    token = token_store.issue(["tasks.read"], label="contract-test", secret=SECRET)
    store = InMemoryTaskStore()
    store.create(title="A task that exists")
    vault = InProcessVault(secret=SECRET)
    app = build_mcp_app(
        invoker=InProcessInvoker(Dispatcher(client=store, vault=vault)),
        audit=AuditSink(str(tmp_path / "audit.db")),
        token_store=token_store,
        secret=SECRET,
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    with TestClient(app.starlette) as client:
        _rpc(client, headers, "initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "contract-test", "version": "1"},
        }, 1)
        yield client, headers


def _rpc(client, headers, method, params, rid):
    response = client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params},
    )
    body = response.text
    # The streamable-HTTP transport may frame the reply as SSE.
    for line in body.splitlines():
        if line.startswith("data: "):
            body = line[len("data: "):]
    return json.loads(body)


def _call_tool(client, headers, name, arguments, rid):
    return _rpc(client, headers, "tools/call", {"name": name, "arguments": arguments}, rid)


def test_failed_tool_returns_an_is_error_result_carrying_the_message(client_and_headers):
    client, headers = client_and_headers
    payload = _call_tool(client, headers, "get_task", {"task_id": "no-such-task"}, 2)

    assert "error" not in payload, (
        "a tool that ran and failed must not surface as a JSON-RPC error -- "
        "the model cannot see or act on a transport fault"
    )
    result = payload["result"]
    assert result["isError"] is True
    text = " ".join(part["text"] for part in result["content"])
    assert "no-such-task" in text, "the tool's own failure text must reach the caller"


def test_successful_tool_is_not_flagged_as_an_error(client_and_headers):
    """Guard the guard: if isError were hardcoded True the test above would pass
    while every successful call was reported as a failure."""
    client, headers = client_and_headers
    payload = _call_tool(client, headers, "list_tasks", {}, 3)

    assert "error" not in payload
    result = payload["result"]
    assert result.get("isError") in (False, None)
    text = " ".join(part["text"] for part in result["content"])
    assert "A task that exists" in text


def test_unknown_tool_is_a_protocol_error_with_a_real_code(client_and_headers):
    client, headers = client_and_headers
    payload = _call_tool(client, headers, "no_such_tool_at_all", {}, 4)

    assert "result" not in payload, (
        "a tool that was never offered did not run, so there is no tool result "
        "to report -- this belongs in the JSON-RPC error member"
    )
    error = payload["error"]
    assert error["code"] == mcp_types.INVALID_PARAMS
    assert "no_such_tool_at_all" in error["message"], (
        "the message must name the tool; a bare 'Internal server error' is what "
        "the modern envelope produces for any non-MCPError, and tells nobody anything"
    )
