"""End-to-end test for the bridge's MCP HTTP surface.

Exercises ``build_mcp_app`` over Starlette's ``TestClient``: an
unauthenticated request is rejected; an authorised bearer-token
request authenticates and reaches the MCP session handler. The
streamable-HTTP MCP protocol itself has a multi-step handshake we
do NOT replay here (that lives in the mcp SDK's own tests); the
purpose of this file is to verify the bridge's *plumbing* —
authentication, route mount, app construction — works end-to-end.

The HITL-via-elicitation flow on the MCP side is covered by
``test_mcp_hitl_roundtrip.py``, which exercises the building blocks
(translation + consent + Vault + RS) end-to-end without depending
on the MCP SDK's elicitation primitive.

Requires `pip install -e '.[mcp]'`.
"""
import pytest

pytest.importorskip("starlette")
pytest.importorskip("mcp")

from starlette.testclient import TestClient  # noqa: E402

from bridge.audit import AuditSink  # noqa: E402
from bridge.auth.hmac import TokenStore  # noqa: E402
from bridge.core.client import InMemoryTaskStore  # noqa: E402
from bridge.core.dispatcher import Dispatcher  # noqa: E402
from bridge.mcp.invoker import InProcessInvoker  # noqa: E402
from bridge.mcp.server import build_mcp_app  # noqa: E402
from bridge.vault import InProcessVault  # noqa: E402

# Ensure command registration before invoker dispatches.
import bridge.commands  # noqa: F401, E402


SECRET = "mcp-server-test-secret-16b-min"


@pytest.fixture
def mcp_world(tmp_path):
    audit = AuditSink(str(tmp_path / "audit.db"))
    token_store = TokenStore(str(tmp_path / "tokens.json"))
    token = token_store.issue(["tasks.read"], label="test-client", secret=SECRET)

    store = InMemoryTaskStore()
    store.create(title="A")
    store.create(title="B")
    vault = InProcessVault(secret=SECRET)
    dispatcher = Dispatcher(client=store, vault=vault)
    invoker = InProcessInvoker(dispatcher)

    app = build_mcp_app(
        invoker=invoker, audit=audit, token_store=token_store, secret=SECRET,
    )
    return app, token


def test_mcp_mount_rejects_unauthenticated_requests(mcp_world):
    app, _ = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post("/mcp")  # no Authorization header
    assert resp.status_code == 401
    body = resp.json()
    assert "unauthorized" in body["error"]["message"]


def test_mcp_mount_rejects_bogus_bearer_token(mcp_world):
    app, _ = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
    assert resp.status_code == 401


def test_mcp_mount_accepts_authenticated_request_and_reaches_session_manager(mcp_world):
    """A valid bearer token gets past the bridge auth wrapper. The MCP
    SDK's session manager then handles the request (and may reject it
    for protocol-level reasons unrelated to our auth — we only assert
    that the auth gate passed, i.e. status != 401)."""
    app, token = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "mcp-session-id": "test-session",
            },
            json={"jsonrpc": "2.0", "method": "initialize", "id": 1,
                  "params": {"protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "clientInfo": {"name": "test", "version": "0"}}},
        )
    # 401 = bridge auth rejected us; anything else means we made it through
    # the auth wrapper into the MCP session manager.
    assert resp.status_code != 401


def test_mcp_mount_has_correct_route(mcp_world):
    """Defensive: the mount is at /mcp, not the root or some other path."""
    app, _ = mcp_world
    routes = app.routes()
    assert len(routes) == 1
    assert "/mcp" in str(routes[0])
