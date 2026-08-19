"""Server-side MCP URL-mode elicitation emission + resume.

Drives the actual ``build_mcp_app`` MCP server over the SDK's in-memory
client/server harness (no HTTP handshake) and asserts the single-agent
HITL loop end to end:

  - a HITL-gated ``tools/call`` makes the server emit a URL-mode
    elicitation (``-32042`` / ``URL_ELICITATION_REQUIRED``) pointing at the
    independent consent surface, and
  - after the human approves at that surface, a retried ``tools/call``
    resumes: the bridge mints a Vault credential and executes, deleting the
    approved task and leaving the bystander untouched.

This is the single-agent path - no A2A. The A2A multi-agent carrier is a
separate composition; here the only hop is MCP-host -> consent surface ->
back.
"""
import pytest

pytest.importorskip("mcp")

import contextlib

import anyio  # noqa: E402
from mcp import types as mcp_types  # noqa: E402
from mcp.client.session import ClientSession  # noqa: E402
from mcp.shared.exceptions import MCPError as McpError  # noqa: E402
from mcp.shared.memory import create_client_server_memory_streams  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

import bridge.commands  # noqa: F401, E402  (register commands before dispatch)
from bridge.audit import AuditSink  # noqa: E402
from bridge.auth.hmac import TokenStore  # noqa: E402
from bridge.consent.url_mode import ConsentStore, build_consent_app  # noqa: E402
from bridge.core.client import InMemoryTaskStore  # noqa: E402
from bridge.core.dispatcher import Dispatcher  # noqa: E402
from bridge.mcp.invoker import InProcessInvoker  # noqa: E402
from bridge.mcp.server import build_mcp_app  # noqa: E402
from bridge.vault import InProcessVault  # noqa: E402

SECRET = "mcp-elicit-emission-secret-32bytes-pad"
RAR_TYPE = "tasktracker_task_action"
USER_SECRET = SECRET  # demo: consent server signs with the same secret the Vault verifies


@contextlib.asynccontextmanager
async def connected_client(server):
    async with create_client_server_memory_streams() as ((client_read, client_write), (server_read, server_write)):
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.run, server_read, server_write, server.create_initialization_options())
            async with ClientSession(client_read, client_write) as client:
                await client.initialize()
                try:
                    yield client
                finally:
                    tg.cancel_scope.cancel()


def _elicitation_id(elicitation: dict) -> str:
    """Read the elicitation's id, pinning the field name that crosses the wire.

    This used to be ``el.get("elicitationId") or el.get("elicitation_id")``,
    which accepted either spelling and so could not fail whichever the SDK
    emitted. Writing it down turned out to matter: mcp 2.0 names the *Python
    attribute* ``elicitation_id`` (the rename the migration had to make in
    ``bridge/mcp/hitl.py``) but serialises it under the camelCase alias
    ``elicitationId``. Those are two different contracts and the permissive
    ``or`` blurred them into one.
    """
    assert "elicitation_id" not in elicitation, (
        "the wire form is the camelCase alias elicitationId; snake_case "
        "appearing in the JSON means the SDK's serialisation alias changed"
    )
    return elicitation["elicitationId"]


def _world(tmp_path):
    audit = AuditSink(str(tmp_path / "audit.db"))
    token_store = TokenStore(str(tmp_path / "tokens.json"))
    store = InMemoryTaskStore()
    target = store.create(title="Q2 launch checklist")
    bystander = store.create(title="Q3 onboarding doc")
    vault = InProcessVault(secret=SECRET)
    dispatcher = Dispatcher(client=store, vault=vault)
    invoker = InProcessInvoker(dispatcher)
    consent_store = ConsentStore()
    app = build_mcp_app(
        invoker=invoker,
        audit=audit,
        token_store=token_store,
        secret=SECRET,
        consent_store=consent_store,
        vault=vault,
        rar_type=RAR_TYPE,
        bridge_base_url="https://bridge.example",
    )
    return {
        "app": app, "store": store, "consent_store": consent_store,
        "vault": vault, "target": target, "bystander": bystander,
    }


def test_hitl_tool_call_emits_url_mode_elicitation(tmp_path):
    w = _world(tmp_path)
    target_id = w["target"]["task_id"]

    async def run():
        async with connected_client(w["app"].server) as client:
            with pytest.raises(McpError) as exc:
                await client.call_tool("delete_task", {"task_id": target_id})
            err_code = exc.value.code
            err_data = exc.value.data
            assert err_code == mcp_types.URL_ELICITATION_REQUIRED
            elicitations = err_data["elicitations"]
            assert len(elicitations) == 1
            el = elicitations[0]
            assert el["mode"] == "url"
            sid = _elicitation_id(el)
            assert el["url"].endswith(f"/consent/{sid}")
            # The server created a pending consent session for that id.
            assert w["consent_store"].get(sid) is not None

    anyio.run(run)


def test_resume_after_approval_executes_the_approved_action(tmp_path):
    w = _world(tmp_path)
    target_id = w["target"]["task_id"]
    bystander_id = w["bystander"]["task_id"]
    # The human's consent surface, over the SAME store the server emits into.
    consent = TestClient(
        build_consent_app(store=w["consent_store"], user_signing_secret=USER_SECRET)
    )

    async def run():
        async with connected_client(w["app"].server) as client:
            # 1. First call → URL-mode elicitation; grab the consent session id.
            with pytest.raises(McpError) as exc:
                await client.call_tool("delete_task", {"task_id": target_id})
            el = exc.value.data["elicitations"][0]
            sid = _elicitation_id(el)

            # 2. Human visits the consent page and approves (demo signs server-side).
            assert consent.get(f"/consent/{sid}").status_code == 200
            assert consent.post(
                f"/consent/{sid}/submit", data={"decision": "approve"}
            ).status_code == 200

            # 3. Retry the same call → bridge resumes: mint + execute.
            result = await client.call_tool("delete_task", {"task_id": target_id})
            assert result.is_error is not True

            # 4. The approved action ran; the bystander was untouched.
            remaining = {t["task_id"] for t in w["store"].list()}
            assert target_id not in remaining
            assert bystander_id in remaining

    anyio.run(run)
