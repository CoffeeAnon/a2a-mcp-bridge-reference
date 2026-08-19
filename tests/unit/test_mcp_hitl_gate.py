"""McpHitlGate - the single-agent HITL emission/resume primitive.

The gate is what the MCP server's call-tool handler uses to turn a
dispatcher ``ApprovalRequired`` outcome into a URL-mode elicitation, and
to resume once the human has approved at the consent server. It is the
single-agent (no-A2A) analogue of the A2A↔MCP translation: same Vault
core, no second agent, just MCP elicitation + an independent consent
surface.

Tested with real components (ConsentStore, InProcessVault, the demo
signer) - no mocks.
"""
import pytest

pytest.importorskip("mcp")

from mcp import types as mcp_types  # noqa: E402

from bridge.consent.url_mode import ConsentStore  # noqa: E402
from bridge.consent.demo_signer import demo_sign_as_user  # noqa: E402
from bridge.mcp.hitl import McpHitlGate  # noqa: E402
from bridge.vault import InProcessVault  # noqa: E402


SECRET = "mcp-hitl-gate-secret-32bytes-minimum-x"
RAR_TYPE = "tasktracker_task_action"


def _gate(store=None, vault=None):
    return McpHitlGate(
        consent_store=store or ConsentStore(),
        bridge_base_url="https://bridge.example",
        rar_type=RAR_TYPE,
        vault=vault,
    )


def test_begin_creates_consent_session_and_returns_url_elicitation():
    store = ConsentStore()
    gate = _gate(store=store)

    params = gate.begin(
        command="delete-task",
        args={"task_id": "t-42"},
        caller_id="alice",
        binding_message="Delete task t-42?",
    )

    assert isinstance(params, mcp_types.ElicitRequestURLParams)
    assert params.mode == "url"
    assert params.url.endswith(f"/consent/{params.elicitation_id}")
    # A consent session exists for that id, carrying the exact action.
    req = store.get(params.elicitation_id)
    assert req is not None
    assert req.command == "delete-task"
    assert dict(req.args) == {"task_id": "t-42"}


def test_try_resume_returns_none_before_approval():
    store = ConsentStore()
    gate = _gate(store=store, vault=InProcessVault(secret=SECRET))
    gate.begin(
        command="delete-task",
        args={"task_id": "t-42"},
        caller_id="alice",
        binding_message="Delete task t-42?",
    )
    # Human has not approved at the consent surface yet.
    token = gate.try_resume(command="delete-task", args={"task_id": "t-42"}, caller_id="alice")
    assert token is None


def _approve(store, params, *, command, args, binding_message):
    """Simulate the human approving at the consent surface (demo signs
    server-side, exactly as the consent server's submit endpoint does)."""
    signed = demo_sign_as_user(
        command=command,
        args=args,
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message=binding_message,
        user_secret=SECRET,
    )
    assert store.submit_signed(params.elicitation_id, signed)


def test_try_resume_mints_credential_after_approval():
    store = ConsentStore()
    vault = InProcessVault(secret=SECRET)
    gate = _gate(store=store, vault=vault)
    params = gate.begin(
        command="delete-task",
        args={"task_id": "t-42"},
        caller_id="alice",
        binding_message="Delete task t-42?",
    )

    _approve(store, params, command="delete-task", args={"task_id": "t-42"},
             binding_message="Delete task t-42?")

    token = gate.try_resume(command="delete-task", args={"task_id": "t-42"}, caller_id="alice")
    assert token is not None
    # The minted credential validates at the same Vault for the approved action.
    consumed = vault.consume(token, "delete-task", {"task_id": "t-42"})
    assert consumed.command == "delete-task"


def test_try_resume_is_idempotent_after_mint():
    """A second resume of an already-minted approval returns the same token
    rather than re-minting (which the Vault's SignatureReplay would reject)."""
    store = ConsentStore()
    vault = InProcessVault(secret=SECRET)
    gate = _gate(store=store, vault=vault)
    params = gate.begin(
        command="delete-task",
        args={"task_id": "t-42"},
        caller_id="alice",
        binding_message="Delete task t-42?",
    )
    _approve(store, params, command="delete-task", args={"task_id": "t-42"},
             binding_message="Delete task t-42?")

    first = gate.try_resume(command="delete-task", args={"task_id": "t-42"}, caller_id="alice")
    second = gate.try_resume(command="delete-task", args={"task_id": "t-42"}, caller_id="alice")
    assert first is not None
    assert first == second
