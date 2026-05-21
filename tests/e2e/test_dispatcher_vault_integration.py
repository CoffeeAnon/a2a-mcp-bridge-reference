"""End-to-end: dispatcher + Vault on both tiers.

These tests exercise the full path from "human signs an authorization-
details payload" through "Vault mints a credential" to "dispatcher
consumes the credential and executes the action." Both tiers are
tested through the same dispatcher API, demonstrating that swapping
Tier 1 for Tier 2 is purely a Vault implementation swap.
"""
import pytest

from bridge.core.client import InMemoryTaskStore
from bridge.core.dispatcher import (
    ApprovalRequired,
    CommandSuccess,
    Dispatcher,
)
from bridge.vault import (
    InProcessVault,
    OAuthVault,
    sign_authorization_details,
)


USER_SECRET = "user-secret"
MINT_SECRET = "mint-secret"
RAR_TYPE = "tasktracker_task_action"


def _signed(command, args, secret=USER_SECRET):
    return sign_authorization_details(
        command=command,
        args=args,
        rar_type=RAR_TYPE,
        approver_id="alice",
        secret=secret,
    )


@pytest.fixture
def seeded_client():
    client = InMemoryTaskStore()
    a = client.create(title="A — promised for deletion")
    b = client.create(title="B — must survive drift attempts")
    return client, a["task_id"], b["task_id"]


# ── Tier 1: InProcessVault ─────────────────────────────────────────────────


def test_tier1_full_flow_deletes_approved_task(seeded_client):
    client, promised_id, drift_id = seeded_client
    vault = InProcessVault(secret=USER_SECRET, expected_rar_type=RAR_TYPE)
    dispatcher = Dispatcher(client=client, vault=vault)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = vault.mint(signed)

    outcome = dispatcher.execute("delete-task", {"task_id": promised_id}, approval_token=minted.credential)
    assert isinstance(outcome, CommandSuccess)
    remaining = {t["task_id"] for t in client.list()}
    assert promised_id not in remaining
    assert drift_id in remaining


def test_tier1_drift_attempt_does_not_execute(seeded_client):
    client, promised_id, drift_id = seeded_client
    vault = InProcessVault(secret=USER_SECRET, expected_rar_type=RAR_TYPE)
    dispatcher = Dispatcher(client=client, vault=vault)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = vault.mint(signed)

    outcome = dispatcher.execute("delete-task", {"task_id": drift_id}, approval_token=minted.credential)
    assert isinstance(outcome, ApprovalRequired)
    assert outcome.reason == "CredentialDrift"
    # Both tasks survive.
    remaining = {t["task_id"] for t in client.list()}
    assert promised_id in remaining
    assert drift_id in remaining


def test_tier1_replay_attempt_does_not_execute(seeded_client):
    client, promised_id, _ = seeded_client
    vault = InProcessVault(secret=USER_SECRET, expected_rar_type=RAR_TYPE)
    dispatcher = Dispatcher(client=client, vault=vault)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = vault.mint(signed)

    # Create a second task with the same id-value to make the test deterministic.
    # First consumption succeeds:
    first = dispatcher.execute("delete-task", {"task_id": promised_id}, approval_token=minted.credential)
    assert isinstance(first, CommandSuccess)

    # Replay: re-create the task to give the second consume something to attempt,
    # then submit the same credential. Vault refuses.
    new_task = client.create(title="replay target")
    replay = dispatcher.execute("delete-task", {"task_id": new_task["task_id"]}, approval_token=minted.credential)
    assert isinstance(replay, ApprovalRequired)
    assert replay.reason in ("CredentialReplay", "CredentialDrift")


# ── Tier 2: OAuthVault ─────────────────────────────────────────────────────


def test_tier2_full_flow_deletes_approved_task(seeded_client):
    client, promised_id, drift_id = seeded_client
    vault = OAuthVault(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
    )
    dispatcher = Dispatcher(client=client, vault=vault)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = vault.mint(signed)

    outcome = dispatcher.execute("delete-task", {"task_id": promised_id}, approval_token=minted.credential)
    assert isinstance(outcome, CommandSuccess)


def test_tier2_drift_attempt_does_not_execute(seeded_client):
    client, promised_id, drift_id = seeded_client
    vault = OAuthVault(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
    )
    dispatcher = Dispatcher(client=client, vault=vault)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = vault.mint(signed)

    outcome = dispatcher.execute("delete-task", {"task_id": drift_id}, approval_token=minted.credential)
    assert isinstance(outcome, ApprovalRequired)
    assert outcome.reason == "CredentialDrift"


def test_tier2_compromised_agent_cannot_escalate_to_different_action(seeded_client):
    """*** The Zero-Trust property in test form. ***

    Realistic threat model: the agent process is compromised. The attacker
    has access to *everything the agent holds* — that includes the user
    signing secret AND the Vault mint secret in this HS256 reference
    (a Tier-2 deployment with the Vault in-process has both keys
    co-located; honest about that limitation in the OAuthVault docstring).

    What the attacker CANNOT do, even with both secrets: cause the legit
    Vault to mint a credential for an action the *human did not sign*.
    The Vault verifies the signature is over the (command, args)
    payload the human approved. An attacker who has captured the human's
    signed payload for "delete task A" cannot turn it into a credential
    for "delete task B" without forging a new human signature for task B —
    which the attacker cannot do unless they also have the human's
    private signing capability (e.g., the WebAuthn-bound key in a
    production deployment, or in this HS256 reference, the user_signing_
    secret — which in real life lives on the user's MCP host, not on
    the agent process).

    In the production-shape deployment the user signing capability is
    held by a WebAuthn-bound authenticator on the human's device. An
    agent-process attacker who somehow obtained mint_secret still cannot
    forge a new human signature. This test models that asymmetry by
    using a "user secret" the adversary does not have access to.
    """
    client, promised_id, drift_id = seeded_client
    vault = OAuthVault(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
    )
    dispatcher = Dispatcher(client=client, vault=vault)

    # Step 1: human signs for promised_id and approves.
    human_signed = _signed("delete-task", {"task_id": promised_id})

    # Step 2: agent-process attacker captures this signed payload (it
    # traverses the agent on its way to the Vault). The attacker now
    # tries to mint a credential for a different task.
    from dataclasses import replace
    forged_for_different_task = replace(human_signed, args={"task_id": drift_id})
    # The signature is now mismatched against the args (still over the
    # original promised_id payload). The Vault refuses to mint.
    from bridge.vault.interface import SignatureMismatch
    with pytest.raises(SignatureMismatch):
        vault.mint(forged_for_different_task)

    # Step 3: nothing was minted; nothing was executed.
    assert promised_id in {t["task_id"] for t in client.list()}
    assert drift_id in {t["task_id"] for t in client.list()}


def test_tier2_compromised_agent_can_remint_same_action_within_ttl(seeded_client):
    """Honest limitation of the reference: an attacker who has captured
    the human's signed payload can re-mint credentials for *the same
    action* until the signed payload's TTL expires.

    The Vault does not track "this signed payload has already been used
    to mint a credential"; it tracks "this minted credential's jti has
    been consumed." So within the 5-minute signed-payload TTL, a
    captured payload can produce multiple distinct credentials (each
    single-use at consume).

    This is a documented narrowing of the Zero-Trust property: the
    reference enforces "fresh consent per *action shape*", not "fresh
    consent per *execution*". A production deployment that needs the
    stronger property must track consumed signed-payload signatures at
    mint time (a small additional set on the Vault). See the Vault
    docstring and the rationale page §"Failure modes worth designing for."
    """
    client, promised_id, _ = seeded_client
    vault = OAuthVault(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
    )

    signed = _signed("delete-task", {"task_id": promised_id})
    first_credential = vault.mint(signed)
    second_credential = vault.mint(signed)

    # Two distinct credentials, both valid until consumed.
    assert first_credential.jti != second_credential.jti
    assert first_credential.credential != second_credential.credential

    # Each can be consumed independently — though only one execution
    # actually makes sense for a delete (the second would 404 at the RS).
    # The point is: the Vault did not refuse the second mint.
