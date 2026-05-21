"""End-to-end: parameter-binding through three independent enforcement layers.

The wiki commits the Tier-2 architecture to three layers:
  1. Vault verifies the human's signature BEFORE minting.
  2. The bridge cannot alter the minted claim (it forwards the JWT unchanged).
  3. The resource server validates the minted JWT's authorization_details
     against the LIVE request, with its own consumed-jti state.

These tests exercise each layer through real code paths. The Vault and the
ResourceServer are separate objects with separate state; the dispatcher
forwards credentials from one to the other without modification.

If any of these tests pass when they should fail, the wiki's "three
independent enforcement layers" claim is broken.
"""
import pytest

from bridge.core.client import InMemoryTaskStore
from bridge.core.dispatcher import ApprovalRequired, CommandSuccess, Dispatcher
from bridge.rs import JwtResourceServer
from bridge.vault import (
    OAuthVault,
    sign_authorization_details,
)


USER_SECRET = "test-user-secret"
MINT_SECRET = "test-mint-secret"
ISSUER = "https://vault.reference.invalid"
AUDIENCE = "bridge-resource-server"
RAR_TYPE = "tasktracker_task_action"


@pytest.fixture
def separated_setup():
    """Vault, RS, and dispatcher wired in the three-layer shape."""
    client = InMemoryTaskStore()
    promised = client.create(title="Q2 launch checklist")
    bystander = client.create(title="Q3 onboarding doc")

    vault = OAuthVault(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        issuer=ISSUER,
        audience=AUDIENCE,
        expected_rar_type=RAR_TYPE,
    )
    rs = JwtResourceServer(
        verification_secret=MINT_SECRET,  # HS256 limitation; would be public key for RS256
        expected_issuer=ISSUER,
        expected_audience=AUDIENCE,
        expected_rar_type=RAR_TYPE,
        client=client,
    )
    dispatcher = Dispatcher(resource_server=rs)
    return client, vault, rs, dispatcher, promised["task_id"], bystander["task_id"]


def _mint(vault, command, args, secret=USER_SECRET):
    signed = sign_authorization_details(
        command=command, args=args, rar_type=RAR_TYPE,
        approver_id="alice", secret=secret,
    )
    return vault.mint(signed)


# ── Happy path through all three layers ────────────────────────────────────


def test_three_layer_happy_path(separated_setup):
    client, vault, rs, dispatcher, promised, bystander = separated_setup
    minted = _mint(vault, "delete-task", {"task_id": promised})

    outcome = dispatcher.execute("delete-task", {"task_id": promised}, approval_token=minted.credential)

    assert isinstance(outcome, CommandSuccess)
    remaining = {t["task_id"] for t in client.list()}
    assert promised not in remaining
    assert bystander in remaining


# ── Layer 1: Vault refuses to mint when human signature is bad ─────────────


def test_layer1_vault_refuses_bad_signature(separated_setup):
    """Layer 1: Vault verify before mint."""
    _, vault, _, _, promised, _ = separated_setup
    from bridge.vault.interface import SignatureMismatch
    signed = sign_authorization_details(
        command="delete-task", args={"task_id": promised}, rar_type=RAR_TYPE,
        approver_id="alice", secret="WRONG-USER-SECRET",
    )
    with pytest.raises(SignatureMismatch):
        vault.mint(signed)


# ── Layer 2: bridge cannot alter the minted claim ──────────────────────────


def test_layer2_bridge_forwards_credential_unchanged(separated_setup):
    """Layer 2: the dispatcher forwards the credential to the RS unmodified.

    Demonstrated by: the JWT presented to the RS is byte-identical to the
    one the Vault minted. (We can't easily intercept the call inside the
    dispatcher in pure Python, but we can prove the property by mutating
    the credential and observing the RS rejects.)
    """
    _, vault, _, dispatcher, promised, _ = separated_setup
    minted = _mint(vault, "delete-task", {"task_id": promised})

    # Modify a single byte in the JWT body. The bridge has no opportunity
    # to "patch" this back to the original because the dispatcher is a
    # straight pass-through; the RS will see the modified token.
    header, body, sig = minted.credential.split(".")
    flipped_body_char = "A" if body[-1] != "A" else "B"
    tampered = f"{header}.{body[:-1]}{flipped_body_char}.{sig}"

    outcome = dispatcher.execute("delete-task", {"task_id": promised}, approval_token=tampered)

    # The RS rejects because the signature no longer verifies over the
    # tampered body — proving the bridge cannot have repaired the token.
    assert isinstance(outcome, ApprovalRequired)
    assert outcome.reason == "SignatureMismatch"


# ── Layer 3: RS validates authorization_details against the live request ──


def test_layer3_rs_rejects_drift_independently(separated_setup):
    """Layer 3: RS sees credential + live request; refuses on mismatch.

    This is structurally distinct from Vault.consume rejecting drift,
    because the RS has its own validation path. Even if the Vault is
    compromised into believing a credential is fine, the RS rejects.
    """
    client, vault, _, dispatcher, promised, bystander = separated_setup
    minted = _mint(vault, "delete-task", {"task_id": promised})

    outcome = dispatcher.execute("delete-task", {"task_id": bystander}, approval_token=minted.credential)

    assert isinstance(outcome, ApprovalRequired)
    assert outcome.reason == "CredentialDrift"
    # Neither task is deleted.
    assert {t["task_id"] for t in client.list()} == {promised, bystander}


# ── Independence: Vault and RS keep separate consumed-jti state ─────────────


def test_independence_vault_and_rs_consumed_state_are_separate(separated_setup):
    """The Vault's consumed set and the RS's consumed set are independent.

    Here the credential is consumed at the RS by a successful execute().
    A second attempt is rejected at the RS via its own _consumed set, not
    via the Vault — the Vault never sees the credential at all when an
    RS is wired in.
    """
    _, vault, rs, dispatcher, promised, _ = separated_setup
    minted = _mint(vault, "delete-task", {"task_id": promised})

    first = dispatcher.execute("delete-task", {"task_id": promised}, approval_token=minted.credential)
    assert isinstance(first, CommandSuccess)

    replay = dispatcher.execute("delete-task", {"task_id": promised}, approval_token=minted.credential)
    assert isinstance(replay, ApprovalRequired)
    assert replay.reason == "CredentialReplay"

    # The Vault was never asked about this credential and has no record of consumption.
    assert minted.jti not in vault._consumed
    # The RS has the jti in its own state.
    assert minted.jti in rs._consumed


# ── Layer 3 catches what Layer 1 + bridge tampering would miss ─────────────


def test_rs_rejects_token_for_different_audience():
    """If a JWT was minted for a different RS audience, this RS rejects.

    Demonstrates that the RS does its own audience check independent of
    whatever the Vault enforces.
    """
    client = InMemoryTaskStore()
    task = client.create(title="target")
    vault_for_other_rs = OAuthVault(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        issuer=ISSUER,
        audience="some-OTHER-resource-server",
        expected_rar_type=RAR_TYPE,
    )
    this_rs = JwtResourceServer(
        verification_secret=MINT_SECRET,
        expected_issuer=ISSUER,
        expected_audience=AUDIENCE,  # different from what the vault minted for
        expected_rar_type=RAR_TYPE,
        client=client,
    )
    dispatcher = Dispatcher(resource_server=this_rs)

    minted = _mint(vault_for_other_rs, "delete-task", {"task_id": task["task_id"]})
    outcome = dispatcher.execute(
        "delete-task", {"task_id": task["task_id"]}, approval_token=minted.credential,
    )
    assert isinstance(outcome, ApprovalRequired)
    assert outcome.reason == "WrongAudience"
    # Task survives.
    assert task["task_id"] in {t["task_id"] for t in client.list()}
