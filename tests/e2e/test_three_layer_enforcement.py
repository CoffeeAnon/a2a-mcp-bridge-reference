"""End-to-end: parameter-binding through three independent enforcement layers.

``docs/architecture.md`` commits the Tier-2 architecture to three layers:
  1. Vault verifies the human's signature BEFORE minting.
  2. The bridge cannot alter the minted claim (it forwards the JWT unchanged).
  3. The resource server validates the minted JWT's authorization_details
     against the LIVE request, with its own consumed-jti state.

These tests exercise each layer through real code paths. The Vault and the
ResourceServer are separate objects with separate state; the dispatcher
forwards credentials from one to the other without modification.

If any of these tests pass when they should fail, the "three independent
enforcement layers" claim is broken.
"""
import pytest

from bridge.core.client import InMemoryTaskStore
from bridge.core.dispatcher import ApprovalRequired, CommandSuccess, Dispatcher
from bridge.rs import JwtResourceServer
from bridge.vault import (
    OAuthVault,
    sign_authorization_details,
)


USER_SECRET = "test-user-secret-32bytes-minimum-pad"
MINT_SECRET = "test-mint-secret-32bytes-minimum-pad"
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


def _mint(vault, command, args, secret=USER_SECRET, binding_message="Delete task ?"):
    signed = sign_authorization_details(
        command=command, args=args, rar_type=RAR_TYPE,
        approver_id="alice", binding_message=binding_message, secret=secret,
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
        approver_id="alice", binding_message="Delete task t-42?",
        secret="WRONG-USER-SECRET-PADDED-32-bytes-fill",
    )
    with pytest.raises(SignatureMismatch):
        vault.mint(signed)


def test_vault_rejects_binding_message_swap(separated_setup):
    """Binding-message tampering: ``binding_message`` is in the canonical bytes.

    Threat: a compromised bridge renders one binding_message to the user
    ("Delete the temp file") but constructs a SignedAuthorizationDetails
    with a different binding_message ("Delete production DB") before
    handing it to the Vault — same args, same command, the user thinks
    they approved the cosmetic action.

    Defence: the HMAC the user computed is over the canonical bytes that
    include the message the user actually saw. If the bridge swaps the
    binding_message, the canonical bytes the Vault recomputes differ
    from the bytes the user signed, and the Vault refuses to mint with
    SignatureMismatch.
    """
    from bridge.vault import SignedAuthorizationDetails
    from bridge.vault.interface import SignatureMismatch

    _, vault, _, _, promised, _ = separated_setup
    # User signs over message they actually saw.
    benign = sign_authorization_details(
        command="delete-task", args={"task_id": promised}, rar_type=RAR_TYPE,
        approver_id="alice", binding_message="Delete the temp file (low impact).",
        secret=USER_SECRET,
    )
    # Compromised bridge tries to present a different binding_message to the Vault
    # while keeping everything else (including the user's signature) intact.
    tampered = SignedAuthorizationDetails(
        command=benign.command, args=benign.args, rar_type=benign.rar_type,
        exp=benign.exp, approver_id=benign.approver_id,
        binding_message="Delete the production database.",
        signature=benign.signature,
    )
    with pytest.raises(SignatureMismatch):
        vault.mint(tampered)


# ── Layer 2: bridge cannot alter the minted claim ──────────────────────────


def test_layer3_rs_catches_credential_mutation_in_transit(separated_setup):
    """Layer 3 again, in a "what if Layer 2 failed?" framing.

    Layer 2 ("the bridge cannot alter the minted claim") is *structural*
    — it's a property of ``Dispatcher._execute_via_rs`` being a 4-line
    pass-through to ``rs.execute``. There is no dynamic test that proves
    a structural property of that shape; you read the dispatcher's code.

    What this test demonstrates is the *defence-in-depth* property: if
    anything between mint and RS were to mutate the credential (a future
    refactor that introduced a transformation, a buggy middleware, an
    attacker who compromised the bridge process), the RS rejects.
    Layer 3 catches what Layer 2's structural pass-through is supposed
    to make impossible in the first place.
    """
    _, vault, _, dispatcher, promised, _ = separated_setup
    minted = _mint(vault, "delete-task", {"task_id": promised})

    header, body, sig = minted.credential.split(".")
    flipped_body_char = "A" if body[-1] != "A" else "B"
    tampered = f"{header}.{body[:-1]}{flipped_body_char}.{sig}"

    outcome = dispatcher.execute("delete-task", {"task_id": promised}, approval_token=tampered)

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


def test_rs_rejects_token_signed_with_different_mint_secret():
    """Sibling of test_rs_rejects_token_for_different_audience but at
    the secret-config level. Demonstrates that the Layer-3 RS verifies
    against its OWN configured key, independent of the Vault's mint
    key. In the HS256 reference these are typically the same string;
    this test simulates a deployment where they're different (e.g., a
    misconfiguration, or a transitioning rotation) and proves the RS
    detects the mismatch."""
    client = InMemoryTaskStore()
    task = client.create(title="target")
    vault = OAuthVault(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        issuer=ISSUER,
        audience=AUDIENCE,
        expected_rar_type=RAR_TYPE,
    )
    # RS configured with a DIFFERENT verification secret than the Vault
    # mints under. In production RS256, this is the analogous
    # mismatch between holding the wrong public key.
    this_rs = JwtResourceServer(
        verification_secret="rs-has-a-different-secret-32bytes-pad",
        expected_issuer=ISSUER,
        expected_audience=AUDIENCE,
        expected_rar_type=RAR_TYPE,
        client=client,
    )
    dispatcher = Dispatcher(resource_server=this_rs)

    minted = _mint(vault, "delete-task", {"task_id": task["task_id"]})
    outcome = dispatcher.execute(
        "delete-task", {"task_id": task["task_id"]}, approval_token=minted.credential,
    )
    assert isinstance(outcome, ApprovalRequired)
    assert outcome.reason == "SignatureMismatch"
    assert task["task_id"] in {t["task_id"] for t in client.list()}


def test_rs_accepts_token_when_aud_is_array():
    """RFC 7519 permits ``aud`` to be a string OR an array of strings.
    The reference's `OAuthVault` mints scalar `aud`; an external AS
    (Keycloak, Authlete) commonly emits array. Verify the RS accepts
    both shapes — otherwise the documented "production swap doesn't
    change Vault.consume" promise is broken."""
    import base64
    import hashlib as _h
    import hmac as _hmac
    import json as _json
    import secrets as _secrets
    import time as _time

    from bridge.vault.oauth import _b64url, jwt_encode

    client = InMemoryTaskStore()
    task = client.create(title="target")
    rs = JwtResourceServer(
        verification_secret=MINT_SECRET,
        expected_issuer=ISSUER,
        expected_audience=AUDIENCE,
        expected_rar_type=RAR_TYPE,
        client=client,
    )

    # Forge a token with array-shaped aud, signed with the same secret.
    claims = {
        "iss": ISSUER,
        "aud": [AUDIENCE, "some-other-rs"],   # array shape, our audience present
        "sub": "alice",
        "iat": int(_time.time()),
        "exp": int(_time.time()) + 60,
        "jti": _secrets.token_hex(8),
        "authorization_details": [{
            "type": RAR_TYPE, "command": "delete-task",
            "args": {"task_id": task["task_id"]},
        }],
    }
    token = jwt_encode(claims, MINT_SECRET)

    outcome = rs.execute("delete-task", {"task_id": task["task_id"]}, token)
    from bridge.rs import RsSuccess
    assert isinstance(outcome, RsSuccess)


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
