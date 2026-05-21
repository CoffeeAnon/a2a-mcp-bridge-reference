"""InProcessVault — Tier 1 verifier.

The load-bearing properties: parameter-binding, single-use enforcement,
HMAC signature verification, expiry. If any of these regress, the Tier
1 security contract breaks.
"""
import time

import pytest

from bridge.vault import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    InProcessVault,
    MalformedCredential,
    PayloadDriftAtMint,
    SignatureMismatch,
    sign_authorization_details,
)


SECRET = "test-shared-secret"
RAR_TYPE = "tasktracker_task_action"


@pytest.fixture
def vault():
    return InProcessVault(secret=SECRET, expected_rar_type=RAR_TYPE)


def _signed(command="delete-task", args=None, secret=SECRET):
    return sign_authorization_details(
        command=command,
        args=args or {"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        secret=secret,
    )


# ── mint ──────────────────────────────────────────────────────────────────────


def test_mint_then_consume_happy_path(vault):
    signed = _signed()
    minted = vault.mint(signed)
    assert minted.command == "delete-task"
    assert minted.args == {"task_id": "t-42"}
    consumed = vault.consume(minted.credential, "delete-task", {"task_id": "t-42"})
    assert consumed.jti == minted.jti


def test_mint_rejects_bad_signature(vault):
    signed = _signed(secret="wrong-secret")
    with pytest.raises(SignatureMismatch):
        vault.mint(signed)


def test_mint_rejects_unexpected_rar_type():
    vault = InProcessVault(secret=SECRET, expected_rar_type="some_other_type")
    signed = _signed()
    with pytest.raises(PayloadDriftAtMint):
        vault.mint(signed)


# ── consume: single-use ─────────────────────────────────────────────────────


def test_consume_rejects_replay(vault):
    """*** The single-use property in test form. ***"""
    signed = _signed()
    minted = vault.mint(signed)
    vault.consume(minted.credential, "delete-task", {"task_id": "t-42"})
    with pytest.raises(CredentialReplay):
        vault.consume(minted.credential, "delete-task", {"task_id": "t-42"})


# ── consume: parameter binding ──────────────────────────────────────────────


def test_consume_rejects_drifted_args(vault):
    signed = _signed(args={"task_id": "approved"})
    minted = vault.mint(signed)
    with pytest.raises(CredentialDrift):
        vault.consume(minted.credential, "delete-task", {"task_id": "drifted"})


def test_consume_rejects_drifted_command(vault):
    signed = _signed(command="delete-task")
    minted = vault.mint(signed)
    with pytest.raises(CredentialDrift):
        vault.consume(minted.credential, "update-task", {"task_id": "t-42"})


# ── consume: malformed ──────────────────────────────────────────────────────


def test_consume_rejects_unknown_credential(vault):
    """Well-formed but the jti was never issued — that's a signature/identity
    failure (someone presented a credential we did not produce)."""
    with pytest.raises(SignatureMismatch):
        vault.consume("nonsense.abcdef", "delete-task", {"task_id": "t-42"})


def test_consume_rejects_malformed(vault):
    """No dot at all — not even structurally a credential. Distinct from
    a signature failure: nothing to verify against."""
    with pytest.raises(MalformedCredential):
        vault.consume("not-a-credential-at-all", "delete-task", {})


# ── consume: expiry ─────────────────────────────────────────────────────────


def test_consume_rejects_expired(vault, monkeypatch):
    signed = sign_authorization_details(
        command="delete-task",
        args={"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        secret=SECRET,
        ttl_seconds=1,
    )
    minted = vault.mint(signed)
    # Pretend we're 10 seconds in the future.
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 10)
    with pytest.raises(CredentialExpired):
        vault.consume(minted.credential, "delete-task", {"task_id": "t-42"})
