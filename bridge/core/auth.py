"""Approval-token primitives and credentials loader.

**Legacy module.** Predates the Vault interface; superseded by
``bridge.vault.InProcessVault`` (Tier 1) and ``bridge.vault.OAuthVault``
(Tier 2). The only remaining caller is ``bridge.a2a.turns`` (the older
A2A executor that signs approval tokens at the LangGraph-resume seam).
New code should use the Vault interface instead — ``generate_approval_token``
does not enforce single-use, which the Vault does.

The functions remain here because they're a useful standalone demonstration
of the HMAC-over-canonical-bytes pattern without the Vault wrapping.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any


class CredentialsError(Exception):
    pass


# OAUTH SEAM: load_credentials() returns whatever the downstream resource server
# needs. The reference's task-tracker example uses a simple Bearer token loaded
# from BRIDGE_RS_TOKEN; production deployments would swap this for an OAuth
# Token Exchange (RFC 8693) call that returns a delegation token with an `act`
# claim recording the agent identity alongside the user identity.
def load_credentials() -> dict:
    url = os.environ.get("BRIDGE_RS_URL")
    if not url:
        raise CredentialsError("BRIDGE_RS_URL environment variable is required")
    token = os.environ.get("BRIDGE_RS_TOKEN")
    if not token:
        raise CredentialsError("BRIDGE_RS_TOKEN environment variable is required")
    verify_ssl_raw = os.environ.get("BRIDGE_VERIFY_SSL", "true").lower()
    verify_ssl = verify_ssl_raw not in ("false", "0", "no")
    return {
        "auth_mode": "bearer",
        "api_url": url.rstrip("/"),
        "token": token,
        "verify_ssl": verify_ssl,
    }


def _make_payload(command: str, args: dict[str, Any], exp: float) -> bytes:
    data = {"cmd": command, "args": args, "exp": exp}
    return json.dumps(data, sort_keys=True).encode()


def generate_approval_token(command: str, args: dict[str, Any], secret: str) -> str:
    """Sign an HMAC approval token over command + args + 5-minute expiry.

    The returned token is opaque base64-payload + hex-signature. Verification
    re-derives the digest from the live command + args; any drift fails.
    """
    exp = time.time() + 300  # 5-minute TTL
    payload = _make_payload(command, args, exp)
    payload_b64 = base64.urlsafe_b64encode(payload).decode()
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_approval_token(
    token: str, command: str, args: dict[str, Any], secret: str
) -> bool:
    """Re-derive the digest from live command+args; reject any mismatch.

    Returns False (not raises) so the dispatcher can surface a uniform
    "approval required" outcome on any verification failure: signature
    mismatch, expired TTL, drifted command, drifted args.
    """
    try:
        payload_b64, sig = token.rsplit(".", 1)
    except ValueError:
        return False
    try:
        payload = base64.urlsafe_b64decode(payload_b64)
    except Exception:
        return False
    expected_sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return False
    if data.get("cmd") != command:
        return False
    if data.get("args") != args:
        return False
    if time.time() > data.get("exp", 0):
        return False
    return True
