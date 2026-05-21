"""DEMO-ONLY: server-side stand-in for client-side signing.

In a production deployment the signing step is performed *by the human's
MCP host* (Claude Desktop, IDE, custom orchestrator) using a credential
the human controls — ideally a WebAuthn / Passkey assertion, not a shared
HMAC secret. The MCP host POSTs the resulting signed payload to the
bridge's consent endpoint.

For the reference's self-contained demo we cannot launch a separate
client process during a single ``pytest`` run, so this module provides
a *fake signer* that runs server-side and signs on the user's behalf.
**This module is the line a real deployment would replace.** Everything
in ``url_mode.py`` is production-shaped (modulo the in-memory store
and the missing user authentication on the consent page); only this
file is demo scaffolding.

The fake signer delegates to ``bridge.vault.sign_authorization_details``
so the demo cannot accidentally drift from the Vault's canonical-bytes
definition. If the canonical form ever changes in one place but not
the other, every demo test fails immediately.
"""
from __future__ import annotations

from bridge.vault import sign_authorization_details


def demo_sign_as_user(
    *,
    command: str,
    args: dict,
    rar_type: str,
    approver_id: str,
    user_secret: str,
    ttl_seconds: int = 300,
) -> dict:
    """Produce a signed authorization-details payload as if the user-side
    MCP host had done so. Returns the wire format the bridge expects on
    the consent submit endpoint.

    DO NOT call this from production code paths. The user_secret should
    not exist on the server side at all in a real deployment.
    """
    signed = sign_authorization_details(
        command=command,
        args=args,
        rar_type=rar_type,
        approver_id=approver_id,
        secret=user_secret,
        ttl_seconds=ttl_seconds,
    )
    return {
        "command": signed.command,
        "args": signed.args,
        "rar_type": signed.rar_type,
        "exp": signed.exp,
        "approver_id": signed.approver_id,
        "signature": signed.signature,
    }
