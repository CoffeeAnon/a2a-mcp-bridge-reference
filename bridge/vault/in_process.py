"""Tier 1 Vault: in-process HMAC verifier.

No external authorization server, no JWT minting, no JWKS — just an HMAC
over the canonical authorization-details payload, verified in-process by
the same dispatcher that will execute the action. The Vault's ``mint``
step is essentially a no-op: it confirms the signature is valid, records
the credential as "issued and unconsumed", and returns the same HMAC as
the minted credential.

This is what the substrate ships. It carries the parameter-binding
property end-to-end through one process, with one shared secret. The
trade-off is documented in the rationale page §"Three deployment tiers":
Tier 1 closes LLM-side threats (prompt injection, parameter drift,
hallucinated arguments) but does NOT defend against agent-process
compromise.

Migrating to Tier 2 is an additive swap: replace the InProcessVault with
an OAuthVault while keeping the dispatcher's ``consume`` call identical.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time

from bridge.vault.interface import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    MalformedCredential,
    MintedCredential,
    PayloadDriftAtMint,
    SignatureMismatch,
    SignedAuthorizationDetails,
    Vault,
)


def canonical_authorization_bytes(
    command: str, args: dict, rar_type: str, exp: int, approver_id: str
) -> bytes:
    """Canonical JSON serialization for HMAC computation.

    Properties (formal spec lives in ``bridge/vault/CANONICAL.md``):
      - sorted keys at every nesting level (``sort_keys=True``)
      - tight separators, no whitespace (``separators=(",", ":")``)
      - ``exp`` is integer seconds since epoch (no float repr drift)
      - list order is *significant* — the human approves [a,b] vs [b,a]
        as different actions
      - string values are caller's responsibility to NFC-normalise

    This is the load-bearing function: if signer and verifier disagree
    about the canonical form, the signature mismatches. Public so Tier 1
    and Tier 2 Vault implementations can share one definition. The spec
    document is the contract for cross-language signer implementations.
    """
    return json.dumps(
        {"cmd": command, "args": args, "rar_type": rar_type, "exp": exp, "approver_id": approver_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sign_authorization_details(
    *,
    command: str,
    args: dict,
    rar_type: str,
    approver_id: str,
    secret: str,
    ttl_seconds: int = 300,
) -> SignedAuthorizationDetails:
    """Helper for the MCP host / client side: produce the signed payload
    that gets POSTed to the Vault. In production this lives in the MCP
    client's elicitation handler, not on the agent service side.

    ``exp`` is computed as integer seconds since epoch to keep the
    canonical bytes byte-stable across language implementations
    (Python's ``float`` repr would not match e.g. JavaScript's).
    """
    exp = int(time.time()) + ttl_seconds
    payload_bytes = canonical_authorization_bytes(command, args, rar_type, exp, approver_id)
    signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return SignedAuthorizationDetails(
        command=command, args=args, rar_type=rar_type, exp=exp,
        approver_id=approver_id, signature=signature,
    )


class InProcessVault(Vault):
    """Tier 1 Vault. Thread-safe single-use enforcement via an in-memory
    consumed-jti set. Production deployments would swap the set for a
    durable store (sqlite, Redis) but the contract is identical.

    **Restart-replay note.** Unlike Tier 2, Tier 1 holds the credential's
    *issuance* record (``_issued``) in the same process as ``_consumed``.
    A restart loses both. Post-restart, replays fail with
    ``SignatureMismatch`` ("jti was not issued by this Vault") because
    the issuance record is also gone — the restart-replay window that
    affects Tier 2 (where the JWT is self-contained) is structurally
    closed at Tier 1. The trade-off is availability: post-restart,
    legitimate-but-unused credentials are also unverifiable. For Tier 1
    that is acceptable because the human can re-approve within the
    5-minute TTL.
    """

    def __init__(self, *, secret: str, expected_rar_type: str | None = None) -> None:
        self._secret = secret
        self._expected_rar_type = expected_rar_type
        self._consumed: set[str] = set()
        self._issued: dict[str, MintedCredential] = {}
        self._lock = threading.Lock()

    def mint(self, signed: SignedAuthorizationDetails) -> MintedCredential:
        # 1. Verify HMAC.
        expected = hmac.new(
            self._secret.encode(),
            canonical_authorization_bytes(signed.command, signed.args, signed.rar_type, signed.exp, signed.approver_id),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signed.signature):
            raise SignatureMismatch("HMAC verification failed")

        # 2. Validate the rar_type if the Vault was configured with one.
        if self._expected_rar_type is not None and signed.rar_type != self._expected_rar_type:
            raise PayloadDriftAtMint(
                f"unexpected rar_type: {signed.rar_type!r} != {self._expected_rar_type!r}"
            )

        # 3. Mint a credential. In Tier 1 the credential IS the signature
        #    augmented with a per-mint jti so single-use can be enforced
        #    even when the same payload is signed twice.
        jti = secrets.token_hex(8)
        credential = f"{signed.signature}.{jti}"
        minted = MintedCredential(
            credential=credential,
            command=signed.command,
            args=signed.args,
            exp=signed.exp,
            jti=jti,
        )
        with self._lock:
            self._issued[jti] = minted
        return minted

    def consume(self, credential: str, command: str, args: dict) -> MintedCredential:
        try:
            _sig, jti = credential.rsplit(".", 1)
        except ValueError:
            raise MalformedCredential("Tier-1 credential must be 'signature.jti'")

        with self._lock:
            minted = self._issued.get(jti)
            if minted is None:
                raise SignatureMismatch("credential jti was not issued by this Vault")
            if jti in self._consumed:
                raise CredentialReplay(f"credential {jti} already consumed")

            # Validate the credential at execution time.
            if time.time() > minted.exp:
                raise CredentialExpired(f"credential {jti} expired")
            if minted.command != command:
                raise CredentialDrift(
                    f"credential bound to command={minted.command!r}, live command={command!r}"
                )
            if minted.args != args:
                raise CredentialDrift(
                    f"credential bound to args={minted.args!r}, live args={args!r}"
                )

            self._consumed.add(jti)
            return minted
