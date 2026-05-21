"""Tier 1 Vault: in-process HMAC verifier.

No external authorization server, no JWT minting, no JWKS: just an HMAC
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

import types

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


_DEFAULT_MAX_SIGNED_PAYLOAD_TTL_SECONDS = 600  # see bridge/vault/oauth.py


def _canonical_default(obj):
    """JSON encoder hook for read-only mapping types.

    ``bridge.consent.url_mode.ProposedAction`` stores ``args`` as a
    ``types.MappingProxyType`` to make the action description immutable
    after creation. ``json.dumps`` doesn't know how to serialise
    MappingProxyType natively, so we provide a default that unwraps
    it to a plain dict for serialization. The contents are the same
    snapshot the proxy guards: bytes-identical to a hand-built dict
    from the same source.
    """
    if isinstance(obj, types.MappingProxyType):
        return dict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _reject_floats(value, path: str = "args") -> None:
    """Recursively reject ``float`` values anywhere in ``args``.

    Floats have no stable cross-language canonical representation:
    ``0.1 + 0.2`` may serialise as ``0.30000000000000004`` on one
    platform and ``0.3`` on another, and Python's ``json.dumps`` and
    JavaScript's ``JSON.stringify`` disagree on edge cases (subnormals,
    very large magnitudes). A reference that teaches a canonical-form
    contract cannot leave that drift surface unaddressed. Callers that
    need fractional quantities must encode them as integers in a fixed
    minor unit (e.g., cents instead of dollars) or as strings.
    ``bool`` is intentionally allowed; ``bool`` is a subclass of
    ``int`` in Python but ``isinstance(True, float)`` is False.
    """
    if isinstance(value, float):
        raise TypeError(
            f"canonical_authorization_bytes: float values are not permitted "
            f"in args (at {path}); use integer minor units or strings. "
            f"See bridge/vault/CANONICAL.md §Floats."
        )
    if isinstance(value, dict) or isinstance(value, types.MappingProxyType):
        for k, v in value.items():
            _reject_floats(v, path=f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _reject_floats(v, path=f"{path}[{i}]")


def canonical_authorization_bytes(
    command: str, args: dict, rar_type: str, exp: int, approver_id: str,
    binding_message: str,
) -> bytes:
    """Canonical JSON serialization for HMAC computation.

    Properties (formal spec lives in ``bridge/vault/CANONICAL.md``):
      - sorted keys at every nesting level (``sort_keys=True``)
      - tight separators, no whitespace (``separators=(",", ":")``)
      - ``exp`` is integer seconds since epoch (no float repr drift)
      - **floats are rejected** anywhere in ``args``; see ``_reject_floats``
      - list order is *significant*: the human approves [a,b] vs [b,a]
        as different actions
      - string values are caller's responsibility to NFC-normalise
      - ``args`` may be a plain ``dict`` or a ``types.MappingProxyType``
        (used by the consent server to make stored args immutable);
        both produce byte-identical output.
      - ``binding_message`` is included so the human-readable summary the
        user actually read is cryptographically bound to the signature.
        Without it a compromised bridge could render "Delete tmp file"
        while signing bytes for "Delete production DB". See
        ``CANONICAL.md`` §"binding_message" and ``SECURITY.md``.

    This is the load-bearing function: if signer and verifier disagree
    about the canonical form, the signature mismatches. Public so Tier 1
    and Tier 2 Vault implementations can share one definition. The spec
    document is the contract for cross-language signer implementations.
    """
    _reject_floats(args)
    return json.dumps(
        {
            "cmd": command, "args": args, "rar_type": rar_type,
            "exp": exp, "approver_id": approver_id,
            "binding_message": binding_message,
        },
        sort_keys=True,                  # recursive key sort at every nesting level
        separators=(",", ":"),           # no whitespace anywhere
        ensure_ascii=True,               # explicit: see bridge/vault/CANONICAL.md §"Non-ASCII strings"
        default=_canonical_default,      # serialise MappingProxyType (immutable args) as plain dict
    ).encode()


def sign_authorization_details(
    *,
    command: str,
    args: dict,
    rar_type: str,
    approver_id: str,
    binding_message: str,
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
    payload_bytes = canonical_authorization_bytes(
        command, args, rar_type, exp, approver_id, binding_message,
    )
    signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return SignedAuthorizationDetails(
        command=command, args=args, rar_type=rar_type, exp=exp,
        approver_id=approver_id, binding_message=binding_message,
        signature=signature,
    )


class InProcessVault(Vault):
    """Tier 1 Vault. Thread-safe single-use enforcement via an in-memory
    consumed-jti set. Production deployments would swap the set for a
    durable store (sqlite, Redis) but the contract is identical.

    **Restart-replay note.** Unlike Tier 2, Tier 1 holds the credential's
    *issuance* record (``_issued``) in the same process as ``_consumed``.
    A restart loses both. Post-restart, replays fail with
    ``SignatureMismatch`` ("jti was not issued by this Vault") because
    the issuance record is also gone - the restart-replay window that
    affects Tier 2 (where the JWT is self-contained) is structurally
    closed at Tier 1. The trade-off is availability: post-restart,
    legitimate-but-unused credentials are also unverifiable. For Tier 1
    that is acceptable because the human can re-approve within the
    5-minute TTL.
    """

    def __init__(
        self,
        *,
        secret: str,
        expected_rar_type: str | None = None,
        max_signed_payload_ttl_seconds: int = _DEFAULT_MAX_SIGNED_PAYLOAD_TTL_SECONDS,
    ) -> None:
        from bridge.vault.oauth import _require_nonempty_secret
        _require_nonempty_secret("secret", secret)
        if max_signed_payload_ttl_seconds <= 0:
            raise ValueError("max_signed_payload_ttl_seconds must be > 0")
        self._secret = secret
        self._expected_rar_type = expected_rar_type
        self._max_ttl = max_signed_payload_ttl_seconds
        self._consumed: set[str] = set()
        self._issued: dict[str, MintedCredential] = {}
        self._lock = threading.Lock()

    def mint(self, signed: SignedAuthorizationDetails) -> MintedCredential:
        # 1. Verify HMAC.
        expected = hmac.new(
            self._secret.encode(),
            canonical_authorization_bytes(
                signed.command, signed.args, signed.rar_type,
                signed.exp, signed.approver_id, signed.binding_message,
            ),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signed.signature):
            raise SignatureMismatch("HMAC verification failed")

        # 1b. Enforce signer-side `exp` bounds. The Vault is the policy
        #     point for credential lifetime; a signer that proposes a
        #     decade-long exp or an already-expired exp is rejected at
        #     mint time.
        now = time.time()
        if signed.exp <= now:
            raise CredentialExpired(
                f"signed payload exp={signed.exp} is already in the past (now={now:.0f})"
            )
        if signed.exp > now + self._max_ttl:
            raise PayloadDriftAtMint(
                f"signed payload exp={signed.exp} exceeds Vault max_ttl of "
                f"{self._max_ttl}s (would be {signed.exp - now:.0f}s out)"
            )

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
        except ValueError as exc:
            raise MalformedCredential("Tier-1 credential must be 'signature.jti'") from exc

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
