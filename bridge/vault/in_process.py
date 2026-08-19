"""Tier 1 Vault: in-process HMAC verifier.

No external authorization server, no JWT minting, no JWKS: just an HMAC
over the canonical authorization-details payload, verified in-process by
the same dispatcher that will execute the action. The Vault's ``mint``
step is essentially a no-op: it confirms the signature is valid, records
the credential as "issued and unconsumed", and returns the same HMAC as
the minted credential.

This is what the substrate ships. It carries the parameter-binding
property end-to-end through one process, with one shared secret. The
trade-off is documented in the rationale page "Three deployment tiers":
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

from bridge.vault.durable_state import DurableReplayState
from bridge.vault.interface import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    InMemorySingleUseRegistry,
    MalformedCredential,
    MintedCredential,
    PayloadDriftAtMint,
    SignatureMismatch,
    SignatureReplay,
    SignedAuthorizationDetails,
    SingleUseRegistry,
    Vault,
    require_nonempty_secret,
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
            f"See the Floats section of bridge/vault/CANONICAL.md."
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
        while signing bytes for "Delete production DB". See the
        "binding_message" section of ``CANONICAL.md`` and ``SECURITY.md``.

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
        ensure_ascii=True,               # explicit: see bridge/vault/CANONICAL.md "Non-ASCII strings"
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
    """Tier 1 Vault: single-use enforcement against a ``SingleUseRegistry``,
    process-local by default and shared when a ``DurableReplayState`` is
    passed as ``durable_state``. The contract is identical either way.

    **Mint-replay closure.** A signed payload accepted at ``mint`` is
    claimed, so a second presentation raises ``SignatureReplay`` rather
    than producing a fresh credential. One human signature exchanges for
    one credential.

    **Where Tier 1's cross-replica guarantee lives.** Sharing the registry
    moves the *mint* decision across replicas: one signed payload, one
    credential, whichever replica sees it. The *consume* decision stays
    process-local by design, because Tier 1 verifies a credential against
    its own ``_issued`` record rather than against a self-contained token.
    A credential minted on replica A and presented to replica B therefore
    fails as ``SignatureMismatch`` ("not issued by this Vault") rather
    than as a replay. Both are rejections. Cross-replica *consume* is a
    Tier-2 property, delivered at the resource server where the JWT
    carries its own claims.

    **Restart behaviour follows from the same fact.** A restart drops
    ``_issued`` along with any process-local claims, so a post-restart
    replay fails at the issuance check rather than the replay check. The
    Tier-2 restart-replay window is structurally closed here, at the cost
    of availability: legitimate-but-unused credentials are also
    unverifiable after a restart. Acceptable at Tier 1, because the human
    can re-approve inside the 5-minute TTL.
    """

    def __init__(
        self,
        *,
        secret: str,
        expected_rar_type: str | None = None,
        max_signed_payload_ttl_seconds: int = _DEFAULT_MAX_SIGNED_PAYLOAD_TTL_SECONDS,
        durable_state: DurableReplayState | None = None,
    ) -> None:
        require_nonempty_secret("secret", secret)
        if max_signed_payload_ttl_seconds <= 0:
            raise ValueError("max_signed_payload_ttl_seconds must be > 0")
        self._secret = secret
        self._expected_rar_type = expected_rar_type
        self._max_ttl = max_signed_payload_ttl_seconds
        # One seam, chosen once. Everything below is written against the
        # registry contract and never branches on which implementation it got.
        self._replay: SingleUseRegistry = durable_state or InMemorySingleUseRegistry()
        # Tier-1 issuance records stay process-local by design; see the class
        # docstring. Their own lock, because they are separate state from the
        # single-use record and the registry owns its own synchronisation.
        self._issued: dict[str, MintedCredential] = {}
        self._issued_lock = threading.Lock()

    def mint(self, signed: SignedAuthorizationDetails) -> MintedCredential:
        # 1. Verify HMAC.
        canonical = canonical_authorization_bytes(
            signed.command, signed.args, signed.rar_type,
            signed.exp, signed.approver_id, signed.binding_message,
        )
        expected = hmac.new(
            self._secret.encode(),
            canonical,
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

        # 3. Claim the signature, then mint. The claim is atomic, so two
        #    concurrent presentations of the same signed payload cannot both
        #    produce a credential - within one process, and across replicas
        #    when the registry is the shared one. Runs after structural
        #    validation so an invalid payload cannot poison the record.
        #
        #    ``_issued`` is recorded separately and always stays process-local:
        #    Tier 1 needs it at consume for the binding check, and it is
        #    deliberately not mirrored into a shared registry (see the class
        #    docstring for where Tier 1's cross-replica guarantee lives).
        signature_hash = hashlib.sha256(canonical).hexdigest()
        if not self._replay.claim_signature(signature_hash, expired_at=float(signed.exp)):
            raise SignatureReplay(
                "signed payload already exchanged for a credential; "
                "one signature = one credential = one execution"
            )

        jti = secrets.token_hex(8)
        minted = MintedCredential(
            credential=f"{signed.signature}.{jti}",
            command=signed.command,
            args=signed.args,
            exp=signed.exp,
            jti=jti,
        )
        with self._issued_lock:
            self._issued[jti] = minted
        return minted

    def consume(self, credential: str, command: str, args: dict) -> MintedCredential:
        try:
            _sig, jti = credential.rsplit(".", 1)
        except ValueError as exc:
            raise MalformedCredential("Tier-1 credential must be 'signature.jti'") from exc

        # The Tier-1 issuance record (``_issued``) is process-local, and the
        # durable store deliberately does NOT duplicate it: Tier 1's
        # cross-replica guarantee is at *mint* time (one signature = one
        # credential, enforced by the shared signature table), not at consume
        # time. A credential minted on replica A and presented to replica B
        # has no local issuance record here, so it fails ``SignatureMismatch``
        # — exactly the documented restart behaviour. (Cross-replica *consume*
        # single-use is guaranteed at the Resource Server for the self-
        # contained Tier-2 JWTs.)
        with self._issued_lock:
            minted = self._issued.get(jti)
            if minted is None:
                raise SignatureMismatch("credential jti was not issued by this Vault")

        # Single-use is queried BEFORE the expiry and binding checks so a
        # replayed credential reports as ``CredentialReplay`` regardless of
        # whether the replay also drifts the parameters or has since expired.
        # The query only selects the message; the claim below is the decision.
        if self._replay.is_jti_consumed(jti):
            raise CredentialReplay(f"credential {jti} already consumed")

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

        if not self._replay.claim_jti(jti, expired_at=float(minted.exp)):
            # Lost the race: a concurrent caller consumed it first.
            raise CredentialReplay(f"credential {jti} already consumed")
        return minted
