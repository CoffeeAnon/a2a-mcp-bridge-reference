"""Vault interface: the cryptographic delegation engine.

Every tier of the bridge expresses its trust substrate through a Vault.
At Tier 1 (`InProcessVault`) the Vault is an in-process HMAC verifier.
At Tier 2 (`OAuthVault`) it is an external authorization server that mints
JWTs with `authorization_details` claims. Both honour the same interface
and the same contract:

  - **mint**: verify the human's signature over a structured authorization
    payload (the RAR `authorization_details`) and return a single-use,
    short-lived credential bound to those exact parameters.
  - **consume**: validate the credential against a live command + args at
    execution time, mark it consumed, and reject replays.

The dispatcher only ever calls ``consume``. The bridge layer calls ``mint``
in response to an elicitation approval and passes the resulting
``MintedCredential`` to the dispatcher.

The security property this contract carries (per ``docs/rationale.md``)
is parameter-binding: the credential is pinned to the exact arguments the
human approved. ``Vault.mint`` is where that pin is set, and ``Vault.consume``
is where it is enforced. A Vault implementation that fails either step
breaks the property and the design contract.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

MIN_SECRET_BYTES = 32
"""HMAC-SHA256 keys shorter than 32 bytes (256 bits) are below the
recommended strength for cryptographic operations."""


def require_nonempty_secret(name: str, value: str) -> None:
    """Validate that a secret string is non-empty and meets the minimum 32-byte entropy requirement."""
    if not value:
        raise ValueError(f"{name} must not be empty")
    if len(value.encode()) < MIN_SECRET_BYTES:
        raise ValueError(
            f"{name} is too short ({len(value.encode())} bytes); "
            f"need at least {MIN_SECRET_BYTES} bytes of entropy"
        )


class SingleUseRegistry(Protocol):
    """Where "this has already been used" is recorded.

    Single-use is the one guarantee in this design that is not a function of
    the bytes in front of you. A signature either verifies or it does not, and
    any process reaches the same verdict; "already spent" is a *memory*, and
    the enforcement is exactly as wide as the storage holding it. Naming that
    storage as a seam is what lets the same enforcement code span one process
    or a whole cluster without branching on which it is.

    Two implementations satisfy this:

      - :class:`InMemorySingleUseRegistry` - process-local, the default. Correct
        for a single process; a second replica has its own empty copy.
      - ``bridge.vault.durable_state.DurableReplayState`` - a shared SQLite
        file, so the record spans replicas and survives restart.

    Callers must treat ``claim_*`` as the authority and never as advice. The
    ``is_*_consumed`` queries exist only to choose an error message *before*
    the binding checks run, so a replayed credential reports as a replay rather
    than as drift; they are deliberately not the decision. Two callers can both
    see ``is_*_consumed() == False`` and race, and exactly one will win the
    subsequent ``claim_*``. A caller that branches on the query and skips the
    claim has reintroduced the check-then-act hole this protocol exists to
    close.

    ``expired_at`` is the end of the window the record must block for: the
    signed payload's ``exp`` for a signature, the credential's ``exp`` for a
    jti. Implementations may keep records past it (the in-memory sets never
    prune at all); they may never drop one before it.
    """

    def is_signature_consumed(self, sig_hash: str) -> bool: ...

    def claim_signature(self, sig_hash: str, *, expired_at: float) -> bool:
        """Record ``sig_hash`` as spent. True only for the first caller."""
        ...

    def is_jti_consumed(self, jti: str) -> bool: ...

    def claim_jti(self, jti: str, *, expired_at: float) -> bool:
        """Record ``jti`` as spent. True only for the first caller."""
        ...


class InMemorySingleUseRegistry:
    """Process-local :class:`SingleUseRegistry`: two sets behind one lock.

    The default for every Vault and resource server, and the whole of the
    single-use guarantee when the deployment is one process. Records are never
    pruned, which is what makes "once consumed, always a replay" true; the
    consumers' expiry checks run before any claim, so a permanently-held key
    can never reject a *valid* presentation (there is no valid presentation of
    an expired key).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._signatures: set[str] = set()
        self._jtis: set[str] = set()

    def is_signature_consumed(self, sig_hash: str) -> bool:
        with self._lock:
            return sig_hash in self._signatures

    def claim_signature(self, sig_hash: str, *, expired_at: float) -> bool:
        with self._lock:
            if sig_hash in self._signatures:
                return False
            self._signatures.add(sig_hash)
            return True

    def is_jti_consumed(self, jti: str) -> bool:
        with self._lock:
            return jti in self._jtis

    def claim_jti(self, jti: str, *, expired_at: float) -> bool:
        with self._lock:
            if jti in self._jtis:
                return False
            self._jtis.add(jti)
            return True


class VaultError(Exception):
    """Raised on any verification failure inside the Vault.

    Subclasses below let callers distinguish *what* failed, which matters
    because each failure mode tells a different audit story:

      - ``MalformedCredential``      → bug, integration error, or fuzzing
      - ``SignatureMismatch``        → cryptographic forgery attempt
      - ``UnknownIssuer`` / ``WrongAudience`` → token from another system
      - ``PayloadDriftAtMint``       → client signed something other than proposed
      - ``CredentialDrift``          → live request doesn't match what was approved
      - ``CredentialExpired``        → time bound exceeded
      - ``CredentialReplay``         → single-use violation (at consume)
      - ``SignatureReplay``          → multi-mint violation (at mint): same
                                       signed payload presented to the Vault
                                       more than once
      - ``PolicyDenied``             → identity lacks the requested permission
                                       (reserved for production AS-side policy;
                                       not raised by the in-process or HS256 demos —
                                       ``approver_id`` is carried for attribution,
                                       not enforced as authorization policy)

    The dispatcher treats every ``VaultError`` uniformly as "approval required"
    when surfacing to callers, but the typed exception is preserved on the
    ``ApprovalRequired.reason`` field for audit attribution.
    """


class MalformedCredential(VaultError):
    """Credential's wire format is structurally broken (e.g., not three
    dot-separated parts for a JWT, body is not valid base64-JSON).
    Distinct from ``SignatureMismatch`` because no cryptographic check
    was attempted: there was nothing to check."""


class SignatureMismatch(VaultError):
    """Cryptographic verification failed: the HMAC or JWT signature does
    not match the expected value computed with the configured secret.
    Raised only after the credential has been confirmed structurally
    well-formed."""


class UnknownIssuer(VaultError):
    """JWT validates cryptographically but the ``iss`` claim does not
    match this Vault's expected issuer. Common cause: token minted by a
    different Vault deployment, or client misconfigured to point at the
    wrong AS."""


class WrongAudience(VaultError):
    """JWT validates cryptographically but the ``aud`` claim does not
    match this resource server's expected audience. Common cause: token
    minted for a different resource server in a multi-RS deployment."""


class PayloadDriftAtMint(VaultError):
    """Signature is valid but the payload contents do not match the
    authorization_details the bridge emitted (i.e., the client signed
    something other than what was proposed)."""


class PolicyDenied(VaultError):
    """Signature and payload are valid but Vault policy refuses to mint
    (e.g., the approver's identity lacks the requested permission).

    Reserved for production AS-side authorization decisions. **Neither the
    in-process Vault nor the HS256 OAuthVault demo raises this**: they treat
    ``approver_id`` as an attribution field carried through to the audit log
    and the JWT ``sub`` claim, not as input to an RBAC/ABAC decision. A
    production AS swapped in behind the ``Vault`` Protocol (Keycloak,
    Authlete, Auth0, Curity, etc.) is where this exception would actually
    surface.
    """


class CredentialReplay(VaultError):
    """Credential has already been consumed."""


class SignatureReplay(VaultError):
    """The same signed RAR payload was presented to the Vault more than once.

    Distinct from ``CredentialReplay``, which fires at *consume* when a minted
    credential is presented twice. ``SignatureReplay`` fires at *mint*: it
    closes the multi-mint surface where one human signature could otherwise
    be exchanged for N distinct, valid credentials within the signed-payload
    TTL. The Vault tracks consumed signed-payload signatures and refuses to
    mint twice from the same one. One signature = one credential = one
    execution.

    The property this protects is "fresh consent per execution," not just
    "fresh consent per action shape." Captured signed payloads cannot be
    replayed by an attacker holding the bytes (e.g., a leaked WebSocket
    frame, a misbehaving relay, a compromised bridge process)."""


class CredentialExpired(VaultError):
    """Credential's `exp` is in the past."""


class CredentialDrift(VaultError):
    """Credential's bound parameters do not match the live request."""


@dataclass(frozen=True)
class SignedAuthorizationDetails:
    """The payload the human signs after reviewing an elicitation.

    Fields:
      command:               canonical command name (e.g. "delete-task")
      args:                  exact arguments the human approved
      rar_type:              the RAR `authorization_details.type` string
      exp:                   POSIX seconds (integer; truncated for
                             cross-language byte-stability; see
                             ``bridge/vault/CANONICAL.md``)
      approver_id:           opaque approver identity (for audit)
      binding_message:       human-readable summary the user actually read
                             at the consent surface (e.g., "Delete the task
                             titled 'Q2 launch checklist'?"). Included in
                             the canonical bytes so that what the user
                             *saw* is cryptographically bound to what they
                             *signed*. A compromised bridge that renders
                             one message and signs different bytes will
                             fail Vault verification; see ``SECURITY.md``.
      signature:             HMAC-SHA256 over the canonical JSON of
                             {command, args, rar_type, exp, approver_id,
                             binding_message}
    """
    command: str
    args: dict
    rar_type: str
    exp: int
    approver_id: str
    binding_message: str
    signature: str


@dataclass(frozen=True)
class MintedCredential:
    """The credential the Vault hands back after a successful mint.

    Tier 1: ``credential`` is the HMAC + a jti suffix.
    Tier 2: ``credential`` is a freshly-minted JWT (HS256 in the reference;
    asymmetric in production) carrying ``authorization_details``.

    The dispatcher does not need to know which tier produced the
    credential - it only knows to pass it to ``Vault.consume`` at
    execution time.

    Fields ``command`` and ``args`` are deliberately denormalised with the
    opaque ``credential`` string: callers (audit, logging, the dispatcher's
    ``ApprovalRequired.reason`` plumbing) need the bound parameters in a
    structured form without re-decoding the credential. The Vault's
    ``consume`` method is the source of truth for whether the bound
    parameters match the live request - these fields exist for
    *attribution*, not for authorization decisions.
    """
    credential: str
    command: str
    args: dict
    exp: int
    jti: str  # unique identifier for single-use tracking


class Vault(Protocol):
    """The trust substrate. Tier 1 and Tier 2 implement this identically
    from the dispatcher's point of view."""

    def mint(self, signed: SignedAuthorizationDetails) -> MintedCredential:
        """Verify the human's signature; return a single-use, action-scoped
        credential bound to the approved arguments. Raises ``VaultError``
        subclass on any failure."""
        ...

    def consume(self, credential: str, command: str, args: dict) -> MintedCredential:
        """Validate the credential at execution time, mark it consumed.
        Returns the parsed MintedCredential (useful for audit). Raises
        ``VaultError`` subclass on any failure."""
        ...
