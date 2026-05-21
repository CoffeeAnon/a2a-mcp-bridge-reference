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

from dataclasses import dataclass
from typing import Protocol


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
      - ``CredentialReplay``         → single-use violation
      - ``PolicyDenied``             → identity lacks the requested permission

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
    (e.g., the approver's identity lacks the requested permission)."""


class CredentialReplay(VaultError):
    """Credential has already been consumed."""


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
      signature:             HMAC-SHA256 over the canonical JSON of {command,
                             args, rar_type, exp, approver_id}
    """
    command: str
    args: dict
    rar_type: str
    exp: int
    approver_id: str
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
