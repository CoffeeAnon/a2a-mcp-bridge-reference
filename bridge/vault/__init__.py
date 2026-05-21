"""Vault primitives — the cryptographic delegation substrate.

Two implementations of the same ``Vault`` Protocol:
  - ``InProcessVault``: Tier 1, in-process HMAC verifier
  - ``OAuthVault``: Tier 2, JWT-minting authorization server (HS256)

See ``docs/rationale.md`` for the three-tier
graduation and ``docs/architecture.md`` for component flows.
"""
from bridge.vault.in_process import InProcessVault, sign_authorization_details
from bridge.vault.interface import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    MalformedCredential,
    MintedCredential,
    PayloadDriftAtMint,
    PolicyDenied,
    SignatureMismatch,
    SignedAuthorizationDetails,
    UnknownIssuer,
    Vault,
    VaultError,
    WrongAudience,
)
from bridge.vault.oauth import OAuthVault

__all__ = [
    "CredentialDrift",
    "CredentialExpired",
    "CredentialReplay",
    "InProcessVault",
    "MalformedCredential",
    "MintedCredential",
    "OAuthVault",
    "PayloadDriftAtMint",
    "PolicyDenied",
    "SignatureMismatch",
    "SignedAuthorizationDetails",
    "UnknownIssuer",
    "Vault",
    "VaultError",
    "WrongAudience",
    "sign_authorization_details",
]
