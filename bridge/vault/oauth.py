"""Tier 2 Vault: OAuth-style authorization server that mints JWTs.

Hand-rolled HS256 JWT — no PyJWT dependency. The reference uses a shared
HMAC secret for signing because the goal is to demonstrate the *shape*
of the Tier 2 architecture (verify human signature → mint JWT with
`authorization_details` claim → enforce single-use at consume), not to
ship a production-grade authorization server.

A production Tier 2 would swap HS256 for RS256/ES256 against a JWKS
endpoint. **The *public API surface* (``Vault.mint`` / ``Vault.consume``)
does not change**, but the swap inside the Vault is not mechanical. The
verifier must enforce that ``alg`` is exactly the expected algorithm
(see ``_EXPECTED_ALG``) — supporting *both* HS256 and asymmetric
algorithms in the same verify path opens the classic
RS256→HS256 key-confusion vulnerability where the attacker re-signs an
asymmetric token with HS256 using the RSA public key as the HMAC
secret. The algorithm-pinning guard below prevents that footgun
structurally.

Differences from Tier 1:

  - Mint produces a JWT structurally different from the input signature.
    The agent receives a *new* credential it could not have produced
    itself, even if it captured the human's signed payload.
  - The JWT body carries `authorization_details` as a structured claim,
    consumable by any resource server that knows the RAR `type`.
  - The Vault is logically separable from the dispatcher (the same JWT
    could be presented to an external RS), even though the reference
    runs them in one process for simplicity.

The threat model the user buys with Tier 2 is documented in the
architecture page §"Threat model": agent-process compromise no longer
yields a usable destructive credential, because no destructive
credential exists at rest in the agent.
"""
from __future__ import annotations

import base64
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
    UnknownIssuer,
    Vault,
    WrongAudience,
)
from bridge.vault.in_process import canonical_authorization_bytes


# ── Minimal HS256 JWT primitives (stdlib only) ───────────────────────────────


_EXPECTED_ALG = "HS256"
"""The only ``alg`` header value this Vault and its companion RS accept.

A production deployment that swaps HS256 for an asymmetric algorithm
must update this constant in lockstep with the signing+verification key
material. Accepting any algorithm the verifier *can* handle is the
classic JWT footgun — see the module docstring for why.
"""


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _jwt_encode(claims: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    c = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h}.{c}".encode()
    sig = _b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{h}.{c}.{sig}"


def _jwt_decode(token: str, secret: str) -> dict:
    """Parse + cryptographically verify a JWT.

    Raises:
      MalformedCredential   structural problems (not three parts, header
                            not decodable, body not decodable, wrong
                            algorithm) — no signature check attempted.
      SignatureMismatch     header parses, alg matches, but HMAC fails.

    The ``alg`` header is parsed and pinned to ``_EXPECTED_ALG`` BEFORE
    the signature check. Tokens with ``alg=none``, ``alg=RS256``, or any
    other algorithm are rejected as malformed-for-this-verifier, never
    reaching the HMAC path. This forecloses the JWT algorithm-confusion
    family of vulnerabilities.
    """
    try:
        h, c, sig = token.split(".")
    except ValueError:
        raise MalformedCredential("JWT must have three dot-separated parts")

    try:
        header = json.loads(_b64url_decode(h))
    except Exception:
        raise MalformedCredential("JWT header is not valid base64-encoded JSON")

    if header.get("alg") != _EXPECTED_ALG:
        raise MalformedCredential(
            f"JWT alg={header.get('alg')!r} is not the expected {_EXPECTED_ALG!r}"
        )

    signing_input = f"{h}.{c}".encode()
    expected_sig = _b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected_sig):
        raise SignatureMismatch("JWT signature does not verify against mint secret")
    try:
        return json.loads(_b64url_decode(c))
    except Exception:
        raise MalformedCredential("JWT body is not valid base64-encoded JSON")


# ── Vault ────────────────────────────────────────────────────────────────────


class OAuthVault(Vault):
    """Tier 2 Vault.

    Two secrets:
      - ``user_signing_secret``: used to verify the human's HMAC over
        the structured authorization-details payload at mint time. The
        human's MCP host (Claude Desktop, IDE, custom orchestrator)
        holds the corresponding signing key. In production this would
        be an asymmetric key the Vault knows via JWKS or attestation
        (WebAuthn / Passkey), and the bridge process would NEVER hold
        the signing material.
      - ``mint_secret``: the Vault's own JWT-signing secret; the RS uses
        the corresponding public key (or, in this HS256 reference, the
        same shared secret) to validate consumed tokens.

    **Demo-mode key-residence caveat.** In the self-contained demo
    (``bridge.consent.demo_signer``), ``user_signing_secret`` is held by
    the bridge process so the example runs end-to-end without a
    separate user-key custodian. A bridge compromise in that
    configuration yields full mint capability. The published threat
    model assumes a production deployment where the user signing
    capability lives client-side; the reference implementation is
    structurally complete with respect to that threat model, but the
    demo configuration is materially weaker.

    These are deliberately separate so a compromised MCP host signing key
    does not let an attacker mint tokens directly — they can still
    forge user signatures, but only the Vault can produce a valid JWT.

    **Restart-replay limitation.** The ``_consumed`` set is in-process
    memory. A bridge restart inside the 5-minute JWT TTL discards the
    consumed-jti record, so a captured-but-not-replayed JWT becomes
    replayable until its ``exp`` passes. Production deployments must
    swap the ``_consumed`` set for a durable store (sqlite, Redis,
    Postgres) with TTL-aware eviction. The reference does not do this
    because (a) stdlib-only is a stated goal, and (b) the failure mode
    is bounded by the 5-minute TTL. A `JwtResourceServer` deployed
    separately has the same limitation in its own ``_consumed`` set —
    both layers need durable jti tracking in production.
    """

    def __init__(
        self,
        *,
        user_signing_secret: str,
        mint_secret: str,
        issuer: str = "https://vault.reference.invalid",
        audience: str = "bridge-resource-server",
        expected_rar_type: str | None = None,
    ) -> None:
        self._user_signing_secret = user_signing_secret
        self._mint_secret = mint_secret
        self._issuer = issuer
        self._audience = audience
        self._expected_rar_type = expected_rar_type
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def mint(self, signed: SignedAuthorizationDetails) -> MintedCredential:
        # 1. Verify the human's HMAC over the signed authorization-details.
        expected = hmac.new(
            self._user_signing_secret.encode(),
            canonical_authorization_bytes(signed.command, signed.args, signed.rar_type, signed.exp, signed.approver_id),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signed.signature):
            raise SignatureMismatch("human signature verification failed")

        # 2. Validate the rar_type if configured.
        if self._expected_rar_type is not None and signed.rar_type != self._expected_rar_type:
            raise PayloadDriftAtMint(
                f"unexpected rar_type: {signed.rar_type!r} != {self._expected_rar_type!r}"
            )

        # 3. Construct the access-token claims. The shape mirrors how a
        #    real OAuth+RAR access token would look — a resource server
        #    that knows the RAR `type` can consume this directly.
        now = time.time()
        jti = secrets.token_hex(8)
        claims = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": signed.approver_id,
            "iat": int(now),
            "exp": int(signed.exp),
            "jti": jti,
            "authorization_details": [{
                "type": signed.rar_type,
                "command": signed.command,
                "args": signed.args,
            }],
        }
        credential = _jwt_encode(claims, self._mint_secret)
        return MintedCredential(
            credential=credential,
            command=signed.command,
            args=signed.args,
            exp=signed.exp,
            jti=jti,
        )

    def consume(self, credential: str, command: str, args: dict) -> MintedCredential:
        claims = _jwt_decode(credential, self._mint_secret)

        # exp check
        exp = float(claims.get("exp", 0))
        if time.time() > exp:
            raise CredentialExpired(f"jti={claims.get('jti')} expired")

        # iss / aud check (defence in depth). Distinct from
        # SignatureMismatch — the JWT validates cryptographically; it just
        # came from / is intended for a different party than this Vault
        # is configured to accept.
        if claims.get("iss") != self._issuer:
            raise UnknownIssuer(
                f"token iss={claims.get('iss')!r} does not match expected {self._issuer!r}"
            )
        if claims.get("aud") != self._audience:
            raise WrongAudience(
                f"token aud={claims.get('aud')!r} does not match expected {self._audience!r}"
            )

        # authorization_details presence
        ad_list = claims.get("authorization_details") or []
        if not ad_list:
            raise PayloadDriftAtMint("token has no authorization_details claim")
        ad = ad_list[0]

        # Single-use enforcement runs BEFORE parameter-binding checks: a
        # replayed credential should be reported as ``CredentialReplay``
        # regardless of whether the replay also drifts the parameters.
        # Matches the check order in ``InProcessVault.consume``.
        jti = claims.get("jti", "")
        with self._lock:
            if jti in self._consumed:
                raise CredentialReplay(f"jti={jti} already consumed")

            if ad.get("command") != command:
                raise CredentialDrift(
                    f"token bound to command={ad.get('command')!r}, live command={command!r}"
                )
            if ad.get("args") != args:
                raise CredentialDrift(
                    f"token bound to args={ad.get('args')!r}, live args={args!r}"
                )
            if self._expected_rar_type is not None and ad.get("type") != self._expected_rar_type:
                raise PayloadDriftAtMint(
                    f"token rar_type={ad.get('type')!r} != expected {self._expected_rar_type!r}"
                )

            self._consumed.add(jti)

        return MintedCredential(
            credential=credential,
            command=command,
            args=args,
            exp=exp,
            jti=jti,
        )
