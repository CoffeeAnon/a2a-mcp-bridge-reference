# Security policy

## Reporting

This is a reference implementation. If you find a *pattern-level* flaw - i.e. the architecture as documented (the Vault contract, three-layer enforcement, canonical-bytes shape, A2A↔MCP translation) teaches something incorrect or unsafe - please open an issue. Pattern-level corrections are exactly what the repo exists to attract.

For *substrate-level* findings (the consent server lacks CSRF tokens, the token store has a race, the audit log stores PII in plaintext), please cross-reference "Intentional Omissions" below before filing. Most of these are documented non-goals; an issue is still welcome if you believe one is mis-classified.

There is no production deployment to coordinate disclosure with. Public issues are appropriate.

## Intentional omissions

The reference deliberately leaves the following out of scope. Copying the repo as a template means re-introducing each of these from production-grade components.

### Substrate concerns the reference will not address

These belong to the deployment substrate, not the architecture being taught. The reference will not add them even in a mature form.

- **Consent-server user authentication.** Anyone with a session ID can render and submit the consent page. Production wraps the consent surface in OIDC / SAML.
- **CSRF protection on `POST /consent/<id>/submit`.** No CSRF tokens. Production adds them at the substrate layer.
- **Session hardening and rate limiting** on the consent server.
- **Durable, transactional token store.** `bridge/auth/hmac.py`'s `TokenStore` is a JSON file with non-atomic load-modify-save. Concurrent issue requests may race.
- **Audit-log PII handling.** `tool_args` and `result_snippet` are stored as-is in the SQLite audit log. No field-level encryption or scrubbing.
- **DPoP / sender-constrained tokens** (RFC 9449).
- **Multi-tenant federation.** Single Vault, single RS, single bridge.
- **Untrusted-MCP-host hardening.** The reference targets cooperative MCP hosts the human controls. Cross-host routing safety requires a signed elicitation-ID carrier; see `bridge.translation.a2a_mcp`.

### Architectural gaps the bundled demo does not close

These are properties the architectural claim *does* commit to, but the bundled demo's substrate stops short of delivering. A production port must close each. They are also listed in the README under "Known production gaps".

- **HS256 → RS256/ES256 + JWKS.** Symmetric secret co-located between Vault and RS in the demo.
- **Server-side signer co-location.** `bridge.consent.demo_signer` holds the user signing key. Production moves signing client-side (WebAuthn / Passkey) and validates the submitted payload against the stored `ProposedAction`.
- ~~**In-memory consumed-jti set.** Vault/RS restart inside the JWT TTL discards the replay-tracking record.~~ *Closed, by injection:* `bridge/vault/durable_state.py` records both the consumed-signature and consumed-`jti` claims in a shared SQLite file via an atomic `INSERT OR IGNORE`, closing the restart window and the cross-replica window that a stateless transport makes the default. `InProcessVault`, `OAuthVault` and `JwtResourceServer` each accept it as `durable_state=`. See `tests/unit/test_durable_state.py`, which includes a real second OS process re-presenting a recorded approval. **Reads "by injection" because three conditions are the deployment's, not the library's:** the kwarg defaults to `None`, so a multi-replica deployment that omits it silently keeps process-local enforcement; the file must be on locking-backed shared storage (WAL over a network share without working POSIX locks is untested and can restore the defect); and `purge_expired()` is never called automatically, so the table grows until an operator prunes it. Tier 1's cross-replica guarantee is at mint only: its `_issued` record stays process-local, so cross-replica presentation fails as `SignatureMismatch`, and cross-replica consume enforcement is delivered at the Tier-2 resource server.
- ~~**Re-mint within signed-payload TTL.** Single-use is enforced per-jti (at consume), not per-signed-payload (at mint).~~ *Closed:* both `InProcessVault` and `OAuthVault` track canonical-bytes hashes of signed payloads accepted at mint and raise `SignatureReplay` on the second presentation. One human signature exchanges for at most one credential, even within the signed-payload TTL. See `tests/unit/test_oauth_vault.py::test_mint_rejects_signature_replay`, `tests/unit/test_in_process_vault.py::test_mint_rejects_signature_replay`, and `tests/e2e/test_dispatcher_vault_integration.py::test_tier2_captured_signed_payload_cannot_be_reminted`.
- **Independent consent surface in production.** The demo's URL-mode consent server runs on the bridge process (`bridge/consent/url_mode.py`) because the demo is self-contained. In production, an entity that orchestrates the LLM (the bridge) cannot also host the page that displays the action to the human - if it controls the pixels, it can render one action and ask the user's signer to sign different bytes, and the `binding_message` defence only catches that *forensically* once the signature is examined. The consent URL must point at an authorization server / consent host in a separate trust domain from the bridge. The reference's `ProposedAction` immutability (`frozen=True` + `MappingProxyType`) is sufficient for the demo's server-side signer but not for a production WebAuthn deployment, where the bridge ships JS to the user's browser and could compose canonical bytes for an action different from the one it renders.
- ~~**MCP scope enforcement.** `bridge/mcp/auth.py` is authentication-only.~~ *Closed:* `Dispatcher.execute` enforces `ToolSpec.required_scopes` against the caller's bearer scopes before HITL routing. See `bridge/core/dispatcher.py` and `tests/e2e/test_scope_enforcement.py`. Any non-MCP surface that bypasses the dispatcher must apply the same check itself.
- ~~**Binding-message tampering.** The human-readable consent summary is not in the canonical bytes.~~ *Closed:* `binding_message` is now a required field of the canonical-bytes contract (CANONICAL.md `binding_message`). A bridge that renders one summary and signs different bytes produces a signature the Vault rejects. See `tests/e2e/test_three_layer_enforcement.py::test_vault_rejects_binding_message_swap`.
- ~~**MCP elicitation emission.** Not bundled in `bridge/mcp/server.py`; demonstrated as building blocks in `tests/e2e/test_mcp_hitl_building_blocks.py`.~~ *Closed:* `bridge/mcp/server.py` emits a URL-mode elicitation (`URL_ELICITATION_REQUIRED`) on a HITL-gated `tools/call` and resumes on retry via `bridge/mcp/hitl.py`, the single-agent secure-approval path with no A2A. Gated tools surface only through an explicit `MCP_HITL_ALLOWLIST` and only when a HITL gate (consent store + Vault) is wired; otherwise the surface stays read-only. See `tests/e2e/test_mcp_elicitation_emission.py` and `tests/unit/test_mcp_hitl_gate.py`. The remaining demo-grade caveat is the in-process consent surface (see "Independent consent surface in production" above).

## What the reference *does* defend, structurally

The architectural claim is exercised through code paths and tests, even though the substrate around it is demo-grade. See `tests/e2e/test_three_layer_enforcement.py`, `tests/e2e/test_dispatcher_vault_integration.py`, and `tests/e2e/test_mcp_hitl_building_blocks.py` for the core assertions:

- Vault refuses to mint without a valid human signature.
- The bridge cannot alter the minted credential between Vault and RS.
- The RS validates the credential's `authorization_details` against the live request independently of the Vault.
- The `ProposedAction` between elicitation emission and signing is structurally immutable (`frozen=True` + `MappingProxyType`).
- JWT algorithm pinning forecloses the `alg=none` and `RS256↔HS256` key-confusion families.
- Canonical bytes are byte-locked across signers, including a non-ASCII fixture.

A bug in any of these would be a pattern-level finding and is in-scope for issues.
