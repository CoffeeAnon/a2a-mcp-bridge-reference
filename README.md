# A2A↔MCP Bridge Reference

> [!WARNING]
> **Reference implementation only, not a production template.** This codebase exists to illustrate the RAR / Vault / HITL patterns and the A2A↔MCP translation shape. It deliberately omits standard substrate concerns (consent-server authentication, CSRF protection, durable session/token storage, OWASP-class hardening) so the architectural mechanics stay readable. Copying this repo as-is into production would ship something insecure. See "Limitations and non-goals" and `SECURITY.md` for the explicit list of what is intentionally out of scope.

A reference implementation of a **stateful, HITL-aware, parameter-bound** bridge between [A2A](https://a2a-protocol.org) and [MCP](https://modelcontextprotocol.io), the two emerging protocols for agent-to-agent and LLM-host-to-tool communication.

## The four necessary and sufficient constraints

A bridge that lets an LLM call destructive tools through a human-in-the-loop check has to hold four properties. Each fails in a specific way if missing; together they are sufficient for the design's goal — *every change to data is approved by a named human, and the approval is verifiable from an audit log alone.*

1. **Parameter-Bound Intent.** The human's signature is computed over the canonical bytes of the exact command and arguments that will run. Without this, the LLM can swap arguments after approval and the system has no way to notice.
2. **Consent Atomicity.** One signed payload mints at most one credential. Without this, a captured signed payload can be replayed to turn one approval into N executions within the signed-payload TTL.
3. **Independent Consent Surface.** The entity that displays the proposed action to the human is in a different trust domain from the entity orchestrating the LLM. Without this, a hostile bridge can render one action while passing canonical bytes for a different action to the user's signer.
4. **Destination Gating.** The resource server refuses any request lacking a valid Vault-minted, parameter-bound credential. Without this, an agent that finds the RS's direct API can bypass the architecture entirely.

The reference closes constraints 1, 2, and 4 in code. Constraint 3 is a deployment-shape requirement (see "Production deployment shape" below): the demo's consent server runs on the bridge for self-containedness; a production deployment must put it in a separate trust domain.

The design realises the four constraints across two patterns:

1. **Protocol orchestration (Pattern 1).** Translation between A2A's task-lifecycle SSE shape and MCP's elicitation shape, so a human in an MCP host (Claude Desktop, IDE, custom orchestrator) can be the human-in-the-loop for an action proposed by a remote A2A agent. Stateful `context_id` continuity across the round-trip.
2. **Cryptographic delegation (Pattern 2).** Every destructive action is approved by a human signing the *specific* `authorization_details` payload (RFC 9396 RAR shape). The signature drives an authorization server (Vault) to mint a single-use, action-scoped credential; the Vault refuses to mint twice from the same signed payload; an independent resource server validates the credential against the live request. The agent process holds no persistent destructive credentials.

The reference ships two tiers behind a single `Vault` Protocol:

- **Tier 1: `InProcessVault`** (HMAC, in-process verifier). Deployable today with no Vault infrastructure. Closes LLM-side threats (prompt injection, parameter drift). Does not defend against agent-process compromise.
- **Tier 2: `OAuthVault` + separate `JwtResourceServer`** (OAuth-shape JWT mint with independent RS verification). Three independent enforcement layers: Vault verify-before-mint (with signed-payload single-use), bridge cannot alter, RS validates against live request. Closes agent-process compromise in the production-shape deployment where the user signing key lives client-side and the consent surface is hosted in a separate trust domain.

---

## What this reference is — and what it isn't

This repo is a reference architecture and executable demo of the building blocks, not a secure reference implementation. The architectural shape (protocol translation, three-layer enforcement, parameter-bound credentials, canonical-form signing contract) is exercised through real code. Several properties the contract names are framing-only in the bundled demo and must be added before production use.

What's actually demonstrated in code:

- The `Vault` Protocol with two interchangeable implementations (Tier 1 in-process, Tier 2 OAuth-shape with separated RS).
- Signature verification, JWT algorithm pinning, canonical-bytes contract with cross-language fixtures, independent RS validation, parameter-drift rejection at three layers.
- **Signed-payload single-use at mint**: both Vaults track canonical-bytes hashes of accepted payloads and refuse a second mint from the same signature (`SignatureReplay`). Closes the multi-mint surface that earlier revisions left as a documented carve-out.
- The A2A↔MCP translation in pure data, the URL-mode consent surface, and the MCP `tools/list` + `tools/call` (read-only) wiring.
- Dispatcher-level scope enforcement: a caller's bearer scopes are checked against the tool's `required_scopes` before HITL routing, so a `tasks.read` bearer cannot execute non-HITL writes (`create_task`, `update_task`) or even reach the HITL gate for `delete_task`. See `tests/e2e/test_scope_enforcement.py`.
- `binding_message` is part of the signed canonical bytes (CANONICAL.md `binding_message`). A bridge that renders one summary on the consent page but signs different bytes fails Vault verification; see `tests/e2e/test_three_layer_enforcement.py::test_vault_rejects_binding_message_swap`.

For the explicit list of what the demo intentionally leaves out and what a production port must still close, see "Limitations and non-goals" below and `SECURITY.md`.

---

## Reading order

The code is organised so it can be read in five short passes. Each pass builds on the previous one and should take five to fifteen minutes.

**1. The contract.** Start with the `Vault` Protocol in `bridge/vault/interface.py`: two methods, the typed exceptions every layer raises, and the `SignedAuthorizationDetails` and `MintedCredential` dataclasses. The rest of the codebase is configured around this contract.

**2. The two Vault implementations.** Tier 1 lives in `bridge/vault/in_process.py` and is roughly 150 lines. Read `canonical_authorization_bytes` first, since it carries the cross-language signer contract, then `mint` and `consume`. Tier 2 lives in `bridge/vault/oauth.py`; the HS256 JWT helpers (`jwt_encode`, `jwt_decode`) are at the top, with algorithm pinning in `jwt_decode`, and `OAuthVault.mint` and `consume` below. The module docstring describes the production swap to RS256/ES256.

**3. The third enforcement layer.** `bridge/rs/jwt_resource_server.py` is the Tier-2 resource server. It performs its own JWT verification, its own `iss`/`aud`/`exp` checks, its own consumed-`jti` tracking, and its own binding check between the live request and the JWT's `authorization_details`, all independent of the Vault.

**4. The HITL gate and the protocol surfaces.** `bridge/core/dispatcher.py` holds the HITL gate. It accepts a `Vault` or a `ResourceServer` but never both, and routes execution accordingly. The Tier-2 path is a four-line pass-through to the RS, which is what makes Layer 2 of the three-layer architecture structural. From there, `bridge/translation/a2a_mcp.py` is Pattern 1 in pure data (A2A `auth_required` ↔ MCP elicitation, preserving `context_id` continuity and `authorization_details` byte-identity), `bridge/consent/url_mode.py` is the URL-mode consent server, and `bridge/mcp/server.py` is the MCP HTTP surface that routes `tools/call` into the same dispatcher the CLI uses.

**5. Run something.** `bridge/walkthrough.py` is the narrated end-to-end flow using every component together. Run it with `bridge walkthrough --tier 2` for a step-by-step trace of the full Tier-2 path.

If you plan to write a non-Python signer, `bridge/vault/CANONICAL.md` is the byte-level contract.

### Tests worth reading

Three tests carry most of the design's weight and are short enough to read directly:

- `tests/e2e/test_three_layer_enforcement.py` exercises Layer 1 (Vault verify-before-mint) and Layer 3 (RS independent verify) through code. Layer 2, the dispatcher's structural pass-through, is asserted by code inspection - what this file tests is Layer 3 catching mutation if it occurred, the defence-in-depth fallback.
- `tests/e2e/test_dispatcher_vault_integration.py::test_tier2_attacker_without_user_secret_cannot_forge_a_new_signature` exercises the production-shape Zero-Trust property: an attacker without the user signing key cannot forge a signature for a new action. The HS256 demo configuration is materially weaker than the WebAuthn-bound production shape, and the docs say so where it matters.
- `tests/e2e/test_mcp_hitl_building_blocks.py` exercises the translation + consent + Vault + RS composition for the MCP HITL flow. It does not drive the MCP server's `tools/call` → `elicitation/create` wire (that emission is documented as a next step in "Limitations and non-goals"), but it shows that the building blocks compose correctly.

---

## Layout

```
bridge/
├── vault/             # Pattern 2: Vault Protocol + InProcessVault + OAuthVault
│   └── CANONICAL.md     ← cross-language signer spec
├── rs/                # Pattern 2: JwtResourceServer (third enforcement layer)
├── translation/       # Pattern 1: A2A ↔ MCP elicitation translation (pure dataclasses)
├── consent/           # URL-mode elicitation consent server (Starlette)
│   ├── url_mode.py      ← three endpoints: render / submit / result
│   └── demo_signer.py   ← server-side stand-in for client-side WebAuthn signing
├── mcp/               # MCP streamable-HTTP surface (bearer-auth, tools/list, tools/call)
│   ├── server.py        ← build_mcp_app(): the ASGI mount
│   ├── invoker.py         ← Dispatcher adapter for MCP tool calls
│   └── auth.py            ← bearer-token verification
├── core/              # Dispatcher (HITL gate), in-memory task store, command registry
├── commands/          # Task-tracker example commands: list/get/create/update/delete
├── auth/              # Shared HMAC bearer-token store (TokenStore + CallerIdentity)
├── tools.py           # ToolSpec registry: declarative tool metadata
├── audit.py           # Append-only SQLite audit log
├── cli.py             # `bridge demo` smoke-test runner
└── walkthrough.py     # `bridge walkthrough` architecture-sequence simulator

tests/
├── unit/              # Vault, RS, canonical-form fixtures, translation, registry, token-store
├── e2e/               # Three-layer enforcement, parameter drift, MCP HITL building blocks, dispatcher
└── protocol/          # MCP server (auth gate), consent server (URL-mode endpoints), read filter
```

The example domain is deliberately generic. Replace `bridge/commands/*.py` and update `bridge/tools.py` to point at your own domain. The Vault, RS, dispatcher, MCP surface, and CLI all stay the same.

---

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .                       # core: stdlib only (CLI + Vault + RS + dispatcher + tests)
pip install -e '.[mcp]'                # add MCP HTTP surface and URL-mode consent server
pip install -e '.[dev]'                # add test runner
```

The CLI demos and the core test suite run with the **core** install. The `[mcp]` extra adds Starlette + uvicorn + Anthropic's MCP SDK + python-multipart and is required if you want to:

- Boot the MCP server (`bridge.mcp.server.build_mcp_app`)
- Run the consent server (`bridge.consent.url_mode.build_consent_app`)
- Execute the protocol-level integration tests (`tests/protocol/test_consent_server.py`, `tests/protocol/test_mcp_server.py`, `tests/e2e/test_mcp_hitl_building_blocks.py`); they `pytest.importorskip` Starlette and the mcp SDK, so they're skipped on a core install.

---

## CLI smoke-test runner

The `bridge` command exercises HITL flow scenarios end-to-end with stable `[OK]` / `[REJECTED]` markers and a non-zero exit code on any unexpected outcome. Useful as a smoke test or as an executable demo.

```bash
bridge demo all                       # run every scenario, print a summary
bridge demo tier1                     # happy-path delete via Tier 1 InProcessVault
bridge demo tier2                     # happy-path delete via Tier 2 OAuthVault
bridge demo drift --tier 2            # LLM substitutes task_id after approval → rejected
bridge demo replay --tier 2           # credential reused → rejected
bridge demo key-isolation             # Tier-2: a JWT minted by one Vault is refused by another
bridge demo translation               # Pattern-1 A2A↔MCP translation round-trip
```

> **Note on `key-isolation`**: this scenario demonstrates a *narrow* cross-Vault key independence property, not Zero Trust under agent compromise. The realistic Zero-Trust property (an attacker with both secrets cannot escalate to actions the human didn't sign) is exercised by `tests/e2e/test_dispatcher_vault_integration.py::test_tier2_attacker_without_user_secret_cannot_forge_a_new_signature`.

For a step-by-step simulation of the sequence diagram in `docs/architecture.md` (12 numbered steps with actual JSON-RPC / SSE / OAuth envelopes printed at each hop):

```bash
bridge walkthrough --tier 2           # full simulation, no pauses
bridge walkthrough --tier 2 --pause   # interactive: Enter between steps
bridge walkthrough --tier 1           # the Tier-1 in-process variant
```

The walkthrough is behaviour-accurate but transport-simulated. The Vault, dispatcher, resource server, and translation calls run for real - the HTTP/SSE envelopes are printed for narration rather than sent over sockets.

Without an install you can run it directly from a checkout:

```bash
python -m bridge.cli demo all
```

---

## Tests

```bash
pytest                       # all (114 tests; protocol/e2e/integration tests need [mcp] extras)
pytest tests/unit            # Vault, RS, canonical fixtures, translation, registry
pytest tests/e2e             # three-layer enforcement, drift, MCP HITL building blocks
pytest tests/protocol        # MCP server, consent server, MCP read filter
```

Key invariants the suite enforces:

- **Parameter-drift**: after a mint, dispatch refuses to execute against drifted args, at both the Vault (Tier 1) and the RS (Tier 2 separated).
- **Single-use, both layers**: a credential consumed once cannot be consumed again (`CredentialReplay` at consume), AND a signed payload presented to the Vault once cannot mint a second credential (`SignatureReplay` at mint). One signature = one credential = one execution. See `tests/unit/test_oauth_vault.py::test_mint_rejects_signature_replay` and `tests/e2e/test_dispatcher_vault_integration.py::test_tier2_captured_signed_payload_cannot_be_reminted`.
- **Cross-Vault key isolation**: a JWT minted by one OAuthVault instance does not validate at another (different `mint_secret`).
- **Three-layer enforcement** (`tests/e2e/test_three_layer_enforcement.py`): each layer (Vault signature verify-before-mint, bridge unable to alter, RS independent verify+binding+single-use) exercised through real code.
- **MCP HITL building blocks** (`tests/e2e/test_mcp_hitl_building_blocks.py`): the translation + consent + Vault + RS composition for the MCP HITL flow. Does NOT exercise the MCP server's `tools/call` → `elicitation/create` wire - that's documented as the unbundled next step in "Limitations and non-goals". What's tested: A2A event → translation → consent page → user approves → bridge polls → translation back → Vault.mint → RS.execute → target deleted, bystander survives.
- **JWT algorithm pinning**: `alg=none`, `alg=RS256` rejected before HMAC verify (forecloses the RS256↔HS256 key-confusion family).
- **`aud` claim shape compliance** (RFC 7519): both scalar `aud` and array-of-strings `aud` accepted at the RS. Production AS implementations (Keycloak, Authlete) commonly emit array shape - the reference `OAuthVault` mints scalar.
- **Signed-payload TTL bound at mint**: `OAuthVault` rejects (`PayloadDriftAtMint`) a signed payload whose `exp` exceeds `max_signed_payload_ttl_seconds` (default 600s). A misbehaving or compromised signer cannot mint long-lived credentials by inflating `exp`.
- **Canonical-form fixtures**: byte-level canonical output locked for known inputs, including a non-ASCII case (`ï`, U+00EF) that any cross-language signer must match.
- **Read filter**: MCP `tools/list` excludes any tool with `requires_approval=True`, defended even if the allowlist is wrong.
- **MCP auth gate**: unauthenticated MCP requests reject 401; bogus bearer rejects 401; valid bearer reaches the session manager.
- **Consent server contract**: render → submit (approve/deny) → poll for result; double-approve idempotent; post-deny approve rejected; unknown session → 404.
- **Audit fidelity**: every MCP tool-call writes exactly one `tool_call` audit row via `AuditSink`. The schema supports richer kinds (`approval_granted`, `approval_rejected`, `error`) as documented in `bridge/audit.py`; emitting those is a downstream-integration choice and not exercised by the bundled CLI.

---

## Limitations and non-goals

Two kinds of limit: things the reference will never attempt (substrate concerns out of scope), and things the architecture commits to but the bundled demo's substrate doesn't fully deliver. A production port replaces the substrate and closes the gaps.

### Non-goals (deliberate scope choices)

The reference will not attempt these even at maturity. Each belongs to substrate concerns that would obscure the patterns the project exists to teach.

- **Production-grade consent surface.** No user authentication on the consent page, no CSRF tokens on `POST /consent/<id>/submit`, no session hardening, no rate limiting. The consent server is a minimal Starlette mount that illustrates the URL-mode elicitation shape. A production deployment authenticates the user (OIDC / SAML), protects the form (CSRF), and rate-limits the endpoint.
- **Durable storage substrate.** The token store is a JSON file with non-atomic load-modify-save. The audit log is SQLite without field-level encryption or scrubbing. The consumed-jti and `_issued` sets are in-process Python sets. Production swaps in durable, transactional, encrypted storage as a substrate change with no architectural impact.
- **Multi-tenant federation.** Single AS, single RS, single bridge. Federated deployments are a deployment-topology concern.
- **DPoP / sender-constrained tokens** (RFC 9449). Strongly recommended for production; not modelled here.
- **Untrusted MCP host hardening.** The bridge trusts the MCP host to route elicitation responses faithfully. Multi-replica or shared-host deployments must replace the elicitation-ID carrier with a signed token. See `bridge.translation.a2a_mcp` and the "Untrusted MCP host" row in `docs/architecture.md`.
- **Audit-log PII handling.** `tool_args` and `result_snippet` are stored as-is. Production must add field-level encryption or automated scrubbing for sensitive arguments.

### Known production gaps

Properties the architecture commits to but the bundled demo stops short of fully delivering. Each is also called out in the relevant module docstrings and in the `docs/architecture.md` threat model.

- **HS256 reference** uses a shared symmetric secret between Vault and RS. In production the Vault would sign with a private key and the RS would verify with the corresponding public key (RS256/ES256 + JWKS). The reference's separated RS demonstrates the architectural property - the symmetric-key limitation means RS compromise yields mint capability in this configuration.
- **Demo-mode signer co-location.** `bridge.consent.demo_signer` produces the user signature on the server side because the demo cannot launch a separate user-key custodian, signing directly over the stored `ProposedAction` rather than accepting a client-submitted payload. A production Tier-2 deployment must (a) move signing client-side (WebAuthn / Passkey) and never hold the user signing key in the bridge process, and (b) when the client submits the signed payload back, verify that the payload's `(command, args, rar_type, approver_id)` matches the stored `ProposedAction` before forwarding to `Vault.mint`. The demo's server-side signing skips this step because it cannot drift by construction. The production shape can drift and must check.
- **In-memory consumed-jti set.** Both `OAuthVault` and `JwtResourceServer` track single-use state in process memory. A Vault/RS restart inside the JWT TTL discards the record. Production deployments must back this with a durable TTL-aware store (sqlite, Redis). Tier 1 is structurally closed against this because `_issued` is also process-local (post-restart credentials fail at `SignatureMismatch`, not as replays).
- **Independent consent surface (production deployment shape).** Constraint 3 above is a property of *deployment topology* and the demo cannot deliver it on its own: the demo's URL-mode consent server runs on the bridge for self-containedness. In production with WebAuthn / Passkey, the bridge ships JS that builds the canonical bytes the user's signer signs — so a hostile bridge can render "Read email" while composing bytes for "Delete database." The fix is to put the consent surface on an authorization server in a separate trust domain from the bridge, so the user signs what the AS displays, not what the bridge displays. This is the standard FAPI 2.0 deployment shape.
- **No approver-authorization policy.** `PolicyDenied` is defined as a typed exception but never raised by either Vault. `approver_id` is carried through the signed payload and JWT `sub` for attribution, not for enforcement. A production AS would consult an RBAC/ABAC policy here.
- **MCP bearer auth is authentication-only at the transport.** `bridge/mcp/auth.py` constructs a `CallerIdentity` from a valid bearer (carrying the scopes the `TokenStore` issued the token with). Scope-vs-tool enforcement happens at the dispatcher (`bridge/core/dispatcher.py`, exercised by `tests/e2e/test_scope_enforcement.py`), not at the transport. Any non-MCP surface that bypasses the dispatcher (e.g. a future direct A2A executor) must apply the same `required_scopes` check itself.
- **MCP elicitation emission is not bundled.** The reference includes the `tools/list` + `tools/call` (read-only) wiring and the URL-mode consent server, but server-side emission of an MCP `elicitation/create` event on a HITL-gated tool call is not yet implemented in `bridge/mcp/server.py`. The building-blocks integration test (`tests/e2e/test_mcp_hitl_building_blocks.py`) demonstrates the translation, consent, Vault, and RS composition by hand. Wiring the elicitation primitive into the MCP server is the natural next step.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

---

## A note on AI usage

This repository was built with AI assistance for development. Planning, review, and testing were performed manually by the maintainer - the AI did not review or sign off on its own output.
