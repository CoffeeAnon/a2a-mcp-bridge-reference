# Architecture

Companion to `rationale.md`. The rationale answers *why*; this document answers *how*: components, flows, and the threat model.

## Components

```
                       ┌──────────────────────────────────┐
                       │   Human (approver device)        │
                       │   - Web browser (consent UI)     │
                       │   - Phone (CIBA push)            │
                       └──────────────┬───────────────────┘
                                      │ approves / denies
                                      │ (RAR consent screen)
                                      ▼
                       ┌──────────────────────────────────┐
   ┌──── signed ──────▶│   Vault / Delegation Engine     │
   │   RAR payload     │   (OAuth AS, HashiCorp Vault,    │
   │  (HMAC over       │    Entra, IBM Verify, …)         │
   │   authorization_  │                                  │
   │   details)        │   verifies human signature →     │
   │                   │   mints single-use JWT w/        │
   │                   │   authorization_details          │
   │                   │   (RFC 9396), short exp          │
   │                   └──────────────────────────────────┘
   │                                  ▲
   │                                  │ token introspect / JWKS
   │                                  │
   │   ┌──────────────────────────────┴──────────────────────────────┐
   │   │                  Agent service (this reference)             │
   │   │                                                             │
   │   │   ┌────────────────────────┐    ┌────────────────────────┐  │
   │   │   │  A2A surface           │    │  MCP surface           │  │
   │   │   │  (production wiring;   │    │  (`/mcp`)              │  │
   │   │   │   simulated by         │    │  - tools/list           │  │
   │   │   │   bridge.walkthrough)  │    │  - tools/call           │  │
   │   │   └────────────┬───────────┘    └────────────┬───────────┘  │
   │   │                │                              │              │
   │   │                └───────────┬──────────────────┘              │
   │   │                            ▼                                 │
   │   │              ┌──────────────────────────────┐                │
   │   │              │  Tool dispatch + HITL gate   │                │
   │   │              │  (bridge.core.dispatcher)    │                │
   │   │              │  - resolves tool by name     │                │
   │   │              │  - if requires_approval:     │                │
   │   │              │      route to RS (Tier 2)    │                │
   │   │              │      or Vault (Tier 1)       │                │
   │   │              └──────────────────────────────┘                │
   │   │                            │                                 │
   │   └────────────────────────────┼─────────────────────────────────┘
   │                                ▼
   │              ┌──────────────────────────────┐
   │              │  Resource server              │
   │              │  (bridge.rs.JwtResourceServer)│
   │              │                               │
   │              │  - validates Bearer token     │
   │              │  - verifies                   │
   │              │    authorization_details      │
   │              │    matches request            │
   │              │  - executes (or rejects on    │
   │              │    drift / replay)            │
   └──────────────┴──────────────────────────────┘
```

## The Vault contract

Both `InProcessVault` (Tier 1) and `OAuthVault` (Tier 2) satisfy a single `Vault` Protocol:

- **`mint(signed_authorization_details) → MintedCredential`**: verify the human signature, then mint a single-use, action-scoped credential bound to the approved arguments. Both implementations bound the signer's requested `exp` against a `max_signed_payload_ttl_seconds` policy (default 600s); an over-long signed payload is rejected as `PayloadDriftAtMint` rather than minted.
- **`consume(credential, command, args) → MintedCredential`**: validate the credential against the live request at execution time. Mark consumed. Reject replays, drift, expiry, and signature mismatches with typed exceptions.

**Structural binding at the bridge.** Between elicitation emission and signing, the bridge holds the proposed action in a `ProposedAction` dataclass (`bridge.consent.url_mode`) that is `frozen=True` with `args` wrapped in `types.MappingProxyType` over a deep-copy. Re-assignment is blocked by the frozen dataclass, and in-place mutation is blocked by the read-only mapping. The "credential is bound to the parameters the human approved" property reduces to this immutability plus the canonical-bytes contract: there is no point in time between emission and signing at which the bridge can alter what the human is being asked to sign.

The dispatcher calls `consume` (or, in the Tier-2 separated-RS shape, forwards the credential to the RS, which performs the equivalent validation independently). The bridge layer calls `mint` in response to an elicitation approval.

## Three independent enforcement layers (Tier 2)

The central architectural claim, three independent enforcement layers, is exercised through real code paths by `tests/e2e/test_three_layer_enforcement.py`:

1. **Vault verifies the human signature** *before* minting (`OAuthVault.mint`). Raises `SignatureMismatch` on bad signature, `CredentialExpired` if the signed payload is already past its `exp`, and `PayloadDriftAtMint` if `exp` exceeds the Vault's `max_signed_payload_ttl_seconds`.
2. **Bridge forwards the minted credential unmodified** to the RS (`Dispatcher._execute_via_rs` is a 4-line pass-through). Layer 2 is structural: a property of the dispatcher's pass-through implementation, asserted by code inspection rather than by a dynamic test. Layer 3 catches any deviation if it occurs.
3. **Resource server validates independently** (`JwtResourceServer.execute`): own verification key, own `iss`/`aud`/`exp` checks, own consumed-jti state, own `authorization_details`-vs-live-request binding check.

The bridge is in the data path of all three layers but in the trust path of none of them.

**Asymmetry worth surfacing.** Layers 2 and 3 are mutually independent - a bug in either does not compromise the other. **Layer 1 is the trust root for the human-signature property**: the RS has no access to the human's HMAC (it's not embedded in the minted JWT's claims), so an `OAuthVault` bug that mints without verifying the human signature is *not* caught downstream. The threat-model row "Vault compromise - out of scope" acknowledges this trust-root status. Read this way, Layers 2 and 3 protect *what happens after mint*; Layer 1 protects *whether mint should have happened at all*.

## HITL flow walkthroughs

### `delete_task` invoked through the A2A surface (target architecture)

```
Client                       Agent service                 Vault                 RS
  │                                  │                       │                    │
  │── POST /a2a (delete) ───────────▶│                       │                    │
  │                                  │ validate t-base       │                    │
  │                                  │  (tasks.read only)    │                    │
  │                                  │ dispatch sees         │                    │
  │                                  │ requires_approval     │                    │
  │◀── SSE: auth_required            │                       │                    │
  │    parts=[DataPart {             │                       │                    │
  │      authorization_details,      │                       │                    │
  │      binding_message }]          │                       │                    │
  │                                  │                       │                    │
  │ (human approves; client signs    │                       │                    │
  │  HMAC over canonical bytes)      │                       │                    │
  │                                  │                       │                    │
  │── POST /a2a (resume with         │                       │                    │
  │   approved + signature) ────────▶│                       │                    │
  │                                  │── present signed     ▶│                    │
  │                                  │   RAR for verify     │                    │
  │                                  │   + mint              │                    │
  │                                  │◀── single-use JWT ────│                    │
  │                                  │                       │                    │
  │                                  │── DELETE /tasks/X ───────────────────────▶│
  │                                  │   Bearer t-delete-X   │                    │
  │                                  │                       │                    │ validate token,
  │                                  │                       │                    │ match auth_details
  │                                  │                       │                    │ to live request,
  │                                  │                       │                    │ mark consumed,
  │                                  │                       │                    │ delete
  │                                  │◀──────── 204 ─────────────────────────────│
  │◀── SSE: completed                │                       │                    │
```

### `delete_task` invoked through the MCP surface

```
MCP host (LLM)              Agent service                    Vault                RS
  │                               │                            │                   │
  │── tools/call delete_task ────▶│                            │                   │
  │                               │ dispatch sees              │                   │
  │                               │ requires_approval          │                   │
  │                               │ → build authorization_     │                   │
  │                               │   details                  │                   │
  │◀── elicitation/create        │                            │                   │
  │    {mode:"url",               │                            │                   │
  │     url: bridge/consent/…}    │                            │                   │
  │                               │                            │                   │
  │ (human visits URL, reviews    │                            │                   │
  │  action, signs)               │                            │                   │
  │                               │                            │                   │
  │── elicitation/response       │                            │                   │
  │    accept + signed payload ──▶│                            │                   │
  │                               │── present signed RAR ─────▶│                   │
  │                               │◀──── minted JWT ───────────│                   │
  │                               │                            │                   │
  │                               │── DELETE /tasks/X ────────────────────────────▶│
  │                               │◀──── 204 ─────────────────────────────────────│
  │◀── tools/call result         │                            │                   │
```

The trust dance is identical across both surfaces - only the protocol envelope differs.

## State and persistence

### `context_id` continuity

The agent service keys conversation state by `context_id`. A new MCP `tools/call` carrying a `context_id` (via the `elicitation_id`-derived round-trip in `bridge.translation`) resumes the same conversation. A call without a `context_id` opens a new one.

In the reference, the consent server's session-id is the carrier: `elicitation_id = "el:<context_id>:<task_id>"`. The bridge recovers `context_id` from the elicitation response in `bridge.translation.mcp_elicitation_response_to_a2a_resume`.

### Token lifecycle

- **Base token**: long-lived per-session token issued at agent-client setup time, carrying minimum scope (e.g., `tasks.read`). Validated on every request.
- **Per-action minted credential**: single-use, short-lived (5 min default), parameter-bound. Acquired through the Vault mint flow at the moment of approval. Validated on the dispatch / RS call.

Restart caveat: the consumed-jti set in `OAuthVault` and `JwtResourceServer` is process-local. A bridge or RS restart inside the JWT TTL discards the record. Production deployments must back this with a durable TTL-aware store (sqlite, Redis). Tier 1 is structurally closed against this because `_issued` is also process-local - post-restart credentials fail at `SignatureMismatch`, not as replays.

### Audit attribution

Every dispatch event writes an audit row (`bridge.audit.AuditSink`). The bundled CLI emits `tool_call` rows. Richer kinds (`approval_granted`, `approval_rejected`, `error`) are schema-supported but not exercised by the reference.

## Failure modes

| Mode | Behaviour |
|---|---|
| HITL approval denied | Bridge polls consent → "denied" → resume with `approved=False` → dispatcher returns `ApprovalRequired` with `reason="decline"`. |
| HITL approval timeout | Consent session expires; bridge sees no signed payload; resume with `approved=False`. |
| Parameter mismatch at consume | `CredentialDrift` exception → `ApprovalRequired(reason="CredentialDrift")` from the dispatcher. The RS never executes the drifted action. |
| Server restart during pause | Pending HITL gates are not persisted; an attempted resume returns `SignatureMismatch` (Tier 1) or fails at the RS's empty consumed set (Tier 2). |
| Token re-use | Per-action credentials are single-use; second consume attempt → `CredentialReplay`. **Caveat:** within the signed-payload TTL, a captured signed payload can produce *multiple* distinct credentials for the *same* `(command, args)`. Reference enforces "fresh consent per action shape", not "fresh consent per execution"; the RS must add per-action idempotency for actions where double-execution is consequential. |

## Threat model

| Threat | Mitigation |
|---|---|
| **Prompt-injected agent** attempts destructive action. | The agent holds no `tasks.delete` credential. A delete attempt produces an `auth_required` event that the human must approve via their MCP host. The injected instruction cannot bypass the human-consent step because the consent step is what *creates* the credential. |
| **Compromised agent process.** | In production-shape: agent holds only the read-scoped `t-base`. Per-action tokens exist only between Vault mint and RS consumption. **In the reference's HS256 demo**, both `user_signing_secret` and `mint_secret` are co-located in the agent process for self-containedness; an attacker has both, and only the "fresh-consent-per-action-shape" property remains as a barrier. Production Tier-2 must move signing client-side (WebAuthn/Passkey). |
| **Parameter drift after approval.** | Three independent layers reject (`tests/e2e/test_three_layer_enforcement.py`): (1) bridge signs over the *emitted* `authorization_details`, held in a frozen `ProposedAction` with `MappingProxyType` args (structural; re-assignment and in-place mutation both blocked between emission and signing); (2) Vault refuses to mint if the HMAC doesn't verify; (3) RS validates the minted token's `authorization_details` against the live request. |
| **Token replay across actions.** | Single-use at the RS via consumed-jti tracking. The token is also pinned to specific `authorization_details`, so capturing it gives no leverage outside the original action. **Carve-out:** single-use is enforced at *consume* (per-jti), not at *mint* (per-signed-payload). A captured signed payload can mint multiple credentials for the *same* `(command, args)` until the signed-payload TTL expires. Reference enforces "fresh consent per action shape", not "fresh consent per execution"; for actions where double-execution matters, the RS must add per-action idempotency or the Vault must track consumed signed-payload signatures at mint time. See §"Failure modes" item "Token re-use" for the operational discussion. |
| **Bridge compromise.** | In production-shape: the bridge cannot mint tokens unilaterally - minting requires a verified human signature, and the user signing key is held by the human's MCP host. Bridge compromise allows re-mint within TTL for previously-approved actions but cannot fabricate signatures for *new* actions. **In the reference's demo configuration**, the bridge holds the user signing key via `bridge.consent.demo_signer`; a bridge compromise is equivalent to a human-key compromise. The demo signer module is the seam to replace. |
| **Vault compromise.** | Out of scope - the Vault is the trust root. Standard Vault-hardening practices apply. |
| **Human-side key compromise.** | Reduces to "attacker is the human." Mitigations are out-of-band: WebAuthn-bound keys (TPM / Secure Enclave), short-lived user-side signing keys. |
| **Denied-action retry without re-approval.** | Retry produces a fresh `auth_required` event. No cached approvals. |

## What the reference deliberately leaves out

- **Real OAuth authorization server**: `OAuthVault` is an HS256 in-process stand-in for the architectural shape. Production deploys swap in Keycloak/Authlete/Auth0/Curity etc.
- **Durable consumed-jti storage**: in-memory `set()` in the reference; production must use sqlite/Redis.
- **Client-side signing key custodian**: the bundled `bridge.consent.demo_signer` runs server-side. Production must use WebAuthn / Passkey on the human's MCP host.
- **A2A executor wiring**: the A2A surface is described and simulated by `bridge.walkthrough`, not bundled as live code. Production A2A integrations write their own executor over the same Vault/dispatcher core.
- **MCP elicitation emission**: the bundled MCP server implements `tools/list` + `tools/call` (read-only). Server-side emission of `elicitation/create` on a HITL-gated tool is the natural next step; the building-blocks integration test (`tests/e2e/test_mcp_hitl_building_blocks.py`) demonstrates the translation + consent + Vault + RS composition by hand.
- **Multi-tenant federation**: single AS / single RS / single bridge. Federated deployments are a deployment concern.
- **DPoP** (RFC 9449) for sender-constrained tokens: strongly recommended for production. Mitigates token theft over the wire; not modelled in the threat-model table.
- **Untrusted MCP host**: the bridge trusts the MCP host to route elicitation responses faithfully. The `elicitation_id` is a process-local HMAC-tagged carrier (`el:<context_id>:<task_id>:<tag>`), so a host that does not hold the tag secret cannot fabricate IDs; but a cooperating-but-replica host might still need a different carrier. The reference is designed for cooperative MCP hosts the human controls (Claude Desktop, IDE, custom orchestrator); a multi-replica or shared-host deployment that needs cross-host routing safety must share the tag secret or replace the elicitation-ID shape with a signed token. See the docstring in `bridge.translation.a2a_mcp` for the rationale.

## Canonical-form contract

Cross-language signers (for example, a JavaScript MCP host) must produce byte-identical canonical bytes for HMAC verification to succeed. The contract is in `bridge/vault/CANONICAL.md`. Test fixtures lock the byte-level output for known inputs, including a non-ASCII case (`ï` → `ï`); `ensure_ascii=True` is what makes the encoding stable across signers.
