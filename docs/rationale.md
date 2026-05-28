# Design Rationale

This document captures the *why* behind the design. The companion `architecture.md` covers the *how*.

## Four necessary and sufficient constraints

A bridge that lets an LLM call destructive tools through a human-in-the-loop check has to hold four properties at once. Each is independent of the others and each fails in a specific way if missing. Together they are sufficient for the design's goal: *every change to data is approved by a named human, and the approval is verifiable from an audit log alone.*

1. **Parameter-Bound Intent.** The human's signature is computed over the canonical bytes of the exact command and arguments that will run. Without this, the LLM can swap arguments after approval (the "drift attack") and the system has no way to notice.
2. **Consent Atomicity.** One signed payload mints at most one credential. Without this, a captured signed payload (leaked WebSocket frame, compromised relay, hostile bridge holding the bytes) can be replayed to mint N credentials for the same action within the signed-payload TTL - one approval, N executions.
3. **Independent Consent Surface.** The entity that displays the proposed action to the human is in a different trust domain from the entity orchestrating the LLM. Without this, a hostile bridge can render one action on screen while passing canonical bytes for a different action to the user's signer, and the binding-message defence only catches the deception forensically after the fact.
4. **Destination Gating.** The resource server refuses any request lacking a valid Vault-minted, parameter-bound credential. Without this, an agent that finds the RS's direct API can bypass the entire architecture by calling it without a credential at all.

The reference closes constraints 1, 2, and 4 in code. Constraint 3 is a deployment-shape requirement (the demo's consent server runs on the bridge for self-containedness; see "Production deployment shape" below).

## What the bridge has to be

A useful A2A↔MCP bridge holds the four constraints above plus two protocol-level properties:

1. **Stateful.** `context_id` continuity across calls.
2. **HITL-aware.** A2A's `auth_required` SSE state translated to an MCP elicitation, with the resume routing back to the paused task.

A stateless bridge fragments conversations; a HITL-unaware bridge cannot route destructive proposals to a human at all. The two patterns below realise the four constraints inside that protocol shape.

## The two patterns

The reference demonstrates two distinct contributions.

### Pattern 1: Protocol orchestration

`bridge.translation` translates between A2A's task-lifecycle SSE shape and MCP's elicitation shape. The translation preserves three properties:

- **`context_id` continuity.** The MCP elicitation carries an `elicitation_id` derived from the A2A context, so the resume message routes back to the paused task.
- **`authorization_details` byte-identity.** The bridge does NOT re-canonicalise. What the agent proposed is exactly what the human signs.
- **URL-mode elicitation.** Required by MCP 2025-11-25 for sensitive consent.

### Pattern 2: Cryptographic delegation

`bridge.vault` and `bridge.rs` realise constraints 1, 2, and 4 across three independent enforcement layers:

1. **Vault verifies the human signature and tracks signed-payload single-use.** Constraint 1 (parameter binding) and constraint 2 (consent atomicity) both close here. The Vault verifies the HMAC over canonical authorization-details bytes and refuses to mint twice from the same signed payload (`_consumed_signatures`). One signature exchanges for one credential.
2. **Bridge cannot alter** what the Vault minted: a JWT pinned to the approved parameters. (Structural property of the dispatcher's pass-through, asserted by code inspection.)
3. **Resource server validates** the credential's `authorization_details` claim against the live request, with its own consumed-jti state. Constraint 4 (destination gating).

The bridge sits in the data path of every authorization decision but in the trust path of none of them. This is the RAR-shaped pattern (RFC 9396 per-action `authorization_details` + per-action mint + RS enforcement) adapted from open-banking FAPI 2.0 deployments to agent authorization. FAPI 2.0 layers further mechanisms on top (mTLS, DPoP, PAR) that this reference does not implement - the *core* RAR-binding pattern is what it draws on.

**Layer asymmetry.** Layers 2 and 3 are mutually independent: a bug in either does not compromise the other. Layer 1 is the trust root for the human-signature property. The RS has no path to re-verify the human's HMAC (it is not in the JWT claims), so an `OAuthVault` bug that mints without verifying the human signature would not be caught downstream. Read carefully: Layers 2 and 3 protect what happens *after* mint; Layer 1 protects whether mint should have happened at all.

### Constraint 3: Independent consent surface in production

Constraints 1, 2, and 4 are properties of code. Constraint 3 is a property of *deployment shape* and cannot be enforced by the bridge alone: the bridge is the entity the constraint is constraining.

The demo's URL-mode consent server (`bridge/consent/url_mode.py`) runs on the bridge process so the reference is self-contained. In that configuration, the `ProposedAction` is `frozen=True` + `MappingProxyType`, so the display and the signed bytes come from the same immutable record - the demo cannot drift the display by construction. The `binding_message` is also part of the canonical bytes, so even in a richer in-process configuration, a render-vs-sign drift produces a signature the Vault rejects (`tests/e2e/test_three_layer_enforcement.py::test_vault_rejects_binding_message_swap`).

What none of those defences cover: a production deployment with WebAuthn / Passkey at the user, where the bridge ships JavaScript to the user's browser. The JS computes canonical bytes for the action and calls `navigator.credentials.get(...)` with that as the challenge. A hostile bridge can render "Read email" HTML while composing canonical bytes for "Delete database" and generating a matching `binding_message`. The user's signer signs honestly; the user was deceived. The signature verifies. The credential mints.

The architectural fix is to put the consent surface in a different trust domain from the bridge - a separate authorization-server-hosted consent page that parses and renders the raw `(command, args)` itself, independent of any HTML the bridge supplies. The user's signer is then signing what the AS displays, not what the bridge displays. This is the standard FAPI 2.0 deployment shape and is the production form constraint 3 requires.

The reference does not bundle a separate AS process because the architectural mechanics it teaches do not depend on the separation - the demo's frozen `ProposedAction` is the same property a separate AS would enforce, just inside one process. The production swap is a deployment-topology change, not a code change to the Vault contract.

## Three deployment tiers, graduated by threat surface

Most published bridges sit at Tier 0; going to Tier 1 closes the dominant threat at near-zero infrastructure cost. Going from Tier 1 to Tier 2 closes a real but secondary threat at significant infrastructure cost. Teams should pick deliberately.

| | Tier 0 | Tier 1 | Tier 2 |
|---|---|---|---|
| Agent holds destructive creds? | Yes | Yes | No |
| Gate location | None | In-process HMAC verifier | External Vault mint + RS validation |
| Prompt injection / LLM drift | ❌ | ✅ | ✅ |
| Agent-process compromise | ❌ | ❌ | ✅ |
| Infrastructure required | None | None (one shared secret) | Vault, RAR-aware RS, OAuth client |
| Reference implements | — | `InProcessVault` | `OAuthVault` + `JwtResourceServer` |

## The interactive last-mile

A Vault closes Zero Trust enforcement: short-lived, downscoped credentials, issued only when policy permits. But Vaults are designed for **non-interactive** authorization decisions. They evaluate a request against static attribute-based policies and answer "issue" or "deny." That model is correct for service-to-service calls where the policy can be predeclared. It is the *wrong* model for agentic workflows, where the LLM proposes contextual, sometimes novel destructive actions that cannot all be encoded as static ABAC rules in advance.

IBM Verify frames this as the **agentic last-mile problem**: the gap between high-level agent reasoning and grounded backend infrastructure, where the database, message broker, or production system has no way to know who the original human was or what they intended.

**The bridge resolves this gap by turning the human into the Vault's dynamic policy engine.** Instead of asking the Vault to evaluate a contextual destructive action from static attributes alone, the bridge intercepts the agent's `auth_required` event, surfaces the proposed action to the human via MCP elicitation, and accepts a signed RAR payload as the human's *just-in-time* policy decision. The Vault no longer guesses - it mints single-use tokens backed by explicit human delegation for exactly the operation the human approved.

This is what makes the bridge non-redundant with a Vault. The Vault gives you Zero Trust enforcement - the bridge gives you *interactive* Zero Trust enforcement.

## Related work

The MCP elicitation primitive as an authorization-gate idea has been independently surfaced. The most concrete prior work is an **individual IETF submission**, [`draft-embesozzi-oauth-agent-native-authorization-00`](https://datatracker.ietf.org/doc/draft-embesozzi-oauth-agent-native-authorization/) (M. Besozzi, TwoGenIdentity, 2026-04-03). The draft extends OAuth 2.0 First-Party Applications with a structured-elicitations array using MCP Elicitation as the normative binding for delivering **authenticator challenges** (TOTP, WebAuthn, push notification) to a human via an agent.

Standardization status caveat: this is an *individual* IETF draft (`draft-<author>-...`), not a working-group draft (`draft-ietf-<wg>-...`). The draft is citable - the citation weight is "another team is thinking along similar lines," not "the IETF is converging on this."

The scope distinction is informative:

| | Besozzi draft (individual submission) | This work |
|---|---|---|
| Elicitation carries | Authenticator challenges (TOTP/WebAuthn/push) | Action-approval payloads (RAR `authorization_details`) |
| Question answered by the elicitation | "Prove this is the user" (identity step-up) | "Did this user approve this specific action with these parameters?" |
| Vault-style cryptographic delegation | Out of scope; agent acts as FiPA client | Tier 2: agent holds no destructive credentials |

The two efforts are complementary. A complete enterprise deployment plausibly wants both: Besozzi's pattern for *"is this the right human, freshly authenticated?"* and this work's pattern for *"did this human approve this specific destructive action?"* They compose at the MCP elicitation layer.

## What this rationale commits the design to

This page commits the bridge design to the four constraints at the top of this document - parameter-bound intent, consent atomicity, independent consent surface (production deployment), destination gating - plus three protocol-level properties:

- **Stateful.** `context_id` continuity across MCP tool calls. *All tiers.*
- **HITL-aware.** `auth_required` SSE event translated to MCP elicitation, with resume-via-`message:send`. *All tiers above Tier 0.*
- **Translation-only, not policy-bearing.** The bridge translates between protocol envelopes but does not make authorization decisions. At Tier 2 this strengthens to *delegation-engine*: the bridge presents the human's signed approval to a Vault and receives a freshly-minted, single-use, action-scoped token. The agent holds no persistent destructive credentials between transactions.

See `architecture.md` for the components, flows, and threat model that hold these properties.
