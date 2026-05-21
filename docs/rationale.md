# Design Rationale

This document captures the *why* behind the two patterns this reference demonstrates. The companion `architecture.md` covers the *how*.

## What the bridge has to be

A useful A2A↔MCP bridge has to hold three properties at once:

1. **Stateful.** `context_id` continuity across calls.
2. **HITL-aware.** A2A's `auth_required` SSE state translated to an MCP elicitation, with the resume routing back to the paused task.
3. **Parameter-bound.** The human approves the specific action with the specific arguments, and only that action with those arguments runs.

Each property is independent. A bridge missing any one of them fails in a specific way: a stateless bridge fragments conversations, a HITL-unaware bridge cannot route destructive proposals to a human at all, and a bridge without parameter binding leaves the LLM free to mutate its own arguments between approval and execution. The design below holds all three.

## The two patterns

The reference demonstrates two distinct contributions.

### Pattern 1: Protocol orchestration

`bridge.translation` translates between A2A's task-lifecycle SSE shape and MCP's elicitation shape. The translation preserves three properties:

- **`context_id` continuity.** The MCP elicitation carries an `elicitation_id` derived from the A2A context, so the resume message routes back to the paused task.
- **`authorization_details` byte-identity.** The bridge does NOT re-canonicalise. What the agent proposed is exactly what the human signs.
- **URL-mode elicitation.** Required by MCP 2025-11-25 for sensitive consent.

### Pattern 2: Cryptographic delegation

`bridge.vault` and `bridge.rs` enforce parameter-bound authorization via three layers:

1. **Vault verifies the human signature** before minting any credential. (Trust-root layer - see asymmetry note below.)
2. **Bridge cannot alter** what the Vault minted: a JWT pinned to the approved parameters. (Structural property of the dispatcher's pass-through, asserted by code inspection.)
3. **Resource server validates** the credential's `authorization_details` claim against the live request, with its own consumed-jti state. (Independent verification.)

The bridge sits in the data path of every authorization decision but in the trust path of none of them. This is the RAR-shaped pattern (RFC 9396 per-action `authorization_details` + per-action mint + RS enforcement) adapted from open-banking FAPI 2.0 deployments to agent authorization. FAPI 2.0 layers further mechanisms on top (mTLS, DPoP, PAR) that this reference does not implement - the *core* RAR-binding pattern is what it draws on.

**Layer asymmetry.** Layers 2 and 3 are mutually independent: a bug in either does not compromise the other. Layer 1 is the trust root for the human-signature property. The RS has no path to re-verify the human's HMAC (it is not in the JWT claims), so an `OAuthVault` bug that mints without verifying the human signature would not be caught downstream. Read carefully: Layers 2 and 3 protect what happens *after* mint; Layer 1 protects whether mint should have happened at all.

### Single-use, with the carve-out stated

The minted credential is single-use *at consume* (per-jti). It is **not** single-use per signed-payload-at-mint. A captured signed payload can mint multiple JWTs for the *same* `(command, args)` until its TTL expires. The reference enforces "fresh consent per action shape," not "fresh consent per execution." For actions where double-execution matters (financial transfers, idempotent deletes that are not idempotent at the RS, and so on), the resource server must add per-action idempotency, or the Vault must track consumed signed-payload signatures at mint time. See `architecture.md` "Token re-use across context" for the operational discussion.

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

This page commits the bridge design to four universal properties and one Tier-2-only property:

1. **Stateful.** `context_id` continuity across MCP tool calls. *All tiers.*
2. **HITL-aware.** `auth_required` SSE event translated to MCP elicitation, with resume-via-`message:send`. *All tiers above Tier 0.*
3. **Parameter-bound.** Every approved action is bound to the exact arguments the human approved, via HMAC at Tier 1 and RAR `authorization_details` at Tier 2.
4. **Translation-only, not policy-bearing.** The bridge translates between protocol envelopes but does not make authorization decisions.
5. **Delegation-engine, not pass-through** *(Tier 2 only)*. The bridge presents the human's signed approval to a Vault and receives a freshly-minted, single-use, action-scoped token. The agent never holds persistent destructive credentials.

See `architecture.md` for the components, flows, and threat model that hold these properties.
