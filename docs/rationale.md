# System Rationale and Security Architecture

This document defines the architectural rationale for the Agent-to-Agent (A2A) and Model Context Protocol (MCP) bridge. Where `architecture.md` details interface implementations and message schemas, this document analyzes the failure domains, cryptographic constraints, and operational tradeoffs governing system behavior.

## The Interactive Authorization Problem

Modern authorization infrastructure (such as HashiCorp Vault, OAuth 2.0 authorization servers, and role-based access control systems) relies on static, predeclared access policies. When two backend microservices communicate, an authorization server can evaluate static identity attributes, scopes, and network boundaries to issue a token.

Large language model (LLM) agents break this static evaluation model. An agent plans dynamically and constructs contextual, state-modifying commands that cannot be predicted or safely permitted through coarse-grained static policies. Granting an agent long-lived destructive permissions introduces vulnerability to prompt injection, parameter drift, and privilege escalation.

The challenge in agent authorization is connecting high-level autonomous reasoning to low-level infrastructure controls without giving the agent persistent authority over destructive APIs. This requires converting the human operator into a dynamic policy evaluator at the exact moment of execution.

```
[Agent proposes action] ──> [Human verifies and signs canonical parameters]
                                 │
[Action executed] <── [RS verifies token] <── [Vault issues single-use token]
```

To achieve this, the system enforces a strict delegation model:
- The agent holds only read-only or non-destructive baseline credentials during standard operation.
- Every state-modifying command generates an explicit authorization request containing the exact target action and parameters.
- An authenticated human signs these parameters using a cryptographic key outside the agent's control.
- An authorization server verifies the human signature and issues a short-lived, single-use credential bound to the approved parameters.
- The target resource server independently validates the credential against the live request before executing the command.

---

## The Four Invariant Constraints

A system that mediates destructive tool execution through human authorization must enforce four invariant properties simultaneously. Missing any single property creates an exploitable security boundary failure.

| Constraint | Enforcement Mechanism | Failure Mode if Omitted |
| :--- | :--- | :--- |
| **1. Parameter-Bound Intent** | Signatures computed over RFC 8259 canonical bytes containing `(cmd, args, rar_type, exp, approver_id, binding_message)` | **Parameter Drift Attack**: An agent modifies arguments after obtaining human approval, executing an unauthorized mutation under an approved umbrella. |
| **2. Consent Atomicity** | Authorization server records canonical payload hashes and enforces single-token issuance per signature | **Mint Replay Attack**: An intermediary or compromised agent captures a signed payload and mints multiple credentials, turning one human approval into multiple executions. |
| **3. Independent Consent Surface** | User consent interface runs in an isolated trust domain separate from the agent orchestration environment | **Display Deception**: A compromised agent displays benign text to the human while passing destructive parameters to the signer. |
| **4. Destination Gating** | Resource server verifies authorization token and parameter match on all mutation endpoints | **Direct API Bypass**: An agent discovers the direct resource server endpoint and executes state modifications without interacting with the bridge. |

In this reference implementation, constraints 1, 2, and 4 are enforced programmatically in code. Constraint 3 represents a deployment topology requirement: while the local demonstration hosts a consent endpoint in-process for self-contained testing, production deployments require hosting the consent interface within a distinct authorization server domain.

---

## Execution Topologies: Single-Domain vs. Multi-Domain Transport

Cryptographic security in this architecture originates entirely from the parameter-bound token exchange, not from the network protocols carrying the payload. Network transports act solely as carriers that pause execution, bubble authorization requirements to the user, and resume upon approval.

The system supports two distinct execution topologies based on whether the workflow spans trust domains:

```
Single-Domain Workflow:
[MCP Host / Client] ──tools/call──> [Agent Service] ──URL elicitation──> [Human Browser / AS]
        │                                 │                                    │
        └────── resumes on retry ─────────┴──────── consumes signed token ─────┘

Multi-Domain Workflow:
[Orchestrator Agent] ──A2A task──> [Sub-Agent] ──auth_required SSE──> [Human Signer]
        │                               │                                  │
        └────── resumes via task ───────┴──────── submits signed payload ──┘
```

### Single-Domain Execution (MCP URL Elicitation)

When a workflow operates within a single agent boundary, no agent-to-agent protocol is needed. The agent service exposes tools via MCP over HTTP:

- When a client invokes a sensitive tool via `tools/call`, the service pauses execution and returns a `URL_ELICITATION_REQUIRED` error pointing to the consent interface.
- After the operator reviews the parameters and signs the canonical payload, the client retries the tool invocation.
- The service then resumes execution using the verified single-use credential (`bridge/mcp/hitl.py`).

### Multi-Domain Delegation (A2A Task Lifecycle)

When a primary agent delegates a subtask to an external or third-party agent, the authorization request must cross process and administrative boundaries without passing bearer tokens.

The A2A protocol provides the structured task lifecycle required for this delegation:

- The sub-agent pauses execution and emits an `auth_required` server-sent event (SSE) containing the Rich Authorization Requests (RAR, RFC 9396) payload.
- The translation module (`bridge/translation/a2a_mcp.py`) maps this event into an MCP elicitation request while preserving `context_id` continuity and byte-level payload identity.
- The human signs the payload, and the response resumes the paused A2A task with the valid signature.

---

## Three-Layer Enforcement Architecture

Tier-2 configurations divide authorization and execution into three decoupled enforcement layers, ensuring defense in depth across system boundaries.

```
           Layer 1: Pre-Mint Verification
           [Human Signature] ──> [OAuthVault / Auth Server]
                                       │ (verifies signature, checks TTL, records hash)
                                       ▼
           Layer 2: Pass-Through Forwarding
           [Minted JWT] ───────> [Dispatcher / Bridge]
                                       │ (unmodified forwarding to resource server)
                                       ▼
           Layer 3: Live Request Validation
           [Incoming Request] ─> [JWT Resource Server]
                                       │ (validates signature, checks aud/exp, verifies args)
                                       ▼
                                 [Execution]
```

### Layer Responsibilities

- **Layer 1: Pre-Mint Verification (`OAuthVault.mint`)**: The authorization server validates the human Hash-based Message Authentication Code (HMAC) signature against the canonical authorization bytes. It enforces the maximum allowed time-to-live (`max_signed_payload_ttl_seconds`) and tracks consumed payload hashes to prevent mint-level replay.
- **Layer 2: Structural Pass-Through (`Dispatcher._execute_via_rs`)**: The bridge forwards the minted token directly to the resource server without modification. This property is structural: the dispatcher does not possess credentials to alter token claims.
- **Layer 3: Live Request Validation (`JwtResourceServer.execute`)**: The resource server independently decodes the token, checks signature validity, ensures the token has not been consumed (`jti` tracking), and validates that the `authorization_details` claim strictly matches the incoming command arguments.

### Trust Boundary Asymmetry

The three layers exhibit a critical structural asymmetry:
* **Post-Mint Isolation**: Layers 2 and 3 operate independently. A software defect in the dispatcher cannot compromise the resource server's verification logic.
* **Pre-Mint Trust Root**: Layer 1 serves as the sole trust root for human intent. Because the human HMAC signature is not embedded directly within downstream JWT claims, an authorization server defect that mints tokens without verifying the signature cannot be detected by the resource server. Layer 1 protects whether a credential should exist; Layers 2 and 3 protect how that credential is used.

---

## Graduated Deployment Tiers

System security scales across three deployment tiers. Teams should select a tier based on their threat model and infrastructure capabilities.

| Property | Tier 0: Unbounded Baseline | Tier 1: In-Process Gate | Tier 2: Separated Architecture |
| :--- | :--- | :--- | :--- |
| **Destructive Credential Location** | Stored in agent process | Stored in agent process | Retained only by Resource Server |
| **Verification Gate** | None | In-process HMAC validator | External Vault and Resource Server |
| **Mitigates Prompt Injection** | No | Yes | Yes |
| **Mitigates Parameter Drift** | No | Yes | Yes |
| **Mitigates Agent Compromise** | No | No | Yes |
| **Infrastructure Overhead** | None | Zero (shared symmetric key) | Dedicated AS, RS, and JWKS infrastructure |
| **Reference Class** | `None` | `InProcessVault` | `OAuthVault` + `JwtResourceServer` |

- **Tier 0** represents standard industry agent deployments where tools execute with ambient credentials.
- **Tier 1** eliminates prompt injection and parameter tampering at minimal operational cost using an in-process verifier (`InProcessVault`).
- **Tier 2** isolates credentials entirely, ensuring that compromising the agent host grants no persistent mutation rights over backend systems.

---

## Comparative Analysis: Identity Step-Up vs. Parameter Authorization

The Model Context Protocol elicitation primitive has also been explored in standards work, most notably in the individual Internet Engineering Task Force (IETF) submission [`draft-embesozzi-oauth-agent-native-authorization-00`](https://datatracker.ietf.org/doc/draft-embesozzi-oauth-agent-native-authorization/) (M. Besozzi, 2026).

Understanding how this reference relates to the Besozzi draft clarifies the boundary between user identity and action authorization:

```
Identity Verification (Besozzi Draft):
[Agent Request] ──> [MCP Elicitation] ──> [User completes TOTP/WebAuthn] ──> "User identity confirmed"

Action Authorization (This Reference):
[Agent Request] ──> [MCP Elicitation] ──> [User signs canonical params] ──> "Action parameters approved"
```

| Dimension | Besozzi IETF Draft | This Architecture |
| :--- | :--- | :--- |
| **Elicitation Payload** | Authenticator challenges (WebAuthn, TOTP, push notifications) | RFC 9396 Rich Authorization Request (`authorization_details`) |
| **Primary Question** | "Is this the authenticated user?" (Identity step-up) | "Did this user authorize this exact state change?" (Action authorization) |
| **Credential Lifecycle** | Standard OAuth session tokens held by agent | Ephemeral, single-use credentials bound to specific parameters |

Because the two approaches address different layers of the security handshake, enterprise environments can deploy Besozzi's pattern to establish authenticated identity and this design's pattern to constrain high-risk actions.

---

## System Invariants and Operational Guarantees

This rationale commits the bridge implementation to four system guarantees:

1. **State Continuity**: Conversation state is preserved across pauses and retries using deterministic `context_id` tracking.
2. **Protocol Fidelity**: The bridge preserves byte-level identity of `authorization_details` during translation between A2A and MCP envelopes without re-serializing or mutating fields.
3. **No Ambient Destructive Authority**: Agent processes never retain long-lived tokens with write permissions.
4. **Delegation Role**: The bridge operates strictly as a protocol translator and delegation coordinator, never making autonomous authorization decisions.
