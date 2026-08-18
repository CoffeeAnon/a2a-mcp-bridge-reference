# Stateless MCP Specification Alignment and Documentation Refactor Plan

This plan specifies the implementation steps required to align `a2a-mcp-bridge-reference` and companion documentation with the **2026-07-28 Model Context Protocol (MCP) specification** (stateless HTTP transport, Model Request Time Request / MRTR continuations) and complete the repository-wide prose refactoring into target technical and product registers.

---

## 1. Context and Problem Statement

The 2026-07-28 MCP specification updates the HTTP transport from session-oriented connections (`initialize` handshakes and `Mcp-Session-Id` headers) to self-describing stateless requests. 

While the underlying cryptographic delegation model (RFC 9396 Rich Authorization Requests, parameter-bound canonical bytes, dispatcher scope gating) remains invariant, stateless HTTP turns **storage locality into a security boundary**:
1. In-process replay registries (`_consumed_signatures` and `_consumed` `jti` sets) are process-local.
2. In a round-robin load-balanced cluster, a single signed approval payload can be submitted to and accepted once by each independent replica.
3. The server must separate process-local state from durable atomic state, replace deterministic session IDs with 256-bit expiring continuation handles, and support MRTR (`inputResponses`) resumption.

Simultaneously, the repository documentation and personal site companion essays require prose refactoring to eliminate formulaic machine patterns and adhere to established architectural (Kleppmann / Percival / Doshi) and product narrative (Marty Cagan / Amazon narrative) registers.

---

## 2. Execution Phases

### Phase 1: Test-Driven Development (TDD) Foundation `[RED]`

Write automated tests before modifying runtime code:

- [ ] **Multi-Instance Round-Robin Replay Tests (`tests/e2e/test_distributed_replay.py`)**:
  - Test case: Two distinct `InProcessVault` or `OAuthVault` instances backed by a shared storage fixture.
  - Test case: Replaying a single signed approval payload against Replica A, then Replica B. Assert Replica B raises `SignatureReplay` / HTTP 403.
  - Test case: Replaying a single minted JWT against Replica A, then Replica B. Assert Replica B rejects the consumed `jti`.
- [ ] **Stateless MCP Protocol Tests (`tests/protocol/test_stateless_mcp.py`)**:
  - Test case: Direct `tools/call` execution without prior `initialize` or `Mcp-Session-Id` header.
  - Test case: HITL pause emission yielding a 256-bit opaque continuation handle.
  - Test case: Resumption using MRTR `inputResponses` carrying the continuation handle and human signature.
- [ ] **Gateway Header Security Tests (`tests/security/test_gateway_headers.py`)**:
  - Test case: Request with mismatched `Mcp-Method` / `Mcp-Name` headers against the JSON-RPC body fails immediately with `400 Bad Request`.
  - Test case: Requests with duplicate headers are rejected.

---

### Phase 2: Core Architecture and Code Refactor `[GREEN]`

Implement the minimal architectural code changes to satisfy the test contracts:

- [ ] **Storage Seam and Replay Registry Protocol (`bridge/vault/interface.py`)**:
  - Define `ReplayRegistry` protocol with atomic test-and-set semantics (`mark_consumed_if_unseen(key, ttl_seconds) -> bool`).
  - Implement in-memory reference adapter (`InMemoryReplayRegistry`) with thread-safe atomic test-and-set.
  - Inject `ReplayRegistry` into `InProcessVault`, `OAuthVault`, and `JwtResourceServer`.
- [ ] **256-Bit Continuation Store (`bridge/mcp/hitl.py`)**:
  - Replace deterministic `consent_session_id` with cryptographically random 256-bit continuation handles.
  - Store continuation records containing `(caller_identity, canonical_action_hash, timestamp, expires_at)`.
  - Require atomic consume on resumption: loading the continuation record marks it consumed in one operation.
- [ ] **Stateless MCP Server Updates (`bridge/mcp/server.py`)**:
  - Update imports and handlers for the pinned MCP SDK (supporting 2026-07-28 stateless transport).
  - Handle MRTR continuation payloads in `tools/call` resume requests.
  - Add gateway routing header validation (`Mcp-Method` / `Mcp-Name` verification).

---

### Phase 3: Code Repository Documentation (Kleppmann / Percival / Doshi Register)

Refactor repository markdown files into direct, high-density architectural specifications:

- [ ] **`README.md`**:
  - Replace heading formulas (`## What this reference is — and what it isn't` -> `## Scope and Architectural Boundaries`).
  - Add dedicated section detailing single-process vs. distributed horizontal scale constraints under stateless MCP.
  - Clean em-dashes, aphoristic openers, and justification codas.
- [ ] **`docs/architecture.md`**:
  - Update sequence diagrams to reflect stateless HTTP requests and MRTR resume payloads.
  - Document the storage seam and the failure domain of process-local state under round-robin topologies.
- [ ] **`SECURITY.md` & `bridge/vault/CANONICAL.md`**:
  - Document gateway header spoofing mitigations.
  - Re-verify byte-level canonicalization test assertions.
- [ ] **Automated Linter Verification**:
  - Run `analyze_cadence.py` across all repository markdown files ($CV > 0.35$, 0 critical issues).
  - Run `prose-lint check` across all repository markdown files (0 critical issues).

---

### Phase 4: Personal Site Portfolio Alignment (Marty Cagan / Amazon Narrative Register)

Update companion writing pieces in `dan_jacobsen_personal_site`:

- [ ] **`content/writing/single-use-agent-tokens.md`**:
  - Clean-room rewrite focusing on **Consent Atomicity**: explain why mint-replay and consume-replay protection must be distributed when moving from stateful sessions to stateless MCP transport.
- [ ] **`content/writing/bridge-implementation-walkthrough.md`**:
  - Update the code walkthrough to reflect the new stateless server architecture, MRTR continuation hooks, and atomic replay registries.
- [ ] **Automated Verification**:
  - Run `compare_drafts.py` on both essays to track density gains, burstiness improvements, and ensure zero lint/cadence issues.

---

### Phase 5: Verification, Squashing & Merging

- [ ] **Automated Test Run**:
  - Execute full test suite: `pytest tests/`.
  - Confirm 100% pass rate across unit, protocol, security, and e2e suites.
- [ ] **Linter and Cadence Summary**:
  - Execute `analyze_cadence.py` and `prose-lint` across both repositories.
- [ ] **Branch Merge**:
  - `a2a-mcp-bridge-reference`: Squash and merge `docs/rationale-reframe` into `main`.
  - `dan_jacobsen_personal_site`: Squash and merge `writing/parameter-bound-hitl-reframe` into `master`.
