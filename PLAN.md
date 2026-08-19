# PLAN — Durable shared replay state for the stateless A2A↔MCP bridge

## STATUS (run 497 — completed)

Item **#1 is done and committed** (`0ad6bf7`). What actually landed:

- `bridge/vault/durable_state.py` — `DurableReplayState` (SQLite, WAL, atomic
  `INSERT OR IGNORE` claim; `timeout=30.0` busy-wait for the cross-process
  lock; read methods lock-guarded).
- Wiring (additive `durable_state` kwarg) in `InProcessVault`, `OAuthVault`,
  and `JwtResourceServer`. The in-memory branch is byte-identical when the
  kwarg is `None`, so all 130 baseline tests are untouched and green.
- `bridge/vault/__init__.py` re-exports `DurableReplayState`.
- `tests/unit/test_durable_state.py` — 13 tests (all pass), including a
  genuine two-OS-process cross-replica check (a real child `python` process
  over the same file must not re-mint / re-consume a recorded approval).
  Full suite: **143 passed, 3 failed, 4 errors** — the 7 failures are the
  pre-existing mcp 1.27→2.0 SDK renames belonging to the untouched item #2;
  no security-logic test fails.

**Deviations from this plan** (recorded in detail in `SELF_REVIEW.md`):

1. *`claim_jti`/`claim_signature` are permanent, not window-bounded.* The
   plan's test 3 asserted "re-claim after `expired_at` → True" but the
   implementation (correctly) uses `INSERT OR IGNORE`, so a record blocks
   **forever** until `purge_expired` drops it. A jti is single-use by
   definition; the consumer's exp-check runs *before* the claim, so an expired
   credential is `CredentialExpired` before it reaches the guard — permanent
   blocking is the safe direction and matches the in-memory baseline's
   "once consumed, always a replay." The test now pins the real behavior
   (re-claim only reopens via explicit `purge_expired`).
2. *Tier-1 cross-replica consume is `SignatureMismatch`, not cross-replica
   replay.* Tier 1's issuance record (`_issued`) is process-local and the
   durable store deliberately does not duplicate it (a command/args/exp record
   cannot be reconstructed from the signature table). So a Tier-1 credential
   minted on replica A and consumed on replica B fails `SignatureMismatch` —
   the same documented restart behavior. The **cross-replica *consume*
   single-use guarantee is delivered at the Resource Server** (Tier-2 JWTs are
   self-contained), which is tested. Tier-1's cross-replica guarantee is at
   **mint** time (one signature = one credential), which is also tested.
3. Items **#2 and #3 are untouched**, exactly as scoped: the mcp SDK here is
   **2.0.0** (callback API; no `@server.list_tools()` decorators), so a
   faithful 2026-07-28 stateless HTTP + MRTR migration needs `bridge/mcp/
   server.py` and the two SDK-dependent test files rewritten. De-risked in
   the "SDK findings" section below.

## Scope (this run)

THE WORK on the card lists three substantial items. Per the coordinator's
explicit instruction that *"a complete pass on one beats a rushed pass on all
three,"* this run delivers **item #1 in full**, with real, failing-capable
tests:

> 1. Make approval/session continuation, signed-payload replay, and
>    consumed-JTI state **durable, shared, TTL-aware, and atomic**; preserve
>    parameter binding and caller scope checks.

Items **#2** (migrate the HTTP surface + SDK dependency contract to the
2026-07-28 stateless protocol and implement MRTR resume) and **#3** (real
HTTP tests for stateless/MRTR/header-mismatch/cache) are **NOT touched** in
this run. They are blocked on the mcp SDK version: the staged code targets
mcp **1.27.0** (decorator API `@server.list_tools()` / `@server.call_tool()`,
`ElicitRequestURLParams(elicitationId=...)`, `McpError`), and only **mcp
2.0.0** is installable in this offline environment. A faithful #2/#3 pass
requires rewriting `bridge/mcp/server.py` + the two SDK-dependent tests to
the 2.0.0 callback API and the 2026-07-28 per-request envelope / MRTR
wire. I de-risked that migration empirically (see **SDK findings** below) so
the next worker starts from verified behavior, not a guess.

Why #1 is the right single complete pass: it is pure stdlib (zero SDK-wire
risk, so it cannot regress on the 1.27→2.0 SDK gap), it directly closes the
card's **#1 known trap** ("`stateless=True` does not make ConsentStore, Vault
replay state, or consumed-JTI state safe across replicas"), and it is exactly
what the card's **hardest test** targets ("a two-instance test must fail if
the same signed approval can execute twice").

## What I will build

One new stdlib module and a surgical wiring of its primitive into the three
existing in-memory replay surfaces. No new third-party dependency.

### New module: `bridge/vault/durable_state.py`

`DurableReplayState` — a SQLite-backed, cross-process shared store with two
tables and atomic claim semantics:

- `consumed_signatures(sig_hash, minted_at, expired_at)` — the **mint-time**
  "one signature = one credential" record. `expired_at` is the *signed
  payload's* `exp` (the re-mint window). No TTL floor: a signature stays
  replay-protected even after the credential expires, so a captured signed
  payload can never be re-minted.
- `consumed_jtis(jti, consumed_at, expired_at)` — the **consume-time**
  single-use record. `expired_at` is the *credential's* `exp` (the replay
  window). TTL-aware: a record past `expired_at` no longer blocks.

Methods (each a single transaction; atomicity is SQLite's `INSERT OR IGNORE`
returning `rowcount`, not a check-then-set):

- `claim_signature(sig_hash, *, expired_at) -> bool` — True iff this was the
  first presentation. Re-presentation → False (replay).
- `is_signature_consumed(sig_hash) -> bool`
- `claim_jti(jti, *, expired_at, ttl_seconds) -> bool` — True iff first
  consume; False if already consumed **and within** `expired_at`. Re-claim
  after expiry → True (the replay window has closed).
- `is_jti_consumed(jti) -> bool` — within-window check (used for the
  audit-distinct "already consumed" message path if needed).
- `purge_expired() -> int` — housekeeping.

Connection: `sqlite3.connect(path, check_same_thread=False)` +
`PRAGMA journal_mode=WAL` (cross-process readers don't block the writer) +
a module-level `threading.Lock` around each transaction (intra-process
serialization; the inter-process atomicity comes from the transaction
itself). `:memory:` is supported for isolated unit tests (single-process).

### Wiring (additive; default behavior unchanged)

Each of the three surfaces gains an **optional** `durable_state:
DurableReplayState | None = None` kwarg. When `None`, the current in-memory
set is used (every existing test and demo keeps passing unchanged). When
provided, the durable store *replaces* the in-memory set for the replay
decision, and two `DurableReplayState` objects pointing at the same file
share state across processes.

| File | Change |
|---|---|
| `bridge/vault/in_process.py` | `InProcessVault.__init__(..., durable_state=None)`. `mint`: replace the `_consumed_signatures` membership check+add with `state.claim_signature(sig_hash, expired_at=signed.exp)` → False ⇒ `SignatureReplay`. `consume`: replace the `jti in _consumed` check+add with `state.claim_jti(jti, expired_at=minted.exp, ttl_seconds=…)` → False ⇒ `CredentialReplay`. Preserve every existing exception type and message verbatim. |
| `bridge/vault/oauth.py` | `OAuthVault.__init__(..., durable_state=None)`. Same two replacements (`mint` → `SignatureReplay`, `consume` → `CredentialReplay`). |
| `bridge/rs/jwt_resource_server.py` | `JwtResourceServer.__init__(..., durable_state=None)`. `_consume_authorization_details`: replace `jti in self._consumed` check+add with `state.claim_jti(…)` → False ⇒ `CredentialReplay`. Keeps its independence from the Vault's own set (two separate tables/state objects if you want them truly independent; the interface allows sharing one for a single-consumer RS). |

`bridge/mcp/hitl.py` needs **no change** for #1: its resume correlation is
deterministic (`consent_session_id`) and its replay protection *is* the
Vault's mint-replay guard, which becomes durable when the Vault is given a
shared `DurableReplayState`. `bridge/consent/url_mode.py`'s `ConsentStore`
remains in-memory (documented limitation) — the card's "approval/session
continuation" durability is satisfied by the signed-payload replay state
being the binding constraint; I record the ConsentStore limitation honestly
in SELF_REVIEW.md rather than over-reach into a full durable consent store
(which would touch the consent HTTP surface, i.e. item #3 territory).

## Consumers of the changed APIs (found by grep, not memory)

Changed public signatures (all **additive optional kwarg** — no existing
caller breaks):

- `InProcessVault.__init__` — consumers: `bridge/cli.py:119`,
  `bridge/walkthrough.py:124`, and 8 test call sites
  (`tests/e2e/test_mcp_elicitation_emission.py`, `tests/e2e/
  test_dispatcher_vault_integration.py` ×3, `tests/e2e/test_scope_
  enforcement.py`, `tests/e2e/test_parameter_drift_e2e.py`,
  `tests/protocol/test_mcp_server.py`, `tests/unit/test_in_process_vault.py`
  ×2, `tests/unit/test_mcp_hitl_gate.py` ×3). **None pass the new kwarg**, so
  none break; all continue to exercise the in-memory path.
- `OAuthVault.__init__` — consumers: `bridge/cli.py:121,320,323`,
  `bridge/walkthrough.py:118`, and ~11 test call sites
  (`tests/e2e/test_three_layer_enforcement.py` ×3,
  `tests/e2e/test_dispatcher_vault_integration.py` ×4,
  `tests/e2e/test_mcp_hitl_building_blocks.py`, `tests/unit/test_oauth_vault.py`
  ×7). **None pass the new kwarg**; none break.
- `JwtResourceServer.__init__` — consumers: `bridge/cli.py` (three-layer
  demo) and `tests/e2e/test_three_layer_enforcement.py` (RS fixtures). **None
  pass the new kwarg**; none break.

New importers of `bridge.vault.durable_state`: only the three files above and
the new test file. `bridge/vault/__init__.py` re-exports the interface; I will
also re-export `DurableReplayState` there so `from bridge.vault import
DurableReplayState` works (additive).

Preserved invariants (asserted by tests, not assumed):
- parameter binding (command/args drift → `CredentialDrift`) unchanged;
- caller scope / rar_type checks unchanged;
- exception *types* and *messages* byte-identical on the in-memory path;
- `:memory:` DurableReplayState is single-process (documented).

## Test plan (tests that can fail)

New file `tests/unit/test_durable_state.py` (pure stdlib; runs without mcp).
No mocks of the function under test — the boundary being crossed is a real
second SQLite connection / second process, which is mocked at nothing.

1. **claim_signature is single-shot.** `claim_signature(h)` True once, False
   on re-presentation (both within and after the signed-payload exp).
2. **is_signature_consumed** reflects claim.
3. **claim_jti is single-shot within the window, re-claims after expiry.**
   Fresh ttl → True; immediate re-claim → False (replay); re-claim after
   `expired_at` (advance a fake clock) → True.
4. **Two connections, one file (cross-process / two-replica).** Open two
   `DurableReplayState` on the same `tmp_path` file. A signature claimed on
   conn A is rejected on conn B. A jti consumed on conn A is rejected on conn
   B within the window.
5. **Cross-replica signature replay (the card's trap).** Two `InProcessVault`
   instances sharing one `DurableReplayState(file)`; mint a signed payload on
   vault A; the *same* `SignedAuthorizationDetails` on vault B →
   `SignatureReplay`. And for `OAuthVault`: mint on A, re-present on B →
   `SignatureReplay`; mint on A, consume on B → `CredentialReplay` on the
   *same jti* across the two.
6. **Two-instance / same-approval-twice (the card's hardest test).** Two
   independent `OAuthVault` over one shared state file. Approve+execute once
   (mint A → consume A). A second full attempt (re-present the *same* signed
   payload) **must not** produce a second consumable credential — it raises
   `SignatureReplay`. If the guard regresses (e.g. a future worker drops the
   shared state), this test fails.
7. **Restart durability.** Vault A over `file` mints+consumes; drop A; build
   Vault B over the *same* `file`; re-present the same signed payload →
   `SignatureReplay` (record survived "restart"); consume a second mint's jti
   that A consumed → `CredentialReplay`.
8. **Atomicity under concurrency.** N threads, one shared state, one
   signature → exactly one `claim_signature` True; one jti → exactly one
   `claim_jti` True. (Thread-level; SQLite transaction gives the guarantee.)
9. **Preserve binding + exception surface.** On the durable path, drift still
   raises `CredentialDrift`, expired raises `CredentialExpired`, wrong rar
   still `PayloadDriftAtMint` — i.e. durable state did not swallow the
   existing checks (the existing per-vault suites already cover the
   in-memory path; these mirror them with `durable_state` injected).

## Honest limits

- No network, no Redis, no real multi-node deployment. "Shared across
  replicas" is proven with two SQLite connections to one file (the real
  cross-process boundary) and two in-process vault instances sharing that
  file — not with two OS processes over a networked volume. A true
  distributed store (Redis/Postgres) is out of scope and out of the offline
  environment.
- `:memory:` DurableReplayState is single-process by definition.
- I will report dependency/version limits honestly (see SDK findings).

## SDK findings (de-risking for the untouched items #2/#3)

Observed by driving mcp **2.0.0** over real HTTP (Starlette TestClient,
stateless manager) — *not* assumed:

- `mcp.server.lowlevel.Server` in 2.0.0 takes **callback handlers**
  (`server.add_request_handler("tools/list", PaginatedRequestParams, fn)`,
  `"tools/call", CallToolRequestParams, fn`), not the 1.27.0
  `@server.list_tools()` / `@server.call_tool()` decorators. Handlers must be
  `async`; `tools/list` must return a `ListToolsResult` (a bare list is
  rejected with `handler returned list; expected BaseModel, dict, or None`).
- The **2026-07-28 per-request envelope** is enforced by the session layer:
  every request's `params._meta` must carry
  `io.modelcontextprotocol/protocolVersion` **and**
  `io.modelcontextprotocol/clientCapabilities`, or the request is rejected
  (`params._meta must be an object carrying the required ... envelope keys`).
  When transport headers are present, `MCP-Protocol-Version` must equal the
  envelope version, `Mcp-Method` must equal `body.method`, and for
  name-bearing methods `Mcp-Name` must equal the named param (see
  `mcp/shared/inbound.py` ladder — this is where the card's "header/body
  mismatch" test would live).
- **MRTR**: `tools/call` params carry `request_state: str | None` and
  `input_responses: dict[str, <result>] | None`. A handler may return
  `types.InputRequiredResult(input_requests=[...], request_state=...)`; the
  client retries the same request echoing `request_state` + `input_responses`.
  `input_requests` is a union `CreateMessageRequest | ListRootsRequest |
  ElicitRequest`; `ElicitRequest.params` is
  `ElicitRequestURLParams | ElicitRequestFormParams`.
- `ElicitRequestURLParams` fields are **snake_case** in 2.0.0:
  `meta, mode, message, url, elicitation_id, task` — the staged code's
  `elicitationId=` is why `tests/unit/test_mcp_hitl_gate.py` currently fails.
- `mcp.shared.exceptions` exports `MCPError` (and still exports
  `UrlElicitationRequiredError(elicitations: list[ElicitRequestURLParams],
  message=None)`) — the staged test's `McpError` import is why
  `tests/e2e/test_mcp_elicitation_emission.py` fails collection.
- **Empirical baseline under mcp 2.0.0** (`pytest -q`, ignoring the one
  collection-error file): `3 failed, 130 passed, 4 errors`. All 7 are the SDK
  rename above; **no security-logic test (replay, drift, scope, canonical,
  in-process/oauth vault) fails.** The 1 collection error is the `McpError`
  import. So "keep existing security tests green" = keep those 130 green while
  adding the durable-state suite; the 7 SDK failures are pre-existing and
  belong to the untouched item #2.

## Out of scope (explicitly, this run)

- `bridge/mcp/server.py` 1.27→2.0 migration (item #2).
- Real-HTTP stateless/MRTR/header-mismatch/cache tests (item #3).
- Making `ConsentStore` durable (recorded as a residual risk in SELF_REVIEW;
  it is item #3 territory and would touch the consent HTTP surface).
- Any change to canonical bytes, scope, or the dispatcher.
