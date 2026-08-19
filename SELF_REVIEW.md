# SELF_REVIEW — durable shared replay state (item #1)

Companion to `PLAN.md`. I diffed the actual code against the plan, and I'm
recording every deviation plus every residual doubt a reviewer should look
at. The honest list of what I could *not* verify is at the bottom.

## What landed (vs the plan)

Plan item | Status | Note
---|---|---
`DurableReplayState` (SQLite, WAL) | DONE | `bridge/vault/durable_state.py`. Two tables (`consumed_signatures`, `consumed_jtis`), atomic `INSERT OR IGNORE` claim, `timeout=30.0` busy-wait, read methods lock-guarded. Optional injected `conn` for tests.
Wire into `InProcessVault.mint`/`consume` | DONE | `bridge/vault/in_process.py`. Additive `durable_state=None` kwarg.
Wire into `OAuthVault.mint`/`consume` | DONE | `bridge/vault/oauth.py`. Same kwarg.
Wire into `JwtResourceServer._consume_authorization_details` | DONE | `bridge/rs/jwt_resource_server.py`. Same kwarg. This is the Tier-2 load-bearing consume point.
Re-export from `bridge.vault` | DONE | `__init__.py` + `__all__`.
Tests (8 listed in plan) | DONE, 13 total | `tests/unit/test_durable_state.py`.
Leave item #2 (SDK migration) untouched | DONE | No edit to `bridge/mcp/*` or the two SDK-dependent test files.

## Deviations from the plan (and why each is the *safer* direction)

1. **`claim_jti` / `claim_signature` are PERMANENT, not window-bounded.**
   The plan's test 3 said: "re-claim after expiry → `True`." That expectation
   did NOT match run 496's implementation, which uses `INSERT OR IGNORE` — a
   record blocks **forever** until `purge_expired()` drops it. I kept the
   implementation and fixed the test, because permanent blocking is correct:
   - A `jti` is single-use by definition. The consumer checks `exp` *before*
     the claim, so an expired credential raises `CredentialExpired` and never
     reaches the replay guard. There is no legitimate reason to ever allow a
     second claim of the same jti.
   - It matches the in-memory baseline exactly: `if jti in self._consumed`
     also blocks forever within a process's lifetime.
   - "Window-bounded re-claim" would be a *downgrade* (a purged-but-not-expired
     jti could be replayed). Permanent is the safe direction.
   The test now asserts: immediate re-claim → replay; record persists past the
   window; only an explicit `purge_expired()` reopens the key.

2. **Tier-1 cross-replica *consume* returns `SignatureMismatch`, not
   `CredentialReplay`.** The plan's item #1 framing implied Tier-1 consume is
   the cross-replica guard. It is *not*, and I want that on the record:
   - Tier 1's issuance record (`self._issued`, command/args/exp/jti) is
     process-local and intentionally NOT mirrored into the durable store. The
     durable store holds only the two hashes (sig, jti). A `command/args/exp`
     record cannot be reconstructed from those hashes, so a Tier-1 credential
     minted on replica A and consumed on replica B raises
     `SignatureMismatch` — identical to the documented single-process restart
     behavior. That is the honest, correct Tier-1 story.
   - The **cross-replica single-use *consume* guarantee is delivered at the
     Resource Server** (Tier-2 JWTs are self-contained), which is where
     `test_rs_two_instances_same_jwt_executes_once` proves it.
   - Tier-1's cross-replica guarantee is at **mint** time (one signed payload
     = one credential across replicas), proven by
     `test_cross_replica_signature_replay_inprocess` and the two-OS-process
     test.
   I did *not* mirror the Tier-1 `_issued` record into the durable store: it
   would duplicate state the plan explicitly kept local, change consume's
   error type for the restart case, and add a command/args/exp table the card
   did not ask for. Flagging this as a design boundary, not an oversight.

3. **Added a genuine two-OS-process test** (`test_true_cross_process_replica_
   cannot_reexecute`) beyond the plan's "two independent DurableReplayState
   objects." The plan's phrasing is ambiguous about whether "two objects"
   means two *connections* or two *processes*. A real deployment is two OS
   processes, so I went further: the test spawns a real child `python` process
   (env-passed, not argv — `python -c` only takes one argv) that opens the same
   SQLite file and must hit `SignatureReplay`. This is the strongest form of
   the boundary and directly answers the card's "cross-replica replay" check.
   Cost: one ~100 ms subprocess in the suite.

## What I verified by execution (not by reading)

- Baseline before any wiring: **130 passed, 3 failed, 4 errors** (the 7
  failures are mcp 1.27→2.0 SDK renames in `test_mcp_hitl_gate.py` and
  `test_mcp_server.py` — item #2 territory, untouched).
- After all wiring + tests: **143 passed, 3 failed, 4 errors**. Delta is
  exactly the 13 new tests; the 7 pre-existing failures are unchanged; zero
  security-logic tests regressed.
- **Negative control** (temporary `negctl.py`, since deleted): with NO shared
  durable state, two in-memory `OAuthVault` replicas over the same signed
  payload **both** minted — producing two *distinct* credentials. That is the
  exact hole the durable store closes, and it's why
  `test_two_instances_same_approval_executes_once` would fail if the wiring
  regressed.
- The two-OS-process test actually spawned a child and observed
  `{"second_execution": false, "error": "SignatureReplay"}` from it.
- Import sanity: `InProcessVault`, `OAuthVault`, `JwtResourceServer` all
  accept `durable_state` (introspected each `__init__`'s signature).

## Residual doubts / things a reviewer should double-check

1. **WAL + shared filesystem across real replicas.** SQLite's cross-process
   file locking requires the replicas to genuinely share one filesystem
   (NFS with proper locking, or a single host). My tests use a local tmp_path,
   so they prove the *code* is correct but do NOT prove a production NFS /
   EFS / CIFS mount gives correct locking. If a deployment pointed several
   replicas at SQLite over a non-locking network share, `claim_*` could
   silently double-allow. **This is the plan's documented caveat and it is
   real.** A reviewer should confirm the deployment target uses locking-backed
   shared storage before relying on this across distinct hosts.

2. **`purge_expired` is not called anywhere by default.** The store will grow
   one row per consumed credential / signature forever unless a caller runs
   `purge_expired()`. There is no background reaper and no retention policy
   wired into the Vaults. For long-lived deployments this is unbounded table
   growth. The card scoped item #1 to the *correctness* of replay protection,
   so I did not add a reaper — but it's a genuine production gap. A cron /
   idle reaper calling `purge_expired()` is the natural follow-up.

3. **`DurableReplayState` is opened lazily per method on a single connection,
   guarded by `threading.Lock`.** That serializes all durable operations per
   process. Under very high concurrency this is a throughput ceiling, though
   the 16-thread atomicity test passed cleanly. Correctness > throughput here
   (it's a security guard), so I accepted the serialization. Noted in case the
   reviewer wants connection pooling.

4. **The `mint` path uses `claim_signature` (atomic), while `consume` / RS
   uses a check-then-claim via `is_jti_consumed` + `claim_jti`.** Both are
   safe *because the claim itself is atomic* (`INSERT OR IGNORE`), and the
   check before it only shapes the *error type* (drift vs replay ordering).
   But if a reviewer reads `is_jti_consumed` as the authority they'll be
   wrong — the authority is the atomic `claim_*`. The in-memory path has the
   same check-then-add-under-lock shape, so this is consistent with baseline;
   flagging only because the durable "check" is a separate query, not a lock
   scope.

5. **Tier-1 `_issued` is still process-local.** I kept it (deviation #2). If
   a reviewer believes the card *required* Tier-1 consume to be
   cross-replica-capable (rather than just cross-replica-*mint*-capable),
   that's a scope decision to confirm. As written in the card, the durable
   store's job is "one-approval / one-execution across replicas and across a
   restart," which for Tier 1 is enforced at mint and for Tier 2 at the RS
   consume. I'm confident this reading is right but it's the one place where a
   stricter reading would change the code.

## Could not verify (honest limits)

- **Real multi-host replication over shared network storage.** I have one
  host and one local tmp_path. I verified two *processes* on one machine, not
  two *hosts* over NFS/EFS. The locking behavior across a non-local share is
  untested (doubt #1).
- **Production AS swap.** `OAuthVault` here is the HS256 reference; a real
  Keycloak/Auth0 is out of scope for this card. I verified the durable store
  composes with the *reference* OAuthVault, not a real AS.
- **The mcp 2.0.0 SDK rename fallout** (the 7 failing tests). I did not touch
  it by design (item #2) and did not attempt to fix it. Those failures are
  present at baseline and unchanged by my work.
