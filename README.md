# A2A↔MCP Bridge Reference

A reference implementation of a **stateful, HITL-aware, parameter-bound** bridge between [A2A](https://a2a-protocol.org) and [MCP](https://modelcontextprotocol.io) — the two emerging protocols for agent-to-agent and LLM-IDE-to-tool communication.

The implementation demonstrates a pattern that no published bridge today provides in combination:

1. **Stateful** — `context_id` is preserved across calls; multi-turn conversations work.
2. **HITL-aware** — destructive actions pause via A2A `auth_required` SSE events; the same pause translates into MCP elicitation when the call originates from an MCP client.
3. **Parameter-bound** — the human approves *the specific action with the specific arguments*. Any drift between approval and execution invalidates the credential. This is the property that makes HITL more than security theatre.

The reference ships in two tiers, both holding the parameter-binding property:

- **Tier 1 — OAuth 2.0 + RAR (target).** Authorization server issues access tokens carrying `authorization_details` (RFC 9396); resource server enforces; approval delivery via CIBA or MCP elicitation. *Not yet implemented in this repo — coming next.*
- **Tier 2 — HMAC (current).** Self-contained: HMAC-SHA256 over `command + sorted args + 5-min TTL`. No authorization server required. Same property; lighter operational footprint. **This is what this repo currently ships.**

---

## Status

**Work in progress.** First structural pass:

- ✅ Dual-surface (A2A + MCP) Starlette app
- ✅ Shared HMAC bearer-token store across both surfaces
- ✅ Tier-2 HMAC approval-token primitive (parameter-bound, 5-min TTL)
- ✅ LangGraph dispatch with interrupt-driven HITL
- ✅ Example domain: task-tracker (`list_tasks`, `get_task`, `create_task`, `update_task`, `delete_task`) with `delete_task` as the HITL-gated destructive action
- 🟨 Tests being ported from substrate; full test suite incoming
- 🟥 Tier-1 OAuth + RAR layer (authorization server, RAR `authorization_details`, CIBA, MCP elicitation translation) — next phase

The architecture is documented in the companion design notes:

- **Rationale** — *Stateful, HITL-aware A2A↔MCP bridge — design rationale* (the *why*: the gap, the four properties, the FAPI-2.0 analogue, the two-tier framing)
- **Architecture** — *Stateful, HITL-aware A2A↔MCP bridge — reference architecture* (the *how*: components, flows, the OAuth + RAR layer the Tier-1 target adds)
- **Authorization patterns** — *Agent Authorization Patterns* (the standards survey: RAR / CIBA / PAR / Token Exchange / GNAP / Step-up)

---

## Layout

```
bridge/
├── a2a/         # A2A surface (HTTP + SSE), built on a2a-sdk
├── mcp/         # MCP surface (streamable HTTP), built on the official MCP Python SDK
├── auth/        # Shared HMAC bearer-token store (used by both surfaces)
├── core/        # Dispatcher with HITL gate; approval-token primitives
├── agent/       # LangGraph + tool registry + audit + invoker
└── commands/    # Task-tracker command implementations (the reference's example domain)
deploy/
└── server.py    # ASGI entry point — wires the two surfaces together
tests/           # Unit + protocol + end-to-end tests (in progress)
```

The example domain is intentionally generic. Replace `bridge/commands/*.py` and update `bridge/agent/tools.py` to point at your own domain; the auth substrate, dispatcher, and protocol surfaces do not change.

---

## Running locally

```bash
# 1. Install (with all extras)
python -m venv .venv && source .venv/bin/activate
pip install -e '.[agent,dev]'

# 2. Set required env vars
export BRIDGE_A2A_SECRET=$(openssl rand -hex 32)
export BRIDGE_APPROVAL_SECRET=$(openssl rand -hex 32)
export LLM_API_KEY=your-llm-key            # or run a local LLM and override LLM_BASE_URL

# 3. Issue a bearer token (writes to ~/.bridge_a2a_tokens.json)
python -m bridge.a2a.tokens_cli issue --label dev --scopes tasks.read,tasks.write

# 4. Run the server
python deploy/server.py
```

The server mounts:

- `/health` — liveness
- `/.well-known/agent-card.json` — A2A agent discovery
- `/` (POST) — A2A message endpoint (SSE-streamed)
- `/mcp` — MCP streamable-HTTP endpoint

---

## CLI smoke-test runner

Once installed (`pip install -e .`), a `bridge` command exercises HITL
flow scenarios end-to-end with stable `[OK]` / `[REJECTED]` markers and a
non-zero exit code on any unexpected outcome — useful as a smoke test
or as an executable demo of the design.

```bash
bridge demo all                  # run every scenario, print a summary
bridge demo tier1                # happy-path delete via Tier 1 InProcessVault
bridge demo tier2                # happy-path delete via Tier 2 OAuthVault
bridge demo drift --tier 2       # LLM substitutes task_id after approval → rejected
bridge demo replay --tier 2      # credential reused → rejected
bridge demo unforgeable          # Tier-2 only: rogue Vault's JWT rejected by dispatcher
```

For a step-by-step simulation of the wiki sequence diagram (12 numbered
steps with actual JSON-RPC / SSE / OAuth envelopes printed at each hop):

```bash
bridge walkthrough --tier 2              # full simulation, no pauses
bridge walkthrough --tier 2 --pause      # interactive: Enter between steps
bridge walkthrough --tier 1              # the Tier-1 in-process variant
```

The walkthrough is behaviour-accurate but transport-simulated — the
Vault, dispatcher, and resource server are real; the HTTP/SSE envelopes
are printed for narration rather than sent over real sockets.

Without an install you can run it directly from a checkout:

```bash
python -m bridge.cli demo all
```

The `unforgeable` scenario is the publishable Zero-Trust demonstration:
it shows that even an adversary holding the human's signed RAR payload
cannot produce a credential the legitimate dispatcher will accept,
because the Vault's mint secret is the cryptographic root of trust.

## Tests

See the architecture page §"Tests" for the test layering. Key invariants:

- **Parameter-drift test** — the load-bearing test. After approval, the dispatch arguments are mutated; HMAC verification must fail; the dispatcher must refuse execution.
- **Read filter test** — MCP `tools/list` excludes any tool with `requires_approval=True`. Defense-in-depth, defended even if the allowlist is wrong.
- **Audit fidelity** — every tool call writes exactly one audit row; approval grant / rejection each write their own row.
- **(Tier 1 — pending)** RAR mismatch test: per-action token issued for `task_id=X`; execution attempts `task_id=Y`; RS rejects 403.

```bash
pytest                          # all
pytest tests/unit                # unit only
pytest tests/protocol            # A2A + MCP protocol tests
pytest tests/e2e                 # end-to-end flow tests
```

---

## License

Apache-2.0.
