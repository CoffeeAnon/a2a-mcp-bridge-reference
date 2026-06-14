# bridge.mcp

MCP HTTP surface for the task-tracker reference agent. Exposes a tool subset of `bridge.tools` via the official Anthropic MCP Python SDK over streamable-HTTP, with shared-HMAC bearer-token authentication. The surface is read-only unless a HITL gate is wired in, in which case HITL-gated tools become callable through a URL-mode elicitation flow.

## What's in here

| Module       | Purpose                                                                                                       |
| ------------ | ------------------------------------------------------------------------------------------------------------- |
| `server.py`  | `build_mcp_app(*, invoker, audit, token_store, secret, consent_store=None, vault=None, ...)` - returns a Starlette ASGI sub-app mounted at `/mcp`. Supplying `consent_store` and `vault` wires the HITL gate. |
| `invoker.py` | `InProcessInvoker` - adapter between the MCP tool-call surface and the shared `bridge.core.dispatcher`.       |
| `auth.py`    | `verify_bearer(...)` - checks the `Authorization: Bearer <token>` header against `bridge.auth.hmac.TokenStore`. |
| `hitl.py`    | `McpHitlGate` - emits a URL-mode elicitation on a HITL-gated `tools/call` and resumes the call once the human has approved. |
| `tools.py`   | Two allowlists: `MCP_V1_ALLOWLIST` (read tools, always exposed) and `MCP_HITL_ALLOWLIST` (HITL-gated tools, exposed only when the gate is wired), plus a defense-in-depth filter. |

## What the MCP surface exposes

`bridge/mcp/tools.py` gates the surface through two explicit allowlists. `MCP_V1_ALLOWLIST` holds the read tools, always exposed, behind a defense-in-depth filter that excludes any spec marked `requires_approval=True` or `in_process=True` even if it is mistakenly listed. `MCP_HITL_ALLOWLIST` holds HITL-gated tools (currently `delete_task`); they surface only when `build_mcp_app` is called with both a `consent_store` and a `vault`, which wires the `McpHitlGate`. With no gate wired the surface is strictly read-only and never exposes `delete_task`.

When the gate is wired, a `tools/call` to a HITL-gated tool returns a URL-mode elicitation (`URL_ELICITATION_REQUIRED`) pointing at the independent consent surface, and a retried call resumes once the human has approved. This is the single-agent secure-approval path over MCP, with no A2A. See `docs/architecture.md` "HITL flow walkthroughs" for the design and `tests/e2e/test_mcp_elicitation_emission.py` for the flow driven end to end through the server.

## Tests

- `tests/protocol/test_mcp_read_filter.py` - the allowlist + defense-in-depth filter contract.
- `tests/protocol/test_mcp_server.py` - the bearer-auth gate over Starlette TestClient (unauthenticated → 401, bogus → 401, valid → passes through to the MCP session manager).
- `tests/unit/test_mcp_hitl_gate.py` - the `McpHitlGate` emit/resume primitive.
- `tests/e2e/test_mcp_elicitation_emission.py` - a HITL-gated `tools/call` driven through the server: emit, approve, resume, execute.

## Optional dependency

This package requires `pip install -e '.[mcp]'` (Anthropic `mcp` SDK + Starlette + uvicorn + python-multipart). The core install does not pull these in; the CLI demos and the Vault/RS/dispatcher tests run on stdlib only.

## Compartmentalization

Shared HMAC primitives live in `bridge.auth.hmac`. Keeping `bridge.mcp` decoupled from the rest of the codebase except via the `Dispatcher` boundary makes the bridge composable with future host protocols: a downstream team adding an A2A surface or a gRPC surface follows the same `build_*_app(dispatcher, ...)` shape.
