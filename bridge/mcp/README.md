# bridge.mcp

MCP HTTP surface for the task-tracker reference agent. Exposes the read-tool subset of `bridge.tools` via the official Anthropic MCP Python SDK over streamable-HTTP, with shared-HMAC bearer-token authentication.

## What's in here

| Module       | Purpose                                                                                                       |
| ------------ | ------------------------------------------------------------------------------------------------------------- |
| `server.py`  | `build_mcp_app(invoker, audit, token_store, secret)` — returns a Starlette ASGI sub-app mounted at `/mcp`.    |
| `invoker.py` | `InProcessInvoker` — adapter between the MCP tool-call surface and the shared `bridge.core.dispatcher`.       |
| `auth.py`    | `verify_bearer(...)` — checks the `Authorization: Bearer <token>` header against `bridge.auth.hmac.TokenStore`. |
| `tools.py`   | The v1 read-only allowlist plus a defense-in-depth filter that rejects any `requires_approval=True` spec.     |

## Read-only by design

`bridge/mcp/tools.py` filters `TOOL_SPECS` through an explicit allowlist *and* a defense-in-depth filter that excludes any tool with `requires_approval=True` or `in_process=True`. The MCP surface in the reference therefore never exposes `delete_task` (HITL-gated). Adding write tools to the MCP surface requires extending the allowlist and wiring the server-side emission of an MCP `elicitation/create` request — see `docs/architecture.md` "HITL flow via MCP" for the design and `tests/e2e/test_mcp_hitl_roundtrip.py` for the building blocks composed end-to-end.

## Tests

- `tests/protocol/test_mcp_read_filter.py` — the allowlist + defense-in-depth filter contract.
- `tests/protocol/test_mcp_server.py` — the bearer-auth gate over Starlette TestClient (unauthenticated → 401, bogus → 401, valid → passes through to the MCP session manager).

## Optional dependency

This package requires `pip install -e '.[mcp]'` (Anthropic `mcp` SDK + Starlette + uvicorn + python-multipart). The core install does not pull these in; the CLI demos and the Vault/RS/dispatcher tests run on stdlib only.

## Compartmentalization

Shared HMAC primitives live in `bridge.auth.hmac`. Keeping `bridge.mcp` decoupled from the rest of the codebase except via the `Dispatcher` boundary makes the bridge composable with future host protocols — a downstream team adding an A2A surface or a gRPC surface follows the same `build_*_app(dispatcher, ...)` shape.
