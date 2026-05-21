# bridge.mcp

MCP server surface for the task-tracker agent. v1 read-only.

- **Spec:** `docs/superpowers/specs/2026-04-28-mcp-server-design.md`
- **Implementation plan:** `docs/superpowers/plans/2026-04-28-mcp-server.md`
- **Operator docs:** `docs/wiki/mcp/server.md`

## Compartmentalization

This package does **not** import from `bridge.a2a`. Shared HMAC + TokenStore primitives live in `bridge.auth.hmac`. This is intentional — keeping the surfaces independent makes a future container split trivial.
