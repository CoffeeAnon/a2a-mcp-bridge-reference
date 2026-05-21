"""MCP tool registry adapter.

Filters the global TOOL_SPECS down to the v1 read-only allowlist. Defense-in-depth
filters exclude any spec marked requires_approval=True (write tools) or
in_process=True (host-LLM-dependent tools), even if accidentally allowlisted.

For the reference implementation this exposes the task-tracker's read tools.
A Tier-2 (OAuth+RAR+Vault) deployment can extend the allowlist to write tools
and surface HITL approvals through MCP elicitation; see the architecture page.
"""
from __future__ import annotations

from bridge.agent.tools import TOOL_SPECS, ToolSpec

MCP_V1_ALLOWLIST: frozenset[str] = frozenset({
    "list_tasks",
    "get_task",
})


def mcp_tool_specs() -> list[ToolSpec]:
    """Return the ToolSpecs that v1 MCP exposes.

    Three independent filters apply (a spec must pass all three):
      1. name in MCP_V1_ALLOWLIST
      2. requires_approval is False  (no write tools)
      3. in_process is False         (no host-LLM tools)
    """
    return [
        s for s in TOOL_SPECS
        if s.name in MCP_V1_ALLOWLIST
        and not s.requires_approval
        and not s.in_process
    ]
