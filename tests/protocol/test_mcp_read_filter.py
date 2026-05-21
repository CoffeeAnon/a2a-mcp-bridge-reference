"""MCP read-only allowlist + defense-in-depth filter.

These tests defend the contract that the MCP surface in Tier-2 (current)
never exposes HITL-gated tools. Adding a write tool to ``TOOL_SPECS``
without also adding it to ``MCP_V1_ALLOWLIST`` must not leak it onto MCP.
"""
from dataclasses import replace

import pytest

from bridge.agent import tools as tools_module
from bridge.agent.tools import SPECS_BY_NAME, TOOL_SPECS, ToolSpec
from bridge.mcp.tools import MCP_V1_ALLOWLIST, mcp_tool_specs


def test_allowlist_contains_only_read_tools():
    for name in MCP_V1_ALLOWLIST:
        spec = SPECS_BY_NAME[name]
        assert not spec.requires_approval, f"{name} is in MCP_V1_ALLOWLIST but requires_approval"
        assert not spec.in_process, f"{name} is in MCP_V1_ALLOWLIST but is in_process"


def test_mcp_tool_specs_excludes_destructive():
    exposed = {s.name for s in mcp_tool_specs()}
    assert "delete_task" not in exposed
    assert "create_task" not in exposed   # not in allowlist
    assert "update_task" not in exposed   # not in allowlist


def test_mcp_tool_specs_includes_reads():
    exposed = {s.name for s in mcp_tool_specs()}
    assert "list_tasks" in exposed
    assert "get_task" in exposed


def test_defense_in_depth_rejects_hitl_tool_added_to_allowlist(monkeypatch):
    """Even if a HITL-gated tool is mistakenly allowlisted, the filter rejects it."""
    rogue = ToolSpec(
        name="rogue_destructive",
        description="should not surface on MCP",
        parameters={"type": "object", "properties": {}},
        cli_name="rogue-destructive",
        requires_approval=True,
        rar_type="rogue",
    )
    monkeypatch.setattr(tools_module, "TOOL_SPECS", TOOL_SPECS + [rogue])
    monkeypatch.setattr(tools_module, "SPECS_BY_NAME", {**SPECS_BY_NAME, rogue.name: rogue})
    monkeypatch.setattr(
        "bridge.mcp.tools.MCP_V1_ALLOWLIST",
        frozenset(MCP_V1_ALLOWLIST | {"rogue_destructive"}),
    )
    monkeypatch.setattr("bridge.mcp.tools.TOOL_SPECS", tools_module.TOOL_SPECS)
    exposed = {s.name for s in mcp_tool_specs()}
    assert "rogue_destructive" not in exposed, (
        "MCP surface must not expose HITL-gated tools even if they are mistakenly "
        "added to MCP_V1_ALLOWLIST. The defense-in-depth filter is the contract."
    )
