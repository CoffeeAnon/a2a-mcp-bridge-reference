"""Shared pytest fixtures."""
import os

import pytest

# Ensure command registration happens before any test imports the registry.
import bridge.commands  # noqa: F401


@pytest.fixture(autouse=True)
def _bridge_env(monkeypatch, tmp_path):
    """Provide a hermetic env for every test: fresh secrets, fresh token files."""
    monkeypatch.setenv("BRIDGE_A2A_SECRET", "test-a2a-secret")
    monkeypatch.setenv("BRIDGE_APPROVAL_SECRET", "test-approval-secret")
    monkeypatch.setenv("BRIDGE_MCP_SECRET", "test-mcp-secret")
    monkeypatch.setenv("BRIDGE_A2A_TOKEN_FILE", str(tmp_path / "a2a_tokens.json"))
    monkeypatch.setenv("BRIDGE_MCP_TOKEN_FILE", str(tmp_path / "mcp_tokens.json"))
    monkeypatch.setenv("BRIDGE_RS_URL", "http://localhost:9999")
    monkeypatch.setenv("BRIDGE_RS_TOKEN", "test-rs-token")
    yield


@pytest.fixture
def fresh_client():
    """A fresh in-memory task store for tests that want a clean slate."""
    from bridge.core.client import InMemoryTaskStore
    return InMemoryTaskStore()
