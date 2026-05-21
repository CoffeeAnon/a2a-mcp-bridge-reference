"""Pure translator: LangGraph stream chunks → AgentEvent descriptors.

Chunks from graph.stream/astream(stream_mode="updates") have the shape:
  {"<node_name>": {"messages": [...]}}   for node outputs
  {"__interrupt__": (Interrupt(...), )} for HITL pauses

An AgentEvent is a plain dict with:
  {"kind": "working",   "message": "<text>"}           LLM called a tool
  {"kind": "final",     "message": "<answer text>"}    Terminal answer
  {"kind": "interrupt", "command": ..., "args": ...}   HITL pause
"""
from __future__ import annotations

from typing import TypedDict

from langchain_core.messages import AIMessage


class AgentEvent(TypedDict, total=False):
    kind: str        # "working" | "final" | "interrupt"
    message: str
    command: str     # interrupt only
    args: dict       # interrupt only
    reason: str      # interrupt only; typically the prior tool error that triggered this retry


def translate_chunk(chunk: dict, history: list) -> AgentEvent | None:
    """Translate one LangGraph stream chunk to an AgentEvent, or None if no event."""
    if "__interrupt__" in chunk:
        return _interrupt_event(chunk)
    for node_name, delta in chunk.items():
        if node_name != "llm_node":
            continue
        for m in (delta or {}).get("messages", []):
            if isinstance(m, AIMessage):
                event = _ai_message_event(m)
                if event:
                    return event
    return None


def _interrupt_event(chunk: dict) -> AgentEvent:
    interrupts = chunk["__interrupt__"]
    payload = (interrupts[0].value or {}) if interrupts else {}
    event = AgentEvent(
        kind="interrupt",
        message=f"Approval required for {payload.get('command', 'unknown')}",
        command=payload.get("command", ""),
        args=payload.get("args", {}),
    )
    reason = payload.get("reason")
    if reason:
        event["reason"] = str(reason)
    return event


def _ai_message_event(m: AIMessage) -> AgentEvent | None:
    if getattr(m, "tool_calls", None):
        return AgentEvent(kind="working", message=f"calling {m.tool_calls[0].get('name', 'unknown')}")
    if m.content:
        return AgentEvent(kind="final", message=str(m.content))
    return None
