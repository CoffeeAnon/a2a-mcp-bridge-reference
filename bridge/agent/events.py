"""Translator: LangGraph stream chunks → typed AgentEvent dicts.

Used by AgentExecutorImpl (A2A transport) to convert LangGraph
stream_mode="updates" chunks into the AgentEvent TypedDict shape.

Stream chunks from graph.stream(..., stream_mode="updates") have shape:
  {"<node_name>": <state_delta>}
  {"__interrupt__": (Interrupt(...), ...)}

We synthesize a "__compacting__" chunk ourselves when history trim fires.
"""
from __future__ import annotations

from typing import Iterable

from langchain_core.messages import AIMessage, ToolMessage


def translate_stream_events(
    chunks: Iterable[dict],
    prior_messages: list | None = None,
    session_id: str | None = None,
):
    """Translate an iterable of LangGraph stream chunks into legacy event dicts.

    - Yields {"type": "step", "summary": "→ <tool_name>"} for each new ToolMessage.
    - Yields {"type": "approval_required", ...} for each __interrupt__.
    - Yields {"type": "compacting", "message": ...} for each __compacting__ marker.
    - Yields {"type": "done", "output": ...} when a final AIMessage with no tool_calls arrives.
    """
    history = list(prior_messages or [])
    final_text: str | None = None

    for chunk in chunks:
        if "__interrupt__" in chunk:
            yield from _interrupt_events(chunk, session_id)
            return
        if "__compacting__" in chunk:
            yield {"type": "compacting", "message": chunk["__compacting__"]}
            continue
        for m in _new_messages(chunk):
            if isinstance(m, ToolMessage):
                yield {"type": "step", "summary": f"→ {_find_tool_name(history, m.tool_call_id)}"}
            elif isinstance(m, AIMessage) and not getattr(m, "tool_calls", None) and m.content:
                final_text = m.content
            history.append(m)

    if final_text is not None:
        yield {"type": "done", "output": final_text}


def _interrupt_events(chunk: dict, session_id: str | None):
    for interrupt in chunk["__interrupt__"]:
        payload = interrupt.value or {}
        event = {
            "type": "approval_required",
            "command": payload.get("command", ""),
            "args": payload.get("args", {}),
        }
        if session_id is not None:
            event["session_id"] = session_id
        yield event


def _new_messages(chunk: dict):
    for node_name, delta in chunk.items():
        if node_name.startswith("__"):
            continue
        yield from (delta or {}).get("messages", [])


def _find_tool_name(history: list, tool_call_id: str) -> str:
    """Walk back through history to find the AIMessage that issued this tool_call_id."""
    for m in reversed(history):
        if isinstance(m, AIMessage):
            for tc in getattr(m, "tool_calls", None) or []:
                if tc.get("id") == tool_call_id:
                    return tc.get("name", "unknown")
    return "unknown"
