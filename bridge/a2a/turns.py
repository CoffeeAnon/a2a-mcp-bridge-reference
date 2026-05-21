"""Turn handlers for the A2A executor.

Encapsulates the three turn types (new, approval, rejection) and the
graph streaming helper.  Imported by ``executor.py`` to keep
``AgentExecutorImpl`` focused on auth and protocol dispatch.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.types import Command

from bridge.a2a.event_mapping import translate_chunk
from bridge.a2a.sdk_compat import (
    DataPart, Message, Part, RequestContext, TaskUpdater, TextPart,
)
from bridge.agent.audit import AuditRow

logger = logging.getLogger("bridge.agent")

if TYPE_CHECKING:
    from bridge.a2a.executor import AgentExecutorImpl

# ── Message helpers ───────────────────────────────────────────────────────────


def _text_message(text: str, updater: TaskUpdater) -> Message:
    return updater.new_agent_message(parts=[Part(root=TextPart(text=text))])


def _write_audit_event(executor: "AgentExecutorImpl", config: dict, kind: str) -> None:
    thread_id = config["configurable"]["thread_id"]
    executor.audit.write(AuditRow(
        thread_id=thread_id,
        tenant_id=thread_id.split(":")[0],
        kind=kind,
        actor=config["configurable"].get("actor", "agent"),
    ))


def _find_pending_tool_call_id(messages: list) -> str | None:
    for m in reversed(messages):
        if isinstance(m, AIMessage):
            tcs = getattr(m, "tool_calls", None) or []
            if tcs:
                return tcs[0]["id"]
    return None


# ── Stream helper ─────────────────────────────────────────────────────────────


async def _stream_graph(
    graph, input_data, config: dict, updater: TaskUpdater
) -> bool:
    """Stream graph and call updater. Returns True if interrupted."""
    final_text: str | None = None
    interrupted = False

    async for chunk in graph.astream(input_data, config=config, stream_mode="updates"):
        event = translate_chunk(chunk, [])
        if event is None:
            continue
        if event["kind"] == "working":
            await updater.start_work(_text_message(event["message"], updater))
        elif event["kind"] == "final":
            final_text = event["message"]
        elif event["kind"] == "interrupt":
            data = {
                "command": event["command"],
                "args": event["args"],
                "context_id": config["configurable"].get("thread_id", ""),
            }
            reason = event.get("reason")
            if reason:
                data["reason"] = reason
            auth_msg = updater.new_agent_message(parts=[Part(root=DataPart(data=data))])
            await updater.requires_auth(auth_msg)
            interrupted = True
            break

    if not interrupted:
        if final_text is not None:
            await updater.add_artifact(parts=[Part(root=TextPart(text=final_text))])
        await updater.complete()

    return interrupted


# ── Turn handlers ─────────────────────────────────────────────────────────────


async def handle_new_turn(
    executor: "AgentExecutorImpl",
    context: RequestContext,
    config: dict,
    updater: TaskUpdater,
) -> None:
    msg = context.message
    text = ""
    if msg:
        for part in msg.parts:
            if isinstance(part.root, TextPart):
                text = part.root.text
                break

    history_len = 0
    try:
        state = await executor.graph.aget_state(config)
        prior_msgs = state.values.get("messages") or []
        history_len = len(prior_msgs)
        has_history = bool(prior_msgs)
    except Exception as exc:
        logger.warning("handle_new_turn: aget_state failed: %s", exc)
        has_history = False

    logger.info(
        "handle_new_turn: thread=%s history_len=%d has_history=%s text=%r",
        config.get("configurable", {}).get("thread_id"),
        history_len, has_history, text[:160],
    )

    if has_history:
        initial = {"messages": [HumanMessage(content=text)]}
    else:
        initial = {"messages": [
            SystemMessage(content=executor._system_prompt),
            HumanMessage(content=text),
        ]}

    await updater.start_work(_text_message("thinking...", updater))
    await _stream_graph(executor.graph, initial, config, updater)


async def handle_approval(
    executor: "AgentExecutorImpl",
    context: RequestContext,
    config: dict,
    updater: TaskUpdater,
) -> None:
    from bridge.core.auth import generate_approval_token

    state = await executor.graph.aget_state(config)
    if not state.tasks or not state.tasks[0].interrupts:
        await updater.failed(_text_message("No pending approval found.", updater))
        return

    trusted = state.tasks[0].interrupts[0].value or {}
    token = generate_approval_token(
        trusted.get("command", ""),
        trusted.get("args", {}),
        executor._approval_secret,
    )
    _write_audit_event(executor, config, "approval_granted")
    await updater.start_work(_text_message("applying approved action...", updater))
    await _stream_graph(executor.graph, Command(resume=token), config, updater)


async def handle_rejection(
    executor: "AgentExecutorImpl",
    context: RequestContext,
    config: dict,
    updater: TaskUpdater,
) -> None:
    reason = ""
    if context.message:
        for part in context.message.parts:
            if isinstance(part.root, DataPart):
                reason = part.root.data.get("reason", "")
                break

    state = await executor.graph.aget_state(config)
    tool_call_id = _find_pending_tool_call_id(state.values.get("messages", []))
    if tool_call_id is None:
        await updater.failed(_text_message("No pending tool call for rejection.", updater))
        return

    await executor.graph.aupdate_state(config, {
        "messages": [
            ToolMessage(tool_call_id=tool_call_id, content="Action rejected by user."),
            HumanMessage(content=reason or "The action was rejected. Please try again."),
        ]
    }, as_node="tool_node")
    _write_audit_event(executor, config, "approval_rejected")
    await updater.start_work(_text_message("applying rejection...", updater))
    await _stream_graph(executor.graph, None, config, updater)
