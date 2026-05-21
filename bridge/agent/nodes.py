"""Graph nodes: llm_node and tool_node.

ReAct shape: llm_node produces an AIMessage that may carry one tool_call;
tool_node dispatches the call (interrupting for HITL if the tool requires
approval), appends a ToolMessage, and cycles back to llm_node.

Enforces one tool call per turn (matches ``tool_calls[0]`` behavior), which
keeps checkpoint semantics clean and sidesteps multi-call-with-interrupt
replay hazards.

The interrupt+resume primitive is what carries the HITL approval flow:
``interrupt()`` pauses the graph at the tool boundary, the A2A executor
surfaces the trusted payload to the client as ``auth_required``, and the
resume value (the HMAC approval token, or — in the Tier-1 OAuth+RAR
deployment — an AS-issued JWT) becomes the ``approval_token`` passed to
the invoker.
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import tiktoken
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.messages.utils import trim_messages
from langgraph.types import interrupt

from bridge.agent.tools import SPECS_BY_NAME

logger = logging.getLogger("bridge.agent")

if TYPE_CHECKING:
    from bridge.agent.invoker import ToolInvoker


_enc = tiktoken.get_encoding("cl100k_base")


def _prior_tool_error(messages) -> str | None:
    """Return the most recent ToolMessage content if it looks like an error.

    Used to surface prior post-approval tool failures in the next auth_required
    payload so a client relaying the prompt can explain why the retry is
    being proposed.
    """
    for msg in reversed(messages):
        if isinstance(msg, ToolMessage):
            content = str(msg.content or "").strip()
            if content.lower().startswith("error"):
                return content
            return None
    return None


def _count_tokens(messages) -> int:
    total = 0
    for m in messages:
        total += len(_enc.encode(str(m.content or "")))
        if isinstance(m, AIMessage) and getattr(m, "tool_calls", None):
            for tc in m.tool_calls:
                total += len(_enc.encode(str(tc.get("name", ""))))
                total += len(_enc.encode(str(tc.get("args", {}))))
    return total


def pre_model_hook(state: dict) -> dict:
    """Trim conversation history when it exceeds MAX_CONTEXT_TOKENS."""
    max_tokens = int(os.environ.get("MAX_CONTEXT_TOKENS", "64000"))
    messages = state["messages"]
    if _count_tokens(messages) <= max_tokens:
        return {}

    trimmed = trim_messages(
        messages,
        max_tokens=max_tokens,
        token_counter=lambda ms: _count_tokens(ms),
        strategy="last",
        include_system=True,
        allow_partial=False,
    )
    return {"messages": trimmed}


def llm_node(state: dict, config: dict, llm) -> dict:
    """Call the LLM with the current message history and append the response."""
    msgs = state["messages"]
    response = llm.invoke(msgs)
    return {"messages": [response]}


def tool_node(state: dict, config: dict, invoker: "ToolInvoker", llm=None) -> dict:
    """Dispatch the single tool call from the last AIMessage.

    For tools with ``requires_approval=True``, call ``interrupt()`` with the
    trusted (command, args) payload before invoking. The resume value is
    the approval token (Tier-2 HMAC or Tier-1 RAR JWT, depending on
    deployment).
    """
    last = state["messages"][-1]
    if not getattr(last, "tool_calls", None):
        return {}

    tool_call = last.tool_calls[0]  # one tool call per turn, enforced
    spec = SPECS_BY_NAME[tool_call["name"]]
    args = tool_call["args"]
    tool_call_id = tool_call["id"]
    logger.info("tool_node → dispatching: name=%s args=%s", spec.name, args)

    result = _invoke_with_approval(invoker, spec, args, state["messages"][:-1])

    return {"messages": [ToolMessage(tool_call_id=tool_call_id, content=result.content)]}


def _build_approval_payload(spec, args: dict, messages: list) -> dict:
    payload = {"command": spec.cli_name or spec.name, "args": args}
    if spec.rar_type:
        payload["rar_type"] = spec.rar_type
    prior_error = _prior_tool_error(messages)
    if prior_error:
        payload["reason"] = prior_error
    return payload


def _invoke_with_approval(invoker: "ToolInvoker", spec, args: dict, prior_messages: list):
    approval_token: str | None = None
    if spec.requires_approval:
        approval_token = interrupt(_build_approval_payload(spec, args, prior_messages))
    result = invoker.invoke(spec, args, approval_token=approval_token)
    if result.approval_required and approval_token is None:
        cli_payload = dict(result.approval_payload or {})
        prior_error = _prior_tool_error(prior_messages)
        if prior_error and "reason" not in cli_payload:
            cli_payload["reason"] = prior_error
        approval_token = interrupt(cli_payload)
        result = invoker.invoke(spec, args, approval_token=approval_token)
    return result
