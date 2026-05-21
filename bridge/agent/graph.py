"""StateGraph factory for the Bridge agent.

build_graph() wires llm_node and tool_node into a ReAct-style loop with a
conditional edge that routes based on whether the last AIMessage carries a
tool_call. Callers provide:

  - checkpointer: any BaseCheckpointSaver (InMemorySaver for dev, SqliteSaver
    or PostgresSaver for persistent state).
  - llm: a ChatOpenAI (or compatible) with tools already bindable via
    .bind_tools(). If omitted, a default one is built from env vars.
  - invoker: a ToolInvoker for dispatching CLI tool calls. Defaults to
    InProcessInvoker (calls Dispatcher.execute() directly — no subprocess).

The compiled graph is configured with recursion_limit=40 — twice the legacy
MAX_ITERATIONS=20 because each iteration is now two graph steps.
"""
from __future__ import annotations

import os
from typing import Annotated
from typing_extensions import TypedDict

from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

from bridge.agent.invoker import InProcessInvoker, ToolInvoker
from bridge.agent.nodes import llm_node, tool_node, pre_model_hook
from bridge.agent.tools import openai_schemas


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]


def _default_llm() -> ChatOpenAI:
    return ChatOpenAI(
        model=os.environ.get("LLM_MODEL", "local-model"),
        base_url=os.environ.get("LLM_BASE_URL", "http://host.docker.internal:1234/v1"),
        api_key=os.environ.get("LLM_API_KEY") or "no-key",
        max_tokens=4096,
        temperature=0,
    )


def build_graph(
    checkpointer: BaseCheckpointSaver,
    llm=None,
    invoker: ToolInvoker | None = None,
):
    """Build and compile the agent graph."""
    llm = llm if llm is not None else _default_llm()
    invoker = invoker if invoker is not None else InProcessInvoker()

    bound_llm = llm.bind_tools(openai_schemas())

    def _llm_node(state, config):
        delta = pre_model_hook(state)
        if "messages" in delta:
            state = {**state, "messages": delta["messages"]}
        return llm_node(state, config, llm=bound_llm)

    def _tool_node(state, config):
        return tool_node(state, config, invoker=invoker, llm=llm)

    def _should_use_tool(state) -> str:
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None):
            return "tool_node"
        return END

    sg: StateGraph = StateGraph(AgentState)
    sg.add_node("llm_node", _llm_node)
    sg.add_node("tool_node", _tool_node)
    sg.add_edge(START, "llm_node")
    sg.add_conditional_edges("llm_node", _should_use_tool, ["tool_node", END])
    sg.add_edge("tool_node", "llm_node")

    return sg.compile(checkpointer=checkpointer)
