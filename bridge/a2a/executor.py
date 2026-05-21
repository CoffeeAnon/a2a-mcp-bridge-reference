"""A2A AgentExecutor wrapping the agent LangGraph.

execute() handles three cases:
  - New turn: delegates to ``turns.handle_new_turn`` which streams
    ``graph.astream()`` and maps events to TaskUpdater calls.
  - Approval: delegates to ``turns.handle_approval`` which pulls trusted
    args from checkpoint interrupt, signs HMAC, and resumes.
  - Rejection: delegates to ``turns.handle_rejection`` which injects
    ToolMessage + HumanMessage and resumes from updated state.

Auth is validated first: a missing or invalid bearer token → failed().
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

from bridge.a2a import turns
from bridge.a2a.sdk_compat import (
    AgentExecutor, DataPart, EventQueue, Message, Part, RequestContext,
    Role, TaskUpdater, TextPart,
)
from bridge.agent.audit import AuditRow

if TYPE_CHECKING:
    from bridge.a2a.auth import TokenStore


class AgentExecutorImpl(AgentExecutor):
    """A2A executor wrapping the agent LangGraph."""

    def __init__(
        self,
        graph,
        audit,
        a2a_secret: str,
        a2a_token_store: "TokenStore",
        approval_secret: str,
        system_prompt: str = "",
    ) -> None:
        self.graph = graph
        self.audit = audit
        self._a2a_secret = a2a_secret
        self._store = a2a_token_store
        self._approval_secret = approval_secret
        self._system_prompt = system_prompt

    # ── Auth helpers ─────────────────────────────────────────────────────────

    def _bearer_token(self, context: RequestContext) -> str | None:
        cc = context.call_context
        if cc is None:
            return None
        return cc.state.get("bearer_token")

    def _is_authenticated(self, token: str | None) -> bool:
        if not token:
            return False
        return self._store.has_scope(token, "tasks.read", self._a2a_secret)

    # ── Message type detection ───────────────────────────────────────────────

    @staticmethod
    def _is_approval_message(message: Message | None) -> bool:
        if message is None:
            return False
        for part in message.parts:
            if isinstance(part.root, DataPart):
                return part.root.data.get("approved") is True
        return False

    @staticmethod
    def _is_rejection_message(message: Message | None) -> bool:
        if message is None:
            return False
        for part in message.parts:
            if isinstance(part.root, DataPart):
                return part.root.data.get("approved") is False
        return False

    # ── Updater factory (patch-able in tests) ───────────────────────────────

    def _create_updater(self, event_queue: EventQueue, context: RequestContext) -> TaskUpdater:
        return TaskUpdater(event_queue, context.task_id, context.context_id)

    # ── A2A protocol entrypoints ─────────────────────────────────────────────

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        updater = self._create_updater(event_queue, context)
        token = self._bearer_token(context)

        if not self._is_authenticated(token):
            await updater.failed(turns._text_message("Unauthorized: valid bearer token required.", updater))
            return

        from bridge.a2a.auth import caller_from_token
        caller = caller_from_token(token, self._store, self._a2a_secret)
        thread_id = f"{caller.tenant}:{context.context_id}"
        config = {"configurable": {"thread_id": thread_id, "actor": caller.display_name}}

        try:
            if self._is_approval_message(context.message):
                await turns.handle_approval(self, context, config, updater)
            elif self._is_rejection_message(context.message):
                await turns.handle_rejection(self, context, config, updater)
            else:
                await turns.handle_new_turn(self, context, config, updater)
        except Exception as exc:
            self.audit.write(AuditRow(
                thread_id=thread_id,
                tenant_id=caller.tenant,
                kind="error",
                result_snippet=str(exc)[:2048],
                actor=caller.display_name,
            ))
            try:
                await updater.failed(turns._text_message(f"Agent error: {exc}", updater))
            except Exception:
                logger.exception("Failed to send error to client")

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        updater = self._create_updater(event_queue, context)
        await updater.cancel(turns._text_message("Task cancelled.", updater))
