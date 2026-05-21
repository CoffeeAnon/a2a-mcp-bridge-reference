from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    BaseCallbackHandler = object  # type: ignore[assignment]
    LLMResult = None  # type: ignore[assignment]
    _LANGCHAIN_AVAILABLE = False

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY,
    ts             TEXT         NOT NULL,
    thread_id      TEXT         NOT NULL,
    tenant_id      TEXT         NOT NULL,
    kind           TEXT         NOT NULL,
    node           TEXT,
    tool_name      TEXT,
    tool_args      TEXT,
    result_snippet TEXT,
    latency_ms     INTEGER,
    token_usage    TEXT,
    actor          TEXT
);
CREATE INDEX IF NOT EXISTS audit_log_thread_ts ON audit_log(thread_id, ts);
CREATE INDEX IF NOT EXISTS audit_log_tenant_ts ON audit_log(tenant_id, ts);
"""

_INSERT = """
INSERT INTO audit_log
    (ts, thread_id, tenant_id, kind, node, tool_name, tool_args,
     result_snippet, latency_ms, token_usage, actor)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant_from_thread(thread_id: str) -> str:
    return thread_id.split(":")[0]


@dataclass
class AuditRow:
    thread_id: str
    tenant_id: str
    kind: str  # llm_call|tool_call|tool_result|approval_requested|approval_granted|approval_rejected|error
    ts: str = field(default_factory=_now_iso)
    node: Optional[str] = None
    tool_name: Optional[str] = None
    tool_args: Optional[str] = None
    result_snippet: Optional[str] = None
    latency_ms: Optional[int] = None
    token_usage: Optional[str] = None
    actor: str = "agent"


class AuditSink:
    """Append-only SQLite audit log. write() never raises; __init__ raises on connection failure."""

    # Log on first failure and then every N failures to avoid log spam.
    _LOG_INTERVAL = 50

    def __init__(self, db_path: str | sqlite3.Connection):
        if isinstance(db_path, sqlite3.Connection):
            self._conn = db_path
        else:
            if db_path not in (":memory:",):
                os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._consecutive_failures = 0

    def write(self, row: AuditRow) -> None:
        try:
            self._conn.execute(
                _INSERT,
                (
                    row.ts, row.thread_id, row.tenant_id, row.kind, row.node,
                    row.tool_name, row.tool_args, row.result_snippet,
                    row.latency_ms, row.token_usage, row.actor,
                ),
            )
            self._conn.commit()
            self._consecutive_failures = 0
        except Exception as exc:
            self._consecutive_failures += 1
            if self._consecutive_failures == 1 or self._consecutive_failures % self._LOG_INTERVAL == 0:
                logger.error(
                    "AuditSink.write failed (%d consecutive failures): %s",
                    self._consecutive_failures, exc,
                )


class AuditCallbackHandler(BaseCallbackHandler):
    """Writes llm_call and tool_call rows on each graph step."""

    def __init__(self, sink: AuditSink, thread_id: str):
        super().__init__()
        self._sink = sink
        self._thread_id = thread_id
        self._tenant_id = _tenant_from_thread(thread_id)
        self._start_times: dict[str, float] = {}

    def on_llm_start(
        self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any
    ) -> None:
        run_id = str(kwargs.get("run_id", ""))
        self._start_times[run_id] = time.monotonic()

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        run_id = str(kwargs.get("run_id", ""))
        self._start_times.pop(run_id, None)

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        run_id = str(kwargs.get("run_id", ""))
        start = self._start_times.pop(run_id, None)
        latency_ms = int((time.monotonic() - start) * 1000) if start is not None else None
        usage = None
        if response.llm_output:
            usage = response.llm_output.get("token_usage")
        self._sink.write(AuditRow(
            thread_id=self._thread_id,
            tenant_id=self._tenant_id,
            kind="llm_call",
            node="llm_node",
            latency_ms=latency_ms,
            token_usage=json.dumps(usage) if usage else None,
        ))

    def on_chain_start(
        self,
        serialized: dict[str, Any] | None,
        inputs: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        name = kwargs.get("name") or (serialized or {}).get("name", "")
        if name != "tool_node":
            return
        messages = inputs.get("messages", [])
        if not messages:
            return
        last = messages[-1]
        tcs = getattr(last, "tool_calls", None) or []
        if not tcs:
            return
        for tc in tcs:
            self._sink.write(AuditRow(
                thread_id=self._thread_id,
                tenant_id=self._tenant_id,
                kind="tool_call",
                node="tool_node",
                tool_name=tc.get("name"),
                tool_args=json.dumps(tc.get("args", {})),
            ))
