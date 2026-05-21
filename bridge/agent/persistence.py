from __future__ import annotations

import asyncio
import os
import sqlite3

from langgraph.checkpoint.base import BaseCheckpointSaver


def _patch_aiosqlite() -> None:
    """aiosqlite 0.22.x lacks Connection.is_alive(); langgraph-checkpoint-sqlite 2.x needs it."""
    import aiosqlite
    if not hasattr(aiosqlite.Connection, "is_alive"):
        aiosqlite.Connection.is_alive = lambda self: self._thread.is_alive()


def build_checkpointer(url: str) -> BaseCheckpointSaver:
    """Return a synchronous SqliteSaver. Used by tests and sync graph.stream() calls."""
    if url.startswith("sqlite:///"):
        from langgraph.checkpoint.sqlite import SqliteSaver
        path = url.removeprefix("sqlite:///")
        if path not in (":memory:",):
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        conn = sqlite3.connect(path, check_same_thread=False)
        saver = SqliteSaver(conn)
        saver.setup()
        return saver
    if url.startswith("sqlite://"):
        raise ValueError(
            f"Malformed SQLite URL {url!r}: use three slashes — "
            f"sqlite:///:memory: or sqlite:///path/to/file.db"
        )
    raise ValueError(f"Unsupported persistence URL: {url!r}")


def build_async_checkpointer(url: str) -> BaseCheckpointSaver:
    """Return an AsyncSqliteSaver by opening the connection in a temporary event loop.

    The aiosqlite background thread survives the loop closure and attaches to
    whatever loop is running at operation time (aiosqlite 0.17+).
    """
    _patch_aiosqlite()

    if url.startswith("sqlite:///"):
        import aiosqlite
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        path = url.removeprefix("sqlite:///")
        if path not in (":memory:",):
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

        async def _make() -> tuple:
            conn = await aiosqlite.connect(path)
            saver = AsyncSqliteSaver(conn)
            await saver.setup()
            return saver, conn

        saver, _conn = asyncio.run(_make())
        return saver

    if url.startswith("sqlite://"):
        raise ValueError(
            f"Malformed SQLite URL {url!r}: use three slashes — "
            f"sqlite:///:memory: or sqlite:///path/to/file.db"
        )
    raise ValueError(f"Unsupported persistence URL: {url!r}")
