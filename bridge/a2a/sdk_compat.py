# bridge/a2a/sdk_compat.py
# Pinned imports for a2a-sdk 0.3.x — centralise symbol resolution here.
# If the SDK renames a symbol, fix it once here.
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.apps import A2AStarletteApplication
from a2a.server.apps.jsonrpc.jsonrpc_app import CallContextBuilder
from a2a.server.context import ServerCallContext
from a2a.server.events import EventQueue, InMemoryQueueManager
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCard,
    AgentCapabilities,
    AgentSkill,
    DataPart,
    HTTPAuthSecurityScheme,
    Message,
    Part,
    Role,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatusUpdateEvent,
    TextPart,
)

__all__ = [
    "AgentCard",
    "AgentCapabilities",
    "AgentExecutor",
    "AgentSkill",
    "A2AStarletteApplication",
    "CallContextBuilder",
    "DataPart",
    "DefaultRequestHandler",
    "EventQueue",
    "HTTPAuthSecurityScheme",
    "InMemoryQueueManager",
    "InMemoryTaskStore",
    "Message",
    "Part",
    "RequestContext",
    "Role",
    "ServerCallContext",
    "TaskArtifactUpdateEvent",
    "TaskState",
    "TaskStatusUpdateEvent",
    "TaskUpdater",
    "TextPart",
]
