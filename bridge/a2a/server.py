"""A2A Starlette application factory.

build_a2a_app() wires the executor into A2AStarletteApplication.
Returns the A2A app object (not a full Starlette app — that's agent/server.py).
"""
from bridge.a2a.auth import BearerTokenCallContextBuilder, TokenStore
from bridge.a2a.sdk_compat import (
    A2AStarletteApplication,
    DefaultRequestHandler,
    InMemoryQueueManager,
    InMemoryTaskStore,
)


def build_a2a_app(
    agent_card,
    executor,
    a2a_token_store: TokenStore,
    a2a_secret: str,
) -> A2AStarletteApplication:
    """Build the A2AStarletteApplication.

    Does NOT include the compat shim routes (/stream, /stream-resume, /chat).
    Those are added by agent/server.py alongside .routes() from this app.
    """
    task_store = InMemoryTaskStore()
    queue_manager = InMemoryQueueManager()
    context_builder = BearerTokenCallContextBuilder(a2a_token_store, a2a_secret)

    handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=task_store,
        queue_manager=queue_manager,
    )

    return A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=handler,
        context_builder=context_builder,
    )
