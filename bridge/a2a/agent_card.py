# bridge/a2a/agent_card.py
from bridge.a2a.sdk_compat import (
    AgentCard, AgentCapabilities, AgentSkill, HTTPAuthSecurityScheme,
)


def build_agent_card(base_url: str) -> AgentCard:
    """Build the A2A AgentCard for the task-tracker reference agent.

    base_url: the server's root URL, e.g. "http://localhost:8080". The A2A
    JSON-RPC endpoint is at the root, so the card URL equals base_url.
    """
    url = base_url.rstrip("/")
    return AgentCard(
        name="Task Tracker Agent",
        description=(
            "Reference A2A agent over a task-tracker domain. "
            "Supports listing, reading, creating, and updating tasks. "
            "Destructive actions (delete) require human approval."
        ),
        url=url,
        version="0.1.0",
        capabilities=AgentCapabilities(
            streaming=True,
            push_notifications=False,
            state_transition_history=False,
        ),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        security_schemes={
            "bearer": HTTPAuthSecurityScheme(scheme="Bearer"),
        },
        security=[{"bearer": ["tasks.read"]}],
        skills=[
            AgentSkill(
                id="query",
                name="Task query",
                description="List and read tasks.",
                tags=["tasks", "read"],
                input_modes=["text/plain"],
                output_modes=["text/plain"],
            ),
            AgentSkill(
                id="mutate",
                name="Task mutation",
                description=(
                    "Create, update, or delete tasks. "
                    "Destructive actions require human approval."
                ),
                tags=["tasks", "write"],
                input_modes=["text/plain"],
                output_modes=["text/plain"],
            ),
        ],
    )
