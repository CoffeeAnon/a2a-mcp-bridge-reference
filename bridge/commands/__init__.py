"""Importing this package registers every task-tracker command in REGISTRY."""
from bridge.commands import list_tasks, get_task, create_task, update_task, delete_task  # noqa: F401
