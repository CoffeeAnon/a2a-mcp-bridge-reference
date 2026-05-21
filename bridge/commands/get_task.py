from bridge.core.client import InMemoryTaskStore
from bridge.core.registry import BaseCommand, command


@command(name="get-task", hitl=False)
class GetTask(BaseCommand):
    def execute(self, client: InMemoryTaskStore, *, task_id: str, **kwargs) -> list[dict]:
        return [client.get(task_id)]
