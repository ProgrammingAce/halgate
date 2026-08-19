"""The harness must request a final summary after empty tool-followup turns."""
import pytest

from harness.harness import Harness
from harness.llm.client import Completion, TokenUsage, ToolCall
from harness.scope import Engagement


class _SummaryClient:
    def __init__(self):
        self.messages = []
        self._responses = [
            Completion(
                content="",
                tool_calls=[ToolCall(
                    id="recall", name="memory_recall",
                    arguments={"engagement_id": "eng1", "query": ""})],
                usage=TokenUsage(10, 5, 15)),
            Completion(content="", tool_calls=[], usage=TokenUsage(12, 4, 16)),
            Completion(content="Summary of completed tool work.", tool_calls=[],
                       usage=TokenUsage(14, 8, 22)),
        ]

    async def stream_complete(self, messages, tools, on_delta):
        self.messages.append(messages)
        return self._responses.pop(0)

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_empty_post_tool_response_triggers_explicit_summary_prompt(config):
    engagement = Engagement("eng1", "target", "192.168.4.10", "defensive")
    harness = Harness(config, [engagement])
    client = _SummaryClient()
    harness.router._clients[harness.router.active_id] = client

    result = await harness.run("Inspect the target")

    assert result == "Summary of completed tool work."
    assert len(client.messages) == 3
    assert any("preceding tool calls have completed" in message["content"]
               for message in client.messages[2]
               if message["role"] == "user")
