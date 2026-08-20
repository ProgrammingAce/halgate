"""The halgate must request a final summary after empty tool-followup turns."""
import pytest

from halgate.halgate import Halgate
from halgate.llm.client import Completion, TokenUsage, ToolCall
from halgate.scope import Engagement


class _SummaryClient:
    def __init__(self):
        self.messages = []
        self._responses = [
            Completion(
                content="",
                tool_calls=[ToolCall(
                    id="recall", name="memory_recall",
                    arguments={"engagement_id": "eng1", "query": ""})],
                usage=TokenUsage(10, 5)),
            Completion(content="", tool_calls=[], usage=TokenUsage(12, 4)),
            Completion(content="Summary of completed tool work.", tool_calls=[],
                       usage=TokenUsage(14, 8)),
        ]

    async def stream_complete(self, messages, tools, on_delta):
        self.messages.append(messages)
        return self._responses.pop(0)

    async def close(self):
        pass


class _CompactionClient:
    def __init__(self):
        self.compaction_messages = []
        self.stream_messages = []

    async def complete(self, messages, tools=None):
        self.compaction_messages.append(messages)
        return Completion(content="Earlier target state summarized.", tool_calls=[],
                          usage=TokenUsage(10, 5))

    async def stream_complete(self, messages, tools, on_delta):
        self.stream_messages.append(messages)
        return Completion(content="Done.", tool_calls=[],
                          usage=TokenUsage(12, 4))

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_empty_post_tool_response_triggers_explicit_summary_prompt(config):
    engagement = Engagement("eng1", "target", "192.168.4.10", "defensive")
    halgate = Halgate(config, [engagement])
    client = _SummaryClient()
    halgate.router._clients[halgate.router.active_endpoint.id] = client

    result = await halgate.run("Inspect the target")

    assert result == "Summary of completed tool work."
    assert len(client.messages) == 3
    assert any("preceding tool calls have completed" in message["content"]
               for message in client.messages[2]
               if message["role"] == "user")


@pytest.mark.asyncio
async def test_compaction_keeps_the_system_prompt_first_and_unique(config):
    halgate = Halgate(config, [])
    client = _CompactionClient()
    halgate.router._clients[halgate.router.active_endpoint.id] = client
    halgate.messages = [
        {"role": "user", "content": "Inspect the target."},
        {"role": "assistant", "content": "Beginning inspection."},
    ]

    assert await halgate.compact(2) == "compacted 2 turns"
    assert halgate.messages[0]["role"] == "assistant"

    assert await halgate.run("What did you find?") == "Done."
    request = client.stream_messages[0]
    assert request[0]["role"] == "system"
    assert [message["role"] for message in request].count("system") == 1
    assert request[1] == {
        "role": "assistant",
        "content": "[COMPACT] Earlier target state summarized.",
    }


@pytest.mark.asyncio
async def test_compaction_uses_structured_source_aware_history(config):
    halgate = Halgate(config, [])
    client = _CompactionClient()
    halgate.router._clients[halgate.router.active_endpoint.id] = client
    halgate.messages = [
        {"role": "assistant", "content": None, "tool_calls": [{
            "id": "source-1", "type": "function", "function": {
                "name": "read_source_code",
                "arguments": '{"path":"src/api.py"}'}}]},
        {"role": "tool", "tool_call_id": "source-1", "content":
         '{"relative_path":"src/api.py","language":"python",'
         '"line_start":1,"line_end":2,"total_lines":200,"truncated":true,'
         '"content":"def handle_request(): pass"}'},
    ]

    assert await halgate.compact(2) == "compacted 2 turns"
    prompt = client.compaction_messages[0][0]["content"]
    assert "REPOSITORY MAP" in prompt
    assert "SOURCE path='src/api.py'" in prompt
    assert "lines=1-2 of 200" in prompt


def test_compaction_never_cuts_through_a_tool_exchange(config):
    halgate = Halgate(config, [])
    halgate.messages = [
        {"role": "user", "content": "Inspect source."},
        {"role": "assistant", "content": None, "tool_calls": [{
            "id": "source-1", "type": "function", "function": {
                "name": "read_source_code", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "source-1", "content": "{}"},
        {"role": "assistant", "content": "Read complete."},
    ]

    assert halgate._safe_compaction_end(2) == 1
    assert halgate._safe_compaction_end(3) == 3
