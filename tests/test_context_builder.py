"""Tests for compact, protocol-correct tool context projection."""

import json

from harness.context_builder import ToolContextBuilder


def _call(call_id: str, name: str, arguments: dict) -> dict:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


def test_completed_scan_is_replaced_by_finding_without_command() -> None:
    command = "nmap -sV --script dangerous 192.168.4.132"
    messages = [
        {"role": "user", "content": "scan it"},
        {"role": "assistant", "content": None,
         "tool_calls": [_call("scan-1", "scan", {
             "targets": ["192.168.4.132"], "reason": "enumerate ports"})]},
        {"role": "tool", "tool_call_id": "scan-1", "content": json.dumps({
            "hosts": [{"host": "192.168.4.132", "ports": [
                {"port": "3000", "proto": "tcp", "state": "open",
                 "service": "http"}]}],
            "raw": command * 10,
        })},
        {"role": "assistant", "content": "Port 3000 is open."},
        {"role": "user", "content": "what next?"},
    ]

    built = ToolContextBuilder().build(messages)

    assert built.compacted_exchanges == 1
    assert all("tool_calls" not in message for message in built.messages)
    text = "\n".join(str(message.get("content", "")) for message in built.messages)
    assert "3000/tcp open http" in text
    assert command not in text
    # The durable transcript is not mutated: UI/audit restoration still has it.
    assert messages[1]["tool_calls"][0]["function"]["name"] == "scan"


def test_open_exchange_retains_required_tool_protocol_messages() -> None:
    messages = [
        {"role": "user", "content": "scan it"},
        {"role": "assistant", "content": None,
         "tool_calls": [_call("scan-1", "scan", {"targets": ["192.168.4.132"]})]},
        {"role": "tool", "tool_call_id": "scan-1", "content": "{\"hosts\": []}"},
    ]

    built = ToolContextBuilder().build(messages)

    assert built.compacted_exchanges == 0
    assert built.messages == messages


def test_open_exchange_bounds_large_tool_output_but_keeps_protocol() -> None:
    large_body = "x" * 10_000
    messages = [
        {"role": "assistant", "content": None,
         "tool_calls": [_call("http-1", "http", {"url": "http://target/"})]},
        {"role": "tool", "tool_call_id": "http-1", "content": json.dumps({
            "status": 200, "body": large_body})},
    ]

    built = ToolContextBuilder().build(messages)

    assert built.messages[1]["role"] == "tool"
    assert built.messages[1]["tool_call_id"] == "http-1"
    result = json.loads(built.messages[1]["content"])
    assert result["truncated_for_context"] is True
    assert result["full_result_in_audit"] is True
    assert result["body_chars_visible"] < result["body_chars_returned"]
    assert len(result["body"]) < len(large_body)
    assert len(messages[1]["content"]) > len(built.messages[1]["content"])


def test_open_source_exchange_bounds_code_but_preserves_metadata() -> None:
    source = "x" * 10_000
    messages = [
        {"role": "assistant", "content": None,
         "tool_calls": [_call("source-1", "read_source_code", {"path": "app.py"})]},
        {"role": "tool", "tool_call_id": "source-1", "content": json.dumps({
            "relative_path": "app.py", "language": "python", "content": source})},
    ]

    built = ToolContextBuilder().build(messages)

    result = json.loads(built.messages[1]["content"])
    assert result["relative_path"] == "app.py"
    assert result["truncated_for_context"] is True
    assert len(result["content"]) < len(source)


def test_completed_http_finding_discloses_context_excerpt_and_response_size() -> None:
    body = "x" * 10_000
    messages = [
        {"role": "assistant", "content": None,
         "tool_calls": [_call("http-1", "http", {"url": "http://target/"})]},
        {"role": "tool", "tool_call_id": "http-1", "content": json.dumps({
            "status": 200, "headers": {}, "body": body, "size": 10_000,
            "truncated": False, "elapsed_ms": 123.45})},
        {"role": "assistant", "content": "Done."},
    ]

    built = ToolContextBuilder().build(messages)

    finding = built.messages[0]["content"]
    assert "900/10000 returned chars" in finding
    assert "10000 response bytes" in finding
    assert "tool response complete" in finding
    assert "elapsed=123.45ms" in finding


def test_completed_source_read_keeps_path_range_and_language() -> None:
    messages = [
        {"role": "assistant", "content": None,
         "tool_calls": [_call("source-1", "read_source_code", {
             "path": "src/auth.py", "offset": 40, "limit": 50})]},
        {"role": "tool", "tool_call_id": "source-1", "content": json.dumps({
            "relative_path": "src/auth.py", "language": "python",
            "line_start": 40, "line_end": 89, "total_lines": 240,
            "truncated": True, "content": "def validate_token(token):\n    return token"})},
        {"role": "assistant", "content": "I found the token validator."},
    ]

    built = ToolContextBuilder().build(messages)

    finding = built.messages[0]["content"]
    assert "SOURCE path='src/auth.py'" in finding
    assert "language=python" in finding
    assert "lines=40-89 of 240" in finding
    assert "def validate_token" in finding


def test_harness_only_engagement_metadata_is_not_sent_to_endpoint() -> None:
    built = ToolContextBuilder().build([
        {"role": "user", "content": "scan it", "_engagement_scope": ["eng-01"]},
    ])

    assert built.messages == [{"role": "user", "content": "scan it"}]


def test_incomplete_parallel_exchange_is_not_compacted() -> None:
    messages = [
        {"role": "assistant", "content": None, "tool_calls": [
            _call("one", "scan", {"targets": ["192.168.4.132"]}),
            _call("two", "http", {"url": "http://192.168.4.132/"}),
        ]},
        {"role": "tool", "tool_call_id": "one", "content": "{}"},
        {"role": "assistant", "content": "continuing"},
    ]

    built = ToolContextBuilder().build(messages)

    assert built.compacted_exchanges == 0
    assert built.messages == messages


def test_completed_pane_exchange_is_absent_from_future_model_context() -> None:
    pane_command = "tail -f /var/log/target.log"
    pane_output = "password=not-for-the-model\n" * 100
    messages = [
        {"role": "user", "content": "watch the service"},
        {"role": "assistant", "content": None, "tool_calls": [
            _call("pane-1", "pane_spawn", {
                "name": "service-log", "command": pane_command,
                "engagement_id": "eng-01"}),
        ]},
        {"role": "tool", "tool_call_id": "pane-1", "content": json.dumps({
            "id": "pane-01", "name": "service-log", "status": "running"})},
        {"role": "assistant", "content": "The log pane is running."},
        {"role": "user", "content": "continue"},
    ]

    built = ToolContextBuilder().build(messages)

    assert built.compacted_exchanges == 1
    text = "\n".join(str(message.get("content", "")) for message in built.messages)
    assert pane_command not in text
    assert pane_output not in text
    assert "pane-01" not in text
