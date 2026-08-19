"""Tests for progress-aware multi-step workflow protection."""
from types import SimpleNamespace

from harness.progress import ProgressController


def _controller(**overrides):
    options = {
        "max_runtime_seconds": 60,
        "emergency_iteration_limit": 100,
        "max_stalled_batches": 3,
        "max_repeated_calls": 2,
        "checkpoint_every_actions": 4,
    }
    options.update(overrides)
    return ProgressController(**options)


def _call(name="http", **arguments):
    return SimpleNamespace(name=name, arguments=arguments)


def test_new_results_allow_a_long_workflow() -> None:
    controller = _controller()
    call = _call(url="http://target/items")

    for number in range(12):
        decision = controller.record_batch([call], [{"status": 200, "body": str(number)}])
        assert decision.continue_running

    assert controller.actions_completed == 12


def test_unchanged_results_stop_after_stall_threshold() -> None:
    controller = _controller(max_stalled_batches=2, max_repeated_calls=20)
    call = _call(url="http://target/items")

    assert controller.record_batch([call], [{"error": "same permanent error"}]).continue_running
    assert controller.record_batch([call], [{"error": "same permanent error"}]).continue_running
    stopped = controller.record_batch([call], [{"error": "same permanent error"}])

    assert not stopped.continue_running
    assert "consecutive" in stopped.reason


def test_transient_failures_do_not_count_as_stalled_loop_evidence() -> None:
    controller = _controller(max_stalled_batches=1, max_repeated_calls=1)
    call = _call(url="http://target/items")

    for _ in range(4):
        assert controller.record_batch(
            [call], [{"status": 503, "body": "temporarily unavailable"}]
        ).continue_running


def test_unchanged_pane_reads_have_a_separate_consecutive_limit() -> None:
    controller = _controller(
        max_stalled_batches=20, max_repeated_calls=20,
        max_unchanged_pane_reads=3)
    call = _call("pane_read", pane_id="pane-1")

    assert controller.record_batch([call], [{"output": ""}]).continue_running
    assert controller.record_batch([call], [{"output": ""}]).continue_running
    stopped = controller.record_batch([call], [{"output": ""}])

    assert not stopped.continue_running
    assert "pane reads" in stopped.reason


def test_repeated_identical_action_stops_without_a_new_result() -> None:
    controller = _controller(max_repeated_calls=2, max_stalled_batches=20)
    call = _call(command="nmap target")

    assert controller.record_batch([call], [{"output": "same"}]).continue_running
    assert controller.record_batch([call], [{"output": "same"}]).continue_running
    stopped = controller.record_batch([call], [{"output": "same"}])

    assert not stopped.continue_running
    assert "repeated" in stopped.reason


def test_reason_is_not_part_of_action_identity() -> None:
    controller = _controller(max_repeated_calls=1, max_stalled_batches=20)
    first = _call(command="nmap target", reason="first wording")
    second = _call(command="nmap target", reason="different wording")

    assert controller.record_batch([first], [{"output": "same"}]).continue_running
    assert not controller.record_batch([second], [{"output": "same"}]).continue_running


def test_checkpoint_is_due_after_configured_action_count() -> None:
    controller = _controller(checkpoint_every_actions=3)

    assert not controller.record_batch([_call(url="a")], [{"body": "a"}]).checkpoint_due
    assert not controller.record_batch([_call(url="b")], [{"body": "b"}]).checkpoint_due
    assert controller.record_batch([_call(url="c")], [{"body": "c"}]).checkpoint_due


def test_wall_clock_limit_is_independent_of_result_progress() -> None:
    now = [0.0]
    controller = ProgressController(
        max_runtime_seconds=10,
        emergency_iteration_limit=100,
        max_stalled_batches=3,
        max_repeated_calls=2,
        checkpoint_every_actions=10,
        clock=lambda: now[0],
    )

    now[0] = 10.0
    decision = controller.before_next_batch(0)
    assert not decision.continue_running
    assert "runtime" in decision.reason
