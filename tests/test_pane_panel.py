"""Interaction tests for the right-side pane tab panel."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.app import App, ComposeResult
from textual.css.scalar import Unit
from textual.widgets import Button, Input, RichLog

from halgate.scope import Engagement
from halgate.tui import (
    ChatInput,
    ConfigModal,
    ChatPanel,
    HalgateApp,
    HelpModal,
    OnboardingModal,
    PanePanel,
    _is_preformatted,
    _note_renderable,
    _safe_ui_label,
)


def _log_text(log: RichLog) -> str:
    return "\n".join(strip.text for strip in log.lines)


class PaneTestApp(App):
    def compose(self) -> ComposeResult:
        yield PanePanel()


class ChatTestApp(App):
    CSS = HalgateApp.CSS

    def compose(self) -> ComposeResult:
        chat = ChatPanel()
        chat.id = "chat-panel"
        yield chat


@pytest.mark.asyncio
async def test_cycle_and_close_active_note_pane() -> None:
    app = PaneTestApp()
    async with app.run_test() as pilot:
        panel = app.query_one(PanePanel)
        panel.note("first", "one")
        panel.note("second", "two")
        await pilot.pause()

        assert panel._tabs.active_pane is not None
        assert panel._tabs.active_pane.id == "note-2"
        assert panel.scroll_active(-1) is True
        assert panel.scroll_active(1) is True

        panel.cycle_tab(-1)
        assert panel._tabs.active_pane is not None
        assert panel._tabs.active_pane.id == "note-1"

        assert panel.close_active() is None
        await pilot.pause()
        assert panel._tabs.active_pane is not None
        assert panel._tabs.active_pane.id == "note-2"


@pytest.mark.asyncio
async def test_split_view_shows_two_panes_and_closes_top() -> None:
    app = PaneTestApp()
    async with app.run_test() as pilot:
        panel = app.query_one(PanePanel)
        panel.note("first", "first output")
        panel.note("second", "second output")
        await pilot.pause()

        assert panel.toggle_split() is True
        await pilot.pause()
        assert panel._split is True
        assert {panel._split_top, panel._split_bottom} == {"note-1", "note-2"}

        assert panel.close_active() is None
        await pilot.pause()
        assert panel._split is False
        assert panel._tab_ids == ["note-1"]


@pytest.mark.asyncio
async def test_prompt_recall_preserves_draft_and_is_bounded() -> None:
    app = ChatTestApp()
    async with app.run_test() as pilot:
        chat = app.query_one(ChatPanel)
        chat.set_prompt_history([f"prompt {i}" for i in range(25)])
        chat._set_input_text("draft")
        assert chat.recall_prompt(-1) is True
        assert chat._input.text == "prompt 24"
        assert chat.recall_prompt(-1) is True
        assert chat._input.text == "prompt 23"
        assert chat.recall_prompt(1) is True
        assert chat._input.text == "prompt 24"
        assert chat.recall_prompt(1) is True
        assert chat._input.text == "draft"
        await pilot.pause()


@pytest.mark.asyncio
async def test_composer_expands_to_four_lines_and_then_stops() -> None:
    app = ChatTestApp()
    async with app.run_test() as pilot:
        chat = app.query_one(ChatPanel)
        chat._set_input_text("one\ntwo\nthree\nfour\nfive")
        await pilot.pause()

        # Four text rows plus the TextArea's top and bottom borders.
        assert str(chat._input.styles.height) == "6"


@pytest.mark.asyncio
async def test_composer_enter_submits_and_shift_enter_inserts_newline() -> None:
    class ComposerApp(App):
        def __init__(self):
            super().__init__()
            self.submissions = 0

        def compose(self) -> ComposeResult:
            yield ChatInput(id="composer")

        def on_chat_input_submitted(self, message: ChatInput.Submitted) -> None:
            self.submissions += 1

    app = ComposerApp()
    async with app.run_test() as pilot:
        composer = app.query_one(ChatInput)
        composer.focus()
        await pilot.press("shift+enter")
        assert composer.text == "\n"
        await pilot.press("enter")
        assert app.submissions == 1


@pytest.mark.asyncio
async def test_thinking_and_context_status_share_a_persistent_bottom_bar() -> None:
    app = ChatTestApp()
    async with app.run_test() as pilot:
        chat = app.query_one(ChatPanel)
        chat.add_status("ctx: 512/8,192 (6%) | 1 turns")
        chat.show_thinking()
        await pilot.pause()

        assert "ctx: 512/8,192" in str(chat._status.render())
        assert "Thinking..." in str(chat._thinking.render())
        assert str(chat._status_bar.styles.dock) == "bottom"

        chat.stop_thinking()
        assert "Thought for 0:00" in str(chat._thinking.render())


def test_ui_labels_are_nonempty_bounded_and_single_line() -> None:
    assert _safe_ui_label("") == "Untitled"
    assert _safe_ui_label("  one\n\ttwo  ") == "one two"
    assert _safe_ui_label("HTTP Endpoints (Juice Store :30000)") == \
        "HTTP Endpoints (Juice Store:30000)"
    assert len(_safe_ui_label("x" * 200)) == 80


@pytest.mark.asyncio
async def test_pane_control_labels_are_compact_in_both_split_states() -> None:
    app = PaneTestApp()
    async with app.run_test() as pilot:
        panel = app.query_one(PanePanel)
        panel.note("first", "one")
        panel.note("second", "two")
        await pilot.pause()

        def total_label_text() -> int:
            return sum(len(btn.label.plain)
                       for btn in (panel._split_btn, panel._close_btn,
                                   panel._save_btn, panel._load_btn))

        assert total_label_text() <= 24
        assert panel.toggle_split() is True
        assert total_label_text() <= 24
        assert panel.toggle_split() is True
        assert panel._split is False
        assert total_label_text() <= 24


@pytest.mark.asyncio
async def test_pane_titles_are_sanitized_before_creating_tabs() -> None:
    app = PaneTestApp()
    async with app.run_test() as pilot:
        panel = app.query_one(PanePanel)
        panel.note("", "content")
        panel.add_pane("pane-01", "x" * 200)
        await pilot.pause()

        assert panel._tab_titles["note-1"] == "Untitled"
        assert len(panel._tab_titles["process-pane-01"]) == 80


@pytest.mark.asyncio
async def test_active_snapshot_binds_saved_content_to_its_engagement() -> None:
    app = PaneTestApp()
    async with app.run_test() as pilot:
        panel = app.query_one(PanePanel)
        panel.note("report", "captured output", "eng-01")
        await pilot.pause()

        assert panel.active_snapshot() == ("report", "captured output", "eng-01")


def test_load_uses_the_only_active_engagement_when_no_pane_exists(tmp_path: Path) -> None:
    """A first load on a new engagement should create its first note pane."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source = scratch / "brief.txt"
    source.write_text("engagement notes")
    engagement = Engagement("eng-01", "Target", "127.0.0.1", "read-only",
                            scratch_dir=str(scratch))

    class Gate:
        def active_engagements(self):
            return [engagement]

        def _require_active(self, engagement_id: str):
            assert engagement_id == engagement.id
            return engagement

    class LoadApp:
        def __init__(self) -> None:
            self._pane_panel = SimpleNamespace(active_snapshot=lambda: None)
            self.h = SimpleNamespace(gate=Gate())
            self.notifications = []
            self.screen = None
            self.callback = None

        def notify(self, message: str, severity: str) -> None:
            self.notifications.append((message, severity))

        def push_screen(self, screen, callback) -> None:
            self.screen = screen
            self.callback = callback

    app = LoadApp()
    HalgateApp._open_scratch_picker(app)

    assert app.notifications == []
    assert app.screen is not None
    assert app.screen._files == [source.resolve()]


@pytest.mark.asyncio
async def test_onboarding_lifetime_usage_is_docked_at_the_bottom() -> None:
    class OnboardingApp(App):
        def on_mount(self) -> None:
            self.push_screen(OnboardingModal(
                ["read-only"], "read-only", [], "Lifetime usage: 100 tokens"))

    app = OnboardingApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        status = app.screen.query_one("#onb-lifetime")
        passphrase = app.screen.query_one("#onb-key-passphrase", Input).value
        assert str(status.render()) == "Lifetime usage: 100 tokens"
        assert str(status.styles.dock) == "bottom"
        assert len(passphrase) == 12
        assert passphrase.isdecimal()
        await pilot.pause()


def _halgate_stub(chat_width_pct: int) -> SimpleNamespace:
    """Just enough halgate surface for HalgateApp.on_mount to run."""
    return SimpleNamespace(
        session_id="8d3d4bd12df1",
        engagements=[SimpleNamespace(id="eng-01", package="defensive",
                                     label="Target", target="127.0.0.1")],
        router=SimpleNamespace(
            active_endpoint=SimpleNamespace(id="remote-coder")),
        config=SimpleNamespace(
            tui=SimpleNamespace(chat_width_pct=chat_width_pct),
            sessions=SimpleNamespace(dir="/tmp"),
            packages={}, scope=SimpleNamespace(package="defensive")),
        tracker=SimpleNamespace(status_line=lambda: "ctx: 0/100 (0%)"),
        registry=SimpleNamespace(ctx=SimpleNamespace(extra={})),
        process_mgr=SimpleNamespace(
            list=lambda: [], drain_output=lambda pane_id: ""),
        lifetime_tokens=SimpleNamespace(status_line=lambda: ""))


@pytest.mark.asyncio
async def test_chat_width_and_identity_follow_config() -> None:
    halgate = _halgate_stub(75)
    app = HalgateApp(halgate)
    async with app.run_test() as pilot:
        await pilot.pause()

        width = app.query_one("#chat-panel").styles.width
        assert (width.value, width.unit) == (75.0, Unit.WIDTH)
        assert app.title == "halgate — 8d3d4bd1"

        header = str(app.query_one("#header-text").render())
        assert "session:8d3d4bd1" in header
        assert "8d3d4bd12df1" not in header
        assert "scope:defensive" in header
        assert "llm:remote-coder" in header


@pytest.mark.asyncio
async def test_chat_width_nudges_step_and_clamp_at_bounds() -> None:
    halgate = _halgate_stub(75)
    app = HalgateApp(halgate)
    async with app.run_test() as pilot:
        await pilot.pause()

        app.action_grow_chat()
        assert halgate.config.tui.chat_width_pct == 79
        width = app.query_one("#chat-panel").styles.width
        assert (width.value, width.unit) == (79.0, Unit.WIDTH)

        app.action_shrink_chat()
        assert halgate.config.tui.chat_width_pct == 75

        halgate.config.tui.chat_width_pct = 80
        app.action_grow_chat()
        assert halgate.config.tui.chat_width_pct == 80

        halgate.config.tui.chat_width_pct = 20
        app.action_shrink_chat()
        assert halgate.config.tui.chat_width_pct == 20


@pytest.mark.asyncio
async def test_agent_responses_render_markdown_and_user_turns_are_labeled() -> None:
    app = ChatTestApp()
    async with app.run_test() as pilot:
        chat = app.query_one(ChatPanel)
        chat.add_user("recheck 8080")
        chat.add_agent(
            "## Findings\n\n- **Open port** on `8080`\n"
            "```\ncurl http://127.0.0.1:8080\n```",
            markup=False,
        )
        chat.add_agent("[yellow]Dry-run enabled.[/yellow]")
        await pilot.pause()

        text = _log_text(chat._log)
        assert "Findings" in text
        assert "Open port" in text
        assert "**" not in text
        assert "curl http://127.0.0.1:8080" in text
        assert "```" not in text
        assert "Agent:" in text
        # UI notices keep their text but get no speaker label
        assert "Dry-run enabled." in text
        assert text.count("Agent:") == 1
        # user turns are quoted and separated from the following turn
        assert "> recheck 8080" in text
        assert "\u2500" in text


def test_agent_transcript_keeps_plain_text() -> None:
    chat = ChatPanel()
    chat.add_user("hi")
    chat.add_agent("- **bold** note", markup=False)
    assert chat.transcript() == "> hi\n\nAgent: - **bold** note"


def test_tool_result_formatting_and_truncation() -> None:
    out = ChatPanel._format_result(
        "http",
        {"status": 302, "url": "http://127.0.0.1/api",
         "headers": {"content-type": "text/html", "location": "/login"},
         "body": "B" * 2000})
    assert out.startswith("HTTP 302 http://127.0.0.1/api (text/html)")
    assert "location: /login" in out
    assert "… (truncated; 800 more characters)" in out

    out = ChatPanel._format_result(
        "shell", {"rc": 0, "stdout": "ok"})
    assert out.startswith("Exit code: 0")
    assert "ok" in out

    out = ChatPanel._format_result(
        "scan", {"hosts": ["127.0.0.1"], "raw": "scan complete"})
    assert "Hosts: 127.0.0.1" in out
    assert "scan complete" in out

    short = ChatPanel._truncate_block("abc", 5)
    assert short == "abc"
    long = ChatPanel._truncate_block("a" * 1300, 1000)
    assert long.startswith("a" * 1000)
    assert long.endswith("… (truncated; 300 more characters)")


@pytest.mark.asyncio
async def test_activity_log_shows_structured_results() -> None:
    app = ChatTestApp()
    async with app.run_test() as pilot:
        chat = app.query_one(ChatPanel)
        chat.toggle_activity()
        chat.add_activity("tool_call", "http: {\"url\": \"http://127.0.0.1/api\"}")
        chat.add_activity(
            "tool_result",
            "http: " + json.dumps({
                "status": 302, "url": "http://127.0.0.1/api",
                "headers": {"content-type": "text/html", "location": "/login"},
                "body": "B" * 2000,
            }))
        await pilot.pause()

        text = _log_text(chat._activity)
        assert "Proposed action:" in text
        assert "http" in text
        assert "HTTP 302 http://127.0.0.1/api (text/html)" in text
        assert "location: /login" in text
        assert "truncated" in text


@pytest.mark.asyncio
async def test_activity_toggle_buttons_raise_and_lower() -> None:
    app = ChatTestApp()
    async with app.run_test() as pilot:
        chat = app.query_one(ChatPanel)
        toggle = app.query_one("#activity-toggle", Button)
        collapse = app.query_one("#collapse-activity", Button)
        await pilot.pause()

        assert toggle.label.plain == "^^^"
        assert collapse.label.plain == "vvv"
        # collapsed by default: the raise button shows, lower is hidden
        assert toggle.styles.display != "none"
        assert collapse.styles.display == "none"

        chat.toggle_activity()
        await pilot.pause()
        # expanded: the lower button now shows
        assert toggle.styles.display == "none"
        assert collapse.styles.display != "none"


@pytest.mark.asyncio
async def test_context_status_turns_amber_then_red() -> None:
    app = ChatTestApp()
    async with app.run_test():
        chat = app.query_one(ChatPanel)
        chat.add_status("ctx: 60/100 (60%)")
        assert chat._status.has_class("ctx-warn")
        assert not chat._status.has_class("ctx-crit")

        chat.add_status("ctx: 90/100 (90%)")
        assert chat._status.has_class("ctx-crit")
        assert not chat._status.has_class("ctx-warn")

        chat.add_status("ctx: 12/100 (12%)")
        assert not chat._status.has_class("ctx-warn")
        assert not chat._status.has_class("ctx-crit")


@pytest.mark.asyncio
async def test_restore_history_routes_each_entry_kind() -> None:
    app = ChatTestApp()
    async with app.run_test() as pilot:
        chat = app.query_one(ChatPanel)
        chat.toggle_activity()
        chat.restore_history([
            {"role": "user", "content": "scan the box"},
            {"role": "assistant", "content": "I will scan.", "tool_calls": [
                {"id": "c1", "function": {
                    "name": "scan",
                    "arguments": '{"targets": "127.0.0.1"}'}}]},
            {"role": "tool", "tool_call_id": "c1",
             "content": '{"hosts": ["127.0.0.1"], "raw": "scan complete"}'},
        ])
        await pilot.pause()

        text = _log_text(chat._log)
        assert "> scan the box" in text
        assert "I will scan." in text
        assert "Agent:" in text

        activity = _log_text(chat._activity)
        assert "Proposed action:" in activity
        assert "scan" in activity
        assert "Hosts: 127.0.0.1" in activity


@pytest.mark.asyncio
async def test_pane_notes_render_markdown() -> None:
    app = PaneTestApp()
    async with app.run_test() as pilot:
        panel = app.query_one(PanePanel)
        panel.note("report", "# Report\n\n- **done**\n- `code`")
        await pilot.pause()

        text = _log_text(next(iter(panel._notes.values())))
        assert "Report" in text
        assert "done" in text
        assert "code" in text
        assert "**" not in text


@pytest.mark.asyncio
async def test_header_buttons_open_help_and_config() -> None:
    halgate = _halgate_stub(62)
    halgate.router.active_endpoint = SimpleNamespace(
        id="remote-coder", base_url="https://api.example", model="model",
        api_key="key", temperature=0.2, max_tokens=4096)
    app = HalgateApp(halgate)
    async with app.run_test() as pilot:
        await pilot.pause()

        assert ("f1", "help", "Help") in HalgateApp.BINDINGS
        help_btn = app.query_one("#header-help", Button)
        config_btn = app.query_one("#header-config", Button)

        help_btn.press()
        await pilot.pause()
        assert isinstance(app.screen, HelpModal)
        assert "F1 / Esc to close" in str(app.screen.query_one("#help-title").render())
        assert "/engagement claims" in _log_text(
            app.screen.query_one("#help-log", RichLog))
        assert "**" not in _log_text(app.screen.query_one("#help-log", RichLog))

        await pilot.press("f1")
        await pilot.pause()
        assert not isinstance(app.screen, HelpModal)

        config_btn.press()
        await pilot.pause()
        assert not isinstance(app.screen, HelpModal)
        assert isinstance(app.screen, ConfigModal)


@pytest.mark.asyncio
async def test_secret_reveal_is_audited() -> None:
    revealed: list[str] = []

    class _FakeKeyStore:
        async def reveal(self, cred_id: str) -> str:
            return "shhh"

    class _FakeAudit:
        def secret_reveal(self, cred_id: str) -> None:
            revealed.append(cred_id)

    halgate = _halgate_stub(62)
    halgate._keystore = _FakeKeyStore()
    halgate.audit = _FakeAudit()
    app = HalgateApp(halgate)
    async with app.run_test() as pilot:
        await pilot.pause()
        await app._handle_command("/secret reveal cred_abc123")
        await pilot.pause()

    assert revealed == ["cred_abc123"]
    assert "Revealed" in _log_text(app._chat._log)


PORT_TABLE = (
    "PORT      STATE          SERVICE\n"
    "3000/tcp  open           http Node.js Express framework\n"
    "6463/tcp  open           unknown (HTTP/JSON API, 404 Not Found)\n"
    "49486/tcp filtered       unknown\n"
    "\nSummary: 10 open, 1 filtered, 65,524 closed"
)


def test_preformatted_detection_distinguishes_tables_and_prose() -> None:
    assert _is_preformatted(PORT_TABLE) is True
    assert _is_preformatted("col1\tcol2\nval1\tval2") is True
    assert _is_preformatted(
        "# Title\n\n- one\n- two\n\nPlain prose line here.") is False
    assert _is_preformatted("| a | b |\n|---|---|\n| 1 | 2 |") is False
    assert _is_preformatted("just one plain line") is False


def test_note_renderable_is_raw_for_tables_and_markdown_for_reports() -> None:
    from rich.markdown import Markdown

    assert _note_renderable(PORT_TABLE) == PORT_TABLE
    assert isinstance(_note_renderable(
        "# Head\n\n- item"), Markdown)


@pytest.mark.asyncio
async def test_note_pane_preserves_table_alignment() -> None:
    app = PaneTestApp()
    async with app.run_test() as pilot:
        panel = app.query_one(PanePanel)
        panel.note("Open Ports", PORT_TABLE)
        await pilot.pause()

        text = _log_text(next(iter(panel._notes.values())))
        assert "PORT      STATE" in text
        assert "3000/tcp  open" in text
        assert "49486/tcp filtered" in text
        # A Markdown pass would join the header row into the first data row.
        assert "SERVICE 3000/tcp" not in text


@pytest.mark.asyncio
async def test_note_pane_renders_markdown_reports() -> None:
    app = PaneTestApp()
    async with app.run_test() as pilot:
        panel = app.query_one(PanePanel)
        panel.note(
            "Findings",
            "# Findings\n\n- **open** port on `8080`\n"
            "```\ncurl localhost:8080\n```")
        await pilot.pause()

        text = _log_text(next(iter(panel._notes.values())))
        assert "Findings" in text
        assert "open" in text
        assert "**" not in text
        assert "```" not in text
