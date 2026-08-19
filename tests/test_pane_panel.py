"""Interaction tests for the right-side pane tab panel."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Input

from harness.scope import Engagement
from harness.tui import ChatInput, ChatPanel, HarnessApp, OnboardingModal, PanePanel, _safe_ui_label


class PaneTestApp(App):
    def compose(self) -> ComposeResult:
        yield PanePanel()


class ChatTestApp(App):
    CSS = HarnessApp.CSS

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
    assert len(_safe_ui_label("x" * 200)) == 80


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
    HarnessApp._open_scratch_picker(app)

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
