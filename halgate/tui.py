"""Textual TUI: chat left, panes right, status bar bottom."""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from rich.markdown import Markdown
from rich.markup import escape
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.message import Message
from textual.widgets import (
    Button, Checkbox, Input, RichLog, Select, Static,
    TabbedContent, TabPane, TextArea,
)
from textual.screen import ModalScreen

from .halgate import Halgate
from .dispatch import ApprovalResult, dispatch_parallel
from .llm.client import ToolCall
from .scope import extract_hostnames, extract_target_refs, extract_urls


# Auto-approval is intentionally narrow and remains target-scoped.
# ScopeGate and the normal budget reservation run before this policy is
# consulted in dispatch_parallel.
TARGET_AUTO_APPROVE_TOOLS = frozenset({"shell", "http", "http_replay", "http_session", "auth_session", "multipart_upload", "websocket", "tcp_probe", "scan", "jwt_sign"})
HTTP_RESULT_TOOLS = frozenset({"http", "http_replay", "http_session"})

SLASH_COMMANDS: list[tuple[str, str]] = [
    ("/status", "current scope, engagement, and safety status"),
    ("/panes", "list running tool processes"),
    ("/recall <query>", "search stored memories"),
    ("/checkpoint", "save a checkpoint now (auto-named)"),
    ("/approval reset", "clear session target auto-approvals"),
    ("/compact [N]", "compress transcript, keep last N turns (default 1)"),
    ("/dry-run on|off", "toggle dry-run mode for all tools"),
    ("/panic", "kill all processes and lock further actions"),
    ("/resume-actions", "unlock actions after /panic"),
    ("/budget [id]", "show budget usage (all or one budget)"),
    ("/engagement list", "list engagements"),
    ("/engagement add label:target[:package]", "add an engagement"),
    ("/engagement pause|resume <id>", "pause or resume an engagement"),
    ("/engagement claims <id> add|remove [key...]", "manage JWT claim extensions"),
    ("/secret list | /secret reveal <id> | /secret store", "browse stored secrets"),
    ("/kill <name>", "kill a running process"),
    ("/sessions", "resume a saved session"),
    ("/new", "start a new scope and engagement"),
    ("/quit", "save a checkpoint and exit"),
]

HELP_MARKDOWN = """\
## Keys

* **Enter** — submit prompt · **Shift+Enter** — newline
* **Up/Down** — prompt history, or scroll the focused pane
* **Tab / Shift+Tab** — cycle panes
* **Esc** — cancel a running prompt (press again to dismiss)
* **F1** — this help · **F5** — refresh panes
* **Ctrl+Shift+[ / ]** — narrow / widen the chat panel
* **Ctrl+Shift+C** — copy selection · **Ctrl+Shift+A** — copy transcript
* **Ctrl+Shift+V** — paste from system clipboard · **Ctrl+C** — quit
* **?** button — this help · **⚙ button** — settings

## Commands

""" + "\n".join(f"* `{c}` — {d}" for c, d in SLASH_COMMANDS)
PANE_SCROLLBACK_LINES = 20_000
MAX_UI_LABEL_LENGTH = 80


# Some terminal multiplexers and remote terminals can deliver mouse reports to
# the focused input as text (for example ESC[<35;141;31M). Textual normally
# consumes these, but treating them as user input is never useful or safe.
_TERMINAL_INPUT_SEQUENCE = re.compile(
    r"\x1b\[<?\d{1,3};\d{1,5};\d{1,5}[Mm]"  # SGR / X10 mouse report
    r"|\[<\d{1,3};\d{1,5};\d{1,5}[Mm]"      # ESC was swallowed upstream
    r"|\x1b\[200~|\x1b\[201~"                # bracketed-paste markers
    r"|\x1b\[[0-?]*[ -/]*[@-~]"                # remaining ANSI CSI controls
    r"|\x1b"
)


def _strip_terminal_input_sequences(value: str) -> str:
    """Remove terminal control traffic that must not reach an agent prompt."""
    return _TERMINAL_INPUT_SEQUENCE.sub("", value)


def _safe_ui_label(value: object, fallback: str = "Untitled") -> str:
    """Make externally supplied titles safe for tabs, buttons, and headings."""
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or ""))
    text = " ".join(text.split())
    text = re.sub(r"\s+:", ":", text)
    if not text:
        return fallback
    if len(text) > MAX_UI_LABEL_LENGTH:
        return text[:MAX_UI_LABEL_LENGTH - 1].rstrip() + "…"
    return text


def _is_preformatted(text: str) -> bool:
    """True for whitespace-aligned content (column tables, raw command output).

    Two or more lines that align columns with interior tabs or runs of two or
    more spaces between words are treated as preformatted so their layout is
    preserved verbatim.  Single-space prose, Markdown lists, and pipe tables
    (which use single spaces) all return False.
    """
    padded = 0
    for line in text.splitlines():
        if re.search(r"\S\t\S", line) or re.search(r"\S {2,}\S", line):
            padded += 1
            if padded >= 2:
                return True
    return False


def _note_renderable(content: str):
    """Render a note body for a pane.

    Preformatted tables and raw output keep their exact spacing; everything
    else is Markdown so headings, lists, code, and pipe tables format nicely.
    """
    if _is_preformatted(content):
        return content
    return Markdown(content)


def _exact_action_target(call: ToolCall) -> str | None:
    """Return one concrete network target, or None for ambiguous actions.

    This is a second, stricter check on top of ScopeGate.  CIDRs, multiple
    targets, and commands with no identifiable network target cannot inherit
    an approval intended for one host.
    """
    if call.name not in TARGET_AUTO_APPROVE_TOOLS:
        return None
    # JWT minting never contacts a network host, but it is already bound to
    # exactly one engagement by dispatch. The session rule is keyed by that
    # engagement and is cleared on target changes, so it can safely inherit
    # the operator's explicit "approve all for this target" decision.
    if call.name == "jwt_sign":
        return "engagement-bound"
    candidates: list[str] = []
    if call.name == "scan":
        targets = call.arguments.get("targets") or []
        if isinstance(targets, str):
            targets = targets.split()
        candidates = [str(target).strip() for target in targets if str(target).strip()]
    elif call.name in {"http", "http_replay", "http_session", "auth_session", "multipart_upload", "websocket"}:
        parsed = urlsplit(str(call.arguments.get("url") or ""))
        if not parsed.scheme or not parsed.hostname:
            return None
        candidates = [parsed.hostname.lower()]
    elif call.name == "tcp_probe":
        host = str(call.arguments.get("host") or "").strip().lower()
        if not host:
            return None
        candidates = [host]
    else:  # shell
        command = str(call.arguments.get("command") or "")
        for url in extract_urls(command):
            parsed = urlsplit(url)
            if parsed.scheme and parsed.hostname:
                candidates.append(parsed.hostname.lower())
        candidates.extend(extract_target_refs(command))
        candidates.extend(extract_hostnames(command))

    normalized = {candidate.rstrip(".").lower() for candidate in candidates}
    # A slash denotes a CIDR/network target. Host paths occur only in the
    # shell extractor and must not be treated as an approval target either.
    if len(normalized) != 1:
        return None
    target = next(iter(normalized))
    if target.startswith("/") or "/" in target:
        return None
    return target


def _approval_requirement_reason(call: ToolCall) -> str:
    """Explain the safety boundary that requires this operator decision."""
    reasons = {
        "shell": "It executes a command and may affect the host or send network traffic.",
        "http": "It sends a network request to the engagement target.",
        "scan": "It sends active network probes to the engagement target.",
        "write_file": "It changes a file in the engagement scope.",
        "pane_write": "It sends input to a running process, changing its behavior.",
        "memory_forget": "It permanently removes saved memory.",
        "memory_edit": "It changes saved memory.",
        "request_callback_endpoint": ("It provisions a local network listener "
                                      "that accepts inbound HTTP, TCP, or DNS callbacks; the "
                                      "listener is bound to this engagement "
                                      "and expires automatically."),
        "jwt_sign": ("It mints an HS256 or explicitly scope-enabled unsigned "
                     "authentication token, bound to this engagement's declared "
                     "claim set and lifetime. HS256 uses a referenced keystore "
                     "credential; the token never appears in text, logs, or "
                     "model context."),
    }
    return reasons.get(call.name, "This action can change state or interact with an external system.")


class ChatInput(TextArea):
    """Composer that reserves Enter for send while retaining Shift+Enter."""

    class Submitted(Message):
        def __init__(self, text_area: "ChatInput") -> None:
            self.text_area = text_area
            super().__init__()

    async def _on_key(self, event: events.Key) -> None:
        if event.key == "enter":
            event.stop()
            event.prevent_default()
            self.post_message(self.Submitted(self))
            return
        if event.key == "shift+enter":
            # Some terminals report this chord as a distinct key rather than
            # Enter with the Shift modifier; TextArea only inserts for `enter`.
            event.stop()
            event.prevent_default()
            start, end = self.selection
            self._replace_via_keyboard("\n", start, end)
            return
        await super()._on_key(event)


class ChatPanel(Vertical):
    """Left panel: chat log + input."""

    CSS = """
    ChatPanel {
        layout: vertical;
    }
    ChatPanel RichLog {
        height: 1fr;
        width: 100%;
    }
    ChatPanel TextArea {
        height: 3;
        min-height: 3;
        max-height: 6;
        width: 100%;
        color: $text;
        background: $surface;
        border: tall $accent;
    }
    ChatPanel TextArea:focus {
        color: $text;
        background: $surface;
        border: tall $primary;
    }
    ChatPanel Static {
        height: 1;
        width: 100%;
    }
    ChatPanel #activity-toggle {
        height: 1;
        width: 100%;
        content-align: left middle;
    }
    ChatPanel #collapse-activity {
        display: none;
        height: 1;
        width: 100%;
        content-align: left middle;
    }
    ChatPanel #activity-log {
        display: none;
        height: 8;
        width: 100%;
        border: tall $accent;
    }
    ChatPanel #stream-output {
        display: none;
        height: auto;
        max-height: 10;
        padding: 0 1;
        border: tall $primary;
        overflow-y: auto;
    }
    ChatPanel #status-bar {
        dock: bottom;
        height: 1;
        width: 100%;
        layout: horizontal;
        background: $surface;
        color: $text-muted;
    }
    ChatPanel #context-status {
        width: 1fr;
        padding: 0 1;
    }
    ChatPanel #context-status.ctx-warn {
        color: $warning;
    }
    ChatPanel #context-status.ctx-crit {
        color: $error;
    }
    ChatPanel #thinking-status {
        width: auto;
        padding: 0 1;
        color: $accent;
    }
    """

    def __init__(self):
        super().__init__()
        self._log = RichLog(highlight=True, markup=True, wrap=True,
                            max_lines=2000)
        self._input = ChatInput(
            placeholder="Type your request or /command... (Shift+Enter for newline)",
            soft_wrap=True, show_line_numbers=False, id="chat-input")
        self._status = Static("ctx: awaiting first response", id="context-status")
        self._thinking = Static("", id="thinking-status")
        self._status_bar = Horizontal(
            self._status, self._thinking, id="status-bar")
        self._activity_toggle = Button("^^^", id="activity-toggle")
        self._activity_collapse = Button("vvv", id="collapse-activity")
        self._activity = RichLog(highlight=True, markup=True, wrap=True,
                                 max_lines=500, id="activity-log")
        self._stream = Static("", id="stream-output")
        self._stream_text = ""
        self._stream_has_response = False
        self._activity_open = False
        self._log_has_entries = False
        self._transcript: list[str] = []
        self._think_timer = None
        self._thinking_started: float | None = None
        self._prompt_history: list[str] = []
        self._prompt_index: int | None = None
        self._prompt_draft = ""

    def compose(self) -> ComposeResult:
        yield self._log
        yield self._activity_toggle
        yield self._activity_collapse
        yield self._activity
        yield self._stream
        yield self._input
        yield self._status_bar

    def _separator(self) -> None:
        """Rule between chat turns, so wrapped text can't merge entries."""
        if not self._log_has_entries:
            self._log_has_entries = True
            return
        n = max(20, self._log.scrollable_content_region.width - 2)
        self._log.write(f"\n[dim]{chr(9472) * n}[/dim]")

    def add_user(self, text: str) -> None:
        self._separator()
        self._transcript.append(f"> {text}")
        self._log.write(f"\n[bold]> {escape(text)}[/bold]")

    def add_agent(self, text: str, *, markup: bool = True) -> None:
        """Add a harness notice or assistant response to the chat log.

        UI-generated notices (``markup=True``) keep their severity colors and
        no speaker label. Model responses pass ``markup=False`` so their text
        can't alter the UI; those are labelled and rendered as Markdown
        (headings, lists, code, tables) rather than as raw text.
        """
        self._separator()
        if markup:
            self._transcript.append(text)
            self._log.write(f"\n{text}")
        else:
            self._transcript.append(f"Agent: {text}")
            self._log.write("\n[bold cyan]Agent:[/bold cyan]")
            if text.strip():
                self._log.write(Markdown(text))

    def add_activity(self, kind: str, text: str) -> None:
        """Show operator-visible agent progress, not private reasoning."""
        if kind == "agent":
            self._transcript.append(f"Agent: {text}")
            self._activity.write(f"[cyan]Agent:[/cyan] {escape(text)}")
        elif kind == "tool_call":
            name, sep, args = text.partition(": ")
            self._transcript.append(f"Proposed action: {text}")
            if sep:
                self._activity.write(
                    f"[yellow]Proposed action:[/yellow] [bold]{escape(name)}[/bold]  "
                    f"{escape(args)}")
            else:
                self._activity.write(
                    f"[yellow]Proposed action:[/yellow] {escape(text)}")
        elif kind == "tool_result":
            name, sep, raw = text.partition(": ")
            if sep:
                try:
                    rendered = self._format_result(name, json.loads(raw))
                except json.JSONDecodeError:
                    rendered = self._truncate_block(raw, 1_500)
            else:
                rendered = self._truncate_block(text, 1_500)
            self._transcript.append(f"Result: {rendered}")
            self._activity.write(f"[dim]Result:[/dim] {escape(rendered)}")

    def add_live_output(self, action: str, stream: str, text: str) -> None:
        """Append live subprocess output to the collapsible Activity panel."""
        if not self._activity_open:
            self.toggle_activity()
        self._activity.write(
            f"[dim]{escape(action)} {escape(stream)}:[/dim] {escape(text)}")

    @staticmethod
    def _truncate_block(text: str, limit: int) -> str:
        """Cap displayed tool output with an explicit truncation marker."""
        if len(text) <= limit:
            return text
        return text[:limit] + f"\n… (truncated; {len(text) - limit:,} more characters)"

    @classmethod
    def _format_result(cls, name: str, result: Any) -> str:
        """Turn verbose tool JSON into an operator-readable result."""
        if not isinstance(result, dict):
            return str(result)
        if name in HTTP_RESULT_TOOLS and "status" in result:
            headers = result.get("headers") or {}
            summary = [f"HTTP {result.get('status', '?')}"]
            if result.get("url"):
                summary.append(str(result["url"]))
            content_type = headers.get("content-type")
            if content_type:
                summary.append(f"({content_type})")
            lines = [" ".join(summary)]
            for key in ("location", "server", "set-cookie"):
                if key in headers:
                    lines.append(f"  {key}: {headers[key]}")
            body = str(result.get("body") or "")
            if body:
                lines.append("")
                lines.append(cls._truncate_block(body, 1_200))
            return "\n".join(lines)
        if name == "scan":
            hosts = result.get("hosts") or []
            raw = str(result.get("raw") or "")
            return (f"Hosts: {', '.join(map(str, hosts)) or 'none reported'}\n\n"
                    + cls._truncate_block(raw, 1_500))
        if name == "shell":
            output = str(result.get("stdout") or result.get("stderr") or "")
            return (f"Exit code: {result.get('rc', '?')}\n\n"
                    + cls._truncate_block(output, 1_500))
        return cls._truncate_block(
            json.dumps(result, indent=2, default=str), 1_500)

    def toggle_activity(self) -> None:
        """Expand or collapse the operator-facing thinking/activity trace."""
        self._activity_open = not self._activity_open
        self._activity.styles.display = "block" if self._activity_open else "none"
        self._activity_toggle.styles.display = "none" if self._activity_open else "block"
        self._activity_collapse.styles.display = "block" if self._activity_open else "none"

    def stream_event(self, kind: str, text: str) -> None:
        """Render response tokens as they arrive, without persisting a draft."""
        if kind == "start":
            self._stream_text = ""
            self._stream_has_response = False
        elif kind == "delta":
            self._stream_has_response = True
            self._stream_text += text
            self._stream.update(self._stream_text)
            self._stream.styles.display = "block"
        elif kind == "end":
            # A response with no visible tokens keeps its elapsed indicator in
            # the persistent status row between tool/model batches.
            if not self._stream_has_response:
                self._stream.styles.display = "none"

    def transcript(self) -> str:
        """Return the plain-text chat transcript for clipboard export."""
        return "\n\n".join(self._transcript)

    def restore_history(self, messages: list[dict]) -> None:
        """Rebuild visible backscroll from a checkpoint transcript.

        Routes each entry through the same methods the live run uses so a
        restored session looks identical to a session that was never closed.
        """
        self._log.clear()
        self._activity.clear()
        self._transcript.clear()
        self._log_has_entries = False
        tool_names: dict[str, str] = {}
        for message in messages:
            role = message.get("role")
            if role == "user":
                self.add_user(str(message.get("content") or ""))
            elif role == "assistant":
                content = message.get("content")
                if content:
                    self.add_agent(str(content), markup=False)
                for call in message.get("tool_calls") or []:
                    function = call.get("function") or {}
                    tool_names[str(call.get("id") or "")] = str(
                        function.get("name") or "tool")
                    self.add_activity(
                        "tool_call",
                        f"{function.get('name') or 'tool'}: "
                        f"{function.get('arguments') or '{}'}")
            elif role == "tool":
                name = tool_names.get(
                    str(message.get("tool_call_id") or ""), "tool")
                self.add_activity(
                    "tool_result",
                    f"{name}: {str(message.get('content') or '')}")

    def add_status(self, text: str) -> None:
        self._update_status(text)

    def _update_status(self, text: str) -> None:
        """Show context usage; turn amber/red as the budget fills up."""
        match = re.search(r"\((\d+)%\)", text)
        pct = int(match.group(1)) if match else 0
        self._status.remove_class("ctx-warn", "ctx-crit")
        if pct >= 80:
            self._status.add_class("ctx-crit")
        elif pct >= 50:
            self._status.add_class("ctx-warn")
        self._status.update(text)

    def get_input(self) -> str:
        return self._input.text

    def focus_input(self) -> None:
        self._input.focus()

    def clear_input(self) -> None:
        self._set_input_text("")
        self._input.focus()

    def _set_input_text(self, text: str) -> None:
        self._input.load_text(text)
        lines = text.splitlines() or [""]
        self._input.move_cursor((len(lines) - 1, len(lines[-1])))
        self._resize_input()

    def _resize_input(self) -> None:
        """Expand the composer to four visible text lines, then scroll."""
        text = self._input.text
        wrap_width = max(1, self._input.wrap_width or 80)
        visual_lines = sum(
            max(1, (len(line) + wrap_width - 1) // wrap_width)
            for line in (text.splitlines() or [""]))
        # TextArea's two border rows surround up to four text rows.
        self._input.styles.height = min(6, 2 + visual_lines)

    def set_prompt_history(self, prompts: list[str]) -> None:
        """Install the current engagement's most recent prompt history."""
        self._prompt_history = prompts[-20:]
        self._prompt_index = None
        self._prompt_draft = ""

    def remember_prompt(self, prompt: str) -> None:
        if not prompt:
            return
        self._prompt_history.append(prompt)
        self._prompt_history = self._prompt_history[-20:]
        self._prompt_index = None
        self._prompt_draft = ""

    def recall_prompt(self, direction: int) -> bool:
        """Move through this scope's prompt history, preserving draft text."""
        if not self._prompt_history:
            return False
        if self._prompt_index is None:
            self._prompt_draft = self._input.text
            self._prompt_index = len(self._prompt_history)
        next_index = self._prompt_index + direction
        if next_index < 0:
            return True
        if next_index >= len(self._prompt_history):
            self._prompt_index = None
            self._set_input_text(self._prompt_draft)
            return True
        self._prompt_index = next_index
        prompt = self._prompt_history[next_index]
        self._set_input_text(prompt)
        return True

    def show_thinking(self) -> None:
        """Show elapsed model wait time without replacing context status."""
        self._thinking_started = time.monotonic()
        self._stream_text = ""
        self._stream_has_response = False
        self._thinking.update(self._thinking_text())
        if self._think_timer:
            return

        def tick() -> None:
            # Tool workflows can continue after a model streams an initial
            # explanation. Keep the elapsed request time live until the final
            # operator-facing response is committed.
            self._thinking.update(self._thinking_text())

        self._think_timer = self.set_interval(0.5, tick)

    def stop_thinking(self, *, completed: bool = True) -> None:
        """Stop the timer and retain the elapsed thought time on success."""
        thought_time = self._thinking_text(prefix="Thought for")
        if self._think_timer:
            self._think_timer.stop()
            self._think_timer = None
        self._thinking_started = None
        self._stream_text = ""
        self._stream_has_response = False
        self._thinking.update(thought_time if completed else "")
        self._stream.update("")
        self._stream.styles.display = "none"

    def _thinking_text(self, *, prefix: str = "Thinking...") -> str:
        """Format the elapsed operator-facing model wait time."""
        started = self._thinking_started
        elapsed = 0 if started is None else max(0, int(time.monotonic() - started))
        minutes, seconds = divmod(elapsed, 60)
        if prefix == "Thinking...":
            return f"[dim]Thinking... ({minutes}:{seconds:02d})[/dim]"
        return f"[dim]{prefix} {minutes}:{seconds:02d}[/dim]"


class PanePanel(Vertical):
    """Right panel: tabbed live pane outputs and saved notes."""

    def __init__(self):
        super().__init__()
        self._panes: dict[str, RichLog] = {}
        self._notes: dict[str, RichLog] = {}
        self._pane_text: dict[str, str] = {}
        self._tab_titles: dict[str, str] = {}
        self._tab_engagements: dict[str, str] = {}
        self._tab_ids: list[str] = []
        self._process_tabs: dict[str, str] = {}
        self._note_tabs: dict[str, str] = {}
        self._closed_processes: set[str] = set()
        self._tabs = TabbedContent(id="pane-tabs")
        self._header = Static("[bold]PANES (0) — Tab / Shift+Tab to switch[/bold]")
        self._split_btn = Button("Split", id="split-panes")
        self._close_btn = Button("Close", id="close-pane")
        self._save_btn  = Button("Save", id="save-pane")
        self._load_btn  = Button("Load", id="load-pane")
        self._split_view = Vertical(id="split-view")
        self._split_top_label = Static("", classes="split-label")
        self._split_top_log = RichLog(highlight=True, markup=False, wrap=True,
                                      max_lines=PANE_SCROLLBACK_LINES)
        self._split_bottom_label = Static("", classes="split-label")
        self._split_bottom_log = RichLog(highlight=True, markup=False, wrap=True,
                                         max_lines=PANE_SCROLLBACK_LINES)
        self._split_view.compose_add_child(self._split_top_label)
        self._split_view.compose_add_child(self._split_top_log)
        self._split_view.compose_add_child(self._split_bottom_label)
        self._split_view.compose_add_child(self._split_bottom_log)
        self._split = False
        self._split_top: str | None = None
        self._split_bottom: str | None = None

    def _set_button_label(self, button: Button, text: str) -> None:
        """Relabel a control button and force a layout pass.

        Textual's auto-sized buttons keep their measured width when only the
        label changes, so swap labels through this helper.
        """
        button.label = text
        button.refresh(layout=True)

    def note(self, name: str, content: str, engagement_id: str = "") -> None:
        """Create or replace a persistent, non-process panel note."""
        title = _safe_ui_label(name)
        key = f"note:{title}"
        if key in self._notes:
            self._notes[key].clear()
            self._notes[key].write(_note_renderable(content))
            pane_id = next((tab_id for tab_id, note_key in self._note_tabs.items()
                            if note_key == key), None)
            if pane_id:
                self._pane_text[pane_id] = content
                if engagement_id:
                    self._tab_engagements[pane_id] = engagement_id
                if self._split and pane_id in (self._split_top, self._split_bottom):
                    self._render_split()
            return
        # RichLog is focusable and vertically scrollable; Static clipped long
        # tables and reports, making stored panes effectively unreadable.
        # Notes preserve preformatted tables verbatim and render everything
        # else as Markdown so agent reports keep their structure.
        note = RichLog(highlight=True, markup=False, wrap=True,
                       max_lines=PANE_SCROLLBACK_LINES,
                       id=f"note-{len(self._notes) + 1}")
        note.write(_note_renderable(content))
        self._notes[key] = note
        pane_id = f"note-{len(self._notes)}"
        self._tabs.add_pane(TabPane(title, note, id=pane_id))
        self._tab_ids.append(pane_id)
        self._note_tabs[pane_id] = key
        self._pane_text[pane_id] = content
        self._tab_titles[pane_id] = title
        self._tab_engagements[pane_id] = engagement_id
        self.call_after_refresh(self._activate_tab, pane_id)
        self._refresh_header()

    def compose(self) -> ComposeResult:
        yield self._header
        yield self._tabs
        yield self._split_view
        yield Horizontal(self._split_btn, self._save_btn, self._load_btn, self._close_btn,
                         id="pane-controls")

    def add_pane(self, pane_id: str, name: str, engagement_id: str = "") -> None:
        if pane_id in self._closed_processes:
            return
        if pane_id in self._panes:
            if engagement_id:
                self._tab_engagements[f"process-{pane_id}"] = engagement_id
            return
        log = RichLog(highlight=True, markup=False, wrap=True,
                      max_lines=PANE_SCROLLBACK_LINES, name=f"pane-{pane_id}")
        tab_id = f"process-{pane_id}"
        title = _safe_ui_label(name, fallback="Process pane")
        self._tabs.add_pane(TabPane(title, log, id=tab_id))
        self._tab_ids.append(tab_id)
        self._process_tabs[tab_id] = pane_id
        self._panes[pane_id] = log
        self._pane_text[tab_id] = ""
        self._tab_titles[tab_id] = title
        self._tab_engagements[tab_id] = engagement_id
        # Bringing a newly created pane forward makes creation unmistakable;
        # the user can then cycle back through the visible tab strip.
        self.call_after_refresh(self._activate_tab, tab_id)
        self._refresh_header()

    def pane_output(self, pane_id: str, text: str) -> None:
        if pane_id in self._panes:
            self._panes[pane_id].write(text)
            tab_id = f"process-{pane_id}"
            self._pane_text[tab_id] = self._pane_text.get(tab_id, "") + text
            if self._split_top == tab_id:
                self._split_top_log.write(text)
            if self._split_bottom == tab_id:
                self._split_bottom_log.write(text)

    def cycle_tab(self, direction: int) -> None:
        if not self._tab_ids:
            return
        if self._split:
            self._cycle_split(direction)
            return
        active_pane = self._tabs.active_pane
        current = active_pane.id if active_pane is not None else None
        try:
            index = self._tab_ids.index(current)
        except ValueError:
            index = -1
        self._tabs.active = self._tab_ids[(index + direction) % len(self._tab_ids)]

    def scroll_active(self, direction: int) -> bool:
        """Scroll the visible pane a few lines without requiring mouse focus."""
        active_pane = self._tabs.active_pane
        tab_id = self._split_top if self._split else (
            active_pane.id if active_pane is not None else None)
        if not tab_id:
            return False
        process_id = self._process_tabs.get(tab_id)
        log = self._panes.get(process_id) if process_id else None
        if log is None:
            note_key = self._note_tabs.get(tab_id)
            log = self._notes.get(note_key) if note_key else None
        if log is None:
            return False
        log.scroll_relative(y=direction * 3, animate=False, immediate=True)
        return True

    def toggle_split(self) -> bool:
        """Toggle a simultaneous top/bottom view of two panes."""
        if not self._split and len(self._tab_ids) < 2:
            return False
        self._split = not self._split
        if self._split:
            active = self._tabs.active_pane
            top = active.id if active is not None else self._tab_ids[0]
            self._select_split_pair(top)
            self._tabs.styles.display = "none"
            self._split_view.styles.display = "block"
            self._set_button_label(self._split_btn, "Single")
            self._set_button_label(self._close_btn, "Close Top")
        else:
            self._tabs.styles.display = "block"
            self._split_view.styles.display = "none"
            if self._split_top:
                self._tabs.active = self._split_top
            self._set_button_label(self._split_btn, "Split")
            self._set_button_label(self._close_btn, "Close")
        self._refresh_header()
        return True

    def _cycle_split(self, direction: int) -> None:
        if not self._split_top:
            return
        try:
            index = self._tab_ids.index(self._split_top)
        except ValueError:
            index = 0
        self._select_split_pair(self._tab_ids[(index + direction) % len(self._tab_ids)])

    def _select_split_pair(self, top: str) -> None:
        self._split_top = top
        index = self._tab_ids.index(top)
        self._split_bottom = self._tab_ids[(index + 1) % len(self._tab_ids)]
        self._render_split()

    def _render_split(self) -> None:
        for tab_id, label, log in (
                (self._split_top, self._split_top_label, self._split_top_log),
                (self._split_bottom, self._split_bottom_label, self._split_bottom_log)):
            log.clear()
            if tab_id:
                label.update(f"[bold]{self._tab_titles.get(tab_id, tab_id)}[/bold]")
                body = self._pane_text.get(tab_id)
                if body:
                    # Notes render exactly like the single view (preserving
                    # preformatted tables / Markdown); process panes are raw.
                    log.write(_note_renderable(body)
                              if tab_id in self._note_tabs else body)

    def close_active(self) -> str | None:
        """Remove the active tab and return its backing process ID, if any."""
        active_pane = self._tabs.active_pane
        tab_id = self._split_top if self._split else (
            active_pane.id if active_pane is not None else None)
        if not tab_id:
            return None
        process_id = self._process_tabs.pop(tab_id, None)
        if process_id:
            self._panes.pop(process_id, None)
            self._closed_processes.add(process_id)
        note_key = self._note_tabs.pop(tab_id, None)
        if note_key:
            self._notes.pop(note_key, None)
        self._tab_ids = [item for item in self._tab_ids if item != tab_id]
        self._pane_text.pop(tab_id, None)
        self._tab_titles.pop(tab_id, None)
        self._tab_engagements.pop(tab_id, None)
        self._tabs.remove_pane(tab_id)
        if self._split:
            if len(self._tab_ids) < 2:
                self.toggle_split()
            else:
                self._select_split_pair(self._tab_ids[0])
        self._refresh_header()
        return process_id

    def reset(self) -> None:
        """Drop tabs from the prior session before panes are replayed."""
        for tab_id in list(self._tab_ids):
            self._tabs.remove_pane(tab_id)
        self._panes.clear()
        self._notes.clear()
        self._pane_text.clear()
        self._tab_titles.clear()
        self._tab_engagements.clear()
        self._tab_ids.clear()
        self._process_tabs.clear()
        self._note_tabs.clear()
        self._closed_processes.clear()
        self._split = False
        self._split_top = None
        self._split_bottom = None
        self._tabs.styles.display = "block"
        self._split_view.styles.display = "none"
        self._set_button_label(self._split_btn, "Split")
        self._set_button_label(self._close_btn, "Close")
        self._refresh_header()

    def _refresh_header(self) -> None:
        count = len(self._tab_ids)
        self._header.update(
            f"[bold]PANES ({count}) — Tab / Shift+Tab to switch[/bold]")

    def _activate_tab(self, tab_id: str) -> None:
        """Select a just-added tab after TabbedContent has mounted it."""
        if tab_id in self._tab_ids:
            self._tabs.active = tab_id
            if self._split:
                self._select_split_pair(tab_id)

    def active_snapshot(self) -> tuple[str, str, str] | None:
        """Return title, retained text, and engagement for the visible active pane."""
        active = self._tabs.active_pane
        tab_id = self._split_top if self._split else (active.id if active else None)
        if not tab_id or tab_id not in self._tab_ids:
            return None
        engagement_id = self._tab_engagements.get(tab_id)
        if not engagement_id:
            return None
        return (self._tab_titles.get(tab_id, "pane"),
                self._pane_text.get(tab_id, ""), engagement_id)


class ScratchPickerModal(ModalScreen):
    """Select a pre-enumerated regular file from one engagement scratch folder."""

    CSS = """
    ScratchPickerModal {
        width: 70;
        height: auto;
        max-height: 24;
        align: center middle;
        background: $surface;
        border: tall $accent;
    }
    ScratchPickerModal > Vertical { padding: 1 2; }
    ScratchPickerModal Button { margin-bottom: 1; }
    ScratchPickerModal ScrollableContainer { height: 1fr; }
    """

    def __init__(self, files: list[Path]):
        super().__init__()
        self._files = files

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("[bold]Load from engagement scratch[/bold]"),
            Static("Only regular files in this engagement's scratch folder are shown."),
            ScrollableContainer(
                *(Button(_safe_ui_label(path.name, fallback="scratch file"), id=f"scratch-{index}")
                  for index, path in enumerate(self._files)),
                Static("No eligible files found.") if not self._files else Static(""),
            ),
            Button("Cancel", id="scratch-cancel"),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scratch-cancel":
            self.dismiss(None)
            return
        if event.button.id and event.button.id.startswith("scratch-"):
            try:
                selected = self._files[int(event.button.id.removeprefix("scratch-"))]
            except (ValueError, IndexError):
                return
            self.dismiss(selected)


class OnboardingModal(ModalScreen):
    """Shown when no engagements are active on startup."""

    AUTO_FOCUS = "#onb-label"

    def __init__(self, packages: list[str], default_pkg: str,
                 sessions: list[dict], lifetime_usage: str = "",
                 key_file: str | None = None):
        super().__init__()
        self._packages = packages
        self._default_pkg = default_pkg
        self._sessions = sessions
        self._lifetime_usage = lifetime_usage
        self._key_file = Path(key_file).expanduser() if key_file else None
        self._key_ready = self._key_file is None

    CSS = """
    OnboardingModal {
        layout: vertical;
        align: center middle;
        /* Transparent so the live app is visible behind the setup card
           instead of a full-screen dimmed overlay that traps input. */
        background: transparent;
    }
    OnboardingModal #onb-content {
        width: 76;
        max-width: 96%;
        height: auto;
        max-height: 90%;
        background: $surface;
        border: tall $accent;
        padding: 1 2;
        overflow-y: auto;
    }
    OnboardingModal #onb-title {
        text-style: bold;
        color: $text;
    }
    OnboardingModal Input,
    OnboardingModal Checkbox {
        border: none;
        height: 1;
        padding: 0 1;
    }
    OnboardingModal #onb-cont {
        layout: vertical;
        height: auto;
    }
    OnboardingModal #onb-cont > Button {
        width: 100%;
    }
    OnboardingModal #onb-buttons {
        layout: vertical;
        height: auto;
        margin-top: 1;
    }
    OnboardingModal #onb-buttons > Button {
        width: 100%;
    }
    OnboardingModal #onb-lifetime {
        height: auto;
        margin-top: 1;
        width: 100%;
        color: $text-muted;
    }
    """

    BINDINGS = [
        ("ctrl+c", "dismiss", "Close"),
        # Escape reveals the live app behind the setup card, so first-run
        # never feels like input is being blocked.
        ("escape", "dismiss", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Setup: New Engagement", id="onb-title"),
            Static("  Label (e.g. 'Staging Server'):"),
            Input(placeholder="My Target App", max_length=MAX_UI_LABEL_LENGTH,
                  id="onb-label"),
            Static("  Target (IP, CIDR, hostname):"),
            Input(placeholder="10.0.0.1", id="onb-target"),
            Static("  Scope package:"),
            Select([(p, p) for p in self._packages],
                   value=self._default_pkg, compact=True, id="onb-pkg"),
            *self._key_controls(),
            *([Vertical(
                    *(Button("Continue: " + s['name'],
                             id=f"onb-cont-{s['id']}")
                      for s in self._sessions[:3]),
                    id="onb-cont",
             )] if self._sessions else []),
            Vertical(
                Button("Start Engagement", variant="success", id="onb-start",
                       disabled=self._key_file is not None and not self._key_file.exists()),
                Button("Manage Sessions", variant="warning", id="onb-manage"),
                *([Button("Generate new encryption key", variant="warning",
                          id="onb-key-generate")]
                  if self._key_file is not None else []),
                id="onb-buttons",
            ),
            Static(self._lifetime_usage, id="onb-lifetime"),
            id="onb-content",
        )

    def on_button_pressed(self, e: Button.Pressed) -> None:
        if e.button.id == "onb-start":
            self._do_start()
        elif e.button.id == "onb-manage":
            self.post_message(OnboardingModal.Manage())
            self.dismiss()
        elif e.button.id and e.button.id.startswith("onb-cont-"):
            sid = e.button.id.removeprefix("onb-cont-")
            self.post_message(OnboardingModal.Continued(sid))
            self.dismiss()
        elif e.button.id == "onb-key-generate":
            if self._key_file and self._key_file.exists():
                self.app.push_screen(KeyResetModal(), self._reset_key)
            else:
                self._create_key()

    def _do_start(self) -> None:
        label = _safe_ui_label(
            self.query_one("#onb-label", Input).value, fallback="Target")
        target = self.query_one("#onb-target", Input).value.strip()
        if not target:
            return
        pkg = self.query_one("#onb-pkg", Select).value
        if self._key_file is not None:
            if self._key_file.exists() and not self._key_ready:
                self.app.push_screen(
                    ExistingKeyWarningModal(), self._existing_key_response)
                return
            if not self._key_ready:
                return
        self.post_message(OnboardingModal.Started(
            label, target, pkg))
        self.dismiss()

    def _existing_key_response(self, result: str | None) -> None:
        if result == "confirmed":
            self._key_ready = True
            self._do_start()
        elif result == "replace":
            self.app.push_screen(KeyResetModal(), self._reset_key)

    def _key_controls(self) -> list:
        if self._key_file is None:
            return []
        if self._key_file.exists():
            return []
        return [
            Static("A native encryption key is required before starting a new "
                   "engagement."),
        ]

    def _create_key(self) -> None:
        from .crypto import NativeCrypto
        from .errors import EncryptionError
        try:
            phrase = NativeCrypto.initialize(self._key_file)
        except EncryptionError as e:
            self.app.notify(f"Couldn't create native key: {e}", severity="error")
            return
        self.app.push_screen(RecoveryPhraseModal(phrase), self._phrase_saved)

    def _phrase_saved(self, stored: bool) -> None:
        self._key_ready = stored
        if stored:
            self.query_one("#onb-start", Button).disabled = False
            self._do_start()

    def _reset_key(self, confirmed: bool) -> None:
        if not confirmed:
            return
        from .crypto import NativeCrypto
        from .errors import EncryptionError
        try:
            phrase, _ = NativeCrypto.archive_and_replace(self._key_file)
        except EncryptionError as e:
            self.app.notify(f"Couldn't replace native key: {e}", severity="error")
            return
        self._key_ready = False
        self.app.push_screen(RecoveryPhraseModal(phrase), self._phrase_saved)

    class Manage(Message):
        pass

    class Started(Message):
        def __init__(self, label: str, target: str, package: str):
            self.label = label
            self.target = target
            self.package = package
            super().__init__()

    class Continued(Message):
        def __init__(self, session_id: str):
            self.session_id = session_id
            super().__init__()


class ExistingKeyWarningModal(ModalScreen):
    """Require explicit recovery-phrase acknowledgement for an existing key."""

    BINDINGS = [("escape", "dismiss", "Cancel")]

    CSS = """
    ExistingKeyWarningModal { align: center middle; background: transparent; }
    ExistingKeyWarningModal #existing-key-content {
        width: 76; max-width: 96%; height: auto; background: $surface;
        border: tall $warning; padding: 1 2;
    }
    ExistingKeyWarningModal Button { width: 100%; }
    """

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("[bold]Recovery phrase required[/bold]"),
            Static("This engagement may retain encrypted credentials and forensic "
                   "records. You will need this key's recovery phrase to access "
                   "them after this session."),
            Checkbox("I have the recovery phrase", id="existing-key-confirm"),
            Button("Continue", variant="warning", id="existing-key-continue",
                   disabled=True),
            Button("Generate new encryption key", variant="error",
                   id="existing-key-replace"),
            id="existing-key-content",
        )

    def action_dismiss(self) -> None:
        self.dismiss(None)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "existing-key-confirm":
            self.query_one("#existing-key-continue", Button).disabled = not event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "existing-key-continue":
            self.dismiss("confirmed")
        elif event.button.id == "existing-key-replace":
            self.dismiss("replace")


class RecoveryPhraseModal(ModalScreen):
    """Blocking one-time display for a newly-created native recovery phrase."""

    BINDINGS = [
        ("escape", "dismiss", "Cancel"),
    ]

    CSS = """
    RecoveryPhraseModal {
        align: center middle;
        background: transparent;
    }
    RecoveryPhraseModal #recovery-content {
        width: 76;
        max-width: 96%;
        height: auto;
        background: $surface;
        border: tall $warning;
        padding: 1 2;
    }
    RecoveryPhraseModal #recovery-phrase {
        margin: 1 0;
        color: $warning;
        text-style: bold;
    }
    RecoveryPhraseModal Button {
        width: 100%;
    }
    """

    def __init__(self, phrase: str):
        super().__init__()
        self._phrase = phrase

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("[bold]Store your recovery phrase now[/bold]"),
            Static("This is the only copy Halgate will display. Keep it offline; "
                   "anyone with it can decrypt your protected records."),
            Static(escape(self._phrase), id="recovery-phrase"),
            Button("Copy recovery phrase", id="recovery-copy"),
            Checkbox("I stored this recovery phrase offline",
                     id="recovery-confirm"),
            Button("Continue", variant="warning", id="recovery-dismiss",
                   disabled=True),
            id="recovery-content",
        )

    def action_dismiss(self) -> None:
        self.dismiss(False)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "recovery-confirm":
            self.query_one("#recovery-dismiss", Button).disabled = not event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "recovery-copy":
            # HalgateApp provides OSC 52 plus a macOS pbcopy fallback, so this
            # path does not depend on terminal mouse selection/reporting.
            self.app._copy_text(self._phrase)  # type: ignore[attr-defined]
        elif event.button.id == "recovery-dismiss":
            self.dismiss(True)


class KeyResetModal(ModalScreen):
    """Require an explicit acknowledgement before archiving an active key."""

    CSS = """
    KeyResetModal { align: center middle; background: transparent; }
    KeyResetModal #key-reset-content {
        width: 76; max-width: 96%; height: auto; background: $surface;
        border: tall $error; padding: 1 2;
    }
    KeyResetModal Button { width: 100%; }
    """

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("[bold red]Replace encryption key[/bold red]"),
            Static("The existing key will be archived beside this key file. "
                   "Records encrypted with it require its original recovery "
                   "phrase. Type RESET to continue."),
            Input(placeholder="Type RESET", id="key-reset-input"),
            Button("Archive key and create replacement", variant="error",
                   id="key-reset-confirm", disabled=True),
            Button("Cancel", id="key-reset-cancel"),
            id="key-reset-content",
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "key-reset-input":
            self.query_one("#key-reset-confirm", Button).disabled = (
                event.value != "RESET")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "key-reset-confirm":
            self.dismiss(True)
        elif event.button.id == "key-reset-cancel":
            self.dismiss(False)


class ContinueModal(ModalScreen):
    """Pick a saved session to resume."""

    CSS = """
    ContinueModal {
        width: 50;
        height: auto;
        max-height: 20;
        align: center middle;
        background: $surface;
        border: tall $accent;
    }
    """

    def __init__(self, sessions: list[dict]):
        super().__init__()
        self._sessions = sessions

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("[bold]Continue Previous Session[/bold]"),
            *(Button(f"{s['name']}  ({s['created'][:10]})",
                     id=s["id"]) for s in self._sessions[:5]),
            Button("Cancel", id="cont-cancel"),
        )

    def on_button_pressed(self, e: Button.Pressed) -> None:
        if e.button.id == "cont-cancel":
            self.dismiss()
        else:
            self.post_message(ContinueModal.Picked(e.button.id))
            self.dismiss()

    class Picked(Message):
        def __init__(self, session_id: str):
            self.session_id = session_id
            super().__init__()


class ApprovalModal(ModalScreen):
    """Explicit in-TUI approval for an action proposed by the agent."""

    CSS = """
    ApprovalModal {
        width: 90%;
        height: 80%;
        align: center middle;
        background: $surface;
        border: tall $accent;
    }
    ApprovalModal > Vertical {
        height: 100%;
        padding: 1 2;
    }
    #approval-command {
        height: 1fr;
        width: 100%;
        border: tall $primary;
        padding: 0 1;
        overflow-y: auto;
    }
    #approval-summary {
        height: auto;
        border: tall $accent;
        padding: 0 1;
    }
    #approval-reason {
        height: auto;
        padding: 0 1;
        color: $warning;
    }
    """

    def __init__(self, call: ToolCall, engagement, exact_target: str | None = None):
        super().__init__()
        self._call = call
        self._engagement = engagement
        self._exact_target = exact_target

    def compose(self) -> ComposeResult:
        detail = (self._call.arguments.get("command")
                  or self._call.arguments.get("url")
                  or json.dumps(self._call.arguments, default=str))
        buttons = [Button("Approve", variant="success", id="approve")]
        if self._exact_target:
            buttons.append(Button(
                f"Approve all valid actions in {self._engagement.target} this session",
                id="approve-target"))
        buttons.extend([
            Button("Explain before approval", id="summarize"),
            Button("Deny", variant="error", id="deny"),
        ])
        yield Vertical(
            Static("[bold]Approval required[/bold]"),
            Static(f"{self._call.name} — {self._engagement.label} "
                   f"({self._engagement.target})"),
            Static("[yellow]Why approval is required:[/yellow] "
                   + _approval_requirement_reason(self._call),
                   id="approval-reason"),
            ScrollableContainer(Static(str(detail)), id="approval-command"),
            Static("", id="approval-summary"),
            Horizontal(*buttons),
        )

    def _summary(self) -> str:
        command = self._call.arguments.get("command")
        if command:
            effect = "Runs this command with the shown arguments."
        elif self._call.name == "scan":
            effect = "Sends network probes to the listed target(s) and ports."
        elif self._call.name == "http":
            effect = "Makes the shown HTTP request to the engagement target."
        else:
            effect = "Performs the displayed action with the shown arguments."
        purpose = self._call.arguments.get("reason") or (
            f"The agent proposed it for the active {self._engagement.label} engagement.")
        return (f"[bold]Before you approve[/bold]\n"
                f"What it will do: {effect}\n"
                f"Why: {purpose}\n"
                f"Scope: {self._engagement.label} — {self._engagement.target}\n"
                "Review the complete command above, then choose Approve or Deny.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "approve":
            self.dismiss(ApprovalResult(approved=True))
        elif event.button.id == "approve-target" and self._exact_target:
            self.dismiss(ApprovalResult(
                approved=True,
                auto_approve_target=self._engagement.target,
            ))
        elif event.button.id == "summarize":
            self.query_one("#approval-summary", Static).update(self._summary())
            event.button.disabled = True
        else:
            self.dismiss(ApprovalResult(approved=False))


class PaneModal(ModalScreen):
    """Collect the minimum data required to create a live pane."""

    AUTO_FOCUS = "#pane-name"

    def __init__(self, engagements: list):
        super().__init__()
        self._engagements = engagements

    def compose(self) -> ComposeResult:
        choices = [(_safe_ui_label(f"{e.label} ({e.target})"), e.id)
                   for e in self._engagements]
        yield Vertical(
            Static("[bold]New Pane[/bold]"),
            Input(placeholder="Pane name", max_length=MAX_UI_LABEL_LENGTH,
                  id="pane-name"),
            Input(placeholder="Allowed command", id="pane-command"),
            Select(choices, value=choices[0][1], id="pane-engagement"),
            Horizontal(Button("Start", variant="success", id="pane-start"),
                       Button("Cancel", id="pane-cancel")),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pane-cancel":
            self.dismiss()
            return
        name = _safe_ui_label(self.query_one("#pane-name", Input).value, fallback="")
        command = self.query_one("#pane-command", Input).value.strip()
        engagement_id = self.query_one("#pane-engagement", Select).value
        if name and command and isinstance(engagement_id, str):
            self.dismiss((name, command, engagement_id))


class SessionsModal(ModalScreen):
    """Manage saved sessions: press 1-9 to pick a session, then r/d.

    r = resume, d = delete
    """

    CSS = """
    SessionsModal {
        width: 78;
        height: auto;
        max-height: 30;
        align: center middle;
        background: $surface;
        border: tall $accent;
        padding: 1 2;
    }
    SessionsModal .sess-header {
        text-style: bold;
        margin-bottom: 1;
    }
    SessionsModal .sess-entry {
        padding: 0 1;
        margin-bottom: 1;
    }
    SessionsModal .sess-selected {
        background: $accent;
        text-style: bold;
    }
    SessionsModal .sess-help {
        margin-top: 1;
        text-style: italic;
        color: $text-muted;
    }
    """

    BINDINGS = [
        ("escape,ctrl+c", "dismiss", "Close"),
        ("up", "move_up", ""),
        ("down", "move_down", ""),
        ("r", "resume", "Resume"),
        ("d", "delete", "Delete"),
    ]

    def __init__(self, sessions: list[dict], sessions_dir: str = ".halgate_sessions"):
        super().__init__()
        self._sessions = sessions[:9]
        self._cursor = 0
        self._sessions_dir = sessions_dir
        self._rows: list[Static] = []

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Sessions — 1-9=select  up/down=cursor  r=resume  d=delete  esc=close",
                   classes="sess-header"),
            *[
                Static(
                    f"  [{i+1}]  {s['name']}  "
                    f"({', '.join(s.get('engagements', [])) or 'no target'})\n"
                    f"       {s['created'][:19]}  {s['turns']} turns  id:{s['id'][:12]}",
                    classes="sess-row",
                )
                for i, s in enumerate(self._sessions)
            ],
            Static("", id="sess-status"),
        )

    def on_mount(self) -> None:
        self._rows = list(self.query(".sess-row"))
        self._refresh()

    def _row_text(self, i: int, s: dict) -> str:
        return (
            f"  [{i+1}]  {s['name']}  "
            f"({', '.join(s.get('engagements', [])) or 'no target'})\n"
            f"       {s['created'][:19]}  {s['turns']} turns  id:{s['id'][:12]}"
        )

    def _refresh(self) -> None:
        for i, row in enumerate(self._rows):
            if i < len(self._sessions):
                row.update(self._row_text(i, self._sessions[i]))
            if i == self._cursor:
                row.add_class("sess-selected")
            else:
                row.remove_class("sess-selected")
        status = self.query_one("#sess-status", Static)
        if self._sessions:
            status.update(f"  [{self._cursor+1}] {self._sessions[self._cursor]['name']}")
        else:
            status.update("  (no sessions)")

    def _remove_session_row(self, index: int) -> None:
        if index < len(self._rows):
            self._rows[index].remove()
            self._rows.pop(index)
        # update remaining rows text
        for i, row in enumerate(self._rows):
            if i < len(self._sessions):
                row.update(self._row_text(i, self._sessions[i]))

    def _selected_session_id(self) -> str:
        if self._sessions:
            return self._sessions[self._cursor]["id"]
        return ""

    def action_dismiss(self) -> None:
        self.dismiss()

    def action_move_up(self) -> None:
        self._cursor = max(0, self._cursor - 1)
        self._refresh()

    def action_move_down(self) -> None:
        self._cursor = min(len(self._sessions) - 1, self._cursor + 1)
        self._refresh()

    def action_resume(self) -> None:
        sid = self._selected_session_id()
        if sid:
            self.post_message(SessionsModal.Resumed(sid))
            self.dismiss()

    def action_delete(self) -> None:
        sid = self._selected_session_id()
        if sid:
            from .sessions.checkpoint import SessionCheckpoint
            SessionCheckpoint.delete(self._sessions_dir, sid)
            self.post_message(SessionsModal.Deleted(sid))
            idx = self._cursor
            self._sessions.pop(self._cursor)
            if self._sessions:
                self._cursor = min(idx, len(self._sessions) - 1)
            self._remove_session_row(idx)
            self._refresh()

    def on_key(self, e: events.Key) -> None:
        if e.character and e.character.isdigit() and 1 <= int(e.character) <= len(self._sessions):
            self._cursor = int(e.character) - 1
            self._refresh()
            e.stop()

    class Resumed(Message):
        def __init__(self, session_id: str):
            self.session_id = session_id
            super().__init__()

    class Deleted(Message):
        def __init__(self, session_id: str):
            self.session_id = session_id
            super().__init__()


class HelpModal(ModalScreen):
    """Keyboard and slash-command reference (F1 or ? button)."""

    CSS = """
    HelpModal {
        width: 78;
        height: 22;
        align: center middle;
        background: $surface;
        border: tall $accent;
    }
    HelpModal #help-title {
        text-style: bold;
        padding: 0 1;
    }
    HelpModal #help-log {
        height: 1fr;
        margin: 0 1 1 1;
    }
    """

    BINDINGS = [
        ("f1", "dismiss", "Close"),
        ("escape", "dismiss", "Close"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._log = RichLog(
            highlight=False, markup=False, wrap=True,
            max_lines=2000, id="help-log")

    def compose(self) -> ComposeResult:
        yield Static("Help — F1 / Esc to close", id="help-title")
        yield self._log

    def on_mount(self) -> None:
        self._log.write(Markdown(HELP_MARKDOWN))

    def action_dismiss(self) -> None:
        self.dismiss()


class ConfigModal(ModalScreen):
    """Settings: LLM endpoint + tool availability toggles."""

    AUTO_FOCUS = "#cfg-url"

    CSS = """
    ConfigModal {
        width: 70;
        height: auto;
        max-height: 30;
        align: center middle;
        background: $surface;
        border: tall $accent;
    }
    ConfigModal .cfg-section {
        text-style: bold;
        margin-top: 1;
    }
    ConfigModal Input {
        margin: 0 0 1 0;
    }
    ConfigModal .cfg-row {
        layout: horizontal;
        margin-bottom: 1;
    }
    ConfigModal .cfg-row Label {
        width: 20;
    }
    ConfigModal .cfg-row Input {
        width: 1fr;
        margin: 0;
    }
    ConfigModal Button {
        margin-left: 2;
    }
    """

    BINDINGS = [
        ("escape,ctrl+c", "dismiss", "Close"),
    ]

    def __init__(self, endpoint: list, tools: list[dict],
                 active_pkg: str):
        """endpoint = [base_url, model, api_key, temperature, max_tokens]
        tools = [{'name': str, 'enabled': bool}, ...]
        """
        super().__init__()
        self._endpoint = endpoint
        self._tools = list(tools)
        self._active_pkg = active_pkg

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Configuration", classes="cfg-section"),
            Static("LLM Endpoint", classes="cfg-section"),
            Static("  Base URL (e.g. http://127.0.0.1:8080/v1)"),
            Input(value=self._endpoint[0], id="cfg-url"),
            Static("  Model"),
            Input(value=self._endpoint[1], id="cfg-model"),
            Static("  API Key (blank for local)"),
            Input(value=self._endpoint[2], password=True, id="cfg-key"),
            Static("  Temperature"),
            Input(value=str(self._endpoint[3]), id="cfg-temp"),
            Static("  Max Tokens"),
            Input(value=str(self._endpoint[4]), id="cfg-maxtok"),
            Static(" ", ),
            Static(f"Tools ({self._active_pkg} package)",
                   classes="cfg-section"),
            *[
                Static(f"  [{'x' if t['enabled'] else ' '}] {t['name']}")
                for t in self._tools
            ],
            Static(" "),
            Horizontal(
                Button("Save", variant="success", id="cfg-save"),
                Button("Cancel", id="cfg-cancel"),
            ),
        )

    def on_button_pressed(self, e: Button.Pressed) -> None:
        if e.button.id == "cfg-cancel":
            self.dismiss()
        elif e.button.id == "cfg-save":
            self._save()

    def _save(self) -> None:
        base_url = self.query_one("#cfg-url", Input).value.strip()
        model = self.query_one("#cfg-model", Input).value.strip()
        api_key = self.query_one("#cfg-key", Input).value.strip()
        temp = self.query_one("#cfg-temp", Input).value.strip() or "0.3"
        maxtok = self.query_one("#cfg-maxtok", Input).value.strip() or "4096"
        try:
            temperature = float(temp)
            max_tokens = int(maxtok)
        except ValueError:
            self.app.notify("Temperature and max tokens must be numbers.", severity="error")
            self.query_one("#cfg-temp", Input).focus()
            return
        if not base_url or not model or not 0 <= temperature <= 2 or max_tokens <= 0:
            self.app.notify("Enter a URL/model, temperature 0–2, and positive token count.",
                            severity="error")
            return
        self.post_message(ConfigModal.Saved(base_url, model, api_key,
                                            temperature, max_tokens))
        self.dismiss()

    class Saved(Message):
        def __init__(self, base_url: str, model: str, api_key: str,
                     temperature: float, max_tokens: int):
            self.base_url = base_url
            self.model = model
            self.api_key = api_key
            self.temperature = temperature
            self.max_tokens = max_tokens
            super().__init__()


class HalgateApp(App):
    """Main textual application."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #header-bar {
        height: 1;
        layout: horizontal;
        background: $primary;
        color: $text;
    }
    #header-text {
        width: 1fr;
    }
    #approval-badge {
        /* AUTO is the safe state (no tools held back), so read as green.
           Pending approvals switch it to yellow via inline markup. */
        width: auto;
        color: $success;
        background: $primary 80%;
        padding: 0 1;
    }
    #header-help,
    #header-config {
        width: 3;
        content-align: center middle;
        background: $primary 80%;
        text-style: bold;
        color: $text;
    }
    #main {
        layout: horizontal;
        height: 1fr;
    }
    #chat-panel {
        width: 62%;
        border: tall $accent;
        layout: vertical;
    }
    #chat-panel RichLog {
        height: 1fr;
        width: 100%;
    }
    #chat-panel TextArea {
        height: 3;
        min-height: 3;
        max-height: 6;
        width: 100%;
        color: $text;
        background: $surface;
        border: tall $accent;
    }
    #chat-panel TextArea:focus {
        color: $text;
        background: $surface;
        border: tall $primary;
    }
    #chat-panel Static {
        height: 1;
        width: 100%;
    }
    #activity-toggle {
        height: 1;
        width: 100%;
        content-align: left middle;
    }
    #collapse-activity {
        display: none;
        height: 1;
        width: 100%;
        content-align: left middle;
    }
    #activity-log {
        display: none;
        height: 8;
        width: 100%;
        border: tall $accent;
    }
    #stream-output {
        display: none;
        height: auto;
        max-height: 10;
        padding: 0 1;
        border: tall $primary;
        overflow-y: auto;
    }
    #chat-panel #status-bar {
        dock: bottom;
        height: 1;
        width: 100%;
        layout: horizontal;
        background: $surface;
        color: $text-muted;
    }
    #chat-panel #context-status {
        width: 1fr;
        padding: 0 1;
    }
    #chat-panel #thinking-status {
        width: auto;
        padding: 0 1;
        color: $accent;
    }
    #pane-panel {
        width: 1fr;
        border: tall $accent;
        height: 100%;
        layout: vertical;
    }
    #pane-panel RichLog {
        height: 1fr;
    }
    #pane-tabs {
        height: 1fr;
    }
    #split-view {
        display: none;
        height: 1fr;
        layout: vertical;
    }
    #split-view .split-label {
        height: 1;
        width: 100%;
        background: $primary 30%;
        padding: 0 1;
    }
    #split-view RichLog {
        height: 1fr;
        width: 100%;
        border: tall $primary;
    }
    #pane-controls {
        height: 3;
        width: 100%;
        dock: bottom;
    }
    #pane-controls Button {
        min-width: 0;
    }
    """

    BINDINGS = [
        ("ctrl+c", "quit", "Quit"),
        ("ctrl+shift+c", "copy_selection", "Copy selection"),
        ("ctrl+shift+a", "copy_transcript", "Copy chat"),
        ("ctrl+shift+v", "paste_system", "Paste"),
        ("f5", "refresh_panes", "Refresh panes"),
        ("f1", "help", "Help"),
        ("ctrl+shift+left_square_bracket", "shrink_chat", "Narrow chat"),
        ("ctrl+shift+right_square_bracket", "grow_chat", "Widen chat"),
    ]

    def __init__(self, halgate: Halgate):
        super().__init__()
        self.h = halgate
        self._chat: ChatPanel | None = None
        self._pane_panel: PanePanel | None = None
        self._processing = False
        self._prompt_task: asyncio.Task[None] | None = None
        self._cancel_armed_at: float | None = None
        # Deliberately held only in memory: restart, restore, and target
        # changes all clear this operator decision.
        self._target_auto_approvals: set[str] = set()
        self._listener_pane_sequence = 0
        self._listener_panes: dict[str, str] = {}
        # dispatch_parallel authorizes calls concurrently.  Keep the modal
        # decision itself single-file so an "Approve all" decision is stored
        # before another already-pending call can open its own prompt.
        # This lock does not affect parallel tool execution.
        self._approval_decision_lock = asyncio.Lock()

    AUTO_FOCUS = "#chat-input"

    def compose(self) -> ComposeResult:
        scope_str = ",".join(e.package for e in self.h.engagements) or "none"
        header_text = Static(
            f"[bold]halgate[/bold]  scope:{scope_str}"
            f"  llm:{self.h.router.active_endpoint.id}"
            f"  session:{self.h.session_id[:8]}")
        header_text.id = "header-text"
        approval_badge = Static("", id="approval-badge")
        help_btn = Button("?", id="header-help", variant="primary",
                          tooltip="Help (F1)")
        config_btn = Button("⚙", id="header-config", variant="primary",
                            tooltip="Settings")
        from textual.containers import Horizontal as _H
        header_bar = _H(
            header_text, approval_badge, help_btn, config_btn, id="header-bar")
        chat = ChatPanel()
        chat.id = "chat-panel"
        pane_p = PanePanel()
        pane_p.id = "pane-panel"
        main = Horizontal(chat, pane_p, id="main")
        self._chat = chat
        self._pane_panel = pane_p
        self._approval_badge = approval_badge
        yield header_bar
        yield main

    def _apply_chat_width(self) -> None:
        """Apply the configured chat/pane split ratio."""
        self.query_one("#chat-panel").styles.width = (
            f"{self.h.config.tui.chat_width_pct}%")

    def _nudge_chat_width(self, delta: int) -> None:
        self.h.config.tui.chat_width_pct = max(
            20, min(80, self.h.config.tui.chat_width_pct + delta))
        self._apply_chat_width()

    def action_shrink_chat(self) -> None:
        self._nudge_chat_width(-4)

    def action_grow_chat(self) -> None:
        self._nudge_chat_width(4)

    def _refresh_identity(self, *, llm: str | None = None) -> None:
        """Keep the terminal title and header in sync (short session id)."""
        sid = self.h.session_id
        self.title = f"halgate — {sid[:8]}"
        scope_str = ",".join(e.package for e in self.h.engagements) or "none"
        if llm is None:
            llm = str(self.h.router.active_endpoint.id)
        self.query_one("#header-text", Static).update(
            f"[bold]halgate[/bold]  scope:{scope_str}"
            f"  llm:{llm}  session:{sid[:8]}")

    def on_mount(self) -> None:
        """Set initial focus to the input and sync panes."""
        self._chat.focus_input()
        self._sync_panes()
        self._apply_chat_width()
        self._refresh_identity()
        self.set_interval(0.25, self._refresh_pane_output)
        self.h.approver = self._approve_tool
        self.h.activity_callback = self._on_agent_activity
        self.h.stream_callback = self._on_stream_event
        self.h.registry.ctx.extra["pane_note_callback"] = self._set_pane_note
        self.h.registry.ctx.extra["live_output_callback"] = self._on_live_output
        self.h.registry.ctx.extra["listener_pane_callback"] = self._on_listener_output
        self._chat.add_status(self.h.tracker.status_line())
        self._refresh_approval_badge()
        if not self.h.engagements:
            self._show_onboarding()

    def on_button_pressed(self, e: Button.Pressed) -> None:
        if e.button.id == "header-help":
            self.action_help()
        elif e.button.id == "header-config":
            self._open_config()
        elif e.button.id == "activity-toggle" and self._chat:
            self._chat.toggle_activity()
        elif e.button.id == "collapse-activity" and self._chat:
            self._chat.toggle_activity()
        elif e.button.id == "split-panes" and self._pane_panel:
            if not self._pane_panel.toggle_split():
                self.notify("Open at least two panes before splitting.", severity="warning")
        elif e.button.id == "close-pane":
            asyncio.create_task(self._close_active_pane())
        elif e.button.id == "save-pane":
            asyncio.create_task(self._save_active_pane())
        elif e.button.id == "load-pane":
            self._open_scratch_picker()

    def on_key(self, event: events.Key) -> None:
        """Handle prompt cancellation and right-panel keyboard navigation."""
        # The app-level Tab/Shift+Tab pane cycling only makes sense on the
        # main screen.  While a modal (onboarding, approvals, config, ...) is
        # open, let Textual's normal focus handling move between its fields and
        # buttons, so a modal stays fully keyboard- and mouse-navigable.
        in_modal = isinstance(self.screen, ModalScreen)
        if in_modal:
            return
        if event.key == "escape" and self._cancel_running_prompt():
            event.stop()
            event.prevent_default()
        elif (event.key in ("up", "down") and self._chat
                and self._chat._input.has_focus
                and self._chat.recall_prompt(-1 if event.key == "up" else 1)):
            event.stop()
            event.prevent_default()
        elif (event.key in ("up", "down") and self._pane_panel
              and self._pane_panel.scroll_active(-1 if event.key == "up" else 1)):
            event.stop()
            event.prevent_default()
        elif event.key == "tab" and self._pane_panel and not in_modal:
            event.stop()
            event.prevent_default()
            self._pane_panel.cycle_tab(1)
        elif event.key == "shift+tab" and self._pane_panel and not in_modal:
            event.stop()
            event.prevent_default()
            self._pane_panel.cycle_tab(-1)

    def _cancel_running_prompt(self) -> bool:
        """Arm then cancel the live task; Escape remains normal otherwise."""
        task = self._prompt_task
        if not self._processing or task is None or task.done():
            return False
        now = time.monotonic()
        if (self._cancel_armed_at is not None
                and now - self._cancel_armed_at <= 2.0):
            self._cancel_armed_at = None
            task.cancel()
            if self._chat:
                self._chat.add_agent(
                    "[yellow]Cancellation requested. Waiting for the active operation to stop…[/yellow]")
            return True
        self._cancel_armed_at = now
        if self._chat:
            self._chat.add_agent(
                "[yellow]Press Escape again within 2 seconds to cancel the running prompt.[/yellow]")
        return True

    async def _approve_tool(self, call: ToolCall, engagement) -> ApprovalResult:
        exact_target = _exact_action_target(call)
        if (exact_target
                and engagement.id in self._target_auto_approvals):
            return self._auto_approved_result(call, engagement, exact_target)

        # A batch can reach this callback at once.  Re-check after acquiring
        # the lock because a preceding modal may have enabled this engagement
        # rule while this call was waiting to make its decision.
        async with self._approval_decision_lock:
            if (exact_target
                    and engagement.id in self._target_auto_approvals):
                return self._auto_approved_result(call, engagement, exact_target)

            loop = asyncio.get_running_loop()
            result: asyncio.Future[ApprovalResult] = loop.create_future()

            def resolved(value) -> None:
                if not result.done():
                    result.set_result(value or ApprovalResult(approved=False))

            self.push_screen(ApprovalModal(call, engagement, exact_target), resolved)
            decision = await result
            if decision.auto_approve_target:
                self._target_auto_approvals.add(engagement.id)
                self.h.audit.guard_decision(
                    call.name, True,
                    "operator enabled session auto-approval for engagement target "
                    f"{decision.auto_approve_target}", engagement.id)
                self._refresh_approval_badge()
                if self._chat:
                    self._chat.add_agent(
                        "[yellow]Auto-approval enabled for this session only: "
                        f"{engagement.label} — {decision.auto_approve_target}. "
                        "Scope, package, and budget checks still apply.[/yellow]")
            return decision

    def _auto_approved_result(self, call: ToolCall, engagement,
                              exact_target: str) -> ApprovalResult:
        """Record and return an engagement-scoped session auto-approval."""
        if self._chat:
            self._chat.add_activity(
                "approval",
                f"Auto-approved {call.name} for {engagement.label} — {exact_target}")
        return ApprovalResult(approved=True, auto_approved=True,
                              auto_approve_target=engagement.target)

    def _clear_target_auto_approvals(self, reason: str = "") -> None:
        if not self._target_auto_approvals:
            return
        self._target_auto_approvals.clear()
        self._refresh_approval_badge()
        if reason and self._chat:
            self._chat.add_agent(f"[yellow]Target auto-approval cleared: {reason}.[/yellow]")

    def _refresh_approval_badge(self) -> None:
        if not hasattr(self, "_approval_badge"):
            return
        labels: list[str] = []
        for engagement_id in sorted(self._target_auto_approvals):
            engagement = next((e for e in self.h.engagements
                               if e.id == engagement_id), None)
            labels.append(
                f"{engagement.label if engagement else engagement_id}: "
                f"{engagement.target if engagement else 'unknown target'}")
        self._approval_badge.update(
            "  AUTO: " + " | ".join(labels) if labels else "")

    def action_copy_selection(self) -> None:
        """Copy selected log text, including when running in macOS Terminal."""
        selected = self.screen.get_selected_text()
        if not selected:
            self.notify("Select text in the chat log first.", severity="warning")
            return
        self._copy_text(selected)

    def action_copy_transcript(self) -> None:
        """Copy the complete plain-text chat transcript."""
        transcript = self._chat.transcript() if self._chat else ""
        if not transcript:
            self.notify("There is no chat text to copy.", severity="warning")
            return
        self._copy_text(transcript)

    def action_paste_system(self) -> None:
        """Paste macOS clipboard text into the chat input when requested."""
        if sys.platform != "darwin" or not self._chat:
            self.notify("Use your terminal's normal paste shortcut.")
            return
        try:
            pasted = subprocess.run(
                ["pbpaste"], capture_output=True, text=True, check=True,
                timeout=2).stdout
        except (OSError, subprocess.SubprocessError):
            self.notify("Couldn't read the system clipboard.", severity="error")
            return
        if pasted:
            input_widget = self._chat._input
            start, end = input_widget.selection
            input_widget.replace(pasted, start, end)

    def _copy_text(self, text: str) -> None:
        """Use OSC 52 generally and pbcopy where macOS Terminal needs it."""
        self.copy_to_clipboard(text)
        if sys.platform == "darwin":
            try:
                subprocess.run(["pbcopy"], input=text, text=True, check=True,
                               timeout=2)
            except (OSError, subprocess.SubprocessError):
                self.notify("Copied for compatible terminals; macOS clipboard failed.",
                            severity="warning")
                return
        self.notify("Copied to clipboard.")

    def _on_agent_activity(self, kind: str, text: str) -> None:
        """Receive non-private progress emitted by the harness run loop."""
        if self._chat:
            self._chat.add_activity(kind, text)

    def _on_stream_event(self, kind: str, text: str) -> None:
        if self._chat:
            self._chat.stream_event(kind, text)

    def _on_live_output(self, action: str, stream: str, text: str) -> None:
        if self._chat:
            self._chat.add_live_output(action, stream, text)

    def _on_listener_output(self, endpoint_id: str, stream: str, text: str,
                            engagement_id: str) -> None:
        """Show each in-process callback listener in a numbered pane."""
        if not self._pane_panel:
            return
        pane_id = self._listener_panes.get(endpoint_id)
        if pane_id is None:
            self._listener_pane_sequence += 1
            pane_id = f"listener-{endpoint_id}"
            self._listener_panes[endpoint_id] = pane_id
            self._pane_panel.add_pane(pane_id,
                                      f"Listener {self._listener_pane_sequence}",
                                      engagement_id)
        prefix = "" if stream == "stdout" else f"[{stream}] "
        self._pane_panel.pane_output(pane_id, prefix + text)

    def _set_pane_note(self, name: str, content: str, engagement_id: str) -> None:
        if self._pane_panel:
            self._pane_panel.note(name, content, engagement_id)

    def _on_pane_requested(self, requested) -> None:
        if requested:
            name, command, engagement_id = requested
            asyncio.create_task(self._spawn_pane(name, command, engagement_id))

    async def _spawn_pane(self, name: str, command: str, engagement_id: str) -> None:
        call = ToolCall(id=f"ui-pane-{id(self):x}", name="pane_spawn",
                        arguments={"name": name, "command": command,
                                   "engagement_id": engagement_id})
        results = await dispatch_parallel([call], self.h.registry, self.h.gate,
                                          self.h.audit, self.h.config,
                                          self._approve_tool, self.h._redactor,
                                          self.h.safety, self.h.budgets)
        self._chat.add_agent(json.dumps(results[0], default=str))
        self._sync_panes()

    async def _close_active_pane(self) -> None:
        if not self._pane_panel:
            return
        process_id = self._pane_panel.close_active()
        if process_id:
            try:
                await self.h.process_mgr.kill(process_id)
            except KeyError:
                pass

    async def _save_active_pane(self) -> None:
        if not self._pane_panel:
            return
        snapshot = self._pane_panel.active_snapshot()
        if not snapshot:
            self.notify("The active pane has no engagement-bound content to save.",
                        severity="warning")
            return
        title, text, engagement_id = snapshot
        try:
            engagement = self.h.gate._require_active(engagement_id)
            if not engagement.scratch_dir:
                raise ValueError("engagement has no scratch directory")
            scratch = Path(engagement.scratch_dir).resolve(strict=True)
            if not scratch.is_dir():
                raise ValueError("engagement scratch path is not a directory")
            payload = text.encode("utf-8", errors="replace")[:10 * 1024 * 1024]
            slug = re.sub(r"[^A-Za-z0-9._-]+", "-", title).strip(".-") or "pane"
            stamp = time.strftime("%Y%m%d-%H%M%S")
            output: Path | None = None
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            for suffix in range(100):
                candidate = scratch / f"{stamp}-{slug[:48]}-{suffix:02d}.txt"
                if not candidate.resolve(strict=False).is_relative_to(scratch):
                    raise ValueError("generated scratch path escaped its directory")
                try:
                    fd = os.open(candidate, flags, 0o600)
                except FileExistsError:
                    continue
                with os.fdopen(fd, "wb") as handle:
                    handle.write(payload)
                output = candidate
                break
            if output is None:
                raise ValueError("could not reserve a unique scratch filename")
        except Exception as exc:
            self.notify(f"Couldn't save active pane: {exc}", severity="error")
            return
        truncated = len(text.encode("utf-8", errors="replace")) > len(payload)
        self.h.audit.tool_call("save_active_pane", {
            "title": title, "path": str(output), "engagement_id": engagement_id,
        }, engagement_id)
        self.h.audit.tool_result("save_active_pane", {
            "path": str(output), "bytes": len(payload), "truncated": truncated,
        }, 0, truncated=truncated, engagement_id=engagement_id)
        self.notify(f"Saved active pane to {output.name}")

    def _open_scratch_picker(self) -> None:
        if not self._pane_panel:
            return
        snapshot = self._pane_panel.active_snapshot()
        # A new engagement has no pane to select yet.  When it is the only
        # active engagement, it is unambiguous which scratch folder owns the
        # loaded text; ``_load_scratch_file`` will create a bound note pane.
        # Keep the explicit-pane requirement when several engagements are
        # active, since choosing one implicitly would cross a scope boundary.
        if snapshot:
            engagement_id = snapshot[2]
        else:
            active = self.h.gate.active_engagements()
            if len(active) != 1:
                self.notify("Select an engagement-bound pane before loading.",
                            severity="warning")
                return
            engagement_id = active[0].id
        try:
            engagement = self.h.gate._require_active(engagement_id)
            scratch = Path(engagement.scratch_dir).resolve(strict=True)
            if not engagement.scratch_dir or not scratch.is_dir():
                raise ValueError("engagement scratch folder is unavailable")
            files = []
            for candidate in sorted(scratch.iterdir(), key=lambda item: item.name.lower()):
                if len(files) >= 100 or candidate.is_symlink():
                    continue
                resolved = candidate.resolve(strict=True)
                if (resolved.is_relative_to(scratch) and resolved.is_file()
                        and resolved.stat().st_size <= 10 * 1024 * 1024):
                    files.append(resolved)
        except (OSError, ValueError) as exc:
            self.notify(f"Couldn't open scratch folder: {exc}", severity="error")
            return
        self.push_screen(ScratchPickerModal(files),
                         lambda selected: self._load_scratch_file(selected, engagement.id))

    def _load_scratch_file(self, selected: Path | None, engagement_id: str) -> None:
        if selected is None or not self._pane_panel:
            return
        try:
            engagement = self.h.gate._require_active(engagement_id)
            scratch = Path(engagement.scratch_dir).resolve(strict=True)
            if selected.is_symlink():
                raise ValueError("symbolic links are not loadable")
            resolved = selected.resolve(strict=True)
            if not resolved.is_relative_to(scratch) or not resolved.is_file():
                raise ValueError("selected file is outside the scratch folder")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(resolved, flags)
            with os.fdopen(fd, "rb") as handle:
                data = handle.read(10 * 1024 * 1024 + 1)
            if len(data) > 10 * 1024 * 1024:
                raise ValueError("selected file exceeds 10 MiB")
            content = data.decode("utf-8", errors="replace")
        except (OSError, ValueError) as exc:
            self.notify(f"Couldn't load scratch file: {exc}", severity="error")
            return
        self._pane_panel.note(f"Loaded: {resolved.name}", content, engagement_id)
        self.h.audit.tool_call("load_scratch_file", {
            "path": str(resolved), "engagement_id": engagement_id,
        }, engagement_id)
        self.h.audit.tool_result("load_scratch_file", {
            "path": str(resolved), "bytes": len(data), "truncated": False,
        }, 0, truncated=False, engagement_id=engagement_id)

    def _open_config(self) -> None:
        ep = self.h.router.active_endpoint
        tools = []
        if self.h.engagements:
            pkg = self.h.config.packages.get(
                self.h.engagements[0].package)
            if pkg and pkg.tools:
                for name, enabled in pkg.tools.items():
                    tools.append({"name": name, "enabled": bool(enabled)})
        else:
            for name in ("read_file", "write_file", "glob", "grep",
                         "shell", "http", "scan", "memory_remember",
                         "memory_recall"):
                tools.append({"name": name, "enabled": True})
        active_pkg = (self.h.engagements[0].package
                      if self.h.engagements
                      else self.h.config.scope.package)
        self.push_screen(ConfigModal(
            [ep.base_url, ep.model, ep.api_key,
             ep.temperature, ep.max_tokens],
            tools, active_pkg))

    async def on_config_modal_saved(self, msg: ConfigModal.Saved) -> None:
        ep = self.h.config.llm.active_endpoint
        ep.base_url = msg.base_url
        ep.model = msg.model
        ep.api_key = msg.api_key
        ep.temperature = msg.temperature
        ep.max_tokens = msg.max_tokens
        await self.h.router.reload(ep.id)
        self._chat.add_agent(
            f"[green]Config updated: {ep.model} @ {ep.base_url} "
            f"temp={ep.temperature} maxtok={ep.max_tokens}[/green]")
        self._refresh_identity(llm=f"{ep.id}:{ep.model}")

    def _restore_chat_history(self) -> None:
        if self._chat:
            self._chat.restore_history(self.h.messages)
            self._refresh_prompt_history()

    def _prompt_scope(self) -> list[str]:
        return sorted(e.id for e in self.h.gate.active_engagements())

    def _refresh_prompt_history(self) -> None:
        if not self._chat:
            return
        scope = self._prompt_scope()
        prompts = [str(message.get("content") or "")
                   for message in self.h.messages
                   if (message.get("role") == "user"
                       and message.get("_engagement_scope") == scope)]
        self._chat.set_prompt_history(prompts)

    async def _restore_panes(self, panes: list[dict]) -> None:
        """Replay saved running panes after a session switch.

        Checkpointed network panes retain the harness's default workdir.  It
        must not be supplied back to ``pane_spawn`` because an explicit path
        is correctly rejected for a network-only engagement.  That previously
        made every restored network pane fail scope validation.
        """
        if self._pane_panel:
            self._pane_panel.reset()
        resumed = 0
        for saved in panes:
            # Checkpoints written before status was added represented active
            # panes implicitly, so preserve their ability to resume.
            if saved.get("status", "running") != "running":
                continue
            engagement_id = saved.get("engagement_id")
            argv = saved.get("argv")
            if not isinstance(argv, list):
                try:
                    argv = shlex.split(str(saved.get("cmd") or ""))
                except ValueError:
                    continue
            if not argv or not isinstance(engagement_id, str):
                continue
            engagement = next((e for e in self.h.engagements
                               if e.id == engagement_id), None)
            if engagement is None:
                if self._chat:
                    self._chat.add_agent(
                        f"[red]Couldn't resume pane '{saved.get('name', 'unknown')}': "
                        "its engagement is unavailable.[/red]")
                continue
            arguments = {
                "name": str(saved.get("name") or "restored pane"),
                "command": shlex.join(argv),
                "engagement_id": engagement_id,
            }
            # Only filesystem engagements may carry a workdir through scope.
            if engagement.is_path_target and saved.get("workdir"):
                arguments["workdir"] = saved["workdir"]
            call = ToolCall(
                id=f"restore-pane-{saved.get('id', '')}", name="pane_spawn",
                arguments=arguments)
            results = await dispatch_parallel([call], self.h.registry, self.h.gate,
                                              self.h.audit, self.h.config,
                                              self._approve_tool, self.h._redactor,
                                              self.h.safety, self.h.budgets)
            result = results[0]
            if result.get("error"):
                if self._chat:
                    self._chat.add_agent(
                        f"[red]Couldn't resume pane '{arguments['name']}': "
                        f"{result['error']}[/red]")
            else:
                resumed += 1
        self._sync_panes()
        if resumed and self._chat:
            self._chat.add_agent(
                f"[green]Resumed {resumed} live pane{'s' if resumed != 1 else ''}."
                "[/green]")

    def on_onboarding_modal_continued(
            self, msg: OnboardingModal.Continued) -> None:
        from .sessions.checkpoint import SessionCheckpoint
        try:
            restored = SessionCheckpoint.load(
                self.h.config.sessions.dir, msg.session_id)
        except FileNotFoundError:
            self._chat.add_agent("[red]Session not found.[/red]")
            return
        self.h.restore_session(restored)
        self._clear_target_auto_approvals("session changed")
        self._restore_chat_history()
        asyncio.create_task(self._restore_panes(restored.panes))
        self._chat.add_agent(
            f"[green]Resumed: {restored.name} "
            f"({', '.join(e.target for e in restored.engagements)}, "
            f"{len(self.h.messages)} messages)[/green]")

    def on_onboarding_modal_started(
            self, msg: OnboardingModal.Started) -> None:
        from .scope import Engagement, new_engagement_id
        eid = new_engagement_id()
        eng = Engagement(id=eid, label=msg.label, target=msg.target,
                          package=msg.package)
        try:
            self.h.add_engagement(eng)
        except ValueError as e:
            self._chat.add_agent(f"[red]{e}[/red]")
            return
        self._clear_target_auto_approvals("engagement target changed")
        self._refresh_prompt_history()
        self._chat.add_agent(
            f"[green]Engagement added: {eid}: {msg.label} "
            f"({msg.target}, {msg.package})[/green]")

    def on_onboarding_modal_manage(self, msg: OnboardingModal.Manage) -> None:
        self._open_sessions_modal()

    def on_continue_modal_picked(
            self, msg: ContinueModal.Picked) -> None:
        from .sessions.checkpoint import SessionCheckpoint
        try:
            restored = SessionCheckpoint.load(
                self.h.config.sessions.dir, msg.session_id)
        except FileNotFoundError:
            self._chat.add_agent("[red]Session not found.[/red]")
            return
        self.h.restore_session(restored)
        self._clear_target_auto_approvals("session changed")
        self._restore_chat_history()
        asyncio.create_task(self._restore_panes(restored.panes))
        self._chat.add_agent(
            "[green]Resumed: " + ", ".join(
                e.label for e in restored.engagements) + "[/green]")

    def _open_sessions_modal(self) -> None:
        from .sessions.checkpoint import SessionCheckpoint
        sessions_dir = self.h.config.sessions.dir
        sessions = SessionCheckpoint.list_sessions(sessions_dir)
        if not sessions:
            self._show_onboarding()
            return
        self.push_screen(
            SessionsModal(sessions, sessions_dir),
            callback=lambda result: self._show_onboarding(),
        )

    def _show_onboarding(self) -> None:
        from .sessions.checkpoint import SessionCheckpoint
        packages = list(self.h.config.packages.keys())
        default_pkg = self.h.config.scope.package or "defensive"
        sessions = SessionCheckpoint.list_sessions(
            self.h.config.sessions.dir)
        self.push_screen(OnboardingModal(
            packages, default_pkg, sessions,
            self.h.lifetime_tokens.status_line(),
            self.h.config.audit.encryption_key_file))

    def on_sessions_modal_resumed(
            self, msg: SessionsModal.Resumed) -> None:
        from .sessions.checkpoint import SessionCheckpoint
        try:
            restored = SessionCheckpoint.load(
                self.h.config.sessions.dir, msg.session_id)
        except FileNotFoundError:
            self._chat.add_agent("[red]Session not found.[/red]")
            return
        self.h.restore_session(restored)
        self._clear_target_auto_approvals("session changed")
        self._restore_chat_history()
        asyncio.create_task(self._restore_panes(restored.panes))
        self._chat.add_agent(
            f"[green]Resumed: {restored.name} "
            f"({', '.join(e.target for e in restored.engagements)}, "
            f"{len(self.h.messages)} messages)[/green]")

    def on_sessions_modal_deleted(
            self, msg: SessionsModal.Deleted) -> None:
        from .sessions.checkpoint import SessionCheckpoint
        SessionCheckpoint.delete(self.h.config.sessions.dir,
                                msg.session_id)
        self._chat.add_agent(
            f"[green]Session {msg.session_id[:8]}… deleted.[/green]")

    def _sync_panes(self) -> None:
        if self._pane_panel is None:
            return
        for p in self.h.process_mgr.list():
            self._pane_panel.add_pane(p["id"], p["name"], p["engagement_id"])

    def _refresh_pane_output(self) -> None:
        if self._pane_panel is None:
            return
        for pane in self.h.process_mgr.list():
            self._pane_panel.add_pane(pane["id"], pane["name"], pane["engagement_id"])
            text = self.h.process_mgr.drain_output(pane["id"])
            if text:
                self._pane_panel.pane_output(pane["id"], text)

    def watch(self) -> None:
        pass

    async def on_text_area_changed(self, e: TextArea.Changed) -> None:
        if not self._chat or e.text_area is not self._chat._input:
            return
        cleaned = _strip_terminal_input_sequences(e.text_area.text)
        if cleaned != e.text_area.text:
            # Assigning the cleaned value emits one final Changed event; it is
            # already clean, so this does not recurse.
            self._chat._set_input_text(cleaned)
        else:
            self._chat._resize_input()

    def on_chat_input_submitted(self, message: ChatInput.Submitted) -> None:
        if self._chat and message.text_area is self._chat._input:
            self._submit_chat_prompt()

    def _submit_chat_prompt(self) -> None:
        if not self._chat:
            return
        text = self._chat.get_input().strip()
        if not text:
            return
        if self._prompt_task is not None and not self._prompt_task.done():
            self._chat.add_agent(
                "[yellow]A prompt is already running. Press Escape twice to cancel it first.[/yellow]")
            return
        self._chat.add_user(text)
        if not text.startswith("/"):
            self._chat.remember_prompt(text)
        self._chat.clear_input()
        self._prompt_task = asyncio.create_task(self._process_input(text))

    async def _process_input(self, text: str) -> None:
        if self._processing:
            return
        self._processing = True
        try:
            if text.startswith("/"):
                await self._handle_command(text)
            else:
                self._chat.show_thinking()
                result = await self.h.run(text)
                self._chat.stop_thinking()
                self._chat.add_agent(result, markup=False)
        except asyncio.CancelledError:
            self._chat.stop_thinking(completed=False)
            self._chat.add_agent("[yellow]Prompt cancelled. Completed results remain in the session.[/yellow]")
            raise
        except Exception as e:
            self._chat.stop_thinking(completed=False)
            self._chat.add_agent(f"[red]ERROR: {e}[/red]")
        finally:
            self._processing = False
            self._cancel_armed_at = None
            if asyncio.current_task() is self._prompt_task:
                self._prompt_task = None
            self._chat._update_status(self.h.tracker.status_line())
            self._chat.focus_input()

    async def _handle_command(self, cmd: str) -> None:
        parts = cmd.strip().split(None, 1)
        name = parts[0].lstrip("/").lower()
        arg = parts[1] if len(parts) > 1 else ""
        if name == "quit":
            self.h.checkpoint()
            self.exit()
            return
        elif name == "new":
            self._show_onboarding()
        elif name == "status":
            s = self.h.status
            self._chat.add_agent(json.dumps(s, indent=2, default=str))
        elif name == "panes":
            self._chat.add_agent(json.dumps(
                self.h.process_mgr.list(), indent=2, default=str))
        elif name == "recall":
            r = self.h.memory.recall(query=arg)
            for m in r.get("memories", []):
                self._chat.add_agent(f"[{m.get('id')}] "
                                     f"{m.get('text')}")
        elif name == "checkpoint":
            self.h.checkpoint()
            self._chat.add_agent(f"Checkpoint saved: {self.h.session_id}")
        elif name == "approval":
            if arg.strip().lower() == "reset":
                if self._target_auto_approvals:
                    self._clear_target_auto_approvals("operator reset")
                else:
                    self._chat.add_agent("No target auto-approvals are active.")
            else:
                self._chat.add_agent("Usage: /approval reset")
        elif name == "compact":
            n = int(arg) if arg.isdigit() else 1
            msg = await self.h.compact(n)
            self._chat.add_agent(msg)
        elif name == "dry-run":
            if arg == "on":
                self.h.config.safety.dry_run = True
                self._chat.add_agent("Dry-run ON.")
            elif arg == "off":
                self.h.config.safety.dry_run = False
                self._chat.add_agent("Dry-run OFF.")
        elif name == "panic":
            result = await self.h.safety.panic()
            self._chat.add_agent(json.dumps(result, default=str))
        elif name == "resume-actions":
            self.h.safety.resume_actions()
            self._chat.add_agent("Actions unlocked.")
        elif name == "budget":
            if arg:
                self._chat.add_agent(json.dumps(
                    self.h.budgets.status(arg), indent=2, default=str))
            else:
                self._chat.add_agent(json.dumps(
                    self.h.budgets.all_status(), indent=2, default=str))
        elif name == "engagement":
            sub = arg.split(None, 1) if arg else ["list", ""]
            if sub[0] == "list" or not arg:
                for e in self.h.engagements:
                    self._chat.add_agent(
                        f"  {e.label} ({e.target}, {e.package}, {e.status})")
            elif sub[0] == "add" and len(sub) > 1:
                parts = sub[1].split(":", 2)
                if len(parts) not in (2, 3):
                    self._chat.add_agent(
                        "Usage: /engagement add label:target[:package]")
                else:
                    label, target = _safe_ui_label(parts[0], fallback="Target"), parts[1]
                    package = (parts[2] if len(parts) >= 3
                               else self.h.config.scope.package)
                    try:
                        from .scope import Engagement, new_engagement_id
                        eid = new_engagement_id()
                        self.h.add_engagement(Engagement(
                            id=eid, label=label, target=target, package=package))
                        self._clear_target_auto_approvals(
                            "engagement target changed")
                        self._refresh_prompt_history()
                        self._chat.add_agent(f"Engagement added: {eid}")
                    except ValueError as e:
                        self._chat.add_agent(f"[red]{e}[/red]")
            elif sub[0] in ("pause", "resume") and len(sub) > 1:
                target = next((e for e in self.h.engagements if e.id == sub[1]), None)
                if target is None:
                    self._chat.add_agent("[red]Unknown engagement.[/red]")
                else:
                    target.status = "paused" if sub[0] == "pause" else "active"
                    self._refresh_prompt_history()
                    self._chat.add_agent(f"{target.label} {target.status}.")
            elif sub[0] == "claims":
                parts = sub[1].split(None, 2) if len(sub) > 1 else []
                if len(parts) < 3:
                    for e in self.h.engagements:
                        ext = ", ".join(e.jwt_claim_extensions) or "(none)"
                        self._chat.add_agent(
                            f"  {e.label} — extensions: [{ext}]")
                    self._chat.add_agent(
                        "Usage: /engagement claims <id> add|remove <keys...>")
                else:
                    eng_id, action = parts[0], parts[1].lower()
                    keys = parts[2].split() if len(parts) > 2 else []
                    eng = next((e for e in self.h.engagements if e.id == eng_id), None)
                    if eng is None:
                        self._chat.add_agent(f"[red]Unknown engagement '{eng_id}'.[/red]")
                    elif action == "add":
                        new_ext = set(eng.jwt_claim_extensions)
                        added = []
                        for k in keys:
                            if re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,63}", k) \
                                    and k not in ("iat", "exp", "nbf"):
                                if k not in new_ext:
                                    added.append(k)
                                new_ext.add(k)
                            else:
                                self._chat.add_agent(
                                    f"[yellow]Warning: invalid claim key '{k}', skipped[/yellow]")
                        pkg = self.h.config.packages.get(eng.package)
                        pkg_claims = set(pkg.jwt_allowed_claims) if pkg else set()
                        if len(new_ext | pkg_claims) > 16:
                            self._chat.add_agent(
                                f"[red]Total claim set would exceed 16 "
                                f"({len(new_ext | pkg_claims)} > 16)[/red]")
                        else:
                            eng.jwt_claim_extensions = tuple(sorted(new_ext))
                            self._chat.add_agent(
                                f"[green]Added {added or '(none new)'} to "
                                f"{eng.label} claim extensions[/green]")
                    elif action == "remove":
                        before = set(eng.jwt_claim_extensions)
                        after = {k for k in before if k not in keys}
                        removed = before - after
                        eng.jwt_claim_extensions = tuple(sorted(after))
                        self._chat.add_agent(
                            f"[green]Removed {removed or '(none)'} from "
                            f"{eng.label} claim extensions[/green]")
                    else:
                        self._chat.add_agent(
                            "Usage: /engagement claims <id> add|remove <keys...>")
        elif name == "secret":
            secret_parts = arg.split() if arg else []
            if secret_parts and secret_parts[0] == "list":
                for entry in self.h._keystore.known_ids():
                    self._chat.add_agent(
                        f"  {entry.get('id')} ({entry.get('type')})")
            elif secret_parts and secret_parts[0] == "reveal" and len(secret_parts) > 1:
                val = await self.h._keystore.reveal(secret_parts[1])
                if val:
                    self.h.audit.secret_reveal(secret_parts[1])
                    self._chat.add_agent(f"Revealed (value hidden — "
                                          f"use CLI `halgate secret reveal {secret_parts[1]}` to display)")
                else:
                    self._chat.add_agent("[red]Not found or decryption failed.[/red]")
            elif secret_parts and secret_parts[0] == "store":
                self._chat.add_agent(
                    "Store a secret via the CLI: [bold]halgate secret store "
                    "[/bold](value is entered via getpass, never logged). "
                    "The returned cred_<uuid> id can then be used with jwt_sign.")
            else:
                self._chat.add_agent(
                    "Usage: /secret list | /secret reveal <id> | /secret store")
        elif name == "kill":
            if arg:
                await self.h.process_mgr.kill(arg)
                self._chat.add_agent(f"Killed {arg}.")
        elif name == "sessions":
            self._open_sessions_modal()
        elif name == "help":
            self.action_help()
        else:
            self._chat.add_agent(
                f"Unknown: /{name} — type /help or press F1 for the "
                "command list")

    def action_help(self) -> None:
        self.push_screen(HelpModal())

    def action_quit(self) -> None:
        self.h.checkpoint()
        self.exit()

    def action_refresh_panes(self) -> None:
        self._sync_panes()
        if self._pane_panel:
            for p in self.h.process_mgr.list():
                self._pane_panel.add_pane(p["id"], p["name"])
