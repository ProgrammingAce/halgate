"""ToolRegistry: maps names to handlers, generates LLM tool schemas."""
from __future__ import annotations

from typing import Callable

from ..config import Config
from ..memory.store import MemoryStore
from ..process import ProcessManager
from ..scope import ScopeGate
from .context import ToolContext
from . import glob as _glob
from . import grep as _grep
from . import http as _http
from . import http_session as _http_session
from . import data as _data
from . import tcp_probe as _tcp_probe
from . import callback_endpoint as _callback_endpoint
from . import http_replay as _http_replay
from . import multipart_upload as _multipart_upload
from . import binary_inspect as _binary_inspect
from . import websocket as _websocket
from . import auth_session as _auth_session
from . import jwt_sign as _jwt_sign
from . import memory_tool as _mem
from . import panes as _panes
from . import pane_note as _pane_note
from . import read_file as _read
from . import read_source_code as _source_code
from . import scan as _scan
from . import shell as _shell
from . import write_file as _write


class ToolRegistry:
    def __init__(self, config: Config, gate: ScopeGate,
                 process_mgr: ProcessManager, memory: MemoryStore):
        self._gate = gate
        self._ctx = ToolContext(config=config, gate=gate,
                                process_mgr=process_mgr, memory=memory)
        self._handlers: dict[str, Callable] = {}
        self._descriptions: dict[str, dict] = {}
        self._register_all()

    def llm_schemas(self) -> list[dict]:
        schemas = []
        for name, desc in self._descriptions.items():
            if self._gate.any_active_engagement_permits(name):
                schemas.append({"type": "function", "function": desc})
        return schemas

    def tool_details(self) -> list[dict[str, str]]:
        """Return every registered tool with its operator-facing description."""
        def short_description(schema: dict) -> str:
            description = str(schema.get("description", "")).strip()
            first_sentence = description.split(". ", 1)[0].strip()
            if first_sentence and first_sentence != description:
                first_sentence += "."
            return (first_sentence[:197].rstrip() + "…"
                    if len(first_sentence) > 198 else first_sentence)

        return [
            {"name": name, "description": short_description(schema)}
            for name, schema in sorted(self._descriptions.items())
        ]

    async def call(self, name: str, args: dict) -> dict:
        """Reject direct execution; dispatch owns approval, budgets, and audit."""
        return {"error": ("tools must be invoked through dispatch_parallel; "
                          "direct registry execution is not permitted")}

    async def call_authorized(self, name: str, args: dict) -> dict:
        """Execute a call after dispatch has applied its workflow controls."""
        if name not in self._handlers:
            return {"error": f"unknown tool: {name}"}
        engagement_id = str(args.get("engagement_id") or "")
        try:
            allowed, reason, _ = self._gate.authorize(name, args, engagement_id)
        except Exception as e:
            return {"error": f"tool authorization failed: {e}"}
        if not allowed:
            return {"error": reason}
        handler = self._handlers[name]
        return await handler(self._ctx, **args)

    def _register(self, name: str, handler: Callable, schema: dict) -> None:
        self._handlers[name] = handler
        self._descriptions[name] = schema

    def _register_all(self) -> None:
        self._register("read_file", _read.handle_read_file,
                       _read.READ_FILE_SCHEMA)
        self._register("read_source_code", _source_code.handle_read_source_code,
                       _source_code.READ_SOURCE_CODE_SCHEMA)
        self._register("write_file", _write.handle_write_file,
                       _write.WRITE_FILE_SCHEMA)
        self._register("glob", _glob.handle_glob, _glob.GLOB_SCHEMA)
        self._register("grep", _grep.handle_grep, _grep.GREP_SCHEMA)
        self._register("shell", _shell.handle_shell, _shell.SHELL_SCHEMA)
        self._register("http", _http.handle_http, _http.HTTP_SCHEMA)
        self._register("http_replay", _http_replay.handle_http_replay,
                       _http_replay.HTTP_REPLAY_SCHEMA)
        self._register("http_session", _http_session.handle_http_session,
                       _http_session.HTTP_SESSION_SCHEMA)
        self._register("auth_session", _auth_session.handle_auth_session,
                       _auth_session.AUTH_SESSION_SCHEMA)
        self._register("jwt_sign", _jwt_sign.handle_jwt_sign,
                       _jwt_sign.JWT_SIGN_SCHEMA)
        self._register("multipart_upload", _multipart_upload.handle_multipart_upload,
                       _multipart_upload.MULTIPART_UPLOAD_SCHEMA)
        self._register("websocket", _websocket.handle_websocket,
                       _websocket.WEBSOCKET_SCHEMA)
        self._register("json_extract", _data.handle_json_extract,
                       _data.JSON_EXTRACT_SCHEMA)
        self._register("base64_decode", _data.handle_base64_decode,
                       _data.BASE64_DECODE_SCHEMA)
        self._register("jwt_inspect", _data.handle_jwt_inspect,
                       _data.JWT_INSPECT_SCHEMA)
        self._register("binary_inspect", _binary_inspect.handle_binary_inspect,
                       _binary_inspect.BINARY_INSPECT_SCHEMA)
        self._register("tcp_probe", _tcp_probe.handle_tcp_probe,
                        _tcp_probe.TCP_PROBE_SCHEMA)
        self._register("request_callback_endpoint",
                       _callback_endpoint.handle_request_callback_endpoint,
                       _callback_endpoint.REQUEST_CALLBACK_ENDPOINT_SCHEMA)
        self._register("read_callback_endpoint",
                       _callback_endpoint.handle_read_callback_endpoint,
                       _callback_endpoint.READ_CALLBACK_ENDPOINT_SCHEMA)
        self._register("scan", _scan.handle_scan, _scan.SCAN_SCHEMA)
        self._register("pane_spawn", _panes.handle_pane_spawn,
                       _panes.PANE_SPAWN_SCHEMA)
        self._register("pane_write", _panes.handle_pane_write,
                       _panes.PANE_WRITE_SCHEMA)
        self._register("pane_read", _panes.handle_pane_read,
                       _panes.PANE_READ_SCHEMA)
        self._register("pane_kill", _panes.handle_pane_kill,
                       _panes.PANE_KILL_SCHEMA)
        self._register("pane_list", _panes.handle_pane_list,
                       _panes.PANE_LIST_SCHEMA)
        self._register("pane_note", _pane_note.handle_pane_note,
                       _pane_note.PANE_NOTE_SCHEMA)
        self._register("memory_remember", _mem.handle_remember,
                       _mem.REMEMBER_SCHEMA)
        self._register("memory_recall", _mem.handle_recall,
                       _mem.RECALL_SCHEMA)
        self._register("memory_forget", _mem.handle_forget,
                       _mem.FORGET_SCHEMA)
        self._register("memory_edit", _mem.handle_edit,
                       _mem.EDIT_SCHEMA)
        self._register("memory_pin", _mem.handle_pin,
                       _mem.PIN_SCHEMA)
        self._register("memory_unpin", _mem.handle_unpin,
                       _mem.UNPIN_SCHEMA)

    @property
    def ctx(self) -> ToolContext:
        return self._ctx
