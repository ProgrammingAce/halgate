"""Shared tool context (avoids circular imports)."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Config
from ..memory.store import MemoryStore
from ..process import ProcessManager
from ..scope import ScopeGate


@dataclass
class ToolContext:
    config: Config
    gate: ScopeGate
    process_mgr: ProcessManager
    memory: MemoryStore
    extra: dict = field(default_factory=dict)
