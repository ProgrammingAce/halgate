"""Per-instance identity for sharded storage (memory shards, keystore, audit)."""
from __future__ import annotations

import socket


def instance_id() -> str:
    """hostname.pid — isolates concurrent instances' shard files."""
    return f"{socket.gethostname()}.{__import__('os').getpid()}"
