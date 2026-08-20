from types import SimpleNamespace

import pytest

from halgate.scope import Engagement, ScopeGate
from halgate.tools.read_source_code import handle_read_source_code


def _ctx(packages, scratch):
    engagement = Engagement("eng-source", "source", "127.0.0.1", "defensive",
                            scratch_dir=str(scratch))
    return SimpleNamespace(gate=ScopeGate([engagement], packages, {}))


@pytest.mark.asyncio
async def test_reads_numbered_source_from_scratch(packages, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "app.py").write_text("def hello():\n    return 'world'\n")

    result = await handle_read_source_code(_ctx(packages, scratch), "app.py",
                                           "eng-source")

    assert result["language"] == "python"
    assert result["relative_path"] == "app.py"
    assert "     1 | def hello():" in result["content"]
    assert result["total_lines"] == 2


def test_scope_accepts_relative_source_paths_only_in_scratch(packages, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    ctx = _ctx(packages, scratch)

    ok, reason, _ = ctx.gate.authorize(
        "read_source_code", {"path": "app.py"}, "eng-source")

    assert ok, reason


@pytest.mark.asyncio
async def test_rejects_scratch_escape_and_binary_files(packages, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    outside = tmp_path / "secret.py"
    outside.write_text("secret = True\n")
    (scratch / "binary.py").write_bytes(b"\0not source")
    ctx = _ctx(packages, scratch)

    escaped = await handle_read_source_code(ctx, "../secret.py", "eng-source")
    binary = await handle_read_source_code(ctx, "binary.py", "eng-source")

    assert "outside" in escaped["error"]
    assert "binary" in binary["error"]


@pytest.mark.asyncio
async def test_paginates_source_without_losing_line_numbers(packages, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "main.ts").write_text("\n".join(f"line_{n}" for n in range(1, 6)))

    result = await handle_read_source_code(_ctx(packages, scratch), "main.ts",
                                           "eng-source", offset=3, limit=2)

    assert result["language"] == "typescript"
    assert "     3 | line_3" in result["content"]
    assert "     4 | line_4" in result["content"]
    assert result["truncated"] is True
