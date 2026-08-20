"""Tests for ShellGuard: deny patterns, allowlist, execution."""
import pytest

from harness.guardrails.shell_guard import ShellGuard


@pytest.fixture
def guard():
    return ShellGuard(
        allowlist=["echo", "cat", "pwd", "ls"],
        timeout=5,
        max_output=1024,
        workdir="/tmp",
    )


# ---------------------------------------------------------------------------
# check() — deny patterns
# ---------------------------------------------------------------------------

class TestDenyPatterns:
    def test_rm_rf_root(self, guard):
        ok, msg = guard.check("rm -rf /")
        assert not ok
        assert "deny pattern" in msg

    def test_sudo(self, guard):
        ok, msg = guard.check("sudo ls")
        assert not ok

    def test_dd_of_dev(self, guard):
        ok, msg = guard.check("dd if=/dev/zero of=/dev/sda")
        assert not ok

    def test_mkfs(self, guard):
        ok, msg = guard.check("mkfs.ext4 /dev/sda1")
        assert not ok

    def test_shutdown(self, guard):
        ok, msg = guard.check("shutdown -h now")
        assert not ok

    def test_reboot(self, guard):
        ok, msg = guard.check("reboot")
        assert not ok

    def test_crontab(self, guard):
        ok, msg = guard.check("crontab -l")
        assert not ok

    def test_systemctl_stop(self, guard):
        ok, msg = guard.check("systemctl stop sshd")
        assert not ok

    def test_iptables_flush(self, guard):
        ok, msg = guard.check("iptables -F")
        assert not ok

    @pytest.mark.parametrize("command", [
        "rm -rf ./results", "python3 -c 'print(1)'", "bash -c 'id'",
    ])
    def test_irreversible_or_interpreter_commands_are_never_approved(
            self, guard, command):
        ok, msg = guard.check(command)
        assert not ok
        assert "blocked" in msg


# ---------------------------------------------------------------------------
# check() — allowlist
# ---------------------------------------------------------------------------

class TestAllowlist:
    def test_allowed_binary(self, guard):
        ok, msg = guard.check("echo hello world")
        assert ok, msg

    def test_denied_binary(self, guard):
        ok, msg = guard.check("nc -l 4444")
        assert not ok
        assert "not in allowlist" in msg

    @pytest.mark.parametrize("binary", ["curl", "wget"])
    def test_http_clients_are_redirected_to_structured_tools(self, guard, binary):
        ok, message = guard.check(f"{binary} http://192.0.2.10/")
        assert not ok
        assert "use http, http_session, http_replay, or multipart_upload" in message

    def test_empty_allowlist_allows(self):
        g = ShellGuard(allowlist=[], timeout=3, max_output=256, workdir="/tmp")
        ok, _ = g.check("anything_at_all")
        assert ok

    def test_glob_pattern(self, guard):
        ok, _ = guard.check("cat *.txt")
        assert ok, "glob pattern should pass allowlist on head binary"

    def test_piping_denied(self, guard):
        "The tool uses direct exec rather than a shell."
        ok, _ = guard.check("echo a | nc -l 4444")
        assert not ok

    @pytest.mark.parametrize("command", [
        "echo a | cat", "echo a > result.txt", "echo $(id)", "echo `id`",
        "echo a && cat result.txt", "echo a; cat result.txt",
    ])
    def test_shell_syntax_is_rejected(self, guard, command):
        ok, message = guard.check(command)
        assert not ok
        assert "shell syntax is unsupported" in message

    def test_chained_semicolon_denied(self, guard):
        ok, _ = guard.check("echo ok; rm -rf /")
        assert not ok


# ---------------------------------------------------------------------------
# execute() — real subprocess runs
# ---------------------------------------------------------------------------

class TestExecute:
    @pytest.fixture
    def executor(self, tmp_path):
        return ShellGuard(
            allowlist=["echo", "cat", "pwd", "sleep", "false", "ls", "printenv"],
            timeout=5,
            max_output=1024,
            workdir=str(tmp_path),
        )

    @pytest.mark.asyncio
    async def test_echo_basic(self, executor):
        res = await executor.execute("echo hello")
        assert res.rc == 0
        assert b"hello" in res.stdout
        assert not res.timed_out

    @pytest.mark.asyncio
    async def test_nonzero_exit(self, executor):
        res = await executor.execute("false")
        assert res.rc != 0

    @pytest.mark.asyncio
    async def test_stderr_capture(self, executor):
        res = await executor.execute(
            "echo 2"  # direct execution has no pipeline or redirect support
        )
        assert b"2" in res.stdout

    @pytest.mark.asyncio
    async def test_quotes_only_group_literal_arguments(self, executor):
        res = await executor.execute("echo 'two words'")
        assert res.rc == 0
        assert res.stdout == b"two words\n"

    @pytest.mark.asyncio
    async def test_stderr_separate(self, executor, tmp_path):
        res = await executor.execute("ls missing-file")
        assert res.rc != 0
        assert res.stderr

    @pytest.mark.asyncio
    async def test_truncation(self, executor, tmp_path):
        big_file = tmp_path / "big.txt"
        big_file.write_text("x" * 2048)
        res = await executor.execute("cat big.txt")
        assert res.truncated
        assert len(res.stdout) == 1024

    @pytest.mark.asyncio
    async def test_no_truncation(self, executor):
        res = await executor.execute("echo hello")
        assert not res.truncated
        assert res.stdout == b"hello\n"

    @pytest.mark.asyncio
    async def test_output_exactly_at_limit_is_not_truncated(self, executor, tmp_path):
        exact_file = tmp_path / "exact.txt"
        exact_file.write_bytes(b"x" * 1024)
        res = await executor.execute("cat exact.txt")
        assert res.stdout == b"x" * 1024
        assert not res.truncated

    @pytest.mark.asyncio
    async def test_timeout(self, tmp_path):
        g = ShellGuard(
            allowlist=["sleep"],
            timeout=1,
            max_output=256,
            workdir=str(tmp_path),
        )
        res = await g.execute("sleep 10")
        assert res.timed_out
        assert res.rc == -1
        assert b"TIMED OUT" in res.stderr

    @pytest.mark.asyncio
    async def test_unsupported_binary(self, tmp_path):
        g = ShellGuard(allowlist=[], timeout=3, max_output=256,
                       workdir=str(tmp_path))
        res = await g.execute("nonexistent_binary_xyz_123")
        assert res.rc != 0

    @pytest.mark.asyncio
    async def test_env_secret_stripped(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "supersecret")
        g = ShellGuard(
            allowlist=["printenv"],
            timeout=3,
            max_output=4096,
            workdir=str(tmp_path),
        )
        res = await g.execute("printenv")
        assert b"AWS_SECRET_ACCESS_KEY" not in res.stdout

    @pytest.mark.asyncio
    @pytest.mark.parametrize("command", [
        "nohup bash -c 'echo hi'",
        "setsid python -c 'print(1)'",
        "timeout python -c 'print(1)'",
    ])
    async def test_execution_wrappers_are_never_approved(self, tmp_path, command):
        g = ShellGuard(allowlist=[], timeout=3, max_output=256,
                       workdir=str(tmp_path))
        ok, _ = g.check(command)
        assert not ok
        result = await g.execute(command)
        assert result.rc == 126

    @pytest.mark.asyncio
    async def test_lowercase_secret_environment_is_stripped(self, tmp_path,
                                                            monkeypatch):
        monkeypatch.setenv("githubtoken", "supersecret")
        g = ShellGuard(allowlist=["printenv"], timeout=3, max_output=4096,
                       workdir=str(tmp_path))
        result = await g.execute("printenv")
        assert b"githubtoken" not in result.stdout
