"""ShellGuard: non-overridable safety blocks -> optional allowlist -> limits."""
from __future__ import annotations

import asyncio
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..scope import command_binaries, shell_binary_allowed

DENY_PATTERNS = [
    re.compile(r"\brm\s+(-[a-z]*r[r]{0,2}[a-z]*\s+)*(/(\s|$))"),   # rm -rf /
    re.compile(r"\b(sudo|doas|su)\b"),
    re.compile(r"\bdd\s+.*of=/dev/"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\b(shutdown|reboot|halt|poweroff)\b"),
    re.compile(r">\s*/dev/(sd|nvme|hd)"),
    re.compile(r"\bchmod\s+(-[a-z]+\s+)?777\s+/"),
    re.compile(r"\bchown\s+.*:\s*.*\s+/"),
    re.compile(r"\bcrontab\b"),
    re.compile(r"\bsystemctl\s+(stop|disable)\b"),
    re.compile(r"\biptables\s+-F\b"),
]

# These are never made available merely by accepting an approval prompt.  The
# shell tool executes commands directly (rather than through a shell), but an
# interpreter still provides arbitrary filesystem and process control and can
# bypass otherwise useful command-level protections.
FORBIDDEN_BINARIES = frozenset({
    "rm", "rmdir", "unlink", "shred", "wipefs", "mkfs", "fdisk", "parted",
    "bash", "sh", "dash", "zsh", "fish", "ksh", "csh", "tcsh",
    "python", "perl", "ruby", "node", "nodejs", "php", "lua", "env",
    # Multi-call binaries can expose an otherwise forbidden shell or
    # interpreter as an applet (for example, ``busybox sh``).
    "busybox", "toybox",
})

# Direct execution does not make these programs safe: each can arrange for a
# second executable to run, defeating argv[0]-only policy checks.
EXEC_WRAPPER_BINARIES = frozenset({
    "nohup", "setsid", "nice", "stdbuf", "timeout", "time", "xargs",
    "watch", "ionice", "chroot",
})

# HTTP traffic must stay on the structured tools so it receives URL scope
# validation, response metadata, session handling, and scratch-safe artifact
# storage.  These are not unsafe binaries in themselves; their shell use is
# simply superseded by the narrower HTTP tool family.
_STRUCTURED_TOOL_BINARIES = frozenset({"curl", "wget"})

_FORBIDDEN_ENV = re.compile(
    r"(AWS_SECRET|AWS_ACCESS|.*KEY.*|.*TOKEN.*|.*SECRET.*|.*PASSWORD.*|GH_TOKEN)",
    re.IGNORECASE)

# These tokens only have their usual meaning in a shell. Rejecting them makes
# a mistaken shell-style request obvious instead of silently passing literals
# to a program. Ampersands are deliberately not included: they are common in
# literal query strings and other program arguments.
_SHELL_SYNTAX = re.compile(
    r"(?:\|\||&&|\||;|<|>)|\$\(|`")


@dataclass
class ShellResult:
    rc: int
    stdout: bytes
    stderr: bytes
    truncated: bool
    timed_out: bool = False


def _reap_pid(pid: int) -> None:
    """Reap a zombied child process without asyncio transport interference."""
    import signal as _sig
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        try:
            os.kill(pid, _sig.SIGKILL)
            os.waitpid(pid, 0)
        except (ChildProcessError, ProcessLookupError, OSError):
            pass


class ShellGuard:
    """Guard direct program execution: regex -> allowlist -> limits -> OS.

    ``cmd`` is a user-friendly string only at the tool boundary.  It is parsed
    with :func:`shlex.split` and passed to ``create_subprocess_exec`` as argv;
    no shell interpreter is ever involved.
    """

    def __init__(self, allowlist: list[str], timeout: int,
                 max_output: int, workdir: str,
                 on_output: Callable[[str, str], None] | None = None):
        self._allowlist = list(allowlist)
        self._timeout = timeout
        self._max_output = max_output
        self._workdir = Path(workdir)
        self._on_output = on_output

    def check(self, cmd: str) -> tuple[bool, str]:
        # Layer 1: deny patterns
        for pat in DENY_PATTERNS:
            if pat.search(cmd):
                return False, "blocked: matches deny pattern"
        if _SHELL_SYNTAX.search(cmd):
            return False, ("blocked: shell syntax is unsupported; provide one "
                           "direct program invocation without shell operators")
        # Layer 2: commands that are unsafe by nature, even with an approval.
        binaries = command_binaries(cmd)
        if not binaries:
            return False, "empty command"
        for binary in binaries:
            name = os.path.basename(binary)
            if name in _STRUCTURED_TOOL_BINARIES:
                return False, (f"blocked: '{name}' is unavailable through shell; "
                               "use http, http_session, http_replay, or "
                               "multipart_upload instead")
            if name in FORBIDDEN_BINARIES or name.startswith("python"):
                return False, f"blocked: '{name}' is not permitted"
            if name in EXEC_WRAPPER_BINARIES:
                return False, (f"blocked: '{name}' can execute another program "
                               "and is not permitted")

        # Layer 3: optional per-package allowlist.  The shipped packages leave
        # this empty: shell commands require an explicit operator approval in
        # the dispatcher, so routine assessment tools need not be pre-enumerated.
        if self._allowlist:
            for binary in binaries:
                if not shell_binary_allowed(binary, self._allowlist):
                    return False, f"'{binary}' not in allowlist"
        return True, ""

    @staticmethod
    def parse(cmd: str) -> list[str]:
        """Return the exact argv representation, or an empty list if invalid."""
        try:
            return shlex.split(cmd)
        except ValueError:
            return []

    async def execute(self, cmd: str, timeout: int | None = None) -> ShellResult:
        return await self.execute_in_mode(cmd, timeout=timeout)

    async def execute_in_mode(self, cmd: str, timeout: int | None = None,
                              execution_mode: str = "host",
                              container_runtime: str = "podman",
                              container_image: str = "localhost/halgate:latest",
                              mount_dir: str | None = None) -> ShellResult:
        """Execute a checked command on the host or in an ephemeral container.

        Container mode deliberately uses an explicit runtime invocation; it
        cannot silently fall back to host execution when Podman is missing.
        The working directory is the only host path mounted into the container.
        """
        # Callers normally validate before prompting, but execution is the
        # final authority. This prevents future callers from bypassing the
        # non-overridable policy by calling this method directly.
        allowed, reason = self.check(cmd)
        if not allowed:
            return ShellResult(rc=126, stdout=b"", stderr=reason.encode(),
                               truncated=False)
        t = timeout or self._timeout
        env = {k: v for k, v in os.environ.items()
               if not _FORBIDDEN_ENV.search(k)}
        try:
            args = shlex.split(cmd)
        except ValueError as e:
            return ShellResult(rc=126, stdout=b"", stderr=str(e).encode(),
                               truncated=False)
        if not args:
            return ShellResult(rc=126, stdout=b"", stderr=b"empty command",
                               truncated=False)
        cwd = self._workdir
        if execution_mode == "container":
            try:
                cwd = Path(mount_dir or self._workdir).resolve(strict=True)
            except (OSError, RuntimeError) as e:
                return ShellResult(rc=126, stdout=b"", stderr=str(e).encode(),
                                   truncated=False)
            # Networking remains available for authorized assessment targets;
            # structured/shell scope checks are enforced before this point.
            args = [container_runtime, "run", "--rm", "--interactive",
                    "--workdir", "/work", "--volume", f"{cwd}:/work:Z",
                    container_image, *args]
        elif execution_mode != "host":
            return ShellResult(rc=126, stdout=b"",
                               stderr=b"invalid execution mode", truncated=False)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=str(cwd),
                preexec_fn=self._setrlimits,
                start_new_session=True,
            )
        except OSError as e:
            return ShellResult(rc=127, stdout=b"", stderr=str(e).encode(),
                               truncated=False)
        async def read_stream(stream, label: str) -> tuple[bytes, bool]:
            """Drain a pipe fully while retaining only the configured prefix."""
            chunks: list[bytes] = []
            kept = 0
            truncated = False
            while chunk := await stream.read(4096):
                accepted = b""
                if kept < self._max_output:
                    accepted = chunk[:self._max_output - kept]
                    chunks.append(accepted)
                    kept += len(accepted)
                if len(accepted) < len(chunk):
                    truncated = True
                if self._on_output is not None and accepted:
                    self._on_output(label, accepted.decode(errors="replace"))
            return b"".join(chunks), truncated

        async def collect() -> tuple[tuple[bytes, bool], tuple[bytes, bool]]:
            out = asyncio.create_task(read_stream(proc.stdout, "stdout"))
            err = asyncio.create_task(read_stream(proc.stderr, "stderr"))
            await proc.wait()
            return await asyncio.gather(out, err)

        comm_task = asyncio.ensure_future(collect())
        done, _ = await asyncio.wait({comm_task}, timeout=t)
        if comm_task in done:
            try:
                (stdout, stdout_truncated), (stderr, stderr_truncated) = comm_task.result()
            except Exception:
                self._kill_group(proc)
                return ShellResult(rc=1, stdout=b"", stderr=b"error",
                                   truncated=False)
        else:
            comm_task.cancel()
            try:
                await comm_task
            except (asyncio.CancelledError, Exception):
                pass
            self._kill_group(proc)
            # Reap the zombied process without going through asyncio transport
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _reap_pid, proc.pid)
            return ShellResult(rc=-1, stdout=b"", stderr=b"TIMED OUT",
                               truncated=False, timed_out=True)
        truncated = stdout_truncated or stderr_truncated
        stdout = stdout[: self._max_output]
        stderr = stderr[: self._max_output]
        return ShellResult(rc=proc.returncode or 0, stdout=stdout, stderr=stderr,
                           truncated=truncated, timed_out=False)

    @staticmethod
    def _kill_group(proc: asyncio.subprocess.Process) -> None:
        import signal
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    @staticmethod
    def _setrlimits() -> None:
        """Apply resource limits in the child (POSIX only)."""
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
            resource.setrlimit(resource.RLIMIT_FSIZE, (50 * 1024**2, 50 * 1024**2))
        except (ImportError, ValueError, OSError):
            pass
