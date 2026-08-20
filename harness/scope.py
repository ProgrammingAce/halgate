"""Core domain: scope packages, engagements, target normalization, ScopeGate."""
from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import shlex
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, Field

from .errors import ScopeError


_ENGAGEMENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")


def new_engagement_id() -> str:
    """Return an opaque, globally unique ID for a newly created engagement."""
    return f"eng_{uuid4().hex}"


class GuardrailConfig(BaseModel):
    shell_timeout: int = 300
    shell_max_output: int = 10485760
    max_concurrent_tools: int = 4
    require_confirmation: bool = True


class ScopePackage(BaseModel):
    name: str
    tools: dict[str, Any] = Field(default_factory=dict)
    shell_allowlist: list[str] = Field(default_factory=list)
    http_methods: list[str] = Field(default_factory=lambda: ["GET"])
    http_max_response: int = 1048576
    scan_enabled: bool = False
    scan_max_targets: int = 10
    scan_max_ports: int = 1000
    scan_timeout: int = 120
    process_enabled: bool = False
    memory_enabled: bool = True
    plan_enabled: bool = True
    # Structured JWT minting. HS256 uses an encrypted keystore credential;
    # unsigned tokens are a separate opt-in for authorized parser testing.
    # Package settings select supported signing algorithms. JWT contents are
    # intentionally target-policy neutral; use is scoped by engagement.
    jwt_sign_enabled: bool = False
    jwt_unsigned_enabled: bool = False
    jwt_max_ttl_seconds: int = 300
    jwt_allowed_claims: list[str] = Field(
        default_factory=lambda: ["iss", "sub", "aud", "jti"])
    jwt_algorithms: list[str] = Field(default_factory=lambda: ["HS256"])
    guardrails: GuardrailConfig = Field(default_factory=GuardrailConfig)

    @classmethod
    def from_yaml(cls, name: str, data: dict[str, Any]) -> "ScopePackage":
        tools = dict(data.get("tools") or {})
        nested = tools.pop("shell_allowlist", None)
        allowlist = nested if nested is not None else list(data.get("shell_allowlist") or [])

        def tool_flag(tool_name: str, default: bool = False) -> bool:
            if tool_name in tools:
                return bool(tools[tool_name])
            return default

        http = data.get("http") or {}
        scan = data.get("scan") or {}
        proc = data.get("process") or {}
        jwt = data.get("jwt") or {}
        guard = data.get("guardrails") or {}
        tool_map = {k: bool(v) for k, v in tools.items() if isinstance(v, bool)}
        # Normalize so `permits()` answers uniformly for section-backed tools:
        # a package enables `http`/`scan`/`process` via its nested section when
        # the tools map does not state them explicitly.
        tool_map.setdefault("http", "http" in data and bool(http.get("methods", True)))
        if "scan" not in tool_map:
            tool_map["scan"] = bool(scan.get("enabled", False))
        if "process" not in tool_map:
            tool_map["process"] = bool(proc.get("enabled", False))
        if "jwt_sign" not in tool_map:
            tool_map["jwt_sign"] = bool(jwt.get("sign", False)
                                       or jwt.get("unsigned", False))
        tool_map.setdefault("memory",
                            bool(data.get("memory", tools.get("memory", True))))
        tool_map.setdefault("plan", bool(data.get("plan", tools.get("plan", True))))
        return cls(
            name=name,
            tools=tool_map,
            shell_allowlist=allowlist,
            http_methods=list(http.get("methods") or ["GET"]),
            http_max_response=int(http.get("max_response_bytes") or 1048576),
            scan_enabled=bool(scan.get("enabled", False) or (data.get("scan") is not None
                                                            and tool_flag("scan", False))),
            scan_max_targets=int(scan.get("max_targets") or 10),
            scan_max_ports=int(scan.get("max_ports") or 1000),
            scan_timeout=int(scan.get("timeout") or 120),
            process_enabled=bool(proc.get("enabled", False) or tool_flag("process", False)),
            memory_enabled=bool(data.get("memory", tools.get("memory", True))),
            plan_enabled=bool(data.get("plan", tools.get("plan", True))),
            jwt_sign_enabled=bool(jwt.get("sign", False) or tool_flag("jwt_sign", False)),
            jwt_unsigned_enabled=bool(jwt.get("unsigned", False)),
            jwt_max_ttl_seconds=max(1, min(int(jwt.get("max_ttl_seconds", 300)), 86400)),
            jwt_allowed_claims=[str(c) for c in (jwt.get("allowed_claims")
                                              or ["iss", "sub", "aud", "jti"])],
            jwt_algorithms=[str(a).upper()
                           for a in (jwt.get("algorithms") or ["HS256"])],
            guardrails=GuardrailConfig(
                shell_timeout=int(guard.get("shell_timeout", 300)),
                shell_max_output=int(guard.get("shell_max_output", 10485760)),
                max_concurrent_tools=int(guard.get("max_concurrent_tools", 4)),
                require_confirmation=bool(guard.get("require_confirmation", True)),
            ),
        )

    def permits(self, tool_name: str) -> bool:
        # Panes are the public operations for the package-level `process`
        # capability.  Keeping that mapping here makes schema visibility and
        # dispatch authorization agree with process.enabled in YAML.
        if tool_name.startswith("pane_"):
            return bool(self.tools.get(tool_name, self.tools.get("process", False)))
        # jwt_sign is section-backed (jwt.sign / jwt.unsigned): answer
        # uniformly whether the package came from YAML or was constructed
        # directly.
        if tool_name == "jwt_sign":
            return bool(self.tools.get("jwt_sign", self.jwt_sign_enabled
                                      or self.jwt_unsigned_enabled))
        return bool(self.tools.get(tool_name, False))


@dataclass
class Engagement:
    id: str
    label: str
    target: str
    package: str
    # Host execution is the normal case.  Container mode is opt-in for an
    # engagement that actually lives in, or is assessed from, a container.
    execution_mode: str = "host"       # "host" (default) | "container"
    budget_overrides: dict[str, int] = field(default_factory=dict)
    jwt_claim_extensions: tuple[str, ...] = ()
    status: str = "active"             # "active" | "paused"
    created: str = ""
    # Provisioned by Harness; never accepted from an engagement package.
    scratch_dir: str = ""

    def __post_init__(self) -> None:
        if not _ENGAGEMENT_ID_RE.fullmatch(self.id):
            raise ScopeError("engagement id must be 1-80 safe identifier characters")
        if self.execution_mode not in ("container", "host"):
            raise ScopeError(f"invalid execution_mode: {self.execution_mode}")
        if self.status not in ("active", "paused"):
            raise ScopeError(f"invalid status: {self.status}")

    @property
    def is_path_target(self) -> bool:
        return self.target.startswith("/")

    def matches_target(self, ref: str) -> bool:
        """Does a target reference (IP, CIDR, path) fall under this engagement?

        Path matching compares resolved *path components* — /opt/project.evil
        must not match /opt/project. Network matching uses ipaddress semantics.
        """
        if self.target.startswith("/"):
            try:
                # strict=True: a missing target root matches nothing (fail closed)
                root = Path(self.target).resolve(strict=True)
            except (OSError, RuntimeError):
                return False
            candidate = Path(ref).resolve(strict=False)
            return candidate.is_relative_to(root)
        try:
            net = ipaddress.ip_network(self.target, strict=False)
            return ipaddress.ip_address(ref) in net
        except ValueError:
            # Bare hostname CIDR-less target: exact match only.
            return ref == self.target


# ---------------------------------------------------------------------------
# Target normalization / validation helpers
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/(?:\d{1,2}))?\b"
)

# Commands whose positional operands can open an outbound network connection.
# Host-like text in other commands (notably printf/echo used by pane notes)
# is data, not a target.
_NETWORK_CLIENT_BINARIES = frozenset({
    "curl", "wget", "nmap", "masscan", "ping", "ping6", "traceroute",
    "traceroute6", "nc", "netcat", "telnet", "ssh", "scp", "sftp",
    "rsync", "dig", "host", "nslookup", "nikto", "whatweb", "ffuf",
    "gobuster", "feroxbuster", "sqlmap", "hydra", "smbclient",
    "rpcclient", "ldapsearch", "snmpwalk",
})

# Values supplied to these options name local result files, not outbound
# destinations.  Looking for FQDNs in every argument of a network client made
# names such as ``select.html`` fail scope validation as if they were hosts.
# This intentionally covers the common output-file spellings across the
# allowed assessment tools; URL and bare-host operands remain scope-checked.
_OUTPUT_FILE_OPTIONS = frozenset({
    "-o", "-D", "-oN", "-oX", "-oG", "-oA",
    "--output", "--output-file", "--output-dir", "--dump-header",
    "--stderr", "--trace", "--trace-ascii", "--log-file", "--log-plaintext",
    "--log-json", "--log-xml", "--output-path",
})


def path_within(root: str, ref: str) -> tuple[bool, str]:
    """True iff `ref` resolves to a path at or under `root`.

    Rejects:
      - prefix-string confusion (/opt/project.evil under /opt/project)
      - `..` escape
      - symlink escape (a symlink inside root pointing outside)
    """
    try:
        root_p = Path(root).resolve(strict=True)
    except (OSError, RuntimeError) as e:
        return False, f"target root unavailable: {e}"
    try:
        ref_p = Path(ref).resolve(strict=False)
    except (OSError, RuntimeError) as e:  # pragma: no cover - exotic fs errors
        return False, f"unresolvable path: {e}"
    if not ref_p.is_relative_to(root_p):
        return False, f"path escapes engagement scope: {ref}"
    return True, ""


def url_in_scope(url: str, engagement: Engagement,
                 resolver: Any = None) -> tuple[bool, str]:
    """Validate a normalized URL against an engagement's network scope.

    - scheme must be http/https, host must be present, no credentials/userinfo
    - every resolved IP of the host must fall inside the engagement network
    - path-target engagements have no network scope and are denied

    `resolver` is injectable for tests; default uses getaddrinfo.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, f"unsupported scheme: {parsed.scheme or 'missing'}"
    if not parsed.hostname:
        return False, "URL has no host"
    if parsed.username or parsed.password:
        return False, "credentials in URL are not permitted"
    if engagement.is_path_target:
        return False, "engagement has no network scope (path target)"

    try:
        port = parsed.port
    except ValueError as e:
        return False, f"invalid URL port: {e}"
    host = parsed.hostname
    def default_resolver(h: str) -> list[ipaddress._BaseAddress]:
        ips: list[ipaddress._BaseAddress] = []
        try:
            infos = socket.getaddrinfo(h, port or (443 if parsed.scheme == "https" else 80),
                                       proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise ScopeError(f"DNS resolution failed for {h}")
        for info in infos:
            addr = info[4][0].split("%")[0]
            try:
                ips.append(ipaddress.ip_address(addr))
            except ValueError:
                raise ScopeError(f"unparseable resolved address for {h}: {addr}")
        if not ips:
            raise ScopeError(f"DNS resolution returned no addresses for {h}")
        # Hostnames (non-IP) are only in scope if the engagement target is that
        # exact hostname string; resolved IPs are always checked against CIDR.
        # IP literal hosts are checked directly against the network.
        return set(ips)

    try:
        resolver_fn = resolver or default_resolver
        ips = resolver_fn(host)
        if isinstance(ips, set):
            ips = list(ips)
    except (ScopeError, ValueError) as e:
        return False, str(e)

    if not engagement.is_path_target:
        try:
            net = ipaddress.ip_network(engagement.target, strict=False)
            for ip in ips:
                if ip.version != net.version or ip not in net:
                    return False, (f"resolved host {host} -> {ip} is outside "
                                   f"engagement network {engagement.target}")
        except ValueError:
            # Non-CIDR hostname target: exact hostname match only.
            if host != engagement.target:
                return False, f"host {host} is outside engagement scope {engagement.target}"
    return True, ""


def extract_target_refs(command: str) -> list[str]:
    """Extract IP/CIDR and absolute-path references out of an arbitrary command.

    Used to validate shell commands against the engagement scope: any
    IP-like or path-like token that can be validated is validated. Unparseable
    tokens are not a failure (the allowlist is the primary control).
    """
    refs: list[str] = []
    for m in _IP_RE.finditer(command):
        try:
            refs.append(str(ipaddress.ip_network(m.group(0), strict=False)
                           if "/" in m.group(0)
                           else ipaddress.ip_address(m.group(0))))
        except ValueError:
            continue
    for token in command.replace('","', " ").replace('\"', " ").split():
        if token.startswith("/") and len(token) > 1 and re.search(r"[a-zA-Z0-9]", token):
            refs.append(token)
    return refs


def extract_urls(command: str) -> list[str]:
    """Return HTTP(S) URLs embedded in a command line.

    Shell commands are not structured like the HTTP tool, but allowing an
    in-scope binary such as curl must not create an unchecked hostname path.
    The URL is subsequently passed through the same DNS-aware scope check as
    the structured HTTP tool.
    """
    return re.findall(r"https?://[^\s'\"<>]+", command, flags=re.IGNORECASE)


def extract_hostnames(command: str) -> list[str]:
    """Find FQDN-like strings for display, not scope authorization."""
    return re.findall(
        r"(?<![A-Za-z0-9.-])([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9-]+)+)(?![A-Za-z0-9.-])", command)


def extract_network_command_hostnames(command: str) -> list[str]:
    """Return host-like operands only from network-capable command segments.

    A generic dotted-token scan is unsafe: it treats prose, semantic versions,
    email addresses, and filenames as outbound hosts.  URLs and IP literals
    are handled separately; this covers bare FQDN operands such as
    ``nmap target.example``.
    """
    hosts: list[str] = []
    for segment in re.split(r"\|\||&&|[|;&()]+", command):
        try:
            tokens = shlex.split(segment)
        except ValueError:
            continue
        if not tokens or os.path.basename(tokens[0]) not in _NETWORK_CLIENT_BINARIES:
            continue
        hosts.extend(extract_hostnames(" ".join(
            _network_operands_without_output_paths(tokens[1:]))))
    return hosts


def _network_operands_without_output_paths(tokens: list[str]) -> list[str]:
    """Remove network-tool output path arguments before hostname extraction."""
    operands: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in _OUTPUT_FILE_OPTIONS:
            skip_next = True
            continue
        if any(token.startswith(option + "=") for option in _OUTPUT_FILE_OPTIONS
               if option.startswith("--")):
            continue
        # Several tools accept a compact short form, e.g. ``-oresults.html``.
        if token.startswith("-o") and len(token) > 2:
            continue
        operands.append(token)
    return operands


def shell_binary_allowed(binary: str, allowlist: list[str]) -> bool:
    """Allowlist match: exact basename, glob (fnmatch), or 'prefix-' entries.

    The shipped packages use entries like "impacket-" to cover all
    impacket-* tools; plain names like "testssl.sh" must match exactly.
    """
    if not allowlist:
        return True  # empty allowlist = no restriction (checked elsewhere)
    name = os.path.basename(binary)
    for entry in allowlist:
        if name == entry or (entry.endswith("-") and name.startswith(entry)):
            return True
        if any(c in entry for c in "*?[") and fnmatch.fnmatch(name, entry):
            return True
    return False


def command_binaries(cmd: str) -> list[str]:
    """Return the executable from a direct-exec command string.

    The shell tool parses this string with ``shlex.split`` and invokes the
    resulting argv directly. Shell control characters are ordinary arguments,
    not separators, so there can be only one executable.
    """
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return []
    return [tokens[0]] if tokens else []


class ScopeGate:
    """Intercepts every tool call. Returns (allowed: bool, reason: str).

    Every target-bearing tool call is bound to exactly one explicit
    engagement_id; authorization is computed solely from that engagement and
    its package. Cross-engagement reuse is always denied.
    """

    def __init__(self, engagements: list[Engagement],
                 packages: dict[str, ScopePackage],
                 overrides: dict[str, bool]):
        ids = [engagement.id for engagement in engagements]
        if len(ids) != len(set(ids)):
            raise ScopeError("duplicate engagement id")
        self._engagements = engagements
        self._packages = packages
        self._overrides = dict(overrides)

    def active_engagements(self) -> list[Engagement]:
        return [e for e in self._engagements if e.status == "active"]

    def active_packages(self) -> list[ScopePackage]:
        return [self._packages[e.package] for e in self.active_engagements()
                if e.package in self._packages]

    def any_active_engagement_permits(self, tool_name: str) -> bool:
        """Schema visibility: tool appears to the LLM if any active
        engagement permits it. Authorization remains engagement-specific."""
        return any(pkg.permits(tool_name) for pkg in self.active_packages())

    def _require_active(self, engagement_id: str) -> Engagement:
        eng = self._find(engagement_id)
        if eng is None:
            raise ScopeError(f"unknown engagement: {engagement_id}")
        if eng.status != "active":
            raise ScopeError(f"engagement {engagement_id} is not active")
        return eng

    def _find(self, engagement_id: str) -> Engagement | None:
        for e in self._engagements:
            if e.id == engagement_id:
                return e
        return None

    def check_tool(self, tool_name: str, engagement_id: str) -> tuple[bool, str]:
        """Is this tool permitted by the explicitly selected active engagement?"""
        if tool_name in self._overrides:
            # Operator override wins over the package, but the engagement must
            # exist and be active (no override can resurrect paused work).
            try:
                self._require_active(engagement_id)
            except ScopeError as e:
                return False, str(e)
            return (self._overrides[tool_name], "")
        try:
            engagement = self._require_active(engagement_id)
        except ScopeError as e:
            return False, str(e)
        pkg = self._packages.get(engagement.package)
        if pkg is None:
            return False, (f"engagement '{engagement_id}' references unknown "
                           f"package '{engagement.package}'")
        if pkg.permits(tool_name):
            return True, ""
        return False, f"tool '{tool_name}' disabled for engagement '{engagement_id}'"

    def resolve_engagement(self, target_ref: str) -> Engagement | None:
        """Find which active engagement owns this target reference."""
        for e in self._engagements:
            if e.status == "active" and e.matches_target(target_ref):
                return e
        return None

    # -- individual target validations (also used by tool adapters) --------

    def check_path(self, path: str, engagement: Engagement) -> tuple[bool, str]:
        if engagement.scratch_dir:
            scratch_ok, _ = path_within(engagement.scratch_dir, path)
            if scratch_ok:
                return True, ""
        if engagement.is_path_target:
            return path_within(engagement.target, path)
        return False, "path is outside this engagement's scratch directory"

    def check_url(self, url: str, engagement: Engagement,
                  resolver: Any = None) -> tuple[bool, str]:
        try:
            return url_in_scope(url, engagement, resolver=resolver)
        except ScopeError as e:
            return False, str(e)

    def check_scan_targets(self, targets: list[str], ports: list[str],
                           engagement: Engagement) -> tuple[bool, str]:
        pkg = self._packages[engagement.package]
        if not pkg.scan_enabled:
            return False, "scan disabled for engagement package"
        if len(targets) > pkg.scan_max_targets:
            return False, f"too many targets ({len(targets)} > {pkg.scan_max_targets})"
        try:
            port_count = self._count_ports(ports)
        except ValueError as e:
            return False, str(e)
        if port_count > pkg.scan_max_ports:
            return False, f"too many ports ({port_count} > {pkg.scan_max_ports})"
        for t in targets:
            if "/" in t:
                try:
                    net = ipaddress.ip_network(t, strict=False)
                except ValueError:
                    return False, f"invalid scan target: {t}"
                if not engagement.matches_target(net.network_address) \
                        or not self._cidr_within(engagement, net):
                    return False, f"scan target {t} outside engagement scope"
            else:
                if not engagement.matches_target(t):
                    return False, f"scan target {t} outside engagement scope"
        return True, ""

    @staticmethod
    def _cidr_within(engagement: Engagement, net: ipaddress._BaseNetwork) -> bool:
        try:
            engagement_net = ipaddress.ip_network(engagement.target, strict=False)
        except ValueError:
            return False
        return net.subnet_of(engagement_net)

    @staticmethod
    def _count_ports(ports: list[str]) -> int:
        total = 0
        for spec in ports or ["80"]:
            for part in str(spec).split(","):
                part = part.strip()
                if not part:
                    continue
                if "-" in part:
                    lo, hi = part.split("-", 1)
                    lo_i, hi_i = int(lo), int(hi)
                    if lo_i < 0 or hi_i > 65535 or hi_i < lo_i:
                        raise ValueError(f"invalid port range: {part}")
                    total += hi_i - lo_i + 1
                else:
                    p = int(part)
                    if p < 0 or p > 65535:
                        raise ValueError(f"invalid port: {part}")
                    total += 1
        return total

    def check_jwt_sign(self, claims: Any, ttl_seconds: Any,
                       engagement: Engagement,
                       algorithm: Any = "HS256") -> tuple[bool, str]:
        """Validate signing capability without constraining JWT contents.

        Tokens are bound to an engagement when stored and can only be attached
        through that engagement's URL-scoped HTTP tools.  Claim policy belongs
        to the authorized target, not to the minting operation.
        """
        pkg = self._packages[engagement.package]
        if algorithm == "none":
            enabled = pkg.jwt_unsigned_enabled
        elif algorithm in pkg.jwt_algorithms:
            enabled = pkg.jwt_sign_enabled
        else:
            return False, (f"algorithm {algorithm} not declared by this "
                           f"package (enabled: {', '.join(pkg.jwt_algorithms)})")
        if not enabled:
            if algorithm == "none":
                return False, "jwt_sign none disabled for engagement package"
            return False, f"jwt_sign {algorithm} disabled for engagement package"
        if not isinstance(claims, dict):
            return False, "claims must be a JSON object"
        if not all(isinstance(key, str) and key for key in claims):
            return False, "JWT claim names must be non-empty strings"
        try:
            import json
            json.dumps(claims, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            return False, "JWT claims must be JSON-serializable values"
        if ttl_seconds is not None and (not isinstance(ttl_seconds, int)
                                        or isinstance(ttl_seconds, bool)
                                        or ttl_seconds < 1):
            return False, "ttl_seconds must be a positive integer when supplied"
        return True, ""

    def check_shell(self, cmd: str, engagement: Engagement) -> tuple[bool, str]:
        """Allowlist + scope-ref check for a shell command."""
        from .guardrails.shell_guard import ShellGuard
        pkg = self._packages[engagement.package]
        guard = ShellGuard(pkg.shell_allowlist, pkg.guardrails.shell_timeout,
                           pkg.guardrails.shell_max_output, ".")
        ok, reason = guard.check(cmd)
        if not ok:
            return ok, reason
        for url in extract_urls(cmd):
            ok, reason = self.check_url(url, engagement)
            if not ok:
                return False, f"URL '{url}' is outside engagement scope: {reason}"
        refs = extract_target_refs(cmd)
        # A dotted filename in an already-extracted absolute path (for
        # example, /scratch/scan.txt) is not a network hostname.
        local_filenames = {
            Path(ref).name for ref in refs if ref.startswith("/")
        }
        # A bare FQDN operand (for example, `nmap target.example`) must still
        # be in scope.  Restrict extraction to network-capable commands so
        # plain text in a pane command cannot become a false target.
        for host in extract_network_command_hostnames(cmd):
            if host in local_filenames:
                continue
            ok, reason = self.check_url(f"http://{host}", engagement)
            if not ok:
                return False, f"host '{host}' is outside engagement scope: {reason}"
        for ref in refs:
            scratch_ok = False
            if engagement.scratch_dir and ref.startswith("/"):
                scratch_ok, _ = path_within(engagement.scratch_dir, ref)
            if not engagement.matches_target(ref) and not scratch_ok:
                owner = self.resolve_engagement(ref)
                who = f" engagement '{owner.id}'" if owner else " no engagement"
                return False, f"target ref '{ref}' in command belongs to{who}, not this engagement"
        return True, ""

    # -- unified authorization --------------------------------------------

    def authorize(self, tool_name: str, args: dict, engagement_id: str,
                  resolver: Any = None) -> tuple[bool, str, Engagement | None]:
        """Validate a tool call against the specified engagement.

        Cross-engagement access is always denied; the operator must issue a
        separate call bound to the owning engagement (auditable boundary).
        """
        if not engagement_id:
            return False, "missing engagement_id", None
        try:
            engagement = self._require_active(engagement_id)
        except ScopeError as e:
            return False, str(e), None
        allowed, reason = self.check_tool(tool_name, engagement_id)
        if not allowed:
            return False, reason, engagement
        return self._authorize_target_args(tool_name, args, engagement, resolver)

    def _authorize_target_args(self, tool_name: str, args: dict,
                               engagement: Engagement,
                               resolver: Any = None) -> tuple[bool, str, Engagement | None]:
        # Non-target tools (memory/plan/pane meta) are engagement-bound but have
        # no structured target to validate here.
        if tool_name in ("http", "http_replay", "http_session", "auth_session", "multipart_upload"):
            method = str(args.get("method", "GET")).upper()
            pkg = self._packages[engagement.package]
            if method not in [m.upper() for m in pkg.http_methods]:
                return False, f"HTTP method {method} not permitted by package", engagement
            url = args.get("url")
            if not url:
                return False, "missing url", engagement
            ok, reason = self.check_url(str(url), engagement, resolver=resolver)
            if ok and tool_name == "multipart_upload":
                path = args.get("path")
                if not path:
                    return False, "missing upload path", engagement
                if not engagement.scratch_dir:
                    return False, "multipart uploads require an engagement scratch directory", engagement
                ok, reason = path_within(engagement.scratch_dir, str(path))
            if ok and tool_name == "http" and args.get("save_as") is not None:
                save_as = args.get("save_as")
                if not isinstance(save_as, str) or not save_as:
                    return False, "save_as must be a non-empty relative path", engagement
                if not engagement.scratch_dir:
                    return False, "saving an HTTP response requires an engagement scratch directory", engagement
                if Path(save_as).is_absolute():
                    return False, "save_as must be relative to the engagement scratch directory", engagement
                ok, reason = path_within(
                    engagement.scratch_dir,
                    str(Path(engagement.scratch_dir) / save_as))
            return ok, reason, engagement
        if tool_name == "websocket":
            url = str(args.get("url") or "")
            if not url.startswith(("ws://", "wss://")):
                return False, "WebSocket URL must use ws:// or wss://", engagement
            http_url = ("https://" if url.startswith("wss://") else "http://") + url.split("://", 1)[1]
            ok, reason = self.check_url(http_url, engagement, resolver=resolver)
            return ok, reason, engagement
        if tool_name == "tcp_probe":
            host = str(args.get("host") or "")
            try:
                port = int(args.get("port"))
            except (TypeError, ValueError):
                return False, "TCP probe requires an integer port", engagement
            if not host or not 1 <= port <= 65535:
                return False, "TCP probe requires one host and port 1-65535", engagement
            # Bracket IPv6 literals so urlparse can unambiguously recover the
            # host and port before applying normal network-scope checks.
            try:
                normalized = str(ipaddress.ip_address(host))
                netloc = f"[{normalized}]:{port}" if ":" in normalized else f"{normalized}:{port}"
            except ValueError:
                netloc = f"{host}:{port}"
            ok, reason = self.check_url(f"http://{netloc}", engagement, resolver)
            return ok, reason, engagement
        if tool_name == "scan":
            targets = args.get("targets") or []
            if isinstance(targets, str):
                targets = [t for t in targets.split() if t]
            if not targets:
                return False, "missing scan targets", engagement
            ok, reason = self.check_scan_targets(
                list(targets), args.get("ports") or [], engagement)
            return ok, reason, engagement
        if tool_name == "jwt_sign":
            ok, reason = self.check_jwt_sign(
                args.get("claims"), args.get("ttl_seconds"), engagement,
                args.get("algorithm", "HS256"))
            return ok, reason, engagement
        if tool_name == "shell":
            cmd = args.get("command")
            if not cmd:
                return False, "missing command", engagement
            ok, reason = self.check_shell(str(cmd), engagement)
            return ok, reason, engagement
        path_args = {
            "read_file": [args.get("path")],
            "read_source_code": [args.get("path")],
            "write_file": [args.get("path")],
            "glob": [args.get("path")],
            "grep": [args.get("path")],
        }
        if tool_name in path_args:
            for ref in path_args[tool_name]:
                if not ref:
                    if tool_name == "glob":
                        # A glob without an explicit base must remain inside
                        # the engagement; never fall back to the process CWD.
                        ref = engagement.scratch_dir
                        if not ref:
                            return False, ("glob requires a path or an engagement "
                                           "scratch directory"), engagement
                    else:
                        continue
                if tool_name == "read_source_code":
                    if not engagement.scratch_dir:
                        return False, "read_source_code requires an engagement scratch directory", engagement
                    candidate = Path(str(ref))
                    if not candidate.is_absolute():
                        candidate = Path(engagement.scratch_dir) / candidate
                    ok, reason = path_within(engagement.scratch_dir,
                                             str(candidate))
                    if not ok:
                        return False, reason, engagement
                    continue
                ok, reason = self.check_path(str(ref), engagement)
                if not ok:
                    return False, reason, engagement
        return True, "", engagement
