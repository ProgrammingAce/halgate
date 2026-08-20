"""Configuration loading and validation (YAML + ${ENV_VAR} expansion)."""
from __future__ import annotations

import os
import re
import ipaddress
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from .errors import ConfigError
from .scope import ScopePackage

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")  # full 40-hex OpenPGP fingerprint


def _expand_env(value: Any, where: str) -> Any:
    """Expand ${VAR} references; raise ConfigError if a variable is missing."""
    if isinstance(value, str):
        def sub(m: re.Match) -> str:
            name = m.group(1)
            if name not in os.environ:
                raise ConfigError(
                    f"config ({where}): environment variable '{name}' is not set")
            return os.environ[name]
        return _ENV_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _expand_env(v, f"{where}.{k}") for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v, f"{where}[{i}]") for i, v in enumerate(value)]
    return value


class EndpointConfig(BaseModel):
    id: str
    base_url: str
    api_key: str = ""
    model: str
    max_tokens: int = 4096
    temperature: float = 0.3
    timeout: float = 180.0
    model_context: int = 32768
    output_reserve: int = 4096


class LLMConfig(BaseModel):
    active: str
    endpoints: list[EndpointConfig] = Field(default_factory=list)

    @property
    def endpoints_by_id(self) -> dict[str, EndpointConfig]:
        return {e.id: e for e in self.endpoints}

    def get_endpoint(self, endpoint_id: str) -> EndpointConfig:
        ep = self.endpoints_by_id.get(endpoint_id)
        if ep is None:
            raise ConfigError(f"unknown LLM endpoint: {endpoint_id}")
        return ep

    @property
    def active_endpoint(self) -> EndpointConfig:
        return self.get_endpoint(self.active)

    @property
    def active_model_context(self) -> int:
        return self.active_endpoint.model_context

    @property
    def active_output_reserve(self) -> int:
        return self.active_endpoint.output_reserve


class ScopeConfig(BaseModel):
    package: str = "defensive"
    overrides: dict[str, bool] = Field(default_factory=dict)


class MemoryConfig(BaseModel):
    dir: str = ".harness_memory"
    max_entries: int = 200
    max_text_chars: int = 500
    recall_limit: int = 10
    prompt_budget_tokens: int = 1000
    dup_similarity: float = 0.5
    recency_halflife_days: float = 14.0
    inferred_daily_cap: int = 12


class ShellConfig(BaseModel):
    workdir: str = "."


class PromptInjectionConfig(BaseModel):
    warn_patterns: bool = True
    require_confirmation_for_actionable_untrusted_content: bool = True


class SafetyConfig(BaseModel):
    dry_run: bool = False
    # This is an emergency backstop, not the normal workflow limit.  The
    # progress controller stops stalled/repeated work much earlier.
    max_tool_iterations_per_turn: int = 250
    max_turn_runtime_seconds: float = 3600.0
    max_stalled_tool_batches: int = 6
    max_repeated_tool_calls: int = 5
    max_unchanged_pane_reads: int = 3
    checkpoint_every_tool_actions: int = 20
    panic_checkpoint_timeout: float = 10.0
    prompt_injection: PromptInjectionConfig = Field(default_factory=PromptInjectionConfig)


class BudgetLimits(BaseModel):
    max_actions: int = 100
    max_requests: int = 500
    max_scan_targets: int = 50
    max_bytes_in: int = 104857600
    max_bytes_out: int = 104857600
    max_runtime_seconds: int = 3600


class BudgetsConfig(BaseModel):
    default: BudgetLimits = Field(default_factory=BudgetLimits)


class AuditConfig(BaseModel):
    dir: str = ".harness_audit"
    rotate_bytes: int = 52428800
    gpg_recipient: str = ""
    gpg_homedir: str | None = None
    gpg_executable: str = "gpg"
    crypto_backend: Literal["gpg", "pgpy"] = "gpg"
    pgpy_public_key: str | None = None
    pgpy_private_key: str | None = None
    pgpy_passphrase_env: str | None = None
    forensic_enabled: bool = True

    @field_validator("gpg_recipient")
    @classmethod
    def _validate_fingerprint(cls, v: str) -> str:
        if v == "":
            return v
        if not _FINGERPRINT_RE.match(v or ""):
            raise ValueError(
                "audit.gpg_recipient must be a full 40-hex OpenPGP fingerprint")
        return v.upper()


class SessionsConfig(BaseModel):
    dir: str = ".harness_sessions"


class EvidenceConfig(BaseModel):
    dir: str = ".harness_evidence"
    max_artifact_bytes: int = 52428800
    retention_days: int = 90


class ProcessConfig(BaseModel):
    max_panes: int = 8
    default_read_timeout: float = 5.0
    # Absorb bursts from long-running panes until the UI polling loop drains
    # them; visible scrollback is independently bounded by the TUI.
    pane_buffer_bytes: int = 8388608
    container_runtime: str = "podman"
    container_image: str = "localhost/harness:latest"


class CallbackConfig(BaseModel):
    """Operator-declared network identity advertised to assessment targets."""
    advertised_host: str | None = None

    @field_validator("advertised_host")
    @classmethod
    def _validate_advertised_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
        host = value.strip()
        if not host:
            return None
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            pass
        if (len(host) > 253 or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host)
                or ".." in host):
            raise ValueError("callback.advertised_host must be a hostname or IP address without a scheme or port")
        return host


class TUIConfig(BaseModel):
    chat_width_pct: int = 62

    @field_validator("chat_width_pct")
    @classmethod
    def _clamp_chat_width(cls, v: int) -> int:
        return max(20, min(80, v))


class Config(BaseModel):
    llm: LLMConfig
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    shell: ShellConfig = Field(default_factory=ShellConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    budgets: BudgetsConfig = Field(default_factory=BudgetsConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    sessions: SessionsConfig = Field(default_factory=SessionsConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    process: ProcessConfig = Field(default_factory=ProcessConfig)
    callback: CallbackConfig = Field(default_factory=CallbackConfig)
    tui: TUIConfig = Field(default_factory=TUIConfig)
    packages: dict[str, ScopePackage] = Field(default_factory=dict)


def load_packages(packages_path: str | Path) -> dict[str, ScopePackage]:
    """Load scope package definitions from a scope_packages.yaml file."""
    path = Path(packages_path)
    if not path.exists():
        raise ConfigError(f"scope packages file not found: {path}")
    data = yaml.safe_load(path.read_text()) or {}
    raw_packages = data.get("packages") or {}
    packages: dict[str, ScopePackage] = {}
    for name, spec in raw_packages.items():
        packages[name] = ScopePackage.from_yaml(str(name), spec or {})
    return packages


def _find_default_packages(config_path: Path | None) -> Path | None:
    if config_path is not None:
        candidate = config_path.parent / "scope_packages.yaml"
        if candidate.exists():
            return candidate
    for base in (Path.cwd(), Path.home() / ".config" / "harness"):
        candidate = base / "scope_packages.yaml"
        if candidate.exists():
            return candidate
    # Shipped alongside the package.
    candidate = Path(__file__).parent.parent / "scope_packages.yaml"
    if candidate.exists():
        return candidate
    return None


DEFAULT_CONFIG_CANDIDATES = (
    "config.yaml",
    str(Path.home() / ".config" / "harness" / "config.yaml"),
)


def load_config(path: str | Path | None = None,
                packages_path: str | Path | None = None) -> Config:
    """Load YAML config, expand ${ENV_VAR} references, validate with pydantic.

    Resolution order for `path`: explicit argument, then ./config.yaml, then
    ~/.config/harness/config.yaml. Missing file => built-in defaults.
    """
    resolved: Path | None = None
    if path is not None:
        resolved = Path(path)
        if not resolved.exists():
            raise ConfigError(f"config file not found: {resolved}")
    else:
        for candidate in DEFAULT_CONFIG_CANDIDATES:
            p = Path(candidate)
            if p.exists():
                resolved = p
                break
    raw: dict[str, Any] = {}
    if resolved is not None:
        raw = yaml.safe_load(resolved.read_text()) or {}
        raw = _expand_env(raw, "config")

    for section in ("llm", "memory", "scope", "shell", "safety", "budgets",
                    "audit", "sessions", "evidence", "process", "callback", "tui"):
        raw.setdefault(section, {})

    llm_active = raw["llm"].get("active")
    if not llm_active and not raw["llm"].get("endpoints"):
        # Sensible local default so the harness starts without a config file.
        raw["llm"] = {
            "active": "llama-local",
            "endpoints": [{
                "id": "llama-local",
                "base_url": "http://127.0.0.1:8080/v1",
                "api_key": "llama",
                "model": "qwen-27b",
            }],
        }
    if not raw["llm"].get("endpoints"):
        raise ConfigError("config: llm.endpoints must not be empty")
    if raw["llm"]["active"] not in {e.get("id") for e in raw["llm"]["endpoints"]}:
        raise ConfigError(f"config: llm.active '{raw['llm']['active']}' is not a defined endpoint")

    try:
        cfg = Config.model_validate(raw)
    except Exception as e:  # pydantic.ValidationError etc.
        raise ConfigError(f"invalid configuration: {e}") from e

    pkgs_path = Path(packages_path) if packages_path else _find_default_packages(resolved)
    if pkgs_path is not None and pkgs_path.exists():
        cfg.packages = load_packages(pkgs_path)
    if cfg.scope.package and cfg.scope.package not in cfg.packages:
        raise ConfigError(
            f"config: scope.package '{cfg.scope.package}' not found in scope packages")
    return cfg
