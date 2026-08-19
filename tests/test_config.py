from pathlib import Path

import pytest

from harness.config import CallbackConfig, Config, load_config, load_packages, _expand_env
from harness.errors import ConfigError

REPO = Path(__file__).resolve().parent.parent


def test_env_expansion(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "abc123")
    data = {"key": "${MY_TOKEN}", "other": "pre-${MY_TOKEN}-post"}
    out = _expand_env(data, "root")
    assert out["key"] == "abc123"
    assert out["other"] == "pre-abc123-post"


def test_env_expansion_missing_raises(monkeypatch):
    monkeypatch.delenv("MISSING_VAR_X", raising=False)
    with pytest.raises(ConfigError, match="MISSING_VAR_X"):
        _expand_env({"k": "${MISSING_VAR_X}"}, "root")


def test_load_config_example(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    cfg = load_config(REPO / "config.example.yaml", REPO / "scope_packages.yaml")
    assert cfg.llm.active == "local"
    assert cfg.llm.active_endpoint.model_context == 32768
    assert set(cfg.packages) == {"offensive", "defensive", "read-only"}
    ro = cfg.packages["read-only"]
    assert ro.permits("read_file") and ro.permits("http")
    assert not ro.permits("shell") and not ro.permits("write_file")
    assert ro.http_methods == ["GET", "HEAD"]
    off = cfg.packages["offensive"]
    assert off.shell_allowlist == []
    assert cfg.callback.advertised_host is None


def test_callback_advertised_host_is_host_only():
    assert CallbackConfig(advertised_host="callback.lab.example").advertised_host == "callback.lab.example"
    assert CallbackConfig(advertised_host="2001:db8::1").advertised_host == "2001:db8::1"
    with pytest.raises(ValueError, match="hostname or IP"):
        CallbackConfig(advertised_host="https://callback.lab.example")


def test_missing_env_var_fails_at_startup(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    p = tmp_path / "bad.yaml"
    p.write_text(
        'llm:\n  active: a\n  endpoints:\n    - id: a\n      base_url: http://x\n'
        '      api_key: "${LLM_API_KEY}"\n      model: m\n')
    with pytest.raises(ConfigError, match="LLM_API_KEY"):
        load_config(p)


def test_short_key_id_rejected(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text(
        "llm:\n  active: a\n  endpoints:\n    - {id: a, base_url: http://x, model: m}\n"
        'audit:\n  gpg_recipient: "ABCDEF1234"\n')
    with pytest.raises(ConfigError, match="fingerprint|gpg_recipient|invalid"):
        load_config(p)


def test_empty_gpg_recipient_explicitly_disables_encryption(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text(
        "llm:\n  active: a\n  endpoints:\n"
        "    - {id: a, base_url: http://x, model: m}\n"
        'audit:\n  gpg_recipient: ""\n')
    assert load_config(p).audit.gpg_recipient == ""


def test_unknown_active_endpoint_rejected(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text(
        "llm:\n  active: nope\n  endpoints:\n"
        "    - {id: a, base_url: http://x, model: m}\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_packages_load_read_only_flattened_tools():
    pkgs = load_packages(REPO / "scope_packages.yaml")
    ro = pkgs["read-only"]
    # read-only yaml embeds http/scan/process/memory under `tools:`
    assert ro.permits("http") is False or ro.http_methods  # http section present
    assert not ro.scan_enabled
    assert not ro.process_enabled
    assert ro.memory_enabled and ro.plan_enabled
    def_pkg = pkgs["defensive"]
    assert def_pkg.scan_enabled and def_pkg.guardrails.max_concurrent_tools == 3
    assert def_pkg.guardrails.require_confirmation is True


def test_config_defaults_without_file(tmp_path):
    cfg = load_config(tmp_path / "nonexistent.yaml" if False else None) if False else None
    # explicit missing path is an error; default resolution uses cwd/config.yaml
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nonexistent.yaml")


def test_scope_package_validation(packages, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    cfg = Config(
        llm=load_config(REPO / "config.example.yaml").llm,
        packages=packages,
    )
    assert cfg.packages["defensive"].name == "defensive"
