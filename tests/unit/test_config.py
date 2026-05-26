# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for config.py — TOML loader + env-var overlay."""
from __future__ import annotations

import pytest

from synology_mcp.config import Config, load_config
from synology_mcp.errors import ConfigError


def _write_toml(tmp_path, contents: str):
    p = tmp_path / "config.toml"
    p.write_text(contents, encoding="utf-8")
    return p


def test_load_minimal_config(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.nas-a]
        ip = "192.0.2.10"
        account = "admin"
        password = "secret"
        """,
    )
    cfg = load_config(path)
    host = cfg.get_host("nas-a")
    assert host.ip == "192.0.2.10"
    assert host.account == "admin"
    assert host.password == "secret"
    assert host.port == 5001
    assert host.use_https is True
    assert host.ssh_port == 22


def test_alias_keys_ip_and_account(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.nas-a]
        address = "10.0.0.5"
        username = "root"
        password = "x"
        """,
    )
    cfg = load_config(path)
    host = cfg.get_host("nas-a")
    assert host.ip == "10.0.0.5"
    assert host.account == "root"


def test_defaults_table_applied(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [defaults]
        port = 5000
        ssh_port = 22334
        verify_tls = false

        [hosts.nas-a]
        ip = "192.0.2.10"
        account = "admin"
        password = "x"
        """,
    )
    cfg = load_config(path)
    host = cfg.get_host("nas-a")
    assert host.port == 5000
    assert host.ssh_port == 22334
    assert host.verify_tls is False


def test_env_var_overrides_file(tmp_path, monkeypatch) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.nas-a]
        ip = "192.0.2.10"
        account = "admin"
        password = "from_file"
        """,
    )
    monkeypatch.setenv("SYNOLOGY_MCP_NAS_A_PASSWORD", "from_env")
    monkeypatch.setenv("SYNOLOGY_MCP_NAS_A_SSH_PORT", "22334")
    cfg = load_config(path)
    host = cfg.get_host("nas-a")
    assert host.password == "from_env"
    assert host.ssh_port == 22334


def test_env_only_host_with_no_file(monkeypatch) -> None:
    monkeypatch.setenv("SYNOLOGY_MCP_CS3_IP", "10.10.3.15")
    monkeypatch.setenv("SYNOLOGY_MCP_CS3_ACCOUNT", "Aless")
    monkeypatch.setenv("SYNOLOGY_MCP_CS3_PASSWORD", "topsecret")
    monkeypatch.setenv("SYNOLOGY_MCP_CS3_SSH_PORT", "22334")
    monkeypatch.setenv("SYNOLOGY_MCP_CS3_VERIFY_TLS", "false")
    cfg = Config()
    host = cfg.get_host("cs3")
    assert host.ip == "10.10.3.15"
    assert host.account == "Aless"
    assert host.password == "topsecret"
    assert host.ssh_port == 22334
    assert host.verify_tls is False


def test_unknown_host_raises_config_error() -> None:
    cfg = Config()
    with pytest.raises(ConfigError):
        cfg.get_host("does-not-exist")


def test_missing_required_field_raises_config_error(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.nas-a]
        ip = "192.0.2.10"
        """,
    )
    cfg = load_config(path)
    with pytest.raises(ConfigError):
        cfg.get_host("nas-a")


def test_missing_file_returns_empty_config(tmp_path) -> None:
    cfg = load_config(tmp_path / "no_such_file.toml")
    assert isinstance(cfg, Config)
    assert cfg.hosts == {}


def test_hostname_with_dashes_and_dots_env(monkeypatch) -> None:
    monkeypatch.setenv("SYNOLOGY_MCP_NAS_PRIMARY_IP", "192.0.2.5")
    monkeypatch.setenv("SYNOLOGY_MCP_NAS_PRIMARY_ACCOUNT", "admin")
    monkeypatch.setenv("SYNOLOGY_MCP_NAS_PRIMARY_PASSWORD", "p")
    cfg = Config()
    host = cfg.get_host("nas-primary")
    assert host.ip == "192.0.2.5"
    assert host.account == "admin"


def test_env_password_alias(monkeypatch) -> None:
    monkeypatch.setenv("SYNOLOGY_MCP_X_IP", "192.0.2.99")
    monkeypatch.setenv("SYNOLOGY_MCP_X_ACCOUNT", "admin")
    monkeypatch.setenv("SYNOLOGY_MCP_X_PASS", "via_alias")
    cfg = Config()
    host = cfg.get_host("x")
    assert host.password == "via_alias"


def test_invalid_int_env_var_raises(monkeypatch) -> None:
    monkeypatch.setenv("SYNOLOGY_MCP_X_IP", "192.0.2.10")
    monkeypatch.setenv("SYNOLOGY_MCP_X_ACCOUNT", "admin")
    monkeypatch.setenv("SYNOLOGY_MCP_X_SSH_PORT", "not_a_number")
    cfg = Config()
    with pytest.raises(ConfigError):
        cfg.get_host("x")


def test_default_config_path_honours_xdg(monkeypatch, tmp_path) -> None:
    from synology_mcp.config import default_config_path

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("SYNOLOGY_MCP_CONFIG", raising=False)
    assert default_config_path() == tmp_path / "synology-mcp" / "config.toml"


def test_default_config_path_uses_override(monkeypatch, tmp_path) -> None:
    from synology_mcp.config import default_config_path

    custom = tmp_path / "custom.toml"
    monkeypatch.setenv("SYNOLOGY_MCP_CONFIG", str(custom))
    assert default_config_path() == custom


def test_malformed_toml_raises_config_error(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("this is = = not valid toml [[[", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)
