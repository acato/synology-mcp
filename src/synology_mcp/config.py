# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Configuration loader for synology-mcp.

Resolves host connection settings from (in priority order):

  1. Environment variables (`SYNOLOGY_MCP_<HOST>_<FIELD>`)
  2. TOML config file (default `~/.config/synology-mcp/config.toml`,
     honours `$XDG_CONFIG_HOME`, overridable via `SYNOLOGY_MCP_CONFIG`)
  3. Defaults baked into this module

See DESIGN.md §6 for the schema.
"""
from __future__ import annotations

import os
import tomllib  # type: ignore[no-redef]
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError

# Aliases accepted in TOML / env for the same logical field.
_IP_ALIASES = ("ip", "host", "address")
_ACCOUNT_ALIASES = ("account", "username")


@dataclass
class HostConfig:
    """Resolved connection settings for one Synology host."""

    name: str
    ip: str
    account: str
    password: str | None = None
    otp_code: str | None = None
    port: int = 5001
    use_https: bool = True
    verify_tls: bool = True
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    ssh_username: str | None = None
    ssh_port: int = 22
    ssh_key_path: str | None = None

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.ip}:{self.port}"

    @property
    def effective_ssh_username(self) -> str:
        return self.ssh_username or self.account

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"HostConfig(name={self.name!r}, ip={self.ip!r}, "
            f"account={self.account!r}, password={'***' if self.password else None}, "
            f"port={self.port}, use_https={self.use_https}, "
            f"verify_tls={self.verify_tls}, ssh_port={self.ssh_port})"
        )


@dataclass
class _Defaults:
    """Defaults applied to all hosts unless overridden."""

    port: int = 5001
    use_https: bool = True
    verify_tls: bool = True
    ssh_port: int = 22
    connect_timeout: float = 10.0
    read_timeout: float = 30.0


@dataclass
class Config:
    """Top-level configuration: defaults + per-host table."""

    defaults: _Defaults = field(default_factory=_Defaults)
    hosts: dict[str, HostConfig] = field(default_factory=dict)

    def get_host(self, name: str) -> HostConfig:
        """Return resolved HostConfig for `name`, layering env vars over file."""
        env_overlay = _collect_env_for_host(name)
        file_host = self.hosts.get(name)
        if file_host is None and not env_overlay:
            raise ConfigError(
                f"unknown host {name!r}: not in config file and no env vars set",
                host=name,
            )
        # Start from file-host or a blank-slate dict.
        merged: dict[str, Any] = {}
        if file_host is not None:
            merged = {
                "ip": file_host.ip,
                "account": file_host.account,
                "password": file_host.password,
                "otp_code": file_host.otp_code,
                "port": file_host.port,
                "use_https": file_host.use_https,
                "verify_tls": file_host.verify_tls,
                "connect_timeout": file_host.connect_timeout,
                "read_timeout": file_host.read_timeout,
                "ssh_username": file_host.ssh_username,
                "ssh_port": file_host.ssh_port,
                "ssh_key_path": file_host.ssh_key_path,
            }
        # Env vars override file values.
        merged.update(env_overlay)
        # Fall back to defaults for anything still missing.
        merged.setdefault("port", self.defaults.port)
        merged.setdefault("use_https", self.defaults.use_https)
        merged.setdefault("verify_tls", self.defaults.verify_tls)
        merged.setdefault("connect_timeout", self.defaults.connect_timeout)
        merged.setdefault("read_timeout", self.defaults.read_timeout)
        merged.setdefault("ssh_port", self.defaults.ssh_port)
        # Final validation: required fields.
        if not merged.get("ip"):
            raise ConfigError(
                f"host {name!r} missing required field 'ip' (alias: host, address)",
                host=name,
            )
        if not merged.get("account"):
            raise ConfigError(
                f"host {name!r} missing required field 'account' (alias: username)",
                host=name,
            )
        return HostConfig(name=name, **merged)


def default_config_path() -> Path:
    """Return the default config-file path, honouring XDG_CONFIG_HOME."""
    override = os.environ.get("SYNOLOGY_MCP_CONFIG")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "synology-mcp" / "config.toml"


def load_config(path: Path | str | None = None) -> Config:
    """Load and parse the TOML config file (or return defaults if missing)."""
    if path is None:
        path = default_config_path()
    path = Path(path).expanduser()
    if not path.exists():
        # Missing config file is fine — env vars may carry everything.
        return Config()
    try:
        with path.open("rb") as f:
            raw = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"failed to read config {path}: {exc}") from exc
    return _parse_config(raw)


def _parse_config(raw: dict[str, Any]) -> Config:
    cfg = Config()
    defaults_raw = raw.get("defaults", {})
    if not isinstance(defaults_raw, dict):
        raise ConfigError("[defaults] must be a table")
    if "port" in defaults_raw:
        cfg.defaults.port = int(defaults_raw["port"])
    if "use_https" in defaults_raw:
        cfg.defaults.use_https = bool(defaults_raw["use_https"])
    if "verify_tls" in defaults_raw:
        cfg.defaults.verify_tls = bool(defaults_raw["verify_tls"])
    if "ssh_port" in defaults_raw:
        cfg.defaults.ssh_port = int(defaults_raw["ssh_port"])
    if "connect_timeout" in defaults_raw:
        cfg.defaults.connect_timeout = float(defaults_raw["connect_timeout"])
    if "read_timeout" in defaults_raw:
        cfg.defaults.read_timeout = float(defaults_raw["read_timeout"])

    hosts_raw = raw.get("hosts", {})
    if not isinstance(hosts_raw, dict):
        raise ConfigError("[hosts] must be a table")
    for name, host_raw in hosts_raw.items():
        if not isinstance(host_raw, dict):
            raise ConfigError(f"[hosts.{name}] must be a table")
        cfg.hosts[name] = _parse_host(name, host_raw, cfg.defaults)
    return cfg


def _parse_host(name: str, raw: dict[str, Any], defaults: _Defaults) -> HostConfig:
    ip = _first_alias(raw, _IP_ALIASES)
    account = _first_alias(raw, _ACCOUNT_ALIASES)
    return HostConfig(
        name=name,
        ip=ip or "",
        account=account or "",
        password=raw.get("password"),
        otp_code=raw.get("otp_code"),
        port=int(raw.get("port", defaults.port)),
        use_https=bool(raw.get("use_https", defaults.use_https)),
        verify_tls=bool(raw.get("verify_tls", defaults.verify_tls)),
        connect_timeout=float(raw.get("connect_timeout", defaults.connect_timeout)),
        read_timeout=float(raw.get("read_timeout", defaults.read_timeout)),
        ssh_username=raw.get("ssh_username"),
        ssh_port=int(raw.get("ssh_port", defaults.ssh_port)),
        ssh_key_path=raw.get("ssh_key_path"),
    )


def _first_alias(raw: dict[str, Any], aliases: tuple[str, ...]) -> str | None:
    for key in aliases:
        if key in raw:
            return str(raw[key])
    return None


# --- Env var overlay ---------------------------------------------------------


def _env_prefix(host: str) -> str:
    """Normalize a host name to its env-var prefix.

    `nas-primary` → `SYNOLOGY_MCP_NAS_PRIMARY_`
    `cs3.example.com` → `SYNOLOGY_MCP_CS3_EXAMPLE_COM_`
    """
    sanitized = "".join(c if c.isalnum() else "_" for c in host).upper()
    return f"SYNOLOGY_MCP_{sanitized}_"


_ENV_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "ip": ("IP", "HOST", "ADDRESS"),
    "account": ("ACCOUNT", "USERNAME"),
    "password": ("PASSWORD", "PASS"),
    "otp_code": ("OTP_CODE", "OTP"),
    "port": ("PORT",),
    "use_https": ("USE_HTTPS",),
    "verify_tls": ("VERIFY_TLS",),
    "connect_timeout": ("CONNECT_TIMEOUT",),
    "read_timeout": ("READ_TIMEOUT",),
    "ssh_username": ("SSH_USERNAME", "SSH_USER"),
    "ssh_port": ("SSH_PORT",),
    "ssh_key_path": ("SSH_KEY_PATH", "SSH_KEY"),
}

_BOOL_FIELDS = {"use_https", "verify_tls"}
_INT_FIELDS = {"port", "ssh_port"}
_FLOAT_FIELDS = {"connect_timeout", "read_timeout"}


def _collect_env_for_host(host: str) -> dict[str, Any]:
    """Collect env-var overrides for `host`, returning a kwargs dict."""
    prefix = _env_prefix(host)
    out: dict[str, Any] = {}
    for field_name, aliases in _ENV_FIELD_ALIASES.items():
        for alias in aliases:
            key = prefix + alias
            val = os.environ.get(key)
            if val is None or val == "":
                continue
            out[field_name] = _coerce(field_name, val)
            break
    return out


def _coerce(field_name: str, raw: str) -> Any:
    if field_name in _BOOL_FIELDS:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if field_name in _INT_FIELDS:
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigError(f"env var for {field_name!r} not an int: {raw!r}") from exc
    if field_name in _FLOAT_FIELDS:
        try:
            return float(raw)
        except ValueError as exc:
            raise ConfigError(f"env var for {field_name!r} not a number: {raw!r}") from exc
    return raw
