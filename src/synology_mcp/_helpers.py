# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Shared helpers used by subsystem modules.

These would live in `tools.py` (per DESIGN.md §2 module layout) but Phase 1
doesn't need a full @tool decorator yet — the FastMCP `@mcp.tool` decorator
in `server.py` handles registration, and the subsystem modules just need a
consistent way to:

  - get a logged-in DSMSession for a host
  - get the cached DSMHttpClient / DSMSshClient for a host
  - shape the success envelope

Avoids circular imports by importing transport modules at function-body level.
"""
from __future__ import annotations

from typing import Any

from .auth import ensure_session
from .errors import ConfigError
from .transport.http import DSMHttpClient
from .transport.ssh import DSMSshClient


def success_envelope(
    host: str, data: object, warnings: list[str] | None = None
) -> dict[str, Any]:
    """Build the standard success envelope (see DESIGN.md §5)."""
    return {"ok": True, "host": host, "data": data, "warnings": warnings or []}


async def call_dsm(
    app_context,
    host: str,
    api: str,
    method: str,
    version: int,
    *,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve host, ensure session, run DSM call, return raw envelope."""
    host_cfg = app_context.config.get_host(host)
    if not host_cfg.password:
        raise ConfigError(
            f"no password configured for host {host!r}", host=host
        )
    session = await ensure_session(
        host_cfg,
        app_context.cache,
        password=host_cfg.password,
        otp_code=host_cfg.otp_code,
    )
    state = app_context.cache.get(host)
    http = state.http_client
    if not isinstance(http, DSMHttpClient):
        http = DSMHttpClient(host_cfg)
        state.http_client = http
    return await http.call(
        api=api, method=method, version=version, params=params, session=session
    )


def get_ssh_client(app_context, host: str) -> DSMSshClient:
    """Return the cached DSMSshClient for `host`, creating it lazily."""
    host_cfg = app_context.config.get_host(host)
    state = app_context.cache.get(host)
    existing = state.ssh_client
    if isinstance(existing, DSMSshClient):
        return existing
    client = DSMSshClient(host_cfg, password=host_cfg.password)
    state.ssh_client = client
    return client
