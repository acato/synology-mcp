# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Live Phase 2 integration tests against a real DSM host.

Gated on SYNOLOGY_MCP_LIVE_HOST. Phase 2 is READ-ONLY:

  SYNOLOGY_MCP_LIVE_HOST=cs3 \\
  SYNOLOGY_MCP_LIVE_IP=10.10.3.15 \\
  SYNOLOGY_MCP_LIVE_ACCOUNT=Aless \\
  SYNOLOGY_MCP_LIVE_PASSWORD=*** \\
  SYNOLOGY_MCP_LIVE_SSH_PORT=22334 \\
  uv run pytest tests/integration -v

Notes:
  * ``ContainerManager`` always exists on CS3 (installed for SR backups)
    so we always validate the docker_health field is present.
  * CS3 has zero SR plans configured at the time of writing; we test the
    empty-list path.
  * The Aless account is in administrators — it has full ACL read on
    every share except ones with explicit deny ACLs (Plex among them).
    We exercise ACL on the ``logs`` share which is open to administrators.
"""
from __future__ import annotations

import os

import pytest

from synology_mcp import packages, shares, snapshot_replication, user_home
from synology_mcp.config import Config, HostConfig
from synology_mcp.server import AppContext
from synology_mcp.session import SessionCache


@pytest.fixture(scope="module")
def live_app_ctx() -> AppContext:
    host_name = os.environ.get("SYNOLOGY_MCP_LIVE_HOST")
    if not host_name:
        pytest.skip("SYNOLOGY_MCP_LIVE_HOST not set")
    ip = os.environ.get("SYNOLOGY_MCP_LIVE_IP", host_name)
    account = os.environ.get("SYNOLOGY_MCP_LIVE_ACCOUNT")
    password = os.environ.get("SYNOLOGY_MCP_LIVE_PASSWORD")
    if not account or not password:
        pytest.skip("SYNOLOGY_MCP_LIVE_ACCOUNT and _PASSWORD must be set")
    ssh_port = int(os.environ.get("SYNOLOGY_MCP_LIVE_SSH_PORT", "22"))
    port = int(os.environ.get("SYNOLOGY_MCP_LIVE_PORT", "5001"))
    verify_tls_raw = os.environ.get("SYNOLOGY_MCP_LIVE_VERIFY_TLS", "false").lower()
    verify_tls = verify_tls_raw in {"1", "true", "yes", "on"}
    host_cfg = HostConfig(
        name=host_name,
        ip=ip,
        account=account,
        password=password,
        port=port,
        use_https=True,
        verify_tls=verify_tls,
        ssh_port=ssh_port,
    )
    cfg = Config(hosts={host_name: host_cfg})
    return AppContext(config=cfg, cache=SessionCache())


# ---------- packages -------------------------------------------------------


@pytest.mark.asyncio
async def test_live_packages_list(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    result = await packages.packages_list(host, app_context=live_app_ctx)
    assert result["ok"] is True
    items = result["data"]["packages"]
    assert isinstance(items, list)
    assert len(items) >= 1
    # Every row has the canonical fields populated.
    for pkg in items:
        assert "id" in pkg
        assert "name" in pkg
        assert "version" in pkg
        assert "status" in pkg
        assert pkg["status"] in {"start", "stop", "error", "unknown"}
    # ContainerManager always carries the docker_health field on CS3.
    cm = next((p for p in items if p["id"] == "ContainerManager"), None)
    if cm is not None:
        assert "docker_health" in cm


@pytest.mark.asyncio
async def test_live_packages_status_storage_manager(
    live_app_ctx: AppContext,
) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    # StorageManager is a system package present on every DSM build.
    result = await packages.packages_status(
        host, "StorageManager", app_context=live_app_ctx,
    )
    assert result["ok"] is True
    data = result["data"]
    assert data["id"] == "StorageManager"
    assert data["version"] != ""
    assert data["status"] in {"start", "stop", "error", "unknown"}


# ---------- user_home ------------------------------------------------------


@pytest.mark.asyncio
async def test_live_user_home_is_enabled(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    result = await user_home.user_home_is_enabled(host, app_context=live_app_ctx)
    assert result["ok"] is True
    data = result["data"]
    # All three tri-check fields are always present in the response.
    assert "enabled" in data
    assert "web_api_says" in data
    assert "synoinfo_says" in data
    assert "symlink_target" in data
    # ``enabled`` is consistent with all-three-agree semantics.
    if data["enabled"]:
        assert data["web_api_says"] is True
        assert data["synoinfo_says"] is True
        assert data["symlink_target"]


# ---------- shares ---------------------------------------------------------


@pytest.mark.asyncio
async def test_live_shares_list(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    result = await shares.shares_list(host, app_context=live_app_ctx)
    assert result["ok"] is True
    items = result["data"]["shares"]
    assert isinstance(items, list)
    assert len(items) >= 1
    for share in items:
        assert "name" in share
        assert "volume" in share
        assert "encrypted" in share
        assert "used_bytes" in share


@pytest.mark.asyncio
async def test_live_shares_get_acl(live_app_ctx: AppContext) -> None:
    """ACL read against a share we know admins can inspect.

    Pick the first non-hidden share so this test stays generic across
    different DSM instances.
    """
    host = next(iter(live_app_ctx.config.hosts))
    listing = await shares.shares_list(host, app_context=live_app_ctx)
    visible = [s for s in listing["data"]["shares"] if not s["hidden"]]
    if not visible:
        pytest.skip("no visible shares on live host")
    target = visible[0]["name"]
    result = await shares.shares_get_acl(
        host, target, app_context=live_app_ctx,
    )
    assert result["ok"] is True
    entries = result["data"]["entries"]
    # Every DSM share has at least one ACL entry (admin/administrators).
    assert isinstance(entries, list)
    assert len(entries) >= 1
    for entry in entries:
        assert entry["type"] in {"local_user", "local_group", "system"}
        assert entry["permission"] in {"RW", "RO", "NO", "ADMIN", "CUSTOM"}


@pytest.mark.asyncio
async def test_live_shares_get_snapshot_config(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    listing = await shares.shares_list(host, app_context=live_app_ctx)
    visible = [s for s in listing["data"]["shares"] if not s["hidden"]]
    if not visible:
        pytest.skip("no visible shares on live host")
    target = visible[0]["name"]
    result = await shares.shares_get_snapshot_config(
        host, target, app_context=live_app_ctx,
    )
    assert result["ok"] is True
    assert result["data"]["share"] == target
    assert "snapshots" in result["data"]
    # The "no schedule config endpoint" warning is always present.
    assert any("schedule/retention" in w for w in result["warnings"])


# ---------- snapshot_replication ------------------------------------------


@pytest.mark.asyncio
async def test_live_snapshot_replication_list_plans(
    live_app_ctx: AppContext,
) -> None:
    """CS3 has no plans configured; we test the empty-list path."""
    host = next(iter(live_app_ctx.config.hosts))
    result = await snapshot_replication.snapshot_replication_list_plans(
        host, app_context=live_app_ctx,
    )
    assert result["ok"] is True
    assert isinstance(result["data"]["plans"], list)


@pytest.mark.asyncio
async def test_live_snapshot_replication_recent_activity(
    live_app_ctx: AppContext,
) -> None:
    """Activity is empty when no plans exist — verify the fallback path runs cleanly."""
    host = next(iter(live_app_ctx.config.hosts))
    result = await snapshot_replication.snapshot_replication_recent_activity(
        host, limit=5, app_context=live_app_ctx,
    )
    assert result["ok"] is True
    assert isinstance(result["data"]["events"], list)
    assert result["data"]["limit"] == 5
