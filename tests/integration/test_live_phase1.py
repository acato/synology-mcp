# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Live integration tests against a real Synology DSM host.

Gated on SYNOLOGY_MCP_LIVE_HOST. Phase 1 is READ-ONLY so these are safe to
run against a production NAS:

  SYNOLOGY_MCP_LIVE_HOST=cs3 \\
  SYNOLOGY_MCP_LIVE_IP=10.10.3.15 \\
  SYNOLOGY_MCP_LIVE_ACCOUNT=Aless \\
  SYNOLOGY_MCP_LIVE_PASSWORD=*** \\
  SYNOLOGY_MCP_LIVE_SSH_PORT=22334 \\
  uv run pytest tests/integration -v

Set SYNOLOGY_MCP_LIVE_VERIFY_TLS=false if the NAS uses a self-signed cert.
"""
from __future__ import annotations

import os

import pytest

from synology_mcp import auth, network, raid
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
    verify_tls_raw = os.environ.get("SYNOLOGY_MCP_LIVE_VERIFY_TLS", "true").lower()
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


@pytest.mark.asyncio
async def test_live_auth_login(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    result = await auth.auth_login(host, app_context=live_app_ctx)
    assert result["ok"] is True
    assert result["data"]["sid_present"] is True
    # Token may or may not be present depending on DSM build.
    assert "issued_at" in result["data"]


@pytest.mark.asyncio
async def test_live_auth_whoami_after_login(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    await auth.auth_login(host, app_context=live_app_ctx)
    result = await auth.auth_whoami(host, app_context=live_app_ctx)
    assert result["ok"] is True
    assert result["data"]["user"] == live_app_ctx.config.hosts[host].account


@pytest.mark.asyncio
async def test_live_raid_list_volumes(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    result = await raid.raid_list_volumes(host, app_context=live_app_ctx)
    assert result["ok"] is True
    volumes = result["data"]["volumes"]
    assert isinstance(volumes, list)
    assert len(volumes) >= 1
    # Every volume should have the canonical fields.
    for vol in volumes:
        assert "name" in vol
        assert "fs" in vol
        assert "raid_level" in vol


@pytest.mark.asyncio
async def test_live_raid_list_disks(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    result = await raid.raid_list_disks(host, app_context=live_app_ctx)
    assert result["ok"] is True
    disks = result["data"]["disks"]
    assert isinstance(disks, list)
    assert len(disks) >= 1
    for disk in disks:
        assert "slot" in disk
        assert "smart_state" in disk


@pytest.mark.asyncio
async def test_live_raid_state(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    result = await raid.raid_state(host, app_context=live_app_ctx)
    assert result["ok"] is True
    devices = result["data"]["devices"]
    # A DSM NAS always has at least md0 (system) and md1 (swap).
    assert isinstance(devices, list)
    assert len(devices) >= 1
    md_names = {d["device"] for d in devices}
    # md0 (system root) is always present on Synology.
    assert any(name.startswith("md") for name in md_names)


@pytest.mark.asyncio
async def test_live_raid_hardware_info(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    result = await raid.raid_hardware_info(host, app_context=live_app_ctx)
    assert result["ok"] is True
    data = result["data"]
    # Real DSM always reports model + DSM version + serial.
    assert data["model"] != "unknown"
    assert data["dsm_version"] != "unknown"


@pytest.mark.asyncio
async def test_live_network_list_interfaces(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    result = await network.network_list_interfaces(host, app_context=live_app_ctx)
    assert result["ok"] is True
    interfaces = result["data"]["interfaces"]
    assert isinstance(interfaces, list)
    # Synology always reports at least eth0.
    names = {i["name"] for i in interfaces}
    assert "eth0" in names or any(n.startswith("eth") for n in names)
    # Public envelope must NOT leak internal debug fields.
    for iface in interfaces:
        assert "_web_speed_mbps" not in iface
        assert "_sysfs_speed_mbps" not in iface
        for key in iface:
            assert not key.startswith("_"), (
                f"underscored field leaked: {key!r}"
            )


@pytest.mark.asyncio
async def test_live_network_get_interface_eth0(live_app_ctx: AppContext) -> None:
    host = next(iter(live_app_ctx.config.hosts))
    # First find an actual interface name (eth0 may not always exist on bond setups).
    listing = await network.network_list_interfaces(host, app_context=live_app_ctx)
    eth_names = [i["name"] for i in listing["data"]["interfaces"] if i["name"].startswith("eth")]
    if not eth_names:
        pytest.skip("no eth* interface found on live host")
    result = await network.network_get_interface(host, eth_names[0], app_context=live_app_ctx)
    assert result["ok"] is True
    detail = result["data"]
    assert detail["name"] == eth_names[0]
    # ethtool may or may not be installed; the call returns {} if not.
    assert "ethtool" in detail
    # Public envelope must NOT leak internal debug fields.
    assert "_web_speed_mbps" not in detail
    assert "_sysfs_speed_mbps" not in detail
    for key in detail:
        assert not key.startswith("_"), f"underscored field leaked: {key!r}"
