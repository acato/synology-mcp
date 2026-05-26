# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for network.py — respx for web API, mocked SSH for sysfs+ethtool."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
import respx

from synology_mcp import network
from synology_mcp.errors import InvalidParam
from synology_mcp.session import DSMSession
from synology_mcp.transport.ssh import DSMSshClient, SshResult


def _seed_session(app_ctx) -> None:
    state = app_ctx.cache.get("testhost")
    state.session = DSMSession(
        sid="FAKE_SID", syno_token="FAKE_TOKEN", user="testuser",
        cookies={"id": "FAKE_SID"},
    )


def _make_sysfs_reply(name: str, *, speed: int, operstate: str = "up",
                      mac: str = "00:00:5e:00:53:01", mtu: int = 1500,
                      duplex: str = "full", carrier: int = 1) -> str:
    """Format a fake stdout reply for the sysfs probe command."""
    return (
        f"address={mac}\n"
        f"speed={speed}\n"
        f"operstate={operstate}\n"
        f"mtu={mtu}\n"
        f"duplex={duplex}\n"
        f"carrier={carrier}\n"
    )


# ---------- network_list_interfaces ----------------------------------------


@pytest.mark.asyncio
async def test_network_list_interfaces_merges_web_and_sysfs(
    app_ctx, fixture_json
) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("network_interface", "list_normal.json")
    # 4 entries in the fixture (eth0, eth1, eth2, pppoe) -> 4 sysfs replies.
    fake_ssh = MagicMock(spec=DSMSshClient)
    sysfs_iter = iter([
        _make_sysfs_reply("eth0", speed=1000, operstate="up", mac="00:00:5e:00:53:01"),
        _make_sysfs_reply("eth1", speed=-1, operstate="down",
                          mac="00:00:5e:00:53:02", carrier=0),
        _make_sysfs_reply("eth2", speed=10000, operstate="up",
                          mac="00:00:5e:00:53:03", mtu=9000),
        _make_sysfs_reply("pppoe", speed=0, operstate="down", carrier=0),
    ])

    async def _run(command, *_, **__):
        return SshResult(
            command=command, stdout=next(sysfs_iter), stderr="", exit_status=0,
        )
    fake_ssh.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await network.network_list_interfaces("testhost", app_context=app_ctx)

    interfaces = result["data"]["interfaces"]
    assert len(interfaces) == 4
    eth0 = next(i for i in interfaces if i["name"] == "eth0")
    assert eth0["state"] == "up"
    assert eth0["speed_mbps"] == 1000
    assert eth0["mac"] == "00:00:5e:00:53:01"
    assert eth0["mtu"] == 1500
    assert "192.0.2.10" in eth0["ips"]
    eth1 = next(i for i in interfaces if i["name"] == "eth1")
    assert eth1["state"] == "down"
    # sysfs says -1 (down); web says -1 too -> None.
    assert eth1["speed_mbps"] is None
    eth2 = next(i for i in interfaces if i["name"] == "eth2")
    assert eth2["state"] == "up"
    assert eth2["speed_mbps"] == 10000
    assert eth2["mtu"] == 9000
    # Internal debug fields must NOT appear in the public envelope.
    for iface in interfaces:
        assert "_web_speed_mbps" not in iface
        assert "_sysfs_speed_mbps" not in iface
        for key in iface:
            assert not key.startswith("_"), (
                f"underscored field leaked: {key!r}"
            )


@pytest.mark.asyncio
async def test_network_list_interfaces_handles_ssh_failure_gracefully(
    app_ctx, fixture_json
) -> None:
    """If sysfs reads fail, we still return what the web API knows."""
    _seed_session(app_ctx)
    payload = fixture_json("network_interface", "list_normal.json")
    fake_ssh = MagicMock(spec=DSMSshClient)
    from synology_mcp.errors import DSMSshError

    async def _run(command, *_, **__):
        raise DSMSshError("simulated SSH failure", host="testhost", command=command)
    fake_ssh.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await network.network_list_interfaces("testhost", app_context=app_ctx)
    # We still get 4 interfaces; their speed comes from the web API.
    interfaces = result["data"]["interfaces"]
    assert len(interfaces) == 4
    eth0 = next(i for i in interfaces if i["name"] == "eth0")
    assert eth0["speed_mbps"] == 1000
    assert eth0["state"] == "up"


# ---------- network_get_interface ------------------------------------------


@pytest.mark.asyncio
async def test_network_get_interface_includes_ethtool(app_ctx, fixture_json) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("network_interface", "list_normal.json")
    fake_ssh = MagicMock(spec=DSMSshClient)
    sysfs_iter = iter([
        _make_sysfs_reply("eth0", speed=1000),
        _make_sysfs_reply("eth1", speed=-1, operstate="down", carrier=0),
        _make_sysfs_reply("eth2", speed=10000, mtu=9000),
        _make_sysfs_reply("pppoe", speed=0, operstate="down", carrier=0),
    ])
    ethtool_stdout = (
        "driver: i40e\n"
        "version: 2.8.20-k\n"
        "firmware-version: 6.01 0x80003557\n"
        "bus-info: 0000:03:00.0\n"
        "supports-statistics: yes\n"
    )

    async def _run(command, *_, **__):
        if command.startswith("ethtool"):
            return SshResult(command=command, stdout=ethtool_stdout, stderr="", exit_status=0)
        return SshResult(command=command, stdout=next(sysfs_iter), stderr="", exit_status=0)
    fake_ssh.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await network.network_get_interface("testhost", "eth2", app_context=app_ctx)
    assert result["ok"] is True
    detail = result["data"]
    assert detail["name"] == "eth2"
    assert detail["ethtool"]["driver"] == "i40e"
    assert detail["ethtool"]["firmware_version"] == "6.01 0x80003557"
    assert detail["ethtool"]["bus_info"] == "0000:03:00.0"
    # Internal debug fields must NOT appear in the public envelope.
    assert "_web_speed_mbps" not in detail
    assert "_sysfs_speed_mbps" not in detail
    for key in detail:
        assert not key.startswith("_"), f"underscored field leaked: {key!r}"


@pytest.mark.asyncio
async def test_network_get_interface_unknown_name(app_ctx, fixture_json) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("network_interface", "list_normal.json")
    fake_ssh = MagicMock(spec=DSMSshClient)
    fake_ssh.run = AsyncMock(
        return_value=SshResult(
            command="echo", stdout=_make_sysfs_reply("xxx", speed=0),
            stderr="", exit_status=0,
        )
    )
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        with pytest.raises(InvalidParam) as exc_info:
            await network.network_get_interface("testhost", "eth99", app_context=app_ctx)
    assert "eth0" in exc_info.value.details["available"]
