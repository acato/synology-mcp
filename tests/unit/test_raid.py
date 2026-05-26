# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for raid.py — respx for web API, mocked SSH for /proc/mdstat."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from synology_mcp import raid
from synology_mcp.errors import PermissionDenied, UnsupportedDSMVersion
from synology_mcp.session import DSMSession
from synology_mcp.transport.ssh import DSMSshClient, SshResult


def _seed_session(app_ctx) -> None:
    """Pre-populate the cache so DSM calls skip the login round-trip."""
    state = app_ctx.cache.get("testhost")
    state.session = DSMSession(
        sid="FAKE_SID", syno_token="FAKE_TOKEN", user="testuser",
        cookies={"id": "FAKE_SID"},
    )


# ---------- mdstat parser ---------------------------------------------------


def test_parse_mdstat_clean(fixture_text) -> None:
    text = fixture_text("proc_mdstat", "clean.txt")
    devices = raid.parse_mdstat(text)
    # md2 (raid6, 8 disks), md1 (raid1), md0 (raid1).
    assert len(devices) == 3
    md2 = next(d for d in devices if d["device"] == "md2")
    assert md2["level"] == "raid6"
    assert md2["state"] == "clean"
    assert md2["resync_pct"] is None
    assert len(md2["members"]) == 8
    assert md2["members"][0]["disk"] == "sdh3"
    assert md2["ud_status"] == "UUUUUUUU"


def test_parse_mdstat_resyncing(fixture_text) -> None:
    text = fixture_text("proc_mdstat", "resyncing.txt")
    devices = raid.parse_mdstat(text)
    md2 = next(d for d in devices if d["device"] == "md2")
    assert md2["state"] == "resyncing"
    assert md2["resync_pct"] == pytest.approx(47.3)
    assert md2["resync_speed_kbps"] == 95432
    # finish=2156.4min -> ~ 2156.4 * 60 sec
    assert md2["resync_eta_seconds"] == pytest.approx(int(2156.4 * 60))
    assert md2["action"] == "resync"


def test_parse_mdstat_degraded(fixture_text) -> None:
    text = fixture_text("proc_mdstat", "degraded.txt")
    devices = raid.parse_mdstat(text)
    md2 = next(d for d in devices if d["device"] == "md2")
    assert md2["state"] == "degraded"
    assert md2["ud_status"] == "UUUU_UUU"
    # Faulty member sde3 has flag 'F'.
    sde3 = next(m for m in md2["members"] if m["disk"] == "sde3")
    assert sde3["flag"] == "F"


# ---------- volumes ---------------------------------------------------------


@pytest.mark.asyncio
async def test_raid_list_volumes_success(app_ctx, fixture_json) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("storage", "load_info_normal.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await raid.raid_list_volumes("testhost", app_context=app_ctx)
    assert result["ok"] is True
    volumes = result["data"]["volumes"]
    assert len(volumes) == 2
    vol1 = volumes[0]
    assert vol1["name"] == "/volume1"
    assert vol1["fs"] == "btrfs"
    assert vol1["size_total_bytes"] == 57540851269632
    assert vol1["size_used_bytes"] == 25711839268864
    assert vol1["size_free_bytes"] == 57540851269632 - 25711839268864
    # device_type ("multiple") on the volume is overridden by the pool's value.
    assert vol1["raid_level"] == "shr_with_2_disk_protect"
    assert vol1["encrypted"] is False
    vol2 = volumes[1]
    assert vol2["raid_level"] == "raid_1"
    assert vol2["encrypted"] is True
    assert vol2["fs"] == "ext4"


@pytest.mark.asyncio
async def test_raid_list_volumes_permission_denied(app_ctx, fixture_json) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("storage", "load_info_permission_denied.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        with pytest.raises(PermissionDenied) as exc_info:
            await raid.raid_list_volumes("testhost", app_context=app_ctx)
    assert exc_info.value.dsm_error_code == 105


# ---------- disks -----------------------------------------------------------


@pytest.mark.asyncio
async def test_raid_list_disks_success(app_ctx, fixture_json) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("storage", "load_info_normal.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await raid.raid_list_disks("testhost", app_context=app_ctx)
    disks = result["data"]["disks"]
    assert len(disks) == 2
    assert disks[0]["slot"] == "sata1"
    assert disks[0]["model"] == "HUH721010ALE600"
    assert disks[0]["smart_state"] == "healthy"
    assert disks[0]["temperature_c"] == 33
    assert disks[0]["role"] == "internal"
    assert disks[1]["smart_state"] == "warning"


@pytest.mark.asyncio
async def test_raid_list_disks_unsupported_method(app_ctx, fixture_json) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("storage", "load_info_unsupported.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        with pytest.raises(UnsupportedDSMVersion):
            await raid.raid_list_disks("testhost", app_context=app_ctx)


# ---------- hardware info ---------------------------------------------------


@pytest.mark.asyncio
async def test_raid_hardware_info_success(app_ctx, fixture_json) -> None:
    _seed_session(app_ctx)
    sys_payload = fixture_json("system_info", "info_ds1825plus.json")
    nic_payload = fixture_json("network_interface", "list_normal.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        # First call -> system info, second call -> network interface list.
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=sys_payload),
                httpx.Response(200, json=nic_payload),
            ]
        )
        result = await raid.raid_hardware_info("testhost", app_context=app_ctx)
    data = result["data"]
    assert data["model"] == "DS1825+"
    assert data["dsm_version"] == "DSM 7.3.2-86009 Update 3"
    assert data["dsm_build"] == "86009"
    assert data["cpu_model"] == "AMD Ryzen V1500B"
    assert data["cpu_cores"] == 4
    # ram_size=8192 MB -> 8 GiB in bytes
    assert data["ram_total_bytes"] == 8192 * 1024 * 1024
    # NIC table pulled from the network endpoint (top-level list shape).
    assert len(data["nics"]) >= 3
    eth0 = next(n for n in data["nics"] if n["name"] == "eth0")
    assert eth0["status"] == "connected"


# ---------- raid_state (mdstat over SSH) ------------------------------------


@pytest.mark.asyncio
async def test_raid_state_uses_ssh_and_parser(app_ctx, fixture_text) -> None:
    _seed_session(app_ctx)
    text = fixture_text("proc_mdstat", "resyncing.txt")
    fake_ssh = MagicMock(spec=DSMSshClient)
    fake_ssh.run = AsyncMock(
        return_value=SshResult(
            command="cat /proc/mdstat", stdout=text, stderr="", exit_status=0,
        )
    )
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    result = await raid.raid_state("testhost", app_context=app_ctx)
    assert result["ok"] is True
    devices = result["data"]["devices"]
    md2 = next(d for d in devices if d["device"] == "md2")
    assert md2["state"] == "resyncing"
    assert md2["resync_pct"] == pytest.approx(47.3)
    fake_ssh.run.assert_awaited_once_with(
        "cat /proc/mdstat", check=True, timeout=10.0
    )


# ---------- transport-level errors ------------------------------------------


@pytest.mark.asyncio
async def test_raid_list_volumes_handles_network_timeout(app_ctx) -> None:
    _seed_session(app_ctx)
    from synology_mcp.errors import DSMTransportError

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=httpx.ConnectTimeout("simulated timeout")
        )
        with pytest.raises(DSMTransportError):
            await raid.raid_list_volumes("testhost", app_context=app_ctx)
