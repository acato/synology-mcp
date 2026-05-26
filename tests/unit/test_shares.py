# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for shares.py — respx-only (no SSH for read paths).

Phase 3b write tools (``shares_create``, ``shares_delete``) also live
in this file. ``shares_create`` is pure-respx; ``shares_delete`` is the
only share tool that touches SSH (for the empty-share size probe).
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from synology_mcp import shares
from synology_mcp.errors import InvalidParam, PermissionDenied
from synology_mcp.session import DSMSession
from synology_mcp.transport.ssh import DSMSshClient, SshResult


def _seed_session(app_ctx) -> None:
    state = app_ctx.cache.get("testhost")
    state.session = DSMSession(
        sid="FAKE_SID", syno_token="FAKE_TOKEN", user="testuser",
        cookies={"id": "FAKE_SID"},
    )


# ---------- shares_list ----------------------------------------------------


@pytest.mark.asyncio
async def test_shares_list_returns_canonical_schema(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("share", "list_normal.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await shares.shares_list("testhost", app_context=app_ctx)
    assert result["ok"] is True
    items = result["data"]["shares"]
    assert len(items) == 2

    movies = next(s for s in items if s["name"] == "Movies")
    assert movies["volume"] == "/volume1"
    assert movies["encrypted"] is False
    assert movies["hidden"] is False
    assert movies["browsable"] is True
    assert movies["acl_enabled"] is True
    # 1024.5 MB → 1024.5 * 1024 * 1024 bytes (rounded)
    assert movies["used_bytes"] == round(1024.5 * 1024 * 1024)
    # quota_value=0 → unlimited (None)
    assert movies["quota_bytes"] is None

    vault = next(s for s in items if s["name"] == "Vault")
    assert vault["encrypted"] is True
    assert vault["hidden"] is True
    assert vault["browsable"] is False
    assert vault["quota_bytes"] == 107374182400


# ---------- shares_get_acl -------------------------------------------------


@pytest.mark.asyncio
async def test_shares_get_acl_merges_user_group_system(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    user_payload = fixture_json("share_permission", "local_user_normal.json")
    group_payload = fixture_json("share_permission", "local_group_normal.json")
    system_payload = fixture_json("share_permission", "system_normal.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=user_payload),
                httpx.Response(200, json=group_payload),
                httpx.Response(200, json=system_payload),
            ]
        )
        result = await shares.shares_get_acl(
            "testhost", "Movies", app_context=app_ctx,
        )

    assert result["ok"] is True
    entries = result["data"]["entries"]
    assert result["data"]["share"] == "Movies"

    # 4 users + 2 groups + 2 system = 8.
    assert len(entries) == 8
    by_name = {(e["name"], e["type"]): e for e in entries}
    assert by_name[("admin", "local_user")]["permission"] == "ADMIN"
    assert by_name[("alice", "local_user")]["permission"] == "ADMIN"
    assert by_name[("bob", "local_user")]["permission"] == "RO"
    assert by_name[("guest", "local_user")]["permission"] == "NO"
    assert by_name[("administrators", "local_group")]["permission"] == "ADMIN"
    assert by_name[("users", "local_group")]["permission"] == "NO"
    assert by_name[("ftp", "system")]["permission"] == "NO"
    assert by_name[("MediaServer", "system")]["permission"] == "ADMIN"


@pytest.mark.asyncio
async def test_shares_get_acl_partial_permission_denied(
    app_ctx, fixture_json,
) -> None:
    """One user_group_type denied → warning, but other types still returned."""
    _seed_session(app_ctx)
    user_payload = fixture_json("share_permission", "local_user_normal.json")
    denied_payload = fixture_json("share_permission", "permission_denied.json")
    group_payload = fixture_json("share_permission", "local_group_normal.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=user_payload),
                httpx.Response(200, json=group_payload),
                httpx.Response(200, json=denied_payload),  # system denied
            ]
        )
        result = await shares.shares_get_acl(
            "testhost", "Movies", app_context=app_ctx,
        )
    assert result["ok"] is True
    # Got users + groups, lost system.
    types = {e["type"] for e in result["data"]["entries"]}
    assert "local_user" in types
    assert "local_group" in types
    assert "system" not in types
    assert any("permission denied" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_shares_get_acl_all_denied_raises(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    denied_payload = fixture_json("share_permission", "permission_denied.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=denied_payload),
                httpx.Response(200, json=denied_payload),
                httpx.Response(200, json=denied_payload),
            ]
        )
        with pytest.raises(PermissionDenied):
            await shares.shares_get_acl(
                "testhost", "Movies", app_context=app_ctx,
            )


@pytest.mark.asyncio
async def test_shares_get_acl_rejects_empty_name(app_ctx) -> None:
    _seed_session(app_ctx)
    with pytest.raises(InvalidParam):
        await shares.shares_get_acl("testhost", "", app_context=app_ctx)


# ---------- shares_get_snapshot_config -------------------------------------


@pytest.mark.asyncio
async def test_shares_get_snapshot_config_empty(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("share_snapshot", "list_empty.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await shares.shares_get_snapshot_config(
            "testhost", "Movies", app_context=app_ctx,
        )
    assert result["ok"] is True
    assert result["data"]["snapshot_count"] == 0
    assert result["data"]["schedule"] is None
    assert result["data"]["retention"] is None
    # Always carries the explanatory warning about missing config.
    assert any("schedule/retention" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_shares_get_snapshot_config_with_snapshots(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("share_snapshot", "list_with_snapshots.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await shares.shares_get_snapshot_config(
            "testhost", "Movies", app_context=app_ctx,
        )
    assert result["ok"] is True
    snaps = result["data"]["snapshots"]
    assert len(snaps) == 2
    assert snaps[0]["name"] == "GMT+00-2026.05.20-00.00.00"
    assert snaps[0]["scheduled"] is True
    assert snaps[1]["locked"] is True
    assert snaps[1]["manual"] is True


@pytest.mark.asyncio
async def test_shares_get_snapshot_config_rejects_empty_name(app_ctx) -> None:
    _seed_session(app_ctx)
    with pytest.raises(InvalidParam):
        await shares.shares_get_snapshot_config(
            "testhost", "", app_context=app_ctx,
        )


# ===========================================================================
# Phase 3b helpers
# ===========================================================================


def _ok(stdout: str = "", exit_status: int = 0, stderr: str = "") -> SshResult:
    return SshResult(
        command="x", stdout=stdout, stderr=stderr, exit_status=exit_status,
    )


def _fake_ssh(routes=None) -> DSMSshClient:
    """Substring-routed fake DSMSshClient. Records every command on .commands."""
    fake = MagicMock(spec=DSMSshClient)
    fake.commands = []

    async def _run(command, *_, **__):
        fake.commands.append(command)
        for needle, result in (routes or {}).items():
            if needle in command:
                if callable(result):
                    return result(command)
                return SshResult(
                    command=command,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    exit_status=result.exit_status,
                )
        return SshResult(
            command=command, stdout="", stderr="", exit_status=0,
        )

    fake.run = AsyncMock(side_effect=_run)
    return fake


def _empty_share_list_body() -> dict:
    """List body with no shares — for idempotency-miss path."""
    return {"success": True, "data": {"shares": [], "total": 0}}


def _share_list_body_with(rows: list[dict]) -> dict:
    return {"success": True, "data": {"shares": rows, "total": len(rows)}}


# ===========================================================================
# shares_create
# ===========================================================================


@pytest.mark.asyncio
async def test_shares_create_happy_path_plain(app_ctx) -> None:
    """Non-encrypted, non-hidden, recycle-bin-off create against an empty fleet."""
    _seed_session(app_ctx)
    create_ok = {"success": True, "data": {"name": "Movies"}}
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_empty_share_list_body()),
                httpx.Response(200, json=create_ok),
            ]
        )
        result = await shares.shares_create(
            "testhost", "Movies", "/volume1", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["created"] is True
    assert result["data"]["share"]["name"] == "Movies"
    assert result["data"]["share"]["volume"] == "/volume1"
    assert result["data"]["share"]["encrypted"] is False
    assert result["data"]["share"]["hidden"] is False
    assert route.call_count == 2

    # The second call (create) carries the shareinfo JSON blob.
    create_url = route.calls[1].request.url
    qs = dict(create_url.params)
    assert qs["api"] == "SYNO.Core.Share"
    assert qs["method"] == "create"
    assert qs["name"] == "Movies"
    shareinfo = json.loads(qs["shareinfo"])
    assert shareinfo["name"] == "Movies"
    assert shareinfo["vol_path"] == "/volume1"
    assert shareinfo["encryption"] == 0
    assert shareinfo["hidden"] is False
    assert shareinfo["enable_recycle_bin"] is False
    assert "enc_passwd" not in shareinfo


@pytest.mark.asyncio
async def test_shares_create_happy_path_hidden_with_recycle_bin(app_ctx) -> None:
    """Hidden + recycle-bin enabled goes through to shareinfo verbatim."""
    _seed_session(app_ctx)
    create_ok = {"success": True, "data": {}}
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_empty_share_list_body()),
                httpx.Response(200, json=create_ok),
            ]
        )
        result = await shares.shares_create(
            "testhost", "Vault", "/volume2",
            hidden=True, enable_recycle_bin=True, desc="audit",
            app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["created"] is True
    assert result["data"]["share"]["hidden"] is True
    assert result["data"]["share"]["recycle_bin_enabled"] is True

    qs = dict(route.calls[1].request.url.params)
    shareinfo = json.loads(qs["shareinfo"])
    assert shareinfo["hidden"] is True
    assert shareinfo["enable_recycle_bin"] is True
    assert shareinfo["desc"] == "audit"


@pytest.mark.asyncio
async def test_shares_create_happy_path_encrypted(app_ctx) -> None:
    """Encrypted share: encryption=1 and enc_passwd present in shareinfo."""
    _seed_session(app_ctx)
    create_ok = {"success": True, "data": {}}
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_empty_share_list_body()),
                httpx.Response(200, json=create_ok),
            ]
        )
        result = await shares.shares_create(
            "testhost", "Secrets", "/volume1",
            encryption=True, encryption_passphrase="hunter2hunter2",
            app_context=app_ctx,
        )

    assert result["data"]["created"] is True
    assert result["data"]["share"]["encrypted"] is True
    qs = dict(route.calls[1].request.url.params)
    shareinfo = json.loads(qs["shareinfo"])
    assert shareinfo["encryption"] == 1
    assert shareinfo["enc_passwd"] == "hunter2hunter2"


@pytest.mark.asyncio
async def test_shares_create_encryption_without_passphrase_invalid(app_ctx) -> None:
    """encryption=True + no passphrase → InvalidParam BEFORE any DSM call."""
    _seed_session(app_ctx)
    with respx.mock(
        base_url="https://192.0.2.10:5001", assert_all_called=False,
    ) as mock:
        route = mock.get("/webapi/entry.cgi").respond(200, json={"success": True})
        with pytest.raises(InvalidParam):
            await shares.shares_create(
                "testhost", "Secrets", "/volume1",
                encryption=True, app_context=app_ctx,
            )
        assert route.called is False


@pytest.mark.parametrize("reserved_name", [
    "music", "photo", "video", "home", "homes", "NetBackup",
    "surveillance", "download",
    # Prefix matches (any suffix counts).
    "usbshare1", "usbshare2-1", "sdshare", "esata-1", "web", "webdefault",
    # Case-insensitive: Music should be denied too.
    "Music", "PHOTO",
    # System aliases.
    "@appstore", "@home",
])
@pytest.mark.asyncio
async def test_shares_create_refuses_reserved_name(app_ctx, reserved_name) -> None:
    """Reserved names refuse with category=reserved_share_name, no DSM calls."""
    _seed_session(app_ctx)
    with respx.mock(
        base_url="https://192.0.2.10:5001", assert_all_called=False,
    ) as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json={"success": True, "data": {}},
        )
        result = await shares.shares_create(
            "testhost", reserved_name, "/volume1", app_context=app_ctx,
        )
    assert result["ok"] is False
    assert result["data"]["category"] == "reserved_share_name"
    assert result["data"]["name"] == reserved_name
    assert "next_step" in result["data"]
    # No DSM call fired — pre-flight rejected before the list call.
    assert route.called is False


@pytest.mark.asyncio
async def test_shares_create_idempotent_when_same_config(
    app_ctx, fixture_json,
) -> None:
    """Same name + same volume + same flags → created=False, no create call."""
    _seed_session(app_ctx)
    list_payload = fixture_json("share", "list_normal.json")
    # Movies in the fixture: /volume1, encryption=0, recycle_bin=False.
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").respond(200, json=list_payload)
        result = await shares.shares_create(
            "testhost", "Movies", "/volume1",
            enable_recycle_bin=False, encryption=False,
            app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["created"] is False
    assert "share already exists" in result["warnings"]
    # ONLY the list call fired, not a second create call.
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_shares_create_refuses_when_same_name_different_volume(
    app_ctx, fixture_json,
) -> None:
    """Same name on different volume → share_exists_with_different_config refusal."""
    _seed_session(app_ctx)
    list_payload = fixture_json("share", "list_normal.json")
    # Movies exists on /volume1; caller asks for /volume2.
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=list_payload)
        result = await shares.shares_create(
            "testhost", "Movies", "/volume2", app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "share_exists_with_different_config"
    assert any("volume" in m for m in result["data"]["mismatches"])


@pytest.mark.asyncio
async def test_shares_create_refuses_when_encryption_mismatch(
    app_ctx, fixture_json,
) -> None:
    """Existing unencrypted Movies + caller asks encrypted → mismatch refusal."""
    _seed_session(app_ctx)
    list_payload = fixture_json("share", "list_normal.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=list_payload)
        result = await shares.shares_create(
            "testhost", "Movies", "/volume1",
            encryption=True, encryption_passphrase="hunter2hunter2",
            app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "share_exists_with_different_config"
    assert any("encryption" in m for m in result["data"]["mismatches"])


@pytest.mark.asyncio
async def test_shares_create_rejects_empty_name(app_ctx) -> None:
    _seed_session(app_ctx)
    with pytest.raises(InvalidParam):
        await shares.shares_create(
            "testhost", "", "/volume1", app_context=app_ctx,
        )


@pytest.mark.asyncio
async def test_shares_create_rejects_bad_volume_path(app_ctx) -> None:
    """Volume path that doesn't start with /volume → InvalidParam."""
    _seed_session(app_ctx)
    for bad in ["", "volume1", "/etc", "/home", "vol1"]:
        with pytest.raises(InvalidParam):
            await shares.shares_create(
                "testhost", "Movies", bad, app_context=app_ctx,
            )
