# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for shares.py — respx-only (no SSH involved)."""
from __future__ import annotations

import httpx
import pytest
import respx

from synology_mcp import shares
from synology_mcp.errors import InvalidParam, PermissionDenied
from synology_mcp.session import DSMSession


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
