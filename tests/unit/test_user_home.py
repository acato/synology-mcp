# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for user_home.py — respx + mocked SSH for synoinfo/readlink."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
import respx

from synology_mcp import user_home
from synology_mcp.session import DSMSession
from synology_mcp.transport.ssh import DSMSshClient, SshResult


def _seed_session(app_ctx) -> None:
    state = app_ctx.cache.get("testhost")
    state.session = DSMSession(
        sid="FAKE_SID", syno_token="FAKE_TOKEN", user="testuser",
        cookies={"id": "FAKE_SID"},
    )


def _ssh_with_signals(synoinfo: str | None, symlink: str | None) -> DSMSshClient:
    """Build a fake SSH client that returns canned signal values.

    `synoinfo` is the value emitted by ``synogetkeyvalue ... userHomeEnable``.
    Use None to simulate a missing key (binary present, no output).

    `symlink` is the target of ``readlink /var/services/homes``. Use None
    to simulate a missing symlink.
    """
    fake = MagicMock(spec=DSMSshClient)

    async def _run(command: str, *_, **__) -> SshResult:
        if "synogetkeyvalue" in command:
            if synoinfo is None:
                return SshResult(command=command, stdout="", stderr="",
                                 exit_status=0)
            return SshResult(command=command, stdout=synoinfo, stderr="",
                             exit_status=0)
        if "readlink" in command:
            return SshResult(
                command=command, stdout=(symlink or ""), stderr="",
                exit_status=0,
            )
        if "grep -E" in command:
            # Fallback grep path. Format: userHomeEnable="yes"
            if synoinfo is None:
                return SshResult(command=command, stdout="", stderr="",
                                 exit_status=1)
            return SshResult(
                command=command,
                stdout=f'userHomeEnable="{synoinfo}"', stderr="",
                exit_status=0,
            )
        return SshResult(command=command, stdout="", stderr="", exit_status=0)

    fake.run = AsyncMock(side_effect=_run)
    return fake


@pytest.mark.asyncio
async def test_user_home_all_three_signals_agree_enabled(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("user_home", "get_enabled.json")
    app_ctx.cache.get("testhost").ssh_client = _ssh_with_signals(
        synoinfo="yes", symlink="/volume1/homes",
    )
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await user_home.user_home_is_enabled(
            "testhost", app_context=app_ctx,
        )
    assert result["ok"] is True
    assert result["data"]["enabled"] is True
    assert result["data"]["web_api_says"] is True
    assert result["data"]["synoinfo_says"] is True
    assert result["data"]["symlink_target"] == "/volume1/homes"
    assert result["warnings"] == []


@pytest.mark.asyncio
async def test_user_home_silent_no_op_pattern_surfaces_warning(
    app_ctx, fixture_json,
) -> None:
    """DSM 7.3 silent no-op: web API says enabled but synoinfo+symlink missing."""
    _seed_session(app_ctx)
    payload = fixture_json("user_home", "get_enabled.json")
    app_ctx.cache.get("testhost").ssh_client = _ssh_with_signals(
        synoinfo=None, symlink=None,
    )
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await user_home.user_home_is_enabled(
            "testhost", app_context=app_ctx,
        )
    assert result["ok"] is True
    # Strict interpretation: only when all three signals agree is User Home
    # truly enabled. Disagreement → enabled=False.
    assert result["data"]["enabled"] is False
    assert result["data"]["web_api_says"] is True
    assert result["data"]["synoinfo_says"] is False
    assert result["data"]["symlink_target"] is None
    # Warning explicitly mentions the disagreement.
    joined = " ".join(result["warnings"])
    assert "signals disagree" in joined
    assert "DSM 7.3 silent-no-op" in joined


@pytest.mark.asyncio
async def test_user_home_all_disabled(app_ctx, fixture_json) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("user_home", "get_disabled.json")
    app_ctx.cache.get("testhost").ssh_client = _ssh_with_signals(
        synoinfo=None, symlink=None,
    )
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await user_home.user_home_is_enabled(
            "testhost", app_context=app_ctx,
        )
    assert result["data"]["enabled"] is False
    assert result["data"]["web_api_says"] is False
    assert result["data"]["synoinfo_says"] is False
    assert result["data"]["symlink_target"] is None
    # All three agree on "off" — no warning needed.
    assert result["warnings"] == []


@pytest.mark.asyncio
async def test_user_home_synoinfo_no_falls_through_to_grep(app_ctx, fixture_json) -> None:
    """When synogetkeyvalue prints 'no', we don't need the grep fallback."""
    _seed_session(app_ctx)
    payload = fixture_json("user_home", "get_disabled.json")
    fake = MagicMock(spec=DSMSshClient)

    async def _run(command: str, *_, **__) -> SshResult:
        if "synogetkeyvalue" in command:
            return SshResult(command=command, stdout="no", stderr="",
                             exit_status=0)
        if "readlink" in command:
            return SshResult(command=command, stdout="", stderr="",
                             exit_status=0)
        return SshResult(command=command, stdout="", stderr="", exit_status=0)

    fake.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await user_home.user_home_is_enabled(
            "testhost", app_context=app_ctx,
        )
    assert result["data"]["synoinfo_says"] is False
    assert result["data"]["enabled"] is False
