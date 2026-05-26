# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for auth.py — respx-driven DSM login fixtures."""
from __future__ import annotations

import httpx
import pytest
import respx

from synology_mcp import auth
from synology_mcp.errors import AuthFailed, OtpRequired


@pytest.mark.asyncio
async def test_auth_login_success(app_ctx, fixture_json) -> None:
    payload = fixture_json("api_auth", "login_success.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await auth.auth_login("testhost", app_context=app_ctx)
    assert result["ok"] is True
    assert result["host"] == "testhost"
    assert result["data"]["sid_present"] is True
    assert result["data"]["token_present"] is True
    # Session is now cached.
    state = app_ctx.cache.get("testhost")
    assert state.session is not None
    assert state.session.user == "testuser"


@pytest.mark.asyncio
async def test_auth_login_bad_password(app_ctx, fixture_json) -> None:
    payload = fixture_json("api_auth", "login_bad_password.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        with pytest.raises(AuthFailed) as exc_info:
            await auth.auth_login("testhost", app_context=app_ctx)
    assert exc_info.value.dsm_error_code == 400
    # No session was cached on failure.
    state = app_ctx.cache.get("testhost")
    assert state.session is None


@pytest.mark.asyncio
async def test_auth_login_otp_required(app_ctx, fixture_json) -> None:
    payload = fixture_json("api_auth", "login_otp_required.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        with pytest.raises(OtpRequired) as exc_info:
            await auth.auth_login("testhost", app_context=app_ctx)
    assert exc_info.value.dsm_error_code == 403


@pytest.mark.asyncio
async def test_auth_whoami_logs_in_on_cache_miss(app_ctx, fixture_json) -> None:
    payload = fixture_json("api_auth", "login_success.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await auth.auth_whoami("testhost", app_context=app_ctx)
        assert route.called
        assert result["ok"] is True
        assert result["data"]["sid_present"] is True


@pytest.mark.asyncio
async def test_auth_whoami_uses_cached_session(app_ctx, fixture_json) -> None:
    # Prime cache with a successful login.
    payload = fixture_json("api_auth", "login_success.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        await auth.auth_login("testhost", app_context=app_ctx)
    # Now whoami should NOT hit the network at all.
    with respx.mock(base_url="https://192.0.2.10:5001", assert_all_called=False) as mock:
        route = mock.get("/webapi/entry.cgi").respond(200, json={"success": True})
        result = await auth.auth_whoami("testhost", app_context=app_ctx)
        assert not route.called
        assert result["data"]["user"] == "testuser"


@pytest.mark.asyncio
async def test_auth_logout_invalidates_cache(app_ctx, fixture_json) -> None:
    login_payload = fixture_json("api_auth", "login_success.json")
    logout_payload = fixture_json("api_auth", "logout_success.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=login_payload),
                httpx.Response(200, json=logout_payload),
            ]
        )
        await auth.auth_login("testhost", app_context=app_ctx)
        result = await auth.auth_logout("testhost", app_context=app_ctx)
    assert result["data"]["had_session"] is True
    state = app_ctx.cache.get("testhost")
    assert state.session is None


@pytest.mark.asyncio
async def test_auth_login_missing_password_raises_config_error(app_ctx) -> None:
    from synology_mcp.errors import ConfigError

    # Wipe the password to force a ConfigError.
    app_ctx.config.hosts["testhost"].password = None
    with pytest.raises(ConfigError):
        await auth.auth_login("testhost", app_context=app_ctx)
