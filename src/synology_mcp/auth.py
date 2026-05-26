# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""DSM web API authentication.

Encapsulates the v6 `SYNO.API.Auth` handshake, session caching, and token
refresh. See DESIGN.md §5.1 for the tool surface and §3 for auth state.

Key DSM quirks handled here:
  - `account=` param name (NOT `username=`)
  - `version=6` + `enable_syno_token=yes` (older versions don't issue tokens)
  - Response carries both `sid` (cookie) AND `synotoken` (X-SYNO-TOKEN header);
    BOTH must accompany subsequent calls or DSM returns 105/119.
  - 2FA via `otp_code` param; some DSM builds require `format=cookie`.
  - Sessions silently expire — callers must be able to retry-once-on-401.
  - DSM major/minor (e.g. (7, 3)) is fetched once via `SYNO.Core.System` info
    on first login and cached on the session, so the §9 compat shim can
    dispatch (`_normalize_v73_*` vs `_normalize_v72_*`) without re-querying.
"""
from __future__ import annotations

import contextlib
import logging
import re
from typing import TYPE_CHECKING

import httpx

from .errors import AuthFailed, OtpRequired, raise_for_dsm_error
from .session import DSMSession
from .transport.http import DSMHttpClient

_log = logging.getLogger(__name__)

# Matches the leading "DSM <major>.<minor>" in firmware_ver strings such as
# "DSM 7.3.2-86009 Update 3" or "DSM 7.2-64570".
_DSM_VERSION_RE = re.compile(r"DSM\s+(?P<major>\d+)\.(?P<minor>\d+)")

if TYPE_CHECKING:  # pragma: no cover
    from .config import HostConfig
    from .session import HostState, SessionCache


def _envelope(host: str, data: object, warnings: list[str] | None = None) -> dict:
    return {"ok": True, "host": host, "data": data, "warnings": warnings or []}


def _get_http_client(host_cfg: HostConfig, state: HostState) -> DSMHttpClient:
    """Return the cached DSMHttpClient for this host, creating it on first use."""
    cached = state.http_client
    if isinstance(cached, DSMHttpClient):
        return cached
    wrapper = DSMHttpClient(host_cfg)
    state.http_client = wrapper
    return wrapper


async def perform_login(
    host_cfg: HostConfig,
    state: HostState,
    *,
    password: str,
    otp_code: str | None = None,
) -> DSMSession:
    """Run the SYNO.API.Auth v6 login handshake against `host_cfg`.

    Stores the resulting DSMSession into `state.session` and returns it.
    Caller is responsible for providing the password (it's read from config
    in the tool wrappers; never passed in via MCP tool input directly).
    """
    http = _get_http_client(host_cfg, state)
    params: dict[str, object] = {
        "account": host_cfg.account,
        "passwd": password,
        "session": "FileStation",
        "format": "cookie",
        "enable_syno_token": "yes",
    }
    if otp_code:
        params["otp_code"] = otp_code

    try:
        body = await http.call(
            api="SYNO.API.Auth",
            method="login",
            version=6,
            params=params,
            session=None,
            raise_on_dsm_error=False,
        )
    except httpx.HTTPError as exc:  # pragma: no cover - covered via DSMTransportError
        raise AuthFailed(
            f"login HTTP failure for host={host_cfg.name}: {exc}",
            host=host_cfg.name,
        ) from exc

    if not body.get("success", False):
        err = body.get("error") or {}
        code = int(err.get("code", 0) or 0)
        if code == 403:
            raise OtpRequired(
                "DSM requires a one-time password (2FA)",
                host=host_cfg.name,
                dsm_error_code=code,
                details={"error": err},
            )
        if code in (400, 401):
            raise AuthFailed(
                "DSM rejected credentials",
                host=host_cfg.name,
                dsm_error_code=code,
                details={"error": err},
            )
        raise_for_dsm_error(code, host=host_cfg.name, details={"error": err})

    data = body.get("data") or {}
    sid = str(data.get("sid", ""))
    syno_token = str(data.get("synotoken", "") or data.get("syno_token", ""))
    if not sid:
        raise AuthFailed(
            "DSM login succeeded but no sid in response",
            host=host_cfg.name,
            details={"body": body},
        )
    if not syno_token:
        # Some older builds don't return synotoken even with enable_syno_token=yes.
        # We continue but downstream calls that hit token-required endpoints
        # will fail with 119, triggering a re-login. Mark this with a warning
        # on the caller side.
        pass

    session = DSMSession(
        sid=sid,
        syno_token=syno_token,
        user=host_cfg.account,
        cookies={"id": sid},
    )
    state.session = session
    # Populate DSM major/minor so the §9 compat shim can dispatch without
    # re-querying. Best-effort: a failure here just leaves the field as None
    # and the shim falls back to its default normaliser.
    session.dsm_major_minor = await _fetch_dsm_major_minor(http, session, host_cfg.name)
    return session


async def _fetch_dsm_major_minor(
    http: DSMHttpClient,
    session: DSMSession,
    host_name: str,
) -> tuple[int, int] | None:
    """Query DSM for its version and parse out (major, minor).

    Uses `SYNO.Core.System` info — same endpoint as `raid_hardware_info` — and
    reads the leading "DSM <major>.<minor>" out of the `firmware_ver` string.
    Failures (transport error, unexpected payload shape, unparseable version)
    return None so the caller can continue without the field populated.

    This costs one extra HTTP roundtrip on first login per host. Subsequent
    calls reuse the cached value on the session.
    """
    try:
        body = await http.call(
            api="SYNO.Core.System",
            method="info",
            version=1,
            session=session,
            raise_on_dsm_error=False,
        )
    except Exception as exc:  # pragma: no cover - logged + best-effort
        _log.warning(
            "could not fetch DSM version for host=%s: %s", host_name, exc,
        )
        return None
    if not body.get("success", False):
        return None
    data = body.get("data") or {}
    fw = data.get("firmware_ver") or data.get("version") or ""
    if not isinstance(fw, str):
        return None
    m = _DSM_VERSION_RE.search(fw)
    if not m:
        return None
    try:
        return (int(m.group("major")), int(m.group("minor")))
    except (TypeError, ValueError):  # pragma: no cover - regex guarantees ints
        return None


async def ensure_session(
    host_cfg: HostConfig,
    cache: SessionCache,
    *,
    password: str,
    otp_code: str | None = None,
) -> DSMSession:
    """Return a cached DSMSession or run login to mint a fresh one."""
    state = cache.get(host_cfg.name)
    if state.session is not None:
        return state.session
    return await perform_login(host_cfg, state, password=password, otp_code=otp_code)


async def perform_logout(host_cfg: HostConfig, state: HostState) -> bool:
    """Best-effort DSM logout. Returns True if a session was active, False otherwise."""
    if state.session is None:
        return False
    http = _get_http_client(host_cfg, state)
    with contextlib.suppress(Exception):  # pragma: no cover - best-effort logout
        await http.call(
            api="SYNO.API.Auth",
            method="logout",
            version=6,
            params={"session": "FileStation"},
            session=state.session,
            raise_on_dsm_error=False,
        )
    state.session = None
    return True


# --- MCP-level tool entrypoints ---------------------------------------------
# These are async functions designed to be wired into the MCP server.
# They take an `app_context` (provided by the server module) which carries
# the SessionCache + config.


async def auth_login(host: str, *, app_context) -> dict:
    """MCP tool: force a fresh login, returning a sanitized session descriptor."""
    host_cfg = app_context.config.get_host(host)
    if not host_cfg.password:
        from .errors import ConfigError

        raise ConfigError(
            f"no password configured for host {host!r} (set in config or env)",
            host=host,
        )
    cache = app_context.cache
    state = cache.get(host)
    # Force-invalidate any cached session before logging in.
    state.session = None
    session = await perform_login(
        host_cfg,
        state,
        password=host_cfg.password,
        otp_code=host_cfg.otp_code,
    )
    return _envelope(host, session.descriptor())


async def auth_logout(host: str, *, app_context) -> dict:
    """MCP tool: invalidate the cached session for `host` (DSM logout best-effort)."""
    host_cfg = app_context.config.get_host(host)
    cache = app_context.cache
    state = cache.get(host)
    prior_age = state.session.age_seconds() if state.session else None
    had_session = await perform_logout(host_cfg, state)
    return _envelope(
        host,
        {
            "had_session": had_session,
            "prior_age_seconds": round(prior_age, 1) if prior_age is not None else None,
        },
    )


async def auth_whoami(host: str, *, app_context) -> dict:
    """MCP tool: return the cached session descriptor, logging in on cache miss."""
    host_cfg = app_context.config.get_host(host)
    cache = app_context.cache
    state = cache.get(host)
    if state.session is not None:
        return _envelope(host, state.session.descriptor())
    if not host_cfg.password:
        from .errors import ConfigError

        raise ConfigError(
            f"no password configured for host {host!r} (set in config or env)",
            host=host,
        )
    session = await perform_login(
        host_cfg,
        state,
        password=host_cfg.password,
        otp_code=host_cfg.otp_code,
    )
    return _envelope(host, session.descriptor())
