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
  - Sessions silently expire — caller must be able to retry-once-on-401.
"""
from __future__ import annotations


async def login(host: str) -> dict:  # noqa: ARG001
    """TODO: perform DSM login and return session descriptor.

    See DESIGN.md §5.1 for full signature + return schema.
    """
    raise NotImplementedError


async def logout(host: str) -> dict:  # noqa: ARG001
    """TODO: invalidate cached session for `host`."""
    raise NotImplementedError


async def whoami(host: str) -> dict:  # noqa: ARG001
    """TODO: return cached session state (user, sid age, token presence)."""
    raise NotImplementedError
