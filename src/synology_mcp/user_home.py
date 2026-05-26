# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""User Home service enable / disable.

Wraps `SYNO.Core.User.Home` with the DSM 7.3 workaround for the
`/etc/synoinfo.conf userHomeEnable=yes` quirk.

Key DSM quirks handled here:
  - On fresh DSM 7.3, the web API silently no-ops `enable_user_home=true`
    if `userHomeEnable` is missing from synoinfo.conf. The `set` call
    returns success but `get` reports `enable=false`. Workaround sequence
    (requires SSH + sudo on the DSM host):
        sudo synosetkeyvalue /etc/synoinfo.conf userHomeEnable yes
        sudo rm -f /var/services/homes
        sudo ln -s /volume1/homes /var/services/homes
        sudo synouserhome --prepare-folder <user>
    See `feedback_dsm_user_home_enable.md`.
"""
from __future__ import annotations


async def is_enabled(host: str) -> dict:  # noqa: ARG001
    """TODO: query current state; do NOT trust web API alone.

    Cross-checks `/etc/synoinfo.conf userHomeEnable` value AND
    that `/var/services/homes` is a non-dangling symlink to /volume*/homes.
    """
    raise NotImplementedError


async def enable(host: str, user: str | None = None) -> dict:  # noqa: ARG001
    """TODO: apply the synoinfo.conf workaround + retarget + prepare-folder.

    Requires SSH with sudo. Atomically reports each step; rolls back symlink
    on failure. See DESIGN.md §5.3.
    """
    raise NotImplementedError


async def disable(host: str) -> dict:  # noqa: ARG001
    """TODO: turn off User Home via web API; does NOT remove `/volume*/homes/*`."""
    raise NotImplementedError
