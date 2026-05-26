# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""User Home service introspection — READ-ONLY in Phase 2.

Phase 2 ships only ``user_home_is_enabled``. The enable/disable writes
live in Phase 3.

Why the tri-check is non-negotiable
-----------------------------------
DSM 7.3's ``SYNO.Core.User.Home`` ``get`` endpoint will happily report
``enable=true`` while the underlying machinery is half-broken:

  * ``/etc/synoinfo.conf`` is missing the ``userHomeEnable=yes`` key, so
    a future package reset will silently turn User Home off again.
  * ``/var/services/homes`` is a dangling symlink, so SSH key auth that
    relies on ``~/.ssh/authorized_keys`` will fail despite User Home
    showing as enabled in the DSM UI.

So we cross-check three signals and flag any disagreement verbatim. See
``feedback_dsm_user_home_enable.md`` for the original incident.
"""
from __future__ import annotations

from ._helpers import call_dsm, get_ssh_client, success_envelope
from .errors import DSMSshError
from .transport.http import extract_warnings
from .transport.ssh import DSMSshClient


async def user_home_is_enabled(host: str, *, app_context) -> dict:
    """Tri-check that User Home is genuinely enabled on `host`.

    Returns a payload of the form::

        {"enabled": bool,
         "web_api_says": bool,
         "synoinfo_says": bool,
         "symlink_target": str | None,
         "location": str | None}

    Plus a ``warnings`` list that surfaces any disagreement between the
    three signals — those warnings are the alert operators care about.
    """
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.User.Home", method="get", version=1,
    )
    data = body.get("data") or {}
    web_api_says = bool(data.get("enable"))
    location = data.get("location")
    if isinstance(location, str) and location:
        location_value: str | None = location
    else:
        location_value = None

    ssh = get_ssh_client(app_context, host)
    synoinfo_says = await _read_synoinfo_user_home(ssh)
    symlink_target = await _read_homes_symlink(ssh)

    warnings: list[str] = list(extract_warnings(body))

    # Disagreement detection. The strictest interpretation wins: User Home
    # is considered enabled ONLY when all three signals agree.
    signals = {
        "web_api_says": web_api_says,
        "synoinfo_says": synoinfo_says,
        "symlink_present": bool(symlink_target),
    }
    truthy = sum(1 for v in signals.values() if v)
    enabled = truthy == 3

    if 0 < truthy < 3:
        # Build a verbatim, operator-friendly disagreement description.
        warnings.append(
            "user_home signals disagree: "
            f"web_api={web_api_says!s}, "
            f"synoinfo={synoinfo_says!s}, "
            f"symlink_target={symlink_target!r}"
        )
        warnings.append(
            "this is the DSM 7.3 silent-no-op pattern — call user_home_enable "
            "to reconcile (Phase 3)"
        )

    return success_envelope(
        host,
        {
            "enabled": enabled,
            "web_api_says": web_api_says,
            "synoinfo_says": synoinfo_says,
            "symlink_target": symlink_target,
            "location": location_value,
        },
        warnings,
    )


# ---------------------------------------------------------------------------
# SSH probes
# ---------------------------------------------------------------------------


# Resolve the synoinfo binary via an absolute path because non-root users
# don't always have /usr/syno/bin in PATH.
_SYNOGETKEYVALUE = "/usr/syno/bin/synogetkeyvalue"
_SYNOINFO_PATH = "/etc/synoinfo.conf"


async def _read_synoinfo_user_home(ssh: DSMSshClient) -> bool:
    """Return True iff ``userHomeEnable=yes`` in ``/etc/synoinfo.conf``.

    Tries ``synogetkeyvalue`` first (canonical) and falls back to a raw
    grep when the binary is missing or unreadable.
    """
    # Path 1: synogetkeyvalue. Exit 0 with stdout=="yes" → True.
    try:
        res = await ssh.run(
            f"{_SYNOGETKEYVALUE} {_SYNOINFO_PATH} userHomeEnable",
            check=False, timeout=10.0,
        )
        val = res.stdout.strip().lower()
        if res.exit_status == 0 and val:
            return val == "yes"
    except DSMSshError:
        pass
    # Path 2: raw grep. Synology wraps the value in double quotes.
    try:
        res = await ssh.run(
            f"grep -E '^userHomeEnable=' {_SYNOINFO_PATH} 2>/dev/null || true",
            check=False, timeout=10.0,
        )
    except DSMSshError:
        return False
    line = res.stdout.strip()
    if not line:
        return False
    # Lines look like:  userHomeEnable="yes"
    _, _, raw_val = line.partition("=")
    cleaned = raw_val.strip().strip('"').strip("'").lower()
    return cleaned == "yes"


async def _read_homes_symlink(ssh: DSMSshClient) -> str | None:
    """Return the target of ``/var/services/homes`` or None if absent/broken.

    A successful return guarantees the symlink exists; we do NOT verify
    that the target dir is itself present and readable — that is the
    caller's call to make based on the tool output.
    """
    try:
        res = await ssh.run(
            "readlink /var/services/homes 2>/dev/null",
            check=False, timeout=10.0,
        )
    except DSMSshError:
        return None
    target = res.stdout.strip()
    return target or None


__all__ = ["user_home_is_enabled"]
