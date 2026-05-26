# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Shared folder introspection — READ-ONLY in Phase 2.

Wraps ``SYNO.Core.Share`` family endpoints. See DESIGN.md §5.5.

Phase 2 ships:
  * ``shares_list``                — name / volume / size / flags
  * ``shares_get_acl``             — local_user + local_group + system ACL
  * ``shares_get_snapshot_config`` — Btrfs snapshot listing/config

Phase 3 will add ``shares_create``.

Key DSM 7.3 quirks handled here:

* ``SYNO.Core.Share`` ``list`` defaults to a thin payload (name + uuid +
  desc + vol_path); the ``additional=[...]`` query param expands it to
  include ``encryption``, ``hidden``, ``share_quota_used``, ``is_aclmode``,
  ``is_support_acl``, ``unite_permission``. We always request the wide
  shape because that's the data operators actually want.
* ``SYNO.Core.Share.Permission`` ``list`` requires a ``user_group_type``
  param (one of ``local_user`` / ``local_group`` / ``system``) and a
  ``name=<share>`` param (NOT ``share_name=...``). It returns one batch
  per type, so we make 3 calls and merge.
* ``SYNO.Core.Share.Snapshot`` ``list`` returns the *historical* list of
  Btrfs snapshots for a share, not the schedule/retention config — DSM
  7.3 does not expose a snapshot-config GET endpoint via the web API.
  We surface the snapshot list verbatim and note the absence of a config
  endpoint as a warning.
"""
from __future__ import annotations

from typing import Any

from ._helpers import call_dsm, success_envelope
from .errors import InvalidParam, OtpRequired, PermissionDenied
from .transport.http import extract_warnings

# ---------------------------------------------------------------------------
# shares_list
# ---------------------------------------------------------------------------


# The ``additional`` JSON-array param expands DSM's thin default share row
# into the structure operators actually need. Sent as a JSON-encoded array
# of column names — DSM accepts this verbatim on DSM 7.3.
_SHARE_LIST_ADDITIONAL = (
    '["encryption","share_quota","hidden","enable_share_cow",'
    '"enable_recycle_bin","is_aclmode","unite_permission","is_support_acl"]'
)


def _normalize_share_row(raw: dict[str, Any]) -> dict[str, Any]:
    """Map DSM 7.3 share row to canonical schema.

    Sizes come from DSM as numbers (potentially floats — DSM reports
    quota_used in MB-as-float). We normalize:

      * ``share_quota_used`` (MB-float) → ``used_bytes`` (int).
      * ``quota_value``     (raw byte count, 0 == unlimited) → ``quota_bytes``.
      * ``encryption`` (int — 0 == none, 1 == enabled) → ``encrypted`` (bool).
    """
    used_mb = raw.get("share_quota_used")
    used_bytes = _mb_float_to_bytes(used_mb)
    quota_raw = raw.get("quota_value")
    quota_bytes = _int_or_none(quota_raw)
    if quota_bytes == 0:
        quota_bytes = None  # 0 means unlimited
    encrypted = bool(raw.get("encryption"))
    return {
        "name": str(raw.get("name") or ""),
        "uuid": str(raw.get("uuid") or ""),
        "volume": str(raw.get("vol_path") or ""),
        "desc": str(raw.get("desc") or ""),
        "encrypted": encrypted,
        "hidden": bool(raw.get("hidden")),
        "browsable": not bool(raw.get("hidden")),
        "is_usb_share": bool(raw.get("is_usb_share")),
        "share_cow_enabled": bool(raw.get("enable_share_cow")),
        "recycle_bin_enabled": bool(raw.get("enable_recycle_bin")),
        "acl_enabled": bool(raw.get("is_aclmode")),
        "acl_supported": bool(raw.get("is_support_acl")),
        "unite_permission": bool(raw.get("unite_permission")),
        "used_bytes": used_bytes,
        "quota_bytes": quota_bytes,
    }


def _extract_share_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    data = body.get("data") or {}
    rows = data.get("shares")
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


async def shares_list(host: str, *, app_context) -> dict:
    """Return all shared folders with quota / encryption / ACL flags."""
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Share", method="list", version=1,
        params={"additional": _SHARE_LIST_ADDITIONAL},
    )
    rows = [_normalize_share_row(r) for r in _extract_share_rows(body)]
    return success_envelope(host, {"shares": rows}, extract_warnings(body))


# ---------------------------------------------------------------------------
# shares_get_acl
# ---------------------------------------------------------------------------


# DSM 7.3 needs one Permission.list call per user_group_type. There's no
# unified "list all" call exposed on this endpoint.
_PERMISSION_TYPES: tuple[str, ...] = ("local_user", "local_group", "system")


def _normalize_perm_entry(raw: dict[str, Any], user_group_type: str) -> dict[str, Any]:
    """Map a DSM permission row to the canonical ``permission`` token.

    DSM 7.3 returns four boolean flags per principal::

        is_admin   — share-admin (full control)
        is_custom  — uses a per-share ACL override
        is_writable
        is_readonly
        is_deny

    We collapse those into one of ``RW`` / ``RO`` / ``NO`` / ``ADMIN`` /
    ``CUSTOM`` and surface the raw flags for callers that need the detail.
    """
    is_deny = bool(raw.get("is_deny"))
    is_admin = bool(raw.get("is_admin"))
    is_writable = bool(raw.get("is_writable"))
    is_readonly = bool(raw.get("is_readonly"))
    is_custom = bool(raw.get("is_custom"))
    if is_deny:
        permission = "NO"
    elif is_admin:
        permission = "ADMIN"
    elif is_custom:
        permission = "CUSTOM"
    elif is_writable:
        permission = "RW"
    elif is_readonly:
        permission = "RO"
    else:
        permission = "NO"
    return {
        "name": str(raw.get("name") or ""),
        "type": user_group_type,
        "permission": permission,
        "is_admin": is_admin,
        "is_custom": is_custom,
        "is_writable": is_writable,
        "is_readonly": is_readonly,
        "is_deny": is_deny,
    }


async def shares_get_acl(host: str, name: str, *, app_context) -> dict:
    """Return decoded ACL for a share — local users + local groups + system.

    Makes three ``SYNO.Core.Share.Permission.list`` calls (one per
    user_group_type) and merges. Any individual call that returns DSM
    error 402/403 is recorded as a warning rather than failing the whole
    tool — partial views are still useful to operators.
    """
    if not name:
        raise InvalidParam(
            "share name must be a non-empty string", host=host,
            details={"param": "name"},
        )

    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    permission_denied_for_all = True

    for user_group_type in _PERMISSION_TYPES:
        try:
            body = await call_dsm(
                app_context, host,
                api="SYNO.Core.Share.Permission", method="list", version=1,
                params={
                    "name": name,
                    "user_group_type": user_group_type,
                    "offset": 0,
                    "limit": -1,
                },
            )
        except (PermissionDenied, OtpRequired) as exc:
            # DSM 403 — the calling user is not allowed to inspect this
            # share's ACL. NB: 403 is also the OTP-required code on
            # SYNO.API.Auth login, but on the share Permission endpoint
            # it means permission-denied. We treat both as denial for
            # ACL queries and surface the per-type denial as a warning
            # so partial results remain useful.
            warnings.append(
                f"permission denied listing {user_group_type} ACL for share "
                f"{name!r} (DSM {exc.dsm_error_code})"
            )
            continue
        permission_denied_for_all = False
        warnings.extend(extract_warnings(body))
        data = body.get("data") or {}
        rows = data.get("items") or []
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            entries.append(_normalize_perm_entry(row, user_group_type))

    if permission_denied_for_all:
        raise PermissionDenied(
            f"DSM denied ACL access for every user_group_type on share {name!r}",
            host=host,
            dsm_error_code=403,
            details={"share": name},
        )

    return success_envelope(
        host, {"share": name, "entries": entries}, warnings,
    )


# ---------------------------------------------------------------------------
# shares_get_snapshot_config
# ---------------------------------------------------------------------------


def _normalize_snapshot_row(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a DSM snapshot row to canonical schema.

    DSM 7.3 returns each snapshot as a dict with at least the fields
    ``name`` (e.g. ``GMT+00-2026.05.25-00.00.00``), ``time`` (epoch s),
    ``desc``, ``lock``, and either ``schedule_snapshot``/``manual``
    flags. We surface them verbatim under canonicalized keys.
    """
    return {
        "name": str(raw.get("name") or ""),
        "time_epoch": _int_or_none(raw.get("time")),
        "desc": str(raw.get("desc") or ""),
        "locked": bool(raw.get("lock")),
        "scheduled": bool(raw.get("schedule_snapshot")),
        "manual": bool(raw.get("manual")),
    }


async def shares_get_snapshot_config(host: str, name: str, *, app_context) -> dict:
    """Return Btrfs snapshot listing for a share.

    DSM 7.3 does NOT expose a snapshot-config GET endpoint (we checked
    ``SYNO.Core.Share.Snapshot.Schedule``, ``...Setting``, and
    ``...get_config`` — all return 102/103). What it DOES expose is the
    historical snapshot list via ``SYNO.Core.Share.Snapshot list``. We
    return that with a warning explaining the omission so callers know
    not to expect retention / schedule keys.
    """
    if not name:
        raise InvalidParam(
            "share name must be a non-empty string", host=host,
            details={"param": "name"},
        )
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Share.Snapshot", method="list", version=1,
        params={"name": name, "offset": 0, "limit": -1},
    )
    data = body.get("data") or {}
    raw_rows = data.get("snapshots")
    if not isinstance(raw_rows, list):
        raw_rows = []
    snapshots = [
        _normalize_snapshot_row(r) for r in raw_rows if isinstance(r, dict)
    ]
    warnings = list(extract_warnings(body))
    warnings.append(
        "DSM 7.3 web API does not expose snapshot schedule/retention "
        "config — only the historical snapshot list. Schedule details "
        "live in the Btrfs replica subsystem (see snapshot_replication_*)."
    )
    return success_envelope(
        host,
        {
            "share": name,
            "snapshots": snapshots,
            "snapshot_count": len(snapshots),
            "schedule": None,
            "retention": None,
        },
        warnings,
    )


# ---------------------------------------------------------------------------
# Tiny private utilities
# ---------------------------------------------------------------------------


def _int_or_none(val: object) -> int | None:
    if val is None or val == "":
        return None
    try:
        return int(val)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        try:
            return int(float(val))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None


def _mb_float_to_bytes(val: object) -> int | None:
    """DSM reports ``share_quota_used`` as a float in *megabytes*."""
    if val is None or val == "":
        return None
    try:
        mb = float(val)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return round(mb * 1024 * 1024)


__all__ = ["shares_get_acl", "shares_get_snapshot_config", "shares_list"]
