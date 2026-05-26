# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Shared folder tools — Phase 2 (reads) + Phase 3b (writes).

Wraps ``SYNO.Core.Share`` family endpoints. See DESIGN.md §5.5.

Phase 2 ships:
  * ``shares_list``                — name / volume / size / flags
  * ``shares_get_acl``             — local_user + local_group + system ACL
  * ``shares_get_snapshot_config`` — Btrfs snapshot listing/config

Phase 3b adds the write half:
  * ``shares_create`` — wrap ``SYNO.Core.Share`` ``create`` with a
    reserved-name pre-flight and idempotent same-config re-creates.
  * ``shares_delete`` — wrap ``SYNO.Core.Share`` ``delete`` with an
    empty-share safety rail.

DSM 7.3 schema verified on CS3 build 86009 by reading the
AdminCenter JS: ``create`` takes params ``name`` (string) + ``shareinfo``
(JSON object with ``name``, ``vol_path``, ``desc``, ``hidden``,
``enable_recycle_bin``, ``encryption``, ``enc_passwd``, ``share_quota``,
``enable_share_cow``); ``delete`` takes ``name`` as a JSON array of
share names. Both endpoints return DSM error 3343 for reserved share
names and 3309 for the max-shares limit.

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

import json
import shlex
from typing import Any

from ._helpers import call_dsm, get_ssh_client, success_envelope
from .errors import DSMSshError, InvalidParam, OtpRequired, PermissionDenied
from .transport.http import extract_warnings
from .transport.ssh import DSMSshClient

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


# ---------------------------------------------------------------------------
# shares_create (Phase 3b)
# ---------------------------------------------------------------------------


# Reserved-name denylist. Source: DSM 7.3 share-naming rules — DSM itself
# returns error 3343 when ``synoshare`` is asked to register any of these
# as user shares. We block client-side so callers get a tidy
# ``reserved_share_name`` envelope instead of an opaque error code, and
# we get to recommend a workaround in the same response.
#
# This list is the conservative subset of what DSM blocks; if DSM
# rejects a name we missed, the call will still fail server-side and
# bubble up as an InvalidParam — we just lose the nice category.
_RESERVED_SHARE_NAMES: frozenset[str] = frozenset({
    # User Home family — DSM reserves these for its own machinery.
    "home", "homes",
    # Built-in package shares.
    "music", "photo", "video", "surveillance", "download",
    # Backup / sync targets DSM owns.
    "NetBackup",
    # System-internal aliases.
    "@appstore", "@autoupdate", "@database", "@docker",
    "@home", "@maillog", "@mailscanner", "@MailScanner",
    "@spool", "@tmp",
})

# Prefix denylist. DSM auto-generates these for removable media and the
# web station: ``usbshare1``, ``usbshare2-1``, ``sdshare1``, ``esata-1``,
# ``web``, ``web_packages``, ``webdefault``. Matching the prefix keeps
# us future-proof against a 6th USB port etc.
_RESERVED_SHARE_PREFIXES: tuple[str, ...] = (
    "usbshare", "sdshare", "esata", "web",
)


def _is_reserved_share_name(name: str) -> bool:
    """Return True if `name` collides with a DSM-reserved share name."""
    lowered = name.lower()
    if name in _RESERVED_SHARE_NAMES:
        return True
    # Case-insensitive check for the canonical lowercase names; this
    # catches ``Music`` etc. without flagging legitimate names like
    # ``MyMusic``.
    if lowered in {n.lower() for n in _RESERVED_SHARE_NAMES}:
        return True
    return any(lowered.startswith(prefix) for prefix in _RESERVED_SHARE_PREFIXES)


def _find_existing_share(rows: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    """Return the row matching `name` (case-sensitive) or None."""
    for row in rows:
        if row.get("name") == name:
            return row
    return None


def _share_config_compatible(
    existing: dict[str, Any],
    volume: str,
    encrypted: bool,
    recycle_bin_enabled: bool,
) -> tuple[bool, list[str]]:
    """Return (compatible, mismatches[]) for an existing share vs requested config.

    "Compatible" means the same volume, the same encryption flag, and
    the same recycle-bin flag. Other settings (description, ACL
    options) are *not* compared — those are mutable via ``set`` and
    don't change the share's identity.

    The mismatch list is human-readable strings useful for the
    ``share_exists_with_different_config`` failure envelope.
    """
    mismatches: list[str] = []
    if existing.get("volume") != volume:
        mismatches.append(
            f"volume: existing={existing.get('volume')!r}, requested={volume!r}"
        )
    if bool(existing.get("encrypted")) != encrypted:
        mismatches.append(
            f"encryption: existing={existing.get('encrypted')}, requested={encrypted}"
        )
    if bool(existing.get("recycle_bin_enabled")) != recycle_bin_enabled:
        mismatches.append(
            "recycle_bin: "
            f"existing={existing.get('recycle_bin_enabled')}, "
            f"requested={recycle_bin_enabled}"
        )
    return (not mismatches, mismatches)


# Public function signature deliberately uses **opts for forward-compat
# with new DSM fields. The supported keys are validated below.
_CREATE_OPT_KEYS: frozenset[str] = frozenset({
    "desc", "hidden", "enable_recycle_bin", "encryption",
    "encryption_passphrase", "enable_share_cow",
})


async def shares_create(
    host: str,
    name: str,
    volume: str,
    *,
    app_context,
    desc: str = "",
    hidden: bool = False,
    enable_recycle_bin: bool = False,
    encryption: bool = False,
    encryption_passphrase: str | None = None,
    enable_share_cow: bool = True,
) -> dict:
    """Create a shared folder.

    Reserved-name pre-flight: if ``name`` matches the DSM denylist
    (``music``, ``photo``, ``video``, ``home``, ``homes``,
    ``NetBackup``, ``usbshare*``, ``sdshare*``, ``esata*``,
    ``surveillance``, ``download``, ``web*``, plus the ``@*`` system
    aliases) the call refuses with ``category="reserved_share_name"``
    and a hint that the dir can still exist as a plain path for
    rsync-style targets.

    Idempotency: list existing shares first. If a share with the same
    name exists on the SAME volume with COMPATIBLE flags (encryption,
    recycle bin), return ``ok=True, data.created=False`` with the
    ``"share already exists"`` warning. If a same-name share exists
    with a *different* config, refuse with
    ``category="share_exists_with_different_config"``.

    DSM 7.3 ``create`` params (verified on CS3 build 86009):
    ``name`` (string) + ``shareinfo`` (JSON-encoded object). The
    ``shareinfo`` payload mirrors what the AdminCenter UI sends.
    """
    if not name:
        raise InvalidParam(
            "share name must be a non-empty string", host=host,
            details={"param": "name"},
        )
    if not volume or not volume.startswith("/volume"):
        raise InvalidParam(
            "volume must be a /volumeN path (e.g. '/volume1')", host=host,
            details={"param": "volume"},
        )
    if encryption and not encryption_passphrase:
        raise InvalidParam(
            "encryption_passphrase is required when encryption=True", host=host,
            details={"param": "encryption_passphrase"},
        )

    # --- reserved-name pre-flight ----------------------------------------
    if _is_reserved_share_name(name):
        return {
            "ok": False,
            "host": host,
            "data": {
                "category": "reserved_share_name",
                "name": name,
                "next_step": (
                    "pick a different name; the dir can still exist as a "
                    "plain path for rsync targets"
                ),
            },
            "warnings": [],
        }

    # --- idempotency pre-flight ------------------------------------------
    list_envelope = await shares_list(host, app_context=app_context)
    existing_rows = list_envelope.get("data", {}).get("shares") or []
    existing = _find_existing_share(existing_rows, name)
    if existing is not None:
        compatible, mismatches = _share_config_compatible(
            existing, volume, encryption, enable_recycle_bin,
        )
        if compatible:
            return success_envelope(
                host,
                {
                    "created": False,
                    "share": existing,
                },
                warnings=["share already exists"],
            )
        return {
            "ok": False,
            "host": host,
            "data": {
                "category": "share_exists_with_different_config",
                "name": name,
                "mismatches": mismatches,
                "existing": existing,
                "next_step": (
                    "delete the existing share first or pick a different name; "
                    "this tool refuses to mutate live share configs"
                ),
            },
            "warnings": [],
        }

    # --- create call -----------------------------------------------------
    # DSM 7.3 ``shareinfo`` object: see admin_center.js getParamShareForm.
    # ``encryption`` is an int (0/1/2) in the server-side schema; the UI
    # uses bool externally and maps. We mirror: bool input → 1 (with
    # passphrase) or 0.
    shareinfo: dict[str, Any] = {
        "name": name,
        "vol_path": volume,
        "desc": desc,
        "hidden": bool(hidden),
        "enable_recycle_bin": bool(enable_recycle_bin),
        "enable_share_cow": bool(enable_share_cow),
        "encryption": 1 if encryption else 0,
    }
    if encryption and encryption_passphrase:
        # The AdminCenter UI sends ``enc_passwd`` for the create-time
        # passphrase. DSM accepts it as a top-level shareinfo key.
        shareinfo["enc_passwd"] = encryption_passphrase

    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Share", method="create", version=1,
        params={
            "name": name,
            "shareinfo": json.dumps(shareinfo),
        },
    )
    warnings = list(extract_warnings(body))

    return success_envelope(
        host,
        {
            "created": True,
            "share": {
                "name": name,
                "volume": volume,
                "encrypted": bool(encryption),
                "hidden": bool(hidden),
                "recycle_bin_enabled": bool(enable_recycle_bin),
                "share_cow_enabled": bool(enable_share_cow),
            },
        },
        warnings,
    )


# ---------------------------------------------------------------------------
# shares_delete (Phase 3b)
# ---------------------------------------------------------------------------


async def _share_directory_size_bytes(
    ssh: DSMSshClient, volume: str, name: str,
) -> int | None:
    """Return the on-disk size of ``<volume>/<name>`` in bytes, or None on probe failure.

    Uses ``du -sb`` with ``--exclude=@eaDir`` because DSM creates a
    sidecar ``@eaDir`` index on every share — non-empty by definition,
    but not user data. We treat the share as "empty" iff everything
    OUTSIDE @eaDir is zero bytes.

    Returns None when the path doesn't exist (the share definition is
    present but the dir was hand-removed earlier) — the caller decides
    whether that counts as "empty" (it does: ``rm -rf`` already happened).
    """
    path = f"{volume}/{name}"
    cmd = (
        f"sudo -n du -sb --exclude=@eaDir {shlex.quote(path)} 2>/dev/null "
        "| awk '{print $1}'"
    )
    try:
        res = await ssh.run(cmd, check=False, timeout=30.0)
    except DSMSshError:
        return None
    out = res.stdout.strip()
    if not out:
        return None
    # ``du`` returns just the numeric byte count when ``-sb`` is used.
    try:
        return int(out.splitlines()[0])
    except (TypeError, ValueError):
        return None


async def shares_delete(
    host: str, name: str, *, app_context, force: bool = False,
) -> dict:
    """Delete a shared folder.

    Safety rail: SSH-probe the share's on-disk size (``du -sb
    --exclude=@eaDir``). If the result is greater than zero we refuse
    with ``category="share_not_empty"`` unless ``force=True``. ``@eaDir``
    is excluded because DSM creates it implicitly on every share — its
    presence is not real "non-empty".

    With ``force=True`` the delete proceeds and a warning notes that
    DSM does NOT remove the underlying directory by default; the
    operator may want to follow up with ``rm -rf`` for full cleanup.

    Idempotency: a share that's already absent from ``shares_list``
    returns ``ok=True, data.deleted=False, warnings=["share not found"]``.

    DSM 7.3 ``delete`` param shape (verified on CS3 build 86009):
    ``name`` is a JSON-encoded array of share names. We send a
    single-element array.
    """
    if not name:
        raise InvalidParam(
            "share name must be a non-empty string", host=host,
            details={"param": "name"},
        )

    # --- idempotency: locate the share -----------------------------------
    list_envelope = await shares_list(host, app_context=app_context)
    existing_rows = list_envelope.get("data", {}).get("shares") or []
    existing = _find_existing_share(existing_rows, name)
    if existing is None:
        return success_envelope(
            host,
            {"deleted": False, "name": name},
            warnings=["share not found"],
        )

    # --- safety rail: empty-share probe ----------------------------------
    if not force:
        ssh = get_ssh_client(app_context, host)
        volume = existing.get("volume") or ""
        size = await _share_directory_size_bytes(ssh, volume, name)
        if size is None:
            # The path doesn't exist — treat as empty and proceed.
            pass
        elif size > 0:
            return {
                "ok": False,
                "host": host,
                "data": {
                    "category": "share_not_empty",
                    "name": name,
                    "size_bytes": size,
                    "volume": volume,
                    "next_step": "call again with force=True to delete anyway",
                },
                "warnings": [],
            }

    # --- delete call -----------------------------------------------------
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Share", method="delete", version=1,
        params={"name": json.dumps([name])},
    )
    warnings = list(extract_warnings(body))
    if force:
        warnings.append(
            "DSM does not remove the underlying directory on share delete; "
            f"follow up with `sudo rm -rf {existing.get('volume') or ''}/{name}` "
            "if you want full cleanup"
        )

    return success_envelope(
        host,
        {
            "deleted": True,
            "name": name,
            "volume": existing.get("volume"),
        },
        warnings,
    )


__all__ = [
    "shares_create",
    "shares_delete",
    "shares_get_acl",
    "shares_get_snapshot_config",
    "shares_list",
]
