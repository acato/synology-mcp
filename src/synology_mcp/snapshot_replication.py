# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Snapshot Replication introspection — READ-ONLY.

Wraps ``SYNO.DR.Plan`` ``list`` (the only DR endpoint that reliably
exists on a fresh DSM 7.3 install with no plans yet) and reads the
plan / sync_info / remote_conn / snap_replica_conf rows out of
``/var/packages/SnapshotReplication/etc/{replica,snap_replica}.db``
directly via SSH + sqlite3 for the detail views.

**Plan creation is permanently out of scope** for this MCP. See
DESIGN.md §11 — DSM's plan creator is gated by a one-shot UI
node-pairing wizard, and creating plans blind risks half-built rows
that DSM UI cannot remediate. Phase 2 ships ONLY read-only.

Live DSM 7.3 observations (cs3, no plans):
  * ``SYNO.DR.Plan list`` v1 → ``{"plans": []}``
  * ``SYNO.DR.Plan list`` v2/v3 → DSM 103 (method does not exist)
  * ``SYNO.DR.Plan list_activity`` → DSM 103
  * ``SYNO.Replica.Share list``    → DSM 103
  * ``SYNO.DR.Node list``          → DSM 103
  → those endpoints only get registered after the first plan is created
   (DSM lazy-loads the DR ``replication`` subsystem). So we treat their
   absence as expected, NOT a transport failure.

DB schema (replica.db on DSM 7.3 SR 7.4.7-1859)::

    plan (plan_id PK, solution_type, main_site, dr_site, sync_mode,
          target_id, target_type, status)
    sync_info (plan_id PK, sched_id, is_send_encrypted,
               is_sync_local_snapshots, notify_time_in_min,
               sync_window_enable, sync_window, worm_lock_enable,
               worm_lock_day, worm_lock_notify_time)
    share_replication (plan_id PK, replication_id)
    volume_replication, lun_replication, namespace_replication
        (plan_id PK, replication_id)
    remote_conn (plan_id, controller_id, cred_id, replica_addr,
                 replica_port, replica_type)
    output_conn (plan_id, controller_id, ifname)

And snap_replica.db::

    snap_replica_conf (replica_id PK, plan_status, direction, src_path,
                       dst_path, dstnodeid, token, additional)
    size_calculate    (id PK, total_size, is_process, pid, time, errcode)
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any

from ._helpers import call_dsm, get_ssh_client, success_envelope
from .errors import DSMSshError, InvalidParam, UnsupportedDSMVersion
from .transport.http import extract_warnings
from .transport.ssh import DSMSshClient

_REPLICA_DB = "/var/packages/SnapshotReplication/etc/replica.db"
_SNAP_REPLICA_DB = "/var/packages/SnapshotReplication/etc/snap_replica.db"
_SQLITE3 = "/usr/bin/sqlite3"

# DSM solution_type enum (observed). 1 = share replication, 2 = LUN,
# 3 = volume, 4 = namespace. Surfaced as a string the caller can grok.
_SOLUTION_TYPE_NAMES = {
    1: "share",
    2: "lun",
    3: "volume",
    4: "namespace",
}

# DSM sync_mode enum. 1 = scheduled, 2 = continuous.
_SYNC_MODE_NAMES = {
    1: "scheduled",
    2: "continuous",
}

# DSM target_type enum (best effort — observed values; new values will
# pass through as the integer with a ``target_type_raw`` companion).
_TARGET_TYPE_NAMES = {
    0: "primary",
    1: "secondary",
}


# ---------------------------------------------------------------------------
# Plan listing (web API + DB merge)
# ---------------------------------------------------------------------------


def _normalize_plan_row_web(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a SYNO.DR.Plan row to canonical schema.

    DSM's web API returns a much richer plan record than what the bare
    SQLite tables hold, but only AFTER a plan has been created and the
    DR resource cache has hydrated. For the empty case we never get
    here.
    """
    plan_id = str(raw.get("plan_id") or raw.get("id") or "")
    solution_type = raw.get("solution_type")
    return {
        "plan_id": plan_id,
        "name": str(raw.get("plan_name") or raw.get("name") or plan_id),
        "solution_type": _enum_name(_SOLUTION_TYPE_NAMES, solution_type),
        "solution_type_raw": _int_or_none(solution_type),
        "role": str(raw.get("role") or "unknown"),
        "source_host": _extract_host(raw, "main_site"),
        "dest_host": _extract_host(raw, "dr_site"),
        "source_share": _extract_share(raw, side="source"),
        "dest_share": _extract_share(raw, side="dest"),
        "sync_mode": _enum_name(_SYNC_MODE_NAMES, raw.get("sync_mode")),
        "sync_mode_raw": _int_or_none(raw.get("sync_mode")),
        "enabled": bool(raw.get("enabled", True)),
        "paused": bool(raw.get("paused", False)),
        "status": str(raw.get("status") or "unknown"),
        "_source": "web_api",
    }


def _normalize_plan_row_db(row: dict[str, Any], shares_lookup: dict[str, str]) -> dict[str, Any]:
    """Map a SQLite ``plan`` row to canonical schema.

    The DB is sparse — we fill what we can from ``plan`` + ``share_replication``
    and leave web-API-only fields (name, schedule, retention) as null.
    """
    plan_id = str(row.get("plan_id") or "")
    solution_type = _int_or_none(row.get("solution_type"))
    return {
        "plan_id": plan_id,
        "name": plan_id,  # DB doesn't carry a user-friendly name
        "solution_type": _enum_name(_SOLUTION_TYPE_NAMES, solution_type),
        "solution_type_raw": solution_type,
        "role": "unknown",
        "source_host": row.get("main_site") or None,
        "dest_host": row.get("dr_site") or None,
        "source_share": shares_lookup.get(plan_id),
        "dest_share": None,  # not in DB
        "sync_mode": _enum_name(_SYNC_MODE_NAMES, _int_or_none(row.get("sync_mode"))),
        "sync_mode_raw": _int_or_none(row.get("sync_mode")),
        "enabled": True,  # DB has no enabled flag — plans are always enabled
        "paused": False,
        "status": _plan_status_name(_int_or_none(row.get("status"))),
        "target_id": row.get("target_id"),
        "target_type": _enum_name(_TARGET_TYPE_NAMES, _int_or_none(row.get("target_type"))),
        "_source": "replica_db",
    }


_PLAN_STATUS_NAMES = {
    0: "idle",
    1: "syncing",
    2: "error",
    3: "paused",
}


def _plan_status_name(code: int | None) -> str:
    if code is None:
        return "unknown"
    return _PLAN_STATUS_NAMES.get(code, f"raw_{code}")


def _enum_name(table: dict[int, str], val: object) -> str:
    code = _int_or_none(val)
    if code is None:
        return "unknown"
    return table.get(code, f"raw_{code}")


def _extract_host(raw: dict[str, Any], key: str) -> str | None:
    val = raw.get(key)
    if isinstance(val, str):
        return val or None
    if isinstance(val, dict):
        # Web shape: {"hostname": "...", "ip": "..."}
        for candidate in ("hostname", "host", "name", "ip"):
            if val.get(candidate):
                return str(val[candidate])
    return None


def _extract_share(raw: dict[str, Any], *, side: str) -> str | None:
    key = "source_share" if side == "source" else "dest_share"
    val = raw.get(key)
    if isinstance(val, str) and val:
        return val
    # Some payloads nest the share under main_site/dr_site.
    container_key = "main_site" if side == "source" else "dr_site"
    container = raw.get(container_key)
    if isinstance(container, dict):
        for candidate in ("share", "share_name", "path"):
            if container.get(candidate):
                return str(container[candidate])
    return None


async def snapshot_replication_list_plans(host: str, *, app_context) -> dict:
    """List all SR plans the host knows about (source or destination role).

    Strategy:
      1. ``SYNO.DR.Plan list`` v1 — authoritative when plans exist.
      2. If web API yields zero rows, fall back to reading the SR
         ``plan`` + ``share_replication`` tables directly. The SQLite
         path is robust for fresh installs where DR's web-API
         registrations haven't been hydrated yet.

    Tested against cs3 (DSM 7.3.2, no plans configured) — both paths
    return an empty list cleanly.
    """
    body = await call_dsm(
        app_context, host,
        api="SYNO.DR.Plan", method="list", version=1,
    )
    data = body.get("data") or {}
    raw_rows = data.get("plans")
    if not isinstance(raw_rows, list):
        raw_rows = []
    warnings: list[str] = list(extract_warnings(body))
    plans = [_normalize_plan_row_web(r) for r in raw_rows if isinstance(r, dict)]

    if not plans:
        # Empty web payload — fall back to the SQLite DB. The DB exists
        # whether or not any plans have been created (SR creates it on
        # install) so we treat its absence as a packaging error and
        # warn rather than fail.
        ssh = get_ssh_client(app_context, host)
        db_plans, db_warnings = await _list_plans_from_db(ssh)
        warnings.extend(db_warnings)
        plans = db_plans
    return success_envelope(host, {"plans": plans}, warnings)


# ---------------------------------------------------------------------------
# Plan status — single-plan detail
# ---------------------------------------------------------------------------


async def snapshot_replication_plan_status(
    host: str, plan_id: str, *, app_context
) -> dict:
    """Return detailed status for one SR plan.

    Tries ``SYNO.DR.Plan get`` first; if DSM rejects it (102/103 on
    installs without DR hydrated), falls back to a direct SQLite read.
    """
    if not plan_id:
        raise InvalidParam(
            "plan_id must be a non-empty string", host=host,
            details={"param": "plan_id"},
        )
    warnings: list[str] = []
    # Try the web API first.
    try:
        body = await call_dsm(
            app_context, host,
            api="SYNO.DR.Plan", method="get", version=1,
            params={"plan_id": plan_id},
        )
        warnings.extend(extract_warnings(body))
        data = body.get("data") or {}
        if isinstance(data, dict) and data:
            detail = _normalize_plan_row_web(data)
            return success_envelope(host, detail, warnings)
    except UnsupportedDSMVersion as exc:
        warnings.append(
            "SYNO.DR.Plan.get not registered on this DSM build "
            f"(error {exc.dsm_error_code}); using replica.db fallback"
        )
    # Fallback: SQLite.
    ssh = get_ssh_client(app_context, host)
    detail, db_warnings = await _plan_status_from_db(ssh, plan_id)
    warnings.extend(db_warnings)
    if detail is None:
        from .errors import DSMError

        raise DSMError(
            f"plan_id {plan_id!r} not found on host {host!r}",
            host=host,
            details={"plan_id": plan_id},
        )
    return success_envelope(host, detail, warnings)


# ---------------------------------------------------------------------------
# Recent activity log
# ---------------------------------------------------------------------------


async def snapshot_replication_recent_activity(
    host: str, limit: int = 20, *, app_context
) -> dict:
    """Return recent SR sync events.

    Activity sources (in preference order):
      1. ``SYNO.DR.Plan list_activity`` web API (only after DR has been
         used at least once — returns 103 on a fresh install).
      2. The ``snap_replica_conf`` + ``size_calculate`` rows in
         ``snap_replica.db`` — gives a per-replica snapshot of recent
         state (NOT a true event log but the closest thing on disk).

    The ``limit`` argument is applied to the merged result.
    """
    if limit < 1 or limit > 1000:
        raise InvalidParam(
            "limit must be between 1 and 1000", host=host,
            details={"param": "limit", "value": limit},
        )

    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    # Web API attempt.
    try:
        body = await call_dsm(
            app_context, host,
            api="SYNO.DR.Plan", method="list_activity", version=1,
            params={"limit": limit, "offset": 0},
        )
        warnings.extend(extract_warnings(body))
        data = body.get("data") or {}
        api_events = data.get("activities") or data.get("events") or []
        if isinstance(api_events, list):
            for evt in api_events:
                if isinstance(evt, dict):
                    events.append(_normalize_activity_web(evt))
    except UnsupportedDSMVersion as exc:
        warnings.append(
            f"SYNO.DR.Plan.list_activity not registered (error "
            f"{exc.dsm_error_code}); using snap_replica.db fallback"
        )

    # DB fallback when the web API yielded nothing.
    if not events:
        ssh = get_ssh_client(app_context, host)
        db_events, db_warnings = await _activity_from_db(ssh, limit=limit)
        warnings.extend(db_warnings)
        events = db_events

    return success_envelope(
        host, {"events": events[:limit], "limit": limit}, warnings,
    )


def _normalize_activity_web(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": str(raw.get("plan_id") or ""),
        "event_type": str(raw.get("event_type") or raw.get("action") or "unknown"),
        "state": str(raw.get("state") or raw.get("status") or "unknown"),
        "timestamp_epoch": _int_or_none(raw.get("time") or raw.get("timestamp")),
        "message": str(raw.get("message") or raw.get("description") or ""),
        "_source": "web_api",
    }


# ---------------------------------------------------------------------------
# SQLite reads (best-effort)
# ---------------------------------------------------------------------------


# SQL is hard-coded — no caller input flows into the SQL string. Plan IDs
# referenced in WHERE clauses are bound via the sqlite3 ``.parameter set``
# syntax to defeat any injection attempt.
_LIST_PLANS_SQL = (
    "SELECT plan_id, solution_type, main_site, dr_site, sync_mode, "
    "target_id, target_type, status FROM plan ORDER BY plan_id"
)
_LIST_SHARE_REPL_SQL = (
    "SELECT plan_id, replication_id FROM share_replication"
)
_GET_PLAN_SQL = (
    "SELECT p.plan_id, p.solution_type, p.main_site, p.dr_site, "
    "p.sync_mode, p.target_id, p.target_type, p.status, "
    "s.sched_id, s.is_send_encrypted, s.is_sync_local_snapshots, "
    "s.notify_time_in_min, s.sync_window_enable, s.sync_window, "
    "s.worm_lock_enable, s.worm_lock_day, s.worm_lock_notify_time "
    "FROM plan p LEFT JOIN sync_info s USING(plan_id) "
    "WHERE p.plan_id = :pid"
)
_LIST_REPLICAS_SQL = (
    "SELECT replica_id, plan_status, direction, src_path, dst_path "
    "FROM snap_replica_conf ORDER BY replica_id"
)
_LIST_SIZE_CALC_SQL = (
    "SELECT id, total_size, is_process, pid, time, errcode "
    "FROM size_calculate ORDER BY time DESC LIMIT :lim"
)


async def _sqlite_query(
    ssh: DSMSshClient, db_path: str, sql: str, *, params: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Run a JSON-mode sqlite3 query over SSH.

    Returns ``(rows, error)``. ``rows`` is empty when ``error`` is set.

    Implementation note: passing dot-commands as positional args confuses
    sqlite3 (each whitespace-separated token becomes a separate arg). We
    feed the script via stdin using ``printf '...' | sqlite3 <db>``. On
    DSM 7.3 ``/bin/sh`` is a symlink to bash, so ``printf``'s ``\\n``
    expansion is reliable.

    We rely on sqlite3's ``json`` output mode (DSM ships sqlite3 3.40.0
    which supports it) for unambiguous parsing. Parameters are bound via
    ``.parameter set`` commands which are evaluated before the SQL.
    """
    script_lines: list[str] = [".mode json", ".headers on"]
    if params:
        for key, val in params.items():
            script_lines.append(f".parameter set :{key} {_sqlite_quote(val)}")
    # End the SQL statement with a semicolon so the sqlite3 shell knows
    # the statement is complete when it reads EOF on stdin.
    sql_stmt = sql.rstrip().rstrip(";") + ";"
    script_lines.append(sql_stmt)
    # Build a printf-safe payload. Each line is joined by literal `\n`
    # (the two-character sequence) so the remote `printf` expands them
    # into real newlines. Single-quote-wrap the whole thing so the
    # remote shell won't try to expand it.
    payload = "\\n".join(_escape_printf(line) for line in script_lines) + "\\n"
    cmd = (
        f"printf '{payload}' | {_SQLITE3} {shlex.quote(db_path)}"
    )
    try:
        res = await ssh.run(cmd, check=False, timeout=15.0)
    except DSMSshError as exc:
        return [], f"ssh error querying {db_path}: {exc}"
    if res.exit_status != 0:
        snippet = (res.stderr or res.stdout or "").strip()[:200]
        return [], f"sqlite3 exit={res.exit_status}: {snippet}"
    out = res.stdout.strip()
    if not out:
        return [], None
    try:
        parsed = json.loads(out)
    except json.JSONDecodeError as exc:
        return [], f"failed to parse sqlite3 JSON output: {exc}"
    if not isinstance(parsed, list):
        return [], "sqlite3 JSON output is not a list"
    return [r for r in parsed if isinstance(r, dict)], None


def _escape_printf(line: str) -> str:
    """Escape a string for inclusion in a single-quoted ``printf`` payload.

    Single quotes need to be `'\\''` (close, escape, reopen). Backslashes
    need to be doubled so they survive printf's own escape pass. Tabs and
    newlines must already be absent — callers do the line splitting.
    """
    return line.replace("\\", "\\\\").replace("'", "'\\''")


_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./:-]+$")


def _sqlite_quote(val: object) -> str:
    """Quote a value for the ``.parameter set`` dot-command.

    Numerics pass through unquoted; strings get single-quote wrapped with
    embedded single-quotes doubled. Unknown shapes fall through to a
    string repr.
    """
    if isinstance(val, bool):
        return "1" if val else "0"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return repr(val)
    s = str(val)
    if _SAFE_TOKEN_RE.match(s):
        return f"'{s}'"
    escaped = s.replace("'", "''")
    return f"'{escaped}'"


async def _list_plans_from_db(
    ssh: DSMSshClient,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Read all plans + their share_replication mapping from replica.db."""
    warnings: list[str] = []
    plan_rows, err = await _sqlite_query(ssh, _REPLICA_DB, _LIST_PLANS_SQL)
    if err:
        warnings.append(f"replica.db plan query: {err}")
        return [], warnings
    share_rows, err = await _sqlite_query(
        ssh, _REPLICA_DB, _LIST_SHARE_REPL_SQL,
    )
    if err:
        warnings.append(f"replica.db share_replication query: {err}")
        share_rows = []
    share_lookup: dict[str, str] = {}
    for sr in share_rows:
        plan_id = str(sr.get("plan_id") or "")
        rep_id = str(sr.get("replication_id") or "")
        if plan_id and rep_id:
            share_lookup[plan_id] = rep_id
    return (
        [_normalize_plan_row_db(r, share_lookup) for r in plan_rows],
        warnings,
    )


async def _plan_status_from_db(
    ssh: DSMSshClient, plan_id: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    warnings: list[str] = []
    rows, err = await _sqlite_query(
        ssh, _REPLICA_DB, _GET_PLAN_SQL, params={"pid": plan_id},
    )
    if err:
        warnings.append(f"replica.db plan query: {err}")
        return None, warnings
    if not rows:
        return None, warnings
    row = rows[0]
    detail = _normalize_plan_row_db(row, {})
    # Layer in sync_info fields when present.
    detail["schedule"] = {
        "sched_id": _int_or_none(row.get("sched_id")),
        "sync_window_enable": bool(row.get("sync_window_enable")),
        "sync_window": row.get("sync_window") or None,
        "notify_time_in_min": _int_or_none(row.get("notify_time_in_min")),
    }
    detail["retention"] = {
        "worm_lock_enable": bool(row.get("worm_lock_enable")),
        "worm_lock_day": _int_or_none(row.get("worm_lock_day")),
        "worm_lock_notify_time": _int_or_none(row.get("worm_lock_notify_time")),
    }
    detail["is_send_encrypted"] = bool(row.get("is_send_encrypted"))
    detail["is_sync_local_snapshots"] = bool(row.get("is_sync_local_snapshots"))
    return detail, warnings


async def _activity_from_db(
    ssh: DSMSshClient, *, limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Approximate "recent activity" from snap_replica_conf + size_calculate.

    DSM does NOT keep an event-log table in either of the two SR DBs we
    have read access to — the closest signal we get is the per-replica
    ``plan_status`` row and the time-stamped ``size_calculate`` rows. We
    surface both with their original column names so callers can correlate
    when needed.
    """
    warnings: list[str] = []
    events: list[dict[str, Any]] = []
    repl_rows, err = await _sqlite_query(
        ssh, _SNAP_REPLICA_DB, _LIST_REPLICAS_SQL,
    )
    if err:
        warnings.append(f"snap_replica.db replica query: {err}")
    else:
        for row in repl_rows:
            events.append({
                "replica_id": row.get("replica_id"),
                "event_type": "plan_status",
                "state": row.get("plan_status"),
                "direction": row.get("direction"),
                "src_path": row.get("src_path"),
                "dst_path": row.get("dst_path"),
                "timestamp_epoch": None,
                "_source": "snap_replica_conf",
            })
    size_rows, err = await _sqlite_query(
        ssh, _SNAP_REPLICA_DB, _LIST_SIZE_CALC_SQL, params={"lim": limit},
    )
    if err:
        warnings.append(f"snap_replica.db size_calculate query: {err}")
    else:
        for row in size_rows:
            events.append({
                "replica_id": row.get("id"),
                "event_type": "size_calculate",
                "state": ("running" if str(row.get("is_process") or "0") == "1"
                          else "complete"),
                "total_size": row.get("total_size"),
                "timestamp_epoch": _int_or_none(row.get("time")),
                "errcode": _int_or_none(row.get("errcode")),
                "_source": "size_calculate",
            })
    return events, warnings


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


__all__ = [
    "snapshot_replication_list_plans",
    "snapshot_replication_plan_status",
    "snapshot_replication_recent_activity",
]
