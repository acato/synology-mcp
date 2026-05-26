# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""DSM package introspection — READ-ONLY in Phase 2.

Wraps ``SYNO.Core.Package`` + per-package SSH probes. See DESIGN.md §5.2.

Key DSM 7.3 quirks handled here:

* ``SYNO.Core.Package`` ``list`` v2 returns ``{id, name, version, timestamp,
  additional.install_type}`` — NO ``status`` / ``auto_start`` fields. We
  derive ``status`` and ``auto_start`` from ``/usr/syno/bin/synopkg`` over
  SSH because the web API simply does not expose them on DSM 7.3.
* ``synopkg status <pkg>`` lies for ContainerManager (reports ``stop`` while
  dockerd is healthy). We add a ``docker_health`` boolean derived from
  ``docker info`` over SSH for ContainerManager specifically, and surface a
  warning when ``synopkg status`` says ``stop`` but docker is up.
  See ``feedback_dsm_cm_status.md``.
* ``synopkg status`` prints a single-line JSON blob and exits non-zero when
  the package is stopped — we accept any exit status and parse the JSON.
* ``synopkg is_onoff`` is the canonical on/off check (exit 0 = on,
  non-zero = off); we use it to short-circuit when ``status`` parsing fails.

Phase 3 will add ``packages_install`` / ``packages_uninstall`` — deferred.
"""
from __future__ import annotations

import asyncio
import json
import shlex
from typing import Any

from ._helpers import call_dsm, get_ssh_client, success_envelope
from .errors import DSMSshError, InvalidParam
from .transport.http import extract_warnings
from .transport.ssh import DSMSshClient

# Synopkg binary path. Standard on every DSM 7.x build.
_SYNOPKG = "/usr/syno/bin/synopkg"

# Sentinel package ID for the docker_health override.
_CONTAINER_MANAGER_ID = "ContainerManager"


# ---------------------------------------------------------------------------
# Web API normalization
# ---------------------------------------------------------------------------


def _normalize_pkg_row(raw: dict[str, Any]) -> dict[str, Any]:
    """Map DSM 7.3 ``SYNO.Core.Package.list`` row to the canonical schema.

    The web API gives us ``id``, ``name``, ``version``, and an ``additional``
    sub-object whose ``install_type`` flag distinguishes ``system`` packages
    from user-installed ones. Everything else (``status``, ``auto_start``,
    ``install_path``, ``last_started_at``) comes from SSH.
    """
    addl = raw.get("additional") or {}
    if not isinstance(addl, dict):
        addl = {}
    return {
        "id": str(raw.get("id") or raw.get("package") or ""),
        "name": str(raw.get("name") or raw.get("dname") or raw.get("id") or ""),
        "version": str(raw.get("version") or ""),
        "install_type": str(addl.get("install_type") or ""),
        # Web API does not provide these; SSH overlay fills them in.
        "status": "unknown",
        "auto_start": None,
        # Carry through the raw timestamp (ms since epoch) so callers can
        # use it as a coarse install/upgrade-time proxy if they want.
        "timestamp_ms": _int_or_none(raw.get("timestamp")),
    }


def _extract_package_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    data = body.get("data") or {}
    rows = data.get("packages")
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


# ---------------------------------------------------------------------------
# SSH-side probes
# ---------------------------------------------------------------------------


def _parse_synopkg_status_blob(stdout: str) -> dict[str, Any]:
    """Parse the JSON blob that ``synopkg status <pkg>`` prints on stdout.

    Example shape on DSM 7.3::

        {"aspect": {"active": {"status": "stop", "status_code": 263, ...}},
         "description": "Status: [263], package is stopped",
         "package": "ContainerManager",
         "status": "stop"}

    Returns ``{}`` when parsing fails (we treat that as "unknown status").
    """
    stripped = stdout.strip()
    if not stripped:
        return {}
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _status_from_synopkg(blob: dict[str, Any], is_onoff_exit: int | None) -> str:
    """Resolve the canonical status string from synopkg outputs.

    Returns one of ``start`` / ``stop`` / ``error`` / ``unknown``. The
    ``status`` field in the blob is authoritative when present; otherwise
    we fall back to ``is_onoff`` exit code.
    """
    raw = blob.get("status")
    if isinstance(raw, str) and raw:
        lower = raw.lower()
        if lower in {"start", "running", "started", "on"}:
            return "start"
        if lower in {"stop", "stopped", "off"}:
            return "stop"
        if lower in {"error", "failed", "fail"}:
            return "error"
        return lower
    if is_onoff_exit is not None:
        return "start" if is_onoff_exit == 0 else "stop"
    return "unknown"


async def _probe_synopkg_status(
    ssh: DSMSshClient, package_id: str
) -> tuple[dict[str, Any], int | None]:
    """Run ``synopkg status`` + ``synopkg is_onoff`` for one package.

    Returns ``(parsed_blob, is_onoff_exit_code)``. Either may be empty on
    SSH failure; the caller renders ``status=unknown`` in that case.
    """
    pkg_arg = shlex.quote(package_id)
    blob: dict[str, Any] = {}
    onoff_exit: int | None = None
    try:
        status_res = await ssh.run(
            f"{_SYNOPKG} status {pkg_arg}", check=False, timeout=10.0,
        )
        blob = _parse_synopkg_status_blob(status_res.stdout)
    except DSMSshError:
        pass
    try:
        onoff_res = await ssh.run(
            f"{_SYNOPKG} is_onoff {pkg_arg}", check=False, timeout=10.0,
        )
        onoff_exit = onoff_res.exit_status
    except DSMSshError:
        pass
    return blob, onoff_exit


async def _probe_container_manager_docker(ssh: DSMSshClient) -> dict[str, Any]:
    """Run ``docker info`` over SSH and return a small summary.

    The ``docker`` binary lives under the ContainerManager package target.
    The Aless user is in ``administrators`` but the docker socket is owned
    by root and not always group-readable, so the call may legitimately
    fail with "permission denied" while docker is in fact healthy. We
    capture both outcomes: ``health=true`` when the daemon answers,
    ``permission_denied=true`` when it doesn't but the binary is present
    (i.e. dockerd is running and our user just can't talk to the socket),
    and ``health=false`` otherwise.
    """
    cmd = (
        # `--format` keeps the output to a single line we can grep.
        "/var/packages/ContainerManager/target/usr/bin/docker info "
        "--format '{{.ServerVersion}}|containers={{.Containers}}|running={{.ContainersRunning}}'"
    )
    try:
        res = await ssh.run(cmd, check=False, timeout=15.0)
    except DSMSshError as exc:
        return {"health": False, "error": str(exc), "summary": None}
    stdout = (res.stdout or "").strip()
    stderr = (res.stderr or "").strip()
    perm_denied = "permission denied" in stderr.lower()
    summary: dict[str, Any] | None = None
    if stdout and "|" in stdout:
        parts = stdout.split("|", 2)
        summary = {
            "server_version": parts[0],
            "containers": _extract_int(parts[1] if len(parts) > 1 else ""),
            "containers_running": _extract_int(parts[2] if len(parts) > 2 else ""),
        }
    # Docker prints partial output on stdout even when the socket is
    # unreachable — so a non-empty stdout does NOT prove the daemon is
    # healthy. The canonical "daemon is responding" signal is a non-empty
    # server_version in the templated output.
    healthy = bool(summary and summary.get("server_version"))
    if healthy:
        return {"health": True, "summary": summary, "error": None}
    if perm_denied:
        return {
            "health": False,
            "permission_denied": True,
            "summary": summary,  # may carry partial info
            "error": stderr,
        }
    return {
        "health": False,
        "summary": summary,
        "error": stderr or "docker info returned no parseable output",
    }


# ---------------------------------------------------------------------------
# Tool entrypoints
# ---------------------------------------------------------------------------


async def packages_list(host: str, *, app_context) -> dict:
    """List installed packages with id, name, version, status, install_type.

    Web API supplies the row set; SSH ``synopkg`` calls supply per-row
    status. ContainerManager rows also carry a ``docker_health`` boolean
    (see module docstring).
    """
    body = await call_dsm(
        app_context, host, api="SYNO.Core.Package", method="list", version=2,
    )
    rows = [_normalize_pkg_row(r) for r in _extract_package_rows(body)]
    ssh = get_ssh_client(app_context, host)
    warnings: list[str] = list(extract_warnings(body))

    # Probe synopkg status for every package in parallel (bounded fan-out
    # — Synology CPUs are modest; 6 concurrent SSH execs is plenty).
    semaphore = asyncio.Semaphore(6)

    async def _decorate(row: dict[str, Any]) -> dict[str, Any]:
        async with semaphore:
            blob, onoff = await _probe_synopkg_status(ssh, row["id"])
        row["status"] = _status_from_synopkg(blob, onoff)
        # synopkg status_code is sometimes useful for downstream debugging.
        aspect = blob.get("aspect") if isinstance(blob, dict) else None
        if isinstance(aspect, dict):
            active = aspect.get("active")
            if isinstance(active, dict):
                row["status_code"] = _int_or_none(active.get("status_code"))
        if row["id"] == _CONTAINER_MANAGER_ID:
            docker = await _probe_container_manager_docker(ssh)
            row["docker_health"] = bool(docker.get("health"))
            row["docker_info_summary"] = docker.get("summary")
            if row["status"] == "stop" and docker.get("health"):
                warnings.append(
                    "ContainerManager: synopkg reports stop but docker daemon "
                    "is healthy — docker_health=True is authoritative"
                )
            elif row["status"] == "stop" and docker.get("permission_denied"):
                warnings.append(
                    "ContainerManager: synopkg reports stop and docker socket "
                    "is permission-denied for this user — daemon state cannot "
                    "be verified from this account; check via root SSH"
                )
        return row

    decorated = await asyncio.gather(*(_decorate(r) for r in rows))
    return success_envelope(host, {"packages": decorated}, warnings)


async def packages_status(host: str, package_id: str, *, app_context) -> dict:
    """Return detailed status for a single package.

    Wraps ``SYNO.Core.Package.get`` (v1 — v2 returns 103 on DSM 7.3) plus
    SSH ``synopkg`` calls for status / install path / last-started time.
    """
    if not package_id:
        raise InvalidParam(
            "package_id must be a non-empty string", host=host,
            details={"param": "package_id"},
        )
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Package", method="get", version=1,
        params={"id": package_id},
    )
    data = body.get("data") or {}
    row = _normalize_pkg_row(data)
    ssh = get_ssh_client(app_context, host)
    blob, onoff = await _probe_synopkg_status(ssh, package_id)
    row["status"] = _status_from_synopkg(blob, onoff)
    aspect = blob.get("aspect") if isinstance(blob, dict) else None
    if isinstance(aspect, dict):
        active = aspect.get("active")
        if isinstance(active, dict):
            row["status_code"] = _int_or_none(active.get("status_code"))
            row["status_description"] = (
                str(active.get("status_description") or "") or None
            )
    # install_path and last_started_at over SSH. Best-effort — failures
    # leave the field null.
    install_path = await _probe_install_path(ssh, package_id)
    if install_path:
        row["install_path"] = install_path
    last_started = await _probe_last_started_at(ssh, package_id)
    if last_started:
        row["last_started_at"] = last_started
    warnings: list[str] = list(extract_warnings(body))
    if package_id == _CONTAINER_MANAGER_ID:
        docker = await _probe_container_manager_docker(ssh)
        row["docker_health"] = bool(docker.get("health"))
        row["docker_info_summary"] = docker.get("summary")
        if row["status"] == "stop" and docker.get("health"):
            warnings.append(
                "ContainerManager: synopkg reports stop but docker daemon is "
                "healthy — docker_health=True is authoritative"
            )
        elif row["status"] == "stop" and docker.get("permission_denied"):
            warnings.append(
                "ContainerManager: synopkg reports stop and docker socket is "
                "permission-denied for this user — daemon state cannot be "
                "verified from this account; check via root SSH"
            )
    return success_envelope(host, row, warnings)


# ---------------------------------------------------------------------------
# SSH detail helpers (best-effort)
# ---------------------------------------------------------------------------


async def _probe_install_path(ssh: DSMSshClient, package_id: str) -> str | None:
    """Resolve the package install path via ``readlink`` of the target dir.

    Every installed DSM package has a symlink at
    ``/var/packages/<id>/target`` pointing to the volume-backed install dir.
    Returns the resolved path or None on failure.
    """
    pkg_arg = shlex.quote(package_id)
    cmd = f"readlink -f /var/packages/{pkg_arg}/target 2>/dev/null"
    try:
        res = await ssh.run(cmd, check=False, timeout=10.0)
    except DSMSshError:
        return None
    out = res.stdout.strip()
    return out or None


async def _probe_last_started_at(ssh: DSMSshClient, package_id: str) -> str | None:
    """Approximate last-started time via the mtime of the ``enabled`` flag file.

    DSM toggles ``/var/packages/<id>/enabled`` when the package transitions
    from stopped to started. Reading its mtime is a much cheaper proxy than
    digging through systemd-journal-equivalent logs.
    """
    pkg_arg = shlex.quote(package_id)
    cmd = (
        f"stat -c '%Y' /var/packages/{pkg_arg}/enabled 2>/dev/null || "
        f"stat -c '%Y' /var/packages/{pkg_arg}/installed_info 2>/dev/null"
    )
    try:
        res = await ssh.run(cmd, check=False, timeout=10.0)
    except DSMSshError:
        return None
    out = res.stdout.strip().splitlines()
    if not out:
        return None
    try:
        epoch = int(out[0])
    except ValueError:
        return None
    # Format as RFC3339-ish UTC for parseability.
    from datetime import UTC, datetime
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


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


def _extract_int(token: str) -> int | None:
    """Pick the first integer out of a ``key=value`` token."""
    _, _, val = token.partition("=")
    return _int_or_none(val.strip())


__all__ = ["packages_list", "packages_status"]
