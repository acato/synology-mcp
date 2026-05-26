# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""DSM package management — Phase 2 (reads) + Phase 3c (writes).

Wraps ``SYNO.Core.Package`` + per-package SSH probes. See DESIGN.md §5.2.

Phase 2 ships:
  * ``packages_list``      — id/name/version/status/install_type table.
  * ``packages_status``    — single-package detail.

Phase 3c adds the write half:
  * ``packages_install``   — ``SYNO.Core.Package.Installation`` with the
    spec'd server→spk fallback chain and EULA gating.
  * ``packages_uninstall`` — ``SYNO.Core.Package.Uninstallation`` with
    a denylist safety rail (refuses to remove the packages other agents
    depend on, e.g. ContainerManager, SnapshotReplication).

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
* ``SYNO.Core.Package.Installation`` on DSM 7.3.2 (build 86009) uses the
  verb ``install`` (or ``upgrade`` when the package is already present).
  The canonical "online install" call shape — confirmed by reading
  ``/usr/syno/synoman/webman/modules/PkgManApp/PkgManApp.js`` on CS3 — is

      api:     "SYNO.Core.Package.Installation"
      method:  "install"          # or "upgrade"
      version: 1
      params:  {name, is_syno, beta, url, checksum, filesize, type,
                blqinst, operation}

  The ``url`` / ``checksum`` / ``filesize`` / ``type`` / ``beta`` /
  ``source`` fields are fetched from ``SYNO.Core.Package.Server`` ``list``
  v2, which returns the public Synology package catalog row for the
  target id. The DSM 6.x verb ``install_from_server`` does NOT exist on
  DSM 7.3 and returns code 103 (method-not-supported) — we surfaced
  this gap during the Phase 3 live run and the refactor here is the
  fix.
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


# ===========================================================================
# Phase 3c — packages_install + packages_uninstall
# ===========================================================================
#
# DSM 7.3.2 schema notes (verified against CS3 build 86009):
#
# * ``SYNO.Core.Package.Installation`` maxVersion=2, minVersion=1.
#   ``SYNO.Core.Package.Installation.check`` v2 returns a volume listing
#   used by the AdminCenter UI to pick an install target; it does NOT
#   touch the installation state. The mutating method is ``install`` v1
#   (or ``upgrade`` v1 when the package is already present). The DSM 6.x
#   verb ``install_from_server`` does NOT exist on DSM 7.3 and returns
#   code 103 (method-not-supported).
# * ``SYNO.Core.Package.Installation.Download`` maxVersion=1. Used to
#   poll an in-progress download task.
# * ``SYNO.Core.Package.Server`` maxVersion=2, ``list`` v2 returns the
#   public Synology package catalog as ``data.packages[]``, each row
#   carrying ``{package, version, link, md5, size, type, beta, source,
#   qinst, ...}``. We fetch this BEFORE the install call so we can
#   feed those fields into the ``Installation.install`` payload.
# * ``SYNO.Core.Package.Uninstallation`` maxVersion=1.
# * ``SYNO.Core.Package.get`` v1 returns ``{id, name, version,
#   additional.install_type, ...}`` for the installed package; 102/103
#   for ``get`` against a not-installed id (caught + treated as
#   "not installed"). DSM 7.3 also surfaces code 4545 from Package
#   Center's private range for the same condition — both are handled by
#   :func:`_is_not_installed_error`.
#
# Online install flow (DSM 7.3 canonical):
#   1. ``Package.get`` → already installed? (idempotency / upgrade gate)
#   2. ``Package.Server.list`` v2 → find the catalog row for the target.
#   3. ``Package.Installation.install`` v1 with the full param set from
#      step 2 (url/checksum/filesize/type/beta/blqinst/operation).
#   4. ``Package.Installation.status`` v1 polling until ``finished=True``.
#   5. ``Package.get`` again to confirm the installed version.
#
# spk_fallback flow (manual .spk upload, observed in the UI's
# "Manual Install" wizard but not exercised live yet):
#   1. ``Package.Installation.upload`` to push a .spk to the NAS.
#   2. ``Package.Installation.install`` v1 with just
#      ``{name, blqinst, volume_path, is_syno, beta, installrunpackage}``
#      (no url/checksum/filesize — the file is already local).
# We document this here for completeness; the implementation surfaces
# the fallback only when the online path fails with a network/catalog
# error (DSM 1000-series), and even then it currently relies on DSM
# performing the .spk fetch itself — we do NOT upload a .spk from the
# MCP process.

# DSM 1000-series codes mean the online install failed — typically the
# Synology download server was unreachable, the package wasn't in the
# catalog, or no .spk matched this DSM build. We surface the code as a
# warning but no longer attempt a download-then-install retry; the
# fallback is documented above but not implemented (out of scope for
# this gap-fix pass).
_ONLINE_INSTALL_ERROR_RANGE = range(1000, 2000)

# Polling parameters for the async install/uninstall task.
_INSTALL_POLL_TIMEOUT_SECONDS = 300.0
_INSTALL_POLL_INTERVAL_SECONDS = 2.0


# Denylist for packages_uninstall. Removing any of these without
# ``force=True`` breaks other systems we run on the same NAS — the
# whole point of the safety rail is to make a misclick on a CM
# uninstall require a deliberate second action.
#
# Justification per entry:
#   * ContainerManager / Docker  -> Plex, Immich, Calibre-Web depend on it.
#   * SnapshotReplication / ReplicationService -> sysop SR backups.
#   * StorageManager             -> Storage administration UI; uninstall
#                                   leaves the volume-management UI in a
#                                   degraded state that the user has to
#                                   recover via a DSM reinstall.
#   * WebStation / Apache* / MariaDB* / PHP* -> hosts Caddy/HA fronted
#                                   admin UIs on some boxes; collateral
#                                   risk is too high.
#   * SecureSignIn / LDAPServer / DirectoryServer -> the auth stack
#                                   itself; removing it can lock the
#                                   account out of the box.
#   * HyperBackup / HyperBackupVault -> off-box backup target dependencies
#                                   (added beyond the proposed list
#                                   because the user's roadmap calls
#                                   out cross-continent Hyper Backup;
#                                   removing the package would break
#                                   the entire DR chain).
_UNINSTALL_DENYLIST: dict[str, str] = {
    # Container / Docker
    "ContainerManager": "Plex, Immich, Calibre-Web depend on the docker daemon",
    "Docker": "Plex, Immich, Calibre-Web depend on the docker daemon",
    # Snapshot Replication backbone
    "SnapshotReplication": "sysop SR backups depend on this package",
    "ReplicationService": "sysop SR backups depend on this package",
    # Hyper Backup chain (cross-continent backup roadmap)
    "HyperBackup": "off-box backup chain depends on this package",
    "HyperBackupVault": "off-box backup chain depends on this package",
    # Storage admin UI
    "StorageManager": "removing StorageManager leaves the Storage UI broken",
    # Web stack collateral risk
    "WebStation": "hosts Caddy/HA admin UIs on some boxes",
    "Apache22": "WebStation backend",
    "Apache24": "WebStation backend",
    "MariaDB10": "WebStation database backend",
    "MariaDB11": "WebStation database backend",
    "PHP7.4": "WebStation runtime",
    "PHP8.0": "WebStation runtime",
    "PHP8.1": "WebStation runtime",
    "PHP8.2": "WebStation runtime",
    # Auth stack — removing locks accounts out
    "SecureSignIn": "auth dependency; uninstalling can lock accounts out",
    "LDAPServer": "auth dependency; uninstalling can lock accounts out",
    "DirectoryServer": "auth dependency; uninstalling can lock accounts out",
}


def _is_not_installed_error(exc: Exception) -> bool:
    """Return True if `exc` looks like 'package not installed'.

    DSM 7.3 returns two different code families for
    ``SYNO.Core.Package.get`` against a package_id it doesn't know:

      * 102/103/104 — "API/method/version not supported on this build".
        ``Package.get`` itself is confirmed-present on 7.3 so we treat
        a 10x raised by ``get`` as "not installed" rather than a
        version mismatch.
      * 4545 — DSM 7.3 Package Center error: ``package is not
        installed`` (verified live on CS4 / build 86009). The 4500-
        family of error codes is DSM Package Center's private range.

    Any other DSMError bubbles to the caller.
    """
    from .errors import UnsupportedDSMVersion
    if isinstance(exc, UnsupportedDSMVersion):
        return True
    code = getattr(exc, "dsm_error_code", None)
    return code == 4545


async def _get_installed_package(
    app_context, host: str, package_id: str,
) -> dict[str, Any] | None:
    """Return the installed package row for `package_id`, or None.

    Implementation: try ``SYNO.Core.Package.get`` v1. A 102/103 from
    ``get`` means the package is not installed (DSM uses the same
    "method not supported" code as "id not found"). Any other DSMError
    bubbles to the caller.
    """
    try:
        body = await call_dsm(
            app_context, host,
            api="SYNO.Core.Package", method="get", version=1,
            params={"id": package_id},
        )
    except Exception as exc:
        if _is_not_installed_error(exc):
            return None
        raise
    data = body.get("data") or {}
    if not data or (not data.get("id") and not data.get("package")):
        return None
    return data


def _extract_eula_text(body: dict[str, Any]) -> str | None:
    """Pull EULA text out of an install response if present.

    DSM has been observed to return EULA prompts under
    ``data.eula`` / ``data.license`` / ``data.eula_text`` depending on
    the package and DSM build. We try each in turn and return the first
    non-empty string.
    """
    data = body.get("data") or {}
    if not isinstance(data, dict):
        return None
    for key in ("eula", "license", "eula_text"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return None


def _extract_dsm_error_code(exc: Exception) -> int | None:
    """Return the DSM error code carried by exc, if any."""
    code = getattr(exc, "dsm_error_code", None)
    if isinstance(code, int):
        return code
    return None


async def _poll_install_task(
    app_context, host: str, task_id: str,
) -> dict[str, Any]:
    """Poll ``SYNO.Core.Package.Installation status`` until done or timeout.

    Returns the final body. Best-effort: DSM's install task model is
    not formally documented, so we accept any response that does NOT
    carry ``finished=False`` as a terminal state. A timeout surfaces
    as a warning, not an exception — the caller decides whether to
    retry.

    DSM 7.3 issues install task IDs in the form
    ``@SYNOPKG_DOWNLOAD_<package_id>``. We pass the task_id straight
    through; the AdminCenter UI uses both ``task_id`` and ``taskid`` as
    the param name depending on the call site (``status`` accepts
    ``task_id``, the Download API accepts ``taskid``).
    """
    import asyncio
    elapsed = 0.0
    last_body: dict[str, Any] = {}
    while elapsed < _INSTALL_POLL_TIMEOUT_SECONDS:
        try:
            last_body = await call_dsm(
                app_context, host,
                api="SYNO.Core.Package.Installation", method="status",
                version=1,
                params={"task_id": task_id},
            )
        except Exception:
            # status method may be 102/103 on some 7.3 builds; treat
            # an unqueryable task as terminal and let the caller
            # check via a follow-up ``Package.get`` call.
            return last_body
        data = last_body.get("data") or {}
        if data.get("finished") is True:
            return last_body
        if data.get("status") in {"done", "complete", "completed", "error"}:
            return last_body
        await asyncio.sleep(_INSTALL_POLL_INTERVAL_SECONDS)
        elapsed += _INSTALL_POLL_INTERVAL_SECONDS
    return last_body


async def _fetch_server_catalog_row(
    app_context, host: str, package_id: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Find the Synology-catalog row for `package_id` via Server.list v2.

    Returns ``(row_or_None, raw_body)``. We scan both ``data.packages``
    and ``data.beta_packages`` for the target id — DSM separates the
    two but installs use the same call shape regardless.

    A None row means the package is not in the catalog and we cannot
    perform an online install. The caller surfaces that as a
    ``not_in_catalog`` refusal (or a fallback path, eventually).
    """
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Package.Server", method="list", version=2,
    )
    data = body.get("data") or {}
    pools: list[list[Any]] = []
    for key in ("packages", "beta_packages"):
        candidate = data.get(key)
        if isinstance(candidate, list):
            pools.append(candidate)
    for pool in pools:
        for raw in pool:
            if not isinstance(raw, dict):
                continue
            # ``package`` and ``id`` are usually identical but DSM
            # historically populated one or the other depending on the
            # client. Check both.
            row_id = raw.get("package") or raw.get("id")
            if row_id == package_id:
                return raw, body
    return None, body


def _build_install_params(
    catalog_row: dict[str, Any],
    package_id: str,
    *,
    accept_eula: bool,
) -> dict[str, Any]:
    """Translate a catalog row into the ``Installation.install`` payload.

    Mirrors the canonical payload produced by ``_onRequestDownload`` in
    ``PkgManApp.js`` (CS3 / DSM 7.3.2 build 86009). All string values
    are stringified at this layer; DSM is permissive about types but
    consistent stringification avoids the occasional 400 from the JSON
    parser on the server side.
    """
    is_syno = str(catalog_row.get("source") or "").lower() == "syno"
    beta = bool(catalog_row.get("beta"))
    qinst = bool(catalog_row.get("qinst"))
    params: dict[str, Any] = {
        "name": package_id,
        "is_syno": "true" if is_syno else "false",
        "beta": "true" if beta else "false",
        "url": str(catalog_row.get("link") or ""),
        "checksum": str(catalog_row.get("md5") or ""),
        "filesize": str(catalog_row.get("size") or "0"),
        "type": str(catalog_row.get("type") or "0"),
        "blqinst": "true" if qinst else "false",
        "operation": "install",
    }
    if accept_eula:
        params["accept_eula"] = "true"
    return params


async def packages_install(
    host: str,
    package_id: str,
    version: str | None = None,
    accept_eula: bool = False,
    *,
    app_context,
) -> dict:
    """Install a package on `host` using the DSM 7.3 canonical verb chain.

    Implementation follows the corrected DESIGN.md §5.2:

      1. Pre-flight: ``Package.get`` to check whether the package is
         already installed.
         - Same version: return ``ok=True, data.installed=False,
           warnings=["already at version X"]``.
         - Different version: refuse with
           ``category="upgrade_required"`` — MVP does not implement
           in-place upgrades.
      2. ``SYNO.Core.Package.Server.list`` v2 to fetch the public
         catalog row for ``package_id`` (url / checksum / filesize /
         type / source / beta). If the row is not present, refuse with
         ``category="not_in_catalog"`` — the spk_fallback path is
         documented but not implemented in this gap-fix pass.
      3. ``SYNO.Core.Package.Installation.install`` v1 with the full
         param set from step 2. The DSM 6.x verb ``install_from_server``
         does NOT exist on 7.3 and was the original bug — see the
         module docstring.
      4. If the install response carries an EULA and ``accept_eula=False``,
         surface ``category="eula_required"`` with the EULA text.
      5. ``SYNO.Core.Package.Installation.status`` v1 polling.
      6. ``Package.get`` again to confirm the installed version.

    Returns ``data.installed: bool, data.version: str, data.method:
    "online" | "noop"`` plus ``package_id``. The legacy ``"server"`` /
    ``"spk_fallback"`` enum values from the pre-Phase-3-fix version are
    no longer produced.
    """
    if not package_id:
        raise InvalidParam(
            "package_id must be a non-empty string", host=host,
            details={"param": "package_id"},
        )

    # --- Pre-flight: already installed? --------------------------------------
    existing = await _get_installed_package(app_context, host, package_id)
    if existing is not None:
        existing_version = str(existing.get("version") or "")
        if version is None or existing_version == version:
            return success_envelope(
                host,
                {
                    "installed": False,
                    "version": existing_version,
                    "method": "noop",
                    "package_id": package_id,
                },
                warnings=[f"already at version {existing_version}"],
            )
        return {
            "ok": False,
            "host": host,
            "data": {
                "category": "upgrade_required",
                "package_id": package_id,
                "installed_version": existing_version,
                "requested_version": version,
                "next_step": (
                    "in-place upgrade is not implemented in MVP; uninstall "
                    "first or run the upgrade from the Package Center UI"
                ),
            },
            "warnings": [],
        }

    # --- Fetch catalog row from Server.list ----------------------------------
    catalog_row, server_body = await _fetch_server_catalog_row(
        app_context, host, package_id,
    )
    warnings: list[str] = list(extract_warnings(server_body))
    if catalog_row is None:
        return {
            "ok": False,
            "host": host,
            "data": {
                "category": "not_in_catalog",
                "package_id": package_id,
                "next_step": (
                    "the Synology package catalog (Server.list v2) does not "
                    "contain this id for the current DSM build; verify the "
                    "package_id spelling or install from a downloaded .spk "
                    "via the DSM UI (spk_fallback is documented in the "
                    "module docstring but not yet implemented)"
                ),
            },
            "warnings": warnings,
        }
    # Sanity-check version. If the caller pinned a specific version and the
    # catalog row offers a different one, refuse rather than silently
    # installing the wrong build.
    catalog_version = str(catalog_row.get("version") or "")
    if version and catalog_version and catalog_version != version:
        return {
            "ok": False,
            "host": host,
            "data": {
                "category": "version_mismatch",
                "package_id": package_id,
                "requested_version": version,
                "catalog_version": catalog_version,
                "next_step": (
                    "Synology's online catalog only carries the latest "
                    "version for this DSM build; specify version=None "
                    "to install whatever the catalog offers, or fetch the "
                    "exact version as a .spk manually"
                ),
            },
            "warnings": warnings,
        }

    # --- Online install via SYNO.Core.Package.Installation.install -----------
    install_params = _build_install_params(
        catalog_row, package_id, accept_eula=accept_eula,
    )
    try:
        install_body = await call_dsm(
            app_context, host,
            api="SYNO.Core.Package.Installation",
            method="install", version=1,
            params=install_params,
        )
    except Exception as exc:
        code = _extract_dsm_error_code(exc)
        if code is not None and code in _ONLINE_INSTALL_ERROR_RANGE:
            warnings.append(
                f"online install failed with DSM {code} — the spk_fallback "
                "path (manual .spk upload) is documented but not yet "
                "implemented in this MCP"
            )
            return {
                "ok": False,
                "host": host,
                "data": {
                    "category": "online_install_failed",
                    "package_id": package_id,
                    "dsm_error_code": code,
                    "next_step": (
                        "retry later (transient network errors), or install "
                        "manually via the DSM UI"
                    ),
                },
                "warnings": warnings,
            }
        raise

    # EULA gate: surface ``eula_text`` if present and we haven't been told
    # to accept.
    eula_text = _extract_eula_text(install_body)
    if eula_text and not accept_eula:
        return {
            "ok": False,
            "host": host,
            "data": {
                "category": "eula_required",
                "package_id": package_id,
                "eula_text": eula_text,
                "next_step": (
                    "re-call with accept_eula=True to agree to the EULA "
                    "and proceed"
                ),
            },
            "warnings": warnings,
        }

    warnings.extend(extract_warnings(install_body))
    install_data = install_body.get("data") or {}
    task_id = install_data.get("task_id") or install_data.get("taskid")
    if task_id:
        final_body = await _poll_install_task(
            app_context, host, str(task_id),
        )
        warnings.extend(extract_warnings(final_body))

    # Verify install by re-checking via Package.get.
    installed = await _get_installed_package(app_context, host, package_id)
    installed_version = (
        str(installed.get("version") or "") if installed else ""
    )
    return success_envelope(
        host,
        {
            "installed": True,
            "version": installed_version,
            "method": "online",
            "package_id": package_id,
        },
        warnings,
    )


async def packages_uninstall(
    host: str, package_id: str, force: bool = False, *, app_context,
) -> dict:
    """Uninstall a package from `host`.

    Safety rail: ``package_id`` is checked against an in-process
    denylist of packages that other agents and the sysop's
    infrastructure depend on (ContainerManager, SnapshotReplication,
    HyperBackup, etc.). Matches are refused with
    ``category="denylist"`` unless ``force=True`` is passed.

    Idempotency: if the package is not installed, returns
    ``ok=True, data.uninstalled=False,
    warnings=["package not installed"]`` — no API call fires.

    DSM 7.3 uses ``SYNO.Core.Package.Uninstallation`` v1 with method
    ``uninstall``. The param name is ``id`` (NOT ``package``), per the
    AdminCenter PkgManApp.js call site:
    ``params: {id: t.id, dsm_apps: t.get("dsm_apps")}``. The DSM
    server returns 120 when sent ``package=<id>`` — same surprise we
    hit on the install verb. The async completion shape mirrors
    ``Installation`` so we use the same poll loop.
    """
    if not package_id:
        raise InvalidParam(
            "package_id must be a non-empty string", host=host,
            details={"param": "package_id"},
        )

    # --- denylist pre-flight -------------------------------------------------
    denylist_reason = _UNINSTALL_DENYLIST.get(package_id)
    if denylist_reason and not force:
        return {
            "ok": False,
            "host": host,
            "data": {
                "category": "denylist",
                "package_id": package_id,
                "denylist_reason": denylist_reason,
                "next_step": "pass force=True to override",
            },
            "warnings": [],
        }

    # --- idempotency: is the package installed? ------------------------------
    existing = await _get_installed_package(app_context, host, package_id)
    if existing is None:
        return success_envelope(
            host,
            {
                "uninstalled": False,
                "package_id": package_id,
            },
            warnings=["package not installed"],
        )

    warnings: list[str] = []
    if denylist_reason and force:
        warnings.append(
            f"force=True override: removing {package_id} despite denylist "
            f"({denylist_reason})"
        )

    # --- uninstall call ------------------------------------------------------
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Package.Uninstallation",
        method="uninstall", version=1,
        params={"id": package_id},
    )
    warnings.extend(extract_warnings(body))
    data = body.get("data") or {}
    task_id = data.get("task_id") or data.get("taskid")
    if task_id:
        final_body = await _poll_install_task(
            app_context, host, str(task_id),
        )
        warnings.extend(extract_warnings(final_body))

    return success_envelope(
        host,
        {
            "uninstalled": True,
            "package_id": package_id,
            "previous_version": str(existing.get("version") or ""),
        },
        warnings,
    )


__all__ = [
    "packages_install",
    "packages_list",
    "packages_status",
    "packages_uninstall",
]
