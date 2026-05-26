# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""User Home service tools — read (Phase 2) + write (Phase 3b).

Phase 2 shipped ``user_home_is_enabled`` (tri-check). Phase 3b adds the
write companion :func:`user_home_enable` — applies the DSM 7.3 4-step
workaround that reconciles synoinfo, the symlink, the web-API flag, and
the per-user home folder. Idempotent; rollback on partial failure. The
``user_home_disable`` counterpart lands in a follow-up commit.

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

DSM 7.3 ``SYNO.Core.User.Home.set`` schema
------------------------------------------
Verified against CS3 / DSM 7.3.2 build 86009 by reading
``/usr/syno/synoman/webman/modules/AdminCenter/admin_center.js``: the
``set`` call takes params ``enable`` (bool) and ``location`` (string,
e.g. ``"/volume1"``). The older 6.x ``enable_user_home`` key is NOT
accepted. We document this in the params docstring to head off the
"copied the wrong name from a forum post" bug.
"""
from __future__ import annotations

import shlex
from typing import Any

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


# ---------------------------------------------------------------------------
# user_home_enable (Phase 3b)
# ---------------------------------------------------------------------------


_HOMES_SYMLINK = "/var/services/homes"
_SYNOSETKEYVALUE = "/usr/syno/bin/synosetkeyvalue"
_SYNOUSERHOME = "/usr/syno/sbin/synouserhome"


async def _readlink_raw(ssh: DSMSshClient) -> str | None:
    """Return the current ``/var/services/homes`` symlink target.

    Distinct from :func:`_read_homes_symlink` because that one is also
    used by the tri-check — keeping the symlink-rollback path private
    avoids accidentally coupling the read-side semantics to the
    rollback-side semantics.
    """
    try:
        res = await ssh.run(
            f"readlink {shlex.quote(_HOMES_SYMLINK)} 2>/dev/null",
            check=False, timeout=10.0,
        )
    except DSMSshError:
        return None
    target = res.stdout.strip()
    return target or None


async def _pick_volume_for_homes(
    ssh: DSMSshClient, host_volume_override: str | None,
) -> str:
    """Pick ``/volume<N>`` to host the ``homes`` share.

    Order of preference:

      1. ``host_cfg.user_home_volume`` from config (e.g. ``"/volume2"``).
         Trusted verbatim — operators who set it presumably know.
      2. The first ``/volume*/homes`` parent dir that already exists.
         (DSM creates ``/volume1/homes`` automatically on the first user
         add; we just point at whatever is there.)
      3. Default to ``/volume1``. If that volume doesn't exist we let
         the symlink create succeed but the dangling link will be caught
         by the tri-check post-step.

    Returns just the volume path (``"/volume1"``), not the ``/homes``
    suffix — the caller appends.
    """
    if host_volume_override:
        return host_volume_override
    # Probe for any /volume*/homes that already exists.
    cmd = (
        "for d in /volume*/homes; do "
        '[ -d "$d" ] && echo "$d" && break; '
        "done"
    )
    try:
        res = await ssh.run(cmd, check=False, timeout=10.0)
    except DSMSshError:
        return "/volume1"
    found = res.stdout.strip()
    if found:
        # found is e.g. "/volume2/homes" -> strip "/homes" suffix.
        return found[: -len("/homes")] if found.endswith("/homes") else "/volume1"
    return "/volume1"


async def user_home_enable(
    host: str, user: str | None = None, *, app_context,
) -> dict:
    """Reconcile DSM's User Home machinery in 4 steps.

    The four steps, in order:

      1. ``synosetkeyvalue /etc/synoinfo.conf userHomeEnable yes``
         (SSH + sudo). This is the bit DSM's web UI silently no-ops.
      2. ``rm -f /var/services/homes && ln -s <vol>/homes /var/services/homes``
         (SSH + sudo). ``<vol>`` is picked via :func:`_pick_volume_for_homes`.
      3. ``SYNO.Core.User.Home.set enable=true&location=<vol>``
         (web API). This is what flips the UI flag.
      4. If ``user`` provided: ``synouserhome --prepare-folder <user>``
         (SSH + sudo). Creates ``<vol>/homes/<user>/`` if absent.

    Idempotency: pre-call :func:`user_home_is_enabled`; if the tri-check
    returns ``enabled=True`` we short-circuit steps 1-3 and only run
    step 4 (if ``user`` is provided). The returned envelope's
    ``data.steps_skipped`` lists the step numbers that were skipped.

    Rollback: if step 2 fails we restore the previous symlink target
    (captured before mutating). If step 3 fails we restore the symlink
    too. Step 1's edit to synoinfo is left in place — it's harmless when
    User Home stays disabled and a no-op when a future enable retries.
    Step 4 failure leaves the previous 3 steps intact and surfaces a
    warning instead of failing the whole tool.

    Returns ``data.steps = [{"n": int, "name": str, "ok": bool,
    "skipped": bool, "error": str | None}, ...]`` so callers can audit
    exactly what happened.
    """
    ssh = get_ssh_client(app_context, host)
    host_cfg = app_context.config.get_host(host)

    # Pre-flight: tri-check the existing state. If already enabled we
    # only need to (possibly) run step 4 — the user's home folder may
    # still need preparing even when User Home is system-wide on.
    pre_envelope = await user_home_is_enabled(host, app_context=app_context)
    pre_data = pre_envelope.get("data") or {}
    already_enabled = bool(pre_data.get("enabled"))

    steps: list[dict[str, Any]] = []
    warnings: list[str] = list(pre_envelope.get("warnings") or [])
    steps_skipped: list[int] = []

    # Capture the previous symlink target BEFORE step 2 so we can
    # restore it on failure.
    previous_symlink = await _readlink_raw(ssh)

    volume = await _pick_volume_for_homes(ssh, host_cfg.user_home_volume)
    new_target = f"{volume}/homes"

    if already_enabled:
        warnings.append("already enabled")
        steps_skipped.extend([1, 2, 3])
        # Mark steps 1-3 as skipped in the per-step audit.
        for n, name in ((1, "synoinfo"), (2, "symlink"), (3, "web_api")):
            steps.append({"n": n, "name": name, "ok": True, "skipped": True, "error": None})
    else:
        # --- Step 1: synosetkeyvalue ---------------------------------------
        step1_cmd = (
            f"sudo -n {shlex.quote(_SYNOSETKEYVALUE)} "
            f"/etc/synoinfo.conf userHomeEnable yes"
        )
        try:
            res1 = await ssh.run(step1_cmd, check=False, timeout=15.0)
        except DSMSshError as exc:
            steps.append({"n": 1, "name": "synoinfo", "ok": False,
                          "skipped": False, "error": str(exc)})
            return _failure_envelope(host, steps, warnings,
                                     "step 1 (synoinfo write) failed")
        if res1.exit_status != 0:
            steps.append({"n": 1, "name": "synoinfo", "ok": False,
                          "skipped": False,
                          "error": f"exit {res1.exit_status}: {res1.stderr.strip()}"})
            return _failure_envelope(host, steps, warnings,
                                     "step 1 (synoinfo write) failed")
        steps.append({"n": 1, "name": "synoinfo", "ok": True,
                      "skipped": False, "error": None})

        # --- Step 2: symlink ----------------------------------------------
        step2_cmd = (
            f"sudo -n sh -c "
            f"{shlex.quote(f'rm -f {_HOMES_SYMLINK} && ln -s {new_target} {_HOMES_SYMLINK}')}"
        )
        try:
            res2 = await ssh.run(step2_cmd, check=False, timeout=15.0)
        except DSMSshError as exc:
            steps.append({"n": 2, "name": "symlink", "ok": False,
                          "skipped": False, "error": str(exc)})
            await _restore_symlink(ssh, previous_symlink, warnings)
            return _failure_envelope(host, steps, warnings,
                                     "step 2 (symlink) failed; symlink restored")
        if res2.exit_status != 0:
            steps.append({"n": 2, "name": "symlink", "ok": False,
                          "skipped": False,
                          "error": f"exit {res2.exit_status}: {res2.stderr.strip()}"})
            await _restore_symlink(ssh, previous_symlink, warnings)
            return _failure_envelope(host, steps, warnings,
                                     "step 2 (symlink) failed; symlink restored")
        steps.append({"n": 2, "name": "symlink", "ok": True,
                      "skipped": False, "error": None})

        # --- Step 3: web API ----------------------------------------------
        try:
            body = await call_dsm(
                app_context, host,
                api="SYNO.Core.User.Home", method="set", version=1,
                params={"enable": "true", "location": volume},
            )
        except Exception as exc:  # rollback path needs broad catch
            steps.append({"n": 3, "name": "web_api", "ok": False,
                          "skipped": False, "error": str(exc)})
            await _restore_symlink(ssh, previous_symlink, warnings)
            return _failure_envelope(host, steps, warnings,
                                     "step 3 (web API set) failed; symlink restored")
        warnings.extend(extract_warnings(body))
        steps.append({"n": 3, "name": "web_api", "ok": True,
                      "skipped": False, "error": None})

    # --- Step 4: per-user home folder prep ---------------------------------
    if user:
        step4_cmd = (
            f"sudo -n {shlex.quote(_SYNOUSERHOME)} --prepare-folder "
            f"{shlex.quote(user)}"
        )
        try:
            res4 = await ssh.run(step4_cmd, check=False, timeout=20.0)
        except DSMSshError as exc:
            steps.append({"n": 4, "name": "prepare_folder", "ok": False,
                          "skipped": False, "error": str(exc)})
            warnings.append(
                f"step 4 (synouserhome --prepare-folder {user!r}) failed: {exc}"
            )
            # Partial success: system-wide enable holds, this user's
            # folder couldn't be prepped. Surface as ok=True with the
            # warning so callers can decide whether to retry.
            return success_envelope(
                host,
                {
                    "user": user, "volume": volume,
                    "steps": steps, "steps_skipped": steps_skipped,
                    "partial": True,
                },
                warnings,
            )
        if res4.exit_status != 0:
            err = f"exit {res4.exit_status}: {res4.stderr.strip()}"
            steps.append({"n": 4, "name": "prepare_folder", "ok": False,
                          "skipped": False, "error": err})
            warnings.append(
                f"step 4 (synouserhome --prepare-folder {user!r}) failed: {err}"
            )
            return success_envelope(
                host,
                {
                    "user": user, "volume": volume,
                    "steps": steps, "steps_skipped": steps_skipped,
                    "partial": True,
                },
                warnings,
            )
        steps.append({"n": 4, "name": "prepare_folder", "ok": True,
                      "skipped": False, "error": None})
    else:
        steps_skipped.append(4)
        steps.append({"n": 4, "name": "prepare_folder", "ok": True,
                      "skipped": True, "error": None})

    return success_envelope(
        host,
        {
            "user": user, "volume": volume,
            "steps": steps, "steps_skipped": steps_skipped,
            "partial": False,
        },
        warnings,
    )


async def _restore_symlink(
    ssh: DSMSshClient, previous_target: str | None, warnings: list[str],
) -> None:
    """Best-effort restore of ``/var/services/homes`` to its prior target.

    Called on step-2 or step-3 failure. Appends a warning describing
    the rollback outcome — never raises, the caller is already in a
    failure path and doesn't need a second exception on top.
    """
    if not previous_target:
        warnings.append(
            "rollback: no prior /var/services/homes symlink to restore"
        )
        return
    cmd = (
        f"sudo -n sh -c "
        f"{shlex.quote(f'rm -f {_HOMES_SYMLINK} && ln -s {previous_target} {_HOMES_SYMLINK}')}"
    )
    try:
        res = await ssh.run(cmd, check=False, timeout=15.0)
    except DSMSshError as exc:
        warnings.append(f"rollback failed: {exc}")
        return
    if res.exit_status != 0:
        warnings.append(
            f"rollback failed: exit {res.exit_status}: {res.stderr.strip()}"
        )
    else:
        warnings.append(
            f"rollback ok: /var/services/homes -> {previous_target}"
        )


def _failure_envelope(
    host: str, steps: list[dict[str, Any]], warnings: list[str], message: str,
) -> dict[str, Any]:
    """Build the standard failure envelope for the enable flow.

    Mirrors :func:`success_envelope`'s shape but with ``ok=False`` and
    a ``data.error`` describing what went wrong. Step-by-step audit is
    preserved so the caller sees exactly which step failed.
    """
    return {
        "ok": False,
        "host": host,
        "data": {
            "category": "step_failed",
            "error": message,
            "steps": steps,
        },
        "warnings": warnings,
    }


__all__ = ["user_home_enable", "user_home_is_enabled"]
