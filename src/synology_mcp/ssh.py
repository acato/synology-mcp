# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""SSH key + service management — Phase 3a + Phase 3c (write tools).

This module ships the write half of the ``ssh_*`` tool family:

  * :func:`ssh_add_authorized_key`    — Phase 3a.
  * :func:`ssh_remove_authorized_key` — Phase 3a.
  * :func:`ssh_enable_user_ssh`       — Phase 3a.
  * :func:`ssh_set_port`              — Phase 3c.

Read-only ``ssh_get_state`` / ``ssh_list_authorized_keys`` ship in a
later phase.

Key DSM 7.3 quirks handled here
-------------------------------

* **DSM SFTP subsystem is disabled by default** — ``paramiko.open_sftp()``
  returns ``Channel closed``. ``authorized_keys`` edits go via
  base64-over-``exec_command`` instead. See
  ``feedback_dsm_no_sftp.md``.

* **User Home must be enabled and consistent** before any
  ``authorized_keys`` write can succeed — the per-user ``~/.ssh`` lives
  under ``/var/services/homes/<user>/`` and that path is a symlink whose
  target is governed by the DSM 7.3 silent-no-op pattern (see
  ``feedback_dsm_user_home_enable.md``). ``add_authorized_key`` calls
  ``user_home_is_enabled`` as a pre-flight and refuses with
  ``category="precondition"`` + ``next_step="user_home_enable"`` if it
  comes back ``enabled=False``.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import shlex
from typing import Any

from . import user_home as _user_home
from ._helpers import call_dsm, get_ssh_client, success_envelope
from .errors import DSMSshError, InvalidParam
from .transport.http import extract_warnings
from .transport.ssh import DSMSshClient

# ---------------------------------------------------------------------------
# Pubkey parsing + fingerprinting
# ---------------------------------------------------------------------------

# Set of OpenSSH key types we accept on input. We don't enforce this list
# server-side — sshd will reject anything it doesn't grok — but a sanity
# check at parse time catches "user pasted their password by accident".
_VALID_KEY_TYPES: frozenset[str] = frozenset(
    {
        "ssh-rsa",
        "ssh-dss",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ssh-ed25519@openssh.com",
        "ssh-rsa-cert-v01@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    }
)


def _parse_pubkey(pubkey: str, *, host: str | None = None) -> tuple[str, bytes, str]:
    """Parse an OpenSSH public-key line.

    Returns ``(key_type, key_bytes, embedded_comment)`` where ``key_bytes``
    is the raw base64-decoded blob (used for fingerprinting) and
    ``embedded_comment`` is whatever followed the base64 part in the
    original line (or ``""`` if absent).

    Raises ``InvalidParam`` for any malformed input.
    """
    if not isinstance(pubkey, str) or not pubkey.strip():
        raise InvalidParam(
            "pubkey must be a non-empty string", host=host,
            details={"param": "pubkey"},
        )
    # Reject embedded newlines — authorized_keys is one-line-per-key.
    if "\n" in pubkey or "\r" in pubkey:
        raise InvalidParam(
            "pubkey must not contain newline characters", host=host,
            details={"param": "pubkey"},
        )
    parts = pubkey.strip().split(None, 2)
    if len(parts) < 2:
        raise InvalidParam(
            "pubkey must contain at least <type> <base64-blob>", host=host,
            details={"param": "pubkey"},
        )
    key_type = parts[0]
    b64_blob = parts[1]
    embedded_comment = parts[2] if len(parts) == 3 else ""
    if key_type not in _VALID_KEY_TYPES:
        raise InvalidParam(
            f"unrecognized key type {key_type!r}",
            host=host,
            details={"param": "pubkey", "key_type": key_type},
        )
    try:
        key_bytes = base64.b64decode(b64_blob, validate=True)
    except (ValueError, TypeError) as exc:
        raise InvalidParam(
            f"pubkey base64 blob is malformed: {exc}", host=host,
            details={"param": "pubkey"},
        ) from exc
    if not key_bytes:
        raise InvalidParam(
            "pubkey base64 blob decoded to zero bytes", host=host,
            details={"param": "pubkey"},
        )
    return key_type, key_bytes, embedded_comment


def _fingerprint_sha256(key_bytes: bytes) -> str:
    """Return the SHA256 fingerprint in OpenSSH ``SHA256:<b64>`` form.

    Matches ``ssh-keygen -lf <key.pub>`` output exactly (base64 without
    padding ``=`` characters).
    """
    digest = hashlib.sha256(key_bytes).digest()
    b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{b64}"


def _normalize_fingerprint(fingerprint: str) -> str:
    """Accept fingerprints with or without the ``SHA256:`` prefix.

    Returns the canonical ``SHA256:<b64-nopad>`` form. Raises
    ``InvalidParam`` for clearly malformed values (empty, MD5-style,
    base64 with the wrong length, base64 with bad alphabet).
    """
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        raise InvalidParam(
            "fingerprint must be a non-empty string",
            details={"param": "fingerprint"},
        )
    fp = fingerprint.strip()
    if fp.lower().startswith("md5:"):
        raise InvalidParam(
            "MD5 fingerprints are not supported -- pass the SHA256 form",
            details={"param": "fingerprint"},
        )
    body = fp.split(":", 1)[1] if fp.upper().startswith("SHA256:") else fp
    body = body.rstrip("=")
    # SHA256 over a non-empty input -> 32 bytes -> 43 chars unpadded base64.
    if len(body) != 43:
        raise InvalidParam(
            "fingerprint does not look like a SHA256 base64 digest "
            f"(expected 43 base64 chars, got {len(body)})",
            details={"param": "fingerprint"},
        )
    # Validate the base64 alphabet without forcing padding.
    try:
        base64.b64decode(body + "=", validate=True)
    except (ValueError, TypeError) as exc:
        raise InvalidParam(
            f"fingerprint base64 is malformed: {exc}",
            details={"param": "fingerprint"},
        ) from exc
    return f"SHA256:{body}"


# ---------------------------------------------------------------------------
# Username validation
# ---------------------------------------------------------------------------


def _validate_username(user: str, *, host: str | None = None) -> None:
    """Reject usernames that would break the shell-quoted file path.

    DSM usernames are 1-32 chars from ``[A-Za-z0-9._-]``; we accept that
    plus the empty-string-rejection that callers usually want.
    """
    if not isinstance(user, str) or not user:
        raise InvalidParam(
            "user must be a non-empty string", host=host,
            details={"param": "user"},
        )
    if len(user) > 32:
        raise InvalidParam(
            "user must be at most 32 characters",
            host=host, details={"param": "user"},
        )
    bad = [ch for ch in user if not (ch.isalnum() or ch in "._-")]
    if bad:
        raise InvalidParam(
            f"user contains disallowed characters: {bad!r}",
            host=host, details={"param": "user", "bad_chars": bad},
        )


# ---------------------------------------------------------------------------
# authorized_keys file ops over SSH (base64-over-exec, NO SFTP)
# ---------------------------------------------------------------------------


# Canonical path. ``/var/services/homes`` is the DSM symlink to
# ``/volume*/homes`` — the user_home tri-check guarantees it exists and is
# valid before we ever land here.
def _home_ssh_dir(user: str) -> str:
    return f"/var/services/homes/{user}/.ssh"


def _authorized_keys_path(user: str) -> str:
    return f"{_home_ssh_dir(user)}/authorized_keys"


async def _ensure_ssh_dir(ssh: DSMSshClient, user: str) -> None:
    """Create ``~/.ssh`` and ``authorized_keys`` with the right perms.

    Idempotent: ``mkdir -p`` + ``touch`` + ``chmod`` is safe to re-run.
    Runs everything in a single exec for fewer round trips.
    """
    ssh_dir = _home_ssh_dir(user)
    ak = _authorized_keys_path(user)
    cmd = (
        f"set -e; "
        f"mkdir -p {shlex.quote(ssh_dir)} && "
        f"chmod 700 {shlex.quote(ssh_dir)} && "
        f"touch {shlex.quote(ak)} && "
        f"chmod 600 {shlex.quote(ak)}"
    )
    res = await ssh.run(cmd, check=False, timeout=15.0)
    if res.exit_status != 0:
        raise DSMSshError(
            f"failed to ensure {ssh_dir} / authorized_keys exist with correct perms",
            exit_status=res.exit_status, stderr=res.stderr, command=cmd,
        )


async def _read_authorized_keys(ssh: DSMSshClient, user: str) -> str:
    """Return the current contents of ``authorized_keys`` or ``""`` if absent."""
    ak = _authorized_keys_path(user)
    # ``|| true`` so a missing file is not a hard error — we treat it as empty.
    cmd = f"cat {shlex.quote(ak)} 2>/dev/null || true"
    res = await ssh.run(cmd, check=False, timeout=15.0)
    # The ``|| true`` shields a missing file, so any non-zero exit here is
    # something unexpected — surface it instead of swallowing.
    if res.exit_status != 0:
        raise DSMSshError(
            f"failed to read {ak}",
            exit_status=res.exit_status, stderr=res.stderr, command=cmd,
        )
    return res.stdout


async def _write_authorized_keys(
    ssh: DSMSshClient, user: str, contents: str,
) -> None:
    """Atomically replace ``authorized_keys`` with ``contents``.

    The payload is base64-encoded on the client side and decoded on the
    server side — that's the canonical workaround for DSM's disabled
    SFTP subsystem (see ``feedback_dsm_no_sftp.md``). The decoded bytes
    land in a temp file in the same directory and then ``mv`` lands
    them atomically (single rename, no torn writes).
    """
    ak = _authorized_keys_path(user)
    tmp = f"{ak}.synology-mcp.tmp"
    payload_b64 = base64.b64encode(contents.encode("utf-8")).decode("ascii")
    # ``printf %s`` (no trailing newline) preserves the exact bytes; the
    # decoded payload already contains its own trailing newline if needed.
    cmd = (
        f"set -e; "
        f"printf %s {shlex.quote(payload_b64)} | base64 -d > {shlex.quote(tmp)} && "
        f"chmod 600 {shlex.quote(tmp)} && "
        f"mv {shlex.quote(tmp)} {shlex.quote(ak)}"
    )
    res = await ssh.run(cmd, check=False, timeout=30.0)
    if res.exit_status != 0:
        # Best effort cleanup of the temp file before re-raising.
        with contextlib.suppress(DSMSshError):  # pragma: no cover - best effort
            await ssh.run(
                f"rm -f {shlex.quote(tmp)}", check=False, timeout=10.0,
            )
        raise DSMSshError(
            f"failed to write {ak}",
            exit_status=res.exit_status, stderr=res.stderr, command=cmd,
        )


def _split_authorized_keys(contents: str) -> list[str]:
    """Split a file blob into normalized one-key-per-line entries.

    Blank lines and lines starting with ``#`` are dropped — they have no
    fingerprint and are not part of the dedup-able key set. (sshd ignores
    them too, so we don't lose anything by skipping them.)
    """
    out: list[str] = []
    for raw in contents.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def _join_authorized_keys(entries: list[str]) -> str:
    """Inverse of :func:`_split_authorized_keys` — always ends with newline."""
    if not entries:
        return ""
    return "\n".join(entries) + "\n"


# ---------------------------------------------------------------------------
# Tool: ssh_add_authorized_key
# ---------------------------------------------------------------------------


async def ssh_add_authorized_key(
    host: str, user: str, pubkey: str, comment: str = "", *, app_context,
) -> dict:
    """Append `pubkey` to ``~<user>/.ssh/authorized_keys`` on `host`.

    Pre-flight: calls :func:`user_home.user_home_is_enabled` first. If
    that returns ``enabled=False`` the call is refused with a
    ``precondition`` envelope pointing at ``user_home_enable``.

    Idempotency: dedupes by SHA256 fingerprint of the key blob. If a key
    with the same fingerprint is already present (regardless of comment
    field), returns ``ok=True`` with ``data.added=False`` and the
    ``"key already present"`` warning.

    File transport: base64-encoded payload over ``exec_command``. NO
    SFTP — DSM disables the SFTP subsystem by default.
    """
    _validate_username(user, host=host)
    key_type, key_bytes, embedded_comment = _parse_pubkey(pubkey, host=host)
    fingerprint = _fingerprint_sha256(key_bytes)

    # Pre-flight: confirm User Home is genuinely enabled.
    home_envelope = await _user_home.user_home_is_enabled(
        host, app_context=app_context,
    )
    home_data = home_envelope.get("data") or {}
    if not home_data.get("enabled"):
        # Reuse the tri-check warnings verbatim so the caller sees the
        # disagreement detail.
        warnings = list(home_envelope.get("warnings") or [])
        warnings.append(
            "ssh_add_authorized_key refused: User Home is not enabled "
            "(or its three signals disagree). Run user_home_enable first."
        )
        return {
            "ok": False,
            "host": host,
            "data": {
                "category": "precondition",
                "next_step": "user_home_enable",
                "user_home": home_data,
            },
            "warnings": warnings,
        }

    # Compose the line we'd add. Prefer caller-supplied ``comment`` over
    # the embedded one; fall back to embedded; finally write just the
    # type+blob with no trailing comment.
    chosen_comment = comment.strip() if comment else embedded_comment
    if chosen_comment:
        # Same scrub as for the pubkey itself.
        if "\n" in chosen_comment or "\r" in chosen_comment:
            raise InvalidParam(
                "comment must not contain newline characters", host=host,
                details={"param": "comment"},
            )
        new_line = (
            f"{key_type} {base64.b64encode(key_bytes).decode('ascii')} "
            f"{chosen_comment}"
        )
    else:
        new_line = f"{key_type} {base64.b64encode(key_bytes).decode('ascii')}"

    ssh = get_ssh_client(app_context, host)
    await _ensure_ssh_dir(ssh, user)
    existing_blob = await _read_authorized_keys(ssh, user)
    existing_entries = _split_authorized_keys(existing_blob)

    # Dedup by fingerprint of the key BLOB (not the full line — comment
    # changes shouldn't trigger a re-add).
    for entry in existing_entries:
        try:
            _, ek_bytes, _ = _parse_pubkey(entry)
        except InvalidParam:
            # Garbage line in the file — skip it, leave it alone, do not
            # let it block a write of a valid new key.
            continue
        if _fingerprint_sha256(ek_bytes) == fingerprint:
            return success_envelope(
                host,
                {
                    "added": False,
                    "fingerprint": fingerprint,
                    "key_type": key_type,
                    "user": user,
                },
                warnings=["key already present"],
            )

    new_entries = [*existing_entries, new_line]
    await _write_authorized_keys(ssh, user, _join_authorized_keys(new_entries))
    return success_envelope(
        host,
        {
            "added": True,
            "fingerprint": fingerprint,
            "key_type": key_type,
            "user": user,
        },
    )


# ---------------------------------------------------------------------------
# Tool: ssh_remove_authorized_key
# ---------------------------------------------------------------------------


async def ssh_remove_authorized_key(
    host: str, user: str, fingerprint: str, *, app_context,
) -> dict:
    """Remove all keys whose SHA256 fingerprint matches `fingerprint`.

    Idempotent: a fingerprint that's not present returns ``ok=True`` with
    ``data.removed_count=0`` (and no warnings). Order of the remaining
    keys is preserved exactly. Lines we can't parse (garbage, custom
    options, etc.) are preserved untouched — we never silently rewrite
    state we don't understand.
    """
    _validate_username(user, host=host)
    target_fp = _normalize_fingerprint(fingerprint)
    ssh = get_ssh_client(app_context, host)
    existing_blob = await _read_authorized_keys(ssh, user)
    existing_entries = _split_authorized_keys(existing_blob)

    kept: list[str] = []
    removed_count = 0
    for entry in existing_entries:
        try:
            _, ek_bytes, _ = _parse_pubkey(entry)
        except InvalidParam:
            # Malformed entry — preserve it untouched. We're not in the
            # business of cleaning up the file behind the user's back.
            kept.append(entry)
            continue
        if _fingerprint_sha256(ek_bytes) == target_fp:
            removed_count += 1
            continue
        kept.append(entry)

    if removed_count == 0:
        return success_envelope(
            host,
            {"removed_count": 0, "fingerprint": target_fp, "user": user},
        )

    await _write_authorized_keys(ssh, user, _join_authorized_keys(kept))
    return success_envelope(
        host,
        {
            "removed_count": removed_count,
            "fingerprint": target_fp,
            "user": user,
        },
    )


# ---------------------------------------------------------------------------
# Tool: ssh_enable_user_ssh
# ---------------------------------------------------------------------------


# DSM 7.3 SSH access gating
# -------------------------
#
# There is NO per-user ``SYNO.SSH`` row in ``SYNO.Core.AppPriv.Rule`` on
# DSM 7.3 — the ``synoappprivilege.db`` ``AppPrivRule`` table only
# contains entries for FTP, SFTP, AFP, Rsync, WebDAV, SMB, FileStation,
# MailServer, MailPlusServer, BackupService, and Desktop (verified
# against CS3 / DSM 7.3 build 86009). SSH is gated by:
#
#   * The system-wide ``SYNO.Core.Terminal`` ``enable_ssh`` flag (set
#     via a later phase tool — out of scope for 3a).
#   * Membership in the ``administrators`` group on a per-user basis.
#
# We therefore implement ``ssh_enable_user_ssh`` as
# ``SYNO.Core.Group.Member.add`` against the ``administrators`` group,
# using ``admin_check`` as the idempotency probe. If a future DSM build
# adds a dedicated per-user SSH AppPriv entry, we can swap this for the
# rule-set call without changing the public tool signature.
_ADMINISTRATORS_GROUP = "administrators"


async def ssh_enable_user_ssh(
    host: str, user: str, *, app_context,
) -> dict:
    """Grant SSH access to `user` on `host` by adding them to ``administrators``.

    Idempotent: if ``admin_check`` says the user is already an admin,
    returns ``ok=True`` with ``warnings=["already enabled"]`` and
    ``data.added=False``.
    """
    _validate_username(user, host=host)

    # Step 1: ``admin_check`` for idempotency. DSM's web framework
    # accepts the ``name`` param as a JSON-encoded array on this
    # endpoint (matches what the AdminCenter UI sends); a single-element
    # array is the canonical shape for one user.
    check_body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Group.Member", method="admin_check", version=1,
        params={"name": json.dumps([user])},
    )
    warnings: list[str] = list(extract_warnings(check_body))
    is_admin = _extract_is_admin(check_body, user)

    if is_admin:
        warnings.insert(0, "already enabled")
        return success_envelope(
            host,
            {
                "added": False,
                "user": user,
                "group": _ADMINISTRATORS_GROUP,
                "mechanism": "administrators_group_membership",
            },
            warnings,
        )

    # Step 2: add to administrators. DSM accepts both ``add`` and
    # ``change`` here; we use ``add`` because it's the narrower verb
    # (no removes possible). ``name`` is a JSON array of users to add.
    add_body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Group.Member", method="add", version=1,
        params={
            "group": _ADMINISTRATORS_GROUP,
            "name": json.dumps([user]),
        },
    )
    warnings.extend(extract_warnings(add_body))

    return success_envelope(
        host,
        {
            "added": True,
            "user": user,
            "group": _ADMINISTRATORS_GROUP,
            "mechanism": "administrators_group_membership",
        },
        warnings,
    )


def _extract_is_admin(body: dict[str, Any], user: str) -> bool:
    """Pull ``users[0].is_admin`` out of an ``admin_check`` response.

    DSM has shipped at least two response shapes for this endpoint
    across the 7.x line:

      * ``data.users[].is_admin`` (with an optional ``name`` field per
        entry; the UI relies on this form).
      * ``data.is_admin`` (flat).

    We accept either and return ``False`` for any unexpected shape so
    a misparsed response falls through to the ``add`` call (which will
    no-op on DSM's side if the user is already in the group).
    """
    data = body.get("data") or {}
    users = data.get("users")
    if isinstance(users, list):
        for entry in users:
            if not isinstance(entry, dict):
                continue
            entry_name = entry.get("name")
            if entry_name is None or entry_name == user:
                return bool(entry.get("is_admin"))
    flat = data.get("is_admin")
    if isinstance(flat, bool):
        return flat
    return False


# ---------------------------------------------------------------------------
# Tool: ssh_set_port (Phase 3c)
# ---------------------------------------------------------------------------


# Port-validation thresholds
_MIN_USER_PORT = 1024
_MAX_PORT = 65535
_DEFAULT_SSH_PORT = 22

# Verification timeout for the new-port handshake. 10s is plenty for a
# DSM unit on a LAN; on a slow remote NAS we'd rather report
# ``verified=False`` (with the user's existing session intact as the
# escape hatch) than block the caller indefinitely.
_NEW_PORT_VERIFY_TIMEOUT = 10.0


def _validate_port(port: int, *, allow_default: bool, host: str | None = None) -> None:
    """Reject ports that fall outside the user range, with a port-22 carve-out.

    Port 22 specifically is refused unless the caller opts in via
    ``allow_default=True`` because it's a security-bad default we don't
    want anyone landing on by accident — every Synology-aimed scanner
    out there hits 22 first.
    """
    if not isinstance(port, int) or isinstance(port, bool):
        raise InvalidParam(
            "port must be an integer", host=host,
            details={"param": "port"},
        )
    if port == _DEFAULT_SSH_PORT:
        if not allow_default:
            raise InvalidParam(
                "port 22 is the well-known SSH default and is refused unless "
                "allow_default=True is passed explicitly",
                host=host,
                details={"param": "port", "value": port},
            )
        return
    if port < _MIN_USER_PORT or port > _MAX_PORT:
        raise InvalidParam(
            f"port must be in [{_MIN_USER_PORT}, {_MAX_PORT}] "
            f"(or 22 with allow_default=True); got {port}",
            host=host,
            details={"param": "port", "value": port},
        )


async def _detect_port_in_use(ssh: DSMSshClient, port: int) -> bool:
    """Return True iff some other listener is already bound to `port` on the host.

    Uses ``ss -lnt 'sport = :<port>'`` — busybox-ss on DSM supports the
    sport filter. If ss is unavailable we fall back to ``netstat -lnt``
    + a literal grep. Either way the contract is: TRUE means we saw an
    LISTEN row matching the port, FALSE means we did not.
    """
    cmd = (
        f"ss -lnt 'sport = :{port}' 2>/dev/null | "
        f"awk 'NR>1 && /LISTEN/ {{print $0}}' | head -1"
    )
    try:
        res = await ssh.run(cmd, check=False, timeout=10.0)
    except DSMSshError:
        # Fallback: netstat (busybox).
        try:
            res = await ssh.run(
                f"netstat -lnt 2>/dev/null | "
                f"awk '/LISTEN/ && $4 ~ /:{port}$/ {{print $0}}' | head -1",
                check=False, timeout=10.0,
            )
        except DSMSshError:
            # If both probes fail we err on the safe side and call the
            # port free — the DSM set call will fail loudly on the
            # server side if we got it wrong.
            return False
    return bool(res.stdout.strip())


def _terminal_set_payload(current: dict[str, Any], new_port: int) -> dict[str, Any]:
    """Build the ``SYNO.Core.Terminal.set`` params from the current state + new port.

    DSM 7.3.2's set endpoint demands the full configuration round-trip:
    enable_ssh, enable_telnet, forbid_console, ssh_port, plus the
    cipher/kex/mac arrays. We pass everything through unchanged except
    ssh_port so we don't accidentally disable any setting as a
    side-effect (see DESIGN.md §5.7 for the carry-forward rationale).

    ``current`` is the ``data`` sub-object from ``SYNO.Core.Terminal.get``.
    """
    payload: dict[str, Any] = {
        "enable_ssh": "true" if current.get("enable_ssh") else "false",
        "ssh_port": str(int(new_port)),
    }
    if "enable_telnet" in current:
        payload["enable_telnet"] = (
            "true" if current.get("enable_telnet") else "false"
        )
    if "forbid_console" in current:
        payload["forbid_console"] = (
            "true" if current.get("forbid_console") else "false"
        )
    # The cipher/kex/mac arrays — DSM accepts them JSON-encoded.
    for key in ("ssh_cipher", "ssh_kex", "ssh_mac"):
        arr = current.get(key)
        if isinstance(arr, list):
            payload[key] = json.dumps(arr)
    return payload


def _verify_ssh_on_port_sync(
    host_cfg: Any,
    port: int,
    password: str | None,
    timeout: float = _NEW_PORT_VERIFY_TIMEOUT,
) -> tuple[bool, str | None]:
    """Open a FRESH paramiko handshake to `host_cfg.ip:port` and close it.

    Returns ``(ok, error_message)``. We do not reuse the cached client
    because the whole point of the verify step is to prove the new port
    works from a CLEAN connection. The session is closed immediately
    after the handshake — we only need to know the daemon accepted us.

    Runs synchronously (paramiko blocks); the async caller offloads to
    a thread.
    """
    import paramiko  # local import keeps the module's import surface narrow

    client = paramiko.SSHClient()
    # No known_hosts file is fine for verify — the cached client
    # already enforces the system policy, this fresh handshake is
    # only checking "does the daemon answer".
    with contextlib.suppress(OSError):
        client.load_system_host_keys()
    connect_kwargs: dict[str, Any] = {
        "hostname": host_cfg.ip,
        "port": port,
        "username": host_cfg.effective_ssh_username,
        "timeout": timeout,
        "auth_timeout": timeout,
        "banner_timeout": timeout,
        "allow_agent": True,
        "look_for_keys": True,
    }
    if host_cfg.ssh_key_path:
        connect_kwargs["key_filename"] = host_cfg.ssh_key_path
    if password:
        connect_kwargs["password"] = password
    try:
        client.connect(**connect_kwargs)
    except (OSError, paramiko.SSHException) as exc:
        with contextlib.suppress(Exception):  # pragma: no cover - best effort
            client.close()
        return False, str(exc)
    with contextlib.suppress(Exception):  # pragma: no cover - best effort
        client.close()
    return True, None


async def _verify_ssh_on_port(
    host_cfg: Any, port: int, password: str | None,
) -> tuple[bool, str | None]:
    """Async wrapper around :func:`_verify_ssh_on_port_sync`."""
    import asyncio
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _verify_ssh_on_port_sync, host_cfg, port, password,
        _NEW_PORT_VERIFY_TIMEOUT,
    )


async def ssh_set_port(
    host: str, port: int, allow_default: bool = False, *, app_context,
) -> dict:
    """Change DSM's SSH listen port to `port`, with pre-flight + post-verify.

    Pre-flight:

      1. ``port`` must be in [1024, 65535] unless ``allow_default=True``
         is passed for port 22 (refused by default — port 22 is a
         security-bad target that every Synology-aimed scanner hits).
      2. ``ss -lnt`` over SSH MUST NOT find a LISTEN row on ``port``.
         If a different listener already has the port, refuse with
         ``category="port_already_in_use"``.
      3. If the current SSH port already equals ``port``, short-circuit
         with ``ok=True, data.changed=False, warnings=["already on this
         port"]``. No mutation, no verify step.

    Mutation: read the current ``SYNO.Core.Terminal.get`` state, mutate
    only ``ssh_port``, and send the FULL payload back via ``set``.
    DSM's set endpoint requires the round-trip; sending a partial
    payload risks disabling other settings as a side-effect.

    Post-change verification: open a NEW paramiko handshake to
    ``<host>:<new_port>``, 10s timeout. We do NOT revert if verify
    fails — the existing SSH session is the user's escape hatch and
    reverting would just compound the confusion. On verify-failure we
    return ``ok=True, data.changed=True, data.verified=False`` with a
    warning explaining the situation.

    Returns ``data = {old_port, new_port, changed: bool,
    verified: bool}`` plus the standard envelope.
    """
    _validate_port(port, allow_default=allow_default, host=host)

    # --- Pre-flight 1: read current Terminal state ---------------------------
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Terminal", method="get", version=3,
    )
    current = body.get("data") or {}
    current_port = _int_or_none(current.get("ssh_port"))
    warnings: list[str] = list(extract_warnings(body))

    # --- Pre-flight 2: idempotency -------------------------------------------
    if current_port == port:
        warnings.insert(0, "already on this port")
        return success_envelope(
            host,
            {
                "changed": False,
                "verified": True,
                "old_port": current_port,
                "new_port": port,
            },
            warnings,
        )

    # --- Pre-flight 3: port-in-use probe -------------------------------------
    ssh = get_ssh_client(app_context, host)
    if await _detect_port_in_use(ssh, port):
        return {
            "ok": False,
            "host": host,
            "data": {
                "category": "port_already_in_use",
                "port": port,
                "next_step": (
                    "pick a different port; the host already has a LISTEN "
                    "socket on this one"
                ),
            },
            "warnings": warnings,
        }

    # --- Mutation ------------------------------------------------------------
    set_params = _terminal_set_payload(current, port)
    set_body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Terminal", method="set", version=3,
        params=set_params,
    )
    warnings.extend(extract_warnings(set_body))

    # --- Post-change verify (fresh paramiko handshake) -----------------------
    host_cfg = app_context.config.get_host(host)
    verified, verify_err = await _verify_ssh_on_port(
        host_cfg, port, host_cfg.password,
    )
    if not verified:
        warnings.append(
            f"new port {port} did not respond within "
            f"{int(_NEW_PORT_VERIFY_TIMEOUT)}s — verify firewall and "
            "connectivity in a SEPARATE session before closing your "
            f"existing one (error: {verify_err})"
        )

    return success_envelope(
        host,
        {
            "changed": True,
            "verified": verified,
            "old_port": current_port,
            "new_port": port,
        },
        warnings,
    )


def _int_or_none(val: object) -> int | None:
    """Coerce DSM's mixed-int-or-string port values to an int."""
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
    "ssh_add_authorized_key",
    "ssh_enable_user_ssh",
    "ssh_remove_authorized_key",
    "ssh_set_port",
]
