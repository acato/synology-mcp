# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""SSH key + service management — Phase 3a (write tools).

This module ships the write half of the ``ssh_*`` tool family:

  * :func:`ssh_add_authorized_key`    — Phase 3a, this commit.
  * :func:`ssh_remove_authorized_key` — Phase 3a, follow-up commit.
  * :func:`ssh_enable_user_ssh`       — Phase 3a, follow-up commit.

Read-only ``ssh_get_state`` / ``ssh_list_authorized_keys`` and
``ssh_set_port`` ship in a later phase.

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
import shlex

from . import user_home as _user_home
from ._helpers import get_ssh_client, success_envelope
from .errors import DSMSshError, InvalidParam
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


__all__ = ["ssh_add_authorized_key"]
