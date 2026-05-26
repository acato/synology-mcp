# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""SSH key + port + service management.

Mix of web API (port, service enable) and direct SSH ops (authorized_keys
edits). See DESIGN.md §5.7.

Key DSM quirks handled here:
  - SFTP subsystem is disabled by default: `paramiko.open_sftp()` returns
    `Channel closed`. authorized_keys writes go via either:
      (a) `printf '%s' <base64> | base64 -d > /tmp/key && sudo mv ...`
          over `exec_command` (preferred for small files), or
      (b) `scp` over the same SSH credentials (works because scp uses the
          shell subsystem, not sftp).
    See `feedback_dsm_no_sftp.md`.
  - User home dir must exist before authorized_keys can be written. If
    User Home is off, calls here surface that and refer to `user_home.enable`.
  - The SSH service enable also has a per-user `app-permissions` flag that
    has to be flipped or the user can shell-in only as `admin`.
"""
from __future__ import annotations


async def get_ssh_state(host: str) -> dict:  # noqa: ARG001
    """TODO: ssh service enabled? port? per-user app-permissions state?"""
    raise NotImplementedError


async def set_ssh_port(host: str, port: int) -> dict:  # noqa: ARG001
    """TODO: change DSM SSH port via SYNO.Core.Terminal. Warns about firewall."""
    raise NotImplementedError


async def enable_user_ssh(host: str, user: str) -> dict:  # noqa: ARG001
    """TODO: grant SSH app-permission to `user`."""
    raise NotImplementedError


async def add_authorized_key(host: str, user: str, pubkey: str, comment: str = "") -> dict:  # noqa: ARG001
    """TODO: append pubkey to /volume*/homes/<user>/.ssh/authorized_keys.

    Idempotent (skip if pubkey bytes already present). Uses base64-over-exec
    instead of SFTP. Requires User Home enabled; refers to user_home.enable
    if not.
    """
    raise NotImplementedError


async def list_authorized_keys(host: str, user: str) -> dict:  # noqa: ARG001
    """TODO: list authorized keys with comment, key type, fingerprint."""
    raise NotImplementedError


async def remove_authorized_key(host: str, user: str, fingerprint: str) -> dict:  # noqa: ARG001
    """TODO: remove a key by SHA256 fingerprint."""
    raise NotImplementedError
