# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Shared folder lifecycle.

Wraps `SYNO.Core.Share`. See DESIGN.md §5.5.

Key DSM quirks handled here:
  - Some share names are reserved by DSM for package use (e.g., `music`,
    `photo`, `video`, `NetBackup`). `synoshare --add` refuses these but
    they CAN exist as plain directories on /volume1 and be rsync-mirrored.
    `create_share` should detect and surface this clearly.
  - ACL reads return a binary blob in some DSM versions; we expose a
    decoded view via the `enumerate` method where available.
"""
from __future__ import annotations


async def list_shares(host: str) -> dict:  # noqa: ARG001
    """TODO: list shared folders with volume, size, encrypted flag."""
    raise NotImplementedError


async def create_share(host: str, name: str, volume: str, **opts: object) -> dict:  # noqa: ARG001
    """TODO: create a share. Surfaces reserved-name conflicts explicitly."""
    raise NotImplementedError


async def get_share_acl(host: str, name: str) -> dict:  # noqa: ARG001
    """TODO: read share ACL (users, groups, permissions). Decoded view."""
    raise NotImplementedError


async def get_share_snapshot_config(host: str, name: str) -> dict:  # noqa: ARG001
    """TODO: read snapshot retention/schedule for a share."""
    raise NotImplementedError
