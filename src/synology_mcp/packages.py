# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""DSM package management.

Wraps `SYNO.Core.Package` family endpoints. See DESIGN.md §5.2.

Key DSM quirks handled here:
  - `install_from_server` can fail with opaque errors for some packages even
    when the package exists in the repo. Fallback path: download the `.spk`
    via `SYNO.Core.Package.Installation.Download`, then
    `SYNO.Core.Package.Installation.install` against the local upload.
  - `synopkg status <pkg>` lies for ContainerManager (reports `stop` while
    dockerd is healthy). For ContainerManager specifically, verify via
    `docker info` over SSH instead. See `feedback_dsm_cm_status.md`.
"""
from __future__ import annotations


async def list_packages(host: str) -> dict:  # noqa: ARG001
    """TODO: list installed packages with version + status."""
    raise NotImplementedError


async def get_package_status(host: str, package_id: str) -> dict:  # noqa: ARG001
    """TODO: status of one package; applies ContainerManager workaround."""
    raise NotImplementedError


async def install_package(host: str, package_id: str, version: str | None = None) -> dict:  # noqa: ARG001
    """TODO: install with `install_from_server`, fall back to `.spk` upload.

    See DESIGN.md §5.2 for full signature + error model.
    """
    raise NotImplementedError


async def uninstall_package(host: str, package_id: str) -> dict:  # noqa: ARG001
    """TODO: uninstall and confirm via package list."""
    raise NotImplementedError
