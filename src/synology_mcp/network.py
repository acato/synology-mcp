# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Network basics — READ-ONLY in MVP.

Wraps `SYNO.Core.Network` + `/sys/class/net/*` SSH reads. See DESIGN.md §5.8.

Key DSM quirks handled here:
  - DSM caches NIC speed in the web API; freshness is unreliable. We always
    cross-check via `cat /sys/class/net/<if>/speed` over SSH for canonical state.
  - Synology's `eth*` naming follows the physical card order, NOT the
    label printed on the chassis. eth0 may be `LAN 1` on one model and
    a 10G card on another. Tools surface BOTH the eth name and any
    discoverable chassis label.
"""
from __future__ import annotations


async def list_interfaces(host: str) -> dict:  # noqa: ARG001
    """TODO: NIC list: name, MAC, MTU, state (up/down), speed/duplex."""
    raise NotImplementedError


async def get_interface(host: str, name: str) -> dict:  # noqa: ARG001
    """TODO: per-interface detail including ip addrs + carrier source."""
    raise NotImplementedError
