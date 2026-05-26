# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Disk / volume / RAID inspection — READ-ONLY.

Mostly SSH-shelled because the web API exposes a thinner view than what
operators actually need (e.g., `/proc/mdstat` resync progress, per-disk
SMART summaries). See DESIGN.md §5.6.

Data sources:
  - SYNO.Storage.Volume / SYNO.Storage.Disk for the web API summary
  - `/proc/mdstat` over SSH for RAID resync state + ETA
  - `synodisk --enum` / `synodisk --get_sys_state` for SMART status
  - `syno_dsm_serial` for hardware serial / model
  - `df` / `synovolume` for filesystem usage
"""
from __future__ import annotations


async def list_volumes(host: str) -> dict:  # noqa: ARG001
    """TODO: volumes with fs, size, used, raid level, encryption state."""
    raise NotImplementedError


async def list_disks(host: str) -> dict:  # noqa: ARG001
    """TODO: physical disks with model, serial, slot, smart state, temp."""
    raise NotImplementedError


async def get_raid_state(host: str) -> dict:  # noqa: ARG001
    """TODO: parse /proc/mdstat. Surfaces resync %, speed, ETA per md device."""
    raise NotImplementedError


async def get_hardware_info(host: str) -> dict:  # noqa: ARG001
    """TODO: model, DSM version, serial, NIC list with MAC + link state."""
    raise NotImplementedError
