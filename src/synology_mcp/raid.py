# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Disk / volume / RAID inspection — READ-ONLY.

Mix of web API and SSH-shell because the web API exposes a thinner view than
operators need (e.g., `/proc/mdstat` resync progress, ethtool detail).
See DESIGN.md §5.6.

Data sources:
  - SYNO.Storage.CGI.Volume `list` for volume summary
  - SYNO.Storage.CGI.HddMan `enumerate` for physical disks
  - SYNO.Core.System `info` for hardware/model/RAM/CPU/NIC table
  - `/proc/mdstat` via SSH for RAID resync state + ETA
"""
from __future__ import annotations

import re
from typing import Any

from ._helpers import call_dsm, get_ssh_client, success_envelope
from .transport.http import extract_warnings

# --- Volumes ----------------------------------------------------------------


def _normalize_volume(raw: dict[str, Any]) -> dict[str, Any]:
    """Map DSM volume JSON into the canonical schema (DESIGN.md §5.6)."""
    # DSM uses different field names across versions: try a few aliases.
    name = (
        raw.get("display_name")
        or raw.get("volume_path")
        or raw.get("name")
        or raw.get("id")
        or ""
    )
    fs = raw.get("fs_type") or raw.get("filesystem") or raw.get("fs") or "unknown"
    size_total = _int_or_none(raw.get("size_total") or raw.get("total_size") or raw.get("size"))
    size_used = _int_or_none(raw.get("size_used") or raw.get("used_size") or raw.get("used"))
    size_free = None
    if size_total is not None and size_used is not None:
        size_free = max(size_total - size_used, 0)
    raid_level = raw.get("raid_type") or raw.get("raid_level") or raw.get("raid") or "unknown"
    encrypted = bool(raw.get("encrypted") or raw.get("is_encrypt") or False)
    status = raw.get("status") or raw.get("state") or "unknown"
    return {
        "name": str(name),
        "fs": str(fs),
        "size_total_bytes": size_total,
        "size_used_bytes": size_used,
        "size_free_bytes": size_free,
        "raid_level": str(raid_level),
        "encrypted": encrypted,
        "status": str(status),
    }


async def raid_list_volumes(host: str, *, app_context) -> dict:
    """List volumes with name, fs, size, raid level, encryption, status."""
    body = await call_dsm(
        app_context, host,
        api="SYNO.Storage.CGI.Volume", method="list", version=1,
    )
    data = body.get("data") or {}
    raw_list = data.get("volumes") or data.get("data") or data.get("items") or []
    if not isinstance(raw_list, list):
        raw_list = []
    volumes = [_normalize_volume(v) for v in raw_list if isinstance(v, dict)]
    return success_envelope(host, {"volumes": volumes}, extract_warnings(body))


# --- Physical disks ---------------------------------------------------------


_SMART_OK = {"normal", "healthy", "good", "0", "ok"}
_SMART_WARN = {"warning", "attention", "1", "warn"}
_SMART_FAIL = {"failing", "critical", "fail", "2", "crashed"}


def _normalize_smart(raw: object) -> str:
    if raw is None:
        return "unknown"
    s = str(raw).strip().lower()
    if s in _SMART_OK:
        return "healthy"
    if s in _SMART_WARN:
        return "warning"
    if s in _SMART_FAIL:
        return "failing"
    return s or "unknown"


def _normalize_disk(raw: dict[str, Any]) -> dict[str, Any]:
    slot = (
        raw.get("disk_id")
        or raw.get("slot")
        or raw.get("name")
        or raw.get("device")
        or ""
    )
    return {
        "slot": str(slot),
        "model": str(raw.get("model") or raw.get("model_name") or "unknown").strip(),
        "serial": str(raw.get("serial") or raw.get("serial_num") or "").strip(),
        "capacity_bytes": _int_or_none(raw.get("capacity") or raw.get("size_total")),
        "smart_state": _normalize_smart(raw.get("smart_status") or raw.get("status")),
        "temperature_c": _int_or_none(raw.get("temp") or raw.get("temperature")),
        "role": str(raw.get("container_type") or raw.get("disk_type") or raw.get("role") or "unknown"),
    }


async def raid_list_disks(host: str, *, app_context) -> dict:
    """List physical disks with model, serial, slot, SMART state, temp."""
    body = await call_dsm(
        app_context, host,
        api="SYNO.Storage.CGI.HddMan", method="enumerate", version=1,
    )
    data = body.get("data") or {}
    raw_list = data.get("disks") or data.get("hdd_info") or data.get("items") or []
    if not isinstance(raw_list, list):
        raw_list = []
    disks = [_normalize_disk(d) for d in raw_list if isinstance(d, dict)]
    return success_envelope(host, {"disks": disks}, extract_warnings(body))


# --- /proc/mdstat parsing ---------------------------------------------------


_MD_HEADER_RE = re.compile(
    r"^(?P<dev>md\d+)\s*:\s*(?P<state>\S+)\s+(?P<level>\S+)\s+(?P<members>.+)$"
)
_MEMBER_RE = re.compile(r"(?P<disk>\S+?)\[(?P<idx>\d+)\](?:\((?P<flag>[FSR])\))?")
_RESYNC_RE = re.compile(
    r"\[(?P<bar>[=>.]+)\]\s+(?:resync|recovery|reshape|check)\s*=\s*"
    r"(?P<pct>[\d.]+)%\s+\((?P<done>\d+)/(?P<total>\d+)\)\s+"
    r"finish=(?P<eta_min>[\d.]+)min\s+speed=(?P<speed>\d+)K/sec",
    re.IGNORECASE,
)
_STATUS_RE = re.compile(r"\[(?P<u>[U_]+)\]")


def parse_mdstat(text: str) -> list[dict[str, Any]]:
    """Parse the output of `cat /proc/mdstat` into per-md-device records.

    Returns one dict per `md<N>` device. State is `resyncing`/`recovering`/`clean`/
    `degraded` depending on what mdstat reports.
    """
    out: list[dict[str, Any]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _MD_HEADER_RE.match(line.strip())
        if not m:
            i += 1
            continue
        dev = m.group("dev")
        state_word = m.group("state")  # 'active' or 'inactive'
        members_blob = m.group("members")
        # 'level' captured here is actually the next token after state; it may be e.g. 'raid6' or 'raid1'.
        # Some kernels print order: "md2 : active raid6 sdb3[1] sdc3[2] ..."
        # Re-parse by splitting tokens after state.
        tokens = members_blob.split()
        # The first token in members_blob is the RAID level if state == 'active'/'inactive'.
        if tokens and tokens[0].startswith("raid"):
            level = tokens[0]
            tokens = tokens[1:]
        else:
            level = m.group("level")
            tokens = members_blob.split()
        members: list[dict[str, Any]] = []
        for tok in tokens:
            mm = _MEMBER_RE.match(tok)
            if not mm:
                continue
            members.append(
                {
                    "disk": mm.group("disk"),
                    "index": int(mm.group("idx")),
                    "flag": mm.group("flag"),  # 'F'=faulty, 'S'=spare, 'R'=replacement
                }
            )
        # Look at the following lines until the next blank line or md header.
        resync_pct: float | None = None
        resync_speed: int | None = None
        resync_eta: int | None = None
        ud_status: str | None = None
        action: str | None = None
        j = i + 1
        while j < len(lines):
            sub = lines[j].strip()
            if sub == "" or _MD_HEADER_RE.match(sub):
                break
            sm = _STATUS_RE.search(sub)
            if sm:
                ud_status = sm.group("u")
            rm = _RESYNC_RE.search(sub)
            if rm:
                resync_pct = float(rm.group("pct"))
                resync_speed = int(rm.group("speed")) * 1024  # KB/s → B/s? Keep KB/s instead.
                # The user-visible field is kbps:
                resync_speed = int(rm.group("speed"))
                resync_eta = int(float(rm.group("eta_min")) * 60)
                # Detect action keyword: resync/recovery/check/reshape.
                low = sub.lower()
                for kw in ("resync", "recovery", "reshape", "check"):
                    if kw in low:
                        action = kw
                        break
            j += 1
        i = j

        # Synthesize state.
        if resync_pct is not None:
            md_state = "resyncing" if action != "recovery" else "recovering"
        elif ud_status is not None and "_" in ud_status:
            md_state = "degraded"
        elif state_word == "active":
            md_state = "clean"
        else:
            md_state = state_word

        out.append(
            {
                "device": dev,
                "level": level,
                "state": md_state,
                "resync_pct": resync_pct,
                "resync_speed_kbps": resync_speed,
                "resync_eta_seconds": resync_eta,
                "ud_status": ud_status,  # e.g. "UUUU" or "U_UU"
                "action": action,
                "members": members,
            }
        )
    return out


async def raid_state(host: str, *, app_context) -> dict:
    """Parse /proc/mdstat over SSH and return per-md state + resync progress."""
    ssh = get_ssh_client(app_context, host)
    result = await ssh.run("cat /proc/mdstat", check=True, timeout=10.0)
    devices = parse_mdstat(result.stdout)
    return success_envelope(host, {"devices": devices})


# --- Hardware info ----------------------------------------------------------


async def raid_hardware_info(host: str, *, app_context) -> dict:
    """Return model, DSM build, serial, RAM, CPU, and NIC table."""
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.System", method="info", version=1,
    )
    data = body.get("data") or {}
    info: dict[str, Any] = {
        "model": str(data.get("model") or data.get("upnp_model_name") or "unknown"),
        "serial": str(data.get("serial") or data.get("system_serial") or "unknown"),
        "dsm_version": str(data.get("firmware_ver") or data.get("version") or "unknown"),
        "dsm_build": str(data.get("buildnumber") or data.get("smallfix_version") or "unknown"),
        "cpu_model": str(data.get("cpu_clock_speed") or data.get("cpu_family") or "unknown"),
        "cpu_cores": _int_or_none(data.get("cpu_cores") or data.get("cpu_num")),
        "ram_total_bytes": _int_or_none(data.get("ram") or data.get("ram_size")),
        "nics": [],
    }
    # NIC table — DSM puts it under different keys.
    nics_raw = data.get("nic") or data.get("network") or data.get("interfaces") or []
    if isinstance(nics_raw, list):
        for n in nics_raw:
            if not isinstance(n, dict):
                continue
            info["nics"].append(
                {
                    "name": str(n.get("name") or n.get("device") or ""),
                    "mac": str(n.get("mac") or n.get("hardware_address") or ""),
                    "speed_mbps": _int_or_none(n.get("speed")),
                    "ip": str(n.get("ip") or n.get("addr") or ""),
                }
            )
    return success_envelope(host, info, extract_warnings(body))


# --- Helpers ----------------------------------------------------------------


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
