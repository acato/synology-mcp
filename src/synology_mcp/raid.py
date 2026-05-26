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

from . import network as _network
from ._helpers import call_dsm, get_ssh_client, success_envelope
from .transport.http import extract_warnings

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _coerce_mac(raw: object) -> str | None:
    """Normalise a MAC string. Returns the lowercase address or None.

    DSM and sysfs both emit ``xx:xx:xx:xx:xx:xx`` form, but the web API
    sometimes hands back the empty string for interfaces it doesn't track
    (pppoe, virtual). Use ``None`` (not ``""``) for "genuinely unavailable".
    """
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if not s:
        return None
    if not _MAC_RE.match(s):
        return None
    return s

# --- Unified storage payload ------------------------------------------------
#
# DSM 7.3 returns volumes, disks, and storage pools from a single endpoint:
#   SYNO.Storage.CGI.Storage method=load_info version=1
# We fetch that once and serve raid_list_volumes / raid_list_disks from the
# same body. (Per-call caching could be added later if it ever becomes hot.)


async def _load_storage_info(app_context, host: str) -> dict[str, Any]:
    """Fetch the unified DSM storage payload (volumes + disks + pools)."""
    body = await call_dsm(
        app_context, host,
        api="SYNO.Storage.CGI.Storage", method="load_info", version=1,
    )
    return body


# --- Volumes ----------------------------------------------------------------


def _pool_index(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build pool_id -> pool record map so we can look up RAID type per volume."""
    pools = data.get("storagePools") or []
    if not isinstance(pools, list):
        return {}
    return {str(p.get("id") or p.get("num_id") or ""): p for p in pools if isinstance(p, dict)}


def _normalize_volume(raw: dict[str, Any], pools: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Map DSM 7.3 volume JSON into the canonical schema (DESIGN.md §5.6)."""
    # `vol_path` is the canonical name on modern DSM ("/volume1"). Older fields
    # kept as fallbacks for forward/backward compatibility.
    name = (
        raw.get("vol_path")
        or raw.get("display_name")
        or raw.get("volume_path")
        or raw.get("name")
        or raw.get("id")
        or ""
    )
    fs = raw.get("fs_type") or raw.get("filesystem") or raw.get("fs") or "unknown"
    size = raw.get("size") if isinstance(raw.get("size"), dict) else None
    if size is not None:
        size_total = _int_or_none(size.get("total"))
        size_used = _int_or_none(size.get("used"))
    else:
        size_total = _int_or_none(raw.get("size_total") or raw.get("total_size"))
        size_used = _int_or_none(raw.get("size_used") or raw.get("used_size"))
    size_free = None
    if size_total is not None and size_used is not None:
        size_free = max(size_total - size_used, 0)
    # `device_type` carries the protection scheme on DSM 7.3
    # (e.g. shr_with_2_disk_protect, raid_6, raid_5, raid_1, basic, jbod).
    raid_level = (
        raw.get("device_type")
        or raw.get("raid_type")
        or raw.get("raidType")
        or raw.get("raid_level")
        or "unknown"
    )
    # If the volume sits on a pool with a different raidType, surface that too.
    pool_path = raw.get("pool_path")
    if pool_path and (pool := pools.get(str(pool_path))):
        # Prefer the pool's device_type when the volume row is generic ("multiple").
        pool_device_type = pool.get("device_type")
        if pool_device_type and raid_level in {"multiple", "unknown", ""}:
            raid_level = pool_device_type
    encrypted = bool(raw.get("is_encrypted") or raw.get("encrypted") or raw.get("is_encrypt"))
    status = raw.get("status") or raw.get("space_status", {}).get("status") if isinstance(raw.get("space_status"), dict) else raw.get("status")
    status = status or "unknown"
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
    body = await _load_storage_info(app_context, host)
    data = body.get("data") or {}
    raw_list = data.get("volumes") or []
    if not isinstance(raw_list, list):
        raw_list = []
    pools = _pool_index(data)
    volumes = [_normalize_volume(v, pools) for v in raw_list if isinstance(v, dict)]
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
    # DSM 7.3 uses `id` (e.g. "sata1") as the slot identifier; older
    # versions used `disk_id`. `slot_id` / `slot` is the physical bay number.
    slot = (
        raw.get("id")
        or raw.get("disk_id")
        or raw.get("slot_id")
        or raw.get("slot")
        or raw.get("name")
        or raw.get("device")
        or ""
    )
    container = raw.get("container")
    if isinstance(container, dict):
        role = container.get("type") or "unknown"
    else:
        role = raw.get("container_type") or raw.get("disk_type") or raw.get("role") or "unknown"
    return {
        "slot": str(slot),
        "model": str(raw.get("model") or raw.get("model_name") or "unknown").strip(),
        "serial": str(raw.get("serial") or raw.get("ui_serial") or raw.get("serial_num") or "").strip(),
        "capacity_bytes": _int_or_none(raw.get("size_total") or raw.get("capacity")),
        "smart_state": _normalize_smart(raw.get("smart_status") or raw.get("status")),
        "temperature_c": _int_or_none(raw.get("temp") or raw.get("temperature")),
        "role": str(role),
    }


async def raid_list_disks(host: str, *, app_context) -> dict:
    """List physical disks with model, serial, slot, SMART state, temp."""
    body = await _load_storage_info(app_context, host)
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


def _normalize_cpu_model(data: dict[str, Any]) -> str:
    """Synthesize a human cpu_model string from DSM 7.3's separate fields."""
    parts = [
        str(data.get("cpu_vendor", "")).strip(),
        str(data.get("cpu_family", "")).strip(),
        str(data.get("cpu_series", "")).strip(),
    ]
    label = " ".join(p for p in parts if p)
    if label:
        return label
    # Fallback for older DSM payloads.
    return str(data.get("cpu_clock_speed") or "unknown")


def _normalize_dsm_build(data: dict[str, Any]) -> str:
    """Extract the build number out of `firmware_ver` (e.g. 'DSM 7.3.2-86009 Update 3')."""
    raw_build = data.get("buildnumber") or data.get("smallfix_version")
    if raw_build:
        return str(raw_build)
    fw = data.get("firmware_ver") or ""
    if isinstance(fw, str) and "-" in fw:
        tail = fw.split("-", 1)[1]
        # Strip trailing " Update N" or whitespace.
        return tail.split(" ", 1)[0]
    return "unknown"


async def raid_hardware_info(host: str, *, app_context) -> dict:
    """Return model, DSM build, serial, RAM, CPU, and NIC table.

    NIC table is delegated to :func:`network.network_list_interfaces` — same
    code path as `network_list_interfaces` so MAC addresses (which come from
    `/sys/class/net/<if>/address` over SSH, NOT from the web API) are filled
    in consistently. `nics[].mac` is a lowercase ``xx:xx:xx:xx:xx:xx`` string
    or ``None`` if genuinely unavailable — never the empty string.
    """
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.System", method="info", version=1,
    )
    data = body.get("data") or {}
    # DSM 7.3 reports ram_size in MB. Older builds used bytes in `ram`.
    ram_mb = _int_or_none(data.get("ram_size"))
    ram_bytes: int | None
    if ram_mb is not None:
        # If the value looks too big (≥ 1 << 20) treat it as already-bytes; else assume MB.
        ram_bytes = ram_mb if ram_mb >= (1 << 24) else ram_mb * 1024 * 1024
    else:
        ram_bytes = _int_or_none(data.get("ram"))
    info: dict[str, Any] = {
        "model": str(data.get("model") or data.get("upnp_model_name") or "unknown"),
        "serial": str(data.get("serial") or data.get("system_serial") or "unknown"),
        "dsm_version": str(data.get("firmware_ver") or data.get("version") or "unknown"),
        "dsm_build": _normalize_dsm_build(data),
        "cpu_model": _normalize_cpu_model(data),
        "cpu_cores": _int_or_none(data.get("cpu_cores") or data.get("cpu_num")),
        "ram_total_bytes": ram_bytes,
        "nics": [],
    }
    warnings: list[str] = list(extract_warnings(body))
    # NIC table — reuse network_list_interfaces (web API + sysfs cross-check)
    # so MACs and link state come from the same canonical source.
    try:
        nic_envelope = await _network.network_list_interfaces(
            host, app_context=app_context,
        )
    except Exception:
        nic_envelope = None
    if nic_envelope is not None:
        for iface in nic_envelope.get("data", {}).get("interfaces", []):
            if not isinstance(iface, dict):
                continue
            ips = iface.get("ips") or []
            primary_ip = next((str(ip) for ip in ips if ip), "")
            info["nics"].append(
                {
                    "name": str(iface.get("name") or ""),
                    "mac": _coerce_mac(iface.get("mac")),
                    "speed_mbps": _int_or_none(iface.get("speed_mbps")),
                    "ip": primary_ip,
                    "type": str(iface.get("type") or "ethernet"),
                    "status": str(iface.get("state") or ""),
                }
            )
        # Surface any warnings the network layer raised (e.g. speed mismatch).
        warnings.extend(nic_envelope.get("warnings", []) or [])
    return success_envelope(host, info, warnings)


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
