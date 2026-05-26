# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Network basics — READ-ONLY in MVP.

Wraps `SYNO.Core.Network.Interface` + `/sys/class/net/*` SSH reads and
`ethtool` for per-NIC driver/firmware detail. See DESIGN.md §5.8.

Key DSM quirks handled here:
  - DSM caches NIC speed in the web API; freshness is unreliable. We always
    cross-check via `cat /sys/class/net/<if>/speed` over SSH for canonical state.
  - Synology's `eth*` naming follows physical-card order, NOT the chassis label.
"""
from __future__ import annotations

import re
from typing import Any

from ._helpers import call_dsm, get_ssh_client, success_envelope
from .errors import DSMSshError
from .transport.http import extract_warnings
from .transport.ssh import DSMSshClient

# ----- web API summary ------------------------------------------------------


def _normalize_iface_web(raw: dict[str, Any]) -> dict[str, Any]:
    """Map DSM's web-API NIC entry to canonical schema."""
    return {
        "name": str(raw.get("id") or raw.get("device") or raw.get("name") or ""),
        "mac": str(raw.get("mac") or raw.get("hwaddr") or "").lower(),
        "mtu": _int_or_none(raw.get("mtu")),
        "ips": _extract_ips(raw),
        "state_web": _normalize_state(raw.get("status") or raw.get("link_status")),
        "speed_mbps_web": _int_or_none(raw.get("speed")),
        "type": str(raw.get("type") or raw.get("interface_type") or "ethernet"),
    }


def _extract_ips(raw: dict[str, Any]) -> list[str]:
    ips: list[str] = []
    direct = raw.get("ip")
    if isinstance(direct, str) and direct:
        ips.append(direct)
    if isinstance(direct, list):
        ips.extend(str(x) for x in direct if x)
    v6 = raw.get("ipv6")
    if isinstance(v6, list):
        for item in v6:
            if isinstance(item, dict):
                addr = item.get("address") or item.get("addr")
                if addr:
                    ips.append(str(addr))
            elif isinstance(item, str):
                ips.append(item)
    return ips


def _normalize_state(raw: object) -> str:
    if raw is None:
        return "unknown"
    s = str(raw).strip().lower()
    if s in {"up", "connected", "1", "active"}:
        return "up"
    if s in {"down", "disconnected", "0", "inactive"}:
        return "down"
    return s


# ----- SSH /sys/class/net cross-check --------------------------------------


async def _read_sysfs_for_iface(ssh: DSMSshClient, name: str) -> dict[str, Any]:
    """Read /sys/class/net/<name>/{address,speed,operstate,mtu,duplex,carrier}.

    Returns whatever is readable; missing files just become None.
    """
    fields = ("address", "speed", "operstate", "mtu", "duplex", "carrier")
    # Build a single shell command that prints `field=value` per line.
    parts = [
        f"echo {f}=$(cat /sys/class/net/{name}/{f} 2>/dev/null || echo \\?)"
        for f in fields
    ]
    cmd = " ; ".join(parts)
    try:
        result = await ssh.run(cmd, check=False, timeout=10.0)
    except DSMSshError:
        return {}
    out: dict[str, Any] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if v == "" or v == "?":
            continue
        out[k.strip()] = v
    return out


def _merge_iface(web: dict[str, Any], sysfs: dict[str, Any]) -> dict[str, Any]:
    """Combine web-API + sysfs data into the canonical schema."""
    speed_sys = _int_or_none(sysfs.get("speed"))
    speed_web = web.get("speed_mbps_web")
    # Prefer sysfs if it's a sane positive number; -1 from sysfs means link down.
    if speed_sys is not None and speed_sys > 0:
        speed = speed_sys
    elif speed_web is not None and speed_web > 0:
        speed = speed_web
    else:
        speed = None
    operstate = sysfs.get("operstate")
    if operstate:
        state = "up" if operstate.lower() == "up" else "down"
    else:
        state = web.get("state_web", "unknown")
    return {
        "name": web["name"],
        "mac": (sysfs.get("address") or web.get("mac") or "").lower(),
        "mtu": _int_or_none(sysfs.get("mtu")) or web.get("mtu"),
        "state": state,
        "speed_mbps": speed,
        "duplex": sysfs.get("duplex"),
        "carrier": _int_or_none(sysfs.get("carrier")),
        "ips": web.get("ips") or [],
        "type": web.get("type"),
        "_web_speed_mbps": speed_web,
        "_sysfs_speed_mbps": speed_sys,
    }


async def network_list_interfaces(host: str, *, app_context) -> dict:
    """List interfaces with name/mac/mtu/state/speed/IPs (web + sysfs merged)."""
    body = await call_dsm(
        app_context, host,
        api="SYNO.Core.Network.Interface", method="list", version=1,
    )
    data = body.get("data") or {}
    raw_list = data.get("interfaces") or data.get("ifaces") or data.get("items") or []
    if not isinstance(raw_list, list):
        raw_list = []
    web_ifaces = [_normalize_iface_web(i) for i in raw_list if isinstance(i, dict)]
    # Cross-check via sysfs over SSH.
    ssh = get_ssh_client(app_context, host)
    merged: list[dict[str, Any]] = []
    for iface in web_ifaces:
        if not iface["name"]:
            continue
        sysfs = await _read_sysfs_for_iface(ssh, iface["name"])
        merged.append(_merge_iface(iface, sysfs))
    return success_envelope(host, {"interfaces": merged}, extract_warnings(body))


# ----- per-interface detail (ethtool) --------------------------------------


_ETHTOOL_DRIVER_RE = re.compile(r"^driver:\s*(?P<v>.+)$", re.MULTILINE)
_ETHTOOL_VERSION_RE = re.compile(r"^version:\s*(?P<v>.+)$", re.MULTILINE)
_ETHTOOL_FW_RE = re.compile(r"^firmware-version:\s*(?P<v>.+)$", re.MULTILINE)
_ETHTOOL_BUS_RE = re.compile(r"^bus-info:\s*(?P<v>.+)$", re.MULTILINE)


async def _ethtool_for_iface(ssh: DSMSshClient, name: str) -> dict[str, Any]:
    """Return driver/firmware metadata from `ethtool -i <name>`."""
    try:
        result = await ssh.run(f"ethtool -i {name}", check=False, timeout=10.0)
    except DSMSshError:
        return {}
    if not result.ok:
        return {}
    blob = result.stdout
    return {
        "driver": _first_match(_ETHTOOL_DRIVER_RE, blob),
        "driver_version": _first_match(_ETHTOOL_VERSION_RE, blob),
        "firmware_version": _first_match(_ETHTOOL_FW_RE, blob),
        "bus_info": _first_match(_ETHTOOL_BUS_RE, blob),
    }


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group("v").strip() if m else None


async def network_get_interface(host: str, name: str, *, app_context) -> dict:
    """Full detail for one interface: web API + sysfs + ethtool driver/firmware."""
    listing = await network_list_interfaces(host, app_context=app_context)
    interfaces = listing["data"]["interfaces"]
    found = next((i for i in interfaces if i["name"] == name), None)
    if found is None:
        from .errors import InvalidParam

        raise InvalidParam(
            f"interface {name!r} not found on host {host!r}",
            host=host,
            details={"available": [i["name"] for i in interfaces]},
        )
    ssh = get_ssh_client(app_context, host)
    ethtool_info = await _ethtool_for_iface(ssh, name)
    detail = {**found, "ethtool": ethtool_info}
    # Surface a warning if sysfs and web disagree on speed (canonical = sysfs).
    warnings: list[str] = list(listing.get("warnings") or [])
    if (
        found.get("_web_speed_mbps") is not None
        and found.get("_sysfs_speed_mbps") is not None
        and found["_web_speed_mbps"] != found["_sysfs_speed_mbps"]
        and found["_sysfs_speed_mbps"] > 0
    ):
        warnings.append(
            f"speed mismatch on {name}: web={found['_web_speed_mbps']}Mb/s, "
            f"sysfs={found['_sysfs_speed_mbps']}Mb/s (sysfs is canonical)"
        )
    return success_envelope(host, detail, warnings)


# ----- helpers --------------------------------------------------------------


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
