# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""MCP server entrypoint.

Wires up the MCP stdio server, registers tools from each Phase-1 module
(`auth`, `raid`, `network`), and owns the per-host session cache + config
loader.

See DESIGN.md §2 (Architecture) and §5 (Tool Surface).
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import (
    auth,
    network,
    packages,
    raid,
    shares,
    snapshot_replication,
    ssh,
    user_home,
)
from .config import Config, load_config
from .errors import DSMError
from .session import SessionCache

logger = logging.getLogger("synology_mcp")


@dataclass
class AppContext:
    """Per-process app state passed implicitly to every tool via closure."""

    config: Config
    cache: SessionCache = field(default_factory=SessionCache)


def build_app(config: Config | None = None) -> tuple[FastMCP, AppContext]:
    """Construct the FastMCP server with Phase-1 tools registered.

    Returns the server + the AppContext so tests can introspect cache state.
    """
    if config is None:
        config = load_config()
    ctx = AppContext(config=config)
    mcp = FastMCP(
        "synology-mcp",
        instructions=(
            "Tools for inspecting and managing Synology DSM appliances. "
            "All tools take a `host` parameter matching a host defined in "
            "the config file (`~/.config/synology-mcp/config.toml`) or via "
            "`SYNOLOGY_MCP_<HOST>_*` environment variables. "
            "Phases 1+2 expose read-only auth, raid, network, packages, "
            "user_home, shares, and snapshot_replication tools. Phase 3a "
            "adds three SSH write tools (ssh_add_authorized_key, "
            "ssh_remove_authorized_key, ssh_enable_user_ssh)."
        ),
    )

    # --- auth -------------------------------------------------------------

    @mcp.tool(description="Force a fresh login to the named Synology host.")
    async def auth_login(host: str) -> dict:
        return await _safe(auth.auth_login(host, app_context=ctx))

    @mcp.tool(description="Invalidate the cached DSM session for the named host.")
    async def auth_logout(host: str) -> dict:
        return await _safe(auth.auth_logout(host, app_context=ctx))

    @mcp.tool(
        description="Return the cached session descriptor for the host "
        "(triggers a login if no session is cached)."
    )
    async def auth_whoami(host: str) -> dict:
        return await _safe(auth.auth_whoami(host, app_context=ctx))

    # --- raid -------------------------------------------------------------

    @mcp.tool(description="List volumes with fs, size, RAID level, encryption, status.")
    async def raid_list_volumes(host: str) -> dict:
        return await _safe(raid.raid_list_volumes(host, app_context=ctx))

    @mcp.tool(
        description="List physical disks with slot, model, serial, capacity, "
        "SMART state, temperature, and role."
    )
    async def raid_list_disks(host: str) -> dict:
        return await _safe(raid.raid_list_disks(host, app_context=ctx))

    @mcp.tool(
        description="Parse /proc/mdstat over SSH and return per-md device "
        "state, resync percentage, speed, ETA, and member disks."
    )
    async def raid_state(host: str) -> dict:
        return await _safe(raid.raid_state(host, app_context=ctx))

    @mcp.tool(
        description="Return hardware info: model, DSM build, serial, RAM, "
        "CPU, and NIC table."
    )
    async def raid_hardware_info(host: str) -> dict:
        return await _safe(raid.raid_hardware_info(host, app_context=ctx))

    # --- network ----------------------------------------------------------

    @mcp.tool(
        description="List network interfaces with name, MAC, MTU, state, "
        "speed/duplex, and IP addresses (web API + sysfs merged)."
    )
    async def network_list_interfaces(host: str) -> dict:
        return await _safe(network.network_list_interfaces(host, app_context=ctx))

    @mcp.tool(
        description="Full detail for one network interface, including driver "
        "and firmware via ethtool over SSH."
    )
    async def network_get_interface(host: str, name: str) -> dict:
        return await _safe(network.network_get_interface(host, name, app_context=ctx))

    # --- packages ---------------------------------------------------------

    @mcp.tool(
        description="List installed packages with id, name, version, status, "
        "and install_type. Status is derived from synopkg over SSH (web API "
        "does not expose it). ContainerManager rows carry a docker_health "
        "boolean derived from `docker info`."
    )
    async def packages_list(host: str) -> dict:
        return await _safe(packages.packages_list(host, app_context=ctx))

    @mcp.tool(
        description="Return detailed status for one installed package "
        "(version, status, install_path, last_started_at). ContainerManager "
        "also returns docker_health and a docker info summary."
    )
    async def packages_status(host: str, package_id: str) -> dict:
        return await _safe(packages.packages_status(host, package_id, app_context=ctx))

    # --- user_home --------------------------------------------------------

    @mcp.tool(
        description="Cross-check User Home is enabled across three signals: "
        "web API, /etc/synoinfo.conf, and the /var/services/homes symlink. "
        "Surfaces disagreement (the DSM 7.3 silent-no-op pattern) as a warning."
    )
    async def user_home_is_enabled(host: str) -> dict:
        return await _safe(user_home.user_home_is_enabled(host, app_context=ctx))

    # --- shares -----------------------------------------------------------

    @mcp.tool(
        description="List shared folders with volume, encryption, quota, "
        "ACL flags, and recycle-bin / CoW state."
    )
    async def shares_list(host: str) -> dict:
        return await _safe(shares.shares_list(host, app_context=ctx))

    @mcp.tool(
        description="Decoded ACL for one share: local users + local groups + "
        "system entries, each tagged RW/RO/NO/ADMIN/CUSTOM. Partial views "
        "(per-type 403) are returned with a warning rather than failing."
    )
    async def shares_get_acl(host: str, name: str) -> dict:
        return await _safe(shares.shares_get_acl(host, name, app_context=ctx))

    @mcp.tool(
        description="Btrfs snapshot listing for a share. DSM 7.3 does NOT "
        "expose snapshot schedule/retention via web API — only the historical "
        "snapshot list is returned (schedule/retention are null)."
    )
    async def shares_get_snapshot_config(host: str, name: str) -> dict:
        return await _safe(
            shares.shares_get_snapshot_config(host, name, app_context=ctx)
        )

    # --- snapshot_replication --------------------------------------------

    @mcp.tool(
        description="List Snapshot Replication plans the host knows about "
        "(source or destination role). Falls back to reading replica.db via "
        "SSH+sqlite3 on fresh DSM installs where DR web endpoints aren't "
        "registered yet. READ-ONLY — plan creation is permanently out of scope."
    )
    async def snapshot_replication_list_plans(host: str) -> dict:
        return await _safe(
            snapshot_replication.snapshot_replication_list_plans(
                host, app_context=ctx,
            )
        )

    @mcp.tool(
        description="Detailed status for one SR plan: schedule, retention, "
        "encryption settings, current state. Falls back to replica.db when "
        "SYNO.DR.Plan.get is not registered."
    )
    async def snapshot_replication_plan_status(host: str, plan_id: str) -> dict:
        return await _safe(
            snapshot_replication.snapshot_replication_plan_status(
                host, plan_id, app_context=ctx,
            )
        )

    @mcp.tool(
        description="Recent SR sync events. Falls back to snap_replica.db "
        "(snap_replica_conf + size_calculate tables) when the web API "
        "list_activity method is not registered."
    )
    async def snapshot_replication_recent_activity(
        host: str, limit: int = 20,
    ) -> dict:
        return await _safe(
            snapshot_replication.snapshot_replication_recent_activity(
                host, limit=limit, app_context=ctx,
            )
        )

    # --- ssh (Phase 3a — WRITE tools) -------------------------------------

    @mcp.tool(
        description="Append a public key to ~user/.ssh/authorized_keys "
        "on `host` (idempotent by SHA256 fingerprint of the key blob). "
        "Pre-flight calls user_home_is_enabled and refuses if it returns "
        "enabled=False. Uses base64-over-exec, NOT SFTP (DSM disables the "
        "SFTP subsystem). Returns data.added (bool) and data.fingerprint "
        "(SHA256:<b64>)."
    )
    async def ssh_add_authorized_key(
        host: str, user: str, pubkey: str, comment: str = "",
    ) -> dict:
        return await _safe(
            ssh.ssh_add_authorized_key(
                host, user, pubkey, comment=comment, app_context=ctx,
            )
        )

    @mcp.tool(
        description="Remove all keys whose SHA256 fingerprint matches "
        "`fingerprint` from ~user/.ssh/authorized_keys on `host`. "
        "Idempotent — a fingerprint that isn't present returns ok=True "
        "with data.removed_count=0. Order of remaining keys is preserved."
    )
    async def ssh_remove_authorized_key(
        host: str, user: str, fingerprint: str,
    ) -> dict:
        return await _safe(
            ssh.ssh_remove_authorized_key(
                host, user, fingerprint, app_context=ctx,
            )
        )

    @mcp.tool(
        description="Grant SSH access to a DSM user by adding them to the "
        "`administrators` group (DSM 7.3 has no per-user SSH app-priv "
        "row — administrators-group membership is the gate). Idempotent: "
        "users already in admin return warnings=['already enabled'] and "
        "data.added=False."
    )
    async def ssh_enable_user_ssh(host: str, user: str) -> dict:
        return await _safe(
            ssh.ssh_enable_user_ssh(host, user, app_context=ctx)
        )

    return mcp, ctx


async def _safe(coro: Any) -> dict:
    """Wrap a tool coroutine to convert DSMError into a structured failure dict."""
    try:
        return await coro
    except DSMError as exc:
        logger.warning(
            "tool failed: host=%s category=%s code=%s msg=%s",
            exc.host, exc.category, exc.dsm_error_code, exc.message,
        )
        return {
            "ok": False,
            "host": exc.host,
            "data": None,
            "warnings": [],
            "error": exc.to_dict(),
        }


def _configure_logging() -> None:
    level_name = os.environ.get("SYNOLOGY_MCP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    # MCP stdio reserves stdout for the JSON-RPC stream — log to stderr only.
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=__import__("sys").stderr,
    )


def main() -> None:
    """Console entrypoint declared in pyproject.toml `[project.scripts]`.

    Starts the MCP stdio server. The MCP client (Claude Code, Claude Desktop)
    spawns this process and speaks JSON-RPC over stdin/stdout.
    """
    _configure_logging()
    mcp, ctx = build_app()
    try:
        mcp.run()
    finally:
        # Best-effort cleanup on shutdown.
        with contextlib.suppress(Exception):  # pragma: no cover - best effort
            asyncio.run(ctx.cache.aclose())


# Re-export for tests / debugging.
__all__ = ["AppContext", "build_app", "main"]


# Allow `python -m synology_mcp.server` for ad-hoc testing.
if __name__ == "__main__":
    main()


# Helper exposed for debugging: print the registered tools as JSON.
def _list_tools() -> str:  # pragma: no cover - debug helper
    mcp, _ = build_app()
    tools = asyncio.run(mcp.list_tools())
    return json.dumps([t.name for t in tools], indent=2)
