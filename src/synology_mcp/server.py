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
            "ssh_remove_authorized_key, ssh_enable_user_ssh). Phase 3b "
            "adds four filesystem-write tools (user_home_enable, "
            "user_home_disable, shares_create, shares_delete). Phase 3c "
            "adds three system-mutation tools (ssh_set_port, "
            "packages_install, packages_uninstall) with denylist + EULA "
            "+ port-in-use safety rails."
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

    @mcp.tool(
        description="Reconcile DSM's User Home machinery in 4 steps: "
        "synosetkeyvalue userHomeEnable=yes, restore the /var/services/homes "
        "symlink, SYNO.Core.User.Home.set enable=true, then synouserhome "
        "--prepare-folder for the given user (if provided). Idempotent: "
        "tri-check already-enabled short-circuits steps 1-3. Rollback on "
        "step 2/3 failure restores the previous symlink target."
    )
    async def user_home_enable(host: str, user: str | None = None) -> dict:
        return await _safe(
            user_home.user_home_enable(host, user=user, app_context=ctx)
        )

    @mcp.tool(
        description="Disable User Home system-wide via SYNO.Core.User.Home.set "
        "enable=false. Safety rail: refuses by default if any user has a "
        "non-empty ~/.ssh/authorized_keys file (would orphan key auth). "
        "Pass confirm_destroy_keys=True to proceed; the affected users are "
        "named in a warning. DSM preserves the /volume*/homes/* data."
    )
    async def user_home_disable(
        host: str, confirm_destroy_keys: bool = False,
    ) -> dict:
        return await _safe(
            user_home.user_home_disable(
                host, confirm_destroy_keys=confirm_destroy_keys,
                app_context=ctx,
            )
        )

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

    @mcp.tool(
        description="Create a shared folder via SYNO.Core.Share.create. "
        "Reserved-name pre-flight refuses DSM-reserved names (home/homes/music/"
        "photo/video/NetBackup/usbshare*/sdshare*/esata*/surveillance/download/"
        "web*/@*) with category=reserved_share_name. Idempotent: same-name on "
        "same volume with compatible flags returns data.created=False with "
        "the 'share already exists' warning; same-name with different config "
        "refuses with category=share_exists_with_different_config. "
        "encryption=True requires encryption_passphrase."
    )
    async def shares_create(
        host: str,
        name: str,
        volume: str,
        desc: str = "",
        hidden: bool = False,
        enable_recycle_bin: bool = False,
        encryption: bool = False,
        encryption_passphrase: str | None = None,
        enable_share_cow: bool = True,
    ) -> dict:
        return await _safe(
            shares.shares_create(
                host, name, volume,
                desc=desc, hidden=hidden,
                enable_recycle_bin=enable_recycle_bin,
                encryption=encryption,
                encryption_passphrase=encryption_passphrase,
                enable_share_cow=enable_share_cow,
                app_context=ctx,
            )
        )

    @mcp.tool(
        description="Delete a shared folder via SYNO.Core.Share.delete. "
        "Safety rail: SSH-probes `du -sb --exclude=@eaDir` on the share path; "
        "refuses with category=share_not_empty if size > 0 unless force=True. "
        "Idempotent: a share that's already absent returns ok=True with "
        "data.deleted=False. DSM does NOT remove the underlying directory "
        "on delete — when force=True a warning reminds the caller to follow "
        "up with rm -rf for full cleanup."
    )
    async def shares_delete(
        host: str, name: str, force: bool = False,
    ) -> dict:
        return await _safe(
            shares.shares_delete(
                host, name, force=force, app_context=ctx,
            )
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

    # --- Phase 3c — system-mutation tools ---------------------------------

    @mcp.tool(
        description="Change DSM's SSH listen port via SYNO.Core.Terminal.set. "
        "Pre-flight: port must be in [1024, 65535] unless port=22 with "
        "allow_default=True (port 22 is refused by default — it's a "
        "security-bad target). Refuses with category=port_already_in_use "
        "if `ss -lnt sport = :<port>` finds another listener on the host. "
        "Idempotent: same-port short-circuits with data.changed=False. "
        "Reads SYNO.Core.Terminal.get v3 and rewrites the full payload "
        "(carries forward enable_ssh/telnet/console + cipher/kex/mac "
        "arrays) so .set never disables other settings as a side-effect. "
        "Post-change: opens a fresh paramiko handshake on the new port "
        "(10s timeout). Failure does NOT revert (the existing SSH session "
        "is the escape hatch); surfaces data.verified=False with a warning."
    )
    async def ssh_set_port(
        host: str, port: int, allow_default: bool = False,
    ) -> dict:
        return await _safe(
            ssh.ssh_set_port(
                host, port, allow_default=allow_default, app_context=ctx,
            )
        )

    @mcp.tool(
        description="Install a package via SYNO.Core.Package.Installation. "
        "Idempotent: same-version installed -> ok=True, data.installed=False "
        "with 'already at version X' warning. Different-version installed -> "
        "refuses with category=upgrade_required (MVP does not implement "
        "in-place upgrade). Primary path is install_from_server; DSM 1000-"
        "series errors trigger the .spk fallback (download + install chain). "
        "EULA gate: if the install response carries data.eula and "
        "accept_eula=False, refuses with category=eula_required and "
        "data.eula_text so the caller can present the agreement before "
        "retrying with accept_eula=True. Returns data.method="
        "'server'|'spk_fallback'|'noop' and the final installed version."
    )
    async def packages_install(
        host: str,
        package_id: str,
        version: str | None = None,
        accept_eula: bool = False,
    ) -> dict:
        return await _safe(
            packages.packages_install(
                host, package_id,
                version=version, accept_eula=accept_eula,
                app_context=ctx,
            )
        )

    @mcp.tool(
        description="Uninstall a package via SYNO.Core.Package.Uninstallation. "
        "Safety rail: refuses with category=denylist if package_id is in "
        "the in-process denylist of packages other agents depend on "
        "(ContainerManager, SnapshotReplication, HyperBackup, StorageManager, "
        "WebStation/Apache/PHP/MariaDB, SecureSignIn/LDAPServer/"
        "DirectoryServer). Pass force=True to override — the override is "
        "recorded as a warning. Idempotent: package not installed -> "
        "ok=True with data.uninstalled=False, no API call fires."
    )
    async def packages_uninstall(
        host: str, package_id: str, force: bool = False,
    ) -> dict:
        return await _safe(
            packages.packages_uninstall(
                host, package_id, force=force, app_context=ctx,
            )
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
