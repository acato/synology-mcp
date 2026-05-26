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

from . import auth, network, raid
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
            "Phase 1 exposes auth, raid (read-only), and network (read-only) tools."
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
