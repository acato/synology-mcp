# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""MCP server entrypoint.

Wires up the MCP stdio server, registers tools from each subsystem module,
and owns the per-host session cache + config loader.

See DESIGN.md §2 (Architecture) and §5 (Tool Surface) for the full plan.
"""
from __future__ import annotations


def main() -> None:
    """Console entrypoint declared in pyproject.toml `[project.scripts]`.

    TODO: instantiate `mcp.server.Server`, register tools from
    `auth`, `packages`, `user_home`, `snapshot_replication`, `shares`,
    `raid`, `ssh`, `network`, and run stdio transport.

    See DESIGN.md §2 for process model and §5 for the tool registry.
    """
    raise NotImplementedError(
        "synology-mcp server entrypoint not yet implemented. See DESIGN.md."
    )


if __name__ == "__main__":
    main()
