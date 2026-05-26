# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Snapshot Replication — READ-ONLY in MVP.

Wraps `SYNO.DR.Plan` / `SYNO.Replica.Share` query endpoints. See DESIGN.md §5.4.

**Plan creation is explicitly out of scope for MVP** — DSM's SR plan creator
is gated through a one-shot UI node-pairing wizard, and creating plans via
the undocumented API endpoints risks half-built rows in
`/var/packages/SnapshotReplication/etc/replica.db` that DSM UI cannot then
remediate. See DESIGN.md §11.
"""
from __future__ import annotations


async def list_plans(host: str) -> dict:
    """TODO: list all SR plans (source-side and destination-side roles)."""
    raise NotImplementedError


async def get_plan_status(host: str, plan_id: str) -> dict:
    """TODO: detailed status: last sync time, lag, retention, schedule."""
    raise NotImplementedError


async def get_recent_activity(host: str, limit: int = 20) -> dict:
    """TODO: recent SR sync events from `replica.db` activity log."""
    raise NotImplementedError
