# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for snapshot_replication.py — respx + mocked SSH for sqlite."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
import respx

from synology_mcp import snapshot_replication
from synology_mcp.errors import InvalidParam
from synology_mcp.session import DSMSession
from synology_mcp.transport.ssh import DSMSshClient, SshResult


def _seed_session(app_ctx) -> None:
    state = app_ctx.cache.get("testhost")
    state.session = DSMSession(
        sid="FAKE_SID", syno_token="FAKE_TOKEN", user="testuser",
        cookies={"id": "FAKE_SID"},
    )


def _sqlite_json_reply(rows: list[dict]) -> str:
    """Encode rows the way the DSM sqlite3 ``.mode json`` shell would."""
    if not rows:
        return ""
    return json.dumps(rows)


# ---------- snapshot_replication_list_plans --------------------------------


@pytest.mark.asyncio
async def test_list_plans_uses_web_api_when_populated(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("dr_plan", "list_with_plans.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        # No SSH client needed — the DB fallback should never be hit.
        result = await snapshot_replication.snapshot_replication_list_plans(
            "testhost", app_context=app_ctx,
        )
    assert result["ok"] is True
    plans = result["data"]["plans"]
    assert len(plans) == 1
    p = plans[0]
    assert p["plan_id"] == "PLAN-AAAA-BBBB-0001"
    assert p["name"] == "movies-to-backup"
    assert p["solution_type"] == "share"
    assert p["sync_mode"] == "scheduled"
    assert p["source_host"] == "nas-primary.example.com"
    assert p["dest_host"] == "nas-backup.example.com"
    assert p["source_share"] == "Movies"
    assert p["_source"] == "web_api"


@pytest.mark.asyncio
async def test_list_plans_empty_web_falls_back_to_db(
    app_ctx, fixture_json,
) -> None:
    """When web API returns plans=[], we read replica.db for any DB-only plans.

    On CS3 (no plans) this is also empty. We assert the fallback was
    invoked AND no warnings about sqlite errors are raised.
    """
    _seed_session(app_ctx)
    payload = fixture_json("dr_plan", "list_empty.json")
    # SSH returns empty list (no rows in plan table).
    fake = MagicMock(spec=DSMSshClient)
    fake.run = AsyncMock(
        return_value=SshResult(
            command="sqlite3", stdout="", stderr="", exit_status=0,
        )
    )
    app_ctx.cache.get("testhost").ssh_client = fake
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await snapshot_replication.snapshot_replication_list_plans(
            "testhost", app_context=app_ctx,
        )
    assert result["ok"] is True
    assert result["data"]["plans"] == []
    # Two SSH calls (plan + share_replication queries).
    assert fake.run.await_count == 2


@pytest.mark.asyncio
async def test_list_plans_db_fallback_with_row(
    app_ctx, fixture_json,
) -> None:
    """If replica.db has a plan row, we surface it tagged as replica_db source."""
    _seed_session(app_ctx)
    payload = fixture_json("dr_plan", "list_empty.json")
    plan_row = {
        "plan_id": "DB-PLAN-0001",
        "solution_type": 1,
        "main_site": "nas-primary.example.com",
        "dr_site": "nas-backup.example.com",
        "sync_mode": 2,
        "target_id": "tgt-1",
        "target_type": 1,
        "status": 0,
    }
    share_row = {"plan_id": "DB-PLAN-0001", "replication_id": "Movies"}

    fake = MagicMock(spec=DSMSshClient)

    async def _run(command: str, *_, **__) -> SshResult:
        if "FROM plan" in command:
            return SshResult(
                command=command,
                stdout=_sqlite_json_reply([plan_row]),
                stderr="", exit_status=0,
            )
        if "share_replication" in command:
            return SshResult(
                command=command,
                stdout=_sqlite_json_reply([share_row]),
                stderr="", exit_status=0,
            )
        return SshResult(command=command, stdout="", stderr="", exit_status=0)

    fake.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await snapshot_replication.snapshot_replication_list_plans(
            "testhost", app_context=app_ctx,
        )
    plans = result["data"]["plans"]
    assert len(plans) == 1
    p = plans[0]
    assert p["plan_id"] == "DB-PLAN-0001"
    assert p["solution_type"] == "share"
    assert p["sync_mode"] == "continuous"
    assert p["source_share"] == "Movies"
    assert p["_source"] == "replica_db"


# ---------- snapshot_replication_plan_status -------------------------------


@pytest.mark.asyncio
async def test_plan_status_unsupported_falls_back_to_db(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    unsupported_payload = fixture_json("dr_plan", "list_activity_unsupported.json")
    plan_row = {
        "plan_id": "DB-PLAN-0001",
        "solution_type": 1,
        "main_site": "nas-primary.example.com",
        "dr_site": "nas-backup.example.com",
        "sync_mode": 1,
        "target_id": "tgt-1",
        "target_type": 0,
        "status": 1,  # syncing
        "sched_id": 42,
        "is_send_encrypted": 1,
        "is_sync_local_snapshots": 0,
        "notify_time_in_min": 60,
        "sync_window_enable": 1,
        "sync_window": "0-23",
        "worm_lock_enable": 0,
        "worm_lock_day": 0,
        "worm_lock_notify_time": 0,
    }

    fake = MagicMock(spec=DSMSshClient)
    fake.run = AsyncMock(
        return_value=SshResult(
            command="sqlite3",
            stdout=_sqlite_json_reply([plan_row]),
            stderr="", exit_status=0,
        )
    )
    app_ctx.cache.get("testhost").ssh_client = fake

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=unsupported_payload)
        result = await snapshot_replication.snapshot_replication_plan_status(
            "testhost", "DB-PLAN-0001", app_context=app_ctx,
        )
    assert result["ok"] is True
    data = result["data"]
    assert data["plan_id"] == "DB-PLAN-0001"
    assert data["status"] == "syncing"
    assert data["schedule"]["sched_id"] == 42
    assert data["schedule"]["sync_window_enable"] is True
    assert data["is_send_encrypted"] is True
    # Warning about the missing web endpoint.
    assert any("not registered" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_plan_status_rejects_empty(app_ctx) -> None:
    _seed_session(app_ctx)
    with pytest.raises(InvalidParam):
        await snapshot_replication.snapshot_replication_plan_status(
            "testhost", "", app_context=app_ctx,
        )


# ---------- snapshot_replication_recent_activity ---------------------------


@pytest.mark.asyncio
async def test_recent_activity_db_fallback(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    unsupported_payload = fixture_json("dr_plan", "list_activity_unsupported.json")
    repl_row = {
        "replica_id": "REPLICA-A",
        "plan_status": "idle",
        "direction": "out",
        "src_path": "/volume1/Movies",
        "dst_path": "/volume2/Movies",
    }
    size_row = {
        "id": "REPLICA-A",
        "total_size": "12345678",
        "is_process": "0",
        "pid": "0",
        "time": "1747700000",
        "errcode": "0",
    }

    fake = MagicMock(spec=DSMSshClient)

    async def _run(command: str, *_, **__) -> SshResult:
        if "snap_replica_conf" in command:
            return SshResult(
                command=command,
                stdout=_sqlite_json_reply([repl_row]),
                stderr="", exit_status=0,
            )
        if "size_calculate" in command:
            return SshResult(
                command=command,
                stdout=_sqlite_json_reply([size_row]),
                stderr="", exit_status=0,
            )
        return SshResult(command=command, stdout="", stderr="", exit_status=0)

    fake.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=unsupported_payload)
        result = await snapshot_replication.snapshot_replication_recent_activity(
            "testhost", limit=10, app_context=app_ctx,
        )
    assert result["ok"] is True
    events = result["data"]["events"]
    assert len(events) == 2
    by_type = {e["event_type"]: e for e in events}
    assert by_type["plan_status"]["replica_id"] == "REPLICA-A"
    assert by_type["plan_status"]["src_path"] == "/volume1/Movies"
    assert by_type["size_calculate"]["timestamp_epoch"] == 1747700000
    assert any("not registered" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_recent_activity_rejects_bad_limit(app_ctx) -> None:
    _seed_session(app_ctx)
    with pytest.raises(InvalidParam):
        await snapshot_replication.snapshot_replication_recent_activity(
            "testhost", limit=0, app_context=app_ctx,
        )
    with pytest.raises(InvalidParam):
        await snapshot_replication.snapshot_replication_recent_activity(
            "testhost", limit=10000, app_context=app_ctx,
        )


# ---------- internal helpers ------------------------------------------------


def test_plan_status_name_lookup() -> None:
    assert snapshot_replication._plan_status_name(0) == "idle"
    assert snapshot_replication._plan_status_name(1) == "syncing"
    assert snapshot_replication._plan_status_name(2) == "error"
    assert snapshot_replication._plan_status_name(None) == "unknown"
    assert snapshot_replication._plan_status_name(99) == "raw_99"


def test_sqlite_quote_escapes_single_quotes() -> None:
    assert snapshot_replication._sqlite_quote(42) == "42"
    assert snapshot_replication._sqlite_quote(True) == "1"
    assert snapshot_replication._sqlite_quote("abc") == "'abc'"
    # Unsafe characters get the doubled-single-quote escape.
    assert snapshot_replication._sqlite_quote("a'b") == "'a''b'"


def test_escape_printf_handles_quotes_and_backslashes() -> None:
    assert snapshot_replication._escape_printf("hello") == "hello"
    assert snapshot_replication._escape_printf("it's") == "it'\\''s"
    assert snapshot_replication._escape_printf("a\\b") == "a\\\\b"
