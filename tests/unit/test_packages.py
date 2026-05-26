# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for packages.py — respx for web API, mocked SSH for synopkg."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
import respx

from synology_mcp import packages
from synology_mcp.errors import InvalidParam
from synology_mcp.session import DSMSession
from synology_mcp.transport.ssh import DSMSshClient, SshResult


def _seed_session(app_ctx) -> None:
    state = app_ctx.cache.get("testhost")
    state.session = DSMSession(
        sid="FAKE_SID", syno_token="FAKE_TOKEN", user="testuser",
        cookies={"id": "FAKE_SID"},
    )


def _fake_ssh_router(responses: dict[str, SshResult]) -> DSMSshClient:
    """Build a MagicMock SSH client whose .run dispatches on substring match.

    `responses` keys are substrings matched against the command. First
    match wins. Commands with no match get an SshResult(exit=0, empty).
    """
    fake = MagicMock(spec=DSMSshClient)

    async def _run(command: str, *_, **__) -> SshResult:
        for needle, result in responses.items():
            if needle in command:
                return SshResult(
                    command=command,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    exit_status=result.exit_status,
                )
        return SshResult(command=command, stdout="", stderr="", exit_status=0)

    fake.run = AsyncMock(side_effect=_run)
    return fake


# ---------- packages_list -------------------------------------------------


@pytest.mark.asyncio
async def test_packages_list_decorates_with_synopkg_status(
    app_ctx, fixture_json, fixture_text,
) -> None:
    _seed_session(app_ctx)
    pkg_list_body = fixture_json("package", "list_normal.json")
    stop_blob = fixture_text("synopkg", "status_stop.txt")
    start_blob = fixture_text("synopkg", "status_start.txt")
    # ContainerManager docker info returns empty server_version + perm denied
    docker_stdout = "|containers=0|running=0"
    docker_stderr = "permission denied while trying to connect to docker socket"

    def _resp(stdout: str, exit_status: int, stderr: str = "") -> SshResult:
        return SshResult(command="x", stdout=stdout, stderr=stderr,
                         exit_status=exit_status)

    # Build responses dynamically:
    # - synopkg status FileStation → "start"
    # - synopkg status everything-else → "stop"
    # - synopkg is_onoff → exit 0 (on) for FileStation, exit 1 (off) for others
    # - docker info → empty server_version + perm denied
    async def _run(command: str, *_, **__) -> SshResult:
        if "docker" in command and "info" in command:
            return _resp(docker_stdout, 0, docker_stderr)
        if "synopkg status FileStation" in command:
            return _resp(start_blob, 0)
        if "synopkg status" in command:
            return _resp(stop_blob, 7)
        if "synopkg is_onoff FileStation" in command:
            return _resp("", 0)
        if "synopkg is_onoff" in command:
            return _resp("package isn't on", 1)
        return _resp("", 0)

    fake_ssh = MagicMock(spec=DSMSshClient)
    fake_ssh.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=pkg_list_body)
        result = await packages.packages_list("testhost", app_context=app_ctx)

    assert result["ok"] is True
    items = result["data"]["packages"]
    by_id = {p["id"]: p for p in items}

    assert by_id["FileStation"]["status"] == "start"
    assert by_id["ActiveInsight"]["status"] == "stop"
    assert by_id["ContainerManager"]["status"] == "stop"

    # ContainerManager rows always carry the docker fields.
    cm = by_id["ContainerManager"]
    assert "docker_health" in cm
    # With empty server_version + perm denied, daemon state is unknown.
    assert cm["docker_health"] is False
    # And a warning was added explaining the permission-denied state.
    assert any(
        "permission-denied" in w.lower() for w in result["warnings"]
    )


@pytest.mark.asyncio
async def test_packages_list_docker_health_true_when_daemon_responds(
    app_ctx, fixture_json, fixture_text,
) -> None:
    _seed_session(app_ctx)
    pkg_list_body = fixture_json("package", "list_normal.json")
    stop_blob = fixture_text("synopkg", "status_stop.txt")

    def _resp(stdout: str, exit_status: int, stderr: str = "") -> SshResult:
        return SshResult(command="x", stdout=stdout, stderr=stderr, exit_status=exit_status)

    async def _run(command: str, *_, **__) -> SshResult:
        if "docker" in command and "info" in command:
            # Daemon responds — non-empty server_version proves healthy.
            return _resp("24.0.2|containers=5|running=3", 0)
        if "synopkg status" in command:
            return _resp(stop_blob, 7)
        if "synopkg is_onoff" in command:
            return _resp("", 1)
        return _resp("", 0)

    fake_ssh = MagicMock(spec=DSMSshClient)
    fake_ssh.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=pkg_list_body)
        result = await packages.packages_list("testhost", app_context=app_ctx)

    by_id = {p["id"]: p for p in result["data"]["packages"]}
    cm = by_id["ContainerManager"]
    assert cm["docker_health"] is True
    assert cm["docker_info_summary"]["server_version"] == "24.0.2"
    assert cm["docker_info_summary"]["containers_running"] == 3
    # Warning about the synopkg/docker disagreement.
    assert any("docker_health=True is authoritative" in w for w in result["warnings"])


# ---------- packages_status ------------------------------------------------


@pytest.mark.asyncio
async def test_packages_status_returns_install_path_and_last_started(
    app_ctx, fixture_json, fixture_text,
) -> None:
    _seed_session(app_ctx)
    get_body = fixture_json("package", "get_container_manager.json")
    stop_blob = fixture_text("synopkg", "status_stop.txt")

    def _resp(stdout: str, exit_status: int, stderr: str = "") -> SshResult:
        return SshResult(command="x", stdout=stdout, stderr=stderr, exit_status=exit_status)

    async def _run(command: str, *_, **__) -> SshResult:
        if "synopkg status" in command:
            return _resp(stop_blob, 7)
        if "synopkg is_onoff" in command:
            return _resp("", 1)
        if "readlink" in command:
            return _resp("/volume1/@appstore/ContainerManager", 0)
        if "stat -c" in command:
            return _resp("1716661690", 0)  # 2024-05-25T17:48:10 UTC
        if "docker" in command and "info" in command:
            return _resp("", 1, "permission denied")
        return _resp("", 0)

    fake_ssh = MagicMock(spec=DSMSshClient)
    fake_ssh.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=get_body)
        result = await packages.packages_status(
            "testhost", "ContainerManager", app_context=app_ctx,
        )

    assert result["ok"] is True
    data = result["data"]
    assert data["id"] == "ContainerManager"
    assert data["version"] == "24.0.2-1606"
    assert data["status"] == "stop"
    assert data["status_code"] == 263
    assert data["status_description"] == "failed to get unit status"
    assert data["install_path"] == "/volume1/@appstore/ContainerManager"
    assert data["last_started_at"].startswith("2024-05-25T")
    assert data["docker_health"] is False


@pytest.mark.asyncio
async def test_packages_status_rejects_empty_package_id(app_ctx) -> None:
    _seed_session(app_ctx)
    with pytest.raises(InvalidParam):
        await packages.packages_status("testhost", "", app_context=app_ctx)


# ---------- parse helpers (pure) -------------------------------------------


def test_status_from_synopkg_prefers_blob_over_is_onoff() -> None:
    blob = {"status": "start", "aspect": {"active": {"status_code": 0}}}
    assert packages._status_from_synopkg(blob, is_onoff_exit=1) == "start"


def test_status_from_synopkg_falls_back_to_is_onoff() -> None:
    assert packages._status_from_synopkg({}, is_onoff_exit=0) == "start"
    assert packages._status_from_synopkg({}, is_onoff_exit=1) == "stop"
    assert packages._status_from_synopkg({}, is_onoff_exit=None) == "unknown"


def test_parse_synopkg_status_blob_handles_garbage() -> None:
    assert packages._parse_synopkg_status_blob("") == {}
    assert packages._parse_synopkg_status_blob("not json") == {}
    parsed = packages._parse_synopkg_status_blob('{"status":"stop"}')
    assert parsed == {"status": "stop"}


def test_normalize_pkg_row_uses_install_type() -> None:
    raw = {
        "id": "FileStation", "name": "File Station", "version": "1.2.3",
        "timestamp": 1234567890123,
        "additional": {"install_type": "system"},
    }
    row = packages._normalize_pkg_row(raw)
    assert row["install_type"] == "system"
    assert row["timestamp_ms"] == 1234567890123
    assert row["status"] == "unknown"
    assert row["auto_start"] is None
