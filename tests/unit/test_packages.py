# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for packages.py — respx for web API, mocked SSH for synopkg."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
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


# ===========================================================================
# packages_install — Phase 3c
# ===========================================================================


def _get_not_installed_body() -> dict:
    """DSM 7.3 returns code 102/103 from Package.get when id is unknown."""
    return {"success": False, "error": {"code": 102}}


def _get_not_installed_4545_body() -> dict:
    """DSM 7.3 Package Center variant: code 4545 = ``package is not installed``.

    Observed live on CS4 / DSM 7.3 build 86009 when calling Package.get
    against ``LogCenter`` while it was uninstalled. The 4500-family is
    Package Center's private error range and is NOT mapped to a
    specific exception class — it surfaces as generic DSMError, so
    ``_is_not_installed_error`` must treat it as "not installed" by
    code, not by isinstance check.
    """
    return {"success": False, "error": {"code": 4545}}


def _get_installed_body(package_id: str, version: str) -> dict:
    return {
        "success": True,
        "data": {
            "id": package_id, "name": package_id, "version": version,
            "additional": {"install_type": ""},
        },
    }


def _server_list_body(package_id: str, version: str, **overrides) -> dict:
    """Build a minimal SYNO.Core.Package.Server.list v2 response.

    Mirrors the real catalog row shape (probed from CS3 live). The
    canonical fields ``packages_install`` reads are ``package``,
    ``version``, ``link``, ``md5``, ``size``, ``type``, ``source``,
    ``beta``, ``qinst``.
    """
    row = {
        "package": package_id,
        "id": package_id,
        "version": version,
        "link": f"https://example.invalid/{package_id}-{version}.spk",
        "md5": "0123456789abcdef0123456789abcdef",
        "size": 12345,
        "type": 0,
        "source": "syno",
        "beta": False,
        "qinst": True,
    }
    row.update(overrides)
    return {
        "success": True,
        "data": {
            "packages": [row],
            "beta_packages": [],
            "categories": [],
            "banners": [],
        },
    }


def _server_list_empty_body() -> dict:
    """Server.list response containing no matching package."""
    return {
        "success": True,
        "data": {
            "packages": [
                {
                    "package": "SomethingElse", "id": "SomethingElse",
                    "version": "1.0.0", "source": "syno",
                },
            ],
            "beta_packages": [],
            "categories": [],
            "banners": [],
        },
    }


@pytest.mark.asyncio
async def test_install_happy_path_online_via_install_verb(app_ctx) -> None:
    """Unknown package -> Server.list -> Installation.install -> installed=True, method=online."""
    _seed_session(app_ctx)
    # Sequence:
    #   1. Package.get -> 102 (not installed)
    #   2. Server.list -> catalog row for "Test" v1.2.3
    #   3. Installation.install -> {task_id: ...}
    #   4. Installation.status -> finished=True
    #   5. Package.get -> installed at 1.2.3
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_get_not_installed_body()),
                httpx.Response(200, json=_server_list_body("Test", "1.2.3")),
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"task_id": "@SYNOPKG_DOWNLOAD_Test"},
                    },
                ),
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"finished": True, "status": "done"},
                    },
                ),
                httpx.Response(200, json=_get_installed_body("Test", "1.2.3")),
            ]
        )
        result = await packages.packages_install(
            "testhost", "Test", version="1.2.3", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["installed"] is True
    assert result["data"]["method"] == "online"
    assert result["data"]["version"] == "1.2.3"
    assert result["data"]["package_id"] == "Test"
    # The 3rd web call MUST be Installation.install with the canonical
    # DSM 7.3 payload (NOT install_from_server).
    install_qs = dict(route.calls[2].request.url.params)
    assert install_qs["api"] == "SYNO.Core.Package.Installation"
    assert install_qs["method"] == "install"
    assert install_qs["name"] == "Test"
    # Catalog fields must round-trip into the install payload.
    assert install_qs["url"].endswith("Test-1.2.3.spk")
    assert install_qs["checksum"] == "0123456789abcdef0123456789abcdef"
    assert install_qs["filesize"] == "12345"
    assert install_qs["is_syno"] == "true"
    assert install_qs["operation"] == "install"


@pytest.mark.asyncio
async def test_install_treats_dsm_4545_as_not_installed(app_ctx) -> None:
    """Live regression: DSM 7.3 returns 4545 from Package.get for an uninstalled
    package_id (observed on CS4 against LogCenter). The 4500-family is Package
    Center's private range and isn't mapped to a specific exception class —
    ``_is_not_installed_error`` must treat it as "not installed" via the
    raw code, otherwise the generic DSMError bubbles and the install path
    never starts.
    """
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                # 1. Package.get -> 4545 (DSM Package Center "not installed").
                httpx.Response(200, json=_get_not_installed_4545_body()),
                # 2. Server.list -> catalog row.
                httpx.Response(
                    200, json=_server_list_body("LogCenter", "9.9.9"),
                ),
                # 3. Installation.install -> task_id.
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"task_id": "@SYNOPKG_DOWNLOAD_LogCenter"},
                    },
                ),
                # 4. status -> finished.
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"finished": True, "status": "done"},
                    },
                ),
                # 5. Package.get -> installed at v9.9.9.
                httpx.Response(
                    200, json=_get_installed_body("LogCenter", "9.9.9"),
                ),
            ],
        )
        result = await packages.packages_install(
            "testhost", "LogCenter", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["installed"] is True
    assert result["data"]["method"] == "online"
    assert result["data"]["version"] == "9.9.9"


@pytest.mark.asyncio
async def test_install_refuses_when_not_in_catalog(app_ctx) -> None:
    """Package not in Server.list -> category=not_in_catalog, no install."""
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_get_not_installed_body()),
                httpx.Response(200, json=_server_list_empty_body()),
            ]
        )
        result = await packages.packages_install(
            "testhost", "Bogus", app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "not_in_catalog"
    assert result["data"]["package_id"] == "Bogus"
    # Exactly two calls — Package.get + Server.list. No install.
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_install_refuses_on_dsm_1000_series_with_warning(app_ctx) -> None:
    """Installation.install returning DSM 1004 -> category=online_install_failed.

    The historical spk_fallback behaviour is documented but not yet
    implemented in this gap-fix pass; we surface a clear refusal envelope
    so the caller knows the online path failed (and why).
    """
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_get_not_installed_body()),
                httpx.Response(200, json=_server_list_body("Test", "1.2.3")),
                # Install fails with DSM 1004 (network error).
                httpx.Response(
                    200, json={"success": False, "error": {"code": 1004}},
                ),
            ]
        )
        result = await packages.packages_install(
            "testhost", "Test", version="1.2.3", app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "online_install_failed"
    assert result["data"]["dsm_error_code"] == 1004
    # Warning explains the spk_fallback gap.
    assert any("spk_fallback" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_install_eula_required_aborts_without_accept(app_ctx) -> None:
    """install response carries data.eula -> category=eula_required, no further calls."""
    _seed_session(app_ctx)
    eula_text = "Synology Package License Agreement: ..."
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_get_not_installed_body()),
                httpx.Response(200, json=_server_list_body("Test", "1.2.3")),
                httpx.Response(
                    200,
                    json={"success": True, "data": {"eula": eula_text}},
                ),
            ]
        )
        result = await packages.packages_install(
            "testhost", "Test", app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "eula_required"
    assert result["data"]["eula_text"] == eula_text
    assert result["data"]["package_id"] == "Test"


@pytest.mark.asyncio
async def test_install_eula_accepted_proceeds(app_ctx) -> None:
    """accept_eula=True passes through to the install call without aborting."""
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_get_not_installed_body()),
                httpx.Response(200, json=_server_list_body("Test", "2.0.0")),
                # No EULA challenge this time — install proceeds directly.
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"task_id": "t1"},
                    },
                ),
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"finished": True, "status": "done"},
                    },
                ),
                httpx.Response(
                    200, json=_get_installed_body("Test", "2.0.0"),
                ),
            ]
        )
        result = await packages.packages_install(
            "testhost", "Test", accept_eula=True, app_context=app_ctx,
        )
    assert result["ok"] is True
    assert result["data"]["installed"] is True
    # accept_eula=true was passed through in the Installation.install call.
    install_qs = dict(route.calls[2].request.url.params)
    assert install_qs["accept_eula"] == "true"
    assert install_qs["method"] == "install"


@pytest.mark.asyncio
async def test_install_refuses_when_catalog_version_differs(app_ctx) -> None:
    """Caller-pinned version vs. catalog's only-version -> category=version_mismatch."""
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_get_not_installed_body()),
                # Catalog only carries v2.0.0, but caller asked for v1.0.0.
                httpx.Response(200, json=_server_list_body("Test", "2.0.0")),
            ]
        )
        result = await packages.packages_install(
            "testhost", "Test", version="1.0.0", app_context=app_ctx,
        )
    assert result["ok"] is False
    assert result["data"]["category"] == "version_mismatch"
    assert result["data"]["requested_version"] == "1.0.0"
    assert result["data"]["catalog_version"] == "2.0.0"
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_install_idempotent_same_version(app_ctx) -> None:
    """Already at the requested version -> installed=False + "already at version" warning."""
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json=_get_installed_body("Test", "1.2.3"),
        )
        result = await packages.packages_install(
            "testhost", "Test", version="1.2.3", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["installed"] is False
    assert result["data"]["method"] == "noop"
    assert any("already at version 1.2.3" in w for w in result["warnings"])
    # Exactly one DSM call (Package.get) — install_from_server was never invoked.
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_install_idempotent_no_version_given(app_ctx) -> None:
    """version=None + package already installed -> noop (any installed version is fine)."""
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(
            200, json=_get_installed_body("Test", "99.0.0"),
        )
        result = await packages.packages_install(
            "testhost", "Test", app_context=app_ctx,
        )
    assert result["ok"] is True
    assert result["data"]["installed"] is False
    assert result["data"]["version"] == "99.0.0"


@pytest.mark.asyncio
async def test_install_refuses_when_different_version_installed(app_ctx) -> None:
    """Already installed at different version -> category=upgrade_required."""
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json=_get_installed_body("Test", "1.0.0"),
        )
        result = await packages.packages_install(
            "testhost", "Test", version="2.0.0", app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "upgrade_required"
    assert result["data"]["installed_version"] == "1.0.0"
    assert result["data"]["requested_version"] == "2.0.0"
    # Pre-flight short-circuits -> only 1 call (the Package.get probe).
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_install_rejects_empty_package_id(app_ctx) -> None:
    _seed_session(app_ctx)
    with pytest.raises(InvalidParam):
        await packages.packages_install(
            "testhost", "", app_context=app_ctx,
        )


# ===========================================================================
# packages_uninstall — Phase 3c
# ===========================================================================


@pytest.mark.asyncio
async def test_uninstall_happy_path(app_ctx) -> None:
    """Installed + not in denylist + force=False -> uninstall + poll succeed."""
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                # 1. Package.get -> installed at 1.0.0.
                httpx.Response(
                    200, json=_get_installed_body("Test", "1.0.0"),
                ),
                # 2. Uninstall -> task_id.
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"task_id": "uninst_t1"},
                    },
                ),
                # 3. Installation.status poll -> finished.
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"finished": True, "status": "done"},
                    },
                ),
            ]
        )
        result = await packages.packages_uninstall(
            "testhost", "Test", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["uninstalled"] is True
    assert result["data"]["package_id"] == "Test"
    assert result["data"]["previous_version"] == "1.0.0"


@pytest.mark.asyncio
async def test_uninstall_denylist_refuses_without_force(app_ctx) -> None:
    """Denylisted package + force=False -> category=denylist refusal.

    Covers three denylist entries: SnapshotReplication, ContainerManager,
    WebStation — one from each of the three concern-categories (SR
    backbone, Docker stack, web stack).
    """
    _seed_session(app_ctx)
    fake_ssh = MagicMock(spec=DSMSshClient)
    fake_ssh.run = AsyncMock(side_effect=lambda *a, **k: SshResult(
        command="x", stdout="", stderr="", exit_status=0,
    ))
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    for pkg in ("SnapshotReplication", "ContainerManager", "WebStation"):
        with respx.mock(
            base_url="https://192.0.2.10:5001", assert_all_called=False,
        ) as mock:
            route = mock.get("/webapi/entry.cgi").respond(
                200, json=_get_installed_body(pkg, "1.0.0"),
            )
            result = await packages.packages_uninstall(
                "testhost", pkg, app_context=app_ctx,
            )
            assert result["ok"] is False
            assert result["data"]["category"] == "denylist"
            assert result["data"]["package_id"] == pkg
            assert result["data"]["denylist_reason"]
            assert "force=True" in result["data"]["next_step"]
            # NO DSM call fires for a denylist refusal — pre-flight
            # short-circuits before Package.get is even attempted.
            assert route.called is False


@pytest.mark.asyncio
async def test_uninstall_denylist_force_override_proceeds(app_ctx) -> None:
    """Denylisted + force=True -> proceeds, warning records the override."""
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json=_get_installed_body("ContainerManager", "24.0.2"),
                ),
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"task_id": "force_uninst"},
                    },
                ),
                httpx.Response(
                    200,
                    json={
                        "success": True,
                        "data": {"finished": True, "status": "done"},
                    },
                ),
            ]
        )
        result = await packages.packages_uninstall(
            "testhost", "ContainerManager", force=True, app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["uninstalled"] is True
    assert any("force=True override" in w for w in result["warnings"])
    assert any("ContainerManager" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_uninstall_idempotent_when_not_installed(app_ctx) -> None:
    """Package not installed -> ok=True, uninstalled=False, no Uninstall call."""
    _seed_session(app_ctx)
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json=_get_not_installed_body(),
        )
        result = await packages.packages_uninstall(
            "testhost", "NotInstalled", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["uninstalled"] is False
    assert "package not installed" in result["warnings"]
    # Only the Package.get probe call ran — no Uninstall call.
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_uninstall_rejects_empty_package_id(app_ctx) -> None:
    _seed_session(app_ctx)
    with pytest.raises(InvalidParam):
        await packages.packages_uninstall(
            "testhost", "", app_context=app_ctx,
        )


def test_uninstall_denylist_covers_required_packages() -> None:
    """Denylist must include the dependencies the spec calls out."""
    required = {
        "SnapshotReplication", "ReplicationService",
        "ContainerManager", "Docker",
        "StorageManager",
        "WebStation",
        "SecureSignIn", "LDAPServer", "DirectoryServer",
    }
    missing = required - packages._UNINSTALL_DENYLIST.keys()
    assert not missing, f"denylist missing required entries: {missing}"


