# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for user_home.py — respx + mocked SSH for synoinfo/readlink.

Phase 2 tests (tri-check) live at the top. Phase 3b tests
(``user_home_enable`` / ``user_home_disable``) follow below. The
write-tool tests use a mock SSH client with command-string routing so
we can assert the EXACT command sequence — ``synosetkeyvalue``,
``rm -f``, ``ln -s``, ``synouserhome`` — appears in the right order.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from synology_mcp import user_home
from synology_mcp.session import DSMSession
from synology_mcp.transport.ssh import DSMSshClient, SshResult


def _seed_session(app_ctx) -> None:
    state = app_ctx.cache.get("testhost")
    state.session = DSMSession(
        sid="FAKE_SID", syno_token="FAKE_TOKEN", user="testuser",
        cookies={"id": "FAKE_SID"},
    )


def _ssh_with_signals(synoinfo: str | None, symlink: str | None) -> DSMSshClient:
    """Build a fake SSH client that returns canned signal values.

    `synoinfo` is the value emitted by ``synogetkeyvalue ... userHomeEnable``.
    Use None to simulate a missing key (binary present, no output).

    `symlink` is the target of ``readlink /var/services/homes``. Use None
    to simulate a missing symlink.
    """
    fake = MagicMock(spec=DSMSshClient)

    async def _run(command: str, *_, **__) -> SshResult:
        if "synogetkeyvalue" in command:
            if synoinfo is None:
                return SshResult(command=command, stdout="", stderr="",
                                 exit_status=0)
            return SshResult(command=command, stdout=synoinfo, stderr="",
                             exit_status=0)
        if "readlink" in command:
            return SshResult(
                command=command, stdout=(symlink or ""), stderr="",
                exit_status=0,
            )
        if "grep -E" in command:
            # Fallback grep path. Format: userHomeEnable="yes"
            if synoinfo is None:
                return SshResult(command=command, stdout="", stderr="",
                                 exit_status=1)
            return SshResult(
                command=command,
                stdout=f'userHomeEnable="{synoinfo}"', stderr="",
                exit_status=0,
            )
        return SshResult(command=command, stdout="", stderr="", exit_status=0)

    fake.run = AsyncMock(side_effect=_run)
    return fake


@pytest.mark.asyncio
async def test_user_home_all_three_signals_agree_enabled(
    app_ctx, fixture_json,
) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("user_home", "get_enabled.json")
    app_ctx.cache.get("testhost").ssh_client = _ssh_with_signals(
        synoinfo="yes", symlink="/volume1/homes",
    )
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await user_home.user_home_is_enabled(
            "testhost", app_context=app_ctx,
        )
    assert result["ok"] is True
    assert result["data"]["enabled"] is True
    assert result["data"]["web_api_says"] is True
    assert result["data"]["synoinfo_says"] is True
    assert result["data"]["symlink_target"] == "/volume1/homes"
    assert result["warnings"] == []


@pytest.mark.asyncio
async def test_user_home_silent_no_op_pattern_surfaces_warning(
    app_ctx, fixture_json,
) -> None:
    """DSM 7.3 silent no-op: web API says enabled but synoinfo+symlink missing."""
    _seed_session(app_ctx)
    payload = fixture_json("user_home", "get_enabled.json")
    app_ctx.cache.get("testhost").ssh_client = _ssh_with_signals(
        synoinfo=None, symlink=None,
    )
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await user_home.user_home_is_enabled(
            "testhost", app_context=app_ctx,
        )
    assert result["ok"] is True
    # Strict interpretation: only when all three signals agree is User Home
    # truly enabled. Disagreement → enabled=False.
    assert result["data"]["enabled"] is False
    assert result["data"]["web_api_says"] is True
    assert result["data"]["synoinfo_says"] is False
    assert result["data"]["symlink_target"] is None
    # Warning explicitly mentions the disagreement.
    joined = " ".join(result["warnings"])
    assert "signals disagree" in joined
    assert "DSM 7.3 silent-no-op" in joined


@pytest.mark.asyncio
async def test_user_home_all_disabled(app_ctx, fixture_json) -> None:
    _seed_session(app_ctx)
    payload = fixture_json("user_home", "get_disabled.json")
    app_ctx.cache.get("testhost").ssh_client = _ssh_with_signals(
        synoinfo=None, symlink=None,
    )
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await user_home.user_home_is_enabled(
            "testhost", app_context=app_ctx,
        )
    assert result["data"]["enabled"] is False
    assert result["data"]["web_api_says"] is False
    assert result["data"]["synoinfo_says"] is False
    assert result["data"]["symlink_target"] is None
    # All three agree on "off" — no warning needed.
    assert result["warnings"] == []


@pytest.mark.asyncio
async def test_user_home_synoinfo_no_falls_through_to_grep(app_ctx, fixture_json) -> None:
    """When synogetkeyvalue prints 'no', we don't need the grep fallback."""
    _seed_session(app_ctx)
    payload = fixture_json("user_home", "get_disabled.json")
    fake = MagicMock(spec=DSMSshClient)

    async def _run(command: str, *_, **__) -> SshResult:
        if "synogetkeyvalue" in command:
            return SshResult(command=command, stdout="no", stderr="",
                             exit_status=0)
        if "readlink" in command:
            return SshResult(command=command, stdout="", stderr="",
                             exit_status=0)
        return SshResult(command=command, stdout="", stderr="", exit_status=0)

    fake.run = AsyncMock(side_effect=_run)
    app_ctx.cache.get("testhost").ssh_client = fake
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=payload)
        result = await user_home.user_home_is_enabled(
            "testhost", app_context=app_ctx,
        )
    assert result["data"]["synoinfo_says"] is False
    assert result["data"]["enabled"] is False


# ===========================================================================
# Phase 3b helpers
# ===========================================================================


def _ok(stdout: str = "", exit_status: int = 0, stderr: str = "") -> SshResult:
    return SshResult(
        command="x", stdout=stdout, stderr=stderr, exit_status=exit_status,
    )


def _fake_ssh(routes=None) -> DSMSshClient:
    """Command-routing fake SSHClient that also records every command.

    Routes match by substring; first match wins. Default response is a
    zero-exit empty stdout, which is what most "we don't care about
    this command" branches expect.
    """
    fake = MagicMock(spec=DSMSshClient)
    fake.commands = []

    async def _run(command, *_, **__):
        fake.commands.append(command)
        for needle, result in (routes or {}).items():
            if needle in command:
                if callable(result):
                    return result(command)
                return SshResult(
                    command=command,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    exit_status=result.exit_status,
                )
        return SshResult(
            command=command, stdout="", stderr="", exit_status=0,
        )

    fake.run = AsyncMock(side_effect=_run)
    return fake


def _enabled_routes_with_volume() -> dict[str, SshResult]:
    """Routes that make the tri-check report enabled with /volume1/homes."""
    return {
        "synogetkeyvalue": _ok("yes\n"),
        "readlink": _ok("/volume1/homes\n"),
    }


def _disabled_routes() -> dict[str, SshResult]:
    return {
        "synogetkeyvalue": _ok("no\n"),
        "readlink": _ok(""),
    }


# ===========================================================================
# user_home_enable
# ===========================================================================


@pytest.mark.asyncio
async def test_user_home_enable_happy_path_all_four_steps(
    app_ctx, fixture_json,
) -> None:
    """Tri-check disabled → 4 steps run in order: synoinfo, symlink, web API, prepare-folder."""
    _seed_session(app_ctx)
    # Pre-check returns disabled, post step-3 web API also responds — we
    # use mock.mock(side_effect=[...]) to script the two web responses
    # (pre-check ``get`` then ``set``).
    pre_payload = fixture_json("user_home", "get_disabled.json")
    set_ok = {"success": True, "data": {}}

    # SSH script: tri-check sees disabled; auto-volume picker probes the
    # /volume*/homes dirs (empty → falls back to /volume1); the four
    # step commands all succeed.
    fake_ssh = _fake_ssh(_disabled_routes())
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=pre_payload),
                httpx.Response(200, json=set_ok),
            ]
        )
        result = await user_home.user_home_enable(
            "testhost", user="alice", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["user"] == "alice"
    assert result["data"]["volume"] == "/volume1"
    assert result["data"]["partial"] is False
    assert result["data"]["steps_skipped"] == []
    step_names = [s["name"] for s in result["data"]["steps"]]
    assert step_names == ["synoinfo", "symlink", "web_api", "prepare_folder"]
    assert all(s["ok"] for s in result["data"]["steps"])

    # File-state assertion: command stream contains the expected
    # commands in the expected order.
    cmds = fake_ssh.commands
    # Step 1: synosetkeyvalue with userHomeEnable yes.
    assert any(
        "synosetkeyvalue" in c and "userHomeEnable yes" in c for c in cmds
    )
    # Step 2: rm -f /var/services/homes && ln -s /volume1/homes ...
    assert any(
        "rm -f /var/services/homes" in c and "ln -s /volume1/homes" in c
        for c in cmds
    )
    # Step 4: synouserhome --prepare-folder alice.
    assert any(
        "synouserhome" in c and "--prepare-folder" in c and "alice" in c
        for c in cmds
    )


@pytest.mark.asyncio
async def test_user_home_enable_short_circuits_when_already_enabled(
    app_ctx, fixture_json,
) -> None:
    """Tri-check enabled → steps 1-3 skipped; step 4 still runs when user given."""
    _seed_session(app_ctx)
    pre_payload = fixture_json("user_home", "get_enabled.json")
    fake_ssh = _fake_ssh(_enabled_routes_with_volume())
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=pre_payload)
        result = await user_home.user_home_enable(
            "testhost", user="bob", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert "already enabled" in result["warnings"]
    assert result["data"]["steps_skipped"] == [1, 2, 3]
    steps_by_name = {s["name"]: s for s in result["data"]["steps"]}
    assert steps_by_name["synoinfo"]["skipped"] is True
    assert steps_by_name["symlink"]["skipped"] is True
    assert steps_by_name["web_api"]["skipped"] is True
    # Step 4 NOT skipped — user was provided.
    assert steps_by_name["prepare_folder"]["skipped"] is False
    assert steps_by_name["prepare_folder"]["ok"] is True

    # SSH command stream MUST contain the prepare-folder call but MUST
    # NOT contain step-1/2 mutations.
    cmds = fake_ssh.commands
    assert any("synouserhome" in c for c in cmds)
    assert not any(
        "synosetkeyvalue" in c and "userHomeEnable yes" in c for c in cmds
    )
    assert not any("rm -f /var/services/homes" in c for c in cmds)


@pytest.mark.asyncio
async def test_user_home_enable_short_circuits_no_user_skips_all_four(
    app_ctx, fixture_json,
) -> None:
    """Already enabled + no user → all 4 steps recorded as skipped."""
    _seed_session(app_ctx)
    pre_payload = fixture_json("user_home", "get_enabled.json")
    fake_ssh = _fake_ssh(_enabled_routes_with_volume())
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=pre_payload)
        result = await user_home.user_home_enable(
            "testhost", user=None, app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["steps_skipped"] == [1, 2, 3, 4]
    steps_by_name = {s["name"]: s for s in result["data"]["steps"]}
    assert steps_by_name["prepare_folder"]["skipped"] is True


@pytest.mark.asyncio
async def test_user_home_enable_step2_failure_restores_symlink(
    app_ctx, fixture_json,
) -> None:
    """Symlink create fails → rollback restores the previous target, no web API call."""
    _seed_session(app_ctx)
    pre_payload = fixture_json("user_home", "get_disabled.json")

    # SSH script: tri-check sees disabled (synoinfo=no, readlink="");
    # capture-previous-target readlink (called separately by enable)
    # returns the PRIOR target /volume2/homes; step 1 succeeds; step 2
    # (rm + ln) fails; rollback ln to /volume2/homes succeeds.
    readlink_calls = {"n": 0}

    def _readlink_dynamic(cmd: str) -> SshResult:
        # First readlink call is by the tri-check (returns ""); the
        # second is by enable's previous-symlink capture (returns
        # "/volume2/homes"). The fake routes both through this handler.
        readlink_calls["n"] += 1
        if readlink_calls["n"] == 1:
            return SshResult(command=cmd, stdout="", stderr="", exit_status=0)
        return SshResult(
            command=cmd, stdout="/volume2/homes\n", stderr="", exit_status=0,
        )

    step2_calls = {"n": 0}

    def _step2_dynamic(cmd: str) -> SshResult:
        step2_calls["n"] += 1
        # First step2-shaped command is the FAILING enable mutation;
        # second is the rollback restoration — must succeed.
        if step2_calls["n"] == 1:
            return SshResult(command=cmd, stdout="", stderr="link failed",
                             exit_status=1)
        return SshResult(command=cmd, stdout="", stderr="", exit_status=0)

    routes = {
        "synogetkeyvalue": _ok("no\n"),
        "readlink": _readlink_dynamic,
        "synosetkeyvalue": _ok(),
        "rm -f /var/services/homes": _step2_dynamic,
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").respond(200, json=pre_payload)
        result = await user_home.user_home_enable(
            "testhost", user="alice", app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "step_failed"
    assert "step 2" in result["data"]["error"]
    # Step 1 ran OK; step 2 failed.
    by_n = {s["n"]: s for s in result["data"]["steps"]}
    assert by_n[1]["ok"] is True
    assert by_n[2]["ok"] is False
    # No step 3 / 4 recorded — we bailed at step 2.
    assert 3 not in by_n
    # Rollback warning surfaced.
    assert any("rollback ok" in w for w in result["warnings"])
    # Web API call: only the pre-check, not the set call.
    assert route.call_count == 1
    # File-state: command stream contains rollback ``ln -s /volume2/homes``.
    rollback_cmds = [c for c in fake_ssh.commands if "ln -s /volume2/homes" in c]
    assert rollback_cmds, "rollback command must be present"


@pytest.mark.asyncio
async def test_user_home_enable_step3_failure_restores_symlink(
    app_ctx, fixture_json,
) -> None:
    """Web API set fails → rollback symlink and report step_failed."""
    _seed_session(app_ctx)
    pre_payload = fixture_json("user_home", "get_disabled.json")
    # Web API set returns DSM error 101 (invalid param) — picked
    # because the transport layer maps it to InvalidParam, which is
    # one of the codes the enable flow's broad except catches.
    set_err = {"success": False, "error": {"code": 101}}

    readlink_calls = {"n": 0}

    def _readlink_dynamic(cmd: str) -> SshResult:
        readlink_calls["n"] += 1
        if readlink_calls["n"] == 1:
            return SshResult(command=cmd, stdout="", stderr="", exit_status=0)
        return SshResult(
            command=cmd, stdout="/volume1/homes\n", stderr="", exit_status=0,
        )

    routes = {
        "synogetkeyvalue": _ok("no\n"),
        "readlink": _readlink_dynamic,
        "synosetkeyvalue": _ok(),
        "rm -f /var/services/homes": _ok(),  # step 2 + rollback both succeed
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=pre_payload),
                httpx.Response(200, json=set_err),
            ]
        )
        result = await user_home.user_home_enable(
            "testhost", user="alice", app_context=app_ctx,
        )

    assert result["ok"] is False
    assert "step 3" in result["data"]["error"]
    by_n = {s["n"]: s for s in result["data"]["steps"]}
    assert by_n[1]["ok"] is True
    assert by_n[2]["ok"] is True
    assert by_n[3]["ok"] is False
    assert 4 not in by_n
    # Two ``rm -f`` calls in the command stream: enable's mutate +
    # rollback restore.
    rm_cmds = [c for c in fake_ssh.commands if "rm -f /var/services/homes" in c]
    assert len(rm_cmds) == 2


@pytest.mark.asyncio
async def test_user_home_enable_step4_failure_is_partial_success(
    app_ctx, fixture_json,
) -> None:
    """Steps 1-3 succeed, step 4 (per-user prep) fails → ok=True, partial=True, warning."""
    _seed_session(app_ctx)
    pre_payload = fixture_json("user_home", "get_disabled.json")
    set_ok = {"success": True, "data": {}}

    routes = {
        "synogetkeyvalue": _ok("no\n"),
        "readlink": _ok(""),  # tri-check + capture both empty
        "synosetkeyvalue": _ok(),
        "rm -f /var/services/homes": _ok(),
        "synouserhome": _ok(stderr="user not found", exit_status=2),
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=pre_payload),
                httpx.Response(200, json=set_ok),
            ]
        )
        result = await user_home.user_home_enable(
            "testhost", user="alice", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["partial"] is True
    by_n = {s["n"]: s for s in result["data"]["steps"]}
    assert by_n[1]["ok"] is True
    assert by_n[2]["ok"] is True
    assert by_n[3]["ok"] is True
    assert by_n[4]["ok"] is False
    assert any("synouserhome" in w and "alice" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_user_home_enable_volume_override_from_config(
    app_ctx, fixture_json,
) -> None:
    """When host_cfg.user_home_volume is set, the symlink target uses it."""
    _seed_session(app_ctx)
    # Patch config in place — the AppContext lazily resolves host_cfg
    # each call via app_ctx.config.get_host(...).
    app_ctx.config.hosts["testhost"].user_home_volume = "/volume4"
    pre_payload = fixture_json("user_home", "get_disabled.json")
    set_ok = {"success": True, "data": {}}

    routes = {
        "synogetkeyvalue": _ok("no\n"),
        "readlink": _ok(""),
        "synosetkeyvalue": _ok(),
        "rm -f /var/services/homes": _ok(),
        "synouserhome": _ok(),
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=pre_payload),
                httpx.Response(200, json=set_ok),
            ]
        )
        result = await user_home.user_home_enable(
            "testhost", user="alice", app_context=app_ctx,
        )

    assert result["data"]["volume"] == "/volume4"
    # The step-2 command must reference /volume4/homes, NOT /volume1/homes.
    step2 = [c for c in fake_ssh.commands if "ln -s" in c]
    assert any("ln -s /volume4/homes" in c for c in step2)
