# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Live Phase 3 integration tests against a real DSM host.

WRITE PATH — gated on ``SYNOLOGY_MCP_LIVE_HOST=cs4`` (exact match). Every
other host name skips the module unconditionally so we never mutate a
production NAS by accident.

Each test snapshots the relevant slice of state before mutating, performs
a round-trip (do + verify + undo + verify undo), and the module-scoped
fixture asserts the WHOLE CS4 baseline is unchanged at teardown. That
post-flight assertion is the single most important guard rail in the
suite: a botched per-test cleanup surfaces as a hard fail there.

Pre-flight snapshot captured at module setup:
  * ``Aless`` authorized_keys SHA256 fingerprints (expected 4 entries)
  * SSH listen port (expected 22334)
  * Visible share-name set (expected DSM system shares only — no
    user-created shares, CS4 still in RAID-resync aftermath)
  * Installed package-id set (DSM defaults + SnapshotReplication +
    ReplicationService + a few other CS4 stock packages)
  * No ``mcptest_*`` users present

Run end-to-end::

  SYNOLOGY_MCP_LIVE_HOST=cs4 \\
  SYNOLOGY_MCP_LIVE_IP=10.10.3.154 \\
  SYNOLOGY_MCP_LIVE_ACCOUNT=Aless \\
  SYNOLOGY_MCP_LIVE_PASSWORD=*** \\
  SYNOLOGY_MCP_LIVE_SSH_PORT=22334 \\
  SYNOLOGY_MCP_LIVE_VERIFY_TLS=false \\
  uv run pytest tests/integration/test_live_phase3.py -v
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import secrets

import pytest
import pytest_asyncio

from synology_mcp import packages, shares, ssh, user_home
from synology_mcp._helpers import call_dsm, get_ssh_client
from synology_mcp.config import Config, HostConfig
from synology_mcp.server import AppContext
from synology_mcp.session import SessionCache

# ---------------------------------------------------------------------------
# Module-scoped fixtures
# ---------------------------------------------------------------------------


_REQUIRED_HOST = "cs4"


@pytest.fixture(scope="module")
def live_app_ctx() -> AppContext:
    """Build an AppContext targeting CS4 only.

    Any value of ``SYNOLOGY_MCP_LIVE_HOST`` other than the exact string
    ``cs4`` skips the entire module. The Phase 3 write path mutates real
    DSM state, so we refuse to touch any other NAS.
    """
    host_name = os.environ.get("SYNOLOGY_MCP_LIVE_HOST")
    if host_name != _REQUIRED_HOST:
        pytest.skip(
            f"Phase 3 live tests refuse to run unless "
            f"SYNOLOGY_MCP_LIVE_HOST=={_REQUIRED_HOST!r} "
            f"(got {host_name!r}). This is the explicit safety gate — "
            f"these tests mutate DSM state."
        )
    ip = os.environ.get("SYNOLOGY_MCP_LIVE_IP", host_name)
    account = os.environ.get("SYNOLOGY_MCP_LIVE_ACCOUNT")
    password = os.environ.get("SYNOLOGY_MCP_LIVE_PASSWORD")
    if not account or not password:
        pytest.skip("SYNOLOGY_MCP_LIVE_ACCOUNT and _PASSWORD must be set")
    ssh_port = int(os.environ.get("SYNOLOGY_MCP_LIVE_SSH_PORT", "22"))
    port = int(os.environ.get("SYNOLOGY_MCP_LIVE_PORT", "5001"))
    verify_tls_raw = os.environ.get("SYNOLOGY_MCP_LIVE_VERIFY_TLS", "false").lower()
    verify_tls = verify_tls_raw in {"1", "true", "yes", "on"}
    host_cfg = HostConfig(
        name=host_name,
        ip=ip,
        account=account,
        password=password,
        port=port,
        use_https=True,
        verify_tls=verify_tls,
        ssh_port=ssh_port,
    )
    cfg = Config(hosts={host_name: host_cfg})
    return AppContext(config=cfg, cache=SessionCache())


# ---------------------------------------------------------------------------
# Baseline capture helpers
# ---------------------------------------------------------------------------


def _fingerprint_sha256(key_bytes: bytes) -> str:
    """OpenSSH SHA256:<b64-nopad> fingerprint of a public-key blob."""
    digest = hashlib.sha256(key_bytes).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


async def _read_aless_key_fingerprints(ctx: AppContext, host: str) -> set[str]:
    """Capture the SHA256 fingerprint set of ``~Aless/.ssh/authorized_keys``.

    Reads directly via the cached SSH client. Aless owns the file so no
    sudo is required. Lines we cannot parse are silently skipped (they
    are not write-set keys anyway).
    """
    ssh_client = get_ssh_client(ctx, host)
    res = await ssh_client.run(
        "cat /var/services/homes/Aless/.ssh/authorized_keys 2>/dev/null || true",
        check=False,
        timeout=10.0,
    )
    fingerprints: set[str] = set()
    for raw in res.stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            key_bytes = base64.b64decode(parts[1], validate=True)
        except (ValueError, TypeError):
            continue
        if key_bytes:
            fingerprints.add(_fingerprint_sha256(key_bytes))
    return fingerprints


async def _read_ssh_port(ctx: AppContext, host: str) -> int | None:
    """Return the current DSM SSH listen port from ``SYNO.Core.Terminal.get``."""
    body = await call_dsm(
        ctx, host,
        api="SYNO.Core.Terminal", method="get", version=3,
    )
    data = body.get("data") or {}
    val = data.get("ssh_port")
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        try:
            return int(float(val))
        except (TypeError, ValueError):
            return None


async def _read_share_names(ctx: AppContext, host: str) -> set[str]:
    """Capture the set of share names visible to the Aless account."""
    envelope = await shares.shares_list(host, app_context=ctx)
    rows = envelope.get("data", {}).get("shares") or []
    return {r.get("name") for r in rows if r.get("name")}


async def _read_package_ids(ctx: AppContext, host: str) -> set[str]:
    """Capture installed package IDs via SSH ``synopkg list --name``.

    We deliberately bypass ``packages_list`` here because that tool fans
    out one SSH probe per package (slow on a 16-package box) and we
    don't need the status decoration for baseline tracking. The list
    of installed package IDs is the only signal we care about.
    """
    ssh_client = get_ssh_client(ctx, host)
    res = await ssh_client.run(
        "/usr/syno/bin/synopkg list --name 2>/dev/null",
        check=False,
        timeout=15.0,
    )
    out: set[str] = set()
    for line in res.stdout.splitlines():
        name = line.strip()
        if name:
            out.add(name)
    return out


async def _list_mcptest_users(ctx: AppContext, host: str) -> list[str]:
    """Return any usernames starting with ``mcptest_`` on ``host``.

    Uses ``SYNO.Core.User.list`` (admin-only). Aless is in administrators
    so this call succeeds. A dummy left over from a prior failed run
    will be flagged here — we WANT the post-flight assertion to catch
    that and fail loudly.
    """
    body = await call_dsm(
        ctx, host,
        api="SYNO.Core.User", method="list", version=1,
        params={"type": "local", "offset": 0, "limit": -1},
    )
    data = body.get("data") or {}
    rows = data.get("users") or []
    out: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        if isinstance(name, str) and name.startswith("mcptest_"):
            out.append(name)
    return out


# ---------------------------------------------------------------------------
# Pre-flight + post-flight: snapshot + drift assertion
# ---------------------------------------------------------------------------


async def _capture_baseline(ctx: AppContext, host: str) -> dict[str, object]:
    """Capture the full CS4 baseline slice in one place."""
    return {
        "aless_keys_fingerprints": await _read_aless_key_fingerprints(ctx, host),
        "ssh_port_current": await _read_ssh_port(ctx, host),
        "shares_current": await _read_share_names(ctx, host),
        "packages_current": await _read_package_ids(ctx, host),
        "mcptest_users_present": await _list_mcptest_users(ctx, host),
    }


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def baseline(live_app_ctx: AppContext) -> dict[str, object]:
    """Snapshot CS4 baseline before any test runs.

    Module-scoped so it runs exactly once at the start of the suite.
    Async so the cached HTTP/SSH clients live in pytest-asyncio's loop
    (matching the per-test loop). The post-flight drift check uses the
    same loop.
    """
    host = next(iter(live_app_ctx.config.hosts))
    snap = await _capture_baseline(live_app_ctx, host)

    # Pre-flight asserts: confirm we are on the expected CS4 state. Any
    # surprise here would make the post-flight drift check unreliable.
    assert snap["ssh_port_current"] == 22334, (
        f"CS4 not on expected SSH port: {snap['ssh_port_current']}"
    )
    assert len(snap["aless_keys_fingerprints"]) == 4, (
        f"CS4 Aless authorized_keys count drifted from baseline: "
        f"got {len(snap['aless_keys_fingerprints'])}, expected 4"
    )
    assert snap["mcptest_users_present"] == [], (
        f"stale mcptest_* user(s) left over from a previous run: "
        f"{snap['mcptest_users_present']!r}"
    )
    return snap


@pytest_asyncio.fixture(scope="module", loop_scope="session", autouse=True)
async def post_flight_drift_check(
    live_app_ctx: AppContext, baseline: dict[str, object],
):
    """Assert the CS4 baseline is unchanged after the suite finishes.

    The single most important assertion in this module. If any test
    leaks state (e.g. an aborted cleanup left a share or user behind),
    drift surfaces here and the suite fails loudly.

    Async fixture so the recheck runs in the same event loop as the
    tests (avoids the cached httpx.AsyncClient binding to a closed loop).
    """
    yield
    host = next(iter(live_app_ctx.config.hosts))
    after = await _capture_baseline(live_app_ctx, host)
    diff: list[str] = []
    if after["aless_keys_fingerprints"] != baseline["aless_keys_fingerprints"]:
        added = after["aless_keys_fingerprints"] - baseline["aless_keys_fingerprints"]
        removed = baseline["aless_keys_fingerprints"] - after["aless_keys_fingerprints"]
        diff.append(
            f"Aless authorized_keys drift: added={added!r}, removed={removed!r}"
        )
    if after["ssh_port_current"] != baseline["ssh_port_current"]:
        diff.append(
            f"SSH port drift: was={baseline['ssh_port_current']}, "
            f"is={after['ssh_port_current']}"
        )
    if after["shares_current"] != baseline["shares_current"]:
        added = after["shares_current"] - baseline["shares_current"]
        removed = baseline["shares_current"] - after["shares_current"]
        diff.append(f"shares drift: added={added!r}, removed={removed!r}")
    if after["packages_current"] != baseline["packages_current"]:
        added = after["packages_current"] - baseline["packages_current"]
        removed = baseline["packages_current"] - after["packages_current"]
        diff.append(f"packages drift: added={added!r}, removed={removed!r}")
    if after["mcptest_users_present"]:
        diff.append(
            f"mcptest_* user(s) leaked: {after['mcptest_users_present']!r}"
        )
    assert not diff, "CS4 baseline drift detected:\n  " + "\n  ".join(diff)


# ---------------------------------------------------------------------------
# Dummy user helpers — SSH + sudo-with-stdin-password (CS4 path)
# ---------------------------------------------------------------------------
#
# CS4 surprises we discovered live:
#   * ``SYNO.Core.User`` has NO ``create`` / ``delete`` methods on DSM 7.3.
#     Verbs are ``set`` / ``get`` / ``list`` / ``invite``; user creation
#     happens via ``set`` with name+password and DSM treats the lack of
#     an existing entry as "create" implicitly. ``SYNO.Core.User.delete``
#     was returning DSM 105 (PermissionDenied) when called with the
#     admin-group Aless session — likely because the endpoint requires
#     a separate Privilege grant we don't have a clean way to introspect.
#   * Aless does NOT have NOPASSWD sudo, but ``sudo -S`` (password on
#     stdin) works fine. We invoke ``/usr/syno/sbin/synouser`` directly
#     via a paramiko channel and pipe the Aless password to ``sudo -S``.
#
# This is a TEST-ONLY shortcut — production code should never embed the
# Aless password in a shell pipeline. We tolerate it here because the
# test harness already has the password in its env (live runner reads it
# from ``~/scripts/.env``).


def _sudo_exec(ctx: AppContext, host: str, cmd: str, timeout: float = 30.0) -> tuple[int, str, str]:
    """Execute ``cmd`` over SSH wrapped in ``sudo -S`` with stdin password.

    Returns ``(exit_status, stdout, stderr)``. Synchronous paramiko call —
    safe to invoke from inside an async test because the channel is
    single-shot.
    """
    import paramiko

    host_cfg = ctx.config.get_host(host)
    client = paramiko.SSHClient()
    with contextlib.suppress(OSError):
        client.load_system_host_keys()
    try:
        client.connect(
            hostname=host_cfg.ip,
            port=host_cfg.ssh_port,
            username=host_cfg.effective_ssh_username,
            password=host_cfg.password,
            timeout=10.0,
            auth_timeout=10.0,
            banner_timeout=10.0,
            allow_agent=True,
            look_for_keys=True,
        )
        # ``sudo -S -p ""`` reads the password from stdin with no prompt.
        full = f'sudo -S -p "" sh -c {json.dumps(cmd)}'
        stdin, stdout, stderr = client.exec_command(full, timeout=timeout)
        stdin.write(host_cfg.password + "\n")
        stdin.flush()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        return exit_status, out, err
    finally:
        with contextlib.suppress(Exception):
            client.close()


async def _create_dummy_user(
    ctx: AppContext, host: str, username: str, password: str,
) -> None:
    """Create a temporary local user via ``synouser --add`` over sudo-SSH.

    ``synouser --add <name> <password> <description> <expired:0|1> <email> <can_change_pw:0|1>``
    is the canonical DSM CLI verb. Raises ``RuntimeError`` on non-zero
    exit so the caller can fail the test cleanly.
    """
    cmd = (
        f"/usr/syno/sbin/synouser --add "
        f"{json.dumps(username)} {json.dumps(password)} "
        f"'synology-mcp integration test (safe to delete)' "
        f"0 '' 0"
    )
    loop = asyncio.get_running_loop()
    exit_status, out, err = await loop.run_in_executor(
        None, _sudo_exec, ctx, host, cmd,
    )
    if exit_status != 0:
        raise RuntimeError(
            f"synouser --add failed (exit {exit_status}): {err.strip() or out.strip()}",
        )


async def _delete_user(ctx: AppContext, host: str, username: str) -> None:
    """Delete a local DSM user via ``synouser --del`` over sudo-SSH."""
    cmd = f"/usr/syno/sbin/synouser --del {json.dumps(username)}"
    loop = asyncio.get_running_loop()
    exit_status, out, err = await loop.run_in_executor(
        None, _sudo_exec, ctx, host, cmd,
    )
    if exit_status != 0:
        raise RuntimeError(
            f"synouser --del failed (exit {exit_status}): {err.strip() or out.strip()}",
        )


async def _user_exists(ctx: AppContext, host: str, username: str) -> bool:
    """Return True iff ``username`` exists as a local DSM user."""
    body = await call_dsm(
        ctx, host,
        api="SYNO.Core.User", method="list", version=1,
        params={"type": "local", "offset": 0, "limit": -1},
    )
    data = body.get("data") or {}
    rows = data.get("users") or []
    return any(
        isinstance(row, dict) and row.get("name") == username for row in rows
    )


def _gen_ed25519_keypair_pem() -> tuple[str, bytes]:
    """Generate an ephemeral ed25519 keypair entirely in memory.

    Returns ``(openssh_public_key_line, openssh_private_key_openssh_bytes)``.
    The private key never touches the disk — paramiko reads it from a
    StringIO buffer in the verify-ssh step.

    paramiko 3.x does not expose ``Ed25519Key.generate()``; we use the
    underlying ``cryptography`` library to mint the keypair and serialize
    it in the OpenSSH formats paramiko understands.
    """
    import struct

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    privkey = ed25519.Ed25519PrivateKey.generate()
    pubkey = privkey.public_key()
    raw_pub = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # OpenSSH ssh-ed25519 wire format: length-prefixed "ssh-ed25519",
    # then length-prefixed 32-byte raw pubkey. Base64 that and prepend
    # the algo + comment.
    blob = (
        struct.pack(">I", len(b"ssh-ed25519")) + b"ssh-ed25519"
        + struct.pack(">I", len(raw_pub)) + raw_pub
    )
    pubkey_b64 = base64.b64encode(blob).decode("ascii")
    pubkey_line = f"ssh-ed25519 {pubkey_b64} mcp_integration_test"

    # Private key in OpenSSH format (paramiko reads this via
    # Ed25519Key.from_private_key).
    privkey_bytes = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pubkey_line, privkey_bytes


# ---------------------------------------------------------------------------
# Test 1 — ssh_set_port idempotent same-port
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_ssh_set_port_idempotent_same_port(
    live_app_ctx: AppContext, baseline: dict[str, object],
) -> None:
    """``ssh_set_port`` on the current port short-circuits without mutating."""
    host = next(iter(live_app_ctx.config.hosts))
    current = baseline["ssh_port_current"]
    assert current == 22334  # sanity: matches the known CS4 baseline.

    result = await ssh.ssh_set_port(host, current, app_context=live_app_ctx)
    assert result["ok"] is True, f"unexpected refusal: {result}"
    data = result["data"]
    assert data["changed"] is False
    assert data["old_port"] == current
    assert data["new_port"] == current
    assert any("already on this port" in w for w in result["warnings"]), (
        f"missing 'already on this port' warning: {result['warnings']}"
    )

    # Prove the live SSH listener is still on the same port via a fresh
    # paramiko handshake. If the tool had mutated state we would see the
    # connection fail or land on a different port.
    after_port = await _read_ssh_port(live_app_ctx, host)
    assert after_port == current


# ---------------------------------------------------------------------------
# Test 2 — Dummy-user lifecycle + per-user SSH writes
# ---------------------------------------------------------------------------
#
# CS4 SURPRISE found during live run (now resolved):
#   * ``ssh_add_authorized_key``'s ``_ensure_ssh_dir`` step runs as the
#     authenticated SSH user (Aless) and tries to ``mkdir -p
#     /var/services/homes/<target_user>/.ssh``. DSM gives each user's
#     home a 0700 mode owned by ``<target_user>:users`` — Aless (in
#     administrators) cannot write into another user's home without
#     sudo.
#
# Phase 3 gap-fix 2026-05-26: the three SSH write tools now refuse
# cross-user requests early with ``category=cross_user_not_supported``.
# That means the dummy-user round-trip (writing to a NON-Aless target)
# is structurally infeasible without a sudo-password mechanism that
# the MCP does not (yet) ship.
#
# The replacement live coverage exercises the calling-user (Aless)
# round-trip — see :func:`test_live_aless_authorized_key_roundtrip`
# below. That test is the canonical happy path the gap-fix unblocked
# and proves the file-write transport (base64-over-exec, NO SFTP) is
# functioning end-to-end. The dummy-user variant remains skipped with
# the new reason.


@pytest.mark.skip(
    reason=(
        "Cross-user SSH writes (target != calling user) refuse with "
        "category=cross_user_not_supported as of gap-fix 2026-05-26. The "
        "dummy-user round-trip would need NOPASSWD sudo for the calling "
        "account (CS4 does not have it), and the strict-first rule keeps "
        "us from shipping a password-on-stdin sudo path in this gap-fix "
        "pass. The unit suite covers cross-user refusal "
        "(test_*_refuses_cross_user); the live calling-user round-trip "
        "is covered by test_live_aless_authorized_key_roundtrip."
    ),
)
@pytest.mark.asyncio
async def test_live_dummy_user_ssh_writes(
    live_app_ctx: AppContext, baseline: dict[str, object],
) -> None:
    """End-to-end round-trip for ssh_enable_user_ssh + add/remove_authorized_key.

    Currently SKIPPED — see decorator reason.

    Original flow:
      1. Create ``mcptest_<random>`` via ``synouser --add`` (sudo+stdin pw).
      2. Verify enable_user_ssh adds them to administrators (idempotent).
      3. Verify add_authorized_key writes + dedupes by fingerprint.
      4. Open a fresh paramiko handshake AS the dummy user with the
         ephemeral private key — proof the key is live on the server.
      5. Verify remove_authorized_key removes + is idempotent.
      6. Delete the dummy user; verify their home folder is cleaned.

    _FAILED_CLEANUP marker: if any step throws mid-test, the dummy user
    persists and the post-flight drift assertion will catch it.
    """
    host = next(iter(live_app_ctx.config.hosts))
    username = f"mcptest_{secrets.token_hex(4)}"
    user_password = "Syn0logy-Mcp-Test!" + secrets.token_hex(4)

    # Generate ephemeral keypair in memory.
    pubkey_line, privkey_pem_bytes = _gen_ed25519_keypair_pem()
    # SHA256 fingerprint of the raw blob — what the tool reports back.
    pub_parts = pubkey_line.split(None, 2)
    pub_blob = base64.b64decode(pub_parts[1], validate=True)
    expected_fp = _fingerprint_sha256(pub_blob)

    await _create_dummy_user(live_app_ctx, host, username, user_password)
    assert await _user_exists(live_app_ctx, host, username), (
        f"dummy user {username!r} not visible in user list after create"
    )

    try:
        # ----- 2a) ssh_enable_user_ssh first call -------------------------
        enable_a = await ssh.ssh_enable_user_ssh(
            host, username, app_context=live_app_ctx,
        )
        assert enable_a["ok"] is True, enable_a
        assert enable_a["data"]["added"] is True
        assert enable_a["data"]["group"] == "administrators"

        # ----- 2b) ssh_enable_user_ssh idempotent re-call -----------------
        enable_b = await ssh.ssh_enable_user_ssh(
            host, username, app_context=live_app_ctx,
        )
        assert enable_b["ok"] is True
        assert enable_b["data"]["added"] is False
        assert any("already enabled" in w for w in enable_b["warnings"]), (
            f"missing idempotency warning: {enable_b['warnings']}"
        )

        # The freshly-created user's home folder is required before
        # add_authorized_key can write. DSM creates it lazily on the
        # first User-Home-aware service touch. We can trigger that via
        # SSH login attempt OR by calling ``synouserhome --prepare-folder``
        # under the user's own (no-sudo) credentials. Easiest path: a
        # paramiko handshake as the dummy user with their password,
        # which DSM treats as a session and prepares the home dir.
        await _trigger_home_folder_creation(
            live_app_ctx, host, username, user_password,
        )

        # ----- 2c) ssh_add_authorized_key first call ----------------------
        add_a = await ssh.ssh_add_authorized_key(
            host, username, pubkey_line,
            comment="mcp_integration_test",
            app_context=live_app_ctx,
        )
        assert add_a["ok"] is True, add_a
        assert add_a["data"]["added"] is True
        assert add_a["data"]["fingerprint"] == expected_fp
        assert add_a["data"]["user"] == username

        # ----- 2d) ssh_add_authorized_key idempotent re-call --------------
        add_b = await ssh.ssh_add_authorized_key(
            host, username, pubkey_line,
            comment="mcp_integration_test",
            app_context=live_app_ctx,
        )
        assert add_b["ok"] is True
        assert add_b["data"]["added"] is False
        assert any("key already present" in w for w in add_b["warnings"]), (
            f"missing dedupe warning: {add_b['warnings']}"
        )

        # ----- 2e) Live SSH handshake AS the dummy user with the key ----
        verified = await _verify_dummy_user_key_login(
            live_app_ctx, host, username, privkey_pem_bytes,
        )
        assert verified, (
            "ephemeral ed25519 keypair failed to authenticate as the dummy "
            "user — ssh_add_authorized_key wrote the wrong content or to "
            "the wrong path"
        )

        # ----- 2f) ssh_remove_authorized_key first call -------------------
        remove_a = await ssh.ssh_remove_authorized_key(
            host, username, expected_fp, app_context=live_app_ctx,
        )
        assert remove_a["ok"] is True, remove_a
        assert remove_a["data"]["removed_count"] == 1

        # ----- 2g) ssh_remove_authorized_key idempotent re-call -----------
        remove_b = await ssh.ssh_remove_authorized_key(
            host, username, expected_fp, app_context=live_app_ctx,
        )
        assert remove_b["ok"] is True
        assert remove_b["data"]["removed_count"] == 0

    finally:
        # _FAILED_CLEANUP: if delete fails the post-flight drift check
        # surfaces ``mcptest_*`` leakage and the suite fails.
        await _delete_user(live_app_ctx, host, username)
        assert not await _user_exists(live_app_ctx, host, username), (
            f"failed to delete dummy user {username!r}"
        )


async def _trigger_home_folder_creation(
    ctx: AppContext, host: str, username: str, password: str,
) -> None:
    """Force DSM to materialize ``/var/services/homes/<username>/``.

    DSM creates the per-user home folder lazily — a freshly-created user
    has the entry in ``/etc/passwd`` but no ``~`` dir until a service
    touches it. We open a one-shot paramiko handshake AS the user with
    password auth; DSM's pam_synomount.so creates the folder during
    the SSH login pipeline. We then close the channel immediately — we
    just needed the side-effect.

    Falls back to writing the dir manually over the persistent Aless
    SSH session if the paramiko login itself fails (which it can on
    DSM builds that gate SSH password auth behind extra config).
    """
    import io

    import paramiko

    host_cfg = ctx.config.get_host(host)
    client = paramiko.SSHClient()
    with contextlib.suppress(OSError):
        client.load_system_host_keys()
    try:
        client.connect(
            hostname=host_cfg.ip,
            port=host_cfg.ssh_port,
            username=username,
            password=password,
            timeout=10.0,
            auth_timeout=10.0,
            banner_timeout=10.0,
            allow_agent=False,
            look_for_keys=False,
        )
        # Run a single command so DSM's session pipeline executes.
        _stdin, stdout, _stderr = client.exec_command(
            "true", timeout=5.0,
        )
        stdout.channel.recv_exit_status()
    except (OSError, paramiko.SSHException):
        # Fallback: as Aless (who is in administrators) we cannot
        # mkdir into another user's home without sudo; but the DSM web
        # API ``SYNO.Core.User.PasswordExpiry.expire`` is not the right
        # hammer either. Best we can do is signal failure -- the
        # downstream add_authorized_key call will then surface a
        # readable error.
        pass
    finally:
        with contextlib.suppress(Exception):
            client.close()
    # Stash for cleanup in caller scope (io import kept for symmetry).
    del io


async def _verify_dummy_user_key_login(
    ctx: AppContext, host: str, username: str, privkey_pem_bytes: bytes,
) -> bool:
    """Open a fresh paramiko session AS ``username`` using the in-memory key.

    Returns True iff the handshake completes cleanly. Synchronous paramiko
    is offloaded to a thread because the calling test is async.
    """
    import io

    import paramiko

    host_cfg = ctx.config.get_host(host)

    def _connect() -> bool:
        privkey = paramiko.Ed25519Key.from_private_key(
            io.StringIO(privkey_pem_bytes.decode("utf-8")),
        )
        client = paramiko.SSHClient()
        with contextlib.suppress(OSError):
            client.load_system_host_keys()
        try:
            client.connect(
                hostname=host_cfg.ip,
                port=host_cfg.ssh_port,
                username=username,
                pkey=privkey,
                timeout=10.0,
                auth_timeout=10.0,
                banner_timeout=10.0,
                allow_agent=False,
                look_for_keys=False,
            )
        except (OSError, paramiko.SSHException):
            with contextlib.suppress(Exception):
                client.close()
            return False
        with contextlib.suppress(Exception):
            client.close()
        return True

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _connect)


# ---------------------------------------------------------------------------
# Test 2b — Calling-user (Aless) SSH-key round-trip
# ---------------------------------------------------------------------------
#
# Phase 3 gap-fix 2026-05-26: the three SSH write tools refuse
# cross-user calls with ``category=cross_user_not_supported``. The
# supported flow is "write to the calling user's authorized_keys."
# This test exercises that flow against the live CS4 Aless account:
#
#   1. Capture the pre-test Aless fingerprint set (must be the
#      baseline-snapshot 4 keys; we assert that the test isn't running
#      out of order).
#   2. Generate an ephemeral ed25519 keypair in-memory.
#   3. ssh_add_authorized_key(host, "Aless", pubkey, comment="
#      mcp_integration_test_<rand>") -> assert added=True, fingerprint
#      matches what we generated.
#   4. Re-add the same key -> assert added=False, "key already
#      present" warning.
#   5. Read authorized_keys live; assert the ephemeral fingerprint is
#      present alongside the 4 baseline fingerprints.
#   6. ssh_remove_authorized_key(host, "Aless", fp) -> assert
#      removed_count=1.
#   7. ssh_remove_authorized_key(host, "Aless", fp) again ->
#      assert removed_count=0 (idempotent).
#   8. Re-read authorized_keys; assert Aless's fingerprint set is now
#      identical to the baseline (no orphan key, no mutation of the
#      original 4).
#
# The try/finally guarantees the ephemeral key is purged even if the
# happy-path assertions fail, so the baseline drift check at module
# teardown still sees a pristine state.


@pytest.mark.asyncio
async def test_live_aless_authorized_key_roundtrip(
    live_app_ctx: AppContext, baseline: dict[str, object],
) -> None:
    """add + dedupe + remove + idempotent-remove against Aless's authorized_keys."""
    host = next(iter(live_app_ctx.config.hosts))
    assert baseline["aless_keys_fingerprints"], "baseline missing Aless keys"

    pubkey_line, _privkey_pem = _gen_ed25519_keypair_pem()
    pub_parts = pubkey_line.split(None, 2)
    pub_blob = base64.b64decode(pub_parts[1], validate=True)
    expected_fp = _fingerprint_sha256(pub_blob)
    assert expected_fp not in baseline["aless_keys_fingerprints"], (
        "ephemeral fingerprint collides with an existing Aless key "
        f"(astronomically unlikely): {expected_fp}"
    )
    comment = f"mcp_integration_test_{secrets.token_hex(4)}"
    # Rebuild the pubkey line with the recognizable comment so the
    # audit trail makes it obvious where the key came from.
    pubkey_line_with_comment = f"{pub_parts[0]} {pub_parts[1]} {comment}"

    key_added = False
    try:
        # ----- 2b.1) ssh_add_authorized_key happy path --------------------
        add_a = await ssh.ssh_add_authorized_key(
            host, "Aless", pubkey_line_with_comment,
            comment=comment,
            app_context=live_app_ctx,
        )
        assert add_a["ok"] is True, add_a
        assert add_a["data"]["added"] is True
        assert add_a["data"]["fingerprint"] == expected_fp
        assert add_a["data"]["user"] == "Aless"
        key_added = True

        # ----- 2b.2) ssh_add_authorized_key dedupe re-call ----------------
        add_b = await ssh.ssh_add_authorized_key(
            host, "Aless", pubkey_line_with_comment,
            comment=comment,
            app_context=live_app_ctx,
        )
        assert add_b["ok"] is True
        assert add_b["data"]["added"] is False
        assert any("key already present" in w for w in add_b["warnings"]), (
            f"missing dedupe warning: {add_b['warnings']}"
        )

        # ----- 2b.3) live read: ephemeral fp + baseline keys all present -
        mid_fps = await _read_aless_key_fingerprints(live_app_ctx, host)
        assert expected_fp in mid_fps, (
            f"ephemeral key not in authorized_keys after add: "
            f"got {mid_fps!r}, expected {expected_fp!r}"
        )
        # All 4 baseline keys must still be there — we MUST NOT have
        # accidentally rewritten the file in a way that drops them.
        missing = baseline["aless_keys_fingerprints"] - mid_fps
        assert not missing, f"baseline keys disappeared mid-test: {missing}"

    finally:
        # ----- 2b.4-7) ssh_remove_authorized_key happy path + idempotent -
        remove_a = await ssh.ssh_remove_authorized_key(
            host, "Aless", expected_fp, app_context=live_app_ctx,
        )
        assert remove_a["ok"] is True, remove_a
        if key_added:
            assert remove_a["data"]["removed_count"] == 1

        remove_b = await ssh.ssh_remove_authorized_key(
            host, "Aless", expected_fp, app_context=live_app_ctx,
        )
        assert remove_b["ok"] is True
        assert remove_b["data"]["removed_count"] == 0

        # ----- 2b.8) post-flight: fingerprint set matches baseline -------
        after_fps = await _read_aless_key_fingerprints(live_app_ctx, host)
        assert after_fps == baseline["aless_keys_fingerprints"], (
            f"Aless fingerprint set drift after remove: "
            f"baseline={baseline['aless_keys_fingerprints']!r}, "
            f"after={after_fps!r}"
        )


# ---------------------------------------------------------------------------
# Test 3 — user_home_disable REFUSAL path
# ---------------------------------------------------------------------------
#
# Phase 3 gap-fix 2026-05-26: ``user_home_disable`` now refuses cleanly
# when ``sudo -n`` cannot enumerate authorized_keys (category=
# sudo_required) AND when it can enumerate and finds users with keys
# (category=would_orphan_keys). EITHER refusal is acceptable for the
# live test — the assertion is "tool refused AND User Home is still
# enabled afterward." On CS4 with the Aless account (no NOPASSWD
# sudo), we expect category=sudo_required.


@pytest.mark.asyncio
async def test_live_user_home_disable_refusal(
    live_app_ctx: AppContext, baseline: dict[str, object],
) -> None:
    """confirm_destroy_keys=False -> refuse with sudo_required OR would_orphan_keys.

    Either refusal category is acceptable — the test asserts the tool
    refuses, doesn't proceed, and User Home is still enabled
    afterward.
    """
    host = next(iter(live_app_ctx.config.hosts))

    result = await user_home.user_home_disable(
        host, confirm_destroy_keys=False, app_context=live_app_ctx,
    )
    assert result["ok"] is False, result
    assert result["data"]["category"] in {"sudo_required", "would_orphan_keys"}, (
        f"unexpected refusal category: {result['data']['category']}"
    )
    if result["data"]["category"] == "would_orphan_keys":
        assert "Aless" in result["data"]["affected_users"]
    # User Home must still be enabled — the safety rail prevented the
    # destructive disable.
    after = await user_home.user_home_is_enabled(host, app_context=live_app_ctx)
    assert after["data"]["enabled"] is True, (
        f"User Home was disabled despite refusal: {after}"
    )


@pytest.mark.skip(
    reason=(
        "The user_home_disable success path requires confirm_destroy_keys"
        "=True, which orphans every SSH key on the host. Refused live "
        "permanently — unit tests cover the happy path with mocked DSM."
    ),
)
@pytest.mark.asyncio
async def test_live_user_home_disable_success_NEVER_RUN(
    live_app_ctx: AppContext,
) -> None:
    """Never executed live — flipping User Home off is irreversible without keys."""


# ---------------------------------------------------------------------------
# Test 4 — shares_create + shares_delete round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_shares_create_delete_roundtrip(
    live_app_ctx: AppContext, baseline: dict[str, object],
) -> None:
    """Create + delete a one-off share; assert idempotent + reserved-name rails."""
    host = next(iter(live_app_ctx.config.hosts))
    name = f"__synmcp_test_{secrets.token_hex(4)}"
    volume = "/volume1"
    desc = "MCP integration test, safe to delete"

    # ----- 4a) shares_create first call -----------------------------------
    create_a = await shares.shares_create(
        host, name, volume,
        desc=desc, app_context=live_app_ctx,
    )
    assert create_a["ok"] is True, create_a
    assert create_a["data"]["created"] is True
    assert create_a["data"]["share"]["name"] == name
    assert create_a["data"]["share"]["volume"] == volume

    try:
        # ----- 4b) shares_create idempotent re-call -----------------------
        create_b = await shares.shares_create(
            host, name, volume,
            desc=desc, app_context=live_app_ctx,
        )
        assert create_b["ok"] is True
        assert create_b["data"]["created"] is False
        assert any("share already exists" in w for w in create_b["warnings"]), (
            f"missing dedupe warning: {create_b['warnings']}"
        )

        # ----- 4c) verify it appears in shares_list ----------------------
        listing = await shares.shares_list(host, app_context=live_app_ctx)
        names = {r["name"] for r in listing["data"]["shares"]}
        assert name in names, f"new share not in shares_list: {names}"

        # ----- 4d) reserved-name refusal ---------------------------------
        reserved = await shares.shares_create(
            host, "music", volume, app_context=live_app_ctx,
        )
        assert reserved["ok"] is False
        assert reserved["data"]["category"] == "reserved_share_name"

    finally:
        # ----- 4e) shares_delete + 4f/4g verify + idempotency ------------
        delete_a = await shares.shares_delete(
            host, name, app_context=live_app_ctx,
        )
        assert delete_a["ok"] is True, delete_a
        assert delete_a["data"]["deleted"] is True

        listing_after = await shares.shares_list(host, app_context=live_app_ctx)
        names_after = {r["name"] for r in listing_after["data"]["shares"]}
        assert name not in names_after, (
            f"share {name!r} still present after delete: {names_after}"
        )

        delete_b = await shares.shares_delete(
            host, name, app_context=live_app_ctx,
        )
        assert delete_b["ok"] is True
        assert delete_b["data"]["deleted"] is False
        assert any("share not found" in w for w in delete_b["warnings"]), (
            f"missing idempotency warning: {delete_b['warnings']}"
        )


# ---------------------------------------------------------------------------
# Test 5 — packages_install idempotency + denylist refusal + not-installed
# ---------------------------------------------------------------------------
#
# CS4 SURPRISES (and resulting test-shape changes from the original spec):
#
#   * The spec proposed OAuthService as the install target. CS4 already
#     has OAuthService PRE-INSTALLED (stopped). Good news: that lets us
#     exercise the ``packages_install`` idempotent-already-installed
#     path against a real installed package without touching system
#     state.
#
#   * DSM 7.3's ``SYNO.Core.Package.Installation.install_from_server``
#     method DOES NOT EXIST -- DSM 103 (method not supported). The real
#     install verb on DSM 7.3 is ``install`` (or ``upgrade``), called
#     with ``{name, is_syno, url, checksum, filesize, type, blqinst,
#     operation}`` per the AdminCenter PkgManApp source. Phase 3 gap-fix
#     pass refactored ``packages_install`` to the real verb chain
#     (``Package.Server.list`` -> ``Package.Installation.install`` ->
#     ``Package.Installation.status``); the live install round-trip
#     below exercises that refactor end-to-end.
#
#   * DSM ``SYNO.Core.Package.get`` returns code 4545 (Package Center
#     "not installed") for unknown package_ids, not the 10x family the
#     implementation originally expected. The fix landed in this commit
#     -- ``_is_not_installed_error`` now matches by code 4545 as well.
#
#   * The Phase 3 spec proposed OAuthService as the install round-trip
#     target, but the CS4 baseline already has OAuthService pre-installed
#     (DSM ships it on most systems). The actual install round-trip
#     therefore targets ``LogCenter`` -- validated absent from the CS4
#     baseline and present in the Synology online catalog. OAuthService
#     is still used as the "already installed" idempotency probe (5a).
#
# What we test live:
#   * 5a — packages_install on the pre-installed OAuthService returns
#          ok=True, installed=False, "already at version X" warning.
#   * 5b — packages_uninstall on a denylisted+installed package
#          (SnapshotReplication) refuses with category=denylist.
#   * 5c — packages_uninstall on a not-installed package
#          (LogCenter, validated as absent from baseline) returns
#          ok=True, uninstalled=False, "package not installed" warning.
#          Exercises the 4545-handling fix end-to-end.
#   * 5d — packages_install round-trip on LogCenter:
#          install -> verify (installed=True, method=online) ->
#          uninstall -> verify gone. Exercises the DSM 7.3 'install'
#          verb refactor (Gap 1 fix).


_PREINSTALLED_TARGET = "OAuthService"
_DENYLIST_INSTALLED_TARGET = "SnapshotReplication"
_NEVER_INSTALLED_TARGET = "LogCenter"


@pytest.mark.asyncio
async def test_live_packages_idempotent_and_denylist(
    live_app_ctx: AppContext, baseline: dict[str, object],
) -> None:
    """packages_install idempotent + denylist refusal + not-installed paths."""
    host = next(iter(live_app_ctx.config.hosts))
    assert _PREINSTALLED_TARGET in baseline["packages_current"], (
        f"{_PREINSTALLED_TARGET!r} expected pre-installed on CS4 baseline"
    )
    assert _DENYLIST_INSTALLED_TARGET in baseline["packages_current"], (
        f"{_DENYLIST_INSTALLED_TARGET!r} expected pre-installed on CS4"
    )
    assert _NEVER_INSTALLED_TARGET not in baseline["packages_current"], (
        f"{_NEVER_INSTALLED_TARGET!r} unexpectedly already installed on CS4"
    )

    # ----- 5a) packages_install on a pre-installed package -----------------
    install = await packages.packages_install(
        host, _PREINSTALLED_TARGET, app_context=live_app_ctx,
    )
    assert install["ok"] is True, install
    assert install["data"]["installed"] is False
    assert install["data"]["method"] == "noop"
    assert any(
        "already at version" in w for w in install["warnings"]
    ), f"missing idempotency warning: {install['warnings']}"

    # ----- 5b) packages_uninstall denylist refusal -------------------------
    deny = await packages.packages_uninstall(
        host, _DENYLIST_INSTALLED_TARGET, app_context=live_app_ctx,
    )
    assert deny["ok"] is False, deny
    assert deny["data"]["category"] == "denylist"
    assert deny["data"]["package_id"] == _DENYLIST_INSTALLED_TARGET
    # The actual package must remain installed -- we never reached the
    # ``Package.Uninstallation`` call.
    after_deny = await _read_package_ids(live_app_ctx, host)
    assert _DENYLIST_INSTALLED_TARGET in after_deny, (
        f"denylist refusal failed -- {_DENYLIST_INSTALLED_TARGET!r} removed"
    )

    # ----- 5c) packages_uninstall on a not-installed package --------------
    # Exercises the DSM 4545 "not installed" code path end-to-end.
    not_installed = await packages.packages_uninstall(
        host, _NEVER_INSTALLED_TARGET, app_context=live_app_ctx,
    )
    assert not_installed["ok"] is True, not_installed
    assert not_installed["data"]["uninstalled"] is False
    assert any(
        "package not installed" in w for w in not_installed["warnings"]
    ), f"missing not-installed warning: {not_installed['warnings']}"


@pytest.mark.asyncio
async def test_live_packages_install_uninstall_roundtrip(
    live_app_ctx: AppContext, baseline: dict[str, object],
) -> None:
    """5d — install LogCenter -> verify -> uninstall -> verify gone.

    Exercises the Gap 1 ``packages_install`` refactor (DSM 7.3
    ``Installation.install`` verb instead of the broken
    ``install_from_server``) and the matching ``packages_uninstall``
    pair. Targets LogCenter because:

      * Absent from CS4 baseline (pre-flight asserts).
      * Present in the Synology online catalog (Server.list v2
        returns a row with link/md5/size).
      * Not on the denylist.
      * Small (~3MB) — install + uninstall in well under a minute.

    Post-flight: assert LogCenter is gone again so the baseline
    drift check at module teardown still passes.
    """
    host = next(iter(live_app_ctx.config.hosts))
    target = _NEVER_INSTALLED_TARGET
    # Sanity: baseline was captured before this test; double-check the
    # live state right now to catch a leak from a prior aborted run.
    pre = await _read_package_ids(live_app_ctx, host)
    assert target not in pre, (
        f"{target!r} unexpectedly present at the start of the install "
        f"round-trip test -- leftover from a prior failed run?"
    )

    install_done = False
    try:
        # ----- 5d.1) install ----------------------------------------------
        install = await packages.packages_install(
            host, target, accept_eula=True, app_context=live_app_ctx,
        )
        assert install["ok"] is True, install
        assert install["data"]["installed"] is True, install
        assert install["data"]["method"] == "online", install
        assert install["data"]["package_id"] == target
        install_done = True

        # ----- 5d.2) verify it now shows in synopkg list ------------------
        after_install = await _read_package_ids(live_app_ctx, host)
        assert target in after_install, (
            f"{target!r} not in synopkg list after install: {after_install}"
        )

    finally:
        # ----- 5d.3) uninstall -- ALWAYS run, even if install asserted ---
        # If install partially succeeded we still need to clean up;
        # if it didn't run the package isn't there and uninstall is a
        # no-op (idempotent).
        uninstall = await packages.packages_uninstall(
            host, target, app_context=live_app_ctx,
        )
        # uninstall must succeed -- it's idempotent so even "wasn't
        # installed" returns ok=True.
        assert uninstall["ok"] is True, uninstall
        if install_done:
            assert uninstall["data"]["uninstalled"] is True, uninstall

        # ----- 5d.4) verify gone -----------------------------------------
        after_uninstall = await _read_package_ids(live_app_ctx, host)
        assert target not in after_uninstall, (
            f"{target!r} still installed after uninstall: {after_uninstall}"
        )
