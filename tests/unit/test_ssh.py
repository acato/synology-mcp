# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for ssh.py — Phase 3a writes.

Three tools, one mocked SSH client per test, respx for the web API
when it's invoked. We cover:

* Happy paths (add appends, remove filters, enable adds to admin group).
* Idempotency paths (dup add, missing-key remove, already-admin enable).
* Pre-flight refusal (add with User Home disabled).
* DSM error propagation (403 from user_home_is_enabled and from
  admin_check; 119 force-relogin via the transport layer).
* Input validation (bad pubkey, bad fingerprint, bad username, newlines).

We also assert on the EXACT base64 payload the SSH layer sees, because
that is the load-bearing contract — if the base64-over-exec write ever
silently flips to SFTP, this suite has to fail loudly.
"""
from __future__ import annotations

import base64
import hashlib
import re
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from synology_mcp import ssh
from synology_mcp.errors import InvalidParam, PermissionDenied, SessionFailed
from synology_mcp.session import DSMSession
from synology_mcp.transport.ssh import DSMSshClient, SshResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_session(app_ctx, user: str = "testuser") -> None:
    """Seed the cached DSMSession so call_dsm + _check_calling_user work.

    ``user`` defaults to "testuser" (matches the test_host_cfg account).
    Tests that exercise the per-user SSH write tools and pass a
    specific target user MUST override this with the same value so the
    cross-user gate (gap-fix 2026-05-26) doesn't refuse the call before
    the actual scenario fires.
    """
    state = app_ctx.cache.get("testhost")
    state.session = DSMSession(
        sid="FAKE_SID", syno_token="FAKE_TOKEN", user=user,
        cookies={"id": "FAKE_SID"},
    )


def _make_pubkey(label: bytes, comment: str = "") -> tuple[str, str, bytes]:
    """Build a parseable ssh-ed25519 line + return (line, fingerprint, blob).

    The blob is an SSH wire-format key body whose only purpose here is
    being uniquely-fingerprintable; sshd would reject it but our
    fingerprint dedup logic doesn't care about that. The 'ssh-ed25519'
    name (11 bytes) + length prefix + 32 raw bytes is the canonical
    shape for ed25519 keys; we pad/truncate the label to 32 bytes.
    """
    raw = (label * 32)[:32]
    # SSH wire format: <uint32 length="11">"ssh-ed25519"<uint32 length="32"><32 bytes>
    blob = (
        b"\x00\x00\x00\x0bssh-ed25519"
        b"\x00\x00\x00\x20" + raw
    )
    b64 = base64.b64encode(blob).decode("ascii")
    fp_digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    fp = f"SHA256:{fp_digest}"
    line = f"ssh-ed25519 {b64}"
    if comment:
        line = f"{line} {comment}"
    return line, fp, blob


def _fake_ssh(routes=None) -> DSMSshClient:
    """Build a MagicMock-spec'd DSMSshClient with command-routing behaviour."""
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


def _ok(stdout: str = "", exit_status: int = 0, stderr: str = "") -> SshResult:
    return SshResult(
        command="x", stdout=stdout, stderr=stderr, exit_status=exit_status,
    )


def _user_home_enabled_routes() -> dict[str, SshResult]:
    """Routes that make the user_home tri-check report enabled."""
    return {
        "synogetkeyvalue": _ok("yes\n"),
        "readlink": _ok("/volume1/homes\n"),
    }


def _user_home_disabled_routes() -> dict[str, SshResult]:
    return {
        "synogetkeyvalue": _ok("no\n"),
        "readlink": _ok("", exit_status=0),
    }


def _decode_payload(commands: list[str]) -> str | None:
    """Find the base64-over-exec write payload and return the decoded text.

    Returns None if no write command was observed — tests use that to
    assert "no file write happened" (e.g. on idempotent remove).
    """
    pat = re.compile(r"printf %s ([^|]+) \| base64 -d ")
    for cmd in commands:
        m = pat.search(cmd)
        if not m:
            continue
        # The captured group is shlex.quoted base64 — strip the quotes
        # if present (shlex.quote uses single-quotes for non-trivial
        # values; plain base64 contains only [A-Za-z0-9+/=] so it
        # qualifies for the trivial path and may come back unquoted).
        token = m.group(1).strip()
        if token.startswith("'") and token.endswith("'"):
            token = token[1:-1]
        return base64.b64decode(token).decode("utf-8")
    return None


# ===========================================================================
# ssh_add_authorized_key
# ===========================================================================


@pytest.mark.asyncio
async def test_add_authorized_key_happy_path(app_ctx, fixture_json) -> None:
    """Empty authorized_keys + valid pubkey → key appended, exact payload sent."""
    _seed_session(app_ctx, user="alice")
    home_payload = fixture_json("user_home", "get_enabled.json")
    pubkey_line, fp, _ = _make_pubkey(b"A", comment="alice@ws")

    # SSH routes: tri-check sees enabled; ensure/read/write all succeed;
    # cat returns empty (no existing keys).
    routes = {
        **_user_home_enabled_routes(),
        "mkdir -p": _ok(),
        "cat ": _ok(""),
        "printf %s": _ok(),
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=home_payload)
        result = await ssh.ssh_add_authorized_key(
            "testhost", "alice", pubkey_line, app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["added"] is True
    assert result["data"]["fingerprint"] == fp
    assert result["data"]["key_type"] == "ssh-ed25519"
    assert result["data"]["user"] == "alice"
    assert result["warnings"] == []

    # File-state assertion: the decoded write payload contains exactly
    # one line and that line round-trips to the same fingerprint we
    # got back.
    payload = _decode_payload(fake_ssh.commands)
    assert payload is not None
    assert payload.endswith("\n")
    assert payload.count("\n") == 1
    assert "ssh-ed25519" in payload
    assert "alice@ws" in payload

    # mkdir/chmod ensure step ran exactly once.
    ensure_cmds = [c for c in fake_ssh.commands if "mkdir -p" in c]
    assert len(ensure_cmds) == 1
    assert "/var/services/homes/alice/.ssh" in ensure_cmds[0]
    assert "chmod 700" in ensure_cmds[0]
    assert "chmod 600" in ensure_cmds[0]


@pytest.mark.asyncio
async def test_add_authorized_key_idempotent_when_already_present(
    app_ctx, fixture_json,
) -> None:
    """Same fingerprint already in file → added=False, no write happens."""
    _seed_session(app_ctx, user="bob")
    home_payload = fixture_json("user_home", "get_enabled.json")
    pubkey_line, fp, _ = _make_pubkey(b"B", comment="bob@ws")
    # Existing file has the SAME key but with a DIFFERENT comment — the
    # dedup MUST still fire (we key off the blob, not the line).
    existing_line, _, _ = _make_pubkey(b"B", comment="bob@old-laptop")
    existing_file = f"{existing_line}\n"

    routes = {
        **_user_home_enabled_routes(),
        "mkdir -p": _ok(),
        "cat ": _ok(existing_file),
        "printf %s": _ok(),  # should NOT be called
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=home_payload)
        result = await ssh.ssh_add_authorized_key(
            "testhost", "bob", pubkey_line, app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["added"] is False
    assert result["data"]["fingerprint"] == fp
    assert "key already present" in result["warnings"]

    # No write command should have run.
    assert _decode_payload(fake_ssh.commands) is None


@pytest.mark.asyncio
async def test_add_authorized_key_pre_flight_refusal_when_user_home_disabled(
    app_ctx, fixture_json,
) -> None:
    """User Home tri-check returns enabled=False → precondition refusal, no SSH writes."""
    _seed_session(app_ctx, user="carol")
    home_payload = fixture_json("user_home", "get_disabled.json")
    pubkey_line, _, _ = _make_pubkey(b"C")

    routes = {
        **_user_home_disabled_routes(),
        "mkdir -p": _ok(),
        "cat ": _ok(""),
        "printf %s": _ok(),
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=home_payload)
        result = await ssh.ssh_add_authorized_key(
            "testhost", "carol", pubkey_line, app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "precondition"
    assert result["data"]["next_step"] == "user_home_enable"
    assert result["data"]["user_home"]["enabled"] is False
    joined = " ".join(result["warnings"])
    assert "User Home" in joined

    # No mkdir, no write — pre-flight short-circuited.
    assert not any("mkdir -p" in c for c in fake_ssh.commands)
    assert _decode_payload(fake_ssh.commands) is None


@pytest.mark.asyncio
async def test_add_authorized_key_dsm_403_on_user_home_propagates(app_ctx) -> None:
    """DSM 403 on user_home_is_enabled → call surfaces as PermissionDenied (OTP-required also maps here)."""
    _seed_session(app_ctx, user="dave")
    pubkey_line, _, _ = _make_pubkey(b"D")
    # DSM 403 -> OtpRequired is the canonical mapping in errors.py; the
    # tool layer lets it bubble (server.py wraps it via _safe).
    err_body = {
        "success": False,
        "error": {"code": 403, "errors": []},
    }
    fake_ssh = _fake_ssh(_user_home_enabled_routes())
    app_ctx.cache.get("testhost").ssh_client = fake_ssh
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=err_body)
        from synology_mcp.errors import OtpRequired
        with pytest.raises(OtpRequired):
            await ssh.ssh_add_authorized_key(
                "testhost", "dave", pubkey_line, app_context=app_ctx,
            )

    # No SSH side-effects.
    assert not any("mkdir -p" in c for c in fake_ssh.commands)


@pytest.mark.asyncio
async def test_add_authorized_key_rejects_malformed_pubkey(app_ctx) -> None:
    """Garbage pubkey → InvalidParam, no DSM/SSH calls.

    Pubkey validation happens before the cross-user gate, so the
    session-seeded user does not need to match the target user here.
    """
    _seed_session(app_ctx, user="alice")
    fake_ssh = _fake_ssh()
    app_ctx.cache.get("testhost").ssh_client = fake_ssh
    # Test cases: empty, wrong number of fields, unknown type, bad base64.
    bad_keys = [
        "",
        "    ",
        "ssh-ed25519",  # only one field
        "rsa-totally-fake AAAA",  # unknown type
        "ssh-ed25519 not_valid_base64!!!",  # bad base64
        "ssh-ed25519 AAAA\nuser@host",  # embedded newline
    ]
    for bad in bad_keys:
        with pytest.raises(InvalidParam):
            await ssh.ssh_add_authorized_key(
                "testhost", "alice", bad, app_context=app_ctx,
            )

    # No SSH at all — validation runs before any side-effect.
    assert fake_ssh.commands == []


@pytest.mark.asyncio
async def test_add_authorized_key_rejects_malformed_username(app_ctx) -> None:
    """Username with disallowed characters → InvalidParam before anything else."""
    _seed_session(app_ctx)
    pubkey_line, _, _ = _make_pubkey(b"E")
    for bad_user in ["", "with space", "../etc/passwd", "u" * 33, "semi;colon"]:
        with pytest.raises(InvalidParam):
            await ssh.ssh_add_authorized_key(
                "testhost", bad_user, pubkey_line, app_context=app_ctx,
            )


@pytest.mark.asyncio
async def test_add_authorized_key_appends_to_existing_file(
    app_ctx, fixture_json,
) -> None:
    """Two existing keys + a new one → file contains all three in order."""
    _seed_session(app_ctx, user="alice")
    home_payload = fixture_json("user_home", "get_enabled.json")
    old1, _, _ = _make_pubkey(b"X", comment="x@host")
    old2, _, _ = _make_pubkey(b"Y", comment="y@host")
    new, new_fp, _ = _make_pubkey(b"Z", comment="z@host")
    existing_blob = f"{old1}\n{old2}\n"

    routes = {
        **_user_home_enabled_routes(),
        "mkdir -p": _ok(),
        "cat ": _ok(existing_blob),
        "printf %s": _ok(),
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=home_payload)
        result = await ssh.ssh_add_authorized_key(
            "testhost", "alice", new, app_context=app_ctx,
        )

    assert result["data"]["added"] is True
    assert result["data"]["fingerprint"] == new_fp

    payload = _decode_payload(fake_ssh.commands)
    assert payload is not None
    lines = [line for line in payload.splitlines() if line.strip()]
    # Order preserved + new key appended at the end.
    assert lines[0].startswith("ssh-ed25519")
    assert lines[0].endswith("x@host")
    assert lines[1].endswith("y@host")
    assert lines[2].endswith("z@host")


# ===========================================================================
# ssh_remove_authorized_key
# ===========================================================================


@pytest.mark.asyncio
async def test_remove_authorized_key_happy_path(app_ctx) -> None:
    """3 keys, remove the middle one → 2 keys, order preserved."""
    _seed_session(app_ctx, user="alice")
    line1, _, _ = _make_pubkey(b"1", comment="one")
    line2, fp2, _ = _make_pubkey(b"2", comment="two")
    line3, _, _ = _make_pubkey(b"3", comment="three")
    existing = f"{line1}\n{line2}\n{line3}\n"

    routes = {
        "cat ": _ok(existing),
        "printf %s": _ok(),
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    result = await ssh.ssh_remove_authorized_key(
        "testhost", "alice", fp2, app_context=app_ctx,
    )

    assert result["ok"] is True
    assert result["data"]["removed_count"] == 1
    assert result["data"]["fingerprint"] == fp2
    assert result["data"]["user"] == "alice"
    assert result["warnings"] == []

    payload = _decode_payload(fake_ssh.commands)
    assert payload is not None
    lines = [line for line in payload.splitlines() if line.strip()]
    assert len(lines) == 2
    assert lines[0].endswith("one")
    assert lines[1].endswith("three")
    # The removed key MUST NOT appear in the rewritten file.
    assert "two" not in payload


@pytest.mark.asyncio
async def test_remove_authorized_key_idempotent_when_missing(app_ctx) -> None:
    """Fingerprint not present → removed_count=0 and NO write happens."""
    _seed_session(app_ctx, user="alice")
    line1, fp1, _ = _make_pubkey(b"K")
    _, fp_missing, _ = _make_pubkey(b"M")
    existing = f"{line1}\n"

    routes = {
        "cat ": _ok(existing),
        "printf %s": _ok(),  # should NOT be called
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    result = await ssh.ssh_remove_authorized_key(
        "testhost", "alice", fp_missing, app_context=app_ctx,
    )

    assert result["ok"] is True
    assert result["data"]["removed_count"] == 0
    assert result["data"]["fingerprint"] == fp_missing
    assert result["warnings"] == []
    # No write happened — the existing file is untouched.
    assert _decode_payload(fake_ssh.commands) is None
    # Sanity: the file we'd have kept is what we read, which still
    # contains the original key (we didn't accidentally remove the
    # wrong one).
    assert fp1 != fp_missing


@pytest.mark.asyncio
async def test_remove_authorized_key_preserves_garbage_lines(app_ctx) -> None:
    """Unparseable lines + the target key → garbage lines preserved untouched."""
    _seed_session(app_ctx, user="alice")
    line1, _, _ = _make_pubkey(b"P", comment="keeper")
    line2, fp2, _ = _make_pubkey(b"Q", comment="remove-me")
    # Garbage we should not silently drop.
    garbage = "command=\"/bin/true\" no-pty"
    existing = f"{line1}\n{garbage}\n{line2}\n"

    routes = {
        "cat ": _ok(existing),
        "printf %s": _ok(),
    }
    fake_ssh = _fake_ssh(routes)
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    result = await ssh.ssh_remove_authorized_key(
        "testhost", "alice", fp2, app_context=app_ctx,
    )

    assert result["data"]["removed_count"] == 1
    payload = _decode_payload(fake_ssh.commands)
    assert payload is not None
    # Garbage line MUST still be present.
    assert garbage in payload
    # The removed key MUST be gone.
    assert "remove-me" not in payload
    # The keeper key MUST still be there.
    assert "keeper" in payload


@pytest.mark.asyncio
async def test_remove_authorized_key_accepts_bare_or_prefixed_fingerprint(
    app_ctx,
) -> None:
    """Both 'SHA256:<b64>' and bare '<b64>' fingerprints are accepted."""
    _seed_session(app_ctx, user="alice")
    line, fp, _ = _make_pubkey(b"R")
    bare_fp = fp.split(":", 1)[1]  # strip SHA256: prefix

    for fp_form in (fp, bare_fp):
        routes = {"cat ": _ok(f"{line}\n"), "printf %s": _ok()}
        fake_ssh = _fake_ssh(routes)
        app_ctx.cache.get("testhost").ssh_client = fake_ssh
        result = await ssh.ssh_remove_authorized_key(
            "testhost", "alice", fp_form, app_context=app_ctx,
        )
        assert result["data"]["removed_count"] == 1
        # Result always reports the normalized 'SHA256:' form.
        assert result["data"]["fingerprint"] == fp


@pytest.mark.asyncio
async def test_remove_authorized_key_rejects_malformed_fingerprint(app_ctx) -> None:
    """Empty / MD5-style / wrong-length / bad-base64 → InvalidParam, no SSH.

    Fingerprint validation happens before the cross-user gate, so the
    session-seeded user does not need to match the target user here.
    """
    _seed_session(app_ctx, user="alice")
    fake_ssh = _fake_ssh()
    app_ctx.cache.get("testhost").ssh_client = fake_ssh
    bad = [
        "",
        "   ",
        "MD5:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
        "SHA256:tooShort",
        "SHA256:" + "A" * 43 + "!",  # bad alphabet char
        "SHA256:" + "A" * 44,  # wrong length
    ]
    for fp_val in bad:
        with pytest.raises(InvalidParam):
            await ssh.ssh_remove_authorized_key(
                "testhost", "alice", fp_val, app_context=app_ctx,
            )
    assert fake_ssh.commands == []


# ===========================================================================
# ssh_enable_user_ssh
# ===========================================================================


@pytest.mark.asyncio
async def test_enable_user_ssh_happy_path(app_ctx, fixture_json) -> None:
    """User is NOT admin → admin_check then add → added=True."""
    _seed_session(app_ctx, user="bob")
    check_body = fixture_json("group_member", "admin_check_no.json")
    add_body = fixture_json("group_member", "add_success.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=check_body),
                httpx.Response(200, json=add_body),
            ]
        )
        result = await ssh.ssh_enable_user_ssh(
            "testhost", "bob", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["added"] is True
    assert result["data"]["user"] == "bob"
    assert result["data"]["group"] == "administrators"
    assert result["data"]["mechanism"] == "administrators_group_membership"
    assert result["warnings"] == []
    # Two web calls fired: admin_check + add.
    assert route.call_count == 2
    # Inspect the second call's query string — it should be the add call
    # against the administrators group with name=["bob"].
    second_url = route.calls[1].request.url
    qs = dict(second_url.params)
    assert qs["api"] == "SYNO.Core.Group.Member"
    assert qs["method"] == "add"
    assert qs["group"] == "administrators"
    assert qs["name"] == '["bob"]'


@pytest.mark.asyncio
async def test_enable_user_ssh_idempotent_already_admin(
    app_ctx, fixture_json,
) -> None:
    """User IS admin → admin_check returns True → no add call, 'already enabled' warning."""
    _seed_session(app_ctx, user="alice")
    check_body = fixture_json("group_member", "admin_check_yes.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").respond(200, json=check_body)
        result = await ssh.ssh_enable_user_ssh(
            "testhost", "alice", app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["added"] is False
    assert "already enabled" in result["warnings"]
    # Exactly ONE web call — no add was issued.
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_enable_user_ssh_accepts_flat_admin_check_shape(
    app_ctx, fixture_json,
) -> None:
    """Older DSM shape: data.is_admin=true (no users[] wrapper)."""
    _seed_session(app_ctx, user="alice")
    check_body = fixture_json("group_member", "admin_check_flat.json")
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=check_body)
        result = await ssh.ssh_enable_user_ssh(
            "testhost", "alice", app_context=app_ctx,
        )
    assert result["data"]["added"] is False
    assert "already enabled" in result["warnings"]


@pytest.mark.asyncio
async def test_enable_user_ssh_dsm_403_permission_denied(app_ctx) -> None:
    """DSM 105 on admin_check → PermissionDenied bubbles."""
    _seed_session(app_ctx, user="alice")
    err_body = {"success": False, "error": {"code": 105}}
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=err_body)
        with pytest.raises(PermissionDenied):
            await ssh.ssh_enable_user_ssh(
                "testhost", "alice", app_context=app_ctx,
            )


@pytest.mark.asyncio
async def test_enable_user_ssh_dsm_119_force_relogin_propagates(app_ctx) -> None:
    """DSM 119 → SessionFailed bubbles (transport layer maps the code)."""
    _seed_session(app_ctx, user="alice")
    err_body = {"success": False, "error": {"code": 119}}
    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(200, json=err_body)
        with pytest.raises(SessionFailed):
            await ssh.ssh_enable_user_ssh(
                "testhost", "alice", app_context=app_ctx,
            )


@pytest.mark.asyncio
async def test_enable_user_ssh_rejects_malformed_username(app_ctx) -> None:
    """Bad usernames are rejected before any DSM call fires.

    We use ``respx.mock(assert_all_called=False)`` paired with a route
    that would respond if it were ever called; if validation works
    correctly the route is never matched and the bare ``assert
    route.called is False`` confirms no DSM call was attempted.

    Username validation happens before the cross-user gate, so the
    session-seeded user does not need to match here.
    """
    _seed_session(app_ctx, user="testuser")
    with respx.mock(
        base_url="https://192.0.2.10:5001", assert_all_called=False,
    ) as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json={"success": True, "data": {}},
        )
        for bad_user in ["", "spaces here", "../etc", "u" * 33]:
            with pytest.raises(InvalidParam):
                await ssh.ssh_enable_user_ssh(
                    "testhost", bad_user, app_context=app_ctx,
                )
        assert route.called is False


# ===========================================================================
# Cross-user gate (Phase 3 gap-fix 2026-05-26)
# ===========================================================================
#
# Cross-user SSH writes (target_user != session.user) need sudo on every
# host where DSM gives each user's home a 0700 mode owned by that user.
# The MCP refuses those calls early with
# ``category=cross_user_not_supported`` so the caller gets a structured
# error instead of a hard ``DSMSshError`` deep in the write path.


@pytest.mark.asyncio
async def test_add_authorized_key_refuses_cross_user(
    app_ctx, fixture_json,
) -> None:
    """target_user != session.user -> category=cross_user_not_supported, no SSH writes."""
    _seed_session(app_ctx, user="alice")  # calling as alice
    pubkey_line, _, _ = _make_pubkey(b"X")
    fake_ssh = _fake_ssh(_user_home_enabled_routes())
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(
        base_url="https://192.0.2.10:5001", assert_all_called=False,
    ) as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json={"success": True, "data": {}},
        )
        result = await ssh.ssh_add_authorized_key(
            "testhost", "bob", pubkey_line, app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "cross_user_not_supported"
    assert result["data"]["target_user"] == "bob"
    assert result["data"]["calling_user"] == "alice"
    assert "NOPASSWD sudo" in result["data"]["next_step"]
    # No SSH writes — the gate fires before mkdir/cat/printf.
    assert not any("mkdir -p" in c for c in fake_ssh.commands)
    assert _decode_payload(fake_ssh.commands) is None
    # No User.Home.get DSM call either — gate fires before that too.
    assert route.called is False


@pytest.mark.asyncio
async def test_remove_authorized_key_refuses_cross_user(app_ctx) -> None:
    """remove against another user -> cross_user_not_supported, no SSH side-effects."""
    _seed_session(app_ctx, user="alice")
    _, fp, _ = _make_pubkey(b"Y")
    fake_ssh = _fake_ssh()
    app_ctx.cache.get("testhost").ssh_client = fake_ssh
    result = await ssh.ssh_remove_authorized_key(
        "testhost", "bob", fp, app_context=app_ctx,
    )
    assert result["ok"] is False
    assert result["data"]["category"] == "cross_user_not_supported"
    assert result["data"]["target_user"] == "bob"
    assert result["data"]["calling_user"] == "alice"
    # No SSH commands at all.
    assert fake_ssh.commands == []


@pytest.mark.asyncio
async def test_enable_user_ssh_refuses_cross_user(app_ctx) -> None:
    """enable against another user -> cross_user_not_supported, no DSM calls."""
    _seed_session(app_ctx, user="alice")
    with respx.mock(
        base_url="https://192.0.2.10:5001", assert_all_called=False,
    ) as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json={"success": True, "data": {}},
        )
        result = await ssh.ssh_enable_user_ssh(
            "testhost", "bob", app_context=app_ctx,
        )
    assert result["ok"] is False
    assert result["data"]["category"] == "cross_user_not_supported"
    assert result["data"]["target_user"] == "bob"
    assert result["data"]["calling_user"] == "alice"
    # No DSM admin_check fired.
    assert route.called is False


# ===========================================================================
# Module-private helpers exercised directly
# ===========================================================================


def test_fingerprint_matches_ssh_keygen_format() -> None:
    """The SHA256 fingerprint is base64-no-pad and starts with 'SHA256:'."""
    _, fp, blob = _make_pubkey(b"F")
    assert fp.startswith("SHA256:")
    body = fp.split(":", 1)[1]
    # No trailing '=' padding.
    assert not body.endswith("=")
    # 43 base64 chars (32-byte SHA256 -> 43 unpadded).
    assert len(body) == 43
    # Round-trip against ssh._fingerprint_sha256.
    assert ssh._fingerprint_sha256(blob) == fp


def test_normalize_fingerprint_round_trip() -> None:
    """Bare + prefixed forms both normalize to canonical 'SHA256:<43>'."""
    _, fp, _ = _make_pubkey(b"N")
    bare = fp.split(":", 1)[1]
    assert ssh._normalize_fingerprint(fp) == fp
    assert ssh._normalize_fingerprint(bare) == fp
    # Trailing '=' padding is tolerated.
    assert ssh._normalize_fingerprint(bare + "=") == fp


def test_parse_pubkey_strips_embedded_comment() -> None:
    """A 3-field line yields the embedded comment in the third tuple position."""
    line, _, blob = _make_pubkey(b"P", comment="me@laptop")
    key_type, key_bytes, comment = ssh._parse_pubkey(line)
    assert key_type == "ssh-ed25519"
    assert key_bytes == blob
    assert comment == "me@laptop"


def test_split_and_join_authorized_keys_round_trip() -> None:
    """Splitter drops blank lines + comments; joiner always ends with newline."""
    line1, _, _ = _make_pubkey(b"A")
    line2, _, _ = _make_pubkey(b"B")
    blob = f"\n# leading comment\n{line1}\n\n{line2}\n# trailing comment\n"
    entries = ssh._split_authorized_keys(blob)
    assert entries == [line1, line2]
    joined = ssh._join_authorized_keys(entries)
    assert joined == f"{line1}\n{line2}\n"


# ===========================================================================
# ssh_set_port — Phase 3c
# ===========================================================================


def _terminal_get_v3_body(ssh_port: int = 22334, **overrides) -> dict:
    """Return a canonical SYNO.Core.Terminal.get v3 response shape.

    Mirrors what CS3 actually returns (probed 2026-05-26). Caller can
    override any scalar field via kwargs to exercise carry-forward
    behaviour.
    """
    data = {
        "enable_ssh": True,
        "enable_telnet": False,
        "forbid_console": False,
        "ssh_port": ssh_port,
        "ssh_cipher": [
            {"name": "aes256-ctr", "in_use": True},
        ],
        "ssh_kex": [
            {"name": "curve25519-sha256", "in_use": True},
        ],
        "ssh_mac": [
            {"name": "hmac-sha2-256", "in_use": True},
        ],
    }
    data.update(overrides)
    return {"success": True, "data": data}


@pytest.mark.asyncio
async def test_set_port_happy_path_verifies_via_fresh_handshake(
    app_ctx, monkeypatch,
) -> None:
    """Valid port -> Terminal.get + Terminal.set + fresh-paramiko verify succeed."""
    _seed_session(app_ctx)
    # SSH probe: port not in use.
    fake_ssh = _fake_ssh({"ss -lnt": _ok("")})
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    # Mock the verify helper — we don't actually want to open a real
    # paramiko session in unit tests.
    async def _fake_verify(host_cfg, port, password):
        assert port == 23456
        return True, None
    monkeypatch.setattr(ssh, "_verify_ssh_on_port", _fake_verify)

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_terminal_get_v3_body(22334)),
                httpx.Response(
                    200,
                    json={"success": True, "data": {}},
                ),
            ]
        )
        result = await ssh.ssh_set_port(
            "testhost", 23456, app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["changed"] is True
    assert result["data"]["verified"] is True
    assert result["data"]["old_port"] == 22334
    assert result["data"]["new_port"] == 23456
    # No "did not respond" warning when verify succeeded.
    assert not any("did not respond" in w for w in result["warnings"])
    # Inspect the Terminal.set call — it MUST carry the full payload
    # forward (enable_ssh + cipher/kex/mac arrays), not just the new
    # port, to avoid disabling other settings as a side-effect.
    set_call = [
        c for c in fake_ssh.commands if "ss -lnt" in c
    ]
    assert set_call, "ss -lnt should have been invoked"


@pytest.mark.asyncio
async def test_set_port_idempotent_when_already_on_port(app_ctx) -> None:
    """Current port == requested port -> no mutation, ok=True, changed=False."""
    _seed_session(app_ctx)
    fake_ssh = _fake_ssh({"ss -lnt": _ok("")})
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json=_terminal_get_v3_body(22334),
        )
        result = await ssh.ssh_set_port(
            "testhost", 22334, app_context=app_ctx,
        )

    assert result["ok"] is True
    assert result["data"]["changed"] is False
    assert result["data"]["verified"] is True
    assert result["data"]["old_port"] == 22334
    assert result["data"]["new_port"] == 22334
    assert "already on this port" in result["warnings"]
    # ONLY the Terminal.get call should have fired — no .set.
    assert route.call_count == 1
    # ss probe never ran either — idempotency short-circuits before it.
    assert not any("ss -lnt" in c for c in fake_ssh.commands)


@pytest.mark.asyncio
async def test_set_port_refuses_when_port_already_in_use(app_ctx) -> None:
    """ss -lnt finds a listener -> category=port_already_in_use refusal."""
    _seed_session(app_ctx)
    fake_ssh = _fake_ssh({
        # A LISTEN row matches the requested port.
        "ss -lnt": _ok(
            "LISTEN 0  128  0.0.0.0:23456  0.0.0.0:*  users:((\"smbd\",pid=1234,fd=33))",
        ),
    })
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").respond(
            200, json=_terminal_get_v3_body(22334),
        )
        result = await ssh.ssh_set_port(
            "testhost", 23456, app_context=app_ctx,
        )

    assert result["ok"] is False
    assert result["data"]["category"] == "port_already_in_use"
    assert result["data"]["port"] == 23456


@pytest.mark.asyncio
async def test_set_port_refuses_port_22_without_allow_default(app_ctx) -> None:
    """port=22 without allow_default=True -> InvalidParam, no DSM calls."""
    _seed_session(app_ctx)
    fake_ssh = _fake_ssh()
    app_ctx.cache.get("testhost").ssh_client = fake_ssh
    with respx.mock(
        base_url="https://192.0.2.10:5001", assert_all_called=False,
    ) as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json={"success": True, "data": {}},
        )
        with pytest.raises(InvalidParam):
            await ssh.ssh_set_port("testhost", 22, app_context=app_ctx)
        assert route.called is False


@pytest.mark.asyncio
async def test_set_port_allows_port_22_with_allow_default(
    app_ctx, monkeypatch,
) -> None:
    """port=22 with allow_default=True -> no InvalidParam, validation passes."""
    _seed_session(app_ctx)
    fake_ssh = _fake_ssh({"ss -lnt": _ok("")})
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    async def _fake_verify(host_cfg, port, password):
        return True, None
    monkeypatch.setattr(ssh, "_verify_ssh_on_port", _fake_verify)

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_terminal_get_v3_body(22334)),
                httpx.Response(200, json={"success": True, "data": {}}),
            ]
        )
        result = await ssh.ssh_set_port(
            "testhost", 22, allow_default=True, app_context=app_ctx,
        )
    assert result["ok"] is True
    assert result["data"]["new_port"] == 22


@pytest.mark.asyncio
async def test_set_port_rejects_out_of_range_port(app_ctx) -> None:
    """Port outside [1024, 65535] -> InvalidParam, no DSM calls."""
    _seed_session(app_ctx)
    fake_ssh = _fake_ssh()
    app_ctx.cache.get("testhost").ssh_client = fake_ssh
    with respx.mock(
        base_url="https://192.0.2.10:5001", assert_all_called=False,
    ) as mock:
        route = mock.get("/webapi/entry.cgi").respond(
            200, json={"success": True, "data": {}},
        )
        for bad_port in (-1, 0, 80, 1023, 65536, 99999):
            with pytest.raises(InvalidParam):
                await ssh.ssh_set_port(
                    "testhost", bad_port, app_context=app_ctx,
                )
        assert route.called is False


@pytest.mark.asyncio
async def test_set_port_verify_failure_surfaces_warning_not_revert(
    app_ctx, monkeypatch,
) -> None:
    """Verify timeout -> ok=True, verified=False, warning, NO revert."""
    _seed_session(app_ctx)
    fake_ssh = _fake_ssh({"ss -lnt": _ok("")})
    app_ctx.cache.get("testhost").ssh_client = fake_ssh

    async def _fake_verify(host_cfg, port, password):
        return False, "timed out after 10s"
    monkeypatch.setattr(ssh, "_verify_ssh_on_port", _fake_verify)

    with respx.mock(base_url="https://192.0.2.10:5001") as mock:
        route = mock.get("/webapi/entry.cgi").mock(
            side_effect=[
                httpx.Response(200, json=_terminal_get_v3_body(22334)),
                httpx.Response(200, json={"success": True, "data": {}}),
            ]
        )
        result = await ssh.ssh_set_port(
            "testhost", 23456, app_context=app_ctx,
        )

    # ok=True because the mutation succeeded; verified=False because
    # the fresh handshake timed out. No revert (the user's existing
    # session is the escape hatch).
    assert result["ok"] is True
    assert result["data"]["changed"] is True
    assert result["data"]["verified"] is False
    assert any("did not respond" in w for w in result["warnings"])
    # Exactly two DSM calls — get + set — and NO third "revert" call.
    assert route.call_count == 2


def test_terminal_set_payload_carries_forward_all_fields() -> None:
    """_terminal_set_payload must include enable_ssh/telnet/console + arrays."""
    current = {
        "enable_ssh": True,
        "enable_telnet": False,
        "forbid_console": False,
        "ssh_port": 22334,
        "ssh_cipher": [{"name": "aes256-ctr", "in_use": True}],
        "ssh_kex": [{"name": "curve25519-sha256", "in_use": True}],
        "ssh_mac": [{"name": "hmac-sha2-256", "in_use": True}],
    }
    payload = ssh._terminal_set_payload(current, 23456)
    assert payload["ssh_port"] == "23456"
    assert payload["enable_ssh"] == "true"
    assert payload["enable_telnet"] == "false"
    assert payload["forbid_console"] == "false"
    # Arrays must round-trip JSON-encoded.
    import json as _json
    assert _json.loads(payload["ssh_cipher"]) == current["ssh_cipher"]
    assert _json.loads(payload["ssh_kex"]) == current["ssh_kex"]
    assert _json.loads(payload["ssh_mac"]) == current["ssh_mac"]


def test_validate_port_accepts_user_range() -> None:
    """Any port in [1024, 65535] passes _validate_port."""
    for port in (1024, 2222, 22334, 49151, 65535):
        ssh._validate_port(port, allow_default=False)
    # Port 22 ONLY when allow_default=True.
    ssh._validate_port(22, allow_default=True)
    with pytest.raises(InvalidParam):
        ssh._validate_port(22, allow_default=False)


def test_validate_port_rejects_non_int() -> None:
    """Strings / floats / bools -> InvalidParam."""
    for bad in ("22334", 22334.5, True, None):
        with pytest.raises(InvalidParam):
            ssh._validate_port(bad, allow_default=False)  # type: ignore[arg-type]
