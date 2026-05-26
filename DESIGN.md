# synology-mcp — Design

> **Status:** design phase. This document is the source of truth for what the MVP looks like. Implementation has not started; the `src/` tree is a scaffold of placeholder modules whose signatures match this design.

## Table of contents

1. [Goals](#1-goals)
2. [Architecture](#2-architecture)
3. [Auth state and session caching](#3-auth-state-and-session-caching)
4. [Error handling and retry policy](#4-error-handling-and-retry-policy)
5. [Tool surface](#5-tool-surface)
   1. [auth_*](#51-auth)
   2. [packages_*](#52-packages)
   3. [user_home_*](#53-user_home)
   4. [snapshot_replication_*](#54-snapshot_replication)
   5. [shares_*](#55-shares)
   6. [raid_*](#56-raid)
   7. [ssh_*](#57-ssh)
   8. [network_*](#58-network)
6. [Configuration](#6-configuration)
7. [DSM API mapping](#7-dsm-api-mapping)
8. [Testing strategy](#8-testing-strategy)
9. [Versioning and DSM compatibility](#9-versioning--dsm-compatibility)
10. [Security](#10-security)
11. [Out of scope for MVP](#11-out-of-scope-for-mvp)

---

## 1. Goals

### What this MCP exists to do

- **Encapsulate DSM auth and quirks once.** Every agent currently rediscovers `account=`-vs-`username=`, the X-SYNO-TOKEN header requirement, the userHomeEnable synoinfo gotcha, etc. This MCP turns each of those into one tool call.
- **Make read-only NAS introspection trivial.** "What packages are running on `nas-3`?" should be one tool call returning structured data, not a chain of SSH + grep.
- **Make the small set of common write ops safe and idempotent.** Adding an SSH key, enabling User Home, installing a package — these recur on every commissioning. They should be one tool call, idempotent, with a clear postcondition.
- **Be multi-host from day 1.** Tools take a `host` parameter; the server holds one session per host. No "primary NAS" concept.
- **Be vendor-agnostic / community-friendly.** No hardcoded IPs, hostnames, paths, or shares from any specific deployment.

### Non-goals

- A replacement for DSM UI. UI-only flows (Snapshot Replication wizard, certificate import dialog) stay in the UI.
- A replacement for SSH. Heavy operational work (raid creation, package marketplace browsing) stays in SSH / DSM UI.
- A fully-featured DSM SDK. We expose what agents actually need; everything else is YAGNI until proven.
- DSM 6.x support. Synology has EOL'd DSM 6; the API surface diverges enough that supporting it is not worth the maintenance burden.

---

## 2. Architecture

### Process model

One long-lived MCP stdio process. Spawned by the MCP client (Claude Code, Claude Desktop) on startup; speaks JSON-RPC over stdin/stdout per the MCP spec.

Future: optional HTTP/SSE transport for multi-client scenarios (e.g., Open-WebUI). Not in MVP.

### Module layout

```
src/synology_mcp/
├── __init__.py
├── server.py              # MCP server bootstrap; tool registry
├── auth.py                # session login/logout/whoami
├── packages.py            # SYNO.Core.Package
├── user_home.py           # SYNO.Core.User.Home + synoinfo workaround
├── snapshot_replication.py # SYNO.DR.Plan / SYNO.Replica.Share (read-only)
├── shares.py              # SYNO.Core.Share
├── raid.py                # SYNO.Storage.* + /proc/mdstat over SSH
├── ssh.py                 # authorized_keys + ssh port + service enable
├── network.py             # SYNO.Core.Network + /sys/class/net/*
├── transport/
│   ├── http.py            # httpx-based DSM HTTP client (per-host)
│   └── ssh.py             # paramiko-based SSH client (per-host)
├── config.py              # config file + env var loader
├── session.py             # per-host session cache (sid + token + expiry)
├── errors.py              # DSM error code → exception mapping
└── tools.py               # MCP tool decorator + registry helpers
```

Each subsystem module declares MCP tools via a thin decorator (`@tool` in `tools.py`) that handles param validation, error mapping, and result schema. The subsystem module owns the DSM call but does NOT own the HTTP/SSH client — those come from `transport/` and are cached per-host in `session.py`.

### Per-host vs. shared state

State lives in `session.py`'s `SessionCache`:

- One `httpx.AsyncClient` per host, cached for the full process lifetime (TLS verify settings come from config). No idle timer; reconnect only on auth error or socket error.
- One `DSMSession` per host (sid + syno_token + cookies + issued_at). Invalidated on DSM 105/107/119, on explicit `auth_logout`, and on process shutdown.
- One `paramiko.SSHClient` per host, cached for the process lifetime with `transport.set_keepalive(60)` to defeat Synology's 10-15 min idle disconnect. Transparent reconnect on channel error.

There is no global state outside `SessionCache` and the config loader. The MCP process can serve calls against arbitrary hosts concurrently with no interference.

### Lifecycle

- Process start → load config → empty session cache → register tools → start MCP transport.
- First tool call against host X → cache miss → run login flow → cache `DSMSession` → continue.
- Subsequent calls for X reuse the cached session until DSM returns 401/119, at which point we re-login once and retry.
- Process shutdown → best-effort logout on every cached session.

---

## 3. Auth state and session caching

DSM 7's auth flow has a few non-obvious requirements:

1. The login endpoint is `SYNO.API.Auth`, **version 6**. Older versions don't issue the `synotoken`.
2. The user param is `account=`, **not** `username=` (DSM accepts neither name nor email here; it's the DSM login name).
3. `enable_syno_token=yes` is required, otherwise the response carries only the cookie.
4. `format=cookie` is the canonical mode (returns sid as a cookie). `format=sid` is also accepted on most builds but some versions glitch.
5. The response body has `data.sid` AND `data.synotoken`. The cookie also has `id=...` set. On subsequent calls send BOTH the cookie AND the `X-SYNO-TOKEN` header, otherwise DSM 7.x returns error code 119 (session not authenticated for token endpoints) for any state-modifying call.
6. 2FA: when enabled, the first login call returns `error.code=403` with an `error.errors` payload requesting `otp_code`. Resubmit the same params plus `otp_code=NNNNNN`. Some builds require `device_name` + `device_id` to be set if you want to skip 2FA prompts on the same device for 30 days.

The `SessionCache` keys by `host` (the config-file name, not the IP) and holds:

```python
@dataclass
class DSMSession:
    sid: str
    syno_token: str
    cookies: httpx.Cookies
    user: str
    issued_at: datetime
    expires_at: datetime | None  # DSM doesn't advertise this; we track soft-expiry
    dsm_major_minor: tuple[int, int] | None  # e.g. (7, 3); see version-fetch below
```

Session invalidation triggers: explicit `auth.logout`, DSM error 119/105/107 on any call, process shutdown.

### DSM version fetch

Immediately after `SYNO.API.Auth login` succeeds, `perform_login` issues a follow-up `SYNO.Core.System info` call and parses the leading `DSM <major>.<minor>` out of the `firmware_ver` string (e.g. `"DSM 7.3.2-86009 Update 3"` → `(7, 3)`). The result is cached on the session as `dsm_major_minor`. The §9 compat shim reads this field to dispatch between `_normalize_v73_*` and `_normalize_v72_*` paths without re-querying DSM.

This costs one additional HTTP roundtrip on first login per host. Failures (transport error, unexpected payload shape, unparseable version) are non-fatal: the field stays `None` and the compat shim falls back to its current default normaliser. The session's `descriptor()` exposes the value to MCP consumers as a 2-element list (or `None`).

---

## 4. Error handling and retry policy

### DSM error codes we care about

| Code | Meaning | Action |
|------|---------|--------|
| 100 | Unknown error | Bubble up, log raw response |
| 101 | Invalid parameter | Bubble up as `InvalidParam` |
| 102 | API does not exist | Bubble up as `UnsupportedDSMVersion` |
| 103 | Method does not exist | Bubble up as `UnsupportedDSMVersion` |
| 104 | Version not supported | Try lower version, then `UnsupportedDSMVersion` |
| 105 | Insufficient user privilege | Bubble up as `PermissionDenied` |
| 106 | Connection timeout | Retry once with backoff |
| 107 | Multiple login | Invalidate session, re-login, retry once |
| 109 | Network error | Retry once with backoff |
| 119 | Session token mismatch | Invalidate session, re-login, retry once |
| 400 | Invalid credentials | `AuthFailed`; do NOT retry |
| 403 | OTP required | `OtpRequired`; surface to caller |

### Retry policy

- Network-level errors (httpx `ConnectError`, `ReadTimeout`): exponential backoff, max 3 attempts.
- DSM 106/109: same as above.
- DSM 107/119: invalidate session → re-login once → retry once. If second attempt also fails, surface as `SessionFailed`.
- DSM 400/403/105: never retry; surface to caller.

All retries log a structured warning with `host`, `endpoint`, `attempt`, and `dsm_error_code`. No secrets in logs.

---

## 5. Tool surface

Every tool name is **flat snake_case** with a module prefix (e.g., `auth_login`, `packages_install`, `raid_list_volumes`). MCP clients see one flat namespace. All tools are async. All take `host: str` as the first positional argument. All return a `dict` with at minimum:

```python
{
    "ok": bool,         # True on success
    "host": str,        # echo of host
    "data": Any,        # the actual payload; schema per tool below
    "warnings": list[str],  # optional, e.g., "User Home was already enabled"
}
```

On failure, the MCP returns a JSON-RPC error with a structured `data` field carrying `dsm_error_code` (when applicable) and `category` (`auth`, `network`, `permission`, `unsupported`, `validation`, `internal`).

### 5.1 auth_*

#### `auth_login(host)`

Force a fresh login (invalidates any cached session first). Returns:

```python
{"ok": True, "host": "nas-primary", "data": {
    "user": "admin",
    "sid_present": True,
    "token_present": True,
    "issued_at": "2026-05-25T20:00:00Z"
}}
```

#### `auth_logout(host)`

Invalidate the cached session and best-effort-call DSM logout. Returns the prior session age or null if no session existed.

#### `auth_whoami(host)`

Return the cached session descriptor without forcing a login. Triggers a login if no session exists.

### 5.2 packages_*

#### `packages_list(host)`

List installed packages. Each item: `id`, `name`, `version`, `status` (`start`/`stop`/`error`), `auto_start`. ContainerManager status is replaced with a `docker_health` boolean derived from `docker info` over SSH (web API alone is unreliable here).

#### `packages_status(host, package_id)`

Detail on one package: same fields as `list` plus `install_path`, `last_started_at` (if available), and for ContainerManager `docker_info_summary`.

#### `packages_install(host, package_id, version=None, accept_eula=False)`

Install a package. **DSM 7.3 verb chain** (Phase 3 gap-fix 2026-05-26 — the legacy `install_from_server` method does NOT exist on DSM 7.3.2 build 86009 and returns code 103 method-not-supported):

1. `SYNO.Core.Package.get` v1 — idempotency / upgrade gate. Same-version already installed → `installed=False, method="noop"`. Different-version installed → refuse with `category="upgrade_required"`.
2. `SYNO.Core.Package.Server.list` v2 — fetch the catalog row for `package_id`. Each row carries `{package, version, link, md5, size, type, source, beta, qinst}` — those become the install request payload. Missing row → refuse with `category="not_in_catalog"`. Caller-pinned version vs. catalog's only-version → refuse with `category="version_mismatch"`.
3. `SYNO.Core.Package.Installation` `install` v1 with `{name, is_syno, beta, url, checksum, filesize, type, blqinst, operation="install"}` — the canonical DSM 7.3 install payload (verified by reading `/usr/syno/synoman/webman/modules/PkgManApp/PkgManApp.js`). The DSM-internal flow downloads the .spk from the Synology repo + installs in one async task whose id is `@SYNOPKG_DOWNLOAD_<package_id>`.
4. `SYNO.Core.Package.Installation.status` v1 polling until `finished=True` (best-effort, 300s timeout).
5. `SYNO.Core.Package.get` v1 again — verify the installed version.

EULA gate: if step 3's response carries `data.eula`/`data.license`/`data.eula_text` and `accept_eula=False`, surface `category="eula_required"` with the text and abort. `accept_eula=True` re-runs step 3 with `accept_eula=true` in the params.

Returns `{installed, version, method, package_id}`. `method` values:
* `"online"` — full install via the catalog-row payload (canonical path).
* `"noop"` — idempotency short-circuit (already installed at requested or unspecified version).

DSM 1000-series errors during the install call surface as `category="online_install_failed"` with the raw DSM code. The legacy `"spk_fallback"` path (manual `.spk` upload via `SYNO.Core.Package.Installation.upload` + simpler install payload) is documented in `src/synology_mcp/packages.py` but not implemented in this MVP — operators hitting `online_install_failed` should install manually via the DSM UI.

#### `packages_uninstall(host, package_id)`

Uninstall. Idempotent — returns ok if package was already absent.

### 5.3 user_home_*

#### `user_home_is_enabled(host)`

Cross-checks three signals:

1. Web API: `SYNO.Core.User.Home.get` `enable_user_home`.
2. `/etc/synoinfo.conf` `userHomeEnable` (via SSH).
3. `/var/services/homes` symlink target exists and points to a valid /volume*/homes.

Returns `{"enabled": bool, "web_api_says": bool, "synoinfo_says": bool, "symlink_target": str | None}`. If those three disagree, `enabled=False` and a warning is added explaining the inconsistency.

#### `user_home_enable(host, user=None)`

Apply the DSM 7.3 workaround atomically:

1. SSH + sudo: `synosetkeyvalue /etc/synoinfo.conf userHomeEnable yes`.
2. SSH + sudo: `rm -f /var/services/homes; ln -s /volume1/homes /var/services/homes`. (Volume picked from config or the first available `/volume*/homes`.)
3. Web API: `SYNO.Core.User.Home.set enable_user_home=true`.
4. If `user` provided: SSH + sudo `synouserhome --prepare-folder <user>`.

On step failure, rolls back: re-restores the old `/var/services/homes` symlink target, leaves synoinfo as-is (writes to it are reversible by re-calling with `enable=false`). Returns per-step status.

#### `user_home_disable(host, confirm_destroy_keys=False)`

Web API call to `SYNO.Core.User.Home.set enable=false`. Does NOT delete `/volume*/homes/*` data.

Safety rails (two layers — Phase 3 gap-fix 2026-05-26):

1. **sudo gate**: the would-orphan-keys enumeration needs `sudo -n find /var/services/homes/*/.ssh/authorized_keys -size +0c -type f` to read every user's authorized_keys (those files live in 0700-mode home dirs owned by the target user). If the calling account does NOT have NOPASSWD sudo configured, the probe fails with `sudo: a password is required` / `sudo: a terminal is required` on stderr + non-zero exit. We treat that exact failure mode as a hard refusal — `category="sudo_required"` — UNLESS `confirm_destroy_keys=True` is passed to explicitly bypass the rail. The bug-fix for the pre-gap-fix behaviour was treating sudo failure as "no users have keys" and proceeding with the destructive disable.

2. **would-orphan-keys gate**: when the enumeration succeeds and returns a non-empty user list, the call is refused with `category="would_orphan_keys"` and the affected_users list. `confirm_destroy_keys=True` overrides.

When `confirm_destroy_keys=True` and the sudo probe still fails, we proceed (caller-explicit override) but record a warning `"sudo -n unavailable: would_orphan_keys check skipped; every user's SSH keys are at risk of being orphaned"` so the audit trail makes the bypass visible.

### 5.4 snapshot_replication_*

**Read-only in MVP.** Plan creation is out of scope; see §11.

#### `snapshot_replication_list_plans(host)`

Returns all SR plans the host knows about (as source or destination):

```python
{"ok": True, "data": [
    {"plan_id": "...", "source_host": "...", "source_share": "...",
     "dest_host": "...", "dest_share": "...", "role": "source"|"destination",
     "schedule": {"kind": "daily", "hour": 2, "minute": 0},
     "retention": {"daily": 7, "weekly": 4, "monthly": 3},
     "enabled": bool, "paused": bool},
    ...
]}
```

#### `snapshot_replication_plan_status(host, plan_id)`

Last sync timestamp, current state (`idle`/`syncing`/`error`), lag estimate, error if any.

#### `snapshot_replication_recent_activity(host, limit=20)`

Recent sync events from the `replica.db` activity log (read-only).

### 5.5 shares_*

#### `shares_list(host)`

Shared folders: name, volume, size, encrypted flag, hidden flag, browsable flag.

#### `shares_create(host, name, volume, **opts)`

Create a share. `opts` includes `description`, `hidden`, `enable_recycle_bin`, `encrypt`, `encryption_passphrase`, `enable_share_cow`. If `name` is a DSM-reserved name (`music`, `photo`, `video`, `NetBackup`, etc.), surface as `ReservedShareName` with a hint that the folder can still exist as a plain dir for rsync targets but cannot be SMB-exposed via `synoshare`.

#### `shares_get_acl(host, name)`

Decoded ACL: users, groups, permissions (`RW`/`RO`/`NO`), inheritable flag.

#### `shares_get_snapshot_config(host, name)`

Returns the share's snapshot schedule + retention if Btrfs snapshots are enabled.

### 5.6 raid_*

#### `raid_list_volumes(host)`

Volumes with name, filesystem (btrfs/ext4), size, used, free, raid level, encryption state, status (`normal`/`degraded`/`crashed`/`resyncing`).

#### `raid_list_disks(host)`

Physical disks: slot, model, serial, capacity, smart state (`healthy`/`warning`/`failing`), temperature, role (`hot_spare`/`active`/`unused`).

#### `raid_state(host)`

Parses `/proc/mdstat` over SSH. For each `md<N>` device returns:

```python
{"device": "md2", "level": "raid6", "state": "resyncing"|"clean",
 "resync_pct": 57.0,  # null if not resyncing
 "resync_speed_kbps": 184000,
 "resync_eta_seconds": 21600,
 "members": [{"disk": "sda3", "state": "U"}, ...]}
```

#### `raid_hardware_info(host)`

Model, DSM build, serial number, total RAM, CPU model, and full NIC table.

The NIC table is sourced from `network_list_interfaces` so MACs and link state come from the same canonical web-API+sysfs cross-check (`/sys/class/net/<if>/address` over SSH). `nics[].mac` is a lowercase `xx:xx:xx:xx:xx:xx` string or `null` if genuinely unavailable — never the empty string. `nics[].status` carries the normalised link state (`up`/`down`).

### 5.7 ssh_*

#### `ssh_get_state(host)`

SSH service enabled? Current port. List of users with SSH app-permission.

#### `ssh_set_port(host, port)`

Change DSM SSH port via `SYNO.Core.Terminal.set`. Warns about firewall rules and confirms reachability post-change.

#### Calling-user constraint (Phase 3 gap-fix 2026-05-26)

`ssh_add_authorized_key`, `ssh_remove_authorized_key`, and `ssh_enable_user_ssh` refuse when `user` differs from the DSM account this MCP is authenticated as (`session.user`). Refusal envelope: `{ok: False, data: {category: "cross_user_not_supported", target_user, calling_user, next_step}}`.

Rationale: DSM gives each user's home a 0700 mode owned by that user. Writing to a different user's `~/.ssh/` from the calling account needs sudo, which would require a password-on-stdin mechanism that the MCP does not (yet) ship. Refusing early surfaces a structured error instead of a deep `DSMSshError` from a failing `mkdir -p`. The same-user path remains fully supported and is the only path with live-integration coverage.

#### `ssh_enable_user_ssh(host, user)`

Grant SSH access to `user` by adding them to the `administrators` group via `SYNO.Core.Group.Member` `admin_check` + `add` (DSM 7.3 has no per-user `SYNO.SSH` AppPriv row). Idempotent — if `admin_check` says the user is already an admin, returns `data.added=False` with `warnings=["already enabled"]`.

Subject to the calling-user constraint above.

#### `ssh_add_authorized_key(host, user, pubkey, comment="")`

Append the pubkey to `/var/services/homes/<user>/.ssh/authorized_keys`. Idempotent — if the pubkey bytes are already present, returns `data.added=False` with `warnings=["key already present"]`. Implementation uses base64-over-`exec_command` (not SFTP — see DSM SFTP quirk in §10).

Pre-flight: verifies User Home is enabled (`user_home_is_enabled` tri-check). If not, refers to `user_home_enable` and refuses with `category="precondition"`.

Subject to the calling-user constraint above.

#### `ssh_list_authorized_keys(host, user)`

Returns each key with `type` (ed25519/rsa/...), `fingerprint` (SHA256), `comment`, `position` (line number).

#### `ssh_remove_authorized_key(host, user, fingerprint)`

Remove by fingerprint. Returns `removed_count`. Idempotent — `removed_count=0` is `ok=True` with no warnings. Unparseable lines in the file are preserved untouched.

Subject to the calling-user constraint above.

### 5.8 network_*

#### `network_list_interfaces(host)`

Each interface: name (`eth0`/`bond0`/`docker0`/...), mac, mtu, state (`up`/`down`), speed (Mb/s, null if down), duplex, ip addresses, link partner detail if available.

The web-API vs sysfs link-speed cross-check happens server-side: any mismatch is surfaced as a string in the envelope's `warnings[]` (sysfs is treated as canonical). Underscore-prefixed implementation fields (e.g. `_web_speed_mbps`, `_sysfs_speed_mbps`) MUST NOT appear in the public per-interface dict.

#### `network_get_interface(host, name)`

Full detail for one interface including driver, firmware (if available via ethtool over SSH), and `/sys/class/net/<name>/speed` cross-checked against web API speed. Same internal-field stripping rule as `network_list_interfaces`.

---

## 6. Configuration

Config is loaded with this precedence (highest first):

1. Explicit per-tool-call params (rare; mostly for testing).
2. Environment variables (`SYNOLOGY_MCP_<HOST>_<FIELD>` — host name uppercased, dashes/dots replaced with underscores).
3. Config file (`SYNOLOGY_MCP_CONFIG` env or `~/.config/synology-mcp/config.toml`, XDG-style; falls back to `$XDG_CONFIG_HOME/synology-mcp/config.toml` if `XDG_CONFIG_HOME` is set).

### Config file schema

See [`examples/config.toml`](examples/config.toml).

```toml
[defaults]
port = 5001
use_https = true
verify_tls = true
ssh_port = 22
connect_timeout = 10
read_timeout = 30

[hosts.<name>]
ip = "fqdn-or-ip"          # alias: `host` or `address`
account = "admin"          # DSM login name (alias: `username`)
password = "..."           # optional; prefer env var
otp_code = "..."           # only if 2FA enabled and you have a static secret
ssh_username = "admin"     # defaults to account
ssh_key_path = "~/.ssh/id_ed25519"  # optional; password-only auth supported
ssh_port = 22              # default 22; override per host if non-standard (e.g. 22334)
port = 5001
use_https = true
verify_tls = true
```

`ip`, `host`, and `address` are accepted interchangeably for the connection target. `account` is the DSM login name; `username` is accepted as an alias.

### Environment variables

Per-host overrides use uppercased + underscored host names. For a host called `cs3`, the lookup keys are:

```
SYNOLOGY_MCP_CS3_IP            # alias: ..._HOST, ..._ADDRESS
SYNOLOGY_MCP_CS3_ACCOUNT       # alias: ..._USERNAME
SYNOLOGY_MCP_CS3_PASSWORD
SYNOLOGY_MCP_CS3_OTP_CODE
SYNOLOGY_MCP_CS3_SSH_PORT
SYNOLOGY_MCP_CS3_SSH_USERNAME
SYNOLOGY_MCP_CS3_SSH_KEY_PATH
SYNOLOGY_MCP_CS3_VERIFY_TLS
SYNOLOGY_MCP_CS3_PORT
SYNOLOGY_MCP_CS3_USE_HTTPS
```

Env-var precedence: per-host env vars override config-file values for the same host. Host names with dashes, dots, or other non-alphanumeric characters are normalized to underscores (`nas-primary` → `SYNOLOGY_MCP_NAS_PRIMARY_*`).

Global overrides:

```
SYNOLOGY_MCP_CONFIG          # path to config file (overrides default location)
SYNOLOGY_MCP_LOG_LEVEL       # DEBUG/INFO/WARNING/ERROR
SYNOLOGY_MCP_LIVE_HOST       # used by tests only
```

A host with `ip` but no `password` (and no `ssh_key_path` for SSH-only tools) will fail tool calls with `ConfigError: password not provided`.

---

## 7. DSM API mapping

| MCP tool | DSM web API / SSH source |
|----------|--------------------------|
| `auth_login` | `SYNO.API.Auth` v6 `login` with `enable_syno_token=yes`, `format=cookie` |
| `auth_logout` | `SYNO.API.Auth` v6 `logout` |
| `auth_whoami` | session cache (no DSM call unless cache miss) |
| `packages_list` | `SYNO.Core.Package` v2 `list` + per-pkg `get` |
| `packages_status` | `SYNO.Core.Package` v2 `get` + (ContainerManager only) `docker info` over SSH |
| `packages_install` | `SYNO.Core.Package.get` v1 (idempotency) + `SYNO.Core.Package.Server` `list` v2 (fetch catalog row → `link`/`md5`/`size`/`type`/`source`/`beta`/`qinst`) + `SYNO.Core.Package.Installation` `install` v1 with `{name, is_syno, beta, url, checksum, filesize, type, blqinst, operation}` + `SYNO.Core.Package.Installation` `status` v1 polling. DSM 7.3 does NOT support the legacy `install_from_server` verb (returns 103). |
| `packages_uninstall` | `SYNO.Core.Package.Uninstallation` `uninstall` v1 + `SYNO.Core.Package.Installation` `status` v1 polling |
| `user_home_is_enabled` | `SYNO.Core.User.Home` `get` + SSH `synogetkeyvalue /etc/synoinfo.conf userHomeEnable` + `readlink /var/services/homes` |
| `user_home_enable` | SSH `synosetkeyvalue` + SSH `ln -s` + `SYNO.Core.User.Home` `set` + SSH `synouserhome --prepare-folder` |
| `user_home_disable` | SSH `sudo -n find /var/services/homes/*/.ssh/authorized_keys -size +0c -type f` (would-orphan-keys + sudo-required safety rails) + `SYNO.Core.User.Home` `set enable=false` |
| `snapshot_replication_list_plans` | `SYNO.DR.Plan` `list` + `SYNO.Replica.Share` `list` |
| `snapshot_replication_plan_status` | `SYNO.DR.Plan` `get` |
| `snapshot_replication_recent_activity` | `SYNO.DR.Plan` `list_activity` (read-only) |
| `shares_list` | `SYNO.Core.Share` `list` |
| `shares_create` | `SYNO.Core.Share` `create` |
| `shares_get_acl` | `SYNO.Core.Share.Permission` `list` (decoded) |
| `shares_get_snapshot_config` | `SYNO.Core.Share.Snapshot` `get_config` |
| `raid_list_volumes` | `SYNO.Storage.CGI.Storage` `load_info` (unified payload — `data.volumes[]` + `data.storagePools[]` for pool device_type) |
| `raid_list_disks` | `SYNO.Storage.CGI.Storage` `load_info` (same unified payload — `data.disks[]`) |
| `raid_state` | SSH `cat /proc/mdstat` (parsed) |
| `raid_hardware_info` | `SYNO.Core.System` `info` (model/serial/cpu/ram_size in MB) + `SYNO.Core.Network.Interface` `list` for the NIC table |
| `ssh_get_state` | `SYNO.Core.Terminal` `get` + `SYNO.Core.Group.Member` for SSH group |
| `ssh_set_port` | `SYNO.Core.Terminal` `set` |
| `ssh_enable_user_ssh` | `SYNO.Core.Group.Member` `admin_check` v1 + `add` v1 (target group: `administrators`). Refuses cross-user requests with `category=cross_user_not_supported`. |
| `ssh_add_authorized_key` | SSH `printf %s '<b64>' | base64 -d >> ~/.ssh/authorized_keys` (NO SFTP — see §10). Refuses cross-user requests with `category=cross_user_not_supported`. |
| `ssh_list_authorized_keys` | SSH `cat ~/.ssh/authorized_keys` + parsing |
| `ssh_remove_authorized_key` | SSH read + filter + write (atomic via `mv tmp final`). Refuses cross-user requests with `category=cross_user_not_supported`. |
| `network_list_interfaces` | `SYNO.Core.Network.Interface` `list` (returns `data` as a top-level list with `ifname`/`ip`/`mask`/`speed`/`status`) + SSH `cat /sys/class/net/<if>/{address,speed,operstate,mtu,duplex,carrier}` |
| `network_get_interface` | same plus `ethtool` over SSH |

---

## 8. Testing strategy

### Unit tests (`tests/unit/`)

- Fast, hermetic, no network. Run on every CI build (3.11 + 3.12 matrix).
- DSM HTTP responses mocked via `respx` (`httpx`-native MockTransport wrapper). Canonical responses live in `tests/fixtures/<api>/<scenario>.json`.
- SSH calls mocked via a thin `transport.ssh` interface that tests can substitute with a fake recording stdout/stderr/exit_status for each `exec_command`.
- Coverage target: 80% on non-transport modules. Transport modules tested via integration.

### Integration tests (`tests/integration/`)

- Gated by `SYNOLOGY_MCP_LIVE_HOST` env var. Skipped on CI.
- Hit a real DSM host (yours, in a test VLAN ideally). Read-only operations only by default. Write tests gated behind a second env var (`SYNOLOGY_MCP_LIVE_WRITE=1`) and explicitly opt-in per test.
- Useful for validating new DSM versions: spin up a fresh DSM VM, point integration tests at it, expect green.

### Recording / replaying real DSM responses

When adding support for a new endpoint, the contributor flow is:

1. Hit the live DSM endpoint with a small recording wrapper (`scripts/record_response.py`, not yet built).
2. Sanitize the response (strip session ids, real serials, IPs — there's a `tests/sanitize.py` helper).
3. Drop the JSON into `tests/fixtures/<api>/<scenario>.json`.
4. Reference it from a `respx` unit test.

### Test data hygiene

- No real credentials in fixtures.
- IPs replaced with documentation prefixes (`192.0.2.0/24`, `2001:db8::/32`).
- MACs replaced with `00:00:5E:00:53:xx`.
- Hostnames replaced with `*.example.com`.

---

## 9. Versioning and DSM compatibility

### Project versioning

SemVer. Anything `0.x.y` is pre-1.0 — breaking changes allowed in minor. After 1.0, breaking changes only in majors.

The **MCP tool surface** is the public API. Internal modules can be reshuffled freely as long as the tool surface and its return schemas stay stable.

### DSM compatibility shim

Different DSM versions return slightly different JSON shapes. A compat shim normalizes them to the schema this MCP exposes.

```python
# Shape: each subsystem module owns a `_normalize_*` family.
# The HTTP transport detects DSM version at login (from
# SYNO.API.Info `info` or the `/etc/VERSION` file over SSH) and stores it
# on the session. Subsystem modules dispatch on `session.dsm_major_minor`:
#
#   if session.dsm == (7, 3): return _normalize_v73_package(raw)
#   if session.dsm == (7, 2): return _normalize_v72_package(raw)
#   raise UnsupportedDSMVersion(session.dsm)
#
# Only the version-specific functions know about field renames /
# additions; everything downstream sees a single schema.
```

### Supported versions

| DSM version | MVP support level | Notes |
|-------------|-------------------|-------|
| 7.3 (build 86009+) | First-class | Reference build for the MVP |
| 7.2 | Best-effort | Compat shim planned; lightly tested |
| 7.1 | None at v0.1 | Likely most calls work; not validated |
| 7.0 | None | Skip |
| 6.x | Out of scope | EOL |

---

## 10. Security

### Credential handling

- Passwords NEVER appear in logs, error messages, exceptions, or returned data structures.
- `__repr__` on session / config objects redacts password fields.
- Error messages sanitize URLs: query strings containing `passwd=` are scrubbed before logging.
- 2FA OTP codes are accepted as input but never echoed back in any return value (they're single-use anyway).

### TLS

- `verify_tls=true` by default. Production deployments MUST keep this on.
- `verify_tls=false` is supported but always logged at WARNING on first use per host: "TLS verification disabled for host=<name>; this is only safe on trusted LANs."
- DSM's self-signed cert is the common reason users want this off. Documentation will steer them toward installing a real cert (Let's Encrypt via DSM's built-in client) before recommending `verify_tls=false`.

### SSH

- Default to ed25519 keys; reject DSA outright; warn on RSA < 2048.
- `paramiko.AutoAddPolicy` is NOT used. Hosts must be in `known_hosts` or the user must explicitly accept the fingerprint via a `trust_host` config field. First-use TOFU is a separate confirmation step.
- SSH passwords accepted as input for first-use scenarios (commissioning) but credentials in flight are not echoed back.

### Why no SFTP

DSM ships with the SFTP subsystem commented out in `/etc/ssh/sshd_config`. We never assume SFTP works. All file ops use `exec_command` with base64-encoded payloads (for small files) or `scp` (for bulk). See `feedback_dsm_no_sftp.md` for the original observation.

### Audit log

Every write tool call logs (at INFO): `timestamp, host, tool, params_redacted, result_ok, dsm_error_code`. This is the operator's audit trail. Logs go to stderr by default (MCP stdout is reserved for the JSON-RPC stream).

---

## 11. Out of scope for MVP

These are deliberately deferred. Adding them later is straightforward — they're noted here to set expectations and to capture the rationale before it's lost.

### Snapshot Replication plan creation

**Why deferred:** DSM's SR plan creation is gated by a one-shot UI node-pairing wizard. Even with manual schedule + "skip initial sync", DSM by default kicks off a baseline send on plan creation, and there is no documented API flag to disable that. The plan creator writes a multi-table record to `/var/packages/SnapshotReplication/etc/replica.db` (tables: `plan`, `share_replication`, `sync_info`, `remote_conn`, `output_conn`). Creating these blind via undocumented `SYNO.DR.Plan` / `SYNO.Replica.Share` endpoints risks half-built rows that DSM UI cannot remediate. Until we capture the exact UI request shape from a recorded browser session, this is too risky to ship.

**Path to support:** capture the request payload from DSM's UI on plan creation, validate against multiple DSM versions, then implement as a single `snapshot_replication_create_plan(host, source_share, dest_host, dest_share, **opts)` tool with the same idempotency + rollback discipline as `user_home_enable`.

### Encryption key management

Share encryption keys, encrypted-volume keys, key vault setup. Deferred because: (a) very low frequency op, (b) high blast radius — a misstep can lock out an entire volume, (c) DSM Key Manager v2 changed the shape between 7.2 and 7.3.

### Certificate rotation

Let's Encrypt issuance + import to DSM. Deferred because Synology's built-in LE client + ACME endpoint changes between DSM versions, and the manual cert-import flow is multi-step with file uploads. There's also overlap with operator workflows that already exist (`acme.sh`, etc.).

### DSM update orchestration

`SYNO.Core.Upgrade` family — check for updates, apply, reboot. Deferred because updating a NAS unattended without confirmation is high blast radius. Read-only "update available?" might be added in a point release.

### Hyper Backup

Hyper Backup task status, list, trigger. Deferred — large surface area, undocumented endpoints, and the rsync MCP equivalent is just SSH + `synopkg`. Will revisit when there's concrete operator demand.

### Package marketplace search

Querying available packages in Synology's repos before install. Deferred — install can already happen with a known ID; discovery is a UI-flavored task.

---

## Resolved design decisions

Resolved 2026-05-26 before Phase 1 implementation:

1. **Config file path.** `~/.config/synology-mcp/config.toml` (XDG-ish; honours `$XDG_CONFIG_HOME` when set). Override with `SYNOLOGY_MCP_CONFIG` env var.
2. **MCP tool naming style.** Flat snake_case with module prefix (`auth_login`, `raid_list_volumes`). No dots. MCP clients see one flat tool namespace, which plays best with current Claude Code / Claude Desktop tool autocomplete.
3. **httpx client lifecycle.** One `httpx.AsyncClient` cached per host for the lifetime of the MCP process. No idle timer. Reconnect only on auth error (DSM 105/107/119) or transport-level socket error. Rationale: an idle httpx client costs ~zero, and DSM does not punish long-lived connections.
4. **paramiko SSH client lifecycle.** One `SSHClient` cached per host for the lifetime of the process. `transport.set_keepalive(60)` to survive Synology's ~10-15 min idle-disconnect. Channel errors trigger a transparent reconnect; the caller never sees stale-channel failures.
5. **DSM warning surfacing.** Verbatim pass-through. Whatever string DSM returns in a `success=true` envelope with a `warning` field (or in the top-level `error.errors` payload on warning-class errors) is appended to the tool's `warnings[]` list with no normalization. Operators see DSM's exact words.

These decisions are locked. Future revisits should treat them as load-bearing for downstream consumers.
