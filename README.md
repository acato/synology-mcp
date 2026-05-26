# synology-mcp

An [MCP](https://modelcontextprotocol.io/) server that wraps the Synology DSM web API so AI agents (Claude Code, Claude Desktop, IDE assistants) can manage Synology NAS appliances without rediscovering DSM's quirks on every task.

**Status:** beta. Feature-complete MVP — 28 tools across 8 modules (auth, raid, network, packages, user_home, shares, snapshot_replication, ssh) covering read-only inspection and supported write operations. 187 unit tests and 24 live integration tests against DSM 7.3.2 currently pass. API is stable; documented v0 limitations: no cross-user SSH writes (would need a sudo-password mechanism), no offline `.spk` fallback for package install. See [DESIGN.md](DESIGN.md) for the full architecture, tool surface, and DSM API mapping.

## Why

DSM's web API has well-known surprises:

- The auth handshake uses `account=` (not `username=`), version 6 of `SYNO.API.Auth`, and the response carries both an `sid` cookie and an `X-SYNO-TOKEN` header that must be sent together on subsequent calls.
- Enabling **User Home** via the documented endpoint silently no-ops on DSM 7.3 unless `/etc/synoinfo.conf` already contains `userHomeEnable=yes`.
- Installing some packages via `SYNO.Core.Package.Installation install_from_server` fails for no obvious reason but works fine if you upload the `.spk` directly.
- **Snapshot Replication** plan creation is gated by a one-shot UI-only node-pairing wizard; you can read plan state via the API but you can't create a plan from a cold start.
- The SFTP subsystem is disabled by default — `paramiko.open_sftp()` returns `Channel closed`. File transfers must use `scp`, `rsync`, or base64-over-`exec`.
- DSM's package status reporter (`synopkg status`) lies about ContainerManager (claims `stop` while Docker is healthily running).

`synology-mcp` encapsulates these quirks once so your agent doesn't have to.

## Scope

### MVP (in active design)

1. **Auth flow** — login → `sid` + `syno_token`, auto-refresh, per-host session cache.
2. **Package management** — install (with `install_from_server`-fails-fallback-to-`.spk`), list, status, uninstall.
3. **User Home enable** — apply the `synoinfo.conf` + symlink retarget + `synouserhome --prepare-folder` workaround in one tool call.
4. **Snapshot Replication** — **read-only** (list plans, status, recent activity). Plan creation is deferred; see [DESIGN.md §11](DESIGN.md#11-out-of-scope-for-mvp).
5. **Shared folder lifecycle** — create, list, ACL read, snapshot config read.
6. **RAID / volume / disk inspection** — surfaces `/proc/mdstat`, `synodisk`, `syno_dsm_serial`, `volume*` fs/usage.
7. **SSH key + port management** — drop pubkeys into `authorized_keys`, set SSH port, enable user-app SSH permission.
8. **Network basics** — eth interface state, MTU, MAC.

### Out of scope (for now)

- Snapshot Replication plan creation (UI-gated)
- Encryption key management
- TLS certificate rotation
- DSM update orchestration
- Hyper Backup
- Package marketplace search

See [DESIGN.md §11](DESIGN.md#11-out-of-scope-for-mvp) for rationale.

## Multi-host

Every tool accepts a `host` parameter. Credentials and connection settings come from a config file or environment variables — there are **no hardcoded hosts** in this codebase. See [`examples/config.toml`](examples/config.toml).

## Quickstart

> Implementation in progress — this section is the intended UX.

```bash
# Install from PyPI (when published)
uv tool install synology-mcp

# Or run from source
git clone https://github.com/acato/synology-mcp
cd synology-mcp
uv sync
uv run synology-mcp
```

### Wire into Claude Code

```bash
claude mcp add synology-mcp -- uv run --directory /path/to/synology-mcp synology-mcp
```

### Configuration

Copy `examples/config.toml` to `~/.config/synology-mcp/config.toml` and fill in your hosts. Or set per-host env vars (see [DESIGN.md §6](DESIGN.md#6-configuration)).

## Documentation

- [DESIGN.md](DESIGN.md) — full architecture and tool surface
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [`examples/`](examples/) — sample configs

## Compatibility

- **DSM 7.3** — first-class target (DSM 7.3.2 build 86009 reference)
- **DSM 7.2** — design includes a thin compatibility shim; will be exercised once 7.3 is stable
- **DSM 6.x** — out of scope (EOL)

See [DESIGN.md §9](DESIGN.md#9-versioning--dsm-compatibility) for the compat strategy.

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attributions.

## Trademarks

This project is not affiliated with, endorsed by, or sponsored by Synology Inc. "Synology" and "DSM" are trademarks of Synology Inc.
