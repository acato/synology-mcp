# Contributing to synology-mcp

Thanks for your interest! This project is in early design / pre-alpha — contributions of any size are welcome.

## Ground rules

- **Read [DESIGN.md](DESIGN.md) first.** The MVP scope, tool signatures, and DSM API mapping are documented there. If your change diverges from the design, propose the design change in an issue or PR first.
- **No vendor-specific defaults.** This codebase must work for any Synology user. No hardcoded IPs, hostnames, share names, or paths from any specific environment.
- **No secrets in code, tests, or fixtures.** Credentials come from config files or environment variables. PRs that hardcode credentials will be rejected.

## Development setup

```bash
git clone https://github.com/acato/synology-mcp
cd synology-mcp
uv sync --all-extras
uv run pytest
uv run ruff check
uv run ruff format --check
```

Python 3.11+ required. Dependencies are managed by [uv](https://docs.astral.sh/uv/).

## Testing

- **Unit tests** (`tests/unit/`) — fast, no network, run on every CI build. Use `httpx.MockTransport` for DSM responses. Fixtures live in `tests/fixtures/`.
- **Live integration tests** (`tests/integration/`) — gated behind the `SYNOLOGY_MCP_LIVE_HOST` env var. Skipped by default. CI never runs these.
- New DSM tools must come with at least unit-test coverage of the happy path + one error case (e.g., auth expired, malformed response). Use `pytest -k` to scope while iterating.

For live tests against your own NAS:

```bash
export SYNOLOGY_MCP_LIVE_HOST=nas.example.com
export SYNOLOGY_MCP_LIVE_USER=admin
export SYNOLOGY_MCP_LIVE_PASS='...'
uv run pytest tests/integration
```

Never commit a real config file or `.env` containing credentials. `.gitignore` excludes `*.env` and `config.local.*`.

## Code style

- `ruff check` and `ruff format` are CI-enforced.
- Type hints are required on public functions (the MCP tool surface). Internal helpers may omit them but they're encouraged.
- Docstrings on every public function. Use the Google docstring style.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`. Scope is optional (`feat(auth): ...`).

## Reporting DSM quirks

If you discover a new DSM-version-specific behavior that the MCP should handle, open an issue with:

1. DSM version (`cat /etc/VERSION`) and product model (`uname -a`).
2. The exact API call that misbehaves (URL, params, headers).
3. The observed response vs. expected.
4. A reproducible sequence of steps if possible.

These are gold — they're exactly the kind of knowledge this project exists to capture.

## License

By contributing, you agree that your contributions will be licensed under [Apache 2.0](LICENSE).
