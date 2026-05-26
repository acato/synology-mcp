# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Per-host session state.

Holds:
  - `DSMSession` dataclass (sid + syno_token + cookies + user + issued_at)
  - `SessionCache` — a process-wide registry keyed by host name (NOT IP)

The cache is held by `server.AppContext` for the life of the MCP process.
Cache invalidation: explicit `auth_logout`, DSM 105/107/119 from any call,
or process shutdown (best-effort logout on every cached session).

See DESIGN.md §3.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class DSMSession:
    """Resolved DSM session credentials for one host."""

    sid: str
    syno_token: str
    user: str
    cookies: dict[str, str] = field(default_factory=dict)
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    dsm_major_minor: tuple[int, int] | None = None

    def age_seconds(self) -> float:
        return (datetime.now(UTC) - self.issued_at).total_seconds()

    def descriptor(self) -> dict[str, object]:
        """Public-safe descriptor (no sid / token bytes)."""
        return {
            "user": self.user,
            "sid_present": bool(self.sid),
            "token_present": bool(self.syno_token),
            "issued_at": self.issued_at.isoformat(),
            "age_seconds": round(self.age_seconds(), 1),
            "dsm_major_minor": list(self.dsm_major_minor) if self.dsm_major_minor else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"DSMSession(user={self.user!r}, sid=***, syno_token=***, "
            f"issued_at={self.issued_at.isoformat()})"
        )


@dataclass
class HostState:
    """All cached state for one host: DSM session + transport clients.

    `http_client` holds a `transport.http.DSMHttpClient` wrapper (NOT a raw
    httpx.AsyncClient — the wrapper owns the actual client and adds the
    DSM-specific JSON / X-SYNO-TOKEN handling). `ssh_client` holds a
    `transport.ssh.DSMSshClient`. Both are typed as `object` here to avoid
    a circular import; the call sites isinstance-check before using.
    """

    session: DSMSession | None = None
    http_client: object | None = None  # transport.http.DSMHttpClient
    ssh_client: object | None = None  # transport.ssh.DSMSshClient

    def has_session(self) -> bool:
        return self.session is not None


class SessionCache:
    """Process-wide cache keyed by config-file host name."""

    def __init__(self) -> None:
        self._by_host: dict[str, HostState] = {}

    def get(self, host: str) -> HostState:
        if host not in self._by_host:
            self._by_host[host] = HostState()
        return self._by_host[host]

    def invalidate_session(self, host: str) -> DSMSession | None:
        state = self._by_host.get(host)
        if state is None:
            return None
        prior = state.session
        state.session = None
        return prior

    def invalidate_http(self, host: str) -> None:
        state = self._by_host.get(host)
        if state is None:
            return
        state.http_client = None

    def invalidate_ssh(self, host: str) -> None:
        state = self._by_host.get(host)
        if state is None:
            return
        state.ssh_client = None

    def all_hosts(self) -> list[str]:
        return list(self._by_host.keys())

    async def aclose(self) -> None:
        """Best-effort close every cached httpx client + ssh client."""
        for state in self._by_host.values():
            if state.http_client is not None:
                with contextlib.suppress(Exception):  # pragma: no cover - best effort
                    await state.http_client.aclose()
                state.http_client = None
            ssh = state.ssh_client
            if ssh is not None:
                with contextlib.suppress(Exception):  # pragma: no cover - best effort
                    ssh.close()  # type: ignore[attr-defined]
                state.ssh_client = None
            state.session = None
