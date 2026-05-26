# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""DSM HTTP transport.

Wraps `httpx.AsyncClient` with:
  - one client per host, cached for process lifetime (see DESIGN.md §2)
  - automatic injection of `X-SYNO-TOKEN` + sid cookie on calls
  - JSON envelope parsing + error-code normalization to our exception hierarchy

The client is intentionally dumb about retries — `auth.py` decides when to
invalidate and re-login. Higher-level retry policy (DSM 106/109 backoff)
lives in the subsystem modules that need it.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from ..errors import DSMTransportError, raise_for_dsm_error

if TYPE_CHECKING:  # pragma: no cover
    from ..config import HostConfig
    from ..session import DSMSession


class DSMHttpClient:
    """One DSM HTTP client per host. Cached in `SessionCache`."""

    def __init__(self, host_cfg: HostConfig) -> None:
        self.host_cfg = host_cfg
        timeout = httpx.Timeout(
            connect=host_cfg.connect_timeout,
            read=host_cfg.read_timeout,
            write=host_cfg.read_timeout,
            pool=host_cfg.read_timeout,
        )
        self._client = httpx.AsyncClient(
            base_url=host_cfg.base_url,
            timeout=timeout,
            verify=host_cfg.verify_tls,
            follow_redirects=False,
        )

    @property
    def httpx_client(self) -> httpx.AsyncClient:
        """Direct access for tests that want to swap transports."""
        return self._client

    async def aclose(self) -> None:
        await self._client.aclose()

    async def call(
        self,
        api: str,
        method: str,
        version: int,
        *,
        params: dict[str, Any] | None = None,
        session: DSMSession | None = None,
        path: str = "/webapi/entry.cgi",
        raise_on_dsm_error: bool = True,
    ) -> dict[str, Any]:
        """Make one DSM call and return the parsed JSON envelope.

        The envelope is the raw DSM response (``{"success": ..., "data": ...,
        "error": ...}``). When `raise_on_dsm_error=True` and ``success`` is
        False, the corresponding exception is raised. When False, the caller
        gets the raw envelope and decides what to do.
        """
        query: dict[str, Any] = {
            "api": api,
            "method": method,
            "version": version,
        }
        if params:
            query.update(params)
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        if session is not None:
            if session.syno_token:
                headers["X-SYNO-TOKEN"] = session.syno_token
            if session.cookies:
                cookies.update(session.cookies)
            elif session.sid:
                cookies["id"] = session.sid
        try:
            resp = await self._client.get(
                path,
                params=query,
                headers=headers or None,
                cookies=cookies or None,
            )
        except httpx.TimeoutException as exc:
            raise DSMTransportError(
                f"DSM call timed out: {api}.{method}",
                host=self.host_cfg.name,
                details={"api": api, "method": method, "version": version},
            ) from exc
        except httpx.TransportError as exc:
            raise DSMTransportError(
                f"DSM transport error on {api}.{method}: {exc}",
                host=self.host_cfg.name,
                details={"api": api, "method": method, "version": version},
            ) from exc

        try:
            body = resp.json()
        except ValueError as exc:
            raise DSMTransportError(
                f"DSM returned non-JSON body (status={resp.status_code})",
                host=self.host_cfg.name,
                details={"status_code": resp.status_code, "body_snippet": resp.text[:200]},
            ) from exc

        if not isinstance(body, dict):
            raise DSMTransportError(
                "DSM JSON body is not an object",
                host=self.host_cfg.name,
                details={"body": body},
            )

        if raise_on_dsm_error and not body.get("success", False):
            err = body.get("error") or {}
            code = int(err.get("code", 0) or 0)
            raise_for_dsm_error(
                code,
                host=self.host_cfg.name,
                details={"api": api, "method": method, "error": err},
            )
            # Defensive: if code 0 with success=false, surface as transport error.
            raise DSMTransportError(
                f"DSM reported success=false with no error code on {api}.{method}",
                host=self.host_cfg.name,
                details={"body": body},
            )

        return body


def extract_warnings(envelope: dict[str, Any]) -> list[str]:
    """Pull DSM warning strings out of a success envelope.

    Per DESIGN.md decision 5, warnings are verbatim pass-through. DSM uses
    several shapes for them (`warning`, `data.warning`, `error.errors` on
    success=true responses); collect whatever we find.
    """
    out: list[str] = []
    top = envelope.get("warning")
    if isinstance(top, str) and top:
        out.append(top)
    elif isinstance(top, list):
        out.extend(str(x) for x in top if x)
    data = envelope.get("data")
    if isinstance(data, dict):
        nested = data.get("warning")
        if isinstance(nested, str) and nested:
            out.append(nested)
        elif isinstance(nested, list):
            out.extend(str(x) for x in nested if x)
    err = envelope.get("error")
    if isinstance(err, dict):
        errors_field = err.get("errors")
        if isinstance(errors_field, list):
            out.extend(str(x) for x in errors_field if x)
        elif isinstance(errors_field, str):
            out.append(errors_field)
    return out
