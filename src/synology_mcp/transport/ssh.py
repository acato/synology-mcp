# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""DSM SSH transport.

One paramiko `SSHClient` per host, cached for the process lifetime, with
`transport.set_keepalive(60)` to survive Synology's 10-15 min idle disconnect.

Channel errors trigger a transparent reconnect on the next call; callers
never see stale-channel exceptions.

Run commands return a `SshResult` dataclass with `stdout`, `stderr`, and
`exit_status`. Non-zero exit raises `DSMSshError` unless `check=False`.
"""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

import paramiko

from ..errors import DSMSshError

if TYPE_CHECKING:  # pragma: no cover
    from ..config import HostConfig


@dataclass
class SshResult:
    """One command's output."""

    command: str
    stdout: str
    stderr: str
    exit_status: int

    @property
    def ok(self) -> bool:
        return self.exit_status == 0


class DSMSshClient:
    """One paramiko SSHClient per host, transparently reconnects on channel errors.

    The client is lazy: the underlying TCP / SSH handshake happens on the
    first call to `run()`. Subsequent calls reuse the cached client.
    """

    def __init__(self, host_cfg: HostConfig, password: str | None = None) -> None:
        self.host_cfg = host_cfg
        self._password = password
        self._client: paramiko.SSHClient | None = None

    def close(self) -> None:
        if self._client is not None:
            with contextlib.suppress(Exception):  # pragma: no cover - best effort
                self._client.close()
            self._client = None

    def _connect_sync(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        # SECURITY: We do NOT use AutoAddPolicy. The user must have the host
        # in known_hosts before connecting (see DESIGN.md §10). load_system_host_keys
        # picks up ~/.ssh/known_hosts; load_host_keys would pick up a custom file.
        client.load_system_host_keys()
        connect_kwargs: dict[str, object] = {
            "hostname": self.host_cfg.ip,
            "port": self.host_cfg.ssh_port,
            "username": self.host_cfg.effective_ssh_username,
            "timeout": self.host_cfg.connect_timeout,
            "auth_timeout": self.host_cfg.connect_timeout,
            "banner_timeout": self.host_cfg.connect_timeout,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if self.host_cfg.ssh_key_path:
            connect_kwargs["key_filename"] = self.host_cfg.ssh_key_path
        if self._password:
            connect_kwargs["password"] = self._password
        try:
            client.connect(**connect_kwargs)  # type: ignore[arg-type]
        except (OSError, paramiko.SSHException) as exc:
            raise DSMSshError(
                f"SSH connect failed for {self.host_cfg.ip}:{self.host_cfg.ssh_port}: {exc}",
                host=self.host_cfg.name,
            ) from exc

        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(60)
        return client

    async def _ensure_client(self) -> paramiko.SSHClient:
        if self._client is not None:
            return self._client
        # paramiko is blocking; offload connect to default executor.
        loop = asyncio.get_running_loop()
        client = await loop.run_in_executor(None, self._connect_sync)
        self._client = client
        return client

    async def run(
        self,
        command: str,
        *,
        check: bool = True,
        timeout: float | None = 30.0,
    ) -> SshResult:
        """Execute one command and return its result.

        On `paramiko.SSHException` (channel error / broken transport), the
        cached client is invalidated and the call retried exactly once.
        """
        for attempt in (1, 2):
            client = await self._ensure_client()
            try:
                result = await asyncio.get_running_loop().run_in_executor(
                    None, _exec_command_sync, client, command, timeout
                )
            except paramiko.SSHException as exc:
                # Stale channel / transport dropped. Reconnect once and retry.
                self.close()
                if attempt == 1:
                    continue
                raise DSMSshError(
                    f"SSH channel error after reconnect: {exc}",
                    host=self.host_cfg.name,
                    command=command,
                ) from exc
            except OSError as exc:
                self.close()
                if attempt == 1:
                    continue
                raise DSMSshError(
                    f"SSH socket error after reconnect: {exc}",
                    host=self.host_cfg.name,
                    command=command,
                ) from exc
            if check and result.exit_status != 0:
                raise DSMSshError(
                    f"command exited {result.exit_status}: {command}",
                    host=self.host_cfg.name,
                    exit_status=result.exit_status,
                    stderr=result.stderr,
                    command=command,
                )
            return result
        # Unreachable; loop returns or raises.
        raise DSMSshError(  # pragma: no cover - defensive
            "SSH run exhausted retries", host=self.host_cfg.name, command=command
        )


def _exec_command_sync(
    client: paramiko.SSHClient, command: str, timeout: float | None
) -> SshResult:
    """Blocking helper run in an executor thread."""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    stdin.close()
    out_bytes = stdout.read()
    err_bytes = stderr.read()
    exit_status = stdout.channel.recv_exit_status()
    return SshResult(
        command=command,
        stdout=out_bytes.decode("utf-8", errors="replace"),
        stderr=err_bytes.decode("utf-8", errors="replace"),
        exit_status=exit_status,
    )
