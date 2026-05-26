# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Exception hierarchy for synology-mcp.

DSM error codes are mapped to specific exception classes (see DESIGN.md §4).
Tool-level callers see one of:

  - ConfigError: misconfiguration (missing password, unknown host, etc.)
  - AuthFailed: bad credentials (DSM 400)
  - OtpRequired: 2FA gate (DSM 403)
  - PermissionDenied: account lacks privilege (DSM 105)
  - SessionFailed: re-login retry exhausted (DSM 107/119)
  - UnsupportedDSMVersion: API/method/version mismatch (DSM 102/103/104)
  - InvalidParam: malformed request (DSM 101)
  - DSMTransportError: network-level failure
  - DSMSshError: SSH command failure (nonzero exit + stderr)
  - DSMError: generic DSM failure (fallback)
"""
from __future__ import annotations

from typing import Any


class DSMError(Exception):
    """Base class for DSM-related failures."""

    category: str = "internal"

    def __init__(
        self,
        message: str,
        *,
        host: str | None = None,
        dsm_error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.host = host
        self.dsm_error_code = dsm_error_code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "message": self.message,
            "host": self.host,
            "dsm_error_code": self.dsm_error_code,
            "details": self.details,
        }


class ConfigError(DSMError):
    """Misconfiguration: missing password, unknown host, malformed file."""

    category = "validation"


class AuthFailed(DSMError):
    """DSM 400 — invalid credentials. Do NOT retry."""

    category = "auth"


class OtpRequired(DSMError):
    """DSM 403 — 2FA gate. Caller must resubmit with `otp_code`."""

    category = "auth"


class PermissionDenied(DSMError):
    """DSM 105 — account lacks the privilege for this endpoint."""

    category = "permission"


class SessionFailed(DSMError):
    """Session-token mismatch or multiple-login; re-login retry was exhausted."""

    category = "auth"


class UnsupportedDSMVersion(DSMError):
    """DSM 102/103/104 — API, method, or version not supported on this build."""

    category = "unsupported"


class InvalidParam(DSMError):
    """DSM 101 — request payload was malformed."""

    category = "validation"


class DSMTransportError(DSMError):
    """Network-level failure (connect/read timeout, socket error)."""

    category = "network"


class DSMSshError(DSMError):
    """SSH command exited non-zero, or SSH transport failed."""

    category = "internal"

    def __init__(
        self,
        message: str,
        *,
        host: str | None = None,
        exit_status: int | None = None,
        stderr: str | None = None,
        command: str | None = None,
    ) -> None:
        super().__init__(
            message,
            host=host,
            details={"exit_status": exit_status, "stderr": stderr, "command": command},
        )
        self.exit_status = exit_status
        self.stderr = stderr
        self.command = command


# Mapping DSM `error.code` integers to exception classes. Codes not in this
# table fall through to a generic DSMError with the raw code preserved.
DSM_CODE_TO_EXC: dict[int, type[DSMError]] = {
    101: InvalidParam,
    102: UnsupportedDSMVersion,
    103: UnsupportedDSMVersion,
    104: UnsupportedDSMVersion,
    105: PermissionDenied,
    107: SessionFailed,
    119: SessionFailed,
    400: AuthFailed,
    403: OtpRequired,
}


def raise_for_dsm_error(
    code: int,
    *,
    host: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Translate a DSM error code into the appropriate exception class.

    Returns normally for code 0 (success). Raises for any non-zero code.
    """
    if code == 0:
        return
    exc_cls = DSM_CODE_TO_EXC.get(code, DSMError)
    raise exc_cls(
        f"DSM error code {code}",
        host=host,
        dsm_error_code=code,
        details=details,
    )
