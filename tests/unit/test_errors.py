# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for errors.raise_for_dsm_error mapping."""
from __future__ import annotations

import pytest

from synology_mcp.errors import (
    AuthFailed,
    DSMError,
    InvalidParam,
    OtpRequired,
    PermissionDenied,
    SessionFailed,
    UnsupportedDSMVersion,
    raise_for_dsm_error,
)


@pytest.mark.parametrize(
    "code,exc_cls",
    [
        (101, InvalidParam),
        (102, UnsupportedDSMVersion),
        (103, UnsupportedDSMVersion),
        (104, UnsupportedDSMVersion),
        (105, PermissionDenied),
        (107, SessionFailed),
        (119, SessionFailed),
        (400, AuthFailed),
        (403, OtpRequired),
    ],
)
def test_known_codes_map_to_typed_exceptions(code, exc_cls) -> None:
    with pytest.raises(exc_cls) as exc_info:
        raise_for_dsm_error(code, host="testhost")
    assert exc_info.value.dsm_error_code == code
    assert exc_info.value.host == "testhost"


def test_unknown_code_falls_back_to_dsmerror() -> None:
    with pytest.raises(DSMError) as exc_info:
        raise_for_dsm_error(9999, host="testhost")
    assert exc_info.value.dsm_error_code == 9999
    # Should be the base class, not a subclass.
    assert type(exc_info.value) is DSMError


def test_zero_code_does_not_raise() -> None:
    # No exception expected.
    raise_for_dsm_error(0, host="testhost")
