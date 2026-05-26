# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for auth.py.

The real respx-driven test suite lands in the same commit as the auth
implementation; this file stays minimal here so the placeholder import
keeps working.
"""
from __future__ import annotations

from synology_mcp import auth


def test_auth_module_exports() -> None:
    """Auth module exposes the Phase-1 tool entrypoints."""
    assert callable(auth.auth_login)
    assert callable(auth.auth_logout)
    assert callable(auth.auth_whoami)
    assert callable(auth.ensure_session)
    assert callable(auth.perform_login)
    assert callable(auth.perform_logout)
