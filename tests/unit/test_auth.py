# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for auth.py — placeholder; tests added with implementation."""
from __future__ import annotations

import pytest

from synology_mcp import auth


@pytest.mark.asyncio
async def test_login_not_implemented() -> None:
    """Placeholder until auth.login is implemented."""
    with pytest.raises(NotImplementedError):
        await auth.login("example.invalid")
