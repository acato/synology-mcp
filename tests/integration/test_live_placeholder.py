# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Live integration tests — skipped unless SYNOLOGY_MCP_LIVE_HOST is set.

See CONTRIBUTING.md for how to run these against your own NAS.
"""
from __future__ import annotations

import os

import pytest


def test_live_env_present() -> None:
    host = os.environ.get("SYNOLOGY_MCP_LIVE_HOST")
    assert host, "SYNOLOGY_MCP_LIVE_HOST must be set for integration tests"
    # Real live tests will be added with the implementation.
    pytest.skip("no live tests implemented yet")
