# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Shared pytest fixtures.

See DESIGN.md §8 (Testing Strategy) for the full plan. In short:
  - `tests/unit/` uses `respx` to mock DSM HTTP responses; no network.
  - `tests/integration/` runs against a real DSM host gated on
    `SYNOLOGY_MCP_LIVE_HOST` env var; skipped by default.
  - `tests/fixtures/` holds canonical DSM response JSON for replay.
"""
from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip live integration tests unless SYNOLOGY_MCP_LIVE_HOST is set."""
    if os.environ.get("SYNOLOGY_MCP_LIVE_HOST"):
        return
    skip_live = pytest.mark.skip(reason="SYNOLOGY_MCP_LIVE_HOST not set")
    for item in items:
        if "integration" in item.nodeid:
            item.add_marker(skip_live)
