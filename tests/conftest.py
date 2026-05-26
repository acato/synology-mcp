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

import json
import os
from pathlib import Path
from typing import Any

import pytest

from synology_mcp.config import Config, HostConfig, _Defaults
from synology_mcp.server import AppContext
from synology_mcp.session import SessionCache

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip live integration tests unless SYNOLOGY_MCP_LIVE_HOST is set."""
    if os.environ.get("SYNOLOGY_MCP_LIVE_HOST"):
        return
    skip_live = pytest.mark.skip(reason="SYNOLOGY_MCP_LIVE_HOST not set")
    for item in items:
        if "integration" in item.nodeid:
            item.add_marker(skip_live)


def load_fixture_json(*path_parts: str) -> dict[str, Any]:
    """Load a JSON fixture from `tests/fixtures/<path>`."""
    p = FIXTURES_DIR.joinpath(*path_parts)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_fixture_text(*path_parts: str) -> str:
    """Load a text fixture (e.g. mdstat dumps)."""
    p = FIXTURES_DIR.joinpath(*path_parts)
    return p.read_text(encoding="utf-8")


@pytest.fixture
def fixture_json():
    """Pytest fixture wrapping :func:`load_fixture_json`."""
    return load_fixture_json


@pytest.fixture
def fixture_text():
    """Pytest fixture wrapping :func:`load_fixture_text`."""
    return load_fixture_text


@pytest.fixture
def test_host_cfg() -> HostConfig:
    """A canned HostConfig pointing at the standard documentation IP."""
    return HostConfig(
        name="testhost",
        ip="192.0.2.10",
        account="testuser",
        password="testpass",
        port=5001,
        use_https=True,
        verify_tls=False,
        ssh_port=22,
    )


@pytest.fixture
def test_config(test_host_cfg: HostConfig) -> Config:
    """Config pre-seeded with one test host."""
    cfg = Config(defaults=_Defaults(), hosts={"testhost": test_host_cfg})
    return cfg


@pytest.fixture
def app_ctx(test_config: Config) -> AppContext:
    """A fresh AppContext bound to the test config."""
    return AppContext(config=test_config, cache=SessionCache())
