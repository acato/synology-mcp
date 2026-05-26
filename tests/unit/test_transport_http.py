# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for transport.http.extract_warnings."""
from __future__ import annotations

from synology_mcp.transport.http import extract_warnings


def test_top_level_warning_string() -> None:
    env = {"success": True, "warning": "Volume nearing capacity"}
    assert extract_warnings(env) == ["Volume nearing capacity"]


def test_top_level_warning_list() -> None:
    env = {"success": True, "warning": ["one", "two"]}
    assert extract_warnings(env) == ["one", "two"]


def test_nested_data_warning() -> None:
    env = {"success": True, "data": {"warning": "User Home already enabled"}}
    assert extract_warnings(env) == ["User Home already enabled"]


def test_error_errors_field_on_success() -> None:
    env = {"success": True, "error": {"errors": ["partial: 3 disks skipped"]}}
    assert extract_warnings(env) == ["partial: 3 disks skipped"]


def test_no_warnings_returns_empty() -> None:
    env = {"success": True, "data": {"sid": "x"}}
    assert extract_warnings(env) == []


def test_warnings_are_verbatim() -> None:
    """DESIGN.md decision 5: warnings pass through verbatim, no normalization."""
    msg = "Snapshot pruned 17 entries; reused 2 holes; resync deferred 4m12s"
    env = {"success": True, "warning": msg}
    assert extract_warnings(env) == [msg]
