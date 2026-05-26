# Copyright 2026 synology-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Smoke test — package imports cleanly."""
from __future__ import annotations


def test_package_imports() -> None:
    import synology_mcp

    assert synology_mcp.__version__ == "0.0.0"


def test_subsystem_modules_importable() -> None:
    from synology_mcp import (
        auth,
        network,
        packages,
        raid,
        server,
        shares,
        snapshot_replication,
        ssh,
        user_home,
    )

    # Just confirm the placeholder modules exist; logic is TODO.
    for mod in (auth, network, packages, raid, server, shares,
                snapshot_replication, ssh, user_home):
        assert mod is not None
