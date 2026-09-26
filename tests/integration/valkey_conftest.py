"""P0.7 integration fixtures — a real Valkey (Redis-protocol) via testcontainers.

Complements the PostgreSQL session fixture (tests/integration/conftest.py):
the relay integration tier needs BOTH a real PostgreSQL 17 and a real
Valkey (§51.1: testcontainers, no stand-ins; App. A: Valkey 8.x).

This module is named ``valkey_conftest`` (not ``conftest``) because pytest
collects ``conftest.py`` files only; the relay test module imports the
fixtures from here explicitly, keeping the existing PostgreSQL conftest
untouched (no relocation of existing infrastructure — P0.7.1 boundary rule).
"""

from __future__ import annotations

import pytest

VALKEY_IMAGE = "valkey/valkey:8"


def _docker_available() -> bool:
    import subprocess

    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


@pytest.fixture(scope="session")
def valkey_url():
    """A real Valkey 8 container; skip the tier transparently without Docker."""
    if not _docker_available():
        pytest.skip(
            "Docker is not available in this environment — relay integration "
            "tier skipped (local-environment limitation, not a test failure)."
        )
    from testcontainers.redis import RedisContainer

    # testcontainers' RedisContainer supports Redis-protocol servers; Valkey
    # speaks the same protocol (App. A / OQ-12). Image is pinned to Valkey.
    with RedisContainer(image=VALKEY_IMAGE) as rc:
        host = rc.get_container_host_ip()
        port = rc.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"
