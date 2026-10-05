# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"
SERVERS = FIXTURES / "servers"


def _has_mcp() -> bool:
    try:
        import mcp.server.transport_security  # noqa: F401
        return True
    except Exception:
        return False


HAS_MCP = _has_mcp()
requires_mcp = pytest.mark.skipif(not HAS_MCP, reason="official 'mcp' SDK not installed (pip install -e .[dev])")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def http_server():
    """Start a fixture server over Streamable HTTP; yields a factory returning the URL."""
    procs = []

    def start(script: str) -> str:
        port = free_port()
        p = subprocess.Popen([sys.executable, str(SERVERS / script), "http", str(port)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return f"http://127.0.0.1:{port}/mcp"
            except OSError:
                time.sleep(0.2)
        raise RuntimeError(f"{script} did not start")

    yield start
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


@pytest.fixture(autouse=True)
def local_network_only(monkeypatch):
    """Local fixture traffic must not depend on a developer's HTTP proxy."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
