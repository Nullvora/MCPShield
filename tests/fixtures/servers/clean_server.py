# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""A well-behaved MCP server (official Python SDK) used as a negative control in tests.

    python clean_server.py              # stdio
    python clean_server.py http 8766    # Streamable HTTP with DNS-rebinding protection enabled
"""

import sys

from _compat import FixtureServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

port = int(sys.argv[2]) if len(sys.argv) > 2 else 8766
fixture = FixtureServer(
    "clean-calculator", port,
    security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[f"127.0.0.1:{port}", f"localhost:{port}"],
        allowed_origins=[f"http://127.0.0.1:{port}", f"http://localhost:{port}"],
    ),
)
mcp = fixture.server


@mcp.tool(description="Add two integers and return the sum.", annotations=ToolAnnotations(readOnlyHint=True))
def add(a: int, b: int) -> int:
    return a + b


@mcp.tool(description="Multiply two integers and return the product.", annotations=ToolAnnotations(readOnlyHint=True))
def multiply(a: int, b: int) -> int:
    return a * b


if __name__ == "__main__":
    fixture.run(http=len(sys.argv) > 1 and sys.argv[1] == "http")
