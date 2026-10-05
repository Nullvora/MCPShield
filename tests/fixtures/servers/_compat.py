# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Run fixture servers on the official Python SDK v1 (FastMCP, initialize-era) or v2 (MCPServer, 2026-07-28)."""

from typing import Any, Optional

from mcp.server.transport_security import TransportSecuritySettings

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

    SDK_MAJOR = 1
except Exception:  # mcp 2.x renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as _Server  # type: ignore[no-redef]

    SDK_MAJOR = 2


class FixtureServer:
    def __init__(self, name: str, port: int, instructions: Optional[str] = None,
                 security: Optional[TransportSecuritySettings] = None):
        self.port = port
        self.security = security
        if SDK_MAJOR == 1:
            self.server: Any = _Server(name, instructions=instructions, host="127.0.0.1", port=port, transport_security=security)
        else:
            self.server = _Server(name, instructions=instructions)

    def run(self, http: bool) -> None:
        if not http:
            self.server.run("stdio")
        elif SDK_MAJOR == 1:
            self.server.run("streamable-http")
        else:
            self.server.run("streamable-http", host="127.0.0.1", port=self.port, transport_security=self.security)
