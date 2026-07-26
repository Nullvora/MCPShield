"""
MCPShield — MCP configuration parser.

Understands three config formats:
  1. Claude Desktop  — {"mcpServers": {"name": {"command": ..., "args": ...}}}
  2. Raw server list — {"servers": [...]}
  3. Direct object   — {"command": ...} or {"url": ...}
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# ── Patterns that suggest credential leakage ────────────────────────────────
_CREDENTIAL_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?'),
    re.compile(r'(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{8,})["\']?'),
    re.compile(r'(?i)(aws_access_key_id)\s*[:=]\s*([A-Z0-9]{20})'),
    re.compile(r'(?i)(aws_secret_access_key)\s*[:=]\s*([A-Za-z0-9/+=]{40})'),
    re.compile(r'(?i)(sk-[a-zA-Z0-9]{32,})'),   # OpenAI / Anthropic key shape
    re.compile(r'(?i)(gh[pousr]_[A-Za-z0-9_]{36,})'),  # GitHub tokens
]

# ── Known vulnerable SDK package identifiers ────────────────────────────────
VULNERABLE_PACKAGES = {
    "@anthropic-ai/mcp": {
        "vulnerable_below": "1.3.1",
        "cves": ["CVE-2025-49596"],
        "description": "RCE via STDIO transport in official Anthropic MCP SDK",
    },
    "@modelcontextprotocol/sdk": {
        "vulnerable_below": "1.3.1",
        "cves": ["CVE-2026-22252"],
        "description": "Arbitrary command execution in TypeScript MCP SDK",
    },
    "mcp": {
        "vulnerable_below": "1.3.1",
        "cves": ["CVE-2025-49596"],
        "description": "RCE in Python MCP SDK transport layer",
    },
}

# ── High-risk STDIO commands ─────────────────────────────────────────────────
RISKY_COMMANDS = {
    "bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh",
    "python", "python3", "node", "ruby", "perl", "php",
}


@dataclass
class MCPServerConfig:
    """Normalised representation of a single MCP server entry."""

    name: str
    transport: str                          # "stdio" | "http" | "sse" | "unknown"
    command: str | None = None           # STDIO: the executable
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None              # HTTP/SSE URL
    headers: dict[str, str] = field(default_factory=dict)
    tls: bool = False
    raw: dict = field(default_factory=dict) # original dict for reference

    # ── derived helpers ──────────────────────────────────────────────────────

    @property
    def has_authentication(self) -> bool:
        if self.transport in ("http", "sse"):
            auth_headers = {k.lower() for k in self.headers}
            return "authorization" in auth_headers or "x-api-key" in auth_headers
        return False  # STDIO has no auth layer by definition

    @property
    def exposed_credentials(self) -> list[tuple[str, str]]:
        """Returns (key_name, redacted_value) pairs for suspected credentials."""
        found = []
        for k, v in self.env.items():
            for pattern in _CREDENTIAL_PATTERNS:
                if pattern.search(f"{k}={v}"):
                    found.append((k, v[:4] + "****" + v[-2:] if len(v) > 6 else "****"))
                    break
        return found

    @property
    def package_names(self) -> list[str]:
        """Best-effort extraction of npm package names from args."""
        packages = []
        for arg in self.args:
            if arg.startswith("@") or "/" not in arg and arg.startswith("mcp"):
                packages.append(arg)
            # npx -y @scope/package
            if arg.startswith("@") and "/" in arg:
                packages.append(arg.split()[0])
        return packages

    @property
    def uses_risky_command(self) -> bool:
        if self.command:
            return Path(self.command).stem.lower() in RISKY_COMMANDS
        return False


@dataclass
class MCPConfig:
    """Parsed and normalised MCP configuration."""

    source_path: str | None
    servers: list[MCPServerConfig]
    raw: dict = field(default_factory=dict)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def server_count(self) -> int:
        return len(self.servers)

    @property
    def stdio_servers(self) -> list[MCPServerConfig]:
        return [s for s in self.servers if s.transport == "stdio"]

    @property
    def http_servers(self) -> list[MCPServerConfig]:
        return [s for s in self.servers if s.transport in ("http", "sse")]


# ── Parser ───────────────────────────────────────────────────────────────────

def parse_config_file(path: str) -> MCPConfig:
    """Load and parse an MCP config file from disk."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(p) as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in config file: {exc}")

    return _parse_raw(raw, source_path=str(p))


def parse_config_dict(data: dict, source: str = "<dict>") -> MCPConfig:
    """Parse an already-loaded config dict."""
    return _parse_raw(data, source_path=source)


def _parse_raw(raw: dict, source_path: str | None) -> MCPConfig:
    servers: list[MCPServerConfig] = []
    errors: list[str] = []

    # Format 1 — Claude Desktop style
    if "mcpServers" in raw:
        for name, cfg in raw["mcpServers"].items():
            try:
                servers.append(_parse_server_entry(name, cfg))
            except Exception as exc:
                errors.append(f"[{name}] {exc}")

    # Format 2 — servers list
    elif "servers" in raw and isinstance(raw["servers"], list):
        for i, cfg in enumerate(raw["servers"]):
            name = cfg.get("name", f"server_{i}")
            try:
                servers.append(_parse_server_entry(name, cfg))
            except Exception as exc:
                errors.append(f"[{name}] {exc}")

    # Format 3 — single server object
    elif "command" in raw or "url" in raw:
        try:
            servers.append(_parse_server_entry("default", raw))
        except Exception as exc:
            errors.append(f"[default] {exc}")

    else:
        errors.append("Unrecognised config format — expected mcpServers, servers[], or direct object")

    return MCPConfig(
        source_path=source_path,
        servers=servers,
        raw=raw,
        parse_errors=errors,
    )


def _parse_server_entry(name: str, cfg: dict) -> MCPServerConfig:
    """Normalise a single server entry regardless of transport."""

    # STDIO transport
    if "command" in cfg:
        url = cfg.get("url")
        tls = url.startswith("https") if url else False
        return MCPServerConfig(
            name=name,
            transport="stdio",
            command=cfg.get("command"),
            args=cfg.get("args", []),
            env=cfg.get("env", {}),
            url=url,
            tls=tls,
            raw=cfg,
        )

    # HTTP / SSE transport
    if "url" in cfg:
        url: str = cfg["url"]
        tls = url.startswith("https://")
        transport = "sse" if "sse" in url.lower() else "http"
        return MCPServerConfig(
            name=name,
            transport=transport,
            url=url,
            headers=cfg.get("headers", {}),
            tls=tls,
            raw=cfg,
        )

    raise ValueError("Cannot determine transport — no 'command' or 'url' key found")
