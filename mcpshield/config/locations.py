# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Well-known MCP configuration locations for popular AI clients (shadow-MCP discovery, OWASP MCP09)."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Location:
    client: str
    path: Path
    scope: str  # "user" | "project"


def _home() -> Path:
    return Path(os.environ.get("MCPSHIELD_HOME") or Path.home())


def user_locations(home: Path | None = None, platform: str | None = None) -> list[Location]:
    home = home or _home()
    platform = platform or sys.platform
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    locs: list[tuple[str, Path]] = []

    if platform == "darwin":
        support = home / "Library" / "Application Support"
        locs += [
            ("Claude Desktop", support / "Claude" / "claude_desktop_config.json"),
            ("VS Code", support / "Code" / "User" / "mcp.json"),
            ("VS Code", support / "Code" / "User" / "settings.json"),
            ("VS Code Insiders", support / "Code - Insiders" / "User" / "mcp.json"),
            ("Cline", support / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"),
        ]
    elif platform.startswith("win"):
        locs += [
            ("Claude Desktop", appdata / "Claude" / "claude_desktop_config.json"),
            ("VS Code", appdata / "Code" / "User" / "mcp.json"),
            ("VS Code", appdata / "Code" / "User" / "settings.json"),
            ("VS Code Insiders", appdata / "Code - Insiders" / "User" / "mcp.json"),
            ("Cline", appdata / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"),
        ]
    else:
        cfg = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        locs += [
            ("Claude Desktop", cfg / "Claude" / "claude_desktop_config.json"),
            ("VS Code", cfg / "Code" / "User" / "mcp.json"),
            ("VS Code", cfg / "Code" / "User" / "settings.json"),
            ("VS Code Insiders", cfg / "Code - Insiders" / "User" / "mcp.json"),
            ("Zed", cfg / "zed" / "settings.json"),
            ("Cline", cfg / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"),
        ]

    locs += [
        ("Claude Code", home / ".claude.json"),
        ("Claude Code", home / ".claude" / "settings.json"),
        ("Cursor", home / ".cursor" / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("Gemini CLI", home / ".gemini" / "settings.json"),
        ("Codex CLI", home / ".codex" / "config.toml"),
        ("Amazon Q", home / ".aws" / "amazonq" / "mcp.json"),
    ]
    return [Location(c, p, "user") for c, p in locs]


PROJECT_FILES: list[tuple[str, str]] = [
    ("Claude Code", ".mcp.json"),
    ("Claude Code", ".claude/settings.json"),
    ("Claude Code", ".claude/settings.local.json"),
    ("Cursor", ".cursor/mcp.json"),
    ("VS Code", ".vscode/mcp.json"),
    ("VS Code", ".vscode/settings.json"),
    ("Gemini CLI", ".gemini/settings.json"),
    ("Amazon Q", ".amazonq/mcp.json"),
    ("Generic", "mcp.json"),
    ("Generic", "mcp_config.json"),
]


def project_locations(root: Path) -> list[Location]:
    return [Location(c, root / rel, "project") for c, rel in PROJECT_FILES]


def discover(project_root: Path | None = None, include_user: bool = True) -> list[Location]:
    """Return existing configuration files on this machine / in this project."""
    candidates: list[Location] = []
    if include_user:
        candidates += user_locations()
    if project_root is not None:
        candidates += project_locations(project_root)
    seen: set[Path] = set()
    found: list[Location] = []
    for loc in candidates:
        try:
            resolved = loc.path.expanduser().resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_file():
            continue
        seen.add(resolved)
        found.append(Location(loc.client, resolved, loc.scope))
    return found
