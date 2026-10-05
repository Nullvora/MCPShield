# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Load and normalise MCP client configuration files.

Supported formats (auto-detected):

* ``mcpServers`` maps — Claude Desktop, Claude Code (``.mcp.json``), Cursor, Windsurf, Gemini CLI, Cline
* ``servers`` maps — VS Code ``mcp.json`` (and ``"mcp": {"servers": …}`` inside ``settings.json``)
* ``servers`` lists — generic ``[{"name": …}, …]``
* ``context_servers`` — Zed
* ``[mcp_servers.<name>]`` tables — OpenAI Codex CLI ``config.toml``
* ``~/.claude.json`` — Claude Code global + per-project ``mcpServers``
* a single bare server object (``{"command": …}`` / ``{"url": …}``)

JSON files may contain comments and trailing commas (JSONC), as VS Code and Zed allow.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from mcpshield.models import ServerSpec


@dataclass
class LoadedConfig:
    path: str
    client: str
    data: Any
    servers: list[ServerSpec] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- JSONC


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, respecting string literals."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        out.append(ch)
        i += 1
    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def load_json_lenient(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(_strip_jsonc(text))


def _load_toml(text: str) -> Any:
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError as exc:
            raise ValueError("TOML config requires Python 3.11+ or the 'tomli' package") from exc
    return tomllib.loads(text)


# --------------------------------------------------------------------------- client detection


def guess_client(path: str) -> str:
    p = path.replace("\\", "/").lower()
    if "claude_desktop_config" in p:
        return "Claude Desktop"
    if p.endswith("/.claude.json") or "/.claude/" in p or p.endswith(".mcp.json"):
        return "Claude Code"
    if "/.cursor/" in p:
        return "Cursor"
    if "windsurf" in p or "codeium" in p:
        return "Windsurf"
    if "/.gemini/" in p:
        return "Gemini CLI"
    if "/.codex/" in p or p.endswith("config.toml"):
        return "Codex CLI"
    if "/zed/" in p:
        return "Zed"
    if "/.vscode/" in p or "/code/user/" in p or "/code - insiders/" in p:
        return "VS Code"
    if "cline" in p:
        return "Cline"
    return "Generic"


# --------------------------------------------------------------------------- normalisation

_HTTP_TYPES = {"http", "streamable-http", "streamablehttp", "streamable_http", "https"}


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _as_str_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): "" if v is None else str(v) for k, v in value.items()}


def normalise_server(name: str, cfg: Any, source: str = "", client: str = "") -> ServerSpec:
    """Turn any known server-entry shape into a :class:`ServerSpec`."""
    if not isinstance(cfg, dict):
        raise ValueError("server entry is not an object")

    declared = str(cfg.get("type") or cfg.get("transport") or "").strip().lower()
    url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl") or cfg.get("endpoint")

    command = cfg.get("command")
    args = _as_str_list(cfg.get("args"))
    env = _as_str_dict(cfg.get("env"))
    # Zed: {"command": {"path": "...", "args": [...], "env": {...}}}
    if isinstance(command, dict):
        args = _as_str_list(command.get("args")) or args
        env = _as_str_dict(command.get("env")) or env
        command = command.get("path") or command.get("command")
    # Some clients put the whole command line in one string
    if isinstance(command, list):
        parts = [str(c) for c in command]
        command, args = (parts[0] if parts else None), parts[1:] + args

    headers = _as_str_dict(cfg.get("headers") or cfg.get("http_headers"))
    if cfg.get("bearer_token_env_var"):   # Codex CLI
        headers.setdefault("Authorization", "Bearer ${" + str(cfg["bearer_token_env_var"]) + "}")

    disabled = bool(cfg.get("disabled")) or cfg.get("enabled") is False

    if declared in ("stdio", "local") or (command and not url):
        transport = "stdio"
    elif declared == "sse":
        transport = "sse"
    elif declared in _HTTP_TYPES or url:
        transport = "http"
        if cfg.get("httpUrl"):
            transport = "http"
        elif isinstance(url, str) and re.search(r"/sse/?(\?|$)", url) and declared not in _HTTP_TYPES:
            transport = "sse"
    else:
        transport = "unknown"

    if transport == "unknown":
        raise ValueError("cannot determine transport (no 'command' or 'url')")
    if transport == "stdio" and not command:
        raise ValueError("stdio server has no 'command'")
    if transport in ("http", "sse") and not url:
        raise ValueError(f"{transport} server has no 'url'")

    return ServerSpec(
        name=str(name),
        transport=transport,
        source=source,
        client=client,
        command=str(command) if command else None,
        args=args,
        env=env,
        url=str(url) if url else None,
        headers=headers,
        disabled=disabled,
        raw=cfg,
    )


def _servers_from_map(mapping: Any, source: str, client: str, errors: list[str], prefix: str = "") -> list[ServerSpec]:
    servers: list[ServerSpec] = []
    if isinstance(mapping, dict):
        items = list(mapping.items())
    elif isinstance(mapping, list):
        items = [(e.get("name", f"server_{i}") if isinstance(e, dict) else f"server_{i}", e) for i, e in enumerate(mapping)]
    else:
        errors.append(f"{source}: server collection has unexpected type {type(mapping).__name__}")
        return servers
    for name, entry in items:
        label = f"{prefix}{name}"
        try:
            servers.append(normalise_server(label, entry, source, client))
        except Exception as exc:  # noqa: BLE001 - report and continue
            errors.append(f"{source}: [{label}] {exc}")
    return servers


def extract_servers(data: Any, source: str = "<memory>", client: str = "") -> tuple[list[ServerSpec], list[str]]:
    errors: list[str] = []
    servers: list[ServerSpec] = []
    client = client or guess_client(source)
    if not isinstance(data, dict):
        return servers, [f"{source}: top-level JSON value is not an object"]

    found_any = False
    if "mcpServers" in data:
        found_any = True
        servers += _servers_from_map(data["mcpServers"], source, client, errors)
    if isinstance(data.get("servers"), (dict, list)):
        found_any = True
        servers += _servers_from_map(data["servers"], source, client, errors)
    if isinstance(data.get("mcp"), dict) and isinstance(data["mcp"].get("servers"), (dict, list)):
        found_any = True
        servers += _servers_from_map(data["mcp"]["servers"], source, client, errors)
    if "context_servers" in data:
        found_any = True
        servers += _servers_from_map(data["context_servers"], source, client, errors)
    if isinstance(data.get("mcp_servers"), dict):  # Codex CLI TOML
        found_any = True
        servers += _servers_from_map(data["mcp_servers"], source, client, errors)
    # Claude Code ~/.claude.json keeps per-project servers
    if isinstance(data.get("projects"), dict):
        for proj, pdata in data["projects"].items():
            if isinstance(pdata, dict) and pdata.get("mcpServers"):
                found_any = True
                servers += _servers_from_map(pdata["mcpServers"], source, client, errors, prefix=f"{Path(proj).name}/")
    if not found_any and ("command" in data or "url" in data or "serverUrl" in data):
        found_any = True
        try:
            servers.append(normalise_server(data.get("name", "default"), data, source, client))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{source}: {exc}")
    return servers, errors


def load_config_file(path: str | Path) -> LoadedConfig:
    p = Path(path).expanduser()
    text = p.read_text(encoding="utf-8-sig")
    source = str(p)
    client = guess_client(source)
    if p.suffix.lower() == ".toml":
        data = _load_toml(text)
    else:
        try:
            data = load_json_lenient(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}: invalid JSON ({exc})") from exc
    servers, errors = extract_servers(data, source, client)
    return LoadedConfig(path=source, client=client, data=data, servers=servers, errors=errors)


def load_config_dict(data: dict[str, Any], source: str = "<memory>", client: str = "") -> LoadedConfig:
    servers, errors = extract_servers(data, source, client)
    return LoadedConfig(path=source, client=client or guess_client(source), data=data, servers=servers, errors=errors)


def parse_command_string(command: str) -> tuple[str, list[str]]:
    """Split a command line into executable + args (used for --stdio targets)."""
    import sys
    import shlex

    if not command.strip():
        raise ValueError("empty command")
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        shell = ctypes.WinDLL("shell32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        split = shell.CommandLineToArgvW
        split.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        split.restype = ctypes.POINTER(wintypes.LPWSTR)
        kernel.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel.LocalFree.restype = wintypes.HLOCAL
        count = ctypes.c_int()
        argv = split(command.lstrip(), ctypes.byref(count))
        if not argv:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            parts = [argv[i] for i in range(count.value)]
        finally:
            kernel.LocalFree(ctypes.cast(argv, wintypes.HLOCAL))
    else:
        parts = shlex.split(command, posix=True)
    if not parts:
        raise ValueError("empty command")
    return parts[0], parts[1:]


def is_env_reference(value: Optional[str]) -> bool:
    """True when a value is a variable/input reference rather than a literal (e.g. ${API_KEY}, ${env:X}, ${input:y})."""
    if not value:
        return False
    v = value.strip()
    return bool(re.fullmatch(r"(Bearer\s+|Token\s+|Basic\s+)?(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)", v))
