# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
import json

import pytest

from mcpshield.config.loader import (
    extract_servers,
    is_env_reference,
    load_config_dict,
    load_config_file,
    load_json_lenient,
    parse_command_string,
)
from mcpshield.scanner import is_project_scope


def test_claude_desktop_format():
    servers, errors = extract_servers({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "pkg"], "env": {"A": "1"}}}}, "claude_desktop_config.json")
    assert not errors
    assert servers[0].transport == "stdio" and servers[0].client == "Claude Desktop"
    assert servers[0].command_line == ["npx", "-y", "pkg"]


def test_vscode_servers_map_with_types():
    data = {"servers": {"gh": {"type": "http", "url": "https://api.example.com/mcp"}, "old": {"type": "sse", "url": "https://x/sse"},
                        "local": {"type": "stdio", "command": "node", "args": ["s.js"]}}, "inputs": []}
    servers, _ = extract_servers(data, "/p/.vscode/mcp.json")
    kinds = {s.name: s.transport for s in servers}
    assert kinds == {"gh": "http", "old": "sse", "local": "stdio"}
    assert servers[0].client == "VS Code"


def test_vscode_settings_nested_mcp():
    servers, _ = extract_servers({"mcp": {"servers": {"a": {"command": "x"}}}}, "settings.json")
    assert [s.name for s in servers] == ["a"]


def test_zed_context_servers():
    data = {"context_servers": {"z": {"command": {"path": "/usr/bin/zs", "args": ["--x"], "env": {"K": "v"}}}}}
    s = extract_servers(data, "/home/u/.config/zed/settings.json")[0][0]
    assert s.command == "/usr/bin/zs" and s.args == ["--x"] and s.env == {"K": "v"}


def test_windsurf_and_gemini_url_keys():
    s1 = extract_servers({"mcpServers": {"w": {"serverUrl": "https://w.example/mcp"}}}, "mcp_config.json")[0][0]
    s2 = extract_servers({"mcpServers": {"g": {"httpUrl": "https://g.example/mcp"}}}, ".gemini/settings.json")[0][0]
    s3 = extract_servers({"mcpServers": {"s": {"url": "https://s.example/sse"}}}, "x.json")[0][0]
    assert (s1.transport, s2.transport, s3.transport) == ("http", "http", "sse")


def test_claude_code_projects():
    data = {"mcpServers": {"g": {"command": "a"}}, "projects": {"/home/u/app": {"mcpServers": {"p": {"type": "http", "url": "https://p/mcp"}}}}}
    names = sorted(s.name for s in extract_servers(data, "/home/u/.claude.json")[0])
    assert names == ["app/p", "g"]


def test_codex_toml(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp@1.0.0"]\n\n[mcp_servers.remote]\nurl = "https://r.example/mcp"\nbearer_token_env_var = "R_TOKEN"\n')
    cfg = load_config_file(p)
    by = {s.name: s for s in cfg.servers}
    assert by["docs"].transport == "stdio" and by["remote"].transport == "http"
    assert by["remote"].headers["Authorization"] == "Bearer ${R_TOKEN}"


def test_jsonc_comments_and_trailing_commas():
    text = '{\n // comment with "quotes"\n "mcpServers": {"a": {"command": "x", "args": ["http://keep//this"],},}, /* block */\n}'
    data = load_json_lenient(text)
    assert data["mcpServers"]["a"]["args"] == ["http://keep//this"]


def test_bad_entries_are_reported_not_fatal():
    cfg = load_config_dict({"mcpServers": {"ok": {"command": "x"}, "bad": {"foo": 1}, "worse": "str"}})
    assert [s.name for s in cfg.servers] == ["ok"]
    assert len(cfg.errors) == 2


def test_single_server_object():
    servers, _ = extract_servers({"command": "python", "args": ["-m", "srv"]})
    assert servers[0].name == "default"


def test_disabled_flag():
    s = extract_servers({"mcpServers": {"a": {"command": "x", "disabled": True}}})[0][0]
    assert s.disabled


@pytest.mark.parametrize("value,expected", [
    ("${GITHUB_TOKEN}", True), ("${env:API_KEY}", True), ("${input:token}", True), ("Bearer ${TOKEN}", True),
    ("$HOME", True), ("%APPDATA%", True), ("ghp_realtoken", False), ("", False), ("prefix-${X}", False),
])
def test_env_reference(value, expected):
    assert is_env_reference(value) is expected


def test_parse_command_string():
    assert parse_command_string('npx -y "my pkg"') == ("npx", ["-y", "my pkg"])


def test_project_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    repo = tmp_path / "repo"
    (repo / ".claude").mkdir(parents=True)
    assert is_project_scope(str(repo / ".mcp.json"))
    assert is_project_scope(str(repo / ".claude" / "settings.json"))
    assert not is_project_scope(str(tmp_path / "home" / ".claude" / "settings.json"))


def test_serialisation_never_includes_secret_values():
    s = extract_servers({"mcpServers": {"a": {"command": "x", "env": {"TOKEN": "supersecretvalue"}}}})[0][0]
    assert "supersecretvalue" not in json.dumps(s.to_dict())
