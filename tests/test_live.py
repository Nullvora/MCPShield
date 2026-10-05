# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""End-to-end tests against real MCP server processes (official Python SDK + a 2026-07-28 fixture)."""

import json
import os
import subprocess
import sys

import pytest
from click.testing import CliRunner

from conftest import SERVERS, requires_mcp
from mcpshield.cli import cli
from mcpshield.live.inspect import inspect_server
from mcpshield.models import ServerSpec
from mcpshield.scanner import ScanOptions, run_scan

pytestmark = pytest.mark.live
PY = sys.executable
try:
    from importlib.metadata import version as _v
    SDK_MAJOR = int(_v("mcp").split(".")[0])
except Exception:
    SDK_MAJOR = 0


def stdio(script, *args, name=None, env=None):
    return ServerSpec(name=name or script, transport="stdio", command=PY, args=[str(SERVERS / script), *args], env=env or {})


# --------------------------------------------------------------------------- protocol eras (no SDK needed)


@pytest.mark.parametrize("mode,era", [("--dual", "modern"), ("--modern", "modern"), ("--legacy", "legacy"), ("--crash-on-unknown", "legacy")])
def test_dual_era_negotiation(mode, era):
    inv = inspect_server(stdio("modern_server.py", mode), timeout=10)
    assert not inv.errors, inv.errors
    assert inv.era == era
    assert [t["name"] for t in inv.tools] == ["echo", "query_region"]


def test_force_legacy_against_modern_only_server_fails_cleanly():
    inv = inspect_server(stdio("modern_server.py", "--modern"), timeout=10, prefer="legacy")
    assert inv.errors and not inv.tools


def test_modern_server_x_mcp_header_finding():
    r = run_scan([], [stdio("modern_server.py", "--modern")], ScanOptions(live=True, timeout=10))
    assert "MCPS-TOOL-011" in {f.rule_id for f in r.findings}
    assert not any(f.rule_id == "MCPS-CAP-002" for f in r.findings)


def test_pin_and_verify_detects_rug_pull(tmp_path):
    lock = tmp_path / "mcpshield.lock"
    runner = CliRunner()
    cmd = f"{PY} {SERVERS / 'modern_server.py'}"
    assert runner.invoke(cli, ["pin", "--stdio", cmd, "--lock", str(lock)]).exit_code == 0
    assert runner.invoke(cli, ["verify", "--stdio", cmd, "--lock", str(lock)]).exit_code == 0
    os.environ["RUGPULL"] = "1"
    try:
        r = runner.invoke(cli, ["verify", "--stdio", cmd, "--lock", str(lock)])
    finally:
        del os.environ["RUGPULL"]
    assert r.exit_code == 1 and "changed since it was pinned" in r.output


def test_unreachable_server_reports_error():
    inv = inspect_server(ServerSpec(name="nope", transport="stdio", command="definitely-not-a-real-binary-xyz"), timeout=5)
    assert inv.errors and not inv.tools


# --------------------------------------------------------------------------- official SDK servers


@requires_mcp
def test_poisoned_stdio_server_detected():
    r = run_scan([], [stdio("poisoned_server.py", name="poison")], ScanOptions(live=True, timeout=20))
    rules = {f.rule_id for f in r.findings}
    assert {"MCPS-TOOL-001", "MCPS-TOOL-002", "MCPS-TOOL-003", "MCPS-TOOL-004", "MCPS-TOOL-008", "MCPS-TOOL-012",
            "MCPS-TOOL-014", "MCPS-TOOL-015"} <= rules
    assert r.grade == "F"


@requires_mcp
def test_clean_stdio_server_has_no_significant_findings():
    r = run_scan([], [stdio("clean_server.py", name="clean")], ScanOptions(live=True, timeout=20))
    assert [f.rule_id for f in r.findings if f.severity.rank >= 2] == []


@requires_mcp
def test_http_probes_distinguish_origin_validation(http_server):
    bad = http_server("poisoned_server.py")
    good = http_server("clean_server.py")
    r = run_scan([], [ServerSpec(name="bad", transport="http", url=bad), ServerSpec(name="good", transport="http", url=good)],
                 ScanOptions(live=True, timeout=20))
    origin = {f.server for f in r.findings if f.rule_id == "MCPS-HTTP-002"}
    assert origin == {"bad"}
    anon = {f.server for f in r.findings if f.rule_id == "MCPS-HTTP-001"}
    assert anon == {"bad", "good"}
    inv = {i.name: i for i in r.inventories}
    assert len(inv["bad"].tools) == 7
    assert inv["good"].era == ("modern" if SDK_MAJOR >= 2 else "legacy")   # SDK v2 speaks MCP 2026-07-28


@requires_mcp
def test_proxy_end_to_end(tmp_path):
    log = tmp_path / "audit.jsonl"
    p = subprocess.Popen([PY, "-m", "mcpshield", "proxy", "--audit-log", str(log), "--name", "poison", "--",
                          PY, str(SERVERS / "poisoned_server.py")],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

    def rpc(i, method, params=None):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n")
        p.stdin.flush()
        while True:
            m = json.loads(p.stdout.readline())
            if m.get("id") == i:
                return m

    try:
        rpc(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}})
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        p.stdin.flush()
        names = {t["name"] for t in rpc(2, "tools/list")["result"]["tools"]}
        assert names == {"delete_file", "run_command", "fetch_url"}
        blocked = rpc(3, "tools/call", {"name": "fetch_url", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}})
        assert blocked["result"]["isError"]
        allowed = rpc(4, "tools/call", {"name": "fetch_url", "arguments": {"url": "https://example.com"}})
        assert allowed["result"]["isError"] is False
    finally:
        p.stdin.close()
        p.wait(timeout=10)
    r = CliRunner().invoke(cli, ["audit", "verify", str(log)])
    assert r.exit_code == 0
    events = [json.loads(line)["event"] for line in log.read_text().splitlines()]
    assert events[0] == "proxy_start" and events[-1] == "proxy_stop" and "tool_hidden" in events
