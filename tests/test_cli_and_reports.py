# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
import json

from click.testing import CliRunner

from mcpshield import __version__
from mcpshield.cli import cli
from mcpshield.models import Finding, ScanResult, ServerSpec, Severity
from mcpshield.reporting.html import to_html
from mcpshield.reporting.markdown import to_markdown
from mcpshield.reporting.sarif import to_sarif


def run(*args):
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def test_version():
    r = run("--version")
    assert r.exit_code == 0 and __version__ in r.output


def test_scan_vulnerable_exits_1_and_json(fixtures, tmp_path):
    out = tmp_path / "r.json"
    r = run("scan", str(fixtures / "vulnerable_config.json"), "--json", str(out), "-q")
    assert r.exit_code == 1
    data = json.loads(out.read_text())
    assert data["summary"]["grade"] == "F"
    assert data["summary"]["counts"]["critical"] >= 3
    assert "ghp_1234567890" not in out.read_text()


def test_scan_secure_passes(fixtures):
    r = run("scan", str(fixtures / "secure_config.json"), "-q")
    assert r.exit_code == 0


def test_fail_on_threshold(fixtures):
    assert run("scan", str(fixtures / "vulnerable_config.json"), "-q", "--fail-on", "none").exit_code == 0


def test_json_to_stdout(fixtures):
    r = run("scan", str(fixtures / "secure_config.json"), "--json", "-")
    assert json.loads(r.output)["tool"] == "mcpshield"


def test_all_report_formats(fixtures, tmp_path):
    r = run("scan", str(fixtures / "vulnerable_config.json"), "-q", "--fail-on", "none",
            "--sarif", str(tmp_path / "r.sarif"), "--html", str(tmp_path / "r.html"), "--markdown", str(tmp_path / "r.md"))
    assert r.exit_code == 0
    sarif = json.loads((tmp_path / "r.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    first = sarif["runs"][0]["results"][0]
    assert first["locations"][0]["physicalLocation"]["region"]["startLine"] > 1
    assert "<html" in (tmp_path / "r.html").read_text()
    assert "| Severity |" in (tmp_path / "r.md").read_text()


def test_baseline_roundtrip(fixtures, tmp_path):
    b = tmp_path / "baseline.json"
    assert run("scan", str(fixtures / "vulnerable_config.json"), "--write-baseline", str(b)).exit_code == 0
    r = run("scan", str(fixtures / "vulnerable_config.json"), "-q", "--baseline", str(b))
    assert r.exit_code == 0


def test_allowlist_option(fixtures, tmp_path):
    allow = tmp_path / "allow.yaml"
    allow.write_text("servers: [filesystem]\n")
    out = tmp_path / "r.json"
    run("scan", str(fixtures / "secure_config.json"), "--allowlist", str(allow), "--json", str(out), "-q", "--fail-on", "none")
    shadow = [f["server"] for f in json.loads(out.read_text())["findings"] if f["rule_id"] == "MCPS-SHD-001"]
    assert sorted(shadow) == ["github", "time"]


def test_nothing_to_scan():
    assert run("scan").exit_code == 2


def test_rules_outputs():
    assert "MCPS-TOOL-001" in run("rules").output
    rules = json.loads(run("rules", "--json").output)
    assert len({r["id"] for r in rules}) == len(rules) >= 50
    assert run("rules", "--markdown").output.startswith("# MCPShield rule catalogue")


def test_init_policy_and_wrap(tmp_path, fixtures):
    pol = tmp_path / "p.yaml"
    assert run("init-policy", str(pol)).exit_code == 0 and pol.exists()
    cfg = tmp_path / "c.json"
    cfg.write_text((fixtures / "secure_config.json").read_text())
    r = run("wrap", str(cfg), "--policy", str(pol), "--write")
    assert r.exit_code == 0
    data = json.loads(cfg.read_text())
    fs = data["mcpServers"]["filesystem"]
    assert fs["args"][0] == "proxy" and "--" in fs["args"] and fs["args"][-1] == "/Users/dev/projects/app"
    assert data["mcpServers"]["github"]["type"] == "http"          # remote servers untouched
    assert (tmp_path / "c.json.bak").exists()


def test_discover_with_fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text('{"mcpServers": {"c": {"command": "npx", "args": ["x@1.0.0"]}}}')
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".mcp.json").write_text('{"mcpServers": {"p": {"type": "http", "url": "https://p.example/mcp"}}}')
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MCPSHIELD_HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    rows = json.loads(run("discover", "--project", str(proj), "--json").output)
    names = sorted(s["name"] for r in rows for s in r["servers"])
    assert names == ["c", "p"]


def test_audit_verify_cli(tmp_path):
    from mcpshield.auditlog import AuditLog
    p = tmp_path / "a.jsonl"
    AuditLog(p, key=b"").write("x")
    assert run("audit", "verify", str(p)).exit_code == 0


def test_html_escapes_everything():
    payload = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    r = ScanResult(servers=[ServerSpec(name=payload, transport="stdio", command=payload)])
    r.add(Finding("MCPS-TOOL-001", payload, Severity.CRITICAL, payload, payload, server=payload, evidence=payload))
    html = to_html(r)
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "default-src 'none'" in html


def test_markdown_escapes_pipes():
    r = ScanResult()
    r.add(Finding("MCPS-SEC-001", "a|b", Severity.HIGH, "d", "fix", server="s|x", evidence="e|v"))
    assert "a\\|b" in to_markdown(r)


def test_sarif_without_file_locations():
    r = ScanResult()
    r.add(Finding("MCPS-HTTP-001", "t", Severity.HIGH, "d", "r", server="remote", location="https://x/mcp"))
    res = to_sarif(r)["runs"][0]["results"][0]
    assert "locations" not in res and res["level"] == "error"


def test_risk_score_monotonic():
    r = ScanResult()
    assert (r.risk_score, r.grade) == (0, "A")
    r.add(Finding("MCPS-SUP-001", "t", Severity.MEDIUM, "d", "r", server="a"))
    s1 = r.risk_score
    r.add(Finding("MCPS-SUP-001", "t2", Severity.MEDIUM, "d", "r", server="b"))
    assert r.risk_score >= s1
    r.add(Finding("MCPS-SUP-003", "t", Severity.CRITICAL, "d", "r", server="c"))
    assert r.risk_score >= 75 and r.grade == "F"
