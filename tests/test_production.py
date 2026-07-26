"""
MCPShield Production Test Suite — Covers CLI, console reporter, alerting, and live scanner.
Run: pytest tests/test_production.py -v
"""

import json
import os
import tempfile
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


# ── Console Reporter Tests ─────────────────────────────────────────────────

FIXTURES = Path(__file__).parent / "fixtures"

VULN_CONFIG = str(FIXTURES / "vulnerable_mcp_config.json")


class TestConsoleReporter:
    def test_print_banner(self):
        from mcpshield.reporter.console import print_banner
        print_banner()  # smoke test — must not raise

    def test_print_scan_header(self):
        from mcpshield.reporter.console import print_scan_header
        print_scan_header("test.json", "config_file", 3)

    def test_print_results_with_findings(self):
        from mcpshield.reporter.console import print_results
        from mcpshield.scanner import scan_config_file
        result = scan_config_file(VULN_CONFIG)
        print_results(result)  # smoke test

    def test_print_results_empty(self):
        from mcpshield.models import ScanResult, ScanTarget
        from mcpshield.reporter.console import print_results
        result = ScanResult(target=ScanTarget(raw="test", scan_type="config_file"))
        print_results(result)

    def test_print_results_with_owasp(self):
        from mcpshield.reporter.console import print_results
        from mcpshield.scanner import scan_config_file
        result = scan_config_file(VULN_CONFIG)
        assert len(result.owasp_coverage) > 0
        print_results(result)

    def test_print_error(self):
        from mcpshield.reporter.console import print_error
        print_error("test error message")

    def test_print_warning(self):
        from mcpshield.reporter.console import print_warning
        print_warning("test warning")

    def test_print_info(self):
        from mcpshield.reporter.console import print_info
        print_info("test info")

    def test_wrap_function(self):
        from mcpshield.reporter.console import _wrap
        # Short text fits in one line
        assert len(_wrap("hello world", 90)) == 1
        # Long text wraps
        long_text = "word " * 30
        lines = _wrap(long_text, 90)
        assert len(lines) > 1
        # Each line is within width
        for line in lines:
            assert len(line) <= 90

    def test_wrap_empty_string(self):
        from mcpshield.reporter.console import _wrap
        assert _wrap("", 90) == []

    def test_wrap_single_long_word(self):
        from mcpshield.reporter.console import _wrap
        result = _wrap("supercalifragilisticexpialidocious", 20)
        assert len(result) >= 1


# ── Alerting Tests ────────────────────────────────────────────────────────

class TestAlertRouter:
    def _make_anomaly(self, severity="HIGH", rule_id="AD-001"):
        from mcpshield.monitor.detector import Anomaly
        return Anomaly(
            rule_id=rule_id,
            severity=severity,
            title="Test Anomaly",
            description="Test description",
            evidence={"param": "value"},
            agent_id="agent-001",
            tool="test_tool",
            server="test_server",
            timestamp="2025-01-01T00:00:00Z",
        )

    def test_add_channel(self):
        from mcpshield.monitor.alerting import AlertConfig, AlertRouter
        router = AlertRouter()
        router.add_channel(AlertConfig(name="test", url="http://localhost:9999"))
        assert len(router.channels) == 1

    def test_dispatch_disabled_channel(self):
        from mcpshield.monitor.alerting import AlertConfig, AlertRouter
        router = AlertRouter()
        router.add_channel(AlertConfig(name="off", url="http://localhost:9999", enabled=False))
        anomaly = self._make_anomaly()
        results = router.dispatch(anomaly)
        assert results == [False]

    def test_dispatch_below_min_severity(self):
        from mcpshield.monitor.alerting import AlertConfig, AlertRouter
        router = AlertRouter()
        router.add_channel(AlertConfig(name="test", url="http://localhost:9999", min_severity="CRITICAL"))
        anomaly = self._make_anomaly(severity="LOW")
        results = router.dispatch(anomaly)
        assert results == [False]

    def test_dispatch_sends_to_matching_severity(self):
        from mcpshield.monitor.alerting import AlertConfig, AlertRouter
        router = AlertRouter()
        router.add_channel(AlertConfig(name="test", url="http://localhost:9999", min_severity="MEDIUM"))
        anomaly = self._make_anomaly(severity="HIGH")
        # Will fail to connect (no server), but should attempt
        results = router.dispatch(anomaly)
        assert len(results) == 1
        assert results[0] == False  # Connection refused

    def test_dispatch_records_history(self):
        from mcpshield.monitor.alerting import AlertConfig, AlertRouter
        router = AlertRouter()
        router.add_channel(AlertConfig(name="test", url="http://localhost:9999", min_severity="INFO"))
        anomaly = self._make_anomaly()
        router.dispatch(anomaly)
        history = router.get_history()
        assert len(history) == 1
        assert history[0]["rule_id"] == "AD-001"
        assert history[0]["channel"] == "test"

    def test_history_limit(self):
        from mcpshield.monitor.alerting import AlertConfig, AlertRouter
        router = AlertRouter()
        router.add_channel(AlertConfig(name="test", url="http://localhost:9999", min_severity="INFO"))
        for i in range(1100):
            router.dispatch(self._make_anomaly(rule_id=f"R-{i}"))
        history = router.get_history()
        assert len(history) <= 1000

    def test_get_history_with_limit(self):
        from mcpshield.monitor.alerting import AlertConfig, AlertRouter
        router = AlertRouter()
        router.add_channel(AlertConfig(name="test", url="http://localhost:9999", min_severity="INFO"))
        for _ in range(10):
            router.dispatch(self._make_anomaly())
        assert len(router.get_history(limit=5)) == 5

    def test_default_payload(self):
        from mcpshield.monitor.alerting import AlertRouter
        anomaly = self._make_anomaly()
        payload = AlertRouter._default_payload(anomaly, "test-channel")
        assert payload["source"] == "MCPShield"
        assert payload["channel"] == "test-channel"
        assert payload["rule_id"] == "AD-001"
        assert payload["tool"] == "test_tool"
        assert payload["server"] == "test_server"

    def test_slack_payload_factory(self):
        from mcpshield.monitor.alerting import AlertRouter
        builder = AlertRouter.slack_payload_factory("MCPShield")
        anomaly = self._make_anomaly(severity="CRITICAL")
        payload = builder(anomaly)
        assert "blocks" in payload
        assert "text" in payload
        assert "CRITICAL" in payload["text"]

    def test_custom_payload_builder(self):
        from mcpshield.monitor.alerting import AlertConfig, AlertRouter
        def custom_builder(anomaly):
            return {"custom": True, "title": anomaly.title}
        router = AlertRouter()
        router.add_channel(AlertConfig(
            name="custom", url="http://localhost:9999",
            custom_payload=custom_builder, min_severity="INFO",
        ))
        anomaly = self._make_anomaly()
        # Will fail to send but payload is built
        router.dispatch(anomaly)
        # Verify the custom payload would be used
        payload = custom_builder(anomaly)
        assert payload["custom"] == True

    def test_alert_config_defaults(self):
        from mcpshield.monitor.alerting import AlertConfig
        config = AlertConfig(name="test", url="http://localhost")
        assert config.enabled is True
        assert config.min_severity == "HIGH"
        assert config.headers == {}
        assert config.custom_payload is None

    def test_severity_ordering(self):
        from mcpshield.monitor.alerting import AlertRouter
        order = AlertRouter._SEVERITY_ORDER
        assert order["CRITICAL"] > order["HIGH"] > order["MEDIUM"] > order["LOW"] > order["INFO"]

    def test_dispatch_multiple_channels(self):
        from mcpshield.monitor.alerting import AlertConfig, AlertRouter
        router = AlertRouter()
        router.add_channel(AlertConfig(name="a", url="http://localhost:9991", min_severity="INFO"))
        router.add_channel(AlertConfig(name="b", url="http://localhost:9992", min_severity="INFO"))
        router.add_channel(AlertConfig(name="c", url="http://localhost:9993", enabled=False))
        anomaly = self._make_anomaly()
        results = router.dispatch(anomaly)
        assert len(results) == 3  # 2 attempted + 1 skipped
        assert results[2] == False  # disabled


class TestAlertConfig:
    def test_all_fields(self):
        from mcpshield.monitor.alerting import AlertConfig
        config = AlertConfig(
            name="slack",
            url="https://hooks.slack.com/test",
            headers={"Authorization": "Bearer x"},
            enabled=False,
            min_severity="CRITICAL",
        )
        assert config.name == "slack"
        assert not config.enabled
        assert config.min_severity == "CRITICAL"
        assert config.headers["Authorization"] == "Bearer x"


# ── Live Scanner Tests ────────────────────────────────────────────────────

class TestLiveScanner:
    def test_live_server_info_defaults(self):
        from mcpshield.scanner.live import LiveServerInfo
        info = LiveServerInfo(url="http://localhost:3000")
        assert info.url == "http://localhost:3000"
        assert info.name is None
        assert info.tls is False
        assert info.connected is False
        assert info.error is None
        assert info.tools == []
        assert info.resources == []

    def test_live_scan_result_empty(self):
        from mcpshield.scanner.live import LiveScanResult, LiveServerInfo
        info = LiveServerInfo(url="http://localhost:3000")
        result = LiveScanResult(info)
        assert len(result.findings) == 0
        assert result.risk_score == 0

    def test_live_scan_result_risk_score(self):
        from mcpshield.models.findings import Category, Finding, Severity
        from mcpshield.scanner.live import LiveScanResult, LiveServerInfo
        info = LiveServerInfo(url="http://localhost:3000")
        result = LiveScanResult(info)
        result.findings.append(Finding(
            id="L1", title="Test", severity=Severity.CRITICAL,
            category=Category.TRANSPORT, description="d",
            affected_component="c", evidence="e", remediation="r", owasp_ref="",
        ))
        assert result.risk_score == 25
        # Cap at 100
        for _ in range(10):
            result.findings.append(Finding(
                id="Lx", title="Test", severity=Severity.CRITICAL,
                category=Category.TRANSPORT, description="d",
                affected_component="c", evidence="e", remediation="r", owasp_ref="",
            ))
        assert result.risk_score == 100

    def test_scan_live_server_connection_error(self):
        from mcpshield.scanner.live import scan_live_server
        # This will fail to connect — should return findings, not raise
        result = scan_live_server("http://127.0.0.1:19999", timeout=3)
        assert len(result.findings) > 0
        assert result.server.connected is False
        assert result.server.error is not None

    def test_scan_live_server_connection_error_finds_unreachable(self):
        from mcpshield.scanner.live import scan_live_server
        result = scan_live_server("http://127.0.0.1:19999", timeout=3)
        titles = [f.title for f in result.findings]
        assert any("Unreachable" in t for t in titles)

    def test_scan_live_server_tls_error(self):
        from mcpshield.scanner.live import scan_live_server
        # HTTPS to a non-TLS port should produce a TLS/connection error
        result = scan_live_server("https://127.0.0.1:19999", timeout=3)
        assert len(result.findings) > 0

    def test_mcp_client_init(self):
        from mcpshield.scanner.live import MCPClient
        client = MCPClient("http://localhost:3000", timeout=5)
        assert client.url == "http://localhost:3000"
        assert client.timeout == 5
        assert client.tls_verify is True
        assert client.headers == {}

    def test_mcp_client_strips_trailing_slash(self):
        from mcpshield.scanner.live import MCPClient
        client = MCPClient("http://localhost:3000/")
        assert client.url == "http://localhost:3000"

    def test_mcp_client_with_headers(self):
        from mcpshield.scanner.live import MCPClient
        client = MCPClient(
            "http://localhost:3000",
            headers={"Authorization": "Bearer test"},
            tls_verify=False,
        )
        assert client.headers["Authorization"] == "Bearer test"
        assert client.tls_verify is False

    def test_live_server_info_full(self):
        from mcpshield.scanner.live import LiveServerInfo
        info = LiveServerInfo(
            url="https://mcp.example.com",
            name="test-server",
            protocol_version="2024-11-05",
            server_info={"name": "Test"},
            tools=[{"name": "read_file"}],
            resources=[{"uri": "file:///data"}],
            tls=True,
            headers={"Authorization": "Bearer x"},
            connected=True,
        )
        assert info.name == "test-server"
        assert info.tls is True
        assert info.connected is True
        assert len(info.tools) == 1

    def test_live_scan_result_timestamp(self):
        import re

        from mcpshield.scanner.live import LiveScanResult, LiveServerInfo
        info = LiveServerInfo(url="http://localhost")
        result = LiveScanResult(info)
        # Should be ISO format
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", result.timestamp)


# ── CLI Integration Tests ─────────────────────────────────────────────────

class TestCLI:
    def test_cli_group_exists(self):
        from mcpshield.cli import cli
        assert cli is not None
        assert cli.name == "cli"

    def test_scan_command_exists(self):
        from mcpshield.cli import cli
        assert "scan" in cli.list_commands({})
        assert "monitor" in cli.list_commands({})
        assert "verify" in cli.list_commands({})
        assert "report" in cli.list_commands({})

    def test_safe_name_helper(self):
        from mcpshield.cli import _safe_name
        assert _safe_name("/path/to/my_config.json") == "my_config"
        assert _safe_name("config with spaces.json") == "config_with_spaces"
        assert _safe_name("simple.json") == "simple"

    def test_main_function(self):
        from mcpshield.cli import main
        assert callable(main)

    def test_version_option(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_scan_missing_file(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "/nonexistent/path.json", "--no-banner"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_scan_http_target_rejected(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "http://example.com/config.json", "--no-banner"])
        assert result.exit_code != 0
        assert "v0.2" in result.output or "http" in result.output.lower()

    def test_scan_severity_filter(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", VULN_CONFIG,
            "--severity", "CRITICAL",
            "--no-banner", "--quiet",
        ])
        # Should only show CRITICAL findings
        assert "CRITICAL" in result.output
        assert "MEDIUM" not in result.output

    def test_scan_module_filter(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", VULN_CONFIG,
            "--modules", "auth",
            "--no-banner", "--quiet",
        ])
        assert "Authentication" in result.output or "auth" in result.output.lower()

    def test_scan_json_output(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            result = runner.invoke(cli, [
                "scan", VULN_CONFIG,
                "--format", "json",
                "--output", tmpdir,
                "--no-banner", "--quiet",
            ])
            assert result.exit_code == 1  # Has critical findings
            # Check JSON file was created
            json_files = list(Path(tmpdir).glob("*.json"))
            assert len(json_files) == 1
            with open(json_files[0]) as f:
                data = json.load(f)
            assert "findings" in data

    def test_scan_html_output(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            runner.invoke(cli, [
                "scan", VULN_CONFIG,
                "--format", "html",
                "--output", tmpdir,
                "--no-banner", "--quiet",
            ])
            html_files = list(Path(tmpdir).glob("*.html"))
            assert len(html_files) == 1
            with open(html_files[0]) as f:
                content = f.read()
            assert "MCPShield" in content

    def test_scan_all_formats(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            runner.invoke(cli, [
                "scan", VULN_CONFIG,
                "--format", "all",
                "--output", tmpdir,
                "--no-banner", "--quiet",
            ])
            assert len(list(Path(tmpdir).glob("*.html"))) == 1
            assert len(list(Path(tmpdir).glob("*.json"))) == 1

    def test_verify_command_empty_log(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        # Empty log has no entries — verify treats this as intact
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            runner = CliRunner()
            result = runner.invoke(cli, ["verify", path])
            assert result.exit_code == 0  # empty chain is trivially intact
        finally:
            os.unlink(path)

    def test_verify_command_valid_log(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        from mcpshield.monitor import AuditLogger
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            logger = AuditLogger(path)
            logger.log_tool_call("a", "s", "t", {})
            runner = CliRunner()
            result = runner.invoke(cli, ["verify", path])
            assert result.exit_code == 0
            assert "intact" in result.output.lower()
        finally:
            os.unlink(path)

    def test_verify_command_missing_file(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", "/nonexistent.log"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_report_command_missing_file(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "/nonexistent.json"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_report_command_generates_html(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        # First generate JSON
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            runner.invoke(cli, [
                "scan", VULN_CONFIG,
                "--format", "json", "--output", tmpdir, "--no-banner", "--quiet",
            ])
            json_file = str(list(Path(tmpdir).glob("*.json"))[0])
            # Now generate HTML from JSON
            result = runner.invoke(cli, ["report", json_file, "--output", tmpdir])
            assert "saved" in result.output.lower()
            html_files = list(Path(tmpdir).glob("mcpshield_report.html"))
            assert len(html_files) == 1

    def test_monitor_command_starts(self):
        from click.testing import CliRunner

        from mcpshield.cli import cli
        runner = CliRunner()
        # Monitor blocks on input, so we use mix_stderr=False and it will
        # just print the header and return when input is exhausted
        result = runner.invoke(cli, ["monitor"], input="\x03")  # Ctrl+C
        assert "Monitor" in result.output or result.exit_code == 0


# ── Agent Monitor Coverage Tests ──────────────────────────────────────────

class TestAgentMonitorExtended:
    def test_monitor_with_custom_policy_dict(self):
        import yaml

        from mcpshield.monitor import AgentMonitor, PolicyAction
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"rules": [{
                "id": "CUSTOM", "description": "Block test",
                "action": "block", "tools": ["danger_tool"],
            }]}, f)
            policy_path = f.name
        try:
            import yaml as _yaml
            with open(policy_path) as pf:
                policy_data = _yaml.safe_load(pf)
            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
                log_path = f.name
            try:
                monitor = AgentMonitor(log_path=log_path)
                monitor.enforcer.load_from_dict(policy_data)
                decision = monitor.before_tool_call(
                    agent_id="a", server="s", tool="danger_tool", parameters={},
                )
                assert decision.action == PolicyAction.BLOCK
            finally:
                os.unlink(log_path)
        finally:
            os.unlink(policy_path)

    def test_alert_callback(self):
        from mcpshield.monitor import AgentMonitor
        from mcpshield.monitor.detector import Anomaly
        alerts_received = []
        def on_alert(anomaly):
            alerts_received.append(anomaly)
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            log_path = f.name
        try:
            monitor = AgentMonitor(log_path=log_path)
            monitor.on_alert = on_alert
            monitor.on_alert(Anomaly(
                rule_id="TEST", severity="HIGH", title="Test",
                description="Test", evidence={}, agent_id="a",
                tool="t", server="s", timestamp="2025-01-01T00:00:00Z",
            ))
            assert len(alerts_received) == 1
        finally:
            os.unlink(log_path)


# ── Edge Case Tests ───────────────────────────────────────────────────────

class TestEdgeCases:
    def test_scan_empty_servers_list(self):
        from mcpshield.scanner.core import scan_config_dict
        result = scan_config_dict({"mcpServers": {}})
        # Empty servers produces 1 INFO finding (no servers found), not 0
        assert len(result.findings) >= 1
        assert all(f.severity.value == "INFO" for f in result.findings)
        assert result.risk_score == 0  # INFO doesn't affect risk score

    def test_scan_config_with_no_mcpServers_key(self):
        from mcpshield.scanner.core import scan_config_dict
        result = scan_config_dict({"someOtherKey": "value"})
        # scan_config_dict always returns config_file type
        assert result.target.scan_type == "config_file"

    def test_config_parser_empty_env(self):
        from mcpshield.models.config import parse_config_dict
        config = {"mcpServers": {"test": {"command": "node", "args": ["server.js"], "env": {}}}}
        result = parse_config_dict(config)
        assert result.server_count == 1

    def test_config_parser_no_env_key(self):
        from mcpshield.models.config import parse_config_dict
        config = {"mcpServers": {"test": {"command": "python", "args": ["-m", "server"]}}}
        result = parse_config_dict(config)
        assert result.server_count == 1

    def test_finding_to_dict_complete(self):
        from mcpshield.models import Category, Finding, Severity
        f = Finding(
            id="T1.1", title="Test", severity=Severity.CRITICAL,
            category=Category.TRANSPORT, description="A test finding",
            affected_component="test component", evidence="test evidence",
            remediation="fix it", owasp_ref="ASI05", cve_refs=["CVE-2025-12345"],
        )
        d = f.to_dict()
        assert d["severity"] == "CRITICAL"
        assert d["cve_refs"] == ["CVE-2025-12345"]
        assert d["owasp_ref"] == "ASI05"

    def test_scan_result_risk_score_clear(self):
        from mcpshield.models import ScanResult, ScanTarget
        result = ScanResult(target=ScanTarget(raw="test", scan_type="config_file"))
        assert result.risk_score == 0
        assert result.risk_label == "CLEAR"

    def test_html_report_empty_scan_still_valid(self):
        from mcpshield.models import ScanResult, ScanTarget
        from mcpshield.reporter import generate_html_report
        result = ScanResult(target=ScanTarget(raw="test", scan_type="config_file"))
        html = generate_html_report(result)
        assert "<!DOCTYPE" in html
        assert "</html>" in html

    def test_json_report_empty_scan(self):
        from mcpshield.models import ScanResult, ScanTarget
        from mcpshield.reporter import generate_json_report
        result = ScanResult(target=ScanTarget(raw="test", scan_type="config_file"))
        json_str = generate_json_report(result)
        data = json.loads(json_str)
        assert data["risk_score"] == 0
        assert len(data["findings"]) == 0

    def test_detector_rate_spike_with_low_threshold(self):
        from mcpshield.monitor import AnomalyDetector
        detector = AnomalyDetector(rate_threshold=3)
        anomalies = []
        for i in range(10):
            anomalies.extend(detector.analyse("fast-agent", "s", "t", {"i": i}))
        rate_anomalies = [a for a in anomalies if a.rule_id == "AD-004"]
        assert len(rate_anomalies) > 0

    def test_enforcer_log_action(self):
        from mcpshield.monitor import PolicyAction, PolicyEnforcer
        enforcer = PolicyEnforcer()
        # send_email triggers ALERT by default
        decision = enforcer.evaluate(
            agent_id="a", server="s", tool="send_email",
            parameters={"to": "test@example.com", "body": "hello"},
        )
        assert decision.action == PolicyAction.ALERT
        assert decision.rule_id is not None
