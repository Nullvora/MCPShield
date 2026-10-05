# SPDX-License-Identifier: Apache-2.0
"""Agent-activity observability: OTLP export, session tracing, trifecta alerts, `mcpshield trace`."""

import io
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from click.testing import CliRunner

from conftest import SERVERS, requires_mcp
from mcpshield import tracing
from mcpshield.auditlog import AuditLog
from mcpshield.cli import cli
from mcpshield.proxy.guard import StdioGuard
from mcpshield.proxy.policy import Policy
from mcpshield.telemetry import OtlpExporter, Span, encode_attributes, parse_headers, parse_traceparent

PY = sys.executable


class ListExporter:
    def __init__(self):
        self.spans: list[Span] = []
        self.closed = False

    def export(self, span):
        self.spans.append(span)

    def close(self):
        self.closed = True


class _Collector(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        type(self).received.append((self.path, dict(self.headers), json.loads(body)))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def collector():
    _Collector.received = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Collector)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", _Collector.received
    srv.shutdown()


def jl(obj):
    return (json.dumps(obj) + "\n").encode()


def make_guard(tmp_path, policy=None, capture=False):
    out = io.BytesIO()
    exp = ListExporter()
    audit = AuditLog(tmp_path / "a.jsonl")
    g = StdioGuard("x", [], policy or Policy(), audit=audit, lock=None, server_name="srv", stdin=io.BytesIO(), stdout=out,
                   exporter=exp, capture_arguments=capture)

    class P:
        stdin = io.BytesIO()
    g.proc = P()  # type: ignore[assignment]
    return g, exp, tmp_path / "a.jsonl"


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def attrs(span):
    return span.attributes


TOOLS = [{"name": "read_file", "description": "Read a file from disk."},
         {"name": "fetch_url", "description": "Fetch a web page."},
         {"name": "send_email", "description": "Send an email."}]


# --------------------------------------------------------------------------- unit


def test_traceparent_parsing():
    tid, sid = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
    assert parse_traceparent(f"00-{tid}-{sid}-01") == (tid, sid)
    assert parse_traceparent("00-" + "0" * 32 + f"-{sid}-01") is None
    assert parse_traceparent("garbage") is None and parse_traceparent(None) is None


def test_attribute_encoding_and_headers():
    enc = {a["key"]: a["value"] for a in encode_attributes({"s": "x", "i": 3, "b": True, "f": 1.5, "l": ["a"], "none": None, "e": ""})}
    assert enc["s"] == {"stringValue": "x"} and enc["i"] == {"intValue": "3"} and enc["b"] == {"boolValue": True}
    assert enc["f"] == {"doubleValue": 1.5} and enc["l"]["arrayValue"]["values"][0] == {"stringValue": "a"}
    assert "none" not in enc and "e" not in enc
    assert parse_headers("Authorization=Bearer x, x-team = a=b") == {"Authorization": "Bearer x", "x-team": "a=b"}


def test_tool_call_span_semconv(tmp_path):
    g, exp, log = make_guard(tmp_path)
    g.handle_client(jl({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-11-25", "clientInfo": {"name": "claude-code", "version": "2"}}}))
    g.handle_client(jl({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "add", "arguments": {"a": 1, "token": "ghp_" + "a" * 36}}}))
    g.handle_server(jl({"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "2"}], "isError": False}}))
    span = [s for s in exp.spans if s.name == "execute_tool add"][0]
    a = attrs(span)
    assert a["gen_ai.operation.name"] == "execute_tool" and a["gen_ai.tool.name"] == "add" and a["mcp.method.name"] == "tools/call"
    assert a["mcp.protocol.version"] == "2025-11-25" and a["gen_ai.agent.name"] == "claude-code" and a["mcpshield.decision"] == "allow"
    assert "gen_ai.tool.call.arguments" not in a          # arguments are opt-in
    assert span.trace_id == g.session_id and span.parent_span_id == g.session_span_id and span.error is None
    res = [r for r in records(log) if r["event"] == "tool_result"][0]
    assert res["tool"] == "add" and res["duration_ms"] >= 0 and res["session"] == g.session_id


def test_capture_args_is_redacted(tmp_path):
    g, exp, _ = make_guard(tmp_path, capture=True)
    g.handle_client(jl({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "add", "arguments": {"token": "ghp_" + "a" * 36}}}))
    g.handle_server(jl({"jsonrpc": "2.0", "id": 2, "result": {"content": []}}))
    captured = attrs(exp.spans[-1])["gen_ai.tool.call.arguments"]
    assert "ghp_" not in captured and "REDACTED" in captured.upper()


def test_traceparent_propagation(tmp_path):
    g, exp, _ = make_guard(tmp_path)
    tid, sid = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
    g.handle_client(jl({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "add", "arguments": {}, "_meta": {"traceparent": f"00-{tid}-{sid}-01",
                                                                           "io.modelcontextprotocol/protocolVersion": "2026-07-28"}}}))
    g.handle_server(jl({"jsonrpc": "2.0", "id": 3, "result": {"content": [], "resultType": "complete"}}))
    span = exp.spans[-1]
    assert span.trace_id == tid and span.parent_span_id == sid
    assert attrs(span)["mcpshield.session.id"] == g.session_id and attrs(span)["mcp.protocol.version"] == "2026-07-28"


def test_blocked_call_span_and_error_status(tmp_path):
    g, exp, log = make_guard(tmp_path, Policy.from_dict({"tools": {"deny": ["rm"]}}))
    g.handle_client(jl({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "rm", "arguments": {}}}))
    span = exp.spans[-1]
    assert attrs(span)["mcpshield.decision"] == "block" and span.error and attrs(span)["mcpshield.reasons"]
    assert any(e["name"] == "mcpshield.policy_violation" for e in span.events)
    g.handle_client(jl({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "add", "arguments": {}}}))
    g.handle_server(jl({"jsonrpc": "2.0", "id": 5, "error": {"code": -32603, "message": "boom"}}))
    assert exp.spans[-1].error == "boom"
    assert [r["is_error"] for r in records(log) if r["event"] == "tool_result"] == [True, True]


def test_lethal_trifecta_session_alert(tmp_path):
    g, exp, log = make_guard(tmp_path)
    g.handle_client(jl({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    g.handle_server(jl({"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS}}))
    assert any(s.name == "tools/list" and attrs(s)["mcpshield.tools.exposed"] == 3 for s in exp.spans)
    for i, name in enumerate(["read_file", "fetch_url", "send_email", "send_email"], start=10):
        g.handle_client(jl({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": {}}}))
        g.handle_server(jl({"jsonrpc": "2.0", "id": i, "result": {"content": []}}))
    alerts = [r for r in records(log) if r["event"] == "alert"]
    # fetch_url reads untrusted content *and* is an outbound channel, so read_file + fetch_url completes it
    assert len(alerts) == 1 and alerts[0]["kind"] == "lethal_trifecta" and alerts[0]["tool"] == "fetch_url"
    assert set(alerts[0]["detail"]) == {"private_data", "untrusted_content", "external_comm"}
    alert_spans = [s for s in exp.spans if any(e["name"] == "mcpshield.alert" for e in s.events)]
    assert len(alert_spans) == 1 and g.stats["alerts"] == 1


def test_no_trifecta_for_readonly_session(tmp_path):
    g, _, log = make_guard(tmp_path)
    g.handle_client(jl({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    g.handle_server(jl({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "add", "description": "Add numbers."}]}}))
    for i in range(3):
        g.handle_client(jl({"jsonrpc": "2.0", "id": 5 + i, "method": "tools/call", "params": {"name": "add", "arguments": {}}}))
        g.handle_server(jl({"jsonrpc": "2.0", "id": 5 + i, "result": {"content": []}}))
    assert not [r for r in records(log) if r["event"] == "alert"]


def test_session_span_on_close(tmp_path):
    g, exp, _ = make_guard(tmp_path)
    g.close_session(0)
    root = exp.spans[-1]
    assert root.span_id == g.session_span_id and root.parent_span_id is None and exp.closed
    assert attrs(root)["process.exit.code"] == 0 and "mcpshield.stats.calls" in attrs(root)


def test_otlp_exporter_posts_json(collector):
    url, received = collector
    exp = OtlpExporter(url, {"Authorization": "Bearer t"}, "svc", {"deployment.environment": "test"}, interval=0.05)
    exp.export(Span("execute_tool add", "a" * 32, "b" * 16, None, 1, 2, attributes={"gen_ai.tool.name": "add"}))
    exp.close()
    assert exp.sent == 1 and exp.failed == 0
    path, headers, body = received[0]
    assert path == "/v1/traces" and headers.get("Authorization") == "Bearer t"
    rs = body["resourceSpans"][0]
    res = {a["key"]: a["value"]["stringValue"] for a in rs["resource"]["attributes"]}
    assert res["service.name"] == "svc" and res["deployment.environment"] == "test"
    assert rs["scopeSpans"][0]["spans"][0]["name"] == "execute_tool add"


def test_otlp_exporter_failure_is_silent():
    exp = OtlpExporter("http://127.0.0.1:9", interval=0.05, timeout=0.5)
    exp.export(Span("x", "a" * 32, "b" * 16, None, 1, 2))
    exp.close()
    assert exp.failed == 1


# --------------------------------------------------------------------------- trace command


def _session_log(tmp_path):
    g, _, log = make_guard(tmp_path, Policy.from_dict({"tools": {"deny": ["rm"]}}))
    g._log("proxy_start", command=["x"], mode="enforce")
    g.handle_client(jl({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    g.handle_server(jl({"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS}}))
    for i, name in enumerate(["read_file", "fetch_url", "rm", "send_email"], start=10):
        g.handle_client(jl({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": {"q": i}}}))
        if name != "rm":
            g.handle_server(jl({"jsonrpc": "2.0", "id": i, "result": {"content": []}}))
    g._log("proxy_stop", exit_code=0, **g.stats)
    return g, log


def test_tracing_groups_sessions(tmp_path):
    g, log = _session_log(tmp_path)
    sessions = tracing.group_sessions(tracing.load_records([log]))
    assert len(sessions) == 1
    sm = sessions[0].summary()
    assert sm["session"] == g.session_id and sm["calls"] == 4 and sm["blocked"] == 1 and sm["alerts"] == ["lethal_trifecta"]
    assert sm["tools"] == ["read_file", "fetch_url", "rm", "send_email"]


def test_trace_cli_timeline_summary_html_json(tmp_path):
    _, log = _session_log(tmp_path)
    r = CliRunner().invoke(cli, ["trace", str(log)])
    assert r.exit_code == 0, r.output
    assert "ALERT lethal_trifecta" in r.output and "call rm" in r.output and "block" in r.output
    r = CliRunner().invoke(cli, ["trace", str(log), "--summary", "--alerts"])
    assert r.exit_code == 0 and "lethal_trifecta" in r.output
    html_path = tmp_path / "activity.html"
    r = CliRunner().invoke(cli, ["trace", str(log), "--html", str(html_path), "--summary"])
    page = html_path.read_text()
    assert r.exit_code == 0 and "chain intact" in page and "lethal_trifecta" in page and "<script" not in page
    r = CliRunner().invoke(cli, ["trace", str(log), "--json"])
    data = json.loads(r.output)
    assert data["sessions"][0]["blocked"] == 1 and list(data["integrity"].values())[0]["ok"]


def test_trace_cli_detects_tampering(tmp_path):
    _, log = _session_log(tmp_path)
    lines = log.read_text().splitlines()
    idx = next(i for i, line in enumerate(lines) if '"decision":"block"' in line and '"tool_call"' in line)
    rec = json.loads(lines[idx])
    rec["decision"] = "allow"                     # attacker hides the blocked call
    lines[idx] = json.dumps(rec, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n")
    r = CliRunner().invoke(cli, ["trace", str(log), "--summary"])
    assert r.exit_code == 1 and "integrity check failed" in r.output


def test_trace_cli_html_escapes(tmp_path):
    g, _, log = make_guard(tmp_path)
    g.handle_client(jl({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "<script>alert(1)</script>", "arguments": {}}}))
    g.handle_server(jl({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}))
    out = tmp_path / "x.html"
    CliRunner().invoke(cli, ["trace", str(log), "--html", str(out), "--summary"])
    assert "<script>alert" not in out.read_text()


# --------------------------------------------------------------------------- end to end


@requires_mcp
def test_proxy_otlp_end_to_end(tmp_path, collector):
    url, received = collector
    log = tmp_path / "audit.jsonl"
    p = subprocess.Popen([PY, "-m", "mcpshield", "proxy", "--audit-log", str(log), "--name", "poison", "--otlp-endpoint", url,
                          "--otlp-header", "x-team=blue", "--", PY, str(SERVERS / "poisoned_server.py")],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

    def rpc(i, method, params=None):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n")
        p.stdin.flush()
        while True:
            m = json.loads(p.stdout.readline())
            if m.get("id") == i:
                return m

    try:
        rpc(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "e2e-agent", "version": "1"}})
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        p.stdin.flush()
        rpc(2, "tools/list")
        rpc(3, "tools/call", {"name": "run_command", "arguments": {"command": "echo hi"}})
        rpc(4, "tools/call", {"name": "fetch_url", "arguments": {"url": "https://example.com"}})
    finally:
        p.stdin.close()
        p.wait(timeout=15)
    spans = [s for _, _, body in received for rs in body["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]]
    names = [s["name"] for s in spans]
    assert "execute_tool run_command" in names and "execute_tool fetch_url" in names and "tools/list" in names
    root = [s for s in spans if s["name"].startswith("mcp.session")][0]
    assert all(s["traceId"] == root["traceId"] for s in spans)
    assert all(h.get("x-team") == "blue" for _, h, _ in received)
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert any(e["event"] == "alert" and e["kind"] == "lethal_trifecta" for e in events)
    r = CliRunner().invoke(cli, ["trace", str(log), "--summary"])
    assert r.exit_code == 0 and "lethal_trifecta" in r.output
