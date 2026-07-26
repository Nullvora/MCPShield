"""
MCPShield Scanner — Live HTTP/SSE Scanner Module
Connects to a running MCP server, retrieves tool definitions via MCP protocol,
and runs injection + privilege analysis on live tool definitions.

Covers: Live tool definition scanning (T3.1, T3.2), live privilege assessment
OWASP: ASI01, ASI02
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import requests

from mcpshield.models.findings import Category, Finding, Severity
from mcpshield.scanner.injection import scan_tool_definition
from mcpshield.scanner.privilege import _HIGH_PRIV_INDICATORS

# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class LiveServerInfo:
    """Information about a connected MCP server."""
    url: str
    name: str | None = None
    protocol_version: str | None = None
    server_info: dict = field(default_factory=dict)
    tools: list[dict] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    tls: bool = False
    headers: dict = field(default_factory=dict)
    connected: bool = False
    error: str | None = None


class LiveScanResult:
    """Result of a live MCP server scan."""

    def __init__(self, server: LiveServerInfo) -> None:
        self.server = server
        self.findings: list[Finding] = []
        self.timestamp: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    @property
    def risk_score(self) -> int:
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        raw = sum(weights[f.severity] for f in self.findings)
        return min(raw, 100)


# ── MCP Protocol Client ───────────────────────────────────────────────────────

class MCPClient:
    """Minimal MCP JSON-RPC client for HTTP/SSE transport.

    Supports the MCP protocol handshake:
      1. initialize → server info + capabilities
      2. tools/list → tool definitions
      3. resources/list → resource templates
    """

    def __init__(
        self,
        url: str,
        headers: dict | None = None,
        timeout: int = 15,
        tls_verify: bool = True,
    ) -> None:
        self.url = url.rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout
        self.tls_verify = tls_verify
        self._session_id: str | None = None

    def _post(self, method: str, params: dict | None = None) -> dict:
        """Send a JSON-RPC request to the MCP server."""
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
        }
        if params:
            payload["params"] = params

        resp = requests.post(
            self.url,
            json=payload,
            headers={"Content-Type": "application/json", **self.headers},
            timeout=self.timeout,
            verify=self.tls_verify,
        )
        resp.raise_for_status()
        data = resp.json()

        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data.get("result", {})

    def initialize(self) -> dict:
        """Send MCP initialize request and return server info."""
        result = self._post("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "MCPShield", "version": "0.1.0"},
        })
        self._session_id = result.get("session", {}).get("id")
        return result

    def list_tools(self) -> list[dict]:
        """Retrieve all tool definitions from the server."""
        result = self._post("tools/list")
        return result.get("tools", [])

    def list_resources(self) -> list[dict]:
        """Retrieve all resource templates from the server."""
        result = self._post("resources/list")
        return result.get("resources", [])


# ── Live Scanner ──────────────────────────────────────────────────────────────

def scan_live_server(
    url: str,
    headers: dict | None = None,
    timeout: int = 15,
    tls_verify: bool = True,
    progress_cb: Callable[[str], None] | None = None,
) -> LiveScanResult:
    """
    Connect to a live MCP server and perform security assessment.

    Args:
        url:         HTTP/SSE URL of the MCP server.
        headers:     Optional auth headers (e.g. {"Authorization": "Bearer ..."}).
        timeout:     Connection and request timeout in seconds.
        tls_verify:  Whether to verify TLS certificates.
        progress_cb: Optional callback for progress messages.

    Returns:
        LiveScanResult with findings.
    """
    def emit(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    server_info = LiveServerInfo(
        url=url,
        tls=url.startswith("https://"),
        headers=headers or {},
    )
    result = LiveScanResult(server_info)

    # ── Step 1: Connect ─────────────────────────────────────────────────────
    emit(f"Connecting to {url}...")
    try:
        client = MCPClient(url, headers=headers, timeout=timeout, tls_verify=tls_verify)
        init_result = client.initialize()
        server_info.connected = True
        server_info.protocol_version = init_result.get("protocolVersion")
        server_info.server_info = init_result.get("serverInfo", {})
        server_info.name = server_info.server_info.get("name", url)
        emit(f"Connected: {server_info.name} (protocol {server_info.protocol_version})")
    except requests.exceptions.SSLError as exc:
        server_info.error = f"TLS error: {exc}"
        result.findings.append(Finding(
            id="L1.1",
            title="TLS Connection Failure",
            severity=Severity.HIGH,
            category=Category.TRANSPORT,
            description=f"Failed to establish TLS connection to {url}: {exc}. "
            f"This may indicate a self-signed or expired certificate.",
            affected_component=f"Server at {url}",
            evidence=str(exc)[:500],
            remediation="Ensure the server uses a valid TLS certificate from a trusted CA. "
            "For internal services, distribute the CA root certificate.",
            owasp_ref="ASI03",
        ))
        return result
    except requests.exceptions.ConnectionError as exc:
        server_info.error = f"Connection refused: {exc}"
        result.findings.append(Finding(
            id="L1.2",
            title="MCP Server Unreachable",
            severity=Severity.HIGH,
            category=Category.TRANSPORT,
            description=f"Could not connect to MCP server at {url}: {exc}",
            affected_component=f"Server at {url}",
            evidence=str(exc)[:500],
            remediation="Verify the server is running and accessible. Check firewall rules "
            "and network connectivity.",
            owasp_ref="ASI07",
        ))
        return result
    except Exception as exc:
        server_info.error = str(exc)
        result.findings.append(Finding(
            id="L1.3",
            title="MCP Connection Error",
            severity=Severity.MEDIUM,
            category=Category.TRANSPORT,
            description=f"Unexpected error connecting to {url}: {exc}",
            affected_component=f"Server at {url}",
            evidence=str(exc)[:500],
            remediation="Check the server URL, authentication, and network configuration.",
            owasp_ref="",
        ))
        return result

    # ── Step 2: Check authentication ─────────────────────────────────────────
    if not headers or not any(
        k.lower() in ("authorization", "x-api-key") for k in headers
    ):
        result.findings.append(Finding(
            id="L2.1",
            title="Live MCP Server Has No Client Authentication",
            severity=Severity.CRITICAL,
            category=Category.AUTHENTICATION,
            description=f"Server {server_info.name} accepted a connection without client authentication. "
            f"Any process that can reach this endpoint can invoke its tools.",
            affected_component=f"Server '{server_info.name}' — {url}",
            evidence="Connected successfully without Authorization or X-API-Key header",
            remediation="Implement Bearer token or mTLS authentication on the MCP server.",
            owasp_ref="ASI03",
        ))

    # ── Step 3: Retrieve and scan tool definitions ────────────────────────────
    try:
        tools = client.list_tools()
        server_info.tools = tools
        emit(f"Retrieved {len(tools)} tool definition(s)")
    except Exception as exc:
        emit(f"Warning: could not list tools: {exc}")
        tools = []

    for tool_def in tools:
        tool_name = tool_def.get("name", "unknown")
        tool_findings = scan_tool_definition(tool_def, server_info.name or url)
        result.findings.extend(tool_findings)

        # Check for high-privilege tool indicators
        name_lower = tool_name.lower()
        description = tool_def.get("description", "").lower()
        search_str = f"{name_lower} {description}"

        for capability, info in _HIGH_PRIV_INDICATORS.items():
            if any(kw in search_str for kw in info["keywords"]):
                result.findings.append(Finding(
                    id="L2.3",
                    title=f"Live Tool High-Privilege Capability: {capability.replace('_', ' ').title()}",
                    severity=Severity.MEDIUM,
                    category=Category.PRIVILEGE,
                    description=f"Tool '{tool_name}' on server '{server_info.name}' provides "
                    f"{capability.replace('_', ' ')} capability. {info['risk']}",
                    affected_component=f"Tool '{tool_name}' on '{server_info.name}'",
                    evidence=f"Capability: {capability}",
                    remediation=info["recommended_scope"],
                    owasp_ref="ASI03",
                ))
                break  # one privilege finding per tool

    # ── Step 4: Retrieve and check resources ──────────────────────────────────
    try:
        resources = client.list_resources()
        server_info.resources = resources
        emit(f"Retrieved {len(resources)} resource template(s)")
    except Exception as exc:
        emit(f"Note: resources/list not supported: {exc}")

    # ── Step 5: Check for dangerous tool combinations ───────────────────────
    tool_names_lower = [t.get("name", "").lower() for t in tools]
    has_read = any(any(kw in n for kw in ("read", "get", "fetch", "list", "download")) for n in tool_names_lower)
    has_send = any(any(kw in n for kw in ("send", "email", "post", "upload", "write", "delete")) for n in tool_names_lower)
    has_exec = any(any(kw in n for kw in ("exec", "run", "eval", "shell", "bash", "command")) for n in tool_names_lower)
    has_fetch = any(any(kw in n for kw in ("fetch", "browse", "http", "request", "scrape")) for n in tool_names_lower)

    if has_read and has_send:
        result.findings.append(Finding(
            id="L5.1",
            title="Dangerous Tool Combination: Read + Send/Write Capabilities",
            severity=Severity.HIGH,
            category=Category.PRIVILEGE,
            description="Server exposes both data-reading and data-sending tools, "
            "enabling potential data exfiltration through tool chaining.",
            affected_component=f"Server '{server_info.name}'",
            evidence=f"Read tools: {has_read}, Send tools: {has_send}",
            remediation="Review whether both read and send capabilities are needed simultaneously. "
            "Consider separating into different servers with different trust levels.",
            owasp_ref="ASI02",
        ))

    if has_fetch and has_exec:
        result.findings.append(Finding(
            id="L5.2",
            title="Dangerous Tool Combination: Fetch + Code Execution",
            severity=Severity.CRITICAL,
            category=Category.INJECTION,
            description="Server exposes both content-fetching and code-execution tools. "
            "This combination enables indirect prompt injection leading to code execution.",
            affected_component=f"Server '{server_info.name}'",
            evidence=f"Fetch tools: {has_fetch}, Exec tools: {has_exec}",
            remediation="Isolate fetching and execution capabilities into separate servers. "
            "Sanitise all fetched content before it can influence execution decisions.",
            owasp_ref="ASI01",
        ))

    emit(f"Live scan complete — {len(result.findings)} finding(s)")
    return result
