"""
MCPShield Scanner — Transport Security Module
Covers: T1.1 (STDIO RCE), T1.2 (Unencrypted HTTP), T1.3 (SSRF)
OWASP: ASI05, ASI03
"""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

from mcpshield.models.config import VULNERABLE_PACKAGES, MCPConfig, MCPServerConfig
from mcpshield.models.findings import Category, Finding, Severity

# ── Version extraction ───────────────────────────────────────────────────────
_VERSION_RE = re.compile(r"@([\d]+\.[\d]+\.[\d]+(?:[.\-]\w+)*)")


def _extract_version(arg: str) -> str | None:
    m = _VERSION_RE.search(arg)
    return m.group(1) if m else None


def _check_package_version(pkg_name: str, version_str: str) -> tuple[bool, str]:
    """Returns (is_vulnerable, message)."""
    info = VULNERABLE_PACKAGES.get(pkg_name)
    if not info:
        return False, ""
    try:
        installed = Version(version_str)
        threshold = Version(info["vulnerable_below"])
        if installed < threshold:
            return True, (
                f"{pkg_name}@{version_str} is below safe version "
                f"{info['vulnerable_below']} — {info['description']}"
            )
    except InvalidVersion:
        pass
    return False, ""


# ── Main audit function ───────────────────────────────────────────────────────

def audit_transport(config: MCPConfig) -> list[Finding]:
    findings: list[Finding] = []

    for server in config.servers:
        findings.extend(_check_stdio(server))
        findings.extend(_check_http_tls(server))
        findings.extend(_check_ssrf_surface(server))
        findings.extend(_check_sdk_version(server))

    return findings


# ── Per-check functions ───────────────────────────────────────────────────────

def _check_stdio(server: MCPServerConfig) -> list[Finding]:
    findings = []

    if server.transport != "stdio":
        return findings

    # T1.1-a — STDIO transport inherently enables OS-level interaction
    finding = Finding(
        id="T1.1",
        title="STDIO Transport Permits OS Command Execution",
        severity=Severity.CRITICAL,
        category=Category.TRANSPORT,
        description=(
            "This MCP server uses STDIO transport, communicating via the process stdin/stdout "
            "streams. CVE-2025-49596 and CVE-2026-22252 document systemic flaws in official "
            "Anthropic MCP SDKs (Python, TypeScript, Java, Rust) that allow crafted STDIO "
            "input to escape the data context and execute arbitrary OS commands on the host. "
            "Over 200,000 server instances were estimated vulnerable at peak exposure."
        ),
        affected_component=f"Server '{server.name}' — STDIO transport",
        evidence=(
            f"command: {server.command!r}  args: {server.args}\n"
            f"Transport type: STDIO (process-level communication)"
        ),
        remediation=(
            "1. Apply patches for CVE-2025-49596 / CVE-2026-22252 immediately by upgrading "
            "to the latest MCP SDK version (>= 1.3.1).\n"
            "2. Restrict STDIO MCP servers to trusted, controlled process environments — "
            "never expose STDIO-based servers over a network socket.\n"
            "3. Run the MCP server process under a least-privilege OS user account.\n"
            "4. Consider containerising the MCP server with restricted capabilities "
            "(--cap-drop ALL, read-only filesystem).\n"
            "See: hardening/remediation_playbooks/PB-001-transport-hardening.md"
        ),
        owasp_ref="ASI05",
        cve_refs=["CVE-2025-49596", "CVE-2026-22252"],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    )
    findings.append(finding)

    # T1.1-b — Direct shell command
    if server.command and server.command.lower() in {"bash", "sh", "zsh", "cmd", "powershell", "pwsh"}:
        findings.append(Finding(
            id="T1.1-b",
            title="MCP Server Invokes Shell Directly",
            severity=Severity.CRITICAL,
            category=Category.TRANSPORT,
            description=(
                f"The MCP server '{server.name}' uses '{server.command}' as its command — "
                "a direct shell invocation. Any argument or environment variable reaching this "
                "server can be executed as a shell command with minimal sanitisation barriers."
            ),
            affected_component=f"Server '{server.name}' — command: {server.command!r}",
            evidence=f"command: {server.command!r}  args: {server.args}",
            remediation=(
                "Replace the shell invocation with a direct binary call or a purpose-built "
                "MCP server implementation. Never use bash/sh/cmd as the MCP server entry point."
            ),
            owasp_ref="ASI05",
            cve_refs=["CVE-2025-49596"],
        ))

    return findings


def _check_http_tls(server: MCPServerConfig) -> list[Finding]:
    findings = []

    if server.transport not in ("http", "sse"):
        return findings

    if not server.tls:
        findings.append(Finding(
            id="T1.2",
            title="MCP Server Communication Is Unencrypted (HTTP Without TLS)",
            severity=Severity.HIGH,
            category=Category.TRANSPORT,
            description=(
                f"Server '{server.name}' communicates over plain HTTP without TLS. "
                "All MCP traffic — tool definitions, agent instructions, parameter values, "
                "tool responses, and any sensitive data in context — is transmitted in cleartext "
                "and is readable by any adversary with network visibility. "
                "In enterprise environments, lateral movement within the network makes "
                "this a realistic threat even on internal networks."
            ),
            affected_component=f"Server '{server.name}' — URL: {server.url}",
            evidence=f"url: {server.url!r} (scheme: http, no TLS)",
            remediation=(
                "1. Configure TLS on the MCP server — obtain a certificate from a trusted CA "
                "or use Let's Encrypt for internal deployments.\n"
                "2. Change the server URL scheme from http:// to https://.\n"
                "3. Enforce HSTS to prevent protocol downgrade attacks.\n"
                "4. For internal services, use a private CA and distribute the root cert.\n"
                "See: hardening/remediation_playbooks/PB-001-transport-hardening.md"
            ),
            owasp_ref="ASI03",
        ))

    return findings


def _check_ssrf_surface(server: MCPServerConfig) -> list[Finding]:
    """
    Heuristic: if the server accepts a URL parameter in its args, flag SSRF risk.
    """
    findings = []

    # Look for --url, -u, or any arg that looks like it accepts a URL
    url_args = [a for a in server.args if "--url" in a or "-u" == a or "http" in a.lower()]

    if url_args:
        findings.append(Finding(
            id="T1.3",
            title="MCP Tool May Be Vulnerable to Server-Side Request Forgery (SSRF)",
            severity=Severity.HIGH,
            category=Category.TRANSPORT,
            description=(
                f"Server '{server.name}' appears to accept URL parameters in its args. "
                "If an MCP tool makes outbound HTTP requests based on agent-supplied or "
                "injection-influenced URL parameters, an attacker can redirect those requests "
                "to internal services, cloud metadata endpoints (169.254.169.254), or other "
                "restricted infrastructure. 36.7% of analysed MCP servers were found vulnerable "
                "to SSRF in independent research."
            ),
            affected_component=f"Server '{server.name}' — URL-accepting args: {url_args}",
            evidence=f"args containing URL references: {url_args}",
            remediation=(
                "1. Implement an allowlist of permitted outbound domains/IPs.\n"
                "2. Block requests to RFC-1918 private ranges (10.0.0.0/8, 172.16.0.0/12, "
                "192.168.0.0/16) and cloud metadata endpoints (169.254.169.254, 100.100.100.200).\n"
                "3. Use a dedicated HTTP client with SSRF protections (e.g., ssrfcheck).\n"
                "4. Validate and normalise all URL inputs before making outbound requests."
            ),
            owasp_ref="ASI02",
        ))

    return findings


def _check_sdk_version(server: MCPServerConfig) -> list[Finding]:
    """Check args for known-vulnerable SDK package versions."""
    findings = []

    args_str = " ".join(server.args)

    for pkg_name, info in VULNERABLE_PACKAGES.items():
        if pkg_name in args_str:
            version = _extract_version(args_str)
            if version:
                is_vuln, msg = _check_package_version(pkg_name, version)
                if is_vuln:
                    findings.append(Finding(
                        id="T1.1-c",
                        title=f"Vulnerable MCP SDK Version Detected: {pkg_name}@{version}",
                        severity=Severity.CRITICAL,
                        category=Category.TRANSPORT,
                        description=msg,
                        affected_component=f"Server '{server.name}' — package: {pkg_name}@{version}",
                        evidence=f"Package reference found in args: {pkg_name}@{version}",
                        remediation=(
                            f"Upgrade {pkg_name} to version >= {info['vulnerable_below']} immediately. "
                            f"Run: npm install {pkg_name}@latest  or  pip install mcp --upgrade"
                        ),
                        owasp_ref="ASI05",
                        cve_refs=info["cves"],
                    ))
            else:
                # Package present but no pinned version — warn
                findings.append(Finding(
                    id="T1.1-d",
                    title=f"MCP SDK Without Pinned Version: {pkg_name}",
                    severity=Severity.MEDIUM,
                    category=Category.SUPPLY_CHAIN,
                    description=(
                        f"Package '{pkg_name}' is referenced without a pinned version. "
                        "This means any vulnerable version could be resolved at runtime, "
                        f"including versions affected by {', '.join(info['cves'])}."
                    ),
                    affected_component=f"Server '{server.name}'",
                    evidence=f"Package in args without explicit version: {pkg_name}",
                    remediation=(
                        f"Pin the package to a specific safe version >= {info['vulnerable_below']}: "
                        f"e.g. npx -y {pkg_name}@{info['vulnerable_below']}"
                    ),
                    owasp_ref="ASI04",
                    cve_refs=info["cves"],
                ))

    return findings
