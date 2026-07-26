"""
MCPShield Scanner — Supply Chain Security Module
Covers: T4.1 (Registry Poisoning), T4.2 (Unpinned / Unverified Dependencies)
OWASP: ASI04
"""

from __future__ import annotations

import re

from mcpshield.models.config import MCPConfig, MCPServerConfig
from mcpshield.models.findings import Category, Finding, Severity

# ── Known malicious / suspicious package patterns (updated from threat intel) ─
# Based on ClawHub poisoning campaign indicators and typosquat patterns
_SUSPICIOUS_PACKAGE_PATTERNS = [
    re.compile(r"(?i)@modelcontextprotocol/server-(?!filesystem|brave|github|gitlab|postgres|sqlite|memory|puppeteer|everything|fetch|gdrive|slack|time|sequential-thinking)[\w\-]+$"),
    re.compile(r"(?i)mcp-server-(?!filesystem|memory|time|fetch|brave|github)[\w\-]+-(?:free|fast|lite|pro|plus)$"),
    re.compile(r"(?i)mcp[-_]?tools?[-_]?(?:all|suite|pack|bundle)"),
]

# Typosquatting patterns targeting official packages
_TYPOSQUAT_TARGETS = {
    "@modelcontextprotocol/sdk": [
        "@modelcontextprotocol/sdkk",
        "@modelcontextprotocols/sdk",
        "@modelcontextprot0col/sdk",
        "modelcontextprotocol-sdk",
    ],
    "@anthropic-ai/mcp": [
        "@anthropic-ai/mcpp",
        "@anthropic_ai/mcp",
        "anthropic-ai-mcp",
    ],
}

# Packages that should never appear in a production MCP deployment
_FORBIDDEN_PACKAGES = {
    "reverse-shell",
    "shell-exec",
    "node-pty",         # terminal emulator — rarely needed in MCP
    "child-process-promise",
}


def audit_supply_chain(config: MCPConfig) -> list[Finding]:
    findings: list[Finding] = []
    for server in config.servers:
        findings.extend(_check_unpinned_packages(server))
        findings.extend(_check_suspicious_packages(server))
        findings.extend(_check_typosquatting(server))
        findings.extend(_check_forbidden_packages(server))
        findings.extend(_check_npx_without_integrity(server))
    return findings


# ── Per-check functions ───────────────────────────────────────────────────────

def _check_unpinned_packages(server: MCPServerConfig) -> list[Finding]:
    """Flag packages used without a pinned version — resolved at runtime."""
    findings = []

    # Look for npx -y patterns without version pins
    args_str = " ".join(server.args)

    # Pattern: npx -y @scope/package  (no @version)
    unpinned = re.findall(
        r"npx\s+(?:-y\s+)?(@[\w\-/]+|[\w\-]+)(?!\s*@[\d])",
        args_str,
    )
    unpinned = [p for p in unpinned if not p.startswith("-")]

    if unpinned:
        findings.append(Finding(
            id="T4.2",
            title="MCP Server Uses Packages Without Pinned Versions",
            severity=Severity.MEDIUM,
            category=Category.SUPPLY_CHAIN,
            description=(
                f"Server '{server.name}' uses the following packages without pinning to a "
                f"specific version: {unpinned}. Unpinned packages resolve to the 'latest' "
                "version at runtime, meaning a malicious package release — or a supply chain "
                "compromise of the package maintainer — would automatically affect this deployment "
                "at the next invocation without any configuration change."
            ),
            affected_component=f"Server '{server.name}' — package args",
            evidence=f"Unpinned packages detected: {unpinned}",
            remediation=(
                "1. Pin all packages to specific, verified versions: "
                "e.g. npx -y @modelcontextprotocol/server-filesystem@1.2.3\n"
                "2. Verify package hashes after download using npm audit or package-lock.json.\n"
                "3. Use a private registry mirror for production deployments.\n"
                "4. Subscribe to security advisories for all MCP packages in use.\n"
                "See: hardening/remediation_playbooks/PB-004-supply-chain-controls.md"
            ),
            owasp_ref="ASI04",
        ))

    return findings


def _check_suspicious_packages(server: MCPServerConfig) -> list[Finding]:
    """Flag packages matching suspicious naming patterns from threat intel."""
    findings = []
    args_str = " ".join(server.args)

    for pattern in _SUSPICIOUS_PACKAGE_PATTERNS:
        match = pattern.search(args_str)
        if match:
            matched_pkg = match.group(0)
            findings.append(Finding(
                id="T4.1",
                title=f"Suspicious Package Name Pattern Detected: {matched_pkg}",
                severity=Severity.HIGH,
                category=Category.SUPPLY_CHAIN,
                description=(
                    f"Server '{server.name}' references a package matching a suspicious "
                    "naming pattern associated with the ClawHub supply chain poisoning campaign "
                    "or known MCP typosquatting tactics. This does not confirm the package is "
                    "malicious, but warrants immediate manual verification. "
                    "At peak, 1,184 malicious skills were confirmed in MCP registries."
                ),
                affected_component=f"Server '{server.name}' — package: {matched_pkg}",
                evidence=f"Matched suspicious pattern: {pattern.pattern}\nPackage: {matched_pkg}",
                remediation=(
                    "1. Manually verify this package on the npm registry — check publish date, "
                    "maintainer history, and download count.\n"
                    "2. Review the package source code on GitHub before using it.\n"
                    "3. Check the package against the ClawHub security advisory list.\n"
                    "4. Replace with an officially maintained alternative if possible."
                ),
                owasp_ref="ASI04",
                references=[
                    "https://www.antiy.com/response/clawHub-campaign.html",
                ],
            ))

    return findings


def _check_typosquatting(server: MCPServerConfig) -> list[Finding]:
    """Check for typosquatted package names targeting official MCP packages."""
    findings = []
    args_str = " ".join(server.args)

    for official_pkg, typosquats in _TYPOSQUAT_TARGETS.items():
        for fake_pkg in typosquats:
            if fake_pkg.lower() in args_str.lower():
                findings.append(Finding(
                    id="T4.1-b",
                    title=f"Possible Typosquatted Package: {fake_pkg}",
                    severity=Severity.CRITICAL,
                    category=Category.SUPPLY_CHAIN,
                    description=(
                        f"Server '{server.name}' references '{fake_pkg}', which appears to be "
                        f"a typosquat of the official package '{official_pkg}'. "
                        "Typosquatted packages are designed to be installed accidentally and "
                        "commonly contain malware, credential stealers, or backdoors."
                    ),
                    affected_component=f"Server '{server.name}' — package: {fake_pkg}",
                    evidence=f"Package: {fake_pkg!r} resembles official: {official_pkg!r}",
                    remediation=(
                        f"Remove {fake_pkg!r} immediately and replace with "
                        f"the official package {official_pkg!r}. "
                        "Rotate any credentials that may have been exposed."
                    ),
                    owasp_ref="ASI04",
                ))

    return findings


def _check_forbidden_packages(server: MCPServerConfig) -> list[Finding]:
    """Flag packages that should never appear in an MCP deployment."""
    findings = []
    args_str = " ".join(server.args)

    for pkg in _FORBIDDEN_PACKAGES:
        if pkg in args_str:
            findings.append(Finding(
                id="T4.1-c",
                title=f"Prohibited Package in MCP Configuration: {pkg}",
                severity=Severity.HIGH,
                category=Category.SUPPLY_CHAIN,
                description=(
                    f"Server '{server.name}' references '{pkg}', a package that has no "
                    "legitimate use case in a standard MCP deployment and is commonly "
                    "associated with malicious activity or unnecessary attack surface expansion."
                ),
                affected_component=f"Server '{server.name}' — package: {pkg}",
                evidence=f"Prohibited package reference: {pkg}",
                remediation=(
                    f"Remove '{pkg}' from the MCP server configuration. "
                    "If there is a genuine use case, document it and have it reviewed "
                    "by a security team before reinstatement."
                ),
                owasp_ref="ASI04",
            ))

    return findings


def _check_npx_without_integrity(server: MCPServerConfig) -> list[Finding]:
    """
    Flag use of npx -y (auto-install without confirmation) in production configs.
    """
    findings = []

    if server.command in ("npx", "bunx") and "-y" in server.args:
        findings.append(Finding(
            id="T4.2-b",
            title="npx -y Used Without Integrity Verification",
            severity=Severity.MEDIUM,
            category=Category.SUPPLY_CHAIN,
            description=(
                f"Server '{server.name}' uses 'npx -y' which auto-installs packages "
                "without user confirmation or integrity verification. In production "
                "environments, this means a newly published malicious version of a package "
                "would be auto-installed and executed the next time this server starts."
            ),
            affected_component=f"Server '{server.name}' — command: {server.command} -y",
            evidence=f"Command: {server.command}, args include -y: {server.args}",
            remediation=(
                "1. Replace 'npx -y' with a proper npm install to a local node_modules "
                "directory with a locked package-lock.json.\n"
                "2. Alternatively, use npx with a pinned version and integrity hash.\n"
                "3. In CI/CD, use 'npm ci' instead of 'npm install' to enforce lock file use."
            ),
            owasp_ref="ASI04",
        ))

    return findings
