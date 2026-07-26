"""
MCPShield Scanner — Privilege & Permissions Module
Covers: T2.3 (Privilege Escalation via Tool Chains), Over-privileged tool scopes
OWASP: ASI02, ASI03
"""

from __future__ import annotations

import re

from mcpshield.models.config import MCPConfig, MCPServerConfig
from mcpshield.models.findings import Category, Finding, Severity

# ── High-privilege tool capability indicators ────────────────────────────────

_HIGH_PRIV_INDICATORS = {
    "filesystem": {
        "keywords": ["filesystem", "file-system", "server-filesystem", "read-file", "write-file"],
        "risk": "Full file system access — can read sensitive files including SSH keys, "
                "credential stores, and application secrets.",
        "recommended_scope": "Restrict to specific directories using --allowed-paths arg.",
    },
    "code_execution": {
        "keywords": ["execute", "run-code", "code-runner", "shell", "subprocess", "eval"],
        "risk": "Code execution capability — can run arbitrary commands on the host system.",
        "recommended_scope": "Restrict to a sandboxed, isolated execution environment with "
                             "no network access and a read-only filesystem.",
    },
    "network_access": {
        "keywords": ["fetch", "http", "browser", "puppeteer", "playwright", "crawl", "browse"],
        "risk": "Network access — can make outbound requests to arbitrary hosts, "
                "potentially enabling data exfiltration and SSRF.",
        "recommended_scope": "Restrict to an allowlist of permitted domains.",
    },
    "email_access": {
        "keywords": ["gmail", "outlook", "email", "smtp", "imap", "mail", "sendgrid"],
        "risk": "Email access — can read inbox contents (sensitive communications) and "
                "send emails (phishing, exfiltration via email).",
        "recommended_scope": "Restrict to read-only access for specific folders. Require "
                             "human approval for any send operation.",
    },
    "database_access": {
        "keywords": ["postgres", "mysql", "sqlite", "database", "mongodb", "redis", "sql"],
        "risk": "Database access — depending on permissions, can read, modify, or delete data.",
        "recommended_scope": "Use a read-only database user where possible. Restrict to "
                             "specific tables/schemas needed for the use case.",
    },
    "git_access": {
        "keywords": ["github", "gitlab", "git", "repo", "repository"],
        "risk": "Repository access — can read source code, secrets in code, and potentially "
                "push commits if write access is granted.",
        "recommended_scope": "Use a fine-grained PAT with read-only access to specific repos.",
    },
    "cloud_access": {
        "keywords": ["aws", "azure", "gcp", "cloud", "s3", "lambda", "ec2", "iam"],
        "risk": "Cloud service access — can interact with cloud infrastructure, "
                "potentially modifying resources or exfiltrating cloud credentials.",
        "recommended_scope": "Use least-privilege IAM roles. Apply resource-level policies.",
    },
}

# Dangerous argument combinations that suggest over-broad scope
_DANGEROUS_ARG_COMBOS = [
    (["--allow-write", "--allow-net"],   "Read+write filesystem with network — enables exfiltration"),
    (["/", "~", "$HOME"],               "Root or home directory access — overly broad filesystem scope"),
    (["--all", "--full-access"],        "Full access flags — violates least privilege"),
]


def audit_privilege(config: MCPConfig) -> list[Finding]:
    findings: list[Finding] = []
    for server in config.servers:
        findings.extend(_check_high_privilege_tools(server))
        findings.extend(_check_dangerous_arg_combos(server))
        findings.extend(_check_path_scope(server))
    return findings


def _check_high_privilege_tools(server: MCPServerConfig) -> list[Finding]:
    findings = []
    args_str = " ".join(server.args).lower()
    name_lower = server.name.lower()
    search_str = f"{name_lower} {args_str}"

    for capability, info in _HIGH_PRIV_INDICATORS.items():
        if any(kw in search_str for kw in info["keywords"]):
            findings.append(Finding(
                id="T2.3",
                title=f"High-Privilege Tool Capability: {capability.replace('_', ' ').title()}",
                severity=Severity.MEDIUM,
                category=Category.PRIVILEGE,
                description=(
                    f"Server '{server.name}' provides {capability.replace('_', ' ')} capability. "
                    f"{info['risk']} "
                    "High-privilege tools must be scoped to their minimum required access — "
                    "an agent with broader permissions than it needs is a larger blast radius "
                    "target when compromised."
                ),
                affected_component=f"Server '{server.name}' — capability: {capability}",
                evidence=f"Capability detected from name/args: {capability}",
                remediation=(
                    f"Apply least-privilege scoping: {info['recommended_scope']}\n"
                    "Document the specific access required and review periodically.\n"
                    "See: hardening/config_templates/tool_permission_policy.json"
                ),
                owasp_ref="ASI03",
            ))

    return findings


def _check_dangerous_arg_combos(server: MCPServerConfig) -> list[Finding]:
    findings = []

    for combo, description in _DANGEROUS_ARG_COMBOS:
        if all(arg in " ".join(server.args) for arg in combo):
            findings.append(Finding(
                id="T2.3-b",
                title=f"Dangerous Argument Combination: {' + '.join(combo)}",
                severity=Severity.HIGH,
                category=Category.PRIVILEGE,
                description=(
                    f"Server '{server.name}' uses a combination of arguments that together "
                    f"create an elevated risk profile: {description}."
                ),
                affected_component=f"Server '{server.name}' — args: {combo}",
                evidence=f"Detected args: {[a for a in combo if a in ' '.join(server.args)]}",
                remediation=(
                    "Review whether all of these permissions are simultaneously necessary. "
                    "Apply the principle of least privilege — grant each capability only when "
                    "it is strictly required for the server's stated purpose."
                ),
                owasp_ref="ASI02",
            ))

    return findings


def _check_path_scope(server: MCPServerConfig) -> list[Finding]:
    """Check if filesystem servers are scoped to overly broad paths."""
    findings = []

    if server.transport != "stdio":
        return findings

    args_str = " ".join(server.args)
    is_filesystem_server = any(
        kw in f"{server.name} {args_str}".lower()
        for kw in ["filesystem", "file-system"]
    )

    if not is_filesystem_server:
        return findings

    broad_paths = []
    for arg in server.args:
        if arg in ("/", "~", "/home", "/Users", "/root"):
            broad_paths.append(arg)
        if re.match(r"^[A-Za-z]:\\\\?$", arg):  # Windows root
            broad_paths.append(arg)

    if broad_paths:
        findings.append(Finding(
            id="T2.3-c",
            title="Filesystem MCP Server Scoped to Overly Broad Path",
            severity=Severity.HIGH,
            category=Category.PRIVILEGE,
            description=(
                f"Server '{server.name}' has filesystem access scoped to a broad path: "
                f"{broad_paths}. This grants the AI agent read (and potentially write) "
                "access to the entire filesystem, including SSH keys (~/.ssh), shell history, "
                "application credentials, and other sensitive files."
            ),
            affected_component=f"Server '{server.name}' — path args: {broad_paths}",
            evidence=f"Broad path args detected: {broad_paths}",
            remediation=(
                "Restrict the allowed path to the minimum directory the agent needs:\n"
                "e.g. change '/' to '/home/user/agent-workspace' or '/app/data'\n"
                "Never grant root, home directory, or OS-level path access to an MCP agent."
            ),
            owasp_ref="ASI03",
        ))

    return findings
