"""
MCPShield Scanner — Prompt Injection Module
Covers: T3.1 (Tool Definition Hijacking), T3.2 (Indirect Injection Surface)
OWASP: ASI01
"""

from __future__ import annotations

import re

from mcpshield.models.config import MCPConfig, MCPServerConfig
from mcpshield.models.findings import Category, Finding, Severity

# ── Injection indicator patterns in tool descriptions / metadata ─────────────

# Role-override phrases that suggest injected instructions
_ROLE_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)ignore\s+(previous|prior|above|all)\s+(instructions?|commands?|prompts?)"),
    re.compile(r"(?i)you\s+are\s+now\s+(in\s+)?(maintenance|debug|admin|developer)\s+mode"),
    re.compile(r"(?i)disregard\s+(your\s+)?(previous|prior|system)\s+(prompt|instructions?)"),
    re.compile(r"(?i)new\s+(role|persona|identity|instructions?)[\s:]+"),
    re.compile(r"(?i)act\s+as\s+(if|though)?\s+(you\s+are\s+)?(a\s+)?(?!an?\s+\w+\s+tool)"),
    re.compile(r"(?i)from\s+now\s+on[\s,]"),
    re.compile(r"(?i)override\s+(safety|security|restriction|policy|guideline)"),
]

# Exfiltration instruction patterns
_EXFIL_PATTERNS = [
    re.compile(r"(?i)(send|forward|email|post|transmit|upload|exfiltrate)\s+.{0,40}(to|at)\s+\S+@\S+"),
    re.compile(r"(?i)(send|post|transmit)\s+.{0,40}(http|https|ftp)s?://"),
    re.compile(r"(?i)(leak|steal|extract|dump)\s+(credential|secret|key|token|password|data)"),
    re.compile(r"(?i)call\s+\w+_tool\s+with\s+.{0,60}(context|history|conversation|secret|key)"),
]

# Suspicious tool chaining instructions
_CHAIN_PATTERNS = [
    re.compile(r"(?i)after\s+(returning|completing|this)\s*.{0,30}(also|then)\s+(call|invoke|run|execute)"),
    re.compile(r"(?i)before\s+(responding|returning)\s*.{0,30}(first|always)\s+(call|invoke|run)"),
    re.compile(r"(?i)in\s+addition\s+to\s+.{0,40}(call|invoke|also\s+run)"),
]

# Patterns suggesting tool fetches external content that could be injected
_EXTERNAL_FETCH_PATTERNS = [
    re.compile(r"(?i)(fetch|retrieve|download|get|read|load)\s+.{0,30}(from\s+)?(url|web|internet|external|http)"),
    re.compile(r"(?i)(browse|visit|open)\s+.{0,30}(url|link|page|site|website)"),
    re.compile(r"(?i)(read|process|parse)\s+.{0,30}(email|document|file|attachment)"),
]


# ── Main audit function ───────────────────────────────────────────────────────

def audit_injection(config: MCPConfig) -> list[Finding]:
    """
    Analyse server configurations for prompt injection risks.
    Note: full tool-definition scanning requires a live server connection;
    this module performs static analysis on the available config.
    """
    findings: list[Finding] = []
    for server in config.servers:
        findings.extend(_check_tool_args_for_injection(server))
        findings.extend(_check_external_fetch_surface(server))
        findings.extend(_check_injection_in_env(server))
    return findings


# ── Per-check functions ───────────────────────────────────────────────────────

def _check_tool_args_for_injection(server: MCPServerConfig) -> list[Finding]:
    """
    Scan args and any inline strings for known injection indicator patterns.
    Flags T3.1 — tool definition hijacking.
    """
    findings = []
    args_blob = " ".join(server.args)

    triggered_override = [p.pattern for p in _ROLE_OVERRIDE_PATTERNS if p.search(args_blob)]
    triggered_exfil = [p.pattern for p in _EXFIL_PATTERNS if p.search(args_blob)]
    triggered_chain = [p.pattern for p in _CHAIN_PATTERNS if p.search(args_blob)]

    if triggered_override:
        findings.append(Finding(
            id="T3.1",
            title="Role-Override Injection Pattern Detected in MCP Server Args",
            severity=Severity.CRITICAL,
            category=Category.INJECTION,
            description=(
                f"Server '{server.name}' contains args that match known prompt injection "
                "patterns targeting role override. An MCP tool definition that contains "
                "these phrases can hijack the AI model's behaviour, causing it to ignore "
                "its system prompt and follow attacker-supplied instructions instead."
            ),
            affected_component=f"Server '{server.name}' — args",
            evidence=f"Matched patterns: {triggered_override[:3]}\nIn args: {args_blob[:300]}",
            remediation=(
                "1. Audit all tool definitions for embedded natural language instructions.\n"
                "2. Tool descriptions should describe what the tool does, not instruct the model.\n"
                "3. Implement a tool definition integrity check — sign and version-pin definitions.\n"
                "4. Monitor tool definitions for unauthorised changes.\n"
                "See: hardening/remediation_playbooks/PB-003-injection-prevention.md"
            ),
            owasp_ref="ASI01",
        ))

    if triggered_exfil:
        findings.append(Finding(
            id="T3.1-b",
            title="Data Exfiltration Instruction Pattern Detected in Server Args",
            severity=Severity.CRITICAL,
            category=Category.INJECTION,
            description=(
                f"Server '{server.name}' args match patterns associated with data exfiltration "
                "instructions. This suggests a tool definition may be directing the AI model "
                "to transmit data to an external endpoint."
            ),
            affected_component=f"Server '{server.name}' — args",
            evidence=f"Matched exfiltration patterns: {triggered_exfil[:2]}",
            remediation=(
                "Immediately audit and remove any tool definition content that instructs "
                "the model to send, forward, or transmit data to external locations. "
                "Treat the affected server config as potentially compromised."
            ),
            owasp_ref="ASI01",
        ))

    if triggered_chain:
        findings.append(Finding(
            id="T3.1-c",
            title="Suspicious Tool Chaining Instruction Detected",
            severity=Severity.HIGH,
            category=Category.INJECTION,
            description=(
                f"Server '{server.name}' args contain patterns that instruct the model to "
                "invoke additional tools beyond the stated purpose of this tool. "
                "Unauthorised tool chaining is a common exfiltration and privilege escalation vector."
            ),
            affected_component=f"Server '{server.name}' — args",
            evidence=f"Matched chaining patterns: {triggered_chain[:2]}",
            remediation=(
                "Tool descriptions must not instruct models to invoke other tools. "
                "Audit the tool definition and remove any chaining instructions."
            ),
            owasp_ref="ASI02",
        ))

    return findings


def _check_external_fetch_surface(server: MCPServerConfig) -> list[Finding]:
    """
    T3.2 — Flag servers that fetch external content, creating an indirect injection surface.
    """
    findings = []
    args_blob = " ".join(server.args)

    fetch_patterns_matched = [p.pattern for p in _EXTERNAL_FETCH_PATTERNS if p.search(args_blob)]

    # Also check common tool names that typically fetch external content
    fetch_tool_names = {
        "fetch", "browse", "web", "browser", "search",
        "email", "gmail", "outlook", "http", "request",
        "scrape", "crawl", "read-file", "filesystem",
    }
    name_suggests_fetch = any(
        keyword in server.name.lower() for keyword in fetch_tool_names
    )

    if fetch_patterns_matched or name_suggests_fetch:
        findings.append(Finding(
            id="T3.2",
            title="MCP Tool Fetches External Content — Indirect Injection Surface",
            severity=Severity.HIGH,
            category=Category.INJECTION,
            description=(
                f"Server '{server.name}' appears to fetch external content (web pages, files, "
                "emails, or other external data sources) and return it to the AI model as context. "
                "Any external content retrieved by an agent and placed into its context window "
                "is a potential indirect prompt injection vector — an attacker who can influence "
                "that external content can hijack the agent's instructions without direct access."
            ),
            affected_component=f"Server '{server.name}'",
            evidence=(
                f"Server name suggests external fetch: {name_suggests_fetch}\n"
                f"Args patterns: {fetch_patterns_matched[:2] or '(name-based detection)'}"
            ),
            remediation=(
                "1. Treat all externally-fetched content as untrusted — do not pass raw external "
                "content directly to the model context.\n"
                "2. Implement output sanitisation: strip HTML, filter control characters, and "
                "check for injection indicator phrases before returning tool results.\n"
                "3. Consider sandboxing external content in a clearly-labelled section that "
                "instructs the model to treat it as potentially adversarial data.\n"
                "4. Instruct the model explicitly in the system prompt that tool response content "
                "may be malicious and must not override core behavioural constraints.\n"
                "See: hardening/remediation_playbooks/PB-003-injection-prevention.md"
            ),
            owasp_ref="ASI01",
        ))

    return findings


def _check_injection_in_env(server: MCPServerConfig) -> list[Finding]:
    """Check env var values for injection patterns."""
    findings = []

    for key, value in server.env.items():
        triggered = [
            p.pattern for p in (
                _ROLE_OVERRIDE_PATTERNS + _EXFIL_PATTERNS + _CHAIN_PATTERNS
            ) if p.search(value)
        ]
        if triggered:
            findings.append(Finding(
                id="T3.1-d",
                title=f"Injection Pattern in Environment Variable: {key}",
                severity=Severity.HIGH,
                category=Category.INJECTION,
                description=(
                    f"Environment variable '{key}' for server '{server.name}' contains "
                    "text matching known prompt injection patterns. If this value is passed "
                    "to the model as part of a system prompt or tool description, it could "
                    "hijack the agent's behaviour."
                ),
                affected_component=f"Server '{server.name}' — env.{key}",
                evidence=f"Matched patterns: {triggered[:2]}\nValue (first 100 chars): {value[:100]}",
                remediation=(
                    f"Review the value of environment variable '{key}'. "
                    "Remove any natural language instructions that could influence model behaviour."
                ),
                owasp_ref="ASI01",
            ))

    return findings


# ── Utility: scan a raw tool definition dict (used by live scanner) ───────────

def scan_tool_definition(tool_def: dict, server_name: str) -> list[Finding]:
    """
    Scan a raw MCP tool definition object for injection risks.
    Called when the live scanner retrieves tool definitions from a running server.
    """
    findings = []
    description = tool_def.get("description", "")
    name = tool_def.get("name", "unknown")

    all_patterns = (
        [(p, "T3.1", Severity.CRITICAL, "role override") for p in _ROLE_OVERRIDE_PATTERNS] +
        [(p, "T3.1-b", Severity.CRITICAL, "exfiltration") for p in _EXFIL_PATTERNS] +
        [(p, "T3.1-c", Severity.HIGH, "tool chaining") for p in _CHAIN_PATTERNS]
    )

    for pattern, tid, severity, label in all_patterns:
        if pattern.search(description):
            findings.append(Finding(
                id=tid,
                title=f"Injection Pattern in Tool Definition: '{name}' ({label})",
                severity=severity,
                category=Category.INJECTION,
                description=(
                    f"Tool '{name}' on server '{server_name}' has a description matching "
                    f"a {label} injection pattern. The model trusts tool descriptions as "
                    "authoritative instructions — this is a direct injection vector."
                ),
                affected_component=f"Tool '{name}' on server '{server_name}'",
                evidence=f"Pattern matched in description: {pattern.pattern}",
                remediation=(
                    "Remove the injected content from the tool description. "
                    "Tool descriptions should only describe tool functionality, "
                    "not instruct the model to take additional actions."
                ),
                owasp_ref="ASI01",
            ))

    return findings
