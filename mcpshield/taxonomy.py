# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Threat taxonomies MCPShield maps its findings to.

* OWASP MCP Top 10 (2025)            — https://owasp.org/www-project-mcp-top-10/
* OWASP Top 10 for Agentic Apps 2026 — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

from __future__ import annotations

OWASP_MCP: dict[str, str] = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Prompt Injection via Contextual Payloads",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

OWASP_ASI: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


def owasp_mcp_url(ref: str) -> str:
    return "https://owasp.org/www-project-mcp-top-10/"


def label(ref: str) -> str:
    """Return 'MCP03 Tool Poisoning' style label for a taxonomy reference."""
    if ref in OWASP_MCP:
        return f"{ref} {OWASP_MCP[ref]}"
    if ref in OWASP_ASI:
        return f"{ref} {OWASP_ASI[ref]}"
    return ref
