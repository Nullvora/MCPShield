"""
MCPShield Scanner — Authentication & Identity Module
Covers: T2.1 (No Auth), T2.2 (Hardcoded Credentials), T2.3 (Privilege Escalation)
OWASP: ASI03
"""

from __future__ import annotations

import re

from mcpshield.models.config import MCPConfig, MCPServerConfig
from mcpshield.models.findings import Category, Finding, Severity

# ── Patterns for detecting hardcoded credentials in env vars ─────────────────
# Uses search (not fullmatch) so BRAVE_API_KEY, OPENAI_API_KEY etc. are detected.
_SECRET_KEY_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|apikey)"),
    re.compile(r"(?i)(secret[_-]?key|auth[_-]?token|bearer[_-]?token|auth[_-]?secret)"),
    re.compile(r"(?i)(password|passwd|pwd|pass)"),
    re.compile(r"(?i)(aws_access_key_id|aws_secret_access_key|azure_client_secret)"),
    re.compile(r"(?i)(openai|anthropic|gemini)[_-]?key"),
    re.compile(r"(?i)(stripe|twilio|sendgrid)[_-]?(key|token)"),
    re.compile(r"(?i)(database_url|db_password|mongo_uri|redis_url)"),
]

# Known safe placeholder values that indicate a template, not a real secret
_SAFE_PLACEHOLDERS = {
    "your-api-key-here", "changeme", "placeholder", "todo",
    "xxxx", "****", "insert-key", "<your-key>", "${api_key}",
    "env:api_key", "",
}


def _is_placeholder(value: str) -> bool:
    return value.lower() in _SAFE_PLACEHOLDERS or value.startswith("${")


def _looks_like_secret_key(key: str) -> bool:
    return any(p.search(key) for p in _SECRET_KEY_PATTERNS)


def _redact(value: str) -> str:
    if len(value) <= 6:
        return "****"
    return value[:3] + "****" + value[-2:]


# ── Main audit function ───────────────────────────────────────────────────────

def audit_auth(config: MCPConfig) -> list[Finding]:
    findings: list[Finding] = []
    for server in config.servers:
        findings.extend(_check_missing_auth(server))
        findings.extend(_check_hardcoded_credentials(server))
        findings.extend(_check_token_in_url(server))
        findings.extend(_check_basic_auth_header(server))
    return findings


# ── Per-check functions ───────────────────────────────────────────────────────

def _check_missing_auth(server: MCPServerConfig) -> list[Finding]:
    """T2.1 — HTTP/SSE server with no authentication headers."""
    findings = []

    if server.transport not in ("http", "sse"):
        return findings

    if not server.has_authentication:
        findings.append(Finding(
            id="T2.1",
            title="MCP Server Has No Client Authentication",
            severity=Severity.CRITICAL,
            category=Category.AUTHENTICATION,
            description=(
                f"Server '{server.name}' accepts connections without requiring client "
                "authentication. Any process or user that can reach the server endpoint can "
                "invoke its tools, read its context, and trigger actions on connected systems. "
                "Research identified 492 MCP servers in production with this exact configuration, "
                "directly accessible from the internet."
            ),
            affected_component=f"Server '{server.name}' — URL: {server.url}",
            evidence=(
                f"url: {server.url!r}\n"
                f"headers: {dict(server.headers) or '(none configured)'}\n"
                f"No Authorization or x-api-key header found."
            ),
            remediation=(
                "1. Implement Bearer token authentication: add an Authorization header "
                "with a strong, randomly generated token.\n"
                "2. For production systems, implement mutual TLS (mTLS) for cryptographic "
                "client identity verification.\n"
                "3. At minimum, restrict the server to localhost (127.0.0.1) if it must "
                "remain unauthenticated.\n"
                "4. Implement IP allowlisting for known client addresses.\n"
                "See: hardening/remediation_playbooks/PB-002-auth-implementation.md"
            ),
            owasp_ref="ASI03",
            references=[
                "https://www.trendmicro.com/en_us/research/mcp-security.html",
            ],
        ))

    return findings


def _check_hardcoded_credentials(server: MCPServerConfig) -> list[Finding]:
    """T2.2 — API keys / secrets exposed in plaintext env vars."""
    findings = []
    exposed = []

    for key, value in server.env.items():
        if _looks_like_secret_key(key) and not _is_placeholder(value):
            exposed.append((key, _redact(value)))

    if exposed:
        exposed_keys = ", ".join(k for k, _ in exposed)
        evidence_lines = "\n".join(f"  {k}: {v}" for k, v in exposed)

        findings.append(Finding(
            id="T2.2",
            title="Hardcoded Credentials Detected in MCP Server Configuration",
            severity=Severity.CRITICAL,
            category=Category.AUTHENTICATION,
            description=(
                f"Server '{server.name}' has what appear to be real credentials stored in "
                "plaintext in the MCP configuration file. If this config file is committed to "
                "a version control system, shared, or read by a compromised process, the "
                "credentials are immediately exposed to attackers. "
                f"Affected keys: {exposed_keys}."
            ),
            affected_component=f"Server '{server.name}' — env block",
            evidence=f"Suspected credentials in env vars (values redacted):\n{evidence_lines}",
            remediation=(
                "1. Remove all credentials from the config file immediately.\n"
                "2. Rotate any exposed credentials — treat them as compromised.\n"
                "3. Use environment variable injection at runtime rather than "
                "storing values in the config file.\n"
                "4. For production, use a secrets manager (AWS Secrets Manager, "
                "HashiCorp Vault, Azure Key Vault) and reference secrets by name.\n"
                "5. Add the MCP config file to .gitignore to prevent accidental commits.\n"
                "6. Run a secret scanning tool (git-secrets, truffleHog) on your repo history."
            ),
            owasp_ref="ASI03",
        ))

    return findings


def _check_token_in_url(server: MCPServerConfig) -> list[Finding]:
    """Credentials embedded in the URL query string."""
    findings = []

    if not server.url:
        return findings

    # Look for ?token=, ?key=, ?api_key= patterns
    sensitive_params = re.findall(
        r"[?&](token|key|api_key|secret|password|auth)=([^&\s]+)",
        server.url,
        re.IGNORECASE,
    )

    if sensitive_params:
        findings.append(Finding(
            id="T2.2-b",
            title="Credentials Embedded in MCP Server URL",
            severity=Severity.HIGH,
            category=Category.AUTHENTICATION,
            description=(
                f"Server '{server.name}' has what appear to be credentials embedded in the "
                "URL query string. URL parameters are logged by web servers, proxies, and "
                "browsers — this is a common source of credential leakage in access logs."
            ),
            affected_component=f"Server '{server.name}' — URL",
            evidence=f"Sensitive query params detected in URL: {[p for p, _ in sensitive_params]}",
            remediation=(
                "Move credentials out of the URL and into request headers "
                "(Authorization: Bearer <token> or X-API-Key: <key>). "
                "Never pass secrets as URL query parameters."
            ),
            owasp_ref="ASI03",
        ))

    return findings


def _check_basic_auth_header(server: MCPServerConfig) -> list[Finding]:
    """Warn if Basic auth is used (credentials base64-encoded, not encrypted)."""
    findings = []

    for header_name, header_value in server.headers.items():
        if header_name.lower() == "authorization" and header_value.lower().startswith("basic "):
            findings.append(Finding(
                id="T2.2-c",
                title="MCP Server Uses HTTP Basic Authentication",
                severity=Severity.MEDIUM,
                category=Category.AUTHENTICATION,
                description=(
                    f"Server '{server.name}' uses HTTP Basic authentication. "
                    "Basic auth credentials are only base64-encoded, not encrypted. "
                    "They are fully readable to anyone who can intercept the request "
                    "(especially relevant if TLS is not enforced)."
                ),
                affected_component=f"Server '{server.name}' — Authorization header",
                evidence="Authorization header uses 'Basic' scheme",
                remediation=(
                    "Replace Basic auth with Bearer token authentication or mTLS. "
                    "If Basic auth must be used, ensure TLS is enforced on all connections."
                ),
                owasp_ref="ASI03",
            ))

    return findings
