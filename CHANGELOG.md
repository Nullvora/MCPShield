# Changelog

All notable changes to MCPShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-23

### Added
- Initial release of MCPShield — the first open-source security assessment, hardening, and runtime monitoring framework for Model Context Protocol (MCP) deployments.
- **Scanner module** with five security assessment sub-modules:
  - Transport security audit (STDIO RCE detection, TLS enforcement, SSRF surface identification, SDK version checks)
  - Authentication & identity audit (missing auth detection, hardcoded credential scanning, token-in-URL detection, Basic auth warnings)
  - Prompt injection detection (role-override patterns, exfiltration instructions, tool chaining detection, env var injection scanning)
  - Supply chain security (unpinned packages, suspicious package patterns, typosquatting detection, forbidden packages, npx -y warnings)
  - Privilege & permissions audit (high-privilege tool capability mapping, dangerous argument combinations, filesystem path scope analysis)
- **Runtime monitor** with behavioral anomaly detection, policy enforcement, and tamper-evident audit logging.
- **Reporter module** with console (Rich), HTML, and JSON output formats.
- **CLI** with `scan`, `monitor`, `verify`, and `report` commands.
- Comprehensive **threat model** mapped to OWASP ASI Top 10 for Agentic Applications.
- **50-point hardening checklist** with four remediation playbooks and configuration templates.
- **Red team attack scenarios** documenting six real-world MCP attack patterns.
- Support for three MCP config formats (Claude Desktop, server list, direct object).
- CVE tracking for CVE-2025-49596, CVE-2026-21852, CVE-2026-22252.

### Security
- All findings include OWASP ASI references and CVE links where applicable.
- Audit logger uses SHA-256 hash chaining for tamper evidence.
- Credential redaction in audit logs by default.

[0.1.0]: https://github.com/Nullvora/MCPShield/releases/tag/v0.1.0
