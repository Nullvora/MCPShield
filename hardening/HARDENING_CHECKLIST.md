# MCPShield Hardening Checklist
## 50-Point MCP Security Checklist

**Version:** 1.0 | **Author:** James Boamah — Nullvora  
**Use:** Complete this checklist before deploying any MCP server in a production environment.

---

## Section 1 — Transport Security (10 Points)

- [ ] **H1.1** All HTTP/SSE MCP connections use TLS 1.2 minimum (TLS 1.3 preferred)
- [ ] **H1.2** TLS certificates are from a trusted CA and validated — self-signed certs not used in production
- [ ] **H1.3** STDIO transport is restricted to trusted, controlled local process environments only
- [ ] **H1.4** No MCP server is exposed to the public internet without authentication and TLS
- [ ] **H1.5** SSRF defences are active — block requests to RFC-1918 ranges and cloud metadata endpoints
- [ ] **H1.6** All MCP SDK packages are patched to versions >= 1.3.1 (CVE-2025-49596 / CVE-2026-22252)
- [ ] **H1.7** STDIO servers are never wrapped in bare shell commands (bash -c, sh -c)
- [ ] **H1.8** MCP server processes run under dedicated least-privilege OS accounts (not root)
- [ ] **H1.9** Network egress from MCP servers is restricted to allowlisted destinations
- [ ] **H1.10** HTTP Strict Transport Security (HSTS) is enforced on all HTTP-accessible MCP endpoints

## Section 2 — Authentication & Identity (10 Points)

- [ ] **H2.1** All HTTP/SSE MCP servers require client authentication (Bearer token minimum)
- [ ] **H2.2** Production environments use mutual TLS (mTLS) for cryptographic client identity
- [ ] **H2.3** Authentication tokens are randomly generated with >= 256 bits of entropy
- [ ] **H2.4** No credentials are stored in the MCP config file — all secrets injected at runtime
- [ ] **H2.5** The MCP config file is excluded from version control (.gitignore)
- [ ] **H2.6** All previously exposed credentials have been rotated
- [ ] **H2.7** Credentials are managed via a secrets manager (Vault, AWS Secrets Manager, etc.)
- [ ] **H2.8** Multi-agent systems implement cryptographic agent identity — agents cannot be impersonated
- [ ] **H2.9** Agent identity tokens have short expiry and are rotated regularly
- [ ] **H2.10** Failed authentication attempts are logged and alerted on

## Section 3 — Tool Definitions & Injection Prevention (10 Points)

- [ ] **H3.1** All tool definitions are audited for embedded natural language instructions
- [ ] **H3.2** Tool descriptions describe functionality only — no instructions to the model
- [ ] **H3.3** Tool definitions are version-controlled and integrity-checked (signed/hashed)
- [ ] **H3.4** Unauthorised changes to tool definitions trigger an alert
- [ ] **H3.5** All externally-fetched content is sanitised before being returned to the model
- [ ] **H3.6** The system prompt explicitly instructs the model to treat tool response content as potentially adversarial
- [ ] **H3.7** Tool parameter inputs are validated and sanitised (type, length, allowlisted values)
- [ ] **H3.8** External data sources used by agents are treated as untrusted — not directly injected into context
- [ ] **H3.9** Injection indicator phrases are monitored in real-time on all tool call parameters
- [ ] **H3.10** Tool output sanitisation strips HTML, control characters, and injection marker phrases

## Section 4 — Supply Chain Security (8 Points)

- [ ] **H4.1** All MCP packages are pinned to specific, verified versions in configuration
- [ ] **H4.2** Package hashes are verified after download (package-lock.json / requirements.txt hashes)
- [ ] **H4.3** Private/curated registry is used for production — public registry not consumed directly
- [ ] **H4.4** All installed MCP packages are scanned against known vulnerability databases
- [ ] **H4.5** CVE advisories for MCP-related packages are subscribed to and acted on
- [ ] **H4.6** Pre-installation scanning runs before any new MCP package is deployed
- [ ] **H4.7** Supply chain audit runs as part of CI/CD pipeline
- [ ] **H4.8** npx -y (auto-install without confirmation) is not used in production configs

## Section 5 — Privilege & Permissions (7 Points)

- [ ] **H5.1** Each MCP tool has documented, minimal required permissions
- [ ] **H5.2** Filesystem servers are restricted to specific directories — not root or home
- [ ] **H5.3** Database connections use read-only users where write access is not required
- [ ] **H5.4** Git/repository access uses fine-grained tokens scoped to specific repos
- [ ] **H5.5** Cloud tool access uses least-privilege IAM roles with resource-level policies
- [ ] **H5.6** Agent permissions are reviewed quarterly and reduced where possible
- [ ] **H5.7** High-privilege tool combinations (read + write + network) require documented approval

## Section 6 — Runtime Monitoring & Audit (5 Points)

- [ ] **H6.1** MCPShield runtime monitor (or equivalent) is deployed and active
- [ ] **H6.2** All MCP tool calls are logged with full parameters to a tamper-evident audit trail
- [ ] **H6.3** Audit log integrity is verified regularly (hash chain verification)
- [ ] **H6.4** Anomaly alerts are routed to a security operations channel (Slack, PagerDuty, etc.)
- [ ] **H6.5** Audit logs are retained for minimum 90 days and protected from deletion

---

## Scoring

| Score     | Status       | Recommended Action |
|---|---|---|
| 45–50     | ✅ Hardened  | Maintain and review quarterly |
| 35–44     | ⚠️ Acceptable | Address remaining gaps within 30 days |
| 25–34     | 🟠 At Risk   | Address critical gaps within 7 days |
| Below 25  | 🔴 Vulnerable | Do not deploy to production |

---

*MCPShield Hardening Checklist v1.0 — Nullvora | github.com/Nullvora/MCPShield*
