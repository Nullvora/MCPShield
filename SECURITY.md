# Security Policy

MCPShield is a security tool, so we hold it to a high bar. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

- Preferred: GitHub → *Security* → *Report a vulnerability* (private advisory) on `Nullvora/MCPShield`
- Or e-mail **security@nullvora.com** (include "MCPShield" in the subject)

Please include the affected version, a description, reproduction steps or proof of concept, and impact.
We aim to acknowledge within **3 business days**, give an initial assessment within **7 days**, and ship a fix for
confirmed high/critical issues within **30 days**, coordinating disclosure with you. We credit reporters who wish to be named.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0 (pre-release prototypes) | ❌ |

## Scope

In scope: the `mcpshield` package, CLI, runtime proxy, HTML/SARIF reporters, the GitHub Action and the container image.
Examples: detection bypasses in the proxy policy engine, audit-log forgery, XSS in reports, SSRF from probes,
command execution triggered by scanning a malicious config.

Out of scope: findings in third-party MCP servers (report those to their maintainers — and consider sending us a
detection or advisory PR), and the deliberately malicious fixtures under `tests/fixtures/servers/`.

## Safe-by-design notes

- Static scans never execute anything. `--live` **does** start stdio servers from the scanned config — only use it on
  configurations you would run anyway, ideally inside a container or VM.
- Live scans only *list* tools/prompts/resources; MCPShield never calls tools and refuses server-initiated sampling,
  elicitation and roots requests.
- HTTP probes pre-check OAuth metadata destinations and disable redirects. DNS rebinding remains a limitation: use network egress restrictions for untrusted endpoints.
- Reports redact recognized secret patterns and HTML-escape displayed content. Review reports manually before sharing; redaction is not comprehensive.

See [LIMITATIONS.md](docs/LIMITATIONS.md) for guard scope, log privacy and residual risks.
