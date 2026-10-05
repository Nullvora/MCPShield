# MCPShield v1.1.1rc1 — Source Beta

MCPShield is an open-source security scanner, hardening checker and runtime guard for Model Context Protocol (MCP) deployments.

This release candidate focuses on safer defaults, stricter runtime behavior, stronger MCP configuration validation and better operational visibility before a wider package-registry release.

## Highlights

- Static MCP configuration auditing across major clients.
- Detection for hardcoded secrets, unsafe launch commands, vulnerable or malicious MCP packages, risky agent settings and overly broad filesystem/network access.
- Live tool inspection for tool poisoning, schema poisoning, Unicode/ASCII smuggling, misleading annotations, cross-server collisions and exfiltration-oriented parameters.
- Rug-pull detection using reviewed tool-definition pinning.
- Runtime stdio policy guard with deny rules, sensitive-path controls, result redaction, sampling denial and tamper-evident audit logging.
- OpenTelemetry-compatible agent activity tracing and lethal-trifecta session alerts.
- SARIF, JSON, Markdown, HTML and console reporting.
- GitHub Actions, pre-commit and Docker support.

## Security hardening in this candidate

- Fail closed on malformed or unsupported JSON-RPC.
- Validate policy modes and field types.
- Bound pending requests and message frames.
- Reject duplicate request IDs that could replace inspected requests.
- Require lock-backed verification before protected tool calls.
- Invalidate verified tool state after tool-list change notifications.
- Inspect all URLs embedded in arguments and tighten private-network checks.
- Make argument capture opt-in for audit and OTLP export.
- Remove the audit key from child environments.
- Use private session-specific audit logs.
- Return a non-zero incomplete-scan result even when `--fail-on none` is selected.
- Preserve monitor-mode behavior without mutating proxied output.
- Fix Windows stdio command parsing and incomplete pin/verify behavior.

## Validation

The reviewed candidate passed local validation with:

- 178 tests passed
- Ruff passed
- Mypy passed
- wheel and source distribution builds passed
- Twine package checks passed

The public GitHub Actions run on `main` has passed lint, build, Docker, self-scan, Linux, macOS and Windows 3.12/3.13 jobs. A rerun is being used to complete the remaining cancelled Windows 3.11/legacy-SDK coverage.

## Install from source

```bash
git clone https://github.com/Nullvora/MCPShield.git
cd MCPShield
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
mcpshield --version
mcpshield scan --auto
```

No API key is required for static scans.

## Beta boundaries

This is a source beta release candidate. It is not a claim of complete containment, sandboxing or independently measured detection accuracy.

The runtime guard is defense in depth. Run untrusted MCP servers with OS/container isolation and appropriate network egress controls.

Package and container registry publication remain intentionally disabled while external feedback is collected.

## Feedback

We want real-world reports from MCP developers, AI-agent engineers and security practitioners.

Please report:
- installation friction;
- false positives and false negatives;
- time to first useful finding;
- MCP client / OS / Python version;
- missing detection ideas;
- whether MCPShield changed how you configured or trusted an MCP server.

Do not post secrets, customer data, private MCP configs or raw audit logs in public issues.

Security vulnerabilities in MCPShield itself should be reported privately using the repository security guidance.

Repository: https://github.com/Nullvora/MCPShield
