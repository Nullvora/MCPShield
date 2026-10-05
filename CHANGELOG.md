# Changelog

## 1.1.1rc1 — 2026-10-05 (unpublished review candidate)

- Fail closed on invalid/unsupported JSON-RPC and inspection errors; bound frames
  and pending requests, reject duplicate IDs and shut down stuck children.
- Validate policy modes/types; check every URL in an argument; require lock-backed
  definitions before calls and invalidate them after list-change notifications.
- Deny modern sampling requests consistently and preserve monitor-mode output.
- Make argument previews opt-in for audit and OTLP; avoid logging launch arguments;
  remove the audit key from child environment; create private, session-specific logs.
- Return exit code 2 for incomplete scans even with `--fail-on none`.
- Bound the telemetry queue and tolerate non-object audit records in verification/viewing.
- Gate publishing on CI, tag/version agreement and explicit repository enablement;
  add product-feedback form, launch plan, architecture review and known limitations.

Breaking behavior: invalid policy files now fail, invalid JSON-RPC is withheld,
lock-backed calls need prior `tools/list`, and default audit filenames include a
unique suffix. Publishing and container availability must not be assumed.

All notable changes to MCPShield are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-09-24

Agent-activity observability: see what every agent session actually did, in the tools you already use.

### Added
- **OpenTelemetry export from the runtime guard** (`mcpshield proxy --otlp-endpoint URL`, `--otlp-header k=v`, or the
  standard `OTEL_EXPORTER_OTLP_(TRACES_)ENDPOINT` / `OTEL_EXPORTER_OTLP_HEADERS` / `OTEL_SERVICE_NAME` variables). OTLP/HTTP
  JSON, batched in a background thread, no OpenTelemetry SDK dependency; export failures never affect the proxied session.
- Span model following the OpenTelemetry GenAI + MCP semantic conventions: `mcp.session <server>` root span,
  `execute_tool <tool>` per `tools/call` (`gen_ai.operation.name`, `gen_ai.tool.name`, `mcp.method.name`,
  `mcp.protocol.version`, `gen_ai.agent.name`, `network.transport`), `tools/list` spans, and `mcpshield.*` security
  attributes (decision, reasons, tool capabilities, hidden tools). Blocked and failed calls get an error status.
- **W3C trace-context propagation**: a `traceparent` in the request `_meta` (MCP 2026-07-28) makes the tool span a child
  of the agent's own trace.
- **Lethal-trifecta session alert**: the guard tracks which capability classes a session has actually exercised and emits
  an `alert` audit event and span event the first time private-data access, untrusted content and an outbound channel
  combine.
- `tool_result` audit events (duration, error state, capabilities) and a `session` id on every audit record.
- **`mcpshield trace`**: offline per-session timelines from audit logs, `--summary`, `--alerts`, `--session`, `--json`,
  and a self-contained `--html` activity report. Verifies each log's hash chain first and exits 1 on tampering.
- `--capture-args` opt-in for exporting (secret-redacted) tool arguments.
- docs/OBSERVABILITY.md.

## [1.0.0] — 2026-09-24

First public release. Consolidates the earlier internal prototypes (v0.1 scanner, "Production Ready" module set and
the v1.0.0 "complete/production/launch" builds) into one tested package.

### Added
- **Config audit** for 10 MCP clients (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex CLI,
  Zed, Cline, Amazon Q), JSONC and TOML aware; `discover` inventory (shadow MCP).
- **Agent-settings rules**: `enableAllProjectMcpServers`, repository hooks, API base-URL overrides, auto-approve flags.
- **Supply chain**: package extraction for npx/bunx/pnpm dlx/uvx/pipx/docker; curated, source-verified advisory data
  (mcp-remote, MCP Inspector, TypeScript & Python SDKs, filesystem & git servers, Figma, Kubernetes …), known-malicious
  packages (postmark-mcp), typosquat detection.
- **Dual-era live client** supporting the stateless MCP 2026-07-28 protocol (`server/discover`, per-request `_meta`)
  with fallback to `initialize`-based revisions; stdio, Streamable HTTP, legacy SSE.
- **Tool-metadata analysis**: tool poisoning, full-schema poisoning, ASCII smuggling (decoded), zero-width/bidi/ANSI,
  exfiltration parameters, shadowing, collisions, misleading annotations, `x-mcp-header` validation, lethal-trifecta analysis.
- **HTTP probes**: anonymous access, Origin/DNS-rebinding, CORS, TLS, RFC 9728 metadata, PKCE S256, RFC 9207, SSRF-prone
  OAuth metadata, legacy session IDs, verbose errors.
- **Pinning** (`pin`, `verify`, `scan --lock`) for rug-pull detection.
- **Runtime guard** (`proxy`, `wrap`, `init-policy`) with YAML policy, DLP redaction, sampling denial and a
  hash-chained, HMAC-signable audit log (`audit verify`).
- Reports: console, JSON, SARIF 2.1.0, HTML (CSP-locked, fully escaped), Markdown; baselines; allowlists.
- GitHub Action, pre-commit hook, Dockerfile, CI (Linux/macOS/Windows × Python 3.10–3.13), release workflow.
- 60 rules mapped to OWASP MCP Top 10, OWASP Agentic Top 10 and CWE; generated rule catalogue.

### Fixed (vs. prototypes)
- Removed findings that were emitted unconditionally for every target (prototype v1 engine).
- Corrected CVE attributions: CVE-2026-22252 (a LibreChat issue) no longer mapped to MCP SDKs; CVE-2025-49596 correctly
  attributed to MCP Inspector; fictional "SDK < 1.3.1" thresholds replaced with real fixed versions.
- Fixed broken packaging (`setuptools.backends.legacy` build backend, stray root `__init__.py`, duplicate `scanner/` trees,
  modules importing classes that did not exist).
- Removed the hardware-fingerprint "licensing" module and unverifiable "14-jurisdiction legal" and economic-impact claims.

### Licensing
- Released under the **Apache License 2.0** (explicit patent grant, enterprise-friendly), with NOTICE and a trademark
  policy for the MCPShield/Nullvora names. Contributions via DCO sign-off.

### Security
- Static scans never execute code; live scans never call tools and refuse server-initiated requests.
- Probes do not follow OAuth metadata into private/link-local networks.
- Secret values are redacted in every output format.
