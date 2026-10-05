# Agent observability

The MCPShield runtime guard (`mcpshield proxy`) sits on the wire between an AI client and an MCP server, so it sees
everything an agent does through that server: which tools it listed, which it called, with what, how long each took,
what failed, and what the guard blocked. MCPShield 1.1 turns that into:

1. **A local, tamper-evident activity record.** The hash-chained audit log, browsed with `mcpshield trace`.
2. **Standard OpenTelemetry traces.** Streamed to the observability backend you already run.

Both are on the security side of the house. The goal isn't prompt/response analytics. It's a precise answer to
*"what could this agent touch, what did it actually touch, and did anything dangerous line up?"*

---

## Local timeline: `mcpshield trace`

```bash
mcpshield trace                                   # all logs in ~/.mcpshield/audit/
mcpshield trace ~/.mcpshield/audit/github.jsonl   # specific log(s)
mcpshield trace --alerts --summary                # one line per risky session
mcpshield trace --session 3f9a1c                  # one session (id prefix)
mcpshield trace --html activity.html              # self-contained, script-free HTML report
mcpshield trace --json                            # machine-readable summaries + integrity result
```

Every log's hash chain (and HMAC signatures when `MCPSHIELD_AUDIT_KEY` is set) is verified before anything is
shown. If a record was edited, inserted or deleted, `trace` reports it and exits with status 1.

Example timeline:

```
──── poison · session fc631833dc00 · 2 call(s), 0 blocked · ALERT lethal_trifecta ────
16:22:43.279 hidden add               Parameter designed to capture context or secrets; Tool poisoning in 'add'
16:22:43.281 tools/list               3/7 exposed, hidden=['add', 'daily_fact', 'format_text', 'get_weather']
16:22:43.283 call run_command         allow  args={"command": "echo hi"}
16:22:43.290 result run_command       ok in 6.46 ms  capabilities=code_exec,external_comm,private_data
16:22:43.293 call fetch_url           allow  args={"url": "https://example.com"}
16:22:43.298 result fetch_url         ok in 5.12 ms  capabilities=external_comm,untrusted_content
16:22:43.299 ALERT lethal_trifecta    session combined private-data access, untrusted content and an outbound channel
```

## OpenTelemetry export

```bash
mcpshield proxy --otlp-endpoint http://localhost:4318 [--otlp-header 'Authorization=Bearer …'] -- <server command>
```

or use the standard environment variables, which work well inside client configs:

| Variable | Meaning |
|---|---|
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP base URL (`/v1/traces` is appended when missing) |
| `OTEL_EXPORTER_OTLP_HEADERS` | `key=value,key2=value2` (auth headers for SaaS backends) |
| `OTEL_SERVICE_NAME` | `service.name` resource attribute (default `mcpshield`) |

The exporter speaks **OTLP/HTTP with JSON encoding** and has no OpenTelemetry SDK dependency. Spans are batched and sent
from a background thread. If the collector is down, spans are dropped and counted, and the MCP session is never delayed
or broken.

### Span model

MCPShield follows the OpenTelemetry **GenAI and MCP semantic conventions** (Development status in 2026; attribute names
may still change upstream, and MCPShield will track them).

| Span | Parent | Key attributes |
|---|---|---|
| `mcp.session <server>` | none (root) | `mcpshield.server`, `mcpshield.session.id`, `mcp.protocol.version`, `gen_ai.agent.name` (client name), `process.exit.code`, `mcpshield.stats.*` |
| `tools/list` | session | `mcp.method.name=tools/list`, `mcpshield.tools.exposed`, `mcpshield.tools.hidden` |
| `execute_tool <tool>` | session, or the caller's span (see below) | `gen_ai.operation.name=execute_tool`, `gen_ai.tool.name`, `mcp.method.name=tools/call`, `network.transport=pipe`, `mcpshield.decision` (`allow`/`flag`/`block`), `mcpshield.reasons`, `mcpshield.tool.capabilities`, optional `gen_ai.tool.call.arguments` |

- Status is **ERROR** for blocked calls, JSON-RPC errors and results with `isError: true`.
- Span events: `mcpshield.policy_violation` (flagged or blocked calls) and `mcpshield.alert` (for example `lethal_trifecta`,
  with the tools that completed it).
- **Trace-context propagation:** when a request carries a W3C `traceparent` in `params._meta` (defined by MCP
  2026-07-28), the `execute_tool` span joins the agent's own trace as a child of that span, and keeps
  `mcpshield.session.id` so you can still pivot to the session. Otherwise all spans of a session share one trace.

### Privacy defaults

- Tool **arguments are not exported** unless you pass `--capture-args`. Even then they go through the same secret
  redaction as the audit log (API keys, tokens, private keys, JWTs …) and are truncated to 2,000 characters.
- Tool result bodies are not exported as spans; error text and other metadata may still be sensitive.
- The audit log omits argument previews unless `--capture-args` is set. Protect `~/.mcpshield/audit/` like any log that can
  contain business data.

## The lethal-trifecta session alert

Static scanning (`mcpshield scan --live`) can tell you a server *could* combine private-data access, untrusted content
and an outbound channel. At runtime the guard tracks which of those capability classes a session has **actually
exercised** (classified from the tool definitions it saw in `tools/list`). The first time all three combine in one
session, it writes an `alert` audit record (`kind: lethal_trifecta`, `severity: high`, the tools per class) and attaches
an `mcpshield.alert` event to the span. That is the moment a prompt-injected agent is able to exfiltrate data.

The alert is detective, not blocking. Pair it with policy rules (`urls.deny`, `tools.deny`, `results.block_injection`)
when you want enforcement.

## Backend recipes

| Backend | Endpoint | Header |
|---|---|---|
| Local OpenTelemetry Collector / Jaeger v2 | `http://localhost:4318` | none |
| Grafana Cloud (OTLP gateway) | `https://otlp-gateway-<zone>.grafana.net/otlp` | `Authorization=Basic <base64 instance:token>` |
| Honeycomb | `https://api.honeycomb.io` | `x-honeycomb-team=<api key>` |
| Datadog (via Agent / OTLP intake) | `http://<agent>:4318` | none |
| Langfuse (OTLP endpoint) | `https://cloud.langfuse.com/api/public/otel` | `Authorization=Basic <base64 pk:sk>` |

Check your vendor's current OTLP/HTTP documentation. Endpoints and auth schemes change, and some require protobuf or
a regional host.

Minimal Collector config:

```yaml
receivers:
  otlp:
    protocols:
      http: { endpoint: 0.0.0.0:4318 }
exporters:
  debug: { verbosity: detailed }
service:
  pipelines:
    traces: { receivers: [otlp], exporters: [debug] }
```

Inside a client config:

```jsonc
"github": {
  "command": "mcpshield",
  "args": ["proxy", "--policy", "/home/me/.mcpshield/policy.yaml", "--", "npx", "-y", "@modelcontextprotocol/server-github@<pinned>"],
  "env": { "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318", "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}" }
}
```

## Limits (v1.1)

- stdio servers only; the Streamable-HTTP reverse proxy is on the roadmap.
- Identity is the MCP client name/version the client sends. User and agent identity enrichment is planned.
- Capability classes come from tool names and descriptions (the same classifier as `scan`), so they are heuristics.

Default audit filenames include a unique session suffix. Explicit `--audit-log` paths must have one writer. See [limitations](LIMITATIONS.md).
