# Runtime guard (`mcpshield proxy`)

The guard inspects newline-delimited JSON-RPC traffic between an MCP client and a local server. Policy decisions feed audit logs and optional telemetry.

## Usage

```bash
mcpshield proxy [--policy policy.yaml] [--lock mcpshield.lock] [--audit-log path] [--name NAME] [--monitor] \
                [--otlp-endpoint URL] [--otlp-header k=v] [--capture-args] -- <command> [args…]
```

- `--monitor` logs decisions without blocking — use it for a week to tune the policy, then switch to `enforce`.
- `--lock` hides any tool whose definition differs from the pinned one (rug pull). With `tools.require_pinned: true`
  new, unreviewed tools are hidden as well.
- Set `MCPSHIELD_AUDIT_KEY` to HMAC-sign every record; `mcpshield audit verify <log>` checks chain and signatures.
- `--otlp-endpoint` (or `OTEL_EXPORTER_OTLP_ENDPOINT`) streams the session as OpenTelemetry traces; `mcpshield trace`
  shows it locally. See [OBSERVABILITY.md](OBSERVABILITY.md).

## Policy reference

`mcpshield init-policy` writes an annotated file. Keys:

| Key | Default | Meaning |
|---|---|---|
| `mode` | `enforce` | `enforce` blocks; `monitor` only logs |
| `block_severity` | `high` | hide tools whose *definition* has a finding at/above this severity |
| `tools.deny` / `tools.allow` | `[]` | glob patterns; `allow` (if set) is exclusive |
| `tools.require_pinned` | `false` | with `--lock`, hide tools not in the lock file |
| `arguments.deny_paths` | SSH/cloud/kube/docker creds, `.env`, MCP configs, `/etc/shadow` … | glob paths (added to built-ins) |
| `arguments.deny_hosts` | cloud metadata hosts | added to built-ins |
| `arguments.deny_private_networks` | `true` | block URLs to RFC 1918, loopback, link-local, `.internal`/`.local` |
| `arguments.deny_patterns` | `rm -rf /`, `curl … | sh`, `/dev/tcp`, fork bomb … | regexes (added to built-ins) |
| `arguments.max_bytes` | `200000` | maximum serialised argument size |
| `results.redact_secrets` | `true` | mask tokens/keys/private keys in tool output |
| `results.block_injection` | `false` | withhold tool output containing high-severity injection language |
| `rate_limits.default_per_minute` / `per_tool` | `120` / `{}` | sliding-window call limits |
| `sampling` | `deny` | refuse `sampling/createMessage` from the server |

Blocked calls return a normal MCP tool result with `isError: true` so the model understands what happened.

## Audit record example (with `--capture-args`)

```json
{"seq":6,"ts":"2026-09-24T12:57:05.330+00:00","event":"tool_call","server":"fetch","session":"3f9a1c…","tool":"fetch_url",
 "arguments":"{\"url\": \"http://169.254.169.254/latest/meta-data/\"}","decision":"block",
 "reasons":["URL host '169.254.169.254' is denied (cloud metadata / denylist)"],"prev":"e1ee…","hash":"39b4…"}
```

Every record carries the `session` id (also the OpenTelemetry trace id of the session).
Events: `proxy_start`, `tools_listed`, `tool_hidden`/`tool_flagged`, `tool_call`, `tool_result` (duration, error,
capabilities), `alert` (e.g. `lethal_trifecta`), `result_redacted`, `result_injection`, `server_request`, `tools_list_changed`, `input_required`, `guard_error`, `proxy_stop` (with counters).
Ship the JSONL to your SIEM with any file forwarder (Splunk UF, Vector, Fluent Bit).

## Limits

The guard is stdio-only in this release (remote servers: use `scan --live` probes today; an HTTP reverse-proxy mode is on the
roadmap). It inspects what crosses the protocol boundary — it is not a sandbox. Combine it with OS/container isolation
for servers that execute code.

## Release candidate behavior changes

Malformed/unsupported frames and inspection failures are withheld, including in
monitor mode. The guard rejects legacy JSON-RPC batches and caps each frame at
4 MiB. Pinning requires a matching server name and prior tool listing. Modern
sampling input requests follow the same deny policy as legacy sampling. Monitor
mode does not redact valid results. Argument logging/export is opt-in with
`--capture-args`. Default audit files are unique per session; explicit paths must
have one writer. See [LIMITATIONS.md](LIMITATIONS.md) before deployment.
