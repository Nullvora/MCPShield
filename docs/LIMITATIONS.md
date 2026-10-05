# Security boundaries and known limitations

This public beta is a configuration scanner and a stdio policy guard. It is not
an OS sandbox, an antivirus product, or proof that an MCP server is safe.

- Static scanning does not start configured servers. `--live`, `pin`, and
  `verify` connect to servers and can start local code. Run only reviewed
  configurations or use a disposable sandbox with restricted egress.
- Runtime rules inspect tool definitions, calls, and recognized tool output.
  They do not mediate a child process's actual file or network operations.
  A server can ignore its arguments or do work before it receives any call.
- Path/URL/command rules and injection/secret detection are heuristics. Symlinks,
  alternate encodings, DNS rebinding, embedded commands, and unknown secret
  formats may evade them. URL rules do not resolve arbitrary hostnames at call
  time. OAuth probes check DNS before fetching, but do not bind the HTTP socket
  to that resolution. Network policy is still required.
- The runtime guard accepts individual JSON-RPC 2.0 objects. Legacy JSON-RPC
  batches, invalid objects, oversized frames (over 4 MiB), and inspection failures
  are withheld. Clients may need to time out and reconnect after malformed
  server responses; malformed responses are not repaired automatically.
- At most 1,024 client requests may be pending. Calls without responses retain
  their state until session end. Per-tool state is not a general resource quota.
- With a lock file, call `tools/list` before `tools/call`; a list-changed notice
  invalidates inspected definitions. Use `--name` matching the pinned server.
  A lock verifies returned metadata, not the server implementation. Without a
  lock, direct calls are checked against argument and allow/deny rules, but
  definition-based checks require the client to list tools first.
- `sampling: deny` covers legacy requests and modern `input_required` sampling.
  Other server-initiated facilities are not an authorization system. Prompts,
  resources, unknown extensions, and arbitrary error data do not all receive
  the same filtering as tool results. Do not claim comprehensive MCP mediation.
- Monitor mode forwards valid messages without result redaction or blocking.
  Invalid/uninspectable frames are still withheld for transport safety.
- HMAC signing is optional (`MCPSHIELD_AUDIT_KEY`). It protects against rewriting
  records without the key; it cannot detect deleting a valid tail or the entire
  log without an independently retained checkpoint. Same-user/root processes
  may read the key from the parent process; separating identities remains necessary.
- Default audit files are unique per session; explicitly supplied audit paths
  require a single writer. New files use owner-only permissions on POSIX. Windows
  ACLs and permissions on existing files require operator configuration.
- Argument previews are omitted unless `--capture-args` is set. Capture applies
  to both audit and OTLP. Recognized secrets are redacted, but ordinary private
  data may remain. Tool names, reasons, paths, error text, and other metadata can
  still be sensitive. Review all reports/logs before sharing them.
- OTLP is activated by explicit CLI settings or `OTEL_EXPORTER_OTLP_*` environment
  variables. It sends data to that configured endpoint, not to Nullvora. Use TLS
  and a trusted collector. Its queue is bounded at 4,096 spans; overload or export
  failure can lose spans. Do not use telemetry as a durable audit store.
- Shutdown terminates the immediate child after a grace period. This is not
  process-tree containment; descendant processes require OS/container controls.

This review did not validate every bundled advisory or measure detection accuracy
against a representative external corpus. Release claims must remain limited to
reproducible tests and documented behavior.
