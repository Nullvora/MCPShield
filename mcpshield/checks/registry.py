# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Rule catalogue. Every finding MCPShield emits references a rule defined here."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from mcpshield.models import Finding, Severity

SPEC = "https://modelcontextprotocol.io/specification/2026-07-28"
BP = "https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    owasp_mcp: tuple[str, ...] = ()
    owasp_asi: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    references: tuple[str, ...] = field(default=())
    scope: str = "config"     # config | live | http | agent | integrity


def _r(id: str, title: str, sev: str, description: str, remediation: str, mcp=(), asi=(), cwe=(), refs=(), scope="config") -> Rule:
    return Rule(id, title, Severity(sev), description, remediation, tuple(mcp), tuple(asi), tuple(cwe), tuple(refs), scope)


RULES: dict[str, Rule] = {r.id: r for r in [
    # ------------------------------------------------------------------ secrets
    _r("MCPS-SEC-001", "Hardcoded secret in server environment", "high",
       "A credential is stored as a literal value in the MCP client configuration. Config files are synced, backed up, "
       "committed to repositories and readable by every process running as the user — including other MCP servers.",
       "Reference the secret from the environment or a secret manager (e.g. \"${GITHUB_TOKEN}\", VS Code \"${input:…}\" "
       "prompts, OS keychain) and rotate the exposed credential.",
       mcp=["MCP01"], asi=["ASI03"], cwe=["CWE-798"]),
    _r("MCPS-SEC-002", "Secret passed on the command line", "high",
       "A credential appears in the server's command-line arguments. Arguments are visible to every local user via the process list "
       "and are frequently written to shell history and logs.",
       "Pass secrets through environment variables or files with restrictive permissions, never through argv. Rotate the credential.",
       mcp=["MCP01"], asi=["ASI03"], cwe=["CWE-214", "CWE-798"]),
    _r("MCPS-SEC-003", "Literal credential in HTTP headers", "high",
       "A remote server's Authorization (or API-key) header contains a literal token in the config file.",
       "Use OAuth 2.1 as defined by the MCP authorization spec, or reference the token from the environment. Rotate the token.",
       mcp=["MCP01", "MCP07"], asi=["ASI03"], cwe=["CWE-798"], refs=[f"{SPEC}/basic/authorization"]),
    _r("MCPS-SEC-004", "Credential embedded in server URL", "high",
       "The server URL carries credentials (user:password@host or a token/key query parameter). URLs leak through logs, proxies, "
       "browser history and Referer headers.",
       "Move credentials to an Authorization header or OAuth. Never place tokens or session identifiers in URLs.",
       mcp=["MCP01"], asi=["ASI03"], cwe=["CWE-598"]),
    _r("MCPS-SEC-005", "Config file containing secrets is readable by other users", "medium",
       "The configuration file holds literal credentials and is group- or world-readable.",
       "chmod 600 the file (or remove the secrets from it).",
       mcp=["MCP01"], cwe=["CWE-732"]),
    # ------------------------------------------------------------------ transport
    _r("MCPS-TRN-001", "Remote MCP server over plaintext HTTP", "high",
       "Traffic — including OAuth tokens, tool arguments and results — travels unencrypted to a non-loopback host.",
       "Use https:// with a valid certificate (TLS 1.2+, preferably 1.3). Plain http:// is only acceptable for localhost development.",
       mcp=["MCP07"], asi=["ASI07"], cwe=["CWE-319"], refs=[f"{SPEC}/basic/transports/streamable-http"]),
    _r("MCPS-TRN-002", "Deprecated HTTP+SSE transport", "low",
       "The HTTP+SSE transport (2024-11-05) is Deprecated under the MCP feature lifecycle policy and may be removed. "
       "It lacks the per-request metadata validation of Streamable HTTP.",
       "Migrate the server and client to Streamable HTTP.",
       mcp=["MCP07"], refs=[f"{SPEC}/changelog"]),
    _r("MCPS-TRN-003", "Local server bound to all interfaces", "high",
       "The server is started with a 0.0.0.0/:: bind address, exposing it to the network. Local MCP servers commonly lack "
       "authentication; hundreds have been found exposed on the internet.",
       "Bind local servers to 127.0.0.1 only (spec SHOULD) and require authentication for any network-exposed server.",
       mcp=["MCP07", "MCP09"], asi=["ASI03"], cwe=["CWE-1327"], refs=[f"{SPEC}/basic/transports/streamable-http"]),
    _r("MCPS-TRN-004", "TLS certificate verification disabled", "high",
       "The server environment or arguments disable TLS verification (e.g. NODE_TLS_REJECT_UNAUTHORIZED=0), enabling "
       "man-in-the-middle interception of upstream API traffic and credentials.",
       "Remove the override and trust the proper CA bundle instead (NODE_EXTRA_CA_CERTS / SSL_CERT_FILE).",
       mcp=["MCP07"], cwe=["CWE-295"]),
    # ------------------------------------------------------------------ execution
    _r("MCPS-EXE-001", "Server launched through a shell interpreter", "medium",
       "The server is started via 'sh -c', 'bash -c', 'cmd /c' or PowerShell. Shell wrappers hide what actually runs, "
       "enable command chaining and are the pattern behind the systemic STDIO command-execution issues reported in 2026.",
       "Invoke the server binary directly with an argument array. If a wrapper is unavoidable, keep it in a reviewed script file.",
       mcp=["MCP05"], asi=["ASI05"], cwe=["CWE-78"], refs=[f"{BP}#local-mcp-server-compromise"]),
    _r("MCPS-EXE-002", "Download-and-execute in server command", "critical",
       "The launch command fetches remote content and pipes it to an interpreter (curl … | sh, iwr … | iex, base64 -d | sh). "
       "Whoever controls that URL controls your machine every time the client starts.",
       "Install a pinned, verified artifact and run it directly. Remove remote-script execution from MCP configuration.",
       mcp=["MCP05", "MCP04"], asi=["ASI05", "ASI04"], cwe=["CWE-494", "CWE-78"], refs=[f"{BP}#local-mcp-server-compromise"]),
    _r("MCPS-EXE-003", "Server runs with elevated privileges", "high",
       "The server is launched through sudo/doas/runas or as root inside a container, so any tool-level compromise becomes a host compromise.",
       "Run MCP servers as an unprivileged user with the minimum filesystem and network access they need.",
       mcp=["MCP02"], asi=["ASI03", "ASI05"], cwe=["CWE-250"]),
    _r("MCPS-EXE-004", "Container escape-prone Docker options", "high",
       "The server container runs with --privileged, host namespaces, dangerous capabilities, the Docker socket, or a host root mount — "
       "which removes the isolation the container was supposed to provide.",
       "Drop --privileged/--cap-add, avoid host networking/PID, never mount /var/run/docker.sock or '/', and mount only the directories required (read-only where possible).",
       mcp=["MCP02", "MCP05"], asi=["ASI05"], cwe=["CWE-250", "CWE-269"]),
    _r("MCPS-EXE-005", "Inline code evaluation in launch command", "medium",
       "The server is started with inline code (node -e, python -c, deno eval). The executed code is not reviewable or versioned.",
       "Move the code into a versioned, reviewed file or package.",
       mcp=["MCP05"], asi=["ASI05"], cwe=["CWE-94"]),
    # ------------------------------------------------------------------ supply chain
    _r("MCPS-SUP-001", "Unpinned package version", "medium",
       "The server is fetched and executed from a registry without a pinned version (npx/uvx/pipx/docker :latest). "
       "A compromised or hijacked release executes automatically on next launch — the delivery mechanism of the postmark-mcp backdoor.",
       "Pin exact versions (pkg@1.2.3, pkg==1.2.3, image@sha256:…), review upgrades, and prefer a lockfile or internal mirror.",
       mcp=["MCP04"], asi=["ASI04"], cwe=["CWE-1357", "CWE-494"]),
    _r("MCPS-SUP-002", "Known-vulnerable MCP package version", "high",
       "The pinned package version is affected by a published vulnerability.",
       "Upgrade to the fixed version listed in the advisory.",
       mcp=["MCP04"], asi=["ASI04"], cwe=["CWE-1395"]),
    _r("MCPS-SUP-003", "Known malicious MCP package", "critical",
       "The configuration launches a package that has been identified as malicious.",
       "Remove the server immediately, rotate every credential it could reach and review the data it handled.",
       mcp=["MCP04"], asi=["ASI04"], cwe=["CWE-506"]),
    _r("MCPS-SUP-004", "Possible typosquatted package", "high",
       "The package name is one or two characters away from (or an unscoped copy of) a well-known MCP server package.",
       "Verify the publisher and repository. Use the official package name.",
       mcp=["MCP04"], asi=["ASI04"], cwe=["CWE-1357"]),
    _r("MCPS-SUP-005", "Package installed from an unvetted URL or git ref", "medium",
       "The server is installed from a git URL, tarball or raw URL rather than a registry release, bypassing registry provenance.",
       "Install from a registry release with provenance, pin to a commit SHA at minimum, and mirror it internally.",
       mcp=["MCP04"], asi=["ASI04"], cwe=["CWE-494"]),
    _r("MCPS-SUP-006", "Package with known advisories used without version pin", "medium",
       "The package has published vulnerabilities in some versions and the configuration does not pin a version, so the installed "
       "version cannot be verified from the configuration alone.",
       "Pin a version at or above the fixed release listed in the advisory.",
       mcp=["MCP04"], asi=["ASI04"], cwe=["CWE-1395"]),
    # ------------------------------------------------------------------ privilege
    _r("MCPS-PRV-001", "Filesystem access scoped to root or home directory", "high",
       "The server is granted the entire filesystem or home directory, which includes SSH keys, cloud credentials, browser "
       "profiles and other MCP configs. Prompt-injected agents routinely target these files.",
       "Grant only the project directories the workflow needs, ideally read-only.",
       mcp=["MCP02"], asi=["ASI03", "ASI02"], cwe=["CWE-732"]),
    _r("MCPS-PRV-002", "Credential store exposed to server", "critical",
       "A path such as ~/.ssh, ~/.aws, ~/.kube, ~/.docker or ~/.gnupg is passed to or mounted into the server.",
       "Remove credential directories from the server's scope. Use short-lived, least-privilege tokens passed via env references.",
       mcp=["MCP01", "MCP02"], asi=["ASI03"], cwe=["CWE-522"]),
    _r("MCPS-PRV-003", "Toxic capability combination across configured servers", "high",
       "The same agent is given (1) access to private data, (2) exposure to untrusted content and (3) a way to communicate "
       "externally. This 'lethal trifecta' lets a single prompt injection in untrusted content exfiltrate private data.",
       "Split these capabilities across separate agents/sessions, require human approval for outbound actions, or run MCPShield "
       "proxy with an egress policy.",
       mcp=["MCP10", "MCP06"], asi=["ASI01", "ASI02"], cwe=["CWE-200"]),
    # ------------------------------------------------------------------ shadow / governance
    _r("MCPS-SHD-001", "MCP server not on the approved allowlist", "medium",
       "A configured MCP server is not in the organisation's allowlist (shadow MCP).",
       "Review the server; add it to the allowlist or remove it from the client configuration.",
       mcp=["MCP09"], asi=["ASI04"]),
    _r("MCPS-SHD-002", "Same server name points to different targets", "low",
       "Two configuration files define a server with the same name but different commands/URLs, so which one runs depends on client precedence.",
       "Give servers unique names and remove stale definitions.",
       mcp=["MCP09"]),
    # ------------------------------------------------------------------ agent/client settings
    _r("MCPS-AGT-001", "Project MCP servers auto-approved", "high",
       "'enableAllProjectMcpServers' (Claude Code) or equivalent auto-enables any MCP server defined in a repository's .mcp.json. "
       "Cloning a malicious repository then starts attacker-chosen servers without consent (see CVE-2025-59536 / CVE-2026-21852).",
       "Set it to false and approve project servers individually ('enabledMcpjsonServers'); keep Claude Code updated.",
       mcp=["MCP09", "MCP05"], asi=["ASI04", "ASI05"], cwe=["CWE-829"],
       refs=["https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/"],
       scope="agent"),
    _r("MCPS-AGT-002", "Repository-defined hooks execute shell commands", "medium",
       "Project-level agent settings define hooks that run shell commands automatically. Hooks in cloned repositories were the "
       "code-execution vector in CVE-2025-59536.",
       "Review every hook command; keep hooks in user-level settings, not in shared repositories.",
       mcp=["MCP05"], asi=["ASI05"], cwe=["CWE-829"], scope="agent"),
    _r("MCPS-AGT-003", "Project settings redirect the model API endpoint", "high",
       "Project settings override ANTHROPIC_BASE_URL / OPENAI_BASE_URL (or similar), which can send API keys and prompts to an "
       "attacker-controlled endpoint (CVE-2026-21852 class).",
       "Remove API endpoint overrides from repository-level settings; set them only in trusted user-level configuration.",
       mcp=["MCP01"], asi=["ASI03"], cwe=["CWE-522"], scope="agent"),
    _r("MCPS-AGT-004", "Tool calls auto-approved without human confirmation", "medium",
       "The client is configured to run MCP tools without confirmation (e.g. Gemini CLI \"trust\": true, Cline/Roo \"alwaysAllow\"/"
       "\"autoApprove\", VS Code chat.tools.autoApprove, Claude Code wildcard mcp__ permissions or bypassPermissions).",
       "Keep confirmation for tools with side effects; auto-approve only read-only tools you have reviewed.",
       mcp=["MCP02"], asi=["ASI09", "ASI02"], cwe=["CWE-862"], scope="agent"),
    # ------------------------------------------------------------------ config hygiene
    _r("MCPS-CFG-001", "Configuration could not be fully parsed", "info",
       "Part of the configuration file could not be interpreted; those entries were not assessed.",
       "Fix the reported entries so they can be scanned.", scope="config"),
    # ------------------------------------------------------------------ live: tool definitions
    _r("MCPS-TOOL-001", "Tool poisoning: instructions embedded in tool description", "critical",
       "The tool description contains language aimed at the model rather than describing the tool (instruction overrides, "
       "concealment from the user, exfiltration steps). Clients pass descriptions to the model verbatim, so this executes "
       "before the tool is ever called ('line jumping').",
       "Do not connect this server. Report it to the publisher/registry. Pin reviewed tool definitions with 'mcpshield pin'.",
       mcp=["MCP03", "MCP06"], asi=["ASI01", "ASI02"], cwe=["CWE-1427"], scope="live",
       refs=["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"]),
    _r("MCPS-TOOL-002", "Hidden characters in model-visible metadata", "high",
       "Tool/prompt/resource metadata contains invisible Unicode tag characters, zero-width or bidi-override characters, or "
       "ANSI escape sequences. These hide content from human reviewers while the model still reads it.",
       "Reject metadata containing these characters; normalise and display metadata in clients before approval.",
       mcp=["MCP03"], asi=["ASI01"], cwe=["CWE-1007", "CWE-116"], scope="live"),
    _r("MCPS-TOOL-003", "Full-schema poisoning: injection inside input schema", "critical",
       "Injection language is embedded in the input schema (parameter names, descriptions, titles, defaults or enum values), "
       "which models also read. Scanners that only check the description miss this.",
       "Treat the whole tool definition as untrusted; do not connect the server.",
       mcp=["MCP03"], asi=["ASI01"], cwe=["CWE-1427"], scope="live",
       refs=["https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning"]),
    _r("MCPS-TOOL-004", "Parameter designed to capture context or secrets", "high",
       "A parameter's name or description asks for conversation history, system prompts, file contents or credentials that the "
       "tool's function does not need (the 'sidenote' exfiltration pattern).",
       "Remove the server or constrain the parameter; audit what has already been sent.",
       mcp=["MCP10", "MCP03"], asi=["ASI01"], cwe=["CWE-200"], scope="live"),
    _r("MCPS-TOOL-005", "Cross-server tool shadowing", "high",
       "A tool's metadata references tools that belong to a different server, attempting to change how those tools behave "
       "(e.g. redirecting e-mail recipients).",
       "Isolate untrusted servers from sensitive ones and remove the offending server.",
       mcp=["MCP03"], asi=["ASI01", "ASI07"], cwe=["CWE-1427"], scope="live"),
    _r("MCPS-TOOL-006", "Tool name collision across servers", "medium",
       "Two servers expose tools with the same name. Clients may resolve calls to the wrong server, and a malicious server can "
       "deliberately collide with a trusted tool.",
       "Rename or namespace the tools, or disable one of the servers.",
       mcp=["MCP03", "MCP09"], asi=["ASI02"], scope="live"),
    _r("MCPS-TOOL-007", "External URL or e-mail address in tool metadata", "medium",
       "Tool metadata references an external URL or e-mail address — a common exfiltration destination in poisoned tools.",
       "Confirm the destination is legitimate and expected for this tool.",
       mcp=["MCP03", "MCP10"], asi=["ASI01"], scope="live"),
    _r("MCPS-TOOL-008", "Misleading tool annotations", "medium",
       "The tool claims readOnlyHint / non-destructive behaviour but its name or schema indicates writes, deletion or execution. "
       "Clients that auto-approve 'read-only' tools can be tricked into running it.",
       "Correct the annotations. Clients must treat annotations from untrusted servers as hints only.",
       mcp=["MCP02"], asi=["ASI09"], scope="live"),
    _r("MCPS-TOOL-009", "Unconstrained high-risk parameter", "low",
       "A parameter that carries a shell command, file path, URL or query is a free-form string with no pattern, enum or length limit.",
       "Constrain the schema (enum/pattern/maxLength, additionalProperties: false) and validate server-side.",
       mcp=["MCP05"], asi=["ASI02"], cwe=["CWE-20"], scope="live"),
    _r("MCPS-TOOL-010", "Oversized tool description", "low",
       "Very long descriptions consume context and are a common place to hide instructions.",
       "Keep descriptions concise (< 1,000 characters) and factual.", mcp=["MCP03"], scope="live"),
    _r("MCPS-TOOL-011", "Invalid x-mcp-header annotation", "medium",
       "An inputSchema property uses 'x-mcp-header' in a way the 2026-07-28 spec forbids (invalid header token, CR/LF, duplicate, "
       "non-primitive or not statically reachable). Conforming clients must drop the tool; lax clients may allow header injection.",
       "Fix the annotation per the Streamable HTTP 'Custom Headers from Tool Parameters' rules.",
       mcp=["MCP05"], cwe=["CWE-113"], refs=[f"{SPEC}/basic/transports/streamable-http"], scope="live"),
    _r("MCPS-TOOL-012", "Lethal trifecta within a single server", "high",
       "One server's tools can read private data, ingest untrusted content and communicate externally. A prompt injection "
       "delivered through the untrusted content can exfiltrate the private data without any other server involved.",
       "Split capabilities, require approval for outbound tools, or enforce an egress policy with 'mcpshield proxy'.",
       mcp=["MCP10", "MCP06"], asi=["ASI01", "ASI02"], cwe=["CWE-200"], scope="live"),
    _r("MCPS-TOOL-013", "Excessive number of tools", "low",
       "The server exposes a very large tool surface, which increases mis-selection risk and the chance of a dangerous tool being invoked.",
       "Expose only the tools the workflow needs (most clients support per-tool disabling).",
       mcp=["MCP02"], asi=["ASI02"], scope="live"),
    _r("MCPS-TOOL-014", "Injection language in server instructions", "high",
       "The 'instructions' returned by the server (injected into the system prompt by many clients) contain manipulative or hidden content.",
       "Do not connect the server; clients should display server instructions to users.",
       mcp=["MCP03", "MCP06"], asi=["ASI01"], cwe=["CWE-1427"], scope="live"),
    _r("MCPS-TOOL-015", "Injection language in prompt or resource metadata", "high",
       "Prompt templates or resource descriptions advertised by the server contain injection language or hidden characters.",
       "Review the server; treat its prompts/resources as untrusted input.",
       mcp=["MCP06", "MCP03"], asi=["ASI01", "ASI06"], cwe=["CWE-1427"], scope="live"),
    _r("MCPS-TOOL-016", "Tool definition changed since it was pinned (rug pull)", "critical",
       "A tool's definition (description or schema) differs from the reviewed version recorded in mcpshield.lock. Silent "
       "redefinition after approval is the 'rug pull' attack.",
       "Review the diff. If unexpected, disconnect the server and rotate credentials it could access. Re-pin only after review.",
       mcp=["MCP03", "MCP04"], asi=["ASI04"], cwe=["CWE-494"], scope="integrity"),
    _r("MCPS-TOOL-017", "Tool added or removed since pinning", "medium",
       "The server's tool list differs from the pinned inventory.",
       "Review the new tools before use and re-pin.", mcp=["MCP03"], asi=["ASI04"], scope="integrity"),
    _r("MCPS-TOOL-018", "Tool name imitates another server's namespace", "low",
       "The tool name contains another well-known server's name or a prefix used for namespacing (e.g. 'github_', 'slack_') while "
       "the server itself is different, which can confuse users approving calls.",
       "Rename the tool to reflect the server that implements it.", mcp=["MCP03"], asi=["ASI09"], scope="live"),
    # ------------------------------------------------------------------ live: HTTP
    _r("MCPS-HTTP-001", "Remote MCP server accepts unauthenticated requests", "high",
       "The server listed its tools to an anonymous client. Anyone who can reach the endpoint can invoke them.",
       "Require OAuth 2.1 per the MCP authorization spec (or at minimum a strong bearer token) for every request.",
       mcp=["MCP07"], asi=["ASI03"], cwe=["CWE-306"], refs=[f"{SPEC}/basic/authorization"], scope="http"),
    _r("MCPS-HTTP-002", "Origin header not validated (DNS rebinding)", "high",
       "The server processed a request carrying a foreign Origin header. The spec requires servers to validate Origin and reply 403 "
       "to invalid origins; without it, any web page the user visits can drive a local MCP server via DNS rebinding.",
       "Validate Origin against an allowlist and return 403 otherwise; bind local servers to 127.0.0.1; upgrade SDKs "
       "(TypeScript ≥1.24.0, Python ≥1.23.0 enable protection by default).",
       mcp=["MCP07"], asi=["ASI03"], cwe=["CWE-350", "CWE-346"], refs=[f"{SPEC}/basic/transports/streamable-http"], scope="http"),
    _r("MCPS-HTTP-003", "No OAuth Protected Resource Metadata", "medium",
       "The server requires authorization but does not advertise RFC 9728 Protected Resource Metadata (WWW-Authenticate "
       "resource_metadata or /.well-known/oauth-protected-resource), so clients cannot discover the authorization server safely.",
       "Serve Protected Resource Metadata and include resource_metadata in 401 WWW-Authenticate challenges.",
       mcp=["MCP07"], cwe=["CWE-287"], refs=[f"{SPEC}/basic/authorization"], scope="http"),
    _r("MCPS-HTTP-004", "Authorization server does not support PKCE S256", "high",
       "The authorization server metadata does not list S256 in code_challenge_methods_supported. MCP clients MUST use PKCE with S256.",
       "Enable PKCE (S256) on the authorization server.",
       mcp=["MCP07"], cwe=["CWE-287"], refs=[f"{SPEC}/basic/authorization"], scope="http"),
    _r("MCPS-HTTP-005", "Authorization metadata points to insecure or internal endpoints", "high",
       "OAuth metadata advertised by the server references http:// endpoints, private/link-local IPs or non-web schemes. A malicious "
       "server can use this to make clients perform SSRF (e.g. cloud metadata at 169.254.169.254) or execute URLs (CVE-2025-6514).",
       "Use https:// public endpoints only. Clients should block private ranges and non-http(s) schemes.",
       mcp=["MCP07"], asi=["ASI03"], cwe=["CWE-918"], refs=[f"{BP}#server-side-request-forgery-ssrf"], scope="http"),
    _r("MCPS-HTTP-006", "Permissive CORS policy", "medium",
       "The server reflects arbitrary origins or allows '*' — letting any website issue cross-origin requests to it.",
       "Return CORS headers only for trusted origins; never combine wildcard origins with credentials.",
       mcp=["MCP07"], cwe=["CWE-942"], scope="http"),
    _r("MCPS-HTTP-007", "TLS configuration weakness", "high",
       "The server's TLS certificate failed verification or a deprecated protocol version was negotiated.",
       "Deploy a valid certificate from a trusted CA and allow only TLS 1.2+.",
       mcp=["MCP07"], cwe=["CWE-295", "CWE-326"], scope="http"),
    _r("MCPS-HTTP-008", "Weak legacy session identifiers", "medium",
       "The server issues Mcp-Session-Id values that are short or predictable. In legacy (≤2025-11-25) Streamable HTTP, session IDs "
       "must be cryptographically random and never used for authentication.",
       "Use ≥128-bit random session IDs, bind them to the authenticated user, or migrate to the stateless 2026-07-28 protocol.",
       mcp=["MCP07"], cwe=["CWE-330", "CWE-384"], scope="http"),
    _r("MCPS-CAP-002", "Server does not support the current MCP protocol revision", "info",
       "The server only speaks an initialize-based (legacy) protocol revision. Newer clients will fall back or fail.",
       "Upgrade the server SDK to a release supporting protocol 2026-07-28.",
       refs=[f"{SPEC}/basic/versioning"], scope="live"),
    _r("MCPS-HTTP-010", "Verbose error disclosure", "low",
       "Malformed input produced stack traces or internal paths in the response.",
       "Return generic JSON-RPC errors and log details server-side.",
       mcp=["MCP08"], cwe=["CWE-209"], scope="http"),
    _r("MCPS-HTTP-011", "Authorization server does not advertise RFC 9207 'iss' support", "low",
       "Without the 'iss' authorization-response parameter, clients cannot defend against OAuth mix-up attacks, which the "
       "2026-07-28 spec addresses by requiring clients to validate 'iss' when present.",
       "Enable authorization_response_iss_parameter_supported on the authorization server.",
       mcp=["MCP07"], refs=[f"{BP}#mix-up-attacks"], scope="http"),
    _r("MCPS-CAP-001", "Server relies on deprecated client features", "info",
       "The server uses Sampling, Roots or Logging, which the 2026-07-28 spec deprecates. Sampling in particular lets a server "
       "ask the client's model to generate content, a known vector for covert prompt injection and resource abuse.",
       "Migrate away from deprecated features; clients should require user approval for every sampling request.",
       mcp=["MCP06"], asi=["ASI01"], refs=[f"{SPEC}/changelog"], scope="live"),
]}


def rule(rule_id: str) -> Rule:
    return RULES[rule_id]


def make(rule_id: str, *, server: str = "", location: str = "", evidence: str = "", severity: Optional[Severity] = None,
         title: Optional[str] = None, description: Optional[str] = None, remediation: Optional[str] = None,
         references: Optional[list[str]] = None) -> Finding:
    r = RULES[rule_id]
    return Finding(
        rule_id=r.id,
        title=title or r.title,
        severity=severity or r.severity,
        description=description or r.description,
        remediation=remediation or r.remediation,
        server=server,
        location=location,
        evidence=evidence,
        owasp_mcp=list(r.owasp_mcp),
        owasp_asi=list(r.owasp_asi),
        cwe=list(r.cwe),
        references=list(r.references) + list(references or []),
    )
