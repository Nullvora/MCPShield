# PB-001 — Transport Security Hardening

**Addresses:** T1.1 (STDIO RCE), T1.2 (Unencrypted HTTP), T1.3 (SSRF)

## Immediate Actions

### 1. Patch SDKs and launchers
Minimum versions (DNS-rebinding protection on by default, cross-client leak fixed, launcher RCEs fixed):

```bash
# Python SDK (CVE-2025-53365, CVE-2025-53366, CVE-2025-66416)
pip install "mcp>=1.23.0"

# TypeScript SDK (CVE-2025-66414, CVE-2026-25536)
npm install "@modelcontextprotocol/sdk@>=1.26.0"

# Launchers / tooling (CVE-2025-6514, CVE-2025-49596)
npx -y mcp-remote@0.1.16            # or later, pinned
npx -y @modelcontextprotocol/inspector@0.14.1   # or later, pinned
```

Verify with `mcpshield scan --auto` (rule MCPS-SUP-002).

### 2. Enable TLS on HTTP Servers
```json
{ "url": "https://your-server.com:3443" }
```

### 3. Restrict STDIO to Local Process Only
- Never bind STDIO MCP servers to a network socket
- Run under a dedicated unprivileged user: `useradd -r -s /sbin/nologin mcp-agent`

### 4. SSRF Defence (nginx example)
```nginx
location /mcp-proxy {
  deny 10.0.0.0/8;
  deny 172.16.0.0/12;
  deny 192.168.0.0/16;
  deny 169.254.169.254;
}
```
