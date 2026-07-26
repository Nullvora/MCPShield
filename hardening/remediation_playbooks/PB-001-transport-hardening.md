# PB-001 — Transport Security Hardening

**Addresses:** T1.1 (STDIO RCE), T1.2 (Unencrypted HTTP), T1.3 (SSRF)

## Immediate Actions

### 1. Patch SDK (CVE-2025-49596 / CVE-2026-22252)
```bash
# Python
pip install mcp --upgrade

# Node.js
npm install @anthropic-ai/mcp@latest
npm install @modelcontextprotocol/sdk@latest
```

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
