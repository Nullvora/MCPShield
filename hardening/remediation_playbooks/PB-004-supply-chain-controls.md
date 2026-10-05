# PB-004 — Supply Chain Security Controls

**Addresses:** T4.1 (Registry Poisoning), T4.2 (Unpinned Dependencies)

## Pin All Package Versions
```json
{
  "args": ["-y", "@modelcontextprotocol/server-filesystem@1.3.2"]
}
```

## Verify Package Integrity (Node.js)
```bash
npm install
# Lock file now records exact versions + hashes
# In CI/CD, use npm ci instead of npm install
npm ci
```

## Pre-installation Scanning
```bash
# Scan before installing any new MCP package
npm audit
pip-audit
```

## Subscribe to Security Advisories
- https://github.com/advisories?query=mcp
- https://nvd.nist.gov/vuln/search?query=model+context+protocol
