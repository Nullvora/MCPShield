# PB-002 — Authentication Implementation

**Addresses:** T2.1 (No Auth), T2.2 (Hardcoded Credentials)

## Implement Bearer Token Auth

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://mcp.company.com:3443",
      "headers": {
        "Authorization": "Bearer ${MCP_TOKEN}"
      }
    }
  }
}
```

## Inject Secrets at Runtime
```bash
# Export from secrets manager, never hardcode
export MCP_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id prod/mcp/auth-token --query SecretString --output text)
```

## Rotate Exposed Credentials Immediately
1. Revoke the exposed key in the provider dashboard
2. Generate a new key with minimal required permissions
3. Update via secrets manager — never in config files
4. Audit git history: `git log -p | grep -i "api_key\|secret\|token"`
