# Try MCPShield and tell us what happened

Start with the static scan; no API keys or cloud account are needed:

```bash
python -m pip install .
mcpshield scan tests/fixtures/vulnerable_config.json --fail-on none
mcpshield scan tests/fixtures/secure_config.json
```

Then scan a copy of your own config without `--live`. Do not share its original
contents. Replace secrets, internal hostnames, personal paths and customer data
before uploading a minimal reproduction.

Use the Product feedback issue form for usability, the detection template for
false positives/missed findings, and the bug template for failures. For security
vulnerabilities, use the private process in [SECURITY.md](../SECURITY.md).

Please include:

1. MCPShield version, OS, Python version and MCP client.
2. What you wanted to check and minutes to your first useful result.
3. Which finding was useful, confusing, incorrect, or missing (include rule ID).
4. What stopped you using it and the one change you want next.
5. Whether you would use it again in your workflow.

Maintainer routine: review new feedback twice weekly, reproduce reports, group
recurring problems, and link each accepted change to its issue. Record actual
counts; do not present stars or downloads as proof of security effectiveness.
