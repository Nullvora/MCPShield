# Examples

| File | Use |
|---|---|
| `allowlist.yaml` | `mcpshield scan --auto --allowlist examples/allowlist.yaml` — report unapproved (shadow) MCP servers |
| `strict-policy.yaml` | `mcpshield proxy --policy examples/strict-policy.yaml -- <server>` — strict runtime policy |
| `github-workflow.yml` | Drop into `.github/workflows/` to scan MCP configs on every PR |
| `sample-report.html` | HTML report from scanning `tests/fixtures/vulnerable_config.json` plus the poisoned fixture server |

More templates live in [`hardening/config_templates/`](../hardening/config_templates/).
