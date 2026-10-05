# CI/CD integration

## GitHub Action

```yaml
name: MCP security
on: [pull_request, push]
permissions: { contents: read, security-events: write }
jobs:
  mcpshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Nullvora/MCPShield@v1
        with:
          path: .                 # discovers .mcp.json, .cursor/, .vscode/, .claude/, .gemini/ … in the repo
          fail-on: high           # critical|high|medium|low|info|none
          allowlist: .github/mcp-allowlist.yaml   # optional
```

The action uploads SARIF to **Security → Code scanning** and writes a Markdown summary to the job page.

## Any CI

```bash
pip install mcpshield
mcpshield scan --project . --sarif mcpshield.sarif --markdown mcpshield.md --fail-on high
```

GitLab: upload `mcpshield.sarif` or convert the JSON report (`--json`) to your dashboard of choice.

## pre-commit

```yaml
repos:
  - repo: https://github.com/Nullvora/MCPShield
    rev: v1.1.0
    hooks:
      - id: mcpshield
```

## Baselines and allowlists

```bash
mcpshield scan --project . --write-baseline .mcpshield-baseline.json   # accept today's findings
mcpshield scan --project . --baseline .mcpshield-baseline.json          # fail only on new ones
mcpshield scan --auto --allowlist examples/allowlist.yaml               # flag unapproved (shadow) servers
```

## Rug-pull gate

Commit `mcpshield.lock` (from `mcpshield pin`) and run `mcpshield verify` in a scheduled job that has the servers'
runtimes available. Any silent change to a tool's description or schema fails the job.

## Exit codes

`0` no findings at/above `--fail-on` · `1` findings at/above threshold · `2` usage error.
