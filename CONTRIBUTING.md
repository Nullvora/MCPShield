# Contributing to MCPShield

Thanks for helping secure the MCP ecosystem! Detection rules, advisory data, false-positive reports and docs are
all valuable contributions.

## Development setup

```bash
git clone https://github.com/Nullvora/MCPShield && cd MCPShield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # includes the official `mcp` SDK used by the live test servers
pytest                           # ~130 tests; live tests start local fixture servers
ruff check mcpshield tests && mypy mcpshield
```

## Project layout

```
mcpshield/
  config/         client config discovery + parsing (Claude, Cursor, VS Code, Windsurf, Gemini, Codex, Zed …)
  checks/         detection logic
    registry.py     ← every rule (ID, severity, OWASP/CWE mapping, remediation)
    config_checks.py  static config rules        text.py  injection / hidden-char / secret primitives
    tool_checks.py    live tool/prompt rules      packages.py  package extraction + advisory matching
  live/           dual-era MCP client (2026-07-28 stateless + legacy initialize) and HTTP probes
  proxy/          runtime guard (stdio proxy) and policy engine
  pinning.py      tool-definition lock files (rug-pull detection)
  auditlog.py     hash-chained, HMAC-signed audit log
  reporting/      console, JSON, SARIF, HTML, Markdown
  data/           advisories.json, known_packages.json
tests/fixtures/servers/  poisoned, clean and 2026-07-28 fixture MCP servers
```

## Adding a rule

1. Define it in `mcpshield/checks/registry.py` (unique `MCPS-<AREA>-NNN` ID, default severity, OWASP MCP / ASI / CWE
   mapping, remediation, primary-source references).
2. Emit it with `make("MCPS-…", …)` from the relevant check module.
3. Add a positive **and** a negative test. For live rules, extend a fixture server.
4. Regenerate the catalogue: `mcpshield rules --markdown > docs/RULES.md`.

Keep false positives low: before merging a tool-metadata heuristic, run it against real servers
(`mcpshield scan <config> --live`) — see "Benchmark" in `docs/ARCHITECTURE.md`.

## Adding an advisory

Edit `mcpshield/data/advisories.json`. Every entry needs the exact package name, ecosystem, affected range
(PEP 440 specifier), fixed version (if any), severity and a **primary source URL** (GHSA, OSV, NVD or the vendor).
Unverified or AI-generated CVE data will not be merged.

## Pull requests

- One logical change per PR; update `CHANGELOG.md`.
- Never commit real secrets — test fixtures use obviously fake values.
- Contributions are accepted under the Apache License 2.0 ("inbound = outbound"). Sign off every commit
  (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/). No CLA is required.
