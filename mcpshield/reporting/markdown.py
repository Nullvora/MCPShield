# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Markdown report (PR comments, tickets, wikis)."""

from __future__ import annotations

from mcpshield.models import ScanResult
from mcpshield.taxonomy import OWASP_MCP

_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def to_markdown(result: ScanResult) -> str:
    c = result.counts
    lines = [
        "# MCPShield security report",
        "",
        f"**Grade {result.grade}** · risk score **{result.risk_score}/100** · "
        + " · ".join(f"{_ICON[k]} {v} {k}" for k, v in c.items()),
        "",
        f"Scanned {len(result.servers)} server(s) from {len(result.targets)} target(s)"
        + (f", {len(result.inventories)} inspected live" if result.inventories else "") + f" — MCPShield v{result.version}, {result.started_at}.",
        "",
    ]
    if result.findings:
        lines += ["| Severity | Rule | Server | Finding | Evidence |", "|---|---|---|---|---|"]
        for f in result.sorted_findings():
            ev = f.evidence.splitlines()[0][:140] if f.evidence else ""
            lines.append(f"| {_ICON[f.severity.value]} {f.severity.value} | `{f.rule_id}` | {_cell(f.server)} | {_cell(f.title)} | {_cell(ev)} |")
        lines += ["", "## Remediation", ""]
        seen = set()
        for f in result.sorted_findings():
            if f.rule_id in seen:
                continue
            seen.add(f.rule_id)
            lines.append(f"- **{f.rule_id} — {f.title}**: {f.remediation}")
    else:
        lines.append("✅ No findings.")
    cov = result.owasp_mcp_coverage()
    if cov:
        lines += ["", "## OWASP MCP Top 10", "", "| ID | Risk | Findings |", "|---|---|---|"]
        lines += [f"| {k} | {OWASP_MCP.get(k, '')} | {v} |" for k, v in cov.items()]
    return "\n".join(lines) + "\n"
