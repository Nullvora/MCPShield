# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Rich terminal output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpshield import __version__
from mcpshield.models import ScanResult, Severity
from mcpshield.taxonomy import OWASP_MCP

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}


def banner(console: Console) -> None:
    console.print(Text.assemble(("MCPShield ", "bold cyan"), (f"v{__version__}", "dim"),
                                ("  ·  MCP security scanner by Nullvora", "dim")))


def print_result(result: ScanResult, console: Console, verbose: bool = False, min_severity: Severity = Severity.LOW) -> None:
    counts = result.counts
    summary = Table.grid(padding=(0, 2))
    summary.add_row(
        Text(f"Grade {result.grade}", style=GRADE_STYLE[result.grade]),
        Text(f"Risk {result.risk_score}/100"),
        *[Text(f"{counts[s.value]} {s.value}", style=SEV_STYLE[s]) for s in Severity],
    )
    live = f" · {len(result.inventories)} inspected live" if result.inventories else ""
    console.print(Panel(summary, title=f"{len(result.servers)} server(s) from {len(result.targets)} target(s){live}", expand=False))

    shown = [f for f in result.sorted_findings() if f.severity >= min_severity]
    if not shown:
        console.print("[green]No findings at or above the selected severity.[/green]")
    for f in shown:
        head = Text.assemble((f" {f.severity.value.upper()} ", SEV_STYLE[f.severity]), " ", (f.rule_id, "bold"), "  ", f.title)
        console.print(head)
        meta = []
        if f.server:
            meta.append(f"server: [bold]{f.server}[/bold]")
        if f.location:
            meta.append(f"at: {f.location}")
        if f.owasp_mcp:
            meta.append("OWASP " + ", ".join(f.owasp_mcp))
        if meta:
            console.print("   " + " · ".join(meta), highlight=False)
        if f.evidence:
            ev = f.evidence if verbose else f.evidence.splitlines()[0][:220]
            console.print(Text("   evidence: " + ev, style="dim"))
        if verbose:
            console.print(Text("   " + f.description, style="italic"))
        console.print(Text("   fix: " + f.remediation.splitlines()[0][:240], style="green"))
        console.print()

    cov = result.owasp_mcp_coverage()
    if cov:
        t = Table(title="OWASP MCP Top 10 exposure", show_edge=False, header_style="bold")
        t.add_column("ID")
        t.add_column("Risk")
        t.add_column("Findings", justify="right")
        for ref, n in cov.items():
            t.add_row(ref, OWASP_MCP.get(ref, ""), str(n))
        console.print(t)
    if result.errors:
        console.print("[yellow]Warnings:[/yellow]")
        for e in result.errors[:20]:
            console.print(f"  • {e}", highlight=False)
