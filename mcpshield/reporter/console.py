"""
MCPShield Reporter — Rich Terminal Console Output
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from mcpshield.models.findings import Finding, ScanResult, Severity

console = Console()


def print_banner() -> None:
    banner = Text()
    banner.append("\n  MCPShield ", style="bold white")
    banner.append("🛡️ ", style="")
    banner.append("v0.1.0\n", style="dim white")
    banner.append("  MCP Security Assessment Framework\n", style="dim cyan")
    banner.append("  by Nullvora  |  github.com/Nullvora/MCPShield\n", style="dim")
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))


def print_scan_header(target: str, scan_type: str, server_count: int) -> None:
    console.print()
    console.print(Rule("[bold cyan]Scan Configuration[/bold cyan]", style="cyan"))
    console.print(f"  [dim]Target    :[/dim] [white]{target}[/white]")
    console.print(f"  [dim]Scan type :[/dim] [white]{scan_type}[/white]")
    console.print(f"  [dim]Servers   :[/dim] [white]{server_count}[/white]")
    console.print()


def print_results(result: ScanResult) -> None:
    """Print the full scan result to the terminal."""

    _print_risk_banner(result)
    _print_finding_summary(result)

    if result.findings:
        console.print()
        console.print(Rule("[bold]Findings[/bold]", style="dim"))
        console.print()
        for finding in result.findings_by_severity():
            _print_finding(finding)

    if result.owasp_coverage:
        console.print()
        console.print(
            "  [dim]OWASP ASI coverage:[/dim] "
            + "  ".join(f"[cyan]{ref}[/cyan]" for ref in result.owasp_coverage)
        )

    if result.cves_referenced:
        console.print(
            "  [dim]CVEs referenced:   [/dim] "
            + "  ".join(f"[red]{c}[/red]" for c in result.cves_referenced)
        )

    console.print()


def _print_risk_banner(result: ScanResult) -> None:
    score = result.risk_score
    label = result.risk_label

    color_map = {
        "CRITICAL": "bold red",
        "HIGH":     "bold red",
        "MEDIUM":   "bold yellow",
        "LOW":      "bold cyan",
        "CLEAR":    "bold green",
    }
    color = color_map.get(label, "white")

    bar_filled  = int(score / 5)
    bar_empty   = 20 - bar_filled
    bar         = "█" * bar_filled + "░" * bar_empty

    t = Text()
    t.append("\n  Risk Score: ", style="dim white")
    t.append(f"{score:3d}/100  ", style=color)
    t.append(f"{bar}  ", style=color)
    t.append(f"[{label}]", style=color)
    t.append("\n")

    console.print(Panel(t, border_style=color.split()[-1], padding=(0, 2)))


def _print_finding_summary(result: ScanResult) -> None:
    counts = result.counts
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold dim",
        padding=(0, 2),
    )
    table.add_column("Severity", style="bold")
    table.add_column("Count",    style="bold", justify="right")

    severity_styles = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
        "INFO":     "dim",
    }
    for sev, style in severity_styles.items():
        count = counts.get(sev, 0)
        if count:
            table.add_row(
                Text(f"{Severity[sev].emoji}  {sev}", style=style),
                Text(str(count), style=style),
            )

    console.print()
    console.print(Rule("[bold]Finding Summary[/bold]", style="dim"))
    console.print(table)


def _print_finding(finding: Finding) -> None:
    sev      = finding.severity
    color    = sev.color
    emoji    = sev.emoji

    # Header line
    console.print(
        f"  {emoji} [{color}]{sev.value}[/{color}]  "
        f"[bold white]{finding.title}[/bold white]  "
        f"[dim][{finding.id}][/dim]"
    )
    console.print(f"     [dim]Category:[/dim] {finding.category.value}")
    console.print(f"     [dim]OWASP   :[/dim] {finding.owasp_ref}" +
                  (f"  [dim]CVEs: {', '.join(finding.cve_refs)}[/dim]" if finding.cve_refs else ""))
    console.print()

    # Description — wrapped
    for line in _wrap(finding.description, 90):
        console.print(f"     {line}")
    console.print()

    # Evidence
    console.print("     [dim]Evidence:[/dim]")
    for line in finding.evidence.strip().splitlines():
        console.print(f"       [italic dim]{line}[/italic dim]")
    console.print()

    # Remediation
    console.print("     [dim]Remediation:[/dim]")
    for line in finding.remediation.strip().splitlines():
        console.print(f"       [green]{line}[/green]")

    console.print()
    console.print(Rule(style="dim"))
    console.print()


def _wrap(text: str, width: int) -> list[str]:
    """Simple word wrapper."""
    words = text.split()
    lines, current = [], ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current = f"{current} {word}".lstrip()
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def print_error(message: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {message}")


def print_warning(message: str) -> None:
    console.print(f"[yellow]Warning:[/yellow] {message}")


def print_info(message: str) -> None:
    console.print(f"[dim]{message}[/dim]")
