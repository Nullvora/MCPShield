"""
MCPShield — Command Line Interface
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option("0.1.0", prog_name="mcpshield")
def cli():
    """
    \b
    MCPShield 🛡️  — MCP Security Assessment Framework
    by Nullvora | github.com/Nullvora/MCPShield

    Scan, harden, and monitor Model Context Protocol deployments.
    """


# ── scan command ──────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", metavar="CONFIG_FILE_OR_URL")
@click.option(
    "--modules", "-m",
    default="all",
    show_default=True,
    help=(
        "Comma-separated list of modules to run. "
        "Options: transport,auth,injection,supply_chain,privilege  "
        "Default: all"
    ),
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output directory for reports. If not set, prints to terminal only.",
)
@click.option(
    "--format", "-f",
    "fmt",
    default="console",
    type=click.Choice(["console", "html", "json", "all"], case_sensitive=False),
    show_default=True,
    help="Output format.",
)
@click.option(
    "--severity", "-s",
    default="LOW",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    show_default=True,
    help="Minimum severity level to display/include in reports.",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress messages.")
@click.option("--no-banner",   is_flag=True, help="Suppress the MCPShield banner.")
def scan(target, modules, output, fmt, severity, quiet, no_banner):
    """
    Run a security assessment against an MCP configuration.

    \b
    Examples:
      mcpshield scan ~/.config/claude/claude_desktop_config.json
      mcpshield scan ./mcp_config.json --format html --output ./reports/
      mcpshield scan ./mcp_config.json --modules transport,auth --severity HIGH
    """
    from mcpshield.reporter.console import (
        print_banner,
        print_error,
        print_info,
        print_results,
    )
    from mcpshield.reporter.html import save_html_report
    from mcpshield.reporter.json_report import save_json_report
    from mcpshield.scanner.core import scan_config_file

    if not no_banner:
        print_banner()

    # ── Resolve modules ───────────────────────────────────────────────────────
    module_list = None
    if modules.lower() != "all":
        module_list = [m.strip() for m in modules.split(",")]

    # ── Resolve target type ───────────────────────────────────────────────────
    if target.startswith(("http://", "https://")):
        print_error("Live HTTP scanning is available in MCPShield v0.2+. "
                    "Please provide a local config file path for now.")
        sys.exit(1)

    if not Path(target).exists():
        print_error(f"Config file not found: {target}")
        sys.exit(1)

    # ── Run scan ──────────────────────────────────────────────────────────────
    def progress(msg):
        if not quiet:
            print_info(msg)

    try:
        result = scan_config_file(
            path=target,
            modules=module_list,
            progress_cb=progress,
        )
    except Exception as exc:
        print_error(f"Scan failed: {exc}")
        sys.exit(1)

    # ── Filter by severity ────────────────────────────────────────────────────
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    min_idx   = sev_order.index(severity.upper())
    result.findings = [
        f for f in result.findings
        if sev_order.index(f.severity.value) <= min_idx
    ]

    # ── Output ────────────────────────────────────────────────────────────────
    if fmt in ("console", "all"):
        print_results(result)

    if fmt in ("html", "all") and output:
        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)
        html_path = out_dir / f"mcpshield_{_safe_name(target)}.html"
        save_html_report(result, str(html_path))
        console.print(f"[green]HTML report saved:[/green] {html_path}")

    if fmt in ("json", "all") and output:
        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / f"mcpshield_{_safe_name(target)}.json"
        save_json_report(result, str(json_path))
        console.print(f"[green]JSON report saved:[/green] {json_path}")

    # ── Exit code: non-zero if CRITICAL or HIGH findings ─────────────────────
    has_critical_or_high = any(
        f.severity.value in ("CRITICAL", "HIGH") for f in result.findings
    )
    sys.exit(1 if has_critical_or_high else 0)


# ── monitor command ───────────────────────────────────────────────────────────

@cli.command()
@click.option("--log",    "-l", default="./audit/mcpshield.log", show_default=True,
              help="Path to the audit log file.")
@click.option("--mode",   "-m", default="monitor",
              type=click.Choice(["monitor", "enforce"], case_sensitive=False),
              show_default=True,
              help=(
                  "monitor = log and alert only.  "
                  "enforce = block calls that violate policy."
              ))
@click.option("--policy", "-p", default=None,
              help="Path to a custom policy YAML/JSON file. Uses built-in defaults if not set.")
def monitor(log, mode, policy):
    """
    Start the MCPShield runtime monitor.

    \b
    The monitor intercepts MCP tool calls, evaluates them against policy rules,
    detects anomalous behaviour, and writes a tamper-evident audit trail.

    \b
    Examples:
      mcpshield monitor
      mcpshield monitor --mode enforce --log ./prod-audit.log
      mcpshield monitor --policy ./my-policy.json
    """
    from mcpshield.monitor import AgentMonitor
    from mcpshield.reporter.console import print_banner

    print_banner()
    console.print("[cyan]Starting MCPShield monitor[/cyan]")
    console.print(f"  Mode    : [bold]{mode.upper()}[/bold]")
    console.print(f"  Log     : {log}")
    console.print(f"  Policy  : {policy or '(built-in defaults)'}")
    console.print()
    console.print("[dim]Monitor is running. Send tool call data via the Python API.[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")
    console.print()

    monitor_instance = AgentMonitor(log_path=log)

    if policy:
        import json  # type: ignore

        import yaml
        try:
            with open(policy) as fh:
                policy_data = json.load(fh) if policy.endswith(".json") else yaml.safe_load(fh)
            monitor_instance.enforcer.load_from_dict(policy_data)
            console.print(f"[green]Custom policy loaded:[/green] {policy}")
        except Exception as exc:
            console.print(f"[red]Failed to load policy file:[/red] {exc}")

    console.print(f"[green]✓[/green] Monitor initialised. Audit log: {log}")


# ── verify command ────────────────────────────────────────────────────────────

@cli.command()
@click.argument("log_file")
def verify(log_file):
    """
    Verify the integrity of an MCPShield audit log.

    Checks the hash chain of the log file to detect tampering,
    deletions, or insertions.

    \b
    Example:
      mcpshield verify ./audit/mcpshield.log
    """
    from mcpshield.monitor.logger import AuditLogger

    console.print(f"[cyan]Verifying audit log:[/cyan] {log_file}")

    if not Path(log_file).exists():
        console.print(f"[red]Log file not found:[/red] {log_file}")
        sys.exit(1)

    logger = AuditLogger(log_file)
    intact, violations = logger.verify_chain()

    if intact:
        console.print("[bold green]✓ Audit log is intact — no tampering detected.[/bold green]")
        sys.exit(0)
    else:
        console.print(f"[bold red]✗ Audit log integrity FAILED — {len(violations)} violation(s):[/bold red]")
        for v in violations:
            console.print(f"  [red]•[/red] {v}")
        sys.exit(1)


# ── report command ────────────────────────────────────────────────────────────

@cli.command()
@click.argument("json_file")
@click.option("--output", "-o", default=".", show_default=True,
              help="Output directory for the HTML report.")
def report(json_file, output):
    """
    Generate an HTML report from a previously saved JSON scan result.

    \b
    Example:
      mcpshield report ./reports/mcpshield_result.json --output ./reports/
    """
    import json as _json

    from mcpshield.models import Category, Finding, ScanResult, ScanTarget, Severity
    from mcpshield.reporter.html import save_html_report

    if not Path(json_file).exists():
        console.print(f"[red]JSON file not found:[/red] {json_file}")
        sys.exit(1)

    console.print(f"[cyan]Generating HTML report from:[/cyan] {json_file}")

    with open(json_file) as fh:
        data = _json.load(fh)

    # Reconstruct ScanResult from dict
    target = ScanTarget(
        raw=data["target"]["raw"],
        scan_type=data["target"]["scan_type"],
        path=data["target"].get("path"),
    )
    result = ScanResult(
        target=target,
        timestamp=data["timestamp"],
        scanner_version=data.get("mcpshield_version", "0.1.0"),
    )
    for fd in data.get("findings", []):
        result.findings.append(Finding(
            id=fd["id"],
            title=fd["title"],
            severity=Severity(fd["severity"]),
            category=Category(fd["category"]),
            description=fd["description"],
            affected_component=fd["affected_component"],
            evidence=fd["evidence"],
            remediation=fd["remediation"],
            owasp_ref=fd.get("owasp_ref", ""),
            cve_refs=fd.get("cve_refs", []),
        ))

    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "mcpshield_report.html"
    save_html_report(result, str(html_path))
    console.print(f"[green]HTML report saved:[/green] {html_path}")


# ── helpers ───────────────────────────────────────────────────────────────────

def _safe_name(path: str) -> str:
    return Path(path).stem.replace(" ", "_")


def main():
    cli()


if __name__ == "__main__":
    main()
