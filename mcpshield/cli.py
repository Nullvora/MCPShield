# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""MCPShield command-line interface."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.table import Table

from mcpshield import __version__
from mcpshield.models import ScanResult, ServerSpec, Severity

console = Console(stderr=False)
err = Console(stderr=True)

SEVERITIES = ["critical", "high", "medium", "low", "info"]


# --------------------------------------------------------------------------- helpers


def _spec_from_url(url: str, headers: dict[str, str]) -> ServerSpec:
    u = urlparse(url)
    transport = "sse" if u.path.rstrip("/").endswith("/sse") else "http"
    return ServerSpec(name=u.hostname or url, transport=transport, url=url, headers=headers, source="", client="CLI")


def _spec_from_command(cmd: str) -> ServerSpec:
    from mcpshield.config.loader import parse_command_string

    exe, args = parse_command_string(cmd)
    name = next((a for a in args if not a.startswith("-")), Path(exe).name)
    return ServerSpec(name=Path(name).name.split("@")[0] or "stdio", transport="stdio", command=exe, args=args, client="CLI")


def _parse_headers(values: tuple[str, ...]) -> dict[str, str]:
    out: dict[str, str] = {}
    for v in values:
        if ":" not in v:
            raise click.BadParameter(f"header must look like 'Name: value' (got {v!r})")
        k, val = v.split(":", 1)
        out[k.strip()] = val.strip()
    return out


def _collect_configs(paths: tuple[str, ...], auto: bool, project: Optional[str]) -> list[str]:
    from mcpshield.config.locations import discover

    configs = [str(Path(p).expanduser()) for p in paths]
    if auto:
        root = Path(project).expanduser().resolve() if project else Path.cwd()
        configs += [str(loc.path) for loc in discover(root, include_user=True)]
    elif project:
        configs += [str(loc.path) for loc in discover(Path(project).expanduser().resolve(), include_user=False)]
    seen: set[str] = set()
    return [c for c in configs if not (c in seen or seen.add(c))]  # type: ignore[func-returns-value]


def _load_yaml_or_json(path: str) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith((".yaml", ".yml")):
        import yaml

        return yaml.safe_load(text) or {}
    return json.loads(text)


def _apply_baseline(result: ScanResult, baseline: Optional[str]) -> int:
    if not baseline or not Path(baseline).exists():
        return 0
    data = json.loads(Path(baseline).read_text(encoding="utf-8"))
    suppressed = set(data.get("fingerprints", []))
    before = len(result.findings)
    result.findings = [f for f in result.findings if f.fingerprint not in suppressed]
    return before - len(result.findings)


def _exit_code(result: ScanResult, fail_on: str) -> int:
    if result.errors:
        return 2
    if fail_on == "none":
        return 0
    threshold = Severity.parse(fail_on)
    return 1 if any(f.severity >= threshold for f in result.findings) else 0


# --------------------------------------------------------------------------- root


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="mcpshield")
def cli() -> None:
    """MCPShield — security scanner, hardening checker and runtime guard for Model Context Protocol (MCP).

    \b
    Quick start:
      mcpshield scan --auto                      # scan every MCP config on this machine + current project
      mcpshield scan .mcp.json --live            # also connect to servers and audit their tools
      mcpshield scan --url https://mcp.example.com/mcp --live
      mcpshield proxy --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem@2025.8.21 ~/work
    """


# --------------------------------------------------------------------------- scan


@cli.command()
@click.argument("configs", nargs=-1, type=click.Path(dir_okay=False))
@click.option("-a", "--auto", is_flag=True, help="Discover MCP configs for Claude, Cursor, VS Code, Windsurf, Gemini, Codex, Zed… plus the project.")
@click.option("--project", type=click.Path(file_okay=False), help="Project directory to search for .mcp.json/.cursor/.vscode configs.")
@click.option("--url", "urls", multiple=True, help="Remote MCP endpoint to scan (repeatable).")
@click.option("--stdio", "stdio_cmds", multiple=True, help="Stdio server command line to scan, e.g. \"npx -y pkg@1.0.0\" (repeatable).")
@click.option("-H", "--header", "headers", multiple=True, help="Extra HTTP header for --url/live connections, e.g. 'Authorization: Bearer $TOKEN'.")
@click.option("--live", is_flag=True, help="Connect to servers and audit tools/prompts/resources. WARNING: starts stdio servers.")
@click.option("--no-probe", is_flag=True, help="With --live: skip HTTP security probes (auth, Origin, CORS, OAuth metadata).")
@click.option("--protocol", type=click.Choice(["auto", "modern", "legacy"]), default="auto", show_default=True,
              help="MCP protocol era for live connections (modern = 2026-07-28 stateless).")
@click.option("--timeout", type=float, default=20.0, show_default=True, help="Per-server live timeout in seconds.")
@click.option("--server", "only_servers", multiple=True, help="Only scan servers with this name (repeatable).")
@click.option("--allowlist", type=click.Path(exists=True, dir_okay=False), help="YAML/JSON allowlist of approved servers/packages/urls (shadow-MCP check).")
@click.option("--lock", "lock_file", type=click.Path(dir_okay=False), help="With --live: compare tools to a lock file from 'mcpshield pin' (rug-pull detection).")
@click.option("--baseline", type=click.Path(dir_okay=False), help="Suppress findings recorded in this baseline file.")
@click.option("--write-baseline", type=click.Path(dir_okay=False), help="Write current findings to a baseline file and exit 0.")
@click.option("--json", "json_out", type=click.Path(dir_okay=False), help="Write JSON report ('-' for stdout).")
@click.option("--sarif", "sarif_out", type=click.Path(dir_okay=False), help="Write SARIF 2.1.0 report (GitHub code scanning).")
@click.option("--html", "html_out", type=click.Path(dir_okay=False), help="Write self-contained HTML report.")
@click.option("--markdown", "md_out", type=click.Path(dir_okay=False), help="Write Markdown report ('-' for stdout).")
@click.option("--min-severity", type=click.Choice(SEVERITIES), default="low", show_default=True, help="Lowest severity shown on the console.")
@click.option("--fail-on", type=click.Choice(SEVERITIES + ["none"]), default="high", show_default=True, help="Exit 1 when a finding at/above this severity exists.")
@click.option("--include-disabled", is_flag=True, help="Also scan servers marked disabled in the config.")
@click.option("--insecure", is_flag=True, help="Do not verify TLS certificates for live connections.")
@click.option("-q", "--quiet", is_flag=True, help="No console report (use with --json/--sarif).")
@click.option("-v", "--verbose", is_flag=True, help="Show full evidence and descriptions.")
def scan(configs, auto, project, urls, stdio_cmds, headers, live, no_probe, protocol, timeout, only_servers, allowlist, lock_file,
         baseline, write_baseline, json_out, sarif_out, html_out, md_out, min_severity, fail_on, include_disabled, insecure, quiet, verbose):
    """Scan MCP client configs and/or servers for security issues."""
    from mcpshield.reporting.console import banner, print_result
    from mcpshield.scanner import ScanOptions, run_scan

    hdrs = _parse_headers(headers)
    paths = _collect_configs(configs, auto, project)
    specs = [_spec_from_url(u, hdrs) for u in urls] + [_spec_from_command(c) for c in stdio_cmds]
    if not paths and not specs:
        if not (auto or project):
            err.print("[yellow]Nothing to scan.[/yellow] Pass config files, --auto, --project, --url or --stdio. See 'mcpshield scan -h'.")
            sys.exit(2)
        err.print("[dim]No MCP configuration files found.[/dim]")
    to_stdout = json_out == "-" or md_out == "-"
    show = not quiet and not to_stdout
    if show:
        banner(console)
    if live and show:
        n_stdio = len(stdio_cmds) + (1 if paths else 0)
        if n_stdio:
            console.print("[yellow]--live starts configured stdio servers as local processes. Only scan configs you would run anyway.[/yellow]")
    options = ScanOptions(
        live=live, probe_http=not no_probe, timeout=timeout, prefer=protocol,
        allowlist=_load_yaml_or_json(allowlist) if allowlist else None, lock_file=lock_file,
        extra_headers=hdrs, verify_tls=not insecure, include_disabled=include_disabled,
        servers=list(only_servers) or None,
    )
    progress = (lambda m: console.print(f"[dim]· {m}[/dim]", highlight=False)) if show and verbose else None
    if show and not verbose:
        with console.status("Scanning…"):
            result = run_scan(paths, specs, options, progress)
    else:
        result = run_scan(paths, specs, options, progress)

    if write_baseline:
        Path(write_baseline).write_text(json.dumps({"tool": "mcpshield", "version": __version__,
                                                     "fingerprints": sorted(f.fingerprint for f in result.findings)}, indent=2) + "\n")
        console.print(f"Baseline with {len(result.findings)} finding(s) written to {write_baseline}")
        sys.exit(2 if result.errors else 0)
    suppressed = _apply_baseline(result, baseline)

    if json_out:
        text = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
        if json_out == "-":
            click.echo(text)
        else:
            Path(json_out).write_text(text + "\n", encoding="utf-8")
    if sarif_out:
        from mcpshield.reporting.sarif import write_sarif

        write_sarif(result, sarif_out)
    if html_out:
        from mcpshield.reporting.html import write_html

        write_html(result, html_out)
    if md_out:
        from mcpshield.reporting.markdown import to_markdown

        if md_out == "-":
            click.echo(to_markdown(result))
        else:
            Path(md_out).write_text(to_markdown(result), encoding="utf-8")

    if show:
        print_result(result, console, verbose=verbose, min_severity=Severity.parse(min_severity))
        if suppressed:
            console.print(f"[dim]{suppressed} finding(s) suppressed by baseline.[/dim]")
        for label, path in (("JSON", json_out), ("SARIF", sarif_out), ("HTML", html_out), ("Markdown", md_out)):
            if path and path != "-":
                console.print(f"[green]✓[/green] {label} report: {path}")
    sys.exit(_exit_code(result, fail_on))


# --------------------------------------------------------------------------- discover


@cli.command()
@click.option("--project", type=click.Path(file_okay=False), default=".", show_default=True, help="Project directory to include.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def discover(project, as_json):
    """Inventory every MCP server configured on this machine (shadow-MCP discovery)."""
    from mcpshield.config.loader import load_config_file
    from mcpshield.config.locations import discover as find

    rows = []
    for loc in find(Path(project).expanduser().resolve(), include_user=True):
        try:
            cfg = load_config_file(loc.path)
        except Exception as exc:  # noqa: BLE001
            rows.append({"file": str(loc.path), "client": loc.client, "scope": loc.scope, "error": str(exc), "servers": []})
            continue
        rows.append({"file": str(loc.path), "client": loc.client, "scope": loc.scope,
                     "servers": [s.to_dict() for s in cfg.servers], "errors": cfg.errors})
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    total = sum(len(r["servers"]) for r in rows)
    t = Table(title=f"{total} MCP server(s) in {len(rows)} config file(s)", header_style="bold")
    for col in ("Client", "Scope", "Server", "Transport", "Command / URL", "File"):
        t.add_column(col, overflow="fold")
    for r in rows:
        for s in r["servers"] or [{"name": "—", "transport": "", "command": r.get("error", ""), "args": [], "url": None}]:
            target = s.get("url") or " ".join([s.get("command") or "", *s.get("args", [])])
            t.add_row(r["client"], r["scope"], s["name"], s.get("transport", ""), target[:80], r["file"])
    console.print(t)


# --------------------------------------------------------------------------- inspect


@cli.command()
@click.argument("target", required=False)
@click.option("--stdio", "stdio_cmd", help="Stdio command line to inspect.")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), help="Config file containing the server.")
@click.option("--server", "server_name", help="Server name inside --config.")
@click.option("-H", "--header", "headers", multiple=True)
@click.option("--protocol", type=click.Choice(["auto", "modern", "legacy"]), default="auto")
@click.option("--timeout", type=float, default=20.0)
@click.option("--json", "as_json", is_flag=True)
def inspect(target, stdio_cmd, config_path, server_name, headers, protocol, timeout, as_json):
    """Connect to ONE server and print its capabilities, tools, prompts and resources (never calls tools)."""
    from mcpshield.config.loader import load_config_file
    from mcpshield.live.inspect import inspect_server

    hdrs = _parse_headers(headers)
    if config_path:
        cfg = load_config_file(config_path)
        matches = [s for s in cfg.servers if s.name == server_name] if server_name else cfg.servers[:1]
        if not matches:
            raise click.UsageError(f"server {server_name!r} not found in {config_path}")
        spec = matches[0]
    elif stdio_cmd:
        spec = _spec_from_command(stdio_cmd)
    elif target:
        spec = _spec_from_url(target, hdrs)
    else:
        raise click.UsageError("give a URL, --stdio CMD or --config FILE [--server NAME]")
    inv = inspect_server(spec, timeout=timeout, prefer=protocol, extra_headers=hdrs)
    if as_json:
        click.echo(json.dumps(inv.to_dict(), indent=2, ensure_ascii=False))
        sys.exit(1 if inv.errors and not inv.tools else 0)
    console.print(f"[bold]{inv.name}[/bold]  era={inv.era or '—'} protocol={inv.protocol_version or '—'}  server={inv.server_info}")
    for e in inv.errors:
        console.print(f"[yellow]⚠ {e}[/yellow]", highlight=False)
    if inv.tools:
        t = Table(title=f"{len(inv.tools)} tools", header_style="bold", show_lines=False)
        t.add_column("Tool")
        t.add_column("Description", overflow="fold")
        t.add_column("Params")
        for tool in inv.tools:
            props = (tool.get("inputSchema") or {}).get("properties") or {}
            t.add_row(str(tool.get("name")), repr(str(tool.get("description", ""))[:200])[1:-1], ", ".join(props))
        console.print(t)
    for label, items in (("prompts", inv.prompts), ("resources", inv.resources), ("resource templates", inv.resource_templates)):
        if items:
            console.print(f"[bold]{len(items)} {label}:[/bold] " + ", ".join(str(i.get("name") or i.get("uri") or i.get("uriTemplate")) for i in items[:30]))
    sys.exit(1 if inv.errors and not inv.tools else 0)


# --------------------------------------------------------------------------- pin / verify


def _live_inventories(configs, auto, project, urls, stdio_cmds, headers, timeout, protocol):
    from mcpshield.config.loader import load_config_file
    from mcpshield.live.inspect import inspect_server

    hdrs = _parse_headers(headers)
    specs: list[ServerSpec] = []
    for p in _collect_configs(configs, auto, project):
        try:
            specs += [s for s in load_config_file(p).servers if not s.disabled]
        except Exception as exc:  # noqa: BLE001
            err.print(f"[yellow]{p}: {exc}[/yellow]")
    specs += [_spec_from_url(u, hdrs) for u in urls] + [_spec_from_command(c) for c in stdio_cmds]
    if not specs:
        raise click.UsageError("no servers to connect to")
    invs = []
    for s in {s.name: s for s in specs}.values():
        inv = inspect_server(s, timeout=timeout, prefer=protocol, extra_headers=hdrs)
        status = f"{len(inv.tools)} tools" if not inv.errors else "; ".join(inv.errors)
        console.print(f"· {s.name}: {status}", highlight=False)
        invs.append(inv)
    return invs


_common_live = [
    click.argument("configs", nargs=-1, type=click.Path(dir_okay=False)),
    click.option("-a", "--auto", is_flag=True),
    click.option("--project", type=click.Path(file_okay=False)),
    click.option("--url", "urls", multiple=True),
    click.option("--stdio", "stdio_cmds", multiple=True),
    click.option("-H", "--header", "headers", multiple=True),
    click.option("--timeout", type=float, default=20.0),
    click.option("--protocol", type=click.Choice(["auto", "modern", "legacy"]), default="auto"),
    click.option("--lock", "lock_file", default="mcpshield.lock", show_default=True, type=click.Path(dir_okay=False)),
]


def _apply(decorators):
    def wrap(fn):
        for d in reversed(decorators):
            fn = d(fn)
        return fn
    return wrap


@cli.command()
@_apply(_common_live)
def pin(configs, auto, project, urls, stdio_cmds, headers, timeout, protocol, lock_file):
    """Record reviewed tool definitions in a lock file (commit it; verify later to catch rug pulls)."""
    from mcpshield.pinning import write_lock

    invs = _live_inventories(configs, auto, project, urls, stdio_cmds, headers, timeout, protocol)
    lock = write_lock(lock_file, invs)
    n = sum(len(s["tools"]) for s in lock["servers"].values())
    console.print(f"[green]✓[/green] pinned {n} tool(s) from {len(lock['servers'])} server(s) → {lock_file}")


@cli.command()
@_apply(_common_live)
def verify(configs, auto, project, urls, stdio_cmds, headers, timeout, protocol, lock_file):
    """Compare live tool definitions with the lock file. Exit 1 on any change."""
    from mcpshield.pinning import load_lock, verify_against_lock

    lock = load_lock(lock_file)
    invs = _live_inventories(configs, auto, project, urls, stdio_cmds, headers, timeout, protocol)
    findings = verify_against_lock(invs, lock)
    if not findings:
        console.print("[green]✓ all tool definitions match the lock file[/green]")
        sys.exit(0)
    for f in findings:
        console.print(f"[red]{f.severity.value.upper()}[/red] {f.server}: {f.title}")
        if f.evidence:
            console.print(f.evidence, style="dim", highlight=False)
    sys.exit(1)


# --------------------------------------------------------------------------- proxy


@cli.command(context_settings={"ignore_unknown_options": True, "allow_interspersed_args": False})
@click.option("--policy", "policy_path", type=click.Path(exists=True, dir_okay=False), help="Policy YAML (see 'mcpshield init-policy').")
@click.option("--audit-log", default=None, help="Hash-chained audit log path (default: ~/.mcpshield/audit/<name>.jsonl).")
@click.option("--lock", "lock_file", type=click.Path(exists=True, dir_okay=False), help="Lock file; hide tools whose definition changed.")
@click.option("--name", default=None, help="Server name used in logs/lock lookups.")
@click.option("--monitor", is_flag=True, help="Log only, never block (overrides policy mode).")
@click.option("--otlp-endpoint", default=None, help="Export agent activity as OpenTelemetry traces (OTLP/HTTP JSON), e.g. http://localhost:4318. "
              "Defaults to OTEL_EXPORTER_OTLP_(TRACES_)ENDPOINT.")
@click.option("--otlp-header", "otlp_headers", multiple=True, help="Extra OTLP header 'key=value' (repeatable; also OTEL_EXPORTER_OTLP_HEADERS).")
@click.option("--capture-args", is_flag=True, help="Include (secret-redacted) tool arguments in exported spans. Off by default.")
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
def proxy(policy_path, audit_log, lock_file, name, monitor, otlp_endpoint, otlp_headers, capture_args, command):
    """Run an stdio MCP server behind the MCPShield runtime guard.

    \b
    Use it in any client config:
      "command": "mcpshield",
      "args": ["proxy", "--policy", "/path/policy.yaml", "--", "npx", "-y", "some-mcp-server@1.2.3"]
    """
    from mcpshield.auditlog import AuditLog
    from mcpshield.pinning import load_lock
    from mcpshield.proxy.guard import StdioGuard
    from mcpshield.proxy.policy import Policy

    cmd = list(command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise click.UsageError("missing server command after --")
    try:
        policy = Policy.load(policy_path)
    except (ValueError, TypeError, OSError) as exc:
        raise click.ClickException(f"Invalid policy: {exc}") from exc
    if policy.require_pinned and not lock_file:
        raise click.UsageError("tools.require_pinned requires --lock")
    if monitor:
        policy.mode = "monitor"
    server_name = name or Path(next((a for a in cmd[1:] if not a.startswith("-")), cmd[0])).name.split("@")[0]
    import uuid

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in server_name)[:80] or "server"
    log_path = audit_log or str(Path.home() / ".mcpshield" / "audit" / f"{safe_name}-{uuid.uuid4().hex}.jsonl")
    from mcpshield.telemetry import OtlpExporter, parse_headers

    resource = {"mcpshield.server": server_name}
    exporter: Any = None
    if otlp_endpoint:
        hdrs = parse_headers(os.environ.get("OTEL_EXPORTER_OTLP_HEADERS"))
        hdrs.update(parse_headers(",".join(otlp_headers)))
        exporter = OtlpExporter(otlp_endpoint, hdrs, os.environ.get("OTEL_SERVICE_NAME", "mcpshield"), resource)
    else:
        exporter = OtlpExporter.from_env(os.environ.get("OTEL_SERVICE_NAME", "mcpshield"), resource)
    guard = StdioGuard(cmd[0], cmd[1:], policy, AuditLog(log_path), load_lock(lock_file) if lock_file else None, server_name,
                       exporter=exporter, capture_arguments=capture_args)
    sys.exit(guard.run())


@cli.command("init-policy")
@click.argument("path", default="mcpshield-policy.yaml", type=click.Path(dir_okay=False))
def init_policy(path):
    """Write an example runtime policy file."""
    from mcpshield.proxy.policy import EXAMPLE_POLICY

    p = Path(path)
    if p.exists():
        raise click.ClickException(f"{path} already exists")
    p.write_text(EXAMPLE_POLICY, encoding="utf-8")
    console.print(f"[green]✓[/green] wrote {path}")


@cli.command()
@click.argument("config", type=click.Path(exists=True, dir_okay=False))
@click.option("--policy", "policy_path", type=click.Path(dir_okay=False), help="Policy file to reference in wrapped entries.")
@click.option("--write", is_flag=True, help="Modify the file in place (a .bak copy is kept).")
def wrap(config, policy_path, write):
    """Rewrite a client config so every stdio server runs behind 'mcpshield proxy'."""
    from mcpshield.config.loader import load_json_lenient

    data = load_json_lenient(Path(config).read_text(encoding="utf-8"))
    exe = shutil.which("mcpshield") or "mcpshield"
    changed = 0

    def wrap_map(servers: dict[str, Any]) -> None:
        nonlocal changed
        for name, entry in servers.items():
            if not isinstance(entry, dict) or "command" not in entry or entry.get("command") in (exe, "mcpshield"):
                continue
            args = ["proxy", "--name", name]
            if policy_path:
                args += ["--policy", str(Path(policy_path).expanduser().resolve())]
            args += ["--", str(entry["command"]), *[str(a) for a in entry.get("args", [])]]
            entry["command"] = exe
            entry["args"] = args
            changed += 1

    for key in ("mcpServers", "servers", "context_servers"):
        if isinstance(data.get(key), dict):
            wrap_map(data[key])
    if isinstance(data.get("mcp"), dict) and isinstance(data["mcp"].get("servers"), dict):
        wrap_map(data["mcp"]["servers"])
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if write:
        shutil.copy2(config, config + ".bak")
        Path(config).write_text(text, encoding="utf-8")
        console.print(f"[green]✓[/green] wrapped {changed} server(s) in {config} (backup: {config}.bak)")
    else:
        click.echo(text)


# --------------------------------------------------------------------------- audit / rules


@cli.group()
def audit():
    """Audit-log utilities."""


@audit.command("verify")
@click.argument("log", type=click.Path(exists=True, dir_okay=False))
def audit_verify(log):
    """Verify the hash chain (and HMAC signatures when MCPSHIELD_AUDIT_KEY is set)."""
    from mcpshield.auditlog import verify as verify_log

    ok, problems, n = verify_log(log)
    if ok:
        console.print(f"[green]✓ {n} record(s) verified — chain intact{' and signatures valid' if os.environ.get('MCPSHIELD_AUDIT_KEY') else ''}[/green]")
        sys.exit(0)
    for p in problems[:50]:
        console.print(f"[red]✗[/red] {p}")
    sys.exit(1)


@cli.command()
@click.argument("logs", nargs=-1, type=click.Path(exists=True, dir_okay=False))
@click.option("--session", default=None, help="Only show sessions whose id starts with this prefix.")
@click.option("--alerts", "only_alerts", is_flag=True, help="Only sessions with alerts, blocked or flagged calls.")
@click.option("--summary", is_flag=True, help="One line per session instead of the full timeline.")
@click.option("--html", "html_out", type=click.Path(dir_okay=False), help="Write a self-contained HTML activity report.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable session summaries.")
def trace(logs, session, only_alerts, summary, html_out, as_json):
    """Show what your agents did: per-session timelines from runtime-guard audit logs.

    \b
    With no LOGS, reads every log in ~/.mcpshield/audit/.
      mcpshield trace                      # timeline of all sessions
      mcpshield trace --alerts --summary   # only risky sessions
      mcpshield trace --html activity.html
    """
    from mcpshield import tracing

    paths = [Path(p) for p in logs] or sorted((Path.home() / ".mcpshield" / "audit").glob("*.jsonl"))
    if not paths:
        raise click.ClickException("no audit logs found (run servers through 'mcpshield proxy' first, or pass log files)")
    integrity = tracing.verify_all(paths)
    sessions = tracing.filter_sessions(tracing.group_sessions(tracing.load_records(paths)), session, only_alerts)
    tampered = [p for p, (ok, _, _) in integrity.items() if not ok]
    if html_out:
        Path(html_out).write_text(tracing.render_html(sessions, integrity), encoding="utf-8")
    if as_json:
        click.echo(json.dumps({"integrity": {p: {"ok": ok, "records": n, "problems": pr[:20]} for p, (ok, pr, n) in integrity.items()},
                               "sessions": [s.summary() for s in sessions]}, indent=2))
        sys.exit(1 if tampered else 0)
    for p in tampered:
        console.print(f"[bold red]✗ integrity check failed:[/bold red] {p} — {integrity[p][1][0]}")
    if summary or not sessions:
        from rich import box

        t = Table(title=f"{len(sessions)} session(s)", box=box.SIMPLE_HEAD, pad_edge=False)
        t.add_column("session", no_wrap=True)
        t.add_column("started (UTC)", no_wrap=True)
        for col in ("calls", "blk", "flag", "err"):
            t.add_column(col, justify="right", no_wrap=True)
        t.add_column("alerts", no_wrap=True)
        t.add_column("tools", overflow="fold", ratio=1, min_width=12)
        for s in sessions:
            sm = s.summary()
            t.add_row(f"{s.session_id[:8]}\n[dim]{sm['server']}[/dim]", sm["started"][5:16].replace("T", " "), str(sm["calls"]),
                      f"[red]{sm['blocked']}[/red]" if sm["blocked"] else "0", str(sm["flagged"]), str(sm["errors"]),
                      "[bold red]" + "\n".join(sm["alerts"]) + "[/bold red]" if sm["alerts"] else "-", ", ".join(sm["tools"][:8]))
        console.print(t)
    else:
        colors = {"ok": "green", "warn": "yellow", "bad": "bold red"}
        for s in sessions:
            sm = s.summary()
            console.rule(f"[bold]{s.server}[/bold] · session {s.session_id[:12]} · {sm['calls']} call(s), {sm['blocked']} blocked"
                         f"{' · ALERT ' + ', '.join(sm['alerts']) if sm['alerts'] else ''}")
            for r in s.records:
                if r.get("event") not in tracing.TIMELINE_EVENTS:
                    continue
                label, detail = tracing.describe(r)
                c = colors[tracing.severity(r)]
                console.print(f"[dim]{str(r.get('ts', ''))[11:23]}[/dim] [{c}]{label:<28}[/{c}] {detail}", markup=True, highlight=False)
    if html_out:
        console.print(f"[green]✓[/green] wrote {html_out}")
    sys.exit(1 if tampered else 0)


@cli.command()
@click.option("--json", "as_json", is_flag=True)
@click.option("--markdown", "as_md", is_flag=True, help="Emit the rule catalogue as Markdown (docs/RULES.md).")
def rules(as_json, as_md):
    """List every detection rule."""
    from mcpshield.checks.registry import RULES
    from mcpshield.taxonomy import label

    if as_json:
        click.echo(json.dumps([{"id": r.id, "title": r.title, "severity": r.severity.value, "scope": r.scope,
                                "owasp_mcp": r.owasp_mcp, "owasp_asi": r.owasp_asi, "cwe": r.cwe,
                                "description": r.description, "remediation": r.remediation, "references": r.references}
                               for r in RULES.values()], indent=2))
        return
    if as_md:
        lines = ["# MCPShield rule catalogue", "", f"{len(RULES)} rules · generated by `mcpshield rules --markdown` (v{__version__}).", "",
                 "Scopes: **config** = static config analysis · **agent** = client/agent settings · **live** = requires `--live` · "
                 "**http** = remote-server probes · **integrity** = lock-file verification.", ""]
        for r in RULES.values():
            lines += [f"## {r.id} — {r.title}", "",
                      f"**Default severity:** {r.severity.value} · **Scope:** {r.scope}" +
                      (f" · **OWASP MCP:** {', '.join(label(x) for x in r.owasp_mcp)}" if r.owasp_mcp else "") +
                      (f" · **OWASP Agentic:** {', '.join(r.owasp_asi)}" if r.owasp_asi else "") +
                      (f" · **CWE:** {', '.join(r.cwe)}" if r.cwe else ""), "",
                      r.description, "", f"**Remediation:** {r.remediation}", ""]
            lines += [f"- <{u}>" for u in r.references] + ([""] if r.references else [])
        click.echo("\n".join(lines))
        return
    t = Table(header_style="bold", title=f"{len(RULES)} rules")
    for col in ("ID", "Severity", "Scope", "Title", "OWASP MCP"):
        t.add_column(col)
    for r in RULES.values():
        t.add_row(r.id, r.severity.value, r.scope, r.title, ", ".join(r.owasp_mcp))
    console.print(t)


def main() -> None:
    cli(prog_name="mcpshield")


if __name__ == "__main__":  # pragma: no cover
    main()
