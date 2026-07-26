"""
MCPShield Scanner — Core Engine
Orchestrates all scanner modules and returns a unified ScanResult.
"""

from __future__ import annotations

from collections.abc import Callable

from mcpshield.models.config import MCPConfig, parse_config_dict, parse_config_file
from mcpshield.models.findings import Finding, ScanResult, ScanTarget
from mcpshield.scanner.auth import audit_auth
from mcpshield.scanner.injection import audit_injection
from mcpshield.scanner.privilege import audit_privilege
from mcpshield.scanner.supply_chain import audit_supply_chain
from mcpshield.scanner.transport import audit_transport

# ── Scan modes ────────────────────────────────────────────────────────────────

def scan_config_file(
    path: str,
    modules: list[str] | None = None,
    progress_cb: Callable[[str], None] | None = None,
) -> ScanResult:
    """
    Run a full security scan against an MCP config file.

    Args:
        path:        Path to the MCP config JSON file.
        modules:     List of module names to run. None = all.
                     Options: transport, auth, injection, supply_chain, privilege
        progress_cb: Optional callback called with status messages during scan.

    Returns:
        ScanResult with all findings.
    """
    def _emit(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    _emit(f"Parsing config file: {path}")
    config = parse_config_file(path)

    target = ScanTarget(
        raw=path,
        scan_type="config_file",
        path=path,
    )

    return _run_scan(config, target, modules, _emit)


def scan_config_dict(
    data: dict,
    label: str = "<inline>",
    modules: list[str] | None = None,
    progress_cb: Callable[[str], None] | None = None,
) -> ScanResult:
    """
    Run a full security scan against an in-memory config dict.
    Useful for testing and integration with other tools.
    """
    def _emit(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    _emit("Parsing config dict...")
    config = parse_config_dict(data, source=label)

    target = ScanTarget(
        raw=label,
        scan_type="config_file",
        path=label,
    )

    return _run_scan(config, target, modules, _emit)


# ── Internal scan runner ──────────────────────────────────────────────────────

_MODULE_MAP: dict[str, Callable[[MCPConfig], list[Finding]]] = {
    "transport":    audit_transport,
    "auth":         audit_auth,
    "injection":    audit_injection,
    "supply_chain": audit_supply_chain,
    "privilege":    audit_privilege,
}


def _run_scan(
    config: MCPConfig,
    target: ScanTarget,
    modules: list[str] | None,
    emit: Callable[[str], None],
) -> ScanResult:

    result = ScanResult(target=target)

    # Surface config parse errors as INFO findings
    for err in config.parse_errors:
        result.findings.append(Finding(
            id="CFG-001",
            title="Config Parse Warning",
            severity=__import__("mcpshield.models.findings", fromlist=["Severity"]).Severity.INFO,
            category=__import__("mcpshield.models.findings", fromlist=["Category"]).Category.CONFIGURATION,
            description=f"Issue encountered while parsing config: {err}",
            affected_component="Config file",
            evidence=err,
            remediation="Review and correct the config file structure.",
            owasp_ref="",
        ))

    if config.server_count == 0 and not config.parse_errors:
        result.findings.append(Finding(
            id="CFG-002",
            title="No MCP Servers Found in Config",
            severity=__import__("mcpshield.models.findings", fromlist=["Severity"]).Severity.INFO,
            category=__import__("mcpshield.models.findings", fromlist=["Category"]).Category.CONFIGURATION,
            description="The config file was parsed successfully but contains no MCP server definitions.",
            affected_component="Config file",
            evidence="servers list is empty",
            remediation="Ensure the config file contains at least one mcpServers entry.",
            owasp_ref="",
        ))
        return result

    emit(f"Found {config.server_count} MCP server(s): {[s.name for s in config.servers]}")

    active_modules = modules or list(_MODULE_MAP.keys())

    for module_name in active_modules:
        fn = _MODULE_MAP.get(module_name)
        if not fn:
            emit(f"[warn] Unknown module: {module_name!r} — skipping")
            continue

        emit(f"Running module: {module_name}...")
        try:
            new_findings = fn(config)
            result.findings.extend(new_findings)
            emit(f"  → {len(new_findings)} finding(s)")
        except Exception as exc:
            emit(f"  [error] Module '{module_name}' raised an exception: {exc}")

    emit(
        f"Scan complete — {len(result.findings)} finding(s) | "
        f"Risk score: {result.risk_score}/100 [{result.risk_label}]"
    )

    return result
