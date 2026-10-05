# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Scan orchestration: configs → static checks → (optional) live inspection → cross-server analysis."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from collections.abc import Callable

from mcpshield.checks.config_checks import check_config, check_duplicates, check_toxic_combination
from mcpshield.checks.tool_checks import check_cross_server, check_inventory
from mcpshield.config.loader import LoadedConfig, load_config_file
from mcpshield.models import ScanResult, ServerInventory, ServerSpec

Progress = Callable[[str], None]


@dataclass
class ScanOptions:
    live: bool = False
    probe_http: bool = True
    timeout: float = 20.0
    prefer: str = "auto"                   # auto | modern | legacy
    allowlist: Optional[dict[str, Any]] = None
    lock_file: Optional[str] = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    include_disabled: bool = False
    servers: Optional[list[str]] = None    # restrict to these server names
    workers: int = 4


def is_project_scope(path: str) -> bool:
    """True for repository-level files (.mcp.json, <repo>/.claude/settings.json, <repo>/.vscode/mcp.json …)."""
    try:
        p = Path(path).expanduser().resolve()
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        return False
    dotdirs = (".claude", ".cursor", ".vscode", ".gemini", ".amazonq")
    root = p.parent.parent if p.parent.name in dotdirs else p.parent
    if root == home:
        return False
    return p.name == ".mcp.json" or p.parent.name in dotdirs


def run_scan(configs: list[str | LoadedConfig], extra_specs: Optional[list[ServerSpec]] = None,
             options: Optional[ScanOptions] = None, progress: Optional[Progress] = None) -> ScanResult:
    options = options or ScanOptions()
    emit = progress or (lambda _m: None)
    result = ScanResult()

    loaded: list[LoadedConfig] = []
    for c in configs:
        if isinstance(c, LoadedConfig):
            loaded.append(c)
            continue
        try:
            loaded.append(load_config_file(c))
            emit(f"loaded {c}")
        except FileNotFoundError:
            result.errors.append(f"{c}: file not found")
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"{c}: {exc}")

    for cfg in loaded:
        result.errors.extend(f"{cfg.path}: {error}" for error in cfg.errors)
        result.targets.append(cfg.path)
        servers = [s for s in cfg.servers if (options.include_disabled or not s.disabled)]
        if options.servers:
            servers = [s for s in servers if s.name in options.servers]
        cfg_view = LoadedConfig(cfg.path, cfg.client, cfg.data, servers, cfg.errors)
        result.servers += servers
        result.add(check_config(cfg_view, project_scope=is_project_scope(cfg.path), allowlist=options.allowlist))
        emit(f"{cfg.path}: {len(servers)} server(s) [{cfg.client}]")

    for spec in extra_specs or []:
        result.targets.append(spec.url or " ".join(spec.command_line))
        result.servers.append(spec)
        from mcpshield.checks.config_checks import check_server

        result.add(check_server(spec))

    result.add(check_duplicates(result.servers))
    if not options.live:
        result.add(check_toxic_combination(result.servers))

    if options.live and result.servers:
        from mcpshield.live.inspect import inspect_server
        from mcpshield.live.probes import probe_http

        def _one(spec: ServerSpec) -> tuple[ServerInventory, list]:
            emit(f"connecting to {spec.name} ({spec.transport}) …")
            inv = inspect_server(spec, timeout=options.timeout, prefer=options.prefer,
                                 extra_headers=options.extra_headers, verify_tls=options.verify_tls)
            probe_findings = probe_http(spec, inv, timeout=min(options.timeout, 10.0), verify_tls=options.verify_tls) \
                if options.probe_http and spec.transport in ("http", "sse") else []
            status = f"{len(inv.tools)} tools, {len(inv.prompts)} prompts, {len(inv.resources)} resources" if not inv.errors else "; ".join(inv.errors)
            emit(f"{spec.name}: {inv.era or '-'} {inv.protocol_version or ''} — {status}")
            return inv, probe_findings

        uniq: dict[str, ServerSpec] = {}
        for s in result.servers:
            uniq.setdefault(s.name, s)
        with ThreadPoolExecutor(max_workers=max(1, options.workers)) as pool:
            for inv, pf in pool.map(_one, uniq.values()):
                result.inventories.append(inv)
                result.add(pf)
                result.add(check_inventory(inv))
                for e in inv.errors:
                    result.errors.append(f"{inv.name}: {e}")
        result.add(check_cross_server([i for i in result.inventories if i.tools]))
        if not any(f.rule_id == "MCPS-PRV-003" for f in result.findings):
            live_ok = {i.name for i in result.inventories if i.tools or not i.errors}
            result.add(check_toxic_combination([s for s in result.servers if s.name not in live_ok]))
        if options.lock_file:
            from mcpshield.pinning import load_lock, verify_against_lock

            try:
                result.add(verify_against_lock(result.inventories, load_lock(options.lock_file)))
            except FileNotFoundError:
                result.errors.append(f"lock file not found: {options.lock_file}")

    result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return result
