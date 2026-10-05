# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Tool-definition pinning — detect rug pulls (silent tool redefinition after approval).

``mcpshield pin`` records a canonical SHA-256 of every tool/prompt definition in ``mcpshield.lock``;
``mcpshield verify`` (or ``scan --lock``) compares the live inventory with it.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcpshield import __version__
from mcpshield.checks.registry import make
from mcpshield.models import Finding, ServerInventory

LOCK_VERSION = 1


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def tool_digest(tool: dict[str, Any]) -> str:
    relevant = {k: tool.get(k) for k in ("name", "title", "description", "inputSchema", "outputSchema", "annotations") if k in tool}
    return "sha256:" + hashlib.sha256(canonical(relevant).encode("utf-8")).hexdigest()


def build_lock(inventories: list[ServerInventory]) -> dict[str, Any]:
    servers: dict[str, Any] = {}
    for inv in inventories:
        if inv.errors and not inv.tools:
            continue
        servers[inv.name] = {
            "target": inv.target,
            "server_info": inv.server_info,
            "protocol_version": inv.protocol_version,
            "tools": {str(t.get("name")): {"digest": tool_digest(t), "definition": t} for t in inv.tools},
            "prompts": {str(p.get("name")): "sha256:" + hashlib.sha256(canonical(p).encode()).hexdigest() for p in inv.prompts},
        }
    return {
        "lockVersion": LOCK_VERSION,
        "generator": f"mcpshield {__version__}",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "servers": servers,
    }


def write_lock(path: str | Path, inventories: list[ServerInventory], merge: bool = True) -> dict[str, Any]:
    p = Path(path)
    lock = build_lock(inventories)
    if merge and p.exists():
        old = json.loads(p.read_text(encoding="utf-8"))
        old.setdefault("servers", {}).update(lock["servers"])
        old["created"] = lock["created"]
        old["generator"] = lock["generator"]
        lock = old
    p.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return lock


def load_lock(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _diff(old: dict[str, Any], new: dict[str, Any]) -> str:
    a = json.dumps(old, indent=1, sort_keys=True, ensure_ascii=False).splitlines()
    b = json.dumps(new, indent=1, sort_keys=True, ensure_ascii=False).splitlines()
    lines = [ln for ln in difflib.unified_diff(a, b, "pinned", "live", lineterm="", n=1) if not ln.startswith(("---", "+++"))]
    return "\n".join(lines[:40])


def verify_against_lock(inventories: list[ServerInventory], lock: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    pinned_servers = lock.get("servers", {})
    for inv in inventories:
        pinned = pinned_servers.get(inv.name)
        if pinned is None or (inv.errors and not inv.tools):
            continue
        live = {str(t.get("name")): t for t in inv.tools}
        ptools = pinned.get("tools", {})
        for name, tool in live.items():
            if name not in ptools:
                findings.append(make("MCPS-TOOL-017", server=inv.name, location=f"{inv.target} :: tool:{name}",
                                     title=f"New tool '{name}' since pinning", evidence="tool not present in lock file"))
                continue
            if tool_digest(tool) != ptools[name]["digest"]:
                findings.append(make("MCPS-TOOL-016", server=inv.name, location=f"{inv.target} :: tool:{name}",
                                     title=f"Tool '{name}' changed since it was pinned (possible rug pull)",
                                     evidence=_diff(ptools[name].get("definition", {}), tool)))
        for name in ptools:
            if name not in live:
                findings.append(make("MCPS-TOOL-017", server=inv.name, location=f"{inv.target} :: tool:{name}",
                                     title=f"Pinned tool '{name}' was removed", evidence="tool missing from live inventory"))
    return findings
