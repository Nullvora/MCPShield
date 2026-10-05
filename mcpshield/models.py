# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Core data models: findings, server specs, inventories and scan results."""

from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from mcpshield import __version__


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls(value.strip().lower())
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown severity {value!r}") from exc

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


@dataclass
class Finding:
    """A single security finding."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    server: str = ""
    location: str = ""          # config file path, URL or "tool:<name>"
    evidence: str = ""
    owasp_mcp: list[str] = field(default_factory=list)
    owasp_asi: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable identifier used for baselines and SARIF partialFingerprints."""
        raw = "|".join([self.rule_id, self.server, self.location, self.title])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ServerSpec:
    """A normalised MCP server definition found in a client configuration file."""

    name: str
    transport: str                       # stdio | http | sse | unknown
    source: str = ""                     # file the definition came from
    client: str = ""                     # e.g. "Claude Desktop", "Cursor", "VS Code"
    command: Optional[str] = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    disabled: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def command_line(self) -> list[str]:
        return ([self.command] if self.command else []) + [str(a) for a in self.args]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport,
            "source": self.source,
            "client": self.client,
            "command": self.command,
            "args": self.args,
            "env_keys": sorted(self.env.keys()),     # never serialise secret values
            "url": self.url,
            "header_keys": sorted(self.headers.keys()),
            "disabled": self.disabled,
        }


@dataclass
class ServerInventory:
    """What a live connection to an MCP server revealed."""

    name: str
    target: str
    transport: str
    protocol_version: str = ""
    era: str = ""                        # "modern" (2026-07-28+) | "legacy" (initialize-based)
    server_info: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    instructions: str = ""
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    resource_templates: list[dict[str, Any]] = field(default_factory=list)
    http: dict[str, Any] = field(default_factory=dict)   # probe observations for HTTP servers
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SEV_BASE = {Severity.CRITICAL: 75, Severity.HIGH: 50, Severity.MEDIUM: 25, Severity.LOW: 8, Severity.INFO: 0}
_SEV_EXTRA = {Severity.CRITICAL: 12, Severity.HIGH: 7, Severity.MEDIUM: 3, Severity.LOW: 1, Severity.INFO: 0}


@dataclass
class ScanResult:
    targets: list[str] = field(default_factory=list)
    servers: list[ServerSpec] = field(default_factory=list)
    inventories: list[ServerInventory] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    finished_at: str = ""
    version: str = __version__

    # ------------------------------------------------------------------ helpers
    def add(self, findings: list[Finding] | Finding) -> None:
        if isinstance(findings, Finding):
            findings = [findings]
        seen = {f.fingerprint for f in self.findings}
        for f in findings:
            if f.fingerprint not in seen:
                self.findings.append(f)
                seen.add(f.fingerprint)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.server, f.rule_id, f.location))

    @property
    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    @property
    def risk_score(self) -> int:
        """0 (clean) … 100 (critical). Driven by the worst finding, with diminishing returns for volume."""
        scored = [f for f in self.findings if f.severity != Severity.INFO]
        if not scored:
            return 0
        worst = max(scored, key=lambda f: f.severity.rank).severity
        extra = sum(_SEV_EXTRA[f.severity] for f in scored) - _SEV_EXTRA[worst]
        remaining = 100 - _SEV_BASE[worst]
        return min(100, int(round(_SEV_BASE[worst] + remaining * (1 - math.exp(-extra / 40)))))

    @property
    def grade(self) -> str:
        s = self.risk_score
        if s == 0:
            return "A"
        if s < 25:
            return "B"
        if s < 50:
            return "C"
        if s < 75:
            return "D"
        return "F"

    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank).severity

    def owasp_mcp_coverage(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            for ref in f.owasp_mcp:
                out[ref] = out.get(ref, 0) + 1
        return dict(sorted(out.items()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "mcpshield",
            "version": self.version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "targets": self.targets,
            "summary": {
                "risk_score": self.risk_score,
                "grade": self.grade,
                "counts": self.counts,
                "servers": len(self.servers),
                "live_inventories": len(self.inventories),
                "owasp_mcp": self.owasp_mcp_coverage(),
            },
            "servers": [s.to_dict() for s in self.servers],
            "inventories": [i.to_dict() for i in self.inventories],
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
        }
