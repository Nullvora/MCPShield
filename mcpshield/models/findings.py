"""
MCPShield — Finding and ScanResult data models.
All scanner output is expressed through these structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def score(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH":     "red",
            "MEDIUM":   "yellow",
            "LOW":      "cyan",
            "INFO":     "dim",
        }[self.value]

    @property
    def emoji(self) -> str:
        return {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢",
            "INFO":     "⚪",
        }[self.value]


class Category(str, Enum):
    TRANSPORT       = "Transport Security"
    AUTHENTICATION  = "Authentication & Identity"
    INJECTION       = "Prompt Injection"
    SUPPLY_CHAIN    = "Supply Chain"
    MEMORY          = "Memory & Context"
    MULTI_AGENT     = "Multi-Agent Security"
    EXFILTRATION    = "Data Exfiltration"
    ROGUE_AGENT     = "Rogue Agent Behaviour"
    CONFIGURATION   = "Configuration"
    PRIVILEGE       = "Privilege & Permissions"


@dataclass
class Finding:
    """A single security finding produced by a scanner module."""

    id: str                          # e.g. T1.1
    title: str
    severity: Severity
    category: Category
    description: str
    affected_component: str
    evidence: str
    remediation: str
    owasp_ref: str                   # e.g. ASI05
    cve_refs: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id":                 self.id,
            "title":              self.title,
            "severity":           self.severity.value,
            "category":           self.category.value,
            "description":        self.description,
            "affected_component": self.affected_component,
            "evidence":           self.evidence,
            "remediation":        self.remediation,
            "owasp_ref":          self.owasp_ref,
            "cve_refs":           self.cve_refs,
            "references":         self.references,
        }


@dataclass
class ScanTarget:
    """Describes what was scanned."""

    raw: str                                   # original input string
    scan_type: str                             # "config_file" | "http" | "stdio"
    path: str | None = None                 # file path if config scan
    host: str | None = None                 # host if live scan
    port: int | None = None
    tls: bool = False


@dataclass
class ScanResult:
    """Complete output of a MCPShield scan run."""

    target: ScanTarget
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    scanner_version: str = "0.1.0"
    findings: list[Finding] = field(default_factory=list)

    # ── derived properties ──────────────────────────────────────────────────

    @property
    def risk_score(self) -> int:
        """
        0–100 composite risk score.
        Weighted sum of finding severities, capped at 100.
        """
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH:     15,
            Severity.MEDIUM:    7,
            Severity.LOW:       2,
            Severity.INFO:      0,
        }
        raw = sum(weights[f.severity] for f in self.findings)
        return min(raw, 100)

    @property
    def risk_label(self) -> str:
        s = self.risk_score
        if s >= 75: return "CRITICAL"
        if s >= 50: return "HIGH"
        if s >= 25: return "MEDIUM"
        if s > 0:   return "LOW"
        return "CLEAR"

    @property
    def counts(self) -> dict[str, int]:
        result = {s.value: 0 for s in Severity}
        for f in self.findings:
            result[f.severity.value] += 1
        return result

    @property
    def owasp_coverage(self) -> list[str]:
        return sorted({f.owasp_ref for f in self.findings if f.owasp_ref})

    @property
    def cves_referenced(self) -> list[str]:
        cves: set[str] = set()
        for f in self.findings:
            cves.update(f.cve_refs)
        return sorted(cves)

    def findings_by_severity(self) -> list[Finding]:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
        return sorted(self.findings, key=lambda f: order.index(f.severity))

    def to_dict(self) -> dict:
        return {
            "mcpshield_version": self.scanner_version,
            "timestamp":         self.timestamp,
            "target": {
                "raw":       self.target.raw,
                "scan_type": self.target.scan_type,
                "path":      self.target.path,
                "host":      self.target.host,
                "port":      self.target.port,
                "tls":       self.target.tls,
            },
            "risk_score":      self.risk_score,
            "risk_label":      self.risk_label,
            "finding_counts":  self.counts,
            "owasp_coverage":  self.owasp_coverage,
            "cves_referenced": self.cves_referenced,
            "findings":        [f.to_dict() for f in self.findings_by_severity()],
        }
