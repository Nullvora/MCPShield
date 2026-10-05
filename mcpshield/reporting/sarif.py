# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""SARIF 2.1.0 output — upload to GitHub code scanning, Azure DevOps, etc."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from mcpshield import __version__
from mcpshield.checks.registry import RULES
from mcpshield.models import ScanResult, Severity
from mcpshield.taxonomy import label

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
_SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "0.0"}


def _line_of(path: str, needle: str, cache: dict[str, list[str]]) -> Optional[int]:
    try:
        lines = cache.setdefault(path, Path(path).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return None
    pat = re.compile(r'["\']?' + re.escape(needle) + r'["\']?\s*[:=]') if needle else None
    for i, line in enumerate(lines, 1):
        if pat and pat.search(line):
            return i
    return 1 if lines else None


def to_sarif(result: ScanResult, base_dir: Optional[str] = None) -> dict[str, Any]:
    base = Path(base_dir or os.getcwd()).resolve()
    used = sorted({f.rule_id for f in result.findings})
    rules = []
    for rid in used:
        r = RULES[rid]
        tags = ["security", "mcp"] + [label(x) for x in r.owasp_mcp] + [label(x) for x in r.owasp_asi] + list(r.cwe)
        rules.append({
            "id": r.id,
            "name": re.sub(r"[^A-Za-z0-9]+", "", r.title.title()),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description},
            "help": {"text": r.remediation, "markdown": f"**Remediation:** {r.remediation}\n\n" + "\n".join(f"- {u}" for u in r.references)},
            "helpUri": (r.references[0] if r.references else "https://github.com/Nullvora/MCPShield/blob/main/docs/RULES.md"),
            "defaultConfiguration": {"level": _LEVEL[r.severity]},
            "properties": {"tags": tags, "security-severity": _SCORE[r.severity], "precision": "high" if r.scope != "live" else "medium"},
        })
    rule_index = {rid: i for i, rid in enumerate(used)}
    source_of = {s.name: s.source for s in result.servers if s.source}
    cache: dict[str, list[str]] = {}
    results = []
    for f in result.sorted_findings():
        src = source_of.get(f.server) or (f.location.split("#", 1)[0] if f.location and "#" in f.location else "")
        if not src and f.location and Path(f.location).is_file():
            src = f.location
        locations = []
        if src and Path(src).exists():
            p = Path(src).resolve()
            try:
                uri = p.relative_to(base).as_posix()
            except ValueError:
                uri = p.as_uri()
            line = _line_of(str(p), f.server, cache) or 1
            locations.append({"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}})
        msg = f"{f.title}" + (f" [server: {f.server}]" if f.server else "") + (f" — {f.evidence.splitlines()[0][:300]}" if f.evidence else "")
        res: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _LEVEL[f.severity],
            "message": {"text": msg},
            "partialFingerprints": {"mcpshield/v1": f.fingerprint},
            "properties": {"severity": f.severity.value, "server": f.server, "location": f.location,
                           "security-severity": _SCORE[f.severity]},
        }
        if locations:
            res["locations"] = locations
        results.append(res)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MCPShield", "version": __version__, "semanticVersion": __version__,
                                "informationUri": "https://github.com/Nullvora/MCPShield", "organization": "Nullvora", "rules": rules}},
            "results": results,
            "invocations": [{"executionSuccessful": True, "startTimeUtc": result.started_at, "endTimeUtc": result.finished_at or result.started_at}],
        }],
    }


def write_sarif(result: ScanResult, path: str, base_dir: Optional[str] = None) -> None:
    Path(path).write_text(json.dumps(to_sarif(result, base_dir), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
