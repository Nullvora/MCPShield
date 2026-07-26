"""
MCPShield Reporter — JSON Report Generator
"""

from __future__ import annotations

import json

from mcpshield.models.findings import ScanResult


def generate_json_report(result: ScanResult, indent: int = 2) -> str:
    """Return the scan result as a formatted JSON string."""
    return json.dumps(result.to_dict(), indent=indent, default=str)


def save_json_report(result: ScanResult, output_path: str) -> None:
    """Write the JSON report to a file."""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(generate_json_report(result))
