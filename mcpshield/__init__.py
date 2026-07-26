"""
MCPShield — MCP Security Assessment Framework
by Nullvora | github.com/Nullvora/MCPShield

The first open-source security assessment, hardening, and runtime monitoring
framework for Model Context Protocol (MCP) deployments.
"""

__version__ = "0.1.0"
__author__  = "James Boamah — Nullvora"
__license__ = "MIT"

from mcpshield.models import Finding, ScanResult, Severity
from mcpshield.monitor import AgentMonitor
from mcpshield.scanner import scan_config_dict, scan_config_file

__all__ = [
    "AgentMonitor",
    "Finding",
    "ScanResult",
    "Severity",
    "scan_config_dict",
    "scan_config_file",
]
