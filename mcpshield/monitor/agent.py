"""
MCPShield Monitor — Agent Monitor
The main runtime monitoring facade.

Usage:
    from mcpshield.monitor import AgentMonitor

    monitor = AgentMonitor(log_path="./audit/mcpshield.log")

    # Before each tool call:
    decision = monitor.before_tool_call(
        agent_id="agent-001",
        server="filesystem",
        tool="read_file",
        parameters={"path": "/home/user/data.csv"},
    )
    if decision.action == "block":
        raise PermissionError(decision.explanation)

    # After the call completes:
    monitor.after_tool_call(
        agent_id="agent-001",
        server="filesystem",
        tool="read_file",
        parameters={"path": "/home/user/data.csv"},
        result={"content": "..."},
    )
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mcpshield.monitor.detector import Anomaly, AnomalyDetector
from mcpshield.monitor.enforcer import PolicyAction, PolicyDecision, PolicyEnforcer
from mcpshield.monitor.logger import AuditLogger


@dataclass
class MonitorEvent:
    """Everything MCPShield recorded about a single tool call."""
    agent_id:      str
    server:        str
    tool:          str
    parameters:    dict
    decision:      PolicyDecision
    anomalies:     list[Anomaly]
    log_entry:     dict
    duration_ms:   float = 0.0


class AgentMonitor:
    """
    Runtime monitor for MCP tool calls.

    Integrates:
      - AnomalyDetector  → behavioural analysis
      - PolicyEnforcer   → allow/block/alert decisions
      - AuditLogger      → tamper-evident logging

    Can be used standalone or as a middleware wrapper.
    """

    def __init__(
        self,
        log_path:          str = "./audit/mcpshield.log",
        policy_rules:      list | None = None,
        alert_callback:    Callable[[Anomaly], None] | None = None,
        redact_log_values: bool = True,
        rate_threshold:    int = 30,
    ) -> None:
        self.logger   = AuditLogger(log_path, redact_values=redact_log_values)
        self.detector = AnomalyDetector(rate_threshold=rate_threshold)
        self.enforcer = PolicyEnforcer(rules=policy_rules)
        self._alert_cb = alert_callback
        self._pending: dict[str, float] = {}  # call_key → start time

    # ── Main API ──────────────────────────────────────────────────────────────

    def before_tool_call(
        self,
        agent_id:   str,
        server:     str,
        tool:       str,
        parameters: dict,
    ) -> PolicyDecision:
        """
        Call BEFORE executing an MCP tool call.
        Returns a PolicyDecision — if action is BLOCK, do not proceed.
        """
        # 1. Policy evaluation
        decision = self.enforcer.evaluate(agent_id, server, tool, parameters)

        # 2. Anomaly detection (even for blocked calls)
        anomalies = self.detector.analyse(agent_id, server, tool, parameters)

        # 3. Alert on anomalies
        for anomaly in anomalies:
            self._dispatch_alert(anomaly)

        # 4. Determine effective action
        #    If detector found CRITICAL anomaly, upgrade to block even if policy says allow
        has_critical = any(a.severity == "CRITICAL" for a in anomalies)
        if has_critical and decision.action == PolicyAction.ALLOW:
            decision = PolicyDecision(
                action=PolicyAction.BLOCK,
                rule_id="ANOMALY-ESCALATION",
                rule_desc="Critical anomaly detected — escalated to block",
                explanation=(
                    f"AnomalyDetector flagged a CRITICAL issue on this call. "
                    f"Escalating from ALLOW to BLOCK. "
                    f"Anomalies: {[a.rule_id for a in anomalies if a.severity == 'CRITICAL']}"
                ),
            )

        # 5. Log the pre-call decision
        if decision.action == PolicyAction.BLOCK:
            self.detector.record_block(agent_id)
            self.logger.log_tool_call(
                agent_id=agent_id,
                server=server,
                tool=tool,
                parameters=parameters,
                result=None,
                policy_action="blocked",
                anomaly_flags=[a.rule_id for a in anomalies],
            )

        # 6. Record start time for duration tracking
        self._pending[f"{agent_id}:{tool}:{time.time()}"] = time.time()

        return decision

    def after_tool_call(
        self,
        agent_id:   str,
        server:     str,
        tool:       str,
        parameters: dict,
        result:     Any = None,
    ) -> MonitorEvent:
        """
        Call AFTER an MCP tool call completes (whether successful or not).
        Always logs; runs post-call anomaly checks on the result.
        """
        anomalies = self.detector.analyse(agent_id, server, tool, parameters)
        decision  = self.enforcer.evaluate(agent_id, server, tool, parameters)

        for anomaly in anomalies:
            self._dispatch_alert(anomaly)

        log_entry = self.logger.log_tool_call(
            agent_id=agent_id,
            server=server,
            tool=tool,
            parameters=parameters,
            result=result,
            policy_action=decision.action.value,
            anomaly_flags=[a.rule_id for a in anomalies],
        )

        return MonitorEvent(
            agent_id=agent_id,
            server=server,
            tool=tool,
            parameters=parameters,
            decision=decision,
            anomalies=anomalies,
            log_entry=log_entry,
        )

    def verify_audit_log(self) -> tuple[bool, list[str]]:
        """Verify the integrity of the audit log chain."""
        return self.logger.verify_chain()

    def recent_events(self, n: int = 20) -> list[dict]:
        """Return the most recent n audit log entries."""
        return self.logger.tail(n)

    # ── Convenience wrapper ───────────────────────────────────────────────────

    def wrap_tool(self, agent_id: str, server: str, tool: str):
        """
        Decorator factory for wrapping an MCP tool function with monitoring.

        Usage:
            @monitor.wrap_tool("agent-001", "filesystem", "read_file")
            def read_file(path: str) -> str:
                ...
        """
        def decorator(fn):
            def wrapper(**kwargs):
                decision = self.before_tool_call(agent_id, server, tool, kwargs)
                if decision.action == PolicyAction.BLOCK:
                    raise PermissionError(
                        f"MCPShield blocked tool call '{tool}': {decision.explanation}"
                    )
                try:
                    result = fn(**kwargs)
                    self.after_tool_call(agent_id, server, tool, kwargs, result)
                    return result
                except Exception as exc:
                    self.after_tool_call(agent_id, server, tool, kwargs, str(exc))
                    raise
            return wrapper
        return decorator

    # ── Internal ──────────────────────────────────────────────────────────────

    def _dispatch_alert(self, anomaly: Anomaly) -> None:
        if self._alert_cb:
            try:
                self._alert_cb(anomaly)
            except Exception:
                pass
        # Always log anomaly events separately
        self.logger.log_anomaly(
            agent_id=anomaly.agent_id,
            description=anomaly.description,
            severity=anomaly.severity,
            context={
                "rule_id": anomaly.rule_id,
                "tool":    anomaly.tool,
                "server":  anomaly.server,
                "evidence": anomaly.evidence,
            },
        )
