"""
MCPShield Monitor — Policy Enforcer
Evaluates MCP tool calls against a declarative policy and allows/blocks/alerts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class PolicyAction(str, Enum):
    ALLOW  = "allow"
    BLOCK  = "block"
    ALERT  = "alert"   # allow but raise anomaly


@dataclass
class PolicyRule:
    """A single policy rule."""
    id:          str
    description: str
    action:      PolicyAction
    # Matching criteria (all specified must match for rule to fire)
    servers:     list[str] | None = None   # None = any server
    tools:       list[str] | None = None   # None = any tool
    agents:      list[str] | None = None   # None = any agent
    param_patterns: list[str] = field(default_factory=list)  # regex on flattened params
    _compiled: list = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.param_patterns]

    def matches(
        self,
        agent_id:   str,
        server:     str,
        tool:       str,
        params_str: str,
    ) -> bool:
        if self.agents  and not any(a == agent_id for a in self.agents):  return False
        if self.servers and not any(s in server   for s in self.servers): return False
        if self.tools   and not any(t in tool     for t in self.tools):   return False
        # Param patterns use OR logic: any single pattern match triggers the rule
        if self._compiled:
            if not any(pattern.search(params_str) for pattern in self._compiled):
                return False
        return True


@dataclass
class PolicyDecision:
    action:      PolicyAction
    rule_id:     str
    rule_desc:   str
    explanation: str


class PolicyEnforcer:
    """
    Evaluates tool calls against an ordered list of PolicyRules.
    Rules are evaluated first-match-wins (like a firewall ACL).
    """

    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self.rules: list[PolicyRule] = rules or _default_rules()

    def evaluate(
        self,
        agent_id:   str,
        server:     str,
        tool:       str,
        parameters: dict,
    ) -> PolicyDecision:
        """
        Evaluate a proposed tool call.
        Returns a PolicyDecision with the action to take.
        """
        params_str = _flatten(parameters)

        for rule in self.rules:
            if rule.matches(agent_id, server, tool, params_str):
                return PolicyDecision(
                    action=rule.action,
                    rule_id=rule.id,
                    rule_desc=rule.description,
                    explanation=(
                        f"Rule '{rule.id}' matched: {rule.description}. "
                        f"Action: {rule.action.value.upper()}"
                    ),
                )

        # Default allow
        return PolicyDecision(
            action=PolicyAction.ALLOW,
            rule_id="DEFAULT",
            rule_desc="Default allow",
            explanation="No matching rule — default allow.",
        )

    def add_rule(self, rule: PolicyRule, position: int = 0) -> None:
        """Insert a rule at a specific position (default: front = highest priority)."""
        self.rules.insert(position, rule)

    def load_from_dict(self, config: dict) -> None:
        """Load rules from a policy config dict (e.g. loaded from YAML/JSON)."""
        self.rules = []
        for r in config.get("rules", []):
            self.rules.append(PolicyRule(
                id=r["id"],
                description=r["description"],
                action=PolicyAction(r["action"]),
                servers=r.get("servers"),
                tools=r.get("tools"),
                agents=r.get("agents"),
                param_patterns=r.get("param_patterns", []),
            ))


def _flatten(params: dict) -> str:
    parts = []
    for k, v in params.items():
        if isinstance(v, dict):
            parts.append(_flatten(v))
        elif isinstance(v, list):
            parts.append(" ".join(str(i) for i in v[:10]))
        else:
            parts.append(f"{k}={v}")
    return " ".join(parts)


def _default_rules() -> list[PolicyRule]:
    """
    Sensible default rules for MCP deployments.
    These can be overridden by loading a custom policy file.
    """
    return [
        # Block prompt injection patterns
        PolicyRule(
            id="P-001",
            description="Block tool calls containing role-override injection phrases",
            action=PolicyAction.BLOCK,
            param_patterns=[
                r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
                r"you\s+are\s+now\s+in\s+(?:maintenance|admin|debug)\s+mode",
                r"disregard\s+(?:your\s+)?(?:system\s+)?prompt",
                r"override\s+(?:safety|security|policy|restriction)",
            ],
        ),

        # Block SSRF targets
        PolicyRule(
            id="P-002",
            description="Block tool calls targeting cloud metadata endpoints (SSRF prevention)",
            action=PolicyAction.BLOCK,
            param_patterns=[
                r"169\.254\.169\.254",
                r"100\.100\.100\.200",
            ],
        ),

        # Alert on internal network targets
        PolicyRule(
            id="P-003",
            description="Alert on tool calls targeting internal network addresses",
            action=PolicyAction.ALERT,
            param_patterns=[
                r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)",
            ],
        ),

        # Alert on credential-shaped values
        PolicyRule(
            id="P-004",
            description="Alert on tool calls containing credential-shaped parameter values",
            action=PolicyAction.ALERT,
            param_patterns=[
                r"sk-[a-zA-Z0-9]{32,}",
                r"gh[pousr]_[A-Za-z0-9]{36,}",
                r"AKIA[0-9A-Z]{16}",
            ],
        ),

        # Block tool calls to shell/exec tools with suspicious args
        PolicyRule(
            id="P-005",
            description="Block shell/exec tool calls with pipe or redirection characters",
            action=PolicyAction.BLOCK,
            tools=["bash", "shell", "execute", "run", "eval"],
            param_patterns=[r"[|;&`$\(\)]"],
        ),

        # Alert on filesystem access outside expected working dirs
        PolicyRule(
            id="P-006",
            description="Alert on filesystem tool calls accessing sensitive paths",
            action=PolicyAction.ALERT,
            tools=["read_file", "write_file", "list_directory", "filesystem"],
            param_patterns=[
                r"(/etc/passwd|/etc/shadow|\.ssh/|\.aws/credentials|\.env)",
                r"(id_rsa|id_ed25519|\.pem|\.key|\.p12)",
            ],
        ),

        # Block outbound data send to non-whitelisted domains
        PolicyRule(
            id="P-007",
            description="Alert on email/send tool calls (potential exfiltration vector)",
            action=PolicyAction.ALERT,
            tools=["send_email", "gmail", "outlook", "send_message", "post"],
        ),
    ]
