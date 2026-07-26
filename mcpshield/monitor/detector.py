"""
MCPShield Monitor — Anomaly Detector
Detects suspicious patterns in MCP tool call streams.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

# ── Anomaly severity levels ───────────────────────────────────────────────────

class AnomalySeverity:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


@dataclass
class Anomaly:
    rule_id:     str
    severity:    str
    title:       str
    description: str
    evidence:    dict
    agent_id:    str
    tool:        str
    server:      str
    timestamp:   float = field(default_factory=time.time)


# ── Detection rules ───────────────────────────────────────────────────────────

# Phrases in tool parameters suggesting injection / exfiltration
_INJECTION_PARAM_PATTERNS = [
    re.compile(r"(?i)ignore\s+(previous|prior|above)\s+instructions?"),
    re.compile(r"(?i)you\s+are\s+now\s+in\s+(maintenance|admin|debug)\s+mode"),
    re.compile(r"(?i)(send|forward|email|post|transmit)\s+.{0,50}\s+(to|at)\s+\S+@\S+"),
    re.compile(r"(?i)(send|post)\s+.{0,50}(https?://)"),
    re.compile(r"(?i)call\s+\w+\s+with\s+.{0,60}(secret|key|token|password|credential)"),
    re.compile(r"(?i)disregard\s+(your|the)\s+(system\s+)?prompt"),
    re.compile(r"(?i)override\s+(safety|security|policy|restriction)"),
]

# Credential-shaped values in parameters
_CREDENTIAL_IN_PARAM = re.compile(
    r"(?i)(sk-[a-zA-Z0-9]{32,}|"        # OpenAI/Anthropic key
    r"gh[pousr]_[A-Za-z0-9]{36,}|"      # GitHub token
    r"AKIA[0-9A-Z]{16}|"                 # AWS Access Key
    r"Bearer\s+[A-Za-z0-9\-_=+/]{20,})" # Bearer token
)

# Internal network / metadata endpoint patterns in URL params
_SSRF_PATTERNS = [
    re.compile(r"(?i)(169\.254\.169\.254|100\.100\.100\.200)"),   # cloud metadata
    re.compile(r"(?i)(localhost|127\.0\.0\.|0\.0\.0\.0)"),
    re.compile(r"(?i)(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"),
]


class AnomalyDetector:
    """
    Stateful detector that analyses each tool call for anomalous behaviour.

    Detects:
      - Injection patterns in tool parameters
      - Rapid tool invocation (rate spikes)
      - Unexpected tool chaining sequences
      - Credential-shaped values in parameters
      - SSRF targets in URL parameters
      - Repeated failures / blocked calls (persistence probing)
    """

    def __init__(
        self,
        rate_window_seconds: int = 60,
        rate_threshold: int = 30,
    ) -> None:
        # Rate limiting state: agent_id → deque of timestamps
        self._call_times:    defaultdict[str, deque] = defaultdict(lambda: deque())
        self._block_counts:  defaultdict[str, int]   = defaultdict(int)
        self._tool_sequences: defaultdict[str, list]  = defaultdict(list)

        self.rate_window    = rate_window_seconds
        self.rate_threshold = rate_threshold

    def analyse(
        self,
        agent_id:   str,
        server:     str,
        tool:       str,
        parameters: dict,
    ) -> list[Anomaly]:
        """
        Analyse a single tool call. Returns a (possibly empty) list of Anomalies.
        """
        anomalies: list[Anomaly] = []
        params_str = _flatten_params(parameters)

        # --- Rule 1: Injection patterns in parameters ---
        for pattern in _INJECTION_PARAM_PATTERNS:
            m = pattern.search(params_str)
            if m:
                anomalies.append(Anomaly(
                    rule_id="AD-001",
                    severity=AnomalySeverity.CRITICAL,
                    title="Prompt Injection Pattern in Tool Parameters",
                    description=(
                        "A tool call contains parameter values matching known prompt injection "
                        "patterns. This may indicate an indirect injection attack delivered "
                        "through external content (T3.2) or a compromised tool definition (T3.1)."
                    ),
                    evidence={
                        "matched_pattern": pattern.pattern,
                        "matched_text": m.group(0)[:200],
                        "tool": tool,
                    },
                    agent_id=agent_id,
                    tool=tool,
                    server=server,
                ))
                break  # one injection anomaly per call

        # --- Rule 2: Credential-shaped values in parameters ---
        m = _CREDENTIAL_IN_PARAM.search(params_str)
        if m:
            anomalies.append(Anomaly(
                rule_id="AD-002",
                severity=AnomalySeverity.HIGH,
                title="Credential-Shaped Value in Tool Parameters",
                description=(
                    "A tool call contains a parameter value that matches the shape of a "
                    "real credential (API key, bearer token, AWS key). This may indicate "
                    "an exfiltration attempt where a prior injection caused the agent to "
                    "pass credentials to a tool."
                ),
                evidence={"matched_pattern": "credential-shape", "tool": tool},
                agent_id=agent_id,
                tool=tool,
                server=server,
            ))

        # --- Rule 3: SSRF targets in URL parameters ---
        for pattern in _SSRF_PATTERNS:
            m = pattern.search(params_str)
            if m:
                anomalies.append(Anomaly(
                    rule_id="AD-003",
                    severity=AnomalySeverity.HIGH,
                    title="Possible SSRF — Internal Target in Tool URL Parameter",
                    description=(
                        "A tool call contains a URL parameter targeting an internal "
                        "network address or cloud metadata endpoint. This may indicate "
                        "an SSRF attempt (T1.3) delivered through prompt injection."
                    ),
                    evidence={"ssrf_target": m.group(0), "tool": tool},
                    agent_id=agent_id,
                    tool=tool,
                    server=server,
                ))
                break

        # --- Rule 4: Rate spike ---
        now = time.time()
        q   = self._call_times[agent_id]
        q.append(now)
        # Evict old entries outside the window
        while q and q[0] < now - self.rate_window:
            q.popleft()

        if len(q) > self.rate_threshold:
            anomalies.append(Anomaly(
                rule_id="AD-004",
                severity=AnomalySeverity.MEDIUM,
                title="Abnormal Tool Invocation Rate",
                description=(
                    f"Agent '{agent_id}' made {len(q)} tool calls in the last "
                    f"{self.rate_window}s (threshold: {self.rate_threshold}). "
                    "This may indicate a runaway loop, an exploitation attempt, "
                    "or an agent operating outside its intended scope."
                ),
                evidence={
                    "call_count": len(q),
                    "window_seconds": self.rate_window,
                    "threshold": self.rate_threshold,
                },
                agent_id=agent_id,
                tool=tool,
                server=server,
            ))

        # --- Rule 5: Dangerous tool sequence ---
        seq = self._tool_sequences[agent_id]
        seq.append(tool)
        if len(seq) > 20:
            seq.pop(0)

        dangerous_seq = _check_dangerous_sequence(seq)
        if dangerous_seq:
            anomalies.append(Anomaly(
                rule_id="AD-005",
                severity=AnomalySeverity.HIGH,
                title=f"Dangerous Tool Sequence Detected: {dangerous_seq['pattern']}",
                description=dangerous_seq["description"],
                evidence={"sequence": seq[-5:], "pattern": dangerous_seq["pattern"]},
                agent_id=agent_id,
                tool=tool,
                server=server,
            ))

        return anomalies

    def record_block(self, agent_id: str) -> None:
        """Record a blocked call — high frequency of blocks may indicate probing."""
        self._block_counts[agent_id] += 1

    def reset_agent(self, agent_id: str) -> None:
        """Clear state for a specific agent (e.g. after session end)."""
        self._call_times.pop(agent_id, None)
        self._block_counts.pop(agent_id, None)
        self._tool_sequences.pop(agent_id, None)


# ── Dangerous sequence patterns ───────────────────────────────────────────────

_DANGEROUS_SEQUENCES = [
    {
        "pattern": "read_then_send",
        "triggers": [
            ({"read", "get", "fetch", "list"}, {"send", "email", "post", "upload", "write"}),
        ],
        "description": (
            "Agent read/fetched data and then immediately called a send/write tool. "
            "This pattern is consistent with data exfiltration (T7.1) — "
            "read sensitive data, transmit to external endpoint."
        ),
    },
    {
        "pattern": "env_then_send",
        "triggers": [
            ({"env", "environment", "config", "secret"}, {"send", "post", "email", "http"}),
        ],
        "description": (
            "Agent accessed environment/config and then called an outbound tool. "
            "This is a known credential exfiltration pattern."
        ),
    },
    {
        "pattern": "browse_then_execute",
        "triggers": [
            ({"browse", "fetch", "read"}, {"execute", "run", "eval", "shell", "bash"}),
        ],
        "description": (
            "Agent fetched external content and then called an execution tool. "
            "This pattern matches an indirect injection leading to code execution."
        ),
    },
]


def _check_dangerous_sequence(sequence: list[str]) -> dict | None:
    seq_lower = [t.lower() for t in sequence]
    for rule in _DANGEROUS_SEQUENCES:
        for read_set, write_set in rule["triggers"]:
            has_read  = any(any(kw in tool for kw in read_set)  for tool in seq_lower)
            has_write = any(any(kw in tool for kw in write_set) for tool in seq_lower)
            # Check write comes after read
            if has_read and has_write:
                last_read  = max((i for i, t in enumerate(seq_lower) if any(kw in t for kw in read_set)),  default=-1)
                last_write = max((i for i, t in enumerate(seq_lower) if any(kw in t for kw in write_set)), default=-1)
                if last_write > last_read:
                    return rule
    return None


def _flatten_params(params: dict, max_depth: int = 3, _depth: int = 0) -> str:
    """Flatten nested param dict to a single string for pattern matching."""
    if _depth > max_depth:
        return ""
    parts = []
    for k, v in params.items():
        if isinstance(v, dict):
            parts.append(_flatten_params(v, max_depth, _depth + 1))
        elif isinstance(v, list):
            parts.append(" ".join(str(i) for i in v[:10]))
        else:
            parts.append(f"{k}={v}")
    return " ".join(parts)
