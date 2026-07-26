"""
MCPShield Monitor — Alert Routing
Dispatches anomaly alerts to external systems (Slack, webhook, etc.).
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

from mcpshield.monitor.detector import Anomaly

logger = logging.getLogger(__name__)


@dataclass
class AlertConfig:
    """Configuration for an alert routing channel."""
    name: str                           # e.g. "slack", "webhook", "pagerduty"
    url: str                            # Webhook URL
    headers: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    min_severity: str = "HIGH"          # Only send alerts at or above this severity
    custom_payload: Callable[[Anomaly], dict] | None = None


class AlertRouter:
    """
    Routes anomaly alerts to configured external channels.

    Usage:
        router = AlertRouter()
        router.add_channel(AlertConfig(
            name="slack",
            url="https://hooks.slack.com/services/...",
            min_severity="HIGH",
        ))
        router.add_channel(AlertConfig(
            name="webhook",
            url="https://my-server.com/api/alerts",
            headers={"Authorization": "Bearer ..."},
        ))

        # In your alert callback:
        def on_anomaly(anomaly):
            router.dispatch(anomaly)
    """

    _SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def __init__(self) -> None:
        self.channels: list[AlertConfig] = []
        self._history: list[dict] = []
        self._max_history: int = 1000

    def add_channel(self, config: AlertConfig) -> None:
        """Register an alert channel."""
        self.channels.append(config)
        logger.info("Alert channel registered: %s (%s)", config.name, config.url)

    def dispatch(self, anomaly: Anomaly) -> list[bool]:
        """
        Send the anomaly to all matching channels.
        Returns a list of (success: bool) for each channel attempted.
        """
        results = []
        anomaly_sev = self._SEVERITY_ORDER.get(anomaly.severity, 0)

        for channel in self.channels:
            if not channel.enabled:
                results.append(False)
                continue

            min_sev = self._SEVERITY_ORDER.get(channel.min_severity, 0)
            if anomaly_sev < min_sev:
                results.append(False)
                continue

            success = self._send(channel, anomaly)
            results.append(success)

            self._history.append({
                "channel": channel.name,
                "rule_id": anomaly.rule_id,
                "severity": anomaly.severity,
                "success": success,
                "timestamp": anomaly.timestamp,
            })
            if len(self._history) > self._max_history:
                self._history.pop(0)

        return results

    def _send(self, channel: AlertConfig, anomaly: Anomaly) -> bool:
        """Send an alert to a single channel."""
        if channel.custom_payload:
            payload = channel.custom_payload(anomaly)
        else:
            payload = self._default_payload(anomaly, channel.name)

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                channel.url,
                data=data,
                headers={"Content-Type": "application/json", **channel.headers},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, OSError, Exception) as exc:
            logger.warning("Failed to send alert to %s: %s", channel.name, exc)
            return False

    @staticmethod
    def _default_payload(anomaly: Anomaly, channel_name: str) -> dict:
        """Generate a generic alert payload."""
        return {
            "source": "MCPShield",
            "channel": channel_name,
            "rule_id": anomaly.rule_id,
            "severity": anomaly.severity,
            "title": anomaly.title,
            "description": anomaly.description,
            "agent_id": anomaly.agent_id,
            "tool": anomaly.tool,
            "server": anomaly.server,
            "evidence": anomaly.evidence,
            "timestamp": anomaly.timestamp,
        }

    @staticmethod
    def slack_payload_factory(channel_name: str = "MCPShield"):
        """Return a payload builder formatted for Slack webhooks."""
        _severity_emoji = {
            "CRITICAL": ":red_circle:", "HIGH": ":orange_circle:",
            "MEDIUM": ":yellow_circle:", "LOW": ":blue_circle:",
        }

        def builder(anomaly: Anomaly) -> dict:
            emoji = _severity_emoji.get(anomaly.severity, ":white_circle:")
            return {
                "text": f"{emoji} *[{anomaly.severity}]* {anomaly.title}",
                "blocks": [{
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*{emoji} [{anomaly.severity}] {anomaly.title}*\n\n"
                            f"*Agent:* `{anomaly.agent_id}`\n"
                            f"*Tool:* `{anomaly.tool}` on `{anomaly.server}`\n\n"
                            f"{anomaly.description}"
                        ),
                    },
                }],
            }
        return builder

    def get_history(self, limit: int = 50) -> list[dict]:
        """Return recent alert dispatch history."""
        return self._history[-limit:]
