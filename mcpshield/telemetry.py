# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Agent-activity telemetry: OpenTelemetry (OTLP/HTTP JSON) export without the OpenTelemetry SDK.

Spans follow the OpenTelemetry GenAI + MCP semantic conventions (Development status as of 2026):

* one ``mcp.session`` root span per proxied server session
* one ``execute_tool {gen_ai.tool.name}`` span per ``tools/call`` (kind INTERNAL), child of the session span
  or of the caller's own span when the request carries W3C ``traceparent`` in ``_meta`` (MCP 2026-07-28)
* ``tools/list`` spans, and span events for security alerts

MCPShield-specific security attributes live under the ``mcpshield.*`` namespace (decision, reasons, risk classes).
Arguments are never exported unless ``capture_arguments`` is enabled, and are secret-redacted even then.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from mcpshield import __version__

log = logging.getLogger("mcpshield.telemetry")

SEMCONV_NOTE = "OpenTelemetry GenAI/MCP semantic conventions (development)"
_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")


def new_trace_id() -> str:
    return secrets.token_hex(16)


def new_span_id() -> str:
    return secrets.token_hex(8)


def parse_traceparent(value: Any) -> Optional[tuple[str, str]]:
    if not isinstance(value, str):
        return None
    m = _TRACEPARENT.match(value.strip().lower())
    if not m or m.group(1) == "0" * 32 or m.group(2) == "0" * 16:
        return None
    return m.group(1), m.group(2)


def _attr_value(v: Any) -> dict[str, Any]:
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [_attr_value(x) for x in v]}}
    return {"stringValue": str(v)}


def encode_attributes(attrs: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"key": k, "value": _attr_value(v)} for k, v in attrs.items() if v is not None and v != [] and v != ""]


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    start_ns: int
    end_ns: int = 0
    kind: int = 1                        # 1 = INTERNAL, 2 = SERVER, 3 = CLIENT
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    def add_event(self, name: str, attrs: Optional[dict[str, Any]] = None, ts_ns: Optional[int] = None) -> None:
        self.events.append({"timeUnixNano": str(ts_ns or time.time_ns()), "name": name, "attributes": encode_attributes(attrs or {})})

    def to_otlp(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "name": self.name,
            "kind": self.kind,
            "startTimeUnixNano": str(self.start_ns),
            "endTimeUnixNano": str(self.end_ns or time.time_ns()),
            "attributes": encode_attributes(self.attributes),
            "status": {"code": 2, "message": self.error[:200]} if self.error else {"code": 0},
        }
        if self.parent_span_id:
            d["parentSpanId"] = self.parent_span_id
        if self.events:
            d["events"] = self.events
        return d


def parse_headers(value: Optional[str]) -> dict[str, str]:
    """Parse OTEL_EXPORTER_OTLP_HEADERS style 'k1=v1,k2=v2'."""
    out: dict[str, str] = {}
    for part in (value or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


class OtlpExporter:
    """Batches spans and POSTs them to ``<endpoint>/v1/traces`` as OTLP JSON from a background thread."""

    def __init__(self, endpoint: str, headers: Optional[dict[str, str]] = None, service_name: str = "mcpshield",
                 resource: Optional[dict[str, Any]] = None, batch_size: int = 64, interval: float = 2.0, timeout: float = 5.0):
        endpoint = endpoint.rstrip("/")
        self.url = endpoint if endpoint.endswith("/v1/traces") else endpoint + "/v1/traces"
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.resource = {"service.name": service_name, "telemetry.sdk.name": "mcpshield", "telemetry.sdk.version": __version__,
                         "telemetry.sdk.language": "python", **(resource or {})}
        self.batch_size = batch_size
        self.interval = interval
        self.timeout = timeout
        self.max_queue_size = 4096
        self.dropped = 0
        self._buf: list[Span] = []
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = False
        self.sent = 0
        self.failed = 0
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    @classmethod
    def from_env(cls, service_name: str, resource: Optional[dict[str, Any]] = None) -> Optional[OtlpExporter]:
        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        if not endpoint:
            return None
        return cls(endpoint, parse_headers(os.environ.get("OTEL_EXPORTER_OTLP_HEADERS")), service_name, resource)

    def export(self, span: Span) -> None:
        with self._lock:
            if self._stop or len(self._buf) >= self.max_queue_size:
                self.dropped += 1
                return
            self._buf.append(span)
            full = len(self._buf) >= self.batch_size
        if full:
            self._wake.set()

    def payload(self, spans: list[Span]) -> dict[str, Any]:
        return {"resourceSpans": [{
            "resource": {"attributes": encode_attributes(self.resource)},
            "scopeSpans": [{"scope": {"name": "mcpshield.proxy", "version": __version__}, "spans": [s.to_otlp() for s in spans]}],
        }]}

    def _flush(self) -> None:
        with self._lock:
            spans, self._buf = self._buf, []
        if not spans:
            return
        try:
            import httpx

            r = httpx.post(self.url, content=json.dumps(self.payload(spans)), headers=self.headers, timeout=self.timeout)
            if r.status_code >= 300:
                raise RuntimeError(f"HTTP {r.status_code}")
            self.sent += len(spans)
        except Exception as exc:  # noqa: BLE001 - telemetry must never break the proxy
            self.failed += len(spans)
            log.debug("OTLP export failed: %s", exc)

    def _run(self) -> None:
        while not self._stop:
            self._wake.wait(self.interval)
            self._wake.clear()
            self._flush()

    def close(self) -> None:
        self._stop = True
        self._wake.set()
        self._thread.join(timeout=self.timeout + 1)
        self._flush()


class NullExporter:
    sent = 0
    failed = 0

    def export(self, span: Span) -> None:
        pass

    def close(self) -> None:
        pass
