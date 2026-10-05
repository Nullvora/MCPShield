# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""``mcpshield proxy`` — a transparent stdio guard between an MCP client and a server.

    client  <—stdio—>  mcpshield proxy  <—stdio—>  real MCP server

What it enforces (see :mod:`mcpshield.proxy.policy`):

* **tools/list**  – hides poisoned tools (tool-poisoning checks), tools changed since pinning (rug pull),
  and tools outside the allow/deny lists.
* **tools/call**  – blocks calls to hidden/denied tools, sensitive paths, cloud-metadata/private URLs,
  dangerous command patterns, oversized arguments and rate-limit violations.
* **results**     – redacts secrets (DLP) and optionally blocks results containing prompt-injection payloads.
* **sampling**    – refuses server-initiated LLM sampling requests unless allowed.
* **audit**       – every decision is written to a hash-chained, optionally HMAC-signed JSONL audit log.

Accepts individual JSON-RPC objects over newline-delimited stdio; legacy batches are rejected.
"""

from __future__ import annotations

import json
import subprocess
import time
import sys
import threading
from typing import IO, Any, Optional

from mcpshield.auditlog import AuditLog
from mcpshield.checks import capabilities as caps
from mcpshield.checks.text import SECRET_PATTERNS, analyse_text
from mcpshield.checks.tool_checks import check_tool
from mcpshield.models import ServerInventory, Severity
from mcpshield.pinning import tool_digest
from mcpshield.proxy.policy import Policy
from mcpshield.telemetry import NullExporter, Span, new_span_id, new_trace_id, parse_traceparent

BLOCK_PREFIX = "⛔ Blocked by MCPShield policy"


def redact_secrets(value: Any) -> tuple[Any, list[str]]:
    found: list[str] = []

    def _r(s: str) -> str:
        for name, rx in SECRET_PATTERNS:
            if rx.search(s):
                found.append(name)
                s = rx.sub(f"[REDACTED:{name}]", s)
        return s

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return _r(v)
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        return v

    return walk(value), sorted(set(found))


def _result_text(result: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in result.get("content") or []:
        if isinstance(item, dict):
            if item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            elif item.get("type") == "resource" and isinstance(item.get("resource"), dict):
                parts.append(str(item["resource"].get("text", "")))
    if result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
    return "\n".join(parts)


class StdioGuard:
    def __init__(self, command: str, args: list[str], policy: Policy, audit: Optional[AuditLog] = None,
                 lock: Optional[dict[str, Any]] = None, server_name: str = "server",
                 stdin: Optional[IO[bytes]] = None, stdout: Optional[IO[bytes]] = None, env: Optional[dict[str, str]] = None,
                 exporter: Any = None, capture_arguments: bool = False):
        if policy.mode not in ("enforce", "monitor"):
            raise ValueError("policy mode must be enforce or monitor")
        if policy.require_pinned and not lock:
            raise ValueError("tools.require_pinned requires a lock file")
        if lock is not None and server_name not in lock.get("servers", {}):
            raise ValueError("server name is missing from lock file; use --name to select the pinned server")
        self.command = command
        self.args = args
        self.policy = policy
        self.audit = audit
        self.lock = lock
        self.server_name = server_name
        self.stdin = stdin or sys.stdin.buffer
        self.stdout = stdout or sys.stdout.buffer
        self.env = env
        self.proc: Optional[subprocess.Popen[bytes]] = None
        self.pending: dict[Any, tuple[str, dict[str, Any]]] = {}
        self.hidden_tools: dict[str, str] = {}
        self._out_lock = threading.Lock()
        self._in_lock = threading.Lock()
        self._inv = ServerInventory(name=server_name, target="proxy", transport="stdio")
        self.stats = {"calls": 0, "blocked": 0, "hidden_tools": 0, "redactions": 0, "injections": 0, "alerts": 0}
        # --- agent-activity observability
        self.exporter = exporter or NullExporter()
        self.capture_arguments = capture_arguments
        self.session_id = new_trace_id()          # also the OpenTelemetry trace id of the session span
        self.session_span_id = new_span_id()
        self.session_start_ns = time.time_ns()
        self.protocol_version = ""
        self.client_info: dict[str, Any] = {}
        self.calls: dict[Any, dict[str, Any]] = {}
        self.tool_defs: dict[str, dict[str, Any]] = {}
        self.session_caps: dict[str, list[str]] = {}
        self.alerted: set[str] = set()

    # ------------------------------------------------------------------ io
    def _log(self, event: str, **fields: Any) -> None:
        if self.audit:
            self.audit.write(event, server=self.server_name, session=self.session_id, **fields)

    def _to_client(self, obj: Any = None, raw: Optional[bytes] = None) -> None:
        data = raw if raw is not None else (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._out_lock:
            self.stdout.write(data)
            self.stdout.flush()

    def _to_server(self, obj: Any = None, raw: Optional[bytes] = None) -> None:
        assert self.proc and self.proc.stdin
        data = raw if raw is not None else (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._in_lock:
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

    def _decode(self, raw: bytes) -> dict[str, Any]:
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("JSON-RPC frame exceeds 4 MiB")
        def invalid_constant(value: str) -> None:
            raise ValueError("non-finite JSON number")
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            obj: dict[str, Any] = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError("duplicate JSON object key")
                obj[key] = value
            return obj
        msg = json.loads(raw, parse_constant=invalid_constant, object_pairs_hook=unique_object)
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            raise ValueError("expected a JSON-RPC 2.0 object; batches are unsupported")
        if "id" in msg and (type(msg["id"]) not in (str, int)):
            raise ValueError("request ID must be a string or integer")
        if "method" in msg:
            if not isinstance(msg["method"], str) or not msg["method"]:
                raise ValueError("method must be a nonempty string")
            params = msg.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("params must be an object")
            if "_meta" in params and not isinstance(params["_meta"], dict):
                raise ValueError("_meta must be an object")
            if msg["method"] == "tools/call":
                if "id" not in msg or not isinstance(params.get("name"), str) or not params["name"]:
                    raise ValueError("tools/call requires an ID and tool name")
                if not isinstance(params.get("arguments", {}), dict):
                    raise ValueError("tool arguments must be an object")
        elif "id" not in msg or ("result" in msg) == ("error" in msg):
            raise ValueError("invalid JSON-RPC response")
        return msg

    def _reject(self, direction: str) -> None:
        # Never forward bytes that failed inspection, even in monitor mode.
        self._log("guard_error", direction=direction, error="invalid or uninspectable message withheld")
        if direction == "client":
            self._to_client({"jsonrpc": "2.0", "id": None, "error": {
                "code": -32600, "message": "MCPShield rejected an invalid or unsupported message"}})

    # ------------------------------------------------------------------ client -> server
    def handle_client(self, raw: bytes) -> None:
        try:
            msg = self._decode(raw)
        except (ValueError, UnicodeError, RecursionError):
            self._reject("client")
            return
        method = msg.get("method")
        rid = msg.get("id")
        if method and rid is not None:
            params = msg.get("params") or {}
            if rid in self.pending or len(self.pending) >= 1024:
                self._reject("client")
                return
            self.pending[rid] = (method, params)
            meta: dict[str, Any] = params["_meta"] if isinstance(params.get("_meta"), dict) else {}
            if method == "initialize":
                self.protocol_version = str(params.get("protocolVersion") or "")
                self.client_info = params.get("clientInfo") or {}
            elif meta.get("io.modelcontextprotocol/protocolVersion"):
                self.protocol_version = str(meta["io.modelcontextprotocol/protocolVersion"])
                self.client_info = meta.get("io.modelcontextprotocol/clientInfo") or self.client_info
            if method == "tools/list":
                self.calls[rid] = {"kind": "list", "start_ns": time.time_ns()}
            if method == "tools/call":
                if self._gate_call(rid, params, modern="_meta" in params and "io.modelcontextprotocol/protocolVersion" in (params.get("_meta") or {})):
                    return
        self._to_server(raw=raw)

    def _gate_call(self, rid: Any, params: dict[str, Any], modern: bool) -> bool:
        """Return True if the call was blocked (and answered)."""
        name = str(params.get("name", ""))
        args = params.get("arguments") or {}
        self.stats["calls"] += 1
        reasons: list[str] = []
        if self.lock is not None and name not in self.tool_defs:
            reasons.append("tool definition has not been inspected; request tools/list first")
        if self.policy.require_pinned and name not in (self.lock or {}).get("servers", {}).get(self.server_name, {}).get("tools", {}):
            reasons.append("tool is not in lock file")
        if name in self.hidden_tools:
            reasons.append(f"tool '{name}' is hidden: {self.hidden_tools[name]}")
        r = self.policy.tool_permitted(name)
        if r:
            reasons.append(r)
        reasons += self.policy.check_arguments(args)
        r = self.policy.rate_limited(name)
        if r:
            reasons.append(r)
        safe_args, _ = redact_secrets(args)
        preview = json.dumps(safe_args, ensure_ascii=False)[:2000] if self.capture_arguments else "[not captured]"
        decision = "allow" if not reasons else ("block" if self.policy.enforce else "flag")
        meta: dict[str, Any] = params["_meta"] if isinstance(params.get("_meta"), dict) else {}
        self.calls[rid] = {"kind": "call", "tool": name, "start_ns": time.time_ns(), "decision": decision, "reasons": reasons,
                           "arguments": preview, "traceparent": parse_traceparent(meta.get("traceparent"))}
        if not reasons:
            self._log("tool_call", tool=name, arguments=preview, decision="allow")
            return False
        self._log("tool_call", tool=name, arguments=preview, decision=decision, reasons=reasons)
        if not self.policy.enforce:
            return False
        self._finish_call(rid, is_error=True, error_text="blocked by policy")
        self.stats["blocked"] += 1
        self.pending.pop(rid, None)
        result: dict[str, Any] = {"content": [{"type": "text", "text": f"{BLOCK_PREFIX}: " + "; ".join(reasons)}], "isError": True}
        if modern:
            result["resultType"] = "complete"
        self._to_client({"jsonrpc": "2.0", "id": rid, "result": result})
        return True

    # ------------------------------------------------------------------ server -> client
    def handle_server(self, raw: bytes) -> None:
        try:
            msg = self._decode(raw)
        except (ValueError, UnicodeError, RecursionError):
            self._reject("server")
            return
        method = msg.get("method")
        if method and "id" in msg:  # server-initiated request (legacy sampling/elicitation/roots)
            if method == "sampling/createMessage" and not self.policy.allow_sampling:
                self._log("server_request", method=method, decision="block" if self.policy.enforce else "flag")
                if self.policy.enforce:
                    self._to_server({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "sampling denied by MCPShield policy"}})
                    return
            else:
                self._log("server_request", method=method, decision="allow")
            self._to_client(raw=raw)
            return
        if method:
            if method == "notifications/tools/list_changed":
                self.tool_defs.clear()
                self._log("tools_list_changed")
            self._to_client(raw=raw)
            return

        rid = msg.get("id")
        pending = self.pending.pop(rid, None)
        if pending and "error" in msg and pending[0] in ("tools/call", "tools/list"):
            err = msg.get("error") or {}
            self._finish_call(rid, is_error=True, error_text=str(err.get("message", "error")) if isinstance(err, dict) else "error")
        if not pending or "result" not in msg or not isinstance(msg["result"], dict):
            self._to_client(raw=raw)
            return
        req_method, req_params = pending
        changed = False
        result = msg["result"]
        if req_method == "tools/list":
            changed = self._filter_tools(result)
            self._finish_list(rid, result)
        elif req_method == "tools/call":
            changed = self._filter_result(str(req_params.get("name", "")), result)
            self._finish_call(rid, is_error=bool(result.get("isError")))
        if result.get("resultType") == "input_required" and not self.policy.allow_sampling:
            requests = result.get("inputRequests")
            if not isinstance(requests, dict) or any(not isinstance(r, dict) or r.get("method") == "sampling/createMessage"
                                                     for r in requests.values()):
                self._log("server_request", method="sampling/createMessage", decision="block" if self.policy.enforce else "flag")
                if self.policy.enforce:
                    result.clear()
                    result.update({"resultType": "complete", "isError": True,
                                   "content": [{"type": "text", "text": f"{BLOCK_PREFIX}: sampling denied"}]})
                    changed = True
        if result.get("resultType") == "input_required":
            kinds = [str(r.get("method")) if isinstance(r, dict) else "invalid" for r in (result.get("inputRequests") or {}).values()] if isinstance(result.get("inputRequests"), dict) else []
            self._log("input_required", method=req_method, requests=kinds)
        self._to_client(msg if changed else None, raw=None if changed else raw)

    def _filter_tools(self, result: dict[str, Any]) -> bool:
        tools = result.get("tools")
        if not isinstance(tools, list):
            return False
        kept: list[dict[str, Any]] = []
        hidden: dict[str, str] = {}
        pinned = ((self.lock or {}).get("servers", {}).get(self.server_name) or {}).get("tools", {}) if self.lock else None
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", ""))
            self.tool_defs[name] = tool
            reason = self.policy.tool_permitted(name)
            if not reason:
                bad = [f for f in check_tool(self._inv, tool) if f.severity >= self.policy.block_severity]
                if bad:
                    reason = "; ".join(sorted({f.title for f in bad}))
            if not reason and pinned is not None:
                if name not in pinned:
                    reason = "not in lock file" if self.policy.require_pinned else ""
                elif pinned[name].get("digest") != tool_digest(tool):
                    reason = "definition changed since pinning (possible rug pull)"
            if reason:
                hidden[name] = reason
                if not self.policy.enforce:
                    kept.append(tool)
            else:
                kept.append(tool)
        for name, why in hidden.items():
            self._log("tool_hidden" if self.policy.enforce else "tool_flagged", tool=name, reason=why)
        self._log("tools_listed", total=len(tools), exposed=len(kept), hidden=sorted(hidden))
        if self.policy.enforce:
            self.hidden_tools.update(hidden)
            self.stats["hidden_tools"] = len(self.hidden_tools)
            if len(kept) != len(tools):
                result["tools"] = kept
                return True
        return False

    def _filter_result(self, tool: str, result: dict[str, Any]) -> bool:
        changed = False
        text = _result_text(result)
        sigs = [s for s in analyse_text(text) if s.severity >= Severity.HIGH]
        if sigs:
            self.stats["injections"] += 1
            self._log("result_injection", tool=tool, signals=[s.message for s in sigs][:5],
                      decision="block" if (self.policy.block_injected_results and self.policy.enforce) else "flag")
            if self.policy.block_injected_results and self.policy.enforce:
                result["content"] = [{"type": "text", "text": f"{BLOCK_PREFIX}: tool output contained prompt-injection content "
                                                              f"({'; '.join(s.message for s in sigs[:3])}) and was withheld."}]
                result.pop("structuredContent", None)
                result["isError"] = True
                return True
        if self.policy.redact_secrets and self.policy.enforce:
            for key in ("content", "structuredContent"):
                if key in result:
                    new, found = redact_secrets(result[key])
                    if found:
                        result[key] = new
                        changed = True
                        self.stats["redactions"] += 1
                        self._log("result_redacted", tool=tool, secret_types=found)
        return changed

    # ------------------------------------------------------------------ observability
    def _base_attrs(self) -> dict[str, Any]:
        return {
            "mcp.protocol.version": self.protocol_version or None,
            "network.transport": "pipe",
            "mcpshield.server": self.server_name,
            "mcpshield.session.id": self.session_id,
            "gen_ai.agent.name": str(self.client_info.get("name") or "") or None,
        }

    def _finish_list(self, rid: Any, result: dict[str, Any]) -> None:
        call = self.calls.pop(rid, None)
        if not call:
            return
        span = Span("tools/list", self.session_id, new_span_id(), self.session_span_id, call["start_ns"], time.time_ns())
        span.attributes.update(self._base_attrs())
        span.attributes.update({"mcp.method.name": "tools/list", "mcpshield.tools.exposed": len(result.get("tools") or []),
                                "mcpshield.tools.hidden": sorted(self.hidden_tools)})
        self.exporter.export(span)

    def _finish_call(self, rid: Any, is_error: bool, error_text: str = "") -> None:
        call = self.calls.pop(rid, None)
        if not call:
            return
        end = time.time_ns()
        if call.get("kind") == "list":
            span = Span("tools/list", self.session_id, new_span_id(), self.session_span_id, call["start_ns"], end, error=error_text or None)
            span.attributes.update({**self._base_attrs(), "mcp.method.name": "tools/list"})
            self.exporter.export(span)
            return
        tool = call["tool"]
        tool_caps = sorted(caps.tool_capabilities(self.tool_defs.get(tool) or {"name": tool}))
        duration_ms = round((end - call["start_ns"]) / 1e6, 2)
        self._log("tool_result", tool=tool, duration_ms=duration_ms, is_error=is_error, decision=call["decision"], capabilities=tool_caps)

        trace_id, parent = (call["traceparent"] or (self.session_id, self.session_span_id))
        span = Span(f"execute_tool {tool}", trace_id, new_span_id(), parent, call["start_ns"], end,
                    error=(error_text or "tool returned isError") if is_error else None)
        span.attributes.update(self._base_attrs())
        span.attributes.update({
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": tool,
            "mcp.method.name": "tools/call",
            "mcpshield.decision": call["decision"],
            "mcpshield.reasons": call["reasons"],
            "mcpshield.tool.capabilities": tool_caps,
        })
        if self.capture_arguments:
            span.attributes["gen_ai.tool.call.arguments"] = call["arguments"]
        if call["traceparent"]:
            span.attributes["mcpshield.session.id"] = self.session_id

        if call["decision"] != "block" and not is_error:
            for c in tool_caps:
                self.session_caps.setdefault(c, [])
                if tool not in self.session_caps[c]:
                    self.session_caps[c].append(tool)
            if caps.is_trifecta(set(self.session_caps)) and "lethal_trifecta" not in self.alerted:
                self.alerted.add("lethal_trifecta")
                self.stats["alerts"] += 1
                detail = {c: self.session_caps[c] for c in (caps.PRIVATE, caps.UNTRUSTED, caps.EXTERNAL)}
                self._log("alert", kind="lethal_trifecta", severity="high", tool=tool,
                          message="session combined private-data access, untrusted content and an outbound channel", detail=detail)
                span.add_event("mcpshield.alert", {"mcpshield.alert.kind": "lethal_trifecta", "mcpshield.alert.severity": "high",
                                                   "mcpshield.alert.tools": sorted({t for v in detail.values() for t in v})})
        if call["decision"] in ("block", "flag"):
            span.add_event("mcpshield.policy_violation", {"mcpshield.reasons": call["reasons"], "mcpshield.decision": call["decision"]})
        self.exporter.export(span)

    def close_session(self, exit_code: Optional[int] = None) -> None:
        span = Span(f"mcp.session {self.server_name}", self.session_id, self.session_span_id, None, self.session_start_ns, time.time_ns())
        span.attributes.update(self._base_attrs())
        span.attributes.update({f"mcpshield.stats.{k}": v for k, v in self.stats.items()})
        if exit_code is not None:
            span.attributes["process.exit.code"] = exit_code
        self.exporter.export(span)
        self.exporter.close()

    # ------------------------------------------------------------------ main loop
    def run(self) -> int:
        import os

        env = dict(os.environ)
        if self.env:
            env.update(self.env)
        # The untrusted child must not receive the key used to authenticate its audit trail.
        env.pop("MCPSHIELD_AUDIT_KEY", None)
        self.proc = subprocess.Popen([self.command, *self.args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env, bufsize=0)  # noqa: S603
        self._log("proxy_start", command=[self.command], mode=self.policy.mode)

        def pump_server() -> None:
            assert self.proc and self.proc.stdout
            server_stdout = self.proc.stdout
            for line in iter(lambda: server_stdout.readline(4 * 1024 * 1024 + 1), b""):
                if len(line) > 4 * 1024 * 1024:
                    self.proc.terminate()
                    return
                if line.strip():
                    try:
                        self.handle_server(line)
                    except Exception:  # noqa: BLE001 - fail closed on inspection errors
                        self._reject("server")

        t = threading.Thread(target=pump_server, daemon=True)
        t.start()
        try:
            for line in iter(lambda: self.stdin.readline(4 * 1024 * 1024 + 1), b""):
                if len(line) > 4 * 1024 * 1024:
                    self.proc.terminate()
                    break
                if line.strip():
                    try:
                        self.handle_client(line)
                    except Exception:  # noqa: BLE001 - fail closed on inspection errors
                        self._reject("client")
        except KeyboardInterrupt:  # pragma: no cover
            pass
        finally:
            if self.proc.stdin:
                try:
                    self.proc.stdin.close()
                except OSError:
                    pass
        try:
            code = self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                code = self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                code = self.proc.wait()
        t.join(timeout=2)
        self._log("proxy_stop", exit_code=code, **self.stats)
        self.close_session(code)
        return code

