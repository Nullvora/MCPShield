# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""A minimal, dependency-light, *dual-era* MCP client used for live inspection.

* Modern protocol (2026-07-28): stateless, per-request ``_meta``, ``server/discover``.
* Legacy protocols (2024-11-05 … 2025-11-25): ``initialize`` handshake, optional ``Mcp-Session-Id``.
* Transports: stdio, Streamable HTTP (JSON or SSE responses) and the deprecated HTTP+SSE transport.

The client only ever *lists* capabilities. It never calls tools, and it refuses every server-initiated
request (sampling, elicitation, roots) — recording that the server attempted it.
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from collections.abc import Callable
from urllib.parse import urljoin

from mcpshield import __version__

MODERN_VERSION = "2026-07-28"
LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
MODERN_ERROR_CODES = {-32020, -32021, -32022}
CLIENT_INFO = {"name": "mcpshield", "version": __version__}


class MCPError(Exception):
    def __init__(self, message: str, code: Optional[int] = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class AuthRequired(MCPError):
    def __init__(self, status: int, www_authenticate: str, body: str = ""):
        super().__init__(f"HTTP {status}: authorization required")
        self.status = status
        self.www_authenticate = www_authenticate
        self.body = body


class TransportClosed(MCPError):
    pass


def expand_env(value: str, env: Optional[dict[str, str]] = None) -> str:
    """Expand ${VAR}, ${env:VAR} and $VAR references (VS Code / Claude style)."""
    env = env if env is not None else dict(os.environ)

    def repl(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        if name.startswith("env:"):
            name = name[4:]
        if name.startswith("input:"):
            return ""
        return env.get(name, "")

    return re.sub(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)", repl, value)


# =========================================================================== transports


class Transport:
    """Sends JSON-RPC messages; delivers every inbound message to ``on_message``."""

    kind = "base"

    def start(self, on_message: Callable[[dict[str, Any]], None]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def send(self, message: dict[str, Any], *, era: str, protocol_version: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover
        pass

    @property
    def alive(self) -> bool:
        return True


class StdioTransport(Transport):
    kind = "stdio"

    def __init__(self, command: str, args: list[str], env: Optional[dict[str, str]] = None, cwd: Optional[str] = None):
        self.command = command
        self.args = args
        self.env = env or {}
        self.cwd = cwd
        self.proc: Optional[subprocess.Popen[bytes]] = None
        self.stderr_tail: list[str] = []
        self._lock = threading.Lock()

    def start(self, on_message: Callable[[dict[str, Any]], None]) -> None:
        env = dict(os.environ)
        env.update({k: expand_env(v) for k, v in self.env.items()})
        self.proc = subprocess.Popen(  # noqa: S603 - launching the configured MCP server is the point of --live
            [self.command, *self.args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd=self.cwd, bufsize=0,
        )

        def read_stdout() -> None:
            assert self.proc and self.proc.stdout
            for raw in iter(self.proc.stdout.readline, b""):
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    self.stderr_tail.append(f"[non-JSON stdout] {line[:200]}")
                    continue
                for m in (msg if isinstance(msg, list) else [msg]):
                    if isinstance(m, dict):
                        on_message(m)
            on_message({"__closed__": True})

        def read_stderr() -> None:
            assert self.proc and self.proc.stderr
            for raw in iter(self.proc.stderr.readline, b""):
                self.stderr_tail.append(raw.decode("utf-8", "replace").rstrip())
                del self.stderr_tail[:-50]

        threading.Thread(target=read_stdout, daemon=True).start()
        threading.Thread(target=read_stderr, daemon=True).start()

    def send(self, message: dict[str, Any], *, era: str, protocol_version: str) -> None:
        if not self.proc or not self.proc.stdin or self.proc.poll() is not None:
            raise TransportClosed("server process is not running")
        data = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise TransportClosed(str(exc)) from exc

    @property
    def alive(self) -> bool:
        return bool(self.proc) and self.proc.poll() is None  # type: ignore[union-attr]

    def close(self) -> None:
        if not self.proc:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=2)
        except Exception:  # noqa: BLE001
            self.proc.kill()
            try:
                self.proc.wait(timeout=2)
            except Exception:  # noqa: BLE001 - best effort
                pass


def _iter_sse(lines: Any) -> Any:
    """Yield (event, data) tuples from an iterator of text lines."""
    event: str = "message"
    data: list[str] = []
    for line in lines:
        if line is None:
            break
        line = line.rstrip("\r")
        if line == "":
            if data:
                yield event, "\n".join(data)
            event, data = "message", []
            continue
        if line.startswith(":"):
            continue
        field_name, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if field_name == "event":
            event = value
        elif field_name == "data":
            data.append(value)
    if data:
        yield event, "\n".join(data)


@dataclass
class HttpObservation:
    """Raw facts about HTTP exchanges, consumed by probes."""

    statuses: list[int] = field(default_factory=list)
    session_ids: list[str] = field(default_factory=list)
    response_headers: list[dict[str, str]] = field(default_factory=list)
    www_authenticate: str = ""
    auth_status: int = 0


class StreamableHttpTransport(Transport):
    kind = "http"

    def __init__(self, url: str, headers: Optional[dict[str, str]] = None, timeout: float = 20.0, verify: bool = True):
        import httpx

        self.url = url
        self.headers = {k: expand_env(v) for k, v in (headers or {}).items()}
        self.headers = {k: v for k, v in self.headers.items() if v.strip() and v.strip() not in ("Bearer", "Token")}
        self.session_id: Optional[str] = None
        self.obs = HttpObservation()
        self._client = httpx.Client(timeout=timeout, verify=verify, follow_redirects=False)
        self._on_message: Optional[Callable[[dict[str, Any]], None]] = None

    def start(self, on_message: Callable[[dict[str, Any]], None]) -> None:
        self._on_message = on_message

    def _headers_for(self, message: dict[str, Any], era: str, protocol_version: str) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": f"mcpshield/{__version__}"}
        h.update(self.headers)
        method = message.get("method", "")
        if era == "modern":
            h["MCP-Protocol-Version"] = protocol_version
            if method:
                h["Mcp-Method"] = method
            params = message.get("params") or {}
            name = params.get("name") or params.get("uri")
            if name and method in ("tools/call", "resources/read", "prompts/get"):
                h["Mcp-Name"] = str(name)
        else:
            if method != "initialize" and protocol_version:
                h["MCP-Protocol-Version"] = protocol_version
            if self.session_id and method != "initialize":
                h["Mcp-Session-Id"] = self.session_id
        return h

    def send(self, message: dict[str, Any], *, era: str, protocol_version: str) -> None:
        assert self._on_message is not None
        headers = self._headers_for(message, era, protocol_version)
        with self._client.stream("POST", self.url, headers=headers, content=json.dumps(message)) as resp:
            self.obs.statuses.append(resp.status_code)
            self.obs.response_headers.append({k.lower(): v for k, v in resp.headers.items()})
            sid = resp.headers.get("mcp-session-id")
            if sid and resp.status_code < 400 and message.get("method") == "initialize":
                # Only a successful initialize establishes a legacy session (some servers echo IDs on errors too).
                self.session_id = sid
                self.obs.session_ids.append(sid)
            if resp.status_code in (401, 403) and resp.headers.get("www-authenticate") is not None or resp.status_code == 401:
                body = resp.read().decode("utf-8", "replace")
                self.obs.www_authenticate = resp.headers.get("www-authenticate", "")
                self.obs.auth_status = resp.status_code
                raise AuthRequired(resp.status_code, self.obs.www_authenticate, body[:500])
            if resp.status_code == 202:
                return
            ctype = resp.headers.get("content-type", "")
            if "text/event-stream" in ctype:
                for _event, data in _iter_sse(resp.iter_lines()):
                    try:
                        msg = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    for m in (msg if isinstance(msg, list) else [msg]):
                        if isinstance(m, dict):
                            self._on_message(m)
                return
            body = resp.read().decode("utf-8", "replace")
            if not body.strip():
                if resp.status_code >= 400:
                    self._on_message({"__http_error__": resp.status_code, "id": message.get("id"), "body": ""})
                return
            try:
                msg = json.loads(body)
            except json.JSONDecodeError:
                self._on_message({"__http_error__": resp.status_code, "id": message.get("id"), "body": body[:500]})
                return
            for m in (msg if isinstance(msg, list) else [msg]):
                if isinstance(m, dict):
                    # One POST carries one request: attribute id-less / non-matching error bodies (e.g. id "server-error") to it.
                    if "error" in m and "id" in message and m.get("id") != message["id"]:
                        m = {**m, "id": message["id"]}
                    self._on_message(m)
            if resp.status_code >= 400 and not isinstance(msg, dict):
                self._on_message({"__http_error__": resp.status_code, "id": message.get("id"), "body": body[:500]})

    def close(self) -> None:
        if self.session_id:
            try:
                self._client.delete(self.url, headers={**self.headers, "Mcp-Session-Id": self.session_id})
            except Exception:  # noqa: BLE001 - best effort
                pass
        self._client.close()


class LegacySseTransport(Transport):
    """Deprecated HTTP+SSE transport (2024-11-05): GET opens a stream, first event names the POST endpoint."""

    kind = "sse"

    def __init__(self, url: str, headers: Optional[dict[str, str]] = None, timeout: float = 20.0, verify: bool = True):
        import httpx

        self.url = url
        self.headers = {k: expand_env(v) for k, v in (headers or {}).items() if expand_env(v).strip()}
        self.timeout = timeout
        self._client = httpx.Client(timeout=httpx.Timeout(timeout, read=None), verify=verify)
        self.endpoint: Optional[str] = None
        self._endpoint_ready = threading.Event()
        self._closed = False
        self.obs = HttpObservation()
        self._error: Optional[Exception] = None

    def start(self, on_message: Callable[[dict[str, Any]], None]) -> None:
        def run() -> None:
            try:
                with self._client.stream("GET", self.url, headers={**self.headers, "Accept": "text/event-stream"}) as resp:
                    self.obs.statuses.append(resp.status_code)
                    if resp.status_code == 401:
                        self.obs.www_authenticate = resp.headers.get("www-authenticate", "")
                        self.obs.auth_status = 401
                        self._error = AuthRequired(401, self.obs.www_authenticate)
                        self._endpoint_ready.set()
                        return
                    for event, data in _iter_sse(resp.iter_lines()):
                        if self._closed:
                            break
                        if event == "endpoint":
                            self.endpoint = urljoin(self.url, data.strip())
                            self._endpoint_ready.set()
                            continue
                        try:
                            msg = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(msg, dict):
                            on_message(msg)
            except Exception as exc:  # noqa: BLE001
                self._error = exc
                self._endpoint_ready.set()
            on_message({"__closed__": True})

        threading.Thread(target=run, daemon=True).start()
        if not self._endpoint_ready.wait(self.timeout):
            raise MCPError("SSE server did not send an endpoint event")
        if self._error:
            raise self._error if isinstance(self._error, MCPError) else MCPError(str(self._error))

    def send(self, message: dict[str, Any], *, era: str, protocol_version: str) -> None:
        if not self.endpoint:
            raise TransportClosed("no SSE endpoint")
        resp = self._client.post(self.endpoint, json=message, headers={**self.headers, "Content-Type": "application/json"})
        self.obs.statuses.append(resp.status_code)
        if resp.status_code == 401:
            raise AuthRequired(401, resp.headers.get("www-authenticate", ""))

    def close(self) -> None:
        self._closed = True
        self._client.close()


# =========================================================================== session


class MCPSession:
    def __init__(self, transport: Transport, timeout: float = 20.0, prefer: str = "auto"):
        self.transport = transport
        self.timeout = timeout
        self.prefer = prefer          # auto | modern | legacy
        self.era = ""
        self.protocol_version = ""
        self.server_info: dict[str, Any] = {}
        self.capabilities: dict[str, Any] = {}
        self.instructions = ""
        self.server_requests: list[str] = []   # server-initiated request methods we refused
        self._next_id = 0
        self._pending: dict[Any, queue.Queue[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._closed = threading.Event()

    # ------------------------------------------------------------------ plumbing
    def _on_message(self, msg: dict[str, Any]) -> None:
        if msg.get("__closed__"):
            self._closed.set()
            for q in list(self._pending.values()):
                q.put({"__closed__": True})
            return
        if "method" in msg and "id" in msg:
            # server -> client request: refuse (scanner never samples, elicits or exposes roots)
            self.server_requests.append(str(msg.get("method")))
            reply = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "mcpshield: client capability not provided"}}
            try:
                threading.Thread(target=self.transport.send, args=(reply,), kwargs={"era": self.era or "legacy", "protocol_version": self.protocol_version}, daemon=True).start()
            except Exception:  # noqa: BLE001
                pass
            return
        if "method" in msg:
            return  # notification
        pending = self._pending.get(msg.get("id"))
        if pending is not None:
            pending.put(msg)

    def _meta(self) -> dict[str, Any]:
        return {
            "io.modelcontextprotocol/protocolVersion": self.protocol_version or MODERN_VERSION,
            "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
            "io.modelcontextprotocol/clientCapabilities": {},
        }

    def request(self, method: str, params: Optional[dict[str, Any]] = None, timeout: Optional[float] = None, era: Optional[str] = None) -> dict[str, Any]:
        era = era or self.era or "legacy"
        with self._lock:
            self._next_id += 1
            rid = self._next_id
        params = dict(params or {})
        if era == "modern":
            params["_meta"] = {**params.get("_meta", {}), **self._meta()}
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params or era == "modern":
            msg["params"] = params
        q: queue.Queue[dict[str, Any]] = queue.Queue()
        self._pending[rid] = q
        try:
            self.transport.send(msg, era=era, protocol_version=self.protocol_version)
            try:
                resp = q.get(timeout=timeout or self.timeout)
            except queue.Empty as exc:
                raise MCPError(f"timeout waiting for {method}") from exc
        finally:
            self._pending.pop(rid, None)
        if resp.get("__closed__"):
            raise TransportClosed(f"connection closed during {method}")
        if "__http_error__" in resp:
            raise MCPError(f"HTTP {resp['__http_error__']} for {method}: {resp.get('body', '')[:200]}", code=None, data={"status": resp["__http_error__"]})
        if "error" in resp:
            err = resp["error"] or {}
            raise MCPError(str(err.get("message", "error")), code=err.get("code"), data=err.get("data"))
        return resp.get("result") or {}

    def notify(self, method: str, params: Optional[dict[str, Any]] = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params:
            msg["params"] = params
        self.transport.send(msg, era=self.era, protocol_version=self.protocol_version)

    # ------------------------------------------------------------------ connection
    def connect(self) -> None:
        self.transport.start(self._on_message)
        if self.prefer != "legacy":
            try:
                if self._try_modern():
                    return
            except AuthRequired:
                raise
            except TransportClosed:
                if isinstance(self.transport, StdioTransport):
                    # Some legacy servers exit on unknown methods; restart before falling back.
                    self.transport.close()
                    self._closed.clear()
                    self.transport.start(self._on_message)
                else:
                    raise
            if self.prefer == "modern":
                raise MCPError("server does not support the modern (2026-07-28) protocol")
        self._legacy_initialize()

    def _try_modern(self) -> bool:
        self.protocol_version = MODERN_VERSION
        try:
            res = self.request("server/discover", {}, timeout=min(self.timeout, 8.0), era="modern")
        except MCPError as exc:
            if isinstance(exc, (AuthRequired, TransportClosed)):
                raise
            if exc.code == -32022 and isinstance(exc.data, dict):
                supported = [v for v in exc.data.get("supported", []) if isinstance(v, str)]
                modern = sorted([v for v in supported if v >= MODERN_VERSION], reverse=True)
                if modern:
                    self.protocol_version = modern[0]
                    res = self.request("server/discover", {}, era="modern")
                else:
                    self.protocol_version = ""
                    return False
            else:
                self.protocol_version = ""
                return False
        self.era = "modern"
        versions = res.get("supportedVersions") or res.get("protocolVersions") or res.get("versions") or []
        if isinstance(versions, list) and versions and self.protocol_version not in versions:
            mv = sorted([v for v in versions if isinstance(v, str) and v >= MODERN_VERSION], reverse=True)
            if mv:
                self.protocol_version = mv[0]
        self.server_info = res.get("serverInfo") or (res.get("_meta") or {}).get("io.modelcontextprotocol/serverInfo") or {}
        self.capabilities = res.get("capabilities") or {}
        self.instructions = res.get("instructions") or ""
        return True

    def _legacy_initialize(self) -> None:
        self.era = "legacy"
        self.protocol_version = ""
        res = self.request("initialize", {
            "protocolVersion": LEGACY_VERSIONS[0],
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        }, era="legacy")
        self.protocol_version = str(res.get("protocolVersion") or LEGACY_VERSIONS[0])
        self.server_info = res.get("serverInfo") or {}
        self.capabilities = res.get("capabilities") or {}
        self.instructions = res.get("instructions") or ""
        try:
            self.notify("notifications/initialized")
        except MCPError:
            pass

    # ------------------------------------------------------------------ listing
    def list_all(self, method: str, key: str, limit_pages: int = 50) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor: Optional[str] = None
        for _ in range(limit_pages):
            params = {"cursor": cursor} if cursor else {}
            res = self.request(method, params)
            items += [i for i in res.get(key, []) if isinstance(i, dict)]
            cursor = res.get("nextCursor")
            if not cursor:
                break
        return items

    def close(self) -> None:
        self.transport.close()


def time_it(fn: Callable[[], Any]) -> tuple[Any, float]:
    t0 = time.monotonic()
    return fn(), time.monotonic() - t0
