# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Non-destructive HTTP probes for remote MCP servers.

Every probe is read-only: discovery/list requests, OPTIONS pre-flights, metadata GETs and a single malformed
JSON body. MCPShield never calls tools. It also applies the SSRF rules it checks for: it refuses to follow
metadata URLs that point at private, link-local or non-HTTPS destinations advertised by the server.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from mcpshield import __version__
from mcpshield.checks.config_checks import is_loopback_host
from mcpshield.checks.registry import make
from mcpshield.live.client import MODERN_VERSION, CLIENT_INFO
from mcpshield.models import Finding, ServerInventory, ServerSpec, Severity

EVIL_ORIGIN = "https://evil.mcpshield-probe.invalid"
_UA = {"User-Agent": f"mcpshield/{__version__} (+https://github.com/Nullvora/MCPShield)"}


def _client(timeout: float, verify: bool):
    import httpx

    return httpx.Client(timeout=timeout, verify=verify, follow_redirects=False)


def _discover_body() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": {
        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
        "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
        "io.modelcontextprotocol/clientCapabilities": {}}}}


def _init_body() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": CLIENT_INFO}}


def _post(client: Any, url: str, body: Any, headers: dict[str, str]) -> Any:
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **_UA, **headers}
    content = body if isinstance(body, str) else json.dumps(body)
    return client.post(url, content=content, headers=h)


def _is_public_https(url: str, allow_loopback: bool) -> tuple[bool, str]:
    """Return (safe_to_fetch, reason)."""
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        return False, f"non-web scheme '{u.scheme}:'"
    host = u.hostname or ""
    if not host:
        return False, "no host"
    try:
        infos = socket.getaddrinfo(host, u.port or (443 if u.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        addrs = {ipaddress.ip_address(i[4][0]) for i in infos}
    except (socket.gaierror, ValueError):
        return False, "unresolvable host"
    for a in addrs:
        if a.is_loopback and allow_loopback:
            continue
        if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified:
            return False, f"resolves to non-public address {a}"
    if u.scheme != "https" and not (allow_loopback and all(a.is_loopback for a in addrs)):
        return False, "plain http"
    return True, ""


def _parse_www_authenticate(value: str) -> dict[str, str]:
    return {k.lower(): v for k, v in re.findall(r'(\w+)="([^"]*)"', value or "")}


def _well_known(url: str, suffix: str) -> list[str]:
    u = urlparse(url)
    path = u.path.rstrip("/")
    base = urlunparse((u.scheme, u.netloc, "", "", "", ""))
    cands = []
    if path:
        cands.append(f"{base}/.well-known/{suffix}{path}")
    cands.append(f"{base}/.well-known/{suffix}")
    return cands


# --------------------------------------------------------------------------- probes


def probe_tls(url: str, timeout: float = 8.0) -> Optional[Finding]:
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        return None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((u.hostname, u.port or 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=u.hostname) as ssock:
                version = ssock.version() or ""
    except ssl.SSLCertVerificationError as exc:
        return make("MCPS-HTTP-007", location=url, evidence=f"certificate verification failed: {exc.verify_message}")
    except (ssl.SSLError, OSError):
        return None
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        return make("MCPS-HTTP-007", location=url, evidence=f"negotiated {version}")
    return None


def probe_http(spec: ServerSpec, inv: ServerInventory, timeout: float = 10.0, verify_tls: bool = True) -> list[Finding]:
    """Run HTTP-level probes and return findings (also annotates inv.http)."""
    url = spec.url or ""
    if not url or spec.transport not in ("http", "sse"):
        return []
    findings: list[Finding] = []
    host = urlparse(url).hostname
    loopback = is_loopback_host(host)
    tls = probe_tls(url)
    if tls:
        tls.server = spec.name
        findings.append(tls)

    try:
        client = _client(timeout, verify_tls)
    except Exception:  # noqa: BLE001
        return findings
    with client:
        # ---- 1. anonymous access ---------------------------------------------------------
        anon_tools: Optional[int] = None
        if spec.transport == "http":
            try:
                r = _post(client, url, _discover_body(), {"MCP-Protocol-Version": MODERN_VERSION, "Mcp-Method": "server/discover"})
                modern_ok = r.status_code == 200 and "result" in _first_json(r)
                sid = None
                if not modern_ok:
                    r = _post(client, url, _init_body(), {})
                    sid = r.headers.get("mcp-session-id")
                if r.status_code == 401 or (r.status_code == 403 and r.headers.get("www-authenticate")):
                    inv.http["auth_required"] = True
                    inv.http["www_authenticate"] = r.headers.get("www-authenticate", "")
                elif r.status_code == 200 and "result" in _first_json(r):
                    hdr = {"MCP-Protocol-Version": MODERN_VERSION, "Mcp-Method": "tools/list"} if modern_ok else \
                          {"MCP-Protocol-Version": str(_first_json(r).get("result", {}).get("protocolVersion", "2025-11-25"))}
                    if sid:
                        hdr["Mcp-Session-Id"] = sid
                        _post(client, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, hdr)
                    body: dict[str, Any] = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
                    if modern_ok:
                        body["params"] = {"_meta": _discover_body()["params"]["_meta"]}
                    tr = _post(client, url, body, hdr)
                    res = _first_json(tr).get("result")
                    if tr.status_code == 200 and isinstance(res, dict):
                        anon_tools = len(res.get("tools", []))
                    if sid:
                        try:
                            client.delete(url, headers={"Mcp-Session-Id": sid, **_UA})
                        except Exception:  # noqa: BLE001
                            pass
                    if sid:
                        inv.http.setdefault("session_ids", []).append(sid)
            except Exception as exc:  # noqa: BLE001
                inv.errors.append(f"anonymous probe failed: {type(exc).__name__}: {exc}")
        if anon_tools is not None:
            inv.http["anonymous_tools"] = anon_tools
            sev = Severity.MEDIUM if loopback else Severity.HIGH
            if not loopback and anon_tools and any(k in json.dumps(inv.tools).lower() for k in ("exec", "shell", "write", "delete", "send")):
                sev = Severity.CRITICAL
            findings.append(make("MCPS-HTTP-001", server=spec.name, location=url, severity=sev,
                                 evidence=f"anonymous client listed {anon_tools} tool(s)"
                                          + (" (loopback-only server; still reachable by any local process or via DNS rebinding)" if loopback else "")))

        # ---- 2. Origin validation (DNS rebinding) -----------------------------------------
        if spec.transport == "http":
            try:
                auth = _auth_headers(spec)
                accepted = None
                r = _post(client, url, _discover_body(), {"Origin": EVIL_ORIGIN, "MCP-Protocol-Version": MODERN_VERSION,
                                                          "Mcp-Method": "server/discover", **auth})
                if r.status_code == 200 and "result" in _first_json(r):
                    accepted = r
                elif r.status_code != 403:
                    r = _post(client, url, _init_body(), {"Origin": EVIL_ORIGIN, **auth})
                    sid = r.headers.get("mcp-session-id")
                    if sid:
                        try:
                            client.delete(url, headers={"Mcp-Session-Id": sid, **auth, **_UA})
                        except Exception:  # noqa: BLE001
                            pass
                    if r.status_code == 200 and "result" in _first_json(r):
                        accepted = r
                inv.http["origin_validated"] = accepted is None
                if accepted is not None:
                    findings.append(make("MCPS-HTTP-002", server=spec.name, location=url,
                                         severity=Severity.HIGH if loopback else Severity.MEDIUM,
                                         evidence=f"request with Origin: {EVIL_ORIGIN} was processed (HTTP {accepted.status_code})"))
            except Exception:  # noqa: BLE001
                pass

        # ---- 3. CORS ------------------------------------------------------------------------
        try:
            r = client.request("OPTIONS", url, headers={"Origin": EVIL_ORIGIN, "Access-Control-Request-Method": "POST",
                                                        "Access-Control-Request-Headers": "content-type,authorization", **_UA})
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
            if acao == EVIL_ORIGIN or (acao == "*" and (loopback or anon_tools is not None)):
                findings.append(make("MCPS-HTTP-006", server=spec.name, location=url,
                                     severity=Severity.HIGH if (acao == EVIL_ORIGIN and acac) or loopback else Severity.MEDIUM,
                                     evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}"))
        except Exception:  # noqa: BLE001
            pass

        # ---- 4. verbose errors ----------------------------------------------------------------
        try:
            r = _post(client, url, '{"jsonrpc": "2.0", "id": ', {"MCP-Protocol-Version": MODERN_VERSION, "Mcp-Method": "tools/list", **_auth_headers(spec)})
            if re.search(r"Traceback \(most recent call last\)|\bat [\w.<>]+ \(.*:\d+:\d+\)|node_modules/|site-packages/|Exception in thread|\.java:\d+\)", r.text):
                findings.append(make("MCPS-HTTP-010", server=spec.name, location=url, evidence=r.text[:200].replace("\n", " ")))
        except Exception:  # noqa: BLE001
            pass

        # ---- 5. legacy session id quality ---------------------------------------------------
        sids = [s for s in inv.http.get("session_ids", []) if s]
        weak = [s for s in sids if len(s) < 16 or s.isdigit() or len(set(s)) < 8]
        if weak:
            findings.append(make("MCPS-HTTP-008", server=spec.name, location=url, evidence=f"Mcp-Session-Id sample: {weak[0][:40]!r}"))

        # ---- 6. OAuth metadata --------------------------------------------------------------
        if inv.http.get("auth_required"):
            findings += _probe_oauth(client, spec, inv, loopback)
    return findings


def _auth_headers(spec: ServerSpec) -> dict[str, str]:
    from mcpshield.live.client import expand_env

    return {k: expand_env(v) for k, v in spec.headers.items() if expand_env(v).strip()}


def _first_json(resp: Any) -> dict[str, Any]:
    text = resp.text or ""
    ctype = resp.headers.get("content-type", "")
    try:
        if "text/event-stream" in ctype:
            for line in text.splitlines():
                if line.startswith("data:"):
                    obj = json.loads(line[5:].strip())
                    if isinstance(obj, dict) and ("result" in obj or "error" in obj):
                        return obj
            return {}
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def _probe_oauth(client: Any, spec: ServerSpec, inv: ServerInventory, loopback: bool) -> list[Finding]:
    out: list[Finding] = []
    url = spec.url or ""
    www = _parse_www_authenticate(inv.http.get("www_authenticate", ""))
    prm_url = www.get("resource_metadata")
    prm: dict[str, Any] = {}
    unsafe: list[str] = []
    candidates = [prm_url] if prm_url else _well_known(url, "oauth-protected-resource")
    for cand in candidates:
        if not cand:
            continue
        ok, why = _is_public_https(cand, allow_loopback=loopback)
        if not ok:
            unsafe.append(f"resource_metadata {cand} ({why})")
            continue
        try:
            r = client.get(cand, headers={"Accept": "application/json", **_UA})
            if r.status_code == 200:
                prm = r.json()
                break
        except Exception:  # noqa: BLE001
            continue
    inv.http["protected_resource_metadata"] = bool(prm)
    if not prm:
        out.append(make("MCPS-HTTP-003", server=spec.name, location=url,
                        evidence="WWW-Authenticate without resource_metadata and no /.well-known/oauth-protected-resource document"
                        if not prm_url else f"resource_metadata URL did not return metadata: {prm_url}"))
    servers = [s for s in (prm.get("authorization_servers") or []) if isinstance(s, str)]
    for issuer in servers[:3]:
        ok, why = _is_public_https(issuer, allow_loopback=loopback)
        if not ok:
            unsafe.append(f"authorization_server {issuer} ({why})")
            continue
        meta: dict[str, Any] = {}
        for cand in _well_known(issuer, "oauth-authorization-server") + _well_known(issuer, "openid-configuration"):
            try:
                r = client.get(cand, headers={"Accept": "application/json", **_UA})
                if r.status_code == 200:
                    meta = r.json()
                    break
            except Exception:  # noqa: BLE001
                continue
        if not meta:
            continue
        inv.http.setdefault("authorization_servers", []).append(issuer)
        if "S256" not in (meta.get("code_challenge_methods_supported") or []):
            out.append(make("MCPS-HTTP-004", server=spec.name, location=issuer,
                            evidence=f"code_challenge_methods_supported={meta.get('code_challenge_methods_supported')}"))
        if not meta.get("authorization_response_iss_parameter_supported"):
            out.append(make("MCPS-HTTP-011", server=spec.name, location=issuer, evidence="authorization_response_iss_parameter_supported not true"))
        for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri"):
            ep = meta.get(key)
            if isinstance(ep, str) and ep:
                ok, why = _is_public_https(ep, allow_loopback=loopback)
                if not ok:
                    unsafe.append(f"{key} {ep} ({why})")
    if unsafe:
        out.append(make("MCPS-HTTP-005", server=spec.name, location=url, evidence="; ".join(unsafe)[:600]))
    return out
