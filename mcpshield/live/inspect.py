# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Connect to a server and build a :class:`ServerInventory`."""

from __future__ import annotations

from typing import Optional

from mcpshield.live.client import (
    AuthRequired,
    LegacySseTransport,
    MCPError,
    MCPSession,
    StdioTransport,
    StreamableHttpTransport,
    Transport,
)
from mcpshield.models import ServerInventory, ServerSpec


def transport_for(spec: ServerSpec, timeout: float = 20.0, extra_headers: Optional[dict[str, str]] = None, verify_tls: bool = True) -> Transport:
    if spec.transport == "stdio":
        assert spec.command
        return StdioTransport(spec.command, spec.args, spec.env)
    headers = {**spec.headers, **(extra_headers or {})}
    if spec.transport == "sse":
        return LegacySseTransport(spec.url or "", headers, timeout, verify_tls)
    return StreamableHttpTransport(spec.url or "", headers, timeout, verify_tls)


def inspect_server(spec: ServerSpec, timeout: float = 20.0, prefer: str = "auto",
                   extra_headers: Optional[dict[str, str]] = None, verify_tls: bool = True) -> ServerInventory:
    target = spec.url or " ".join(spec.command_line)
    inv = ServerInventory(name=spec.name, target=target, transport=spec.transport)
    transport = transport_for(spec, timeout, extra_headers, verify_tls)
    session = MCPSession(transport, timeout=timeout, prefer=prefer)
    try:
        session.connect()
    except AuthRequired as exc:
        inv.errors.append(f"authorization required (HTTP {exc.status})")
        inv.http["auth_required"] = True
        inv.http["www_authenticate"] = exc.www_authenticate
        session.close()
        return inv
    except (MCPError, OSError) as exc:
        detail = str(exc)
        if isinstance(transport, StdioTransport) and transport.stderr_tail:
            detail += " | stderr: " + " / ".join(transport.stderr_tail[-3:])[:300]
        inv.errors.append(f"connect failed: {detail}")
        session.close()
        return inv
    except Exception as exc:  # noqa: BLE001 - httpx errors etc.
        inv.errors.append(f"connect failed: {type(exc).__name__}: {exc}")
        session.close()
        return inv

    inv.era = session.era
    inv.protocol_version = session.protocol_version
    inv.server_info = session.server_info
    inv.capabilities = session.capabilities
    inv.instructions = session.instructions
    caps = session.capabilities or {}

    def _collect(method: str, key: str, cap: str) -> list[dict]:
        if session.era == "legacy" and cap not in caps:
            return []
        try:
            return session.list_all(method, key)
        except MCPError as exc:
            if exc.code != -32601:
                inv.errors.append(f"{method}: {exc}")
            return []

    try:
        inv.tools = _collect("tools/list", "tools", "tools")
        inv.prompts = _collect("prompts/list", "prompts", "prompts")
        inv.resources = _collect("resources/list", "resources", "resources")
        inv.resource_templates = _collect("resources/templates/list", "resourceTemplates", "resources")
    except Exception as exc:  # noqa: BLE001
        inv.errors.append(f"listing failed: {type(exc).__name__}: {exc}")
    finally:
        if session.server_requests:
            inv.http["server_initiated_requests"] = sorted(set(session.server_requests))
        obs = getattr(transport, "obs", None)
        if obs is not None:
            inv.http["session_ids"] = list(obs.session_ids)
            inv.http["statuses"] = list(obs.statuses)
            inv.http["response_headers"] = obs.response_headers[:1]
        session.close()
    return inv
