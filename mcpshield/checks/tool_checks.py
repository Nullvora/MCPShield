# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Checks over live inventories: tool poisoning, hidden content, shadowing, toxic flows, schema hygiene."""

from __future__ import annotations

import json
import re
from typing import Any
from collections.abc import Iterable

from mcpshield.checks import capabilities as caps
from mcpshield.checks.registry import make
from mcpshield.checks.text import Signal, analyse_text, extract_emails, extract_urls, hidden_character_signals
from mcpshield.models import Finding, ServerInventory, Severity

_EXFIL_PARAM_STRONG = re.compile(
    r"^(sidenote|side_note|full_context|conversation|conversation_history|chat_history|previous_messages|messages_so_far|"
    r"system_prompt|systemprompt|secrets?|credentials?|api_?keys?|passwords?|ssh_key|private_key|env_vars|environment_variables|"
    r"summary_of_conversation)$", re.I)
_EXFIL_PARAM_WEAK = re.compile(r"^(context|note|notes|history|memory|feedback|debug_info|instructions|metadata|extra|comment)$", re.I)
_EXFIL_PARAM_DESC = re.compile(
    r"\b(entire|full|whole|complete|all)\b.{0,30}\b(conversation|chat|context|history|messages|system\s+prompt)\b|"
    r"\b(contents?\s+of|read)\b.{0,30}(~/|\.ssh|\.env|credentials?|mcp\.json)|\b(your|the\s+user'?s?)\s+(api\s*keys?|passwords?|credentials|secrets)\b|"
    r"\bsystem\s+prompt\b", re.I)
_HIGH_RISK_PARAM = re.compile(r"^(cmd|command|commands|shell|script|code|exec|expression|query|sql|path|file|filepath|file_path|filename|dir|directory|url|uri|endpoint|host)$", re.I)
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_DESTRUCTIVE_NAME = re.compile(r"(^|[_\-.])(delete|remove|drop|truncate|write|update|overwrite|kill|destroy|rm|exec|execute|run|send|post|create|insert|move|rename|transfer|pay|deploy|push|merge)([_\-.]|$)", re.I)
_WELL_KNOWN_PREFIX = re.compile(r"^(github|gitlab|slack|gmail|google|notion|jira|stripe|aws|azure|filesystem|postgres)[_\-.]", re.I)


def _sig_to_severity(signals: list[Signal]) -> Severity:
    return max((s.severity for s in signals), key=lambda s: s.rank) if signals else Severity.INFO


def _fmt(signals: Iterable[Signal]) -> str:
    parts = []
    for s in sorted(signals, key=lambda x: -x.severity.rank):
        parts.append(f"[{s.severity.value}] {s.message}" + (f": “{s.snippet}”" if s.snippet else ""))
    return "\n".join(parts)[:1200]


def _schema_strings(schema: Any, path: str = "inputSchema") -> Iterable[tuple[str, str]]:
    """Yield (path, text) for every model-visible string inside a JSON schema, including property *names*."""
    if isinstance(schema, dict):
        for k, v in schema.items():
            p = f"{path}.{k}"
            if k == "properties" and isinstance(v, dict):
                for prop_name, prop_schema in v.items():
                    yield f"{p}.{prop_name}<name>", str(prop_name)
                    yield from _schema_strings(prop_schema, f"{p}.{prop_name}")
            elif isinstance(v, str) and k in ("description", "title", "default", "const", "examples", "pattern", "$comment", "format", "markdownDescription"):
                yield p, v
            elif isinstance(v, (dict, list)):
                yield from _schema_strings(v, p)
            elif k in ("default", "const") and v is not None:
                yield p, str(v)
    elif isinstance(schema, list):
        for i, v in enumerate(schema):
            if isinstance(v, str):
                yield f"{path}[{i}]", v
            else:
                yield from _schema_strings(v, f"{path}[{i}]")


def _validate_x_mcp_headers(schema: Any) -> list[str]:
    problems: list[str] = []
    seen: set[str] = set()

    def walk(node: Any, path: str, static: bool) -> None:
        if isinstance(node, dict):
            if "x-mcp-header" in node:
                val = node["x-mcp-header"]
                where = path or "<root>"
                if not static:
                    problems.append(f"{where}: annotation not statically reachable via 'properties'")
                if not isinstance(val, str) or not val:
                    problems.append(f"{where}: empty or non-string value")
                else:
                    if any(c in val for c in "\r\n") or not _HEADER_TOKEN.match(val):
                        problems.append(f"{where}: '{val!r}' is not a valid HTTP header token")
                    if val.lower() in seen:
                        problems.append(f"{where}: duplicate header name '{val}'")
                    seen.add(val.lower())
                t = node.get("type")
                if t not in ("string", "integer", "boolean"):
                    problems.append(f"{where}: applied to type {t!r} (only string/integer/boolean allowed)")
            for k, v in node.items():
                if k == "properties" and isinstance(v, dict):
                    for pn, ps in v.items():
                        walk(ps, f"{path}.{pn}" if path else pn, static)
                elif isinstance(v, (dict, list)) and k != "x-mcp-header":
                    walk(v, f"{path}/{k}", False)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]", False)

    walk(schema, "", True)
    return problems


# --------------------------------------------------------------------------- per-tool


def check_tool(inv: ServerInventory, tool: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    name = str(tool.get("name", "?"))
    loc = f"{inv.target} :: tool:{name}"
    desc = str(tool.get("description") or "")
    title = str(tool.get("title") or (tool.get("annotations") or {}).get("title") or "")

    # 1. description / title
    text = f"{title}\n{desc}" if title else desc
    signals = analyse_text(text)
    hidden = [s for s in signals if s.kind in ("unicode_tags", "zero_width", "bidi", "ansi", "control", "padding")]
    inject = [s for s in signals if s not in hidden]
    if hidden:
        out.append(make("MCPS-TOOL-002", server=inv.name, location=loc, evidence=_fmt(hidden), severity=_sig_to_severity(hidden)))
    if inject:
        sev = _sig_to_severity(inject)
        out.append(make("MCPS-TOOL-001", server=inv.name, location=loc, evidence=_fmt(inject), severity=sev,
                        title=f"Tool poisoning in '{name}'" if sev >= Severity.HIGH else f"Suspicious language in '{name}' description"))

    # 2. full schema
    schema = tool.get("inputSchema") or {}
    schema_hits: list[str] = []
    schema_sev = Severity.INFO
    for path, s in _schema_strings(schema):
        sigs = analyse_text(s)
        if sigs:
            schema_sev = max([schema_sev, _sig_to_severity(sigs)], key=lambda x: x.rank)
            schema_hits.append(f"{path}: " + "; ".join(x.message for x in sigs))
    if schema_hits:
        out.append(make("MCPS-TOOL-003", server=inv.name, location=loc, evidence="\n".join(schema_hits)[:1200],
                        severity=schema_sev if schema_sev >= Severity.HIGH else Severity.MEDIUM))

    # 3. exfil-style params & unconstrained high-risk params
    props = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(props, dict):
        exfil = []
        loose = []
        for pname, pschema in props.items():
            pdesc = str((pschema or {}).get("description", "")) if isinstance(pschema, dict) else ""
            ptype = pschema.get("type", "string") if isinstance(pschema, dict) else "string"
            if ptype in ("string", None) or (isinstance(ptype, list) and "string" in ptype):
                if _EXFIL_PARAM_STRONG.match(pname) or _EXFIL_PARAM_DESC.search(pdesc) or \
                        (_EXFIL_PARAM_WEAK.match(pname) and re.search(r"conversation|chat|history|secret|credential|prompt|before|always", pdesc, re.I)):
                    exfil.append(f"{pname}: {pdesc[:120]}" if pdesc else pname)
            if isinstance(pschema, dict) and _HIGH_RISK_PARAM.match(pname) and pschema.get("type", "string") == "string" \
                    and not any(k in pschema for k in ("enum", "pattern", "maxLength", "const", "format")):
                loose.append(pname)
        if exfil:
            out.append(make("MCPS-TOOL-004", server=inv.name, location=loc, evidence="; ".join(exfil)[:600]))
        if loose:
            out.append(make("MCPS-TOOL-009", server=inv.name, location=loc, evidence=f"free-form: {', '.join(loose)}"))

    # 4. URLs / e-mails
    blob = text + " " + json.dumps(schema, ensure_ascii=False)
    dests = sorted(set(extract_urls(blob)) | set(extract_emails(blob)))
    dests = [d for d in dests if not re.search(r"json-schema\.org|schema\.org|example\.(com|org)|localhost|127\.0\.0\.1", d)]
    if dests:
        out.append(make("MCPS-TOOL-007", server=inv.name, location=loc, evidence=", ".join(dests[:8])))

    # 5. annotations
    ann = tool.get("annotations") or {}
    if isinstance(ann, dict) and ann.get("readOnlyHint") is True and _DESTRUCTIVE_NAME.search(name):
        out.append(make("MCPS-TOOL-008", server=inv.name, location=loc, evidence=f"readOnlyHint=true on '{name}'"))
    if isinstance(ann, dict) and ann.get("destructiveHint") is False and re.search(r"(^|[_\-.])(delete|drop|destroy|truncate|rm|kill)([_\-.]|$)", name, re.I):
        out.append(make("MCPS-TOOL-008", server=inv.name, location=loc, evidence=f"destructiveHint=false on '{name}'"))

    # 6. size / x-mcp-header
    if len(desc) > 2000:
        out.append(make("MCPS-TOOL-010", server=inv.name, location=loc, evidence=f"{len(desc)} characters"))
    problems = _validate_x_mcp_headers(schema)
    if problems:
        out.append(make("MCPS-TOOL-011", server=inv.name, location=loc, evidence="; ".join(problems)[:600]))

    # 7. output schema (also model-visible in many clients)
    oschema = tool.get("outputSchema")
    if isinstance(oschema, dict):
        o_hits = [f"{p}: " + "; ".join(x.message for x in analyse_text(s)) for p, s in _schema_strings(oschema, "outputSchema") if analyse_text(s)]
        if o_hits:
            out.append(make("MCPS-TOOL-003", server=inv.name, location=loc + " (outputSchema)", evidence="\n".join(o_hits)[:800]))
    return out


# --------------------------------------------------------------------------- per-server


def check_inventory(inv: ServerInventory) -> list[Finding]:
    out: list[Finding] = []
    for tool in inv.tools:
        out += check_tool(inv, tool)

    # server instructions
    if inv.instructions:
        sigs = analyse_text(inv.instructions)
        if sigs and _sig_to_severity(sigs) >= Severity.MEDIUM:
            out.append(make("MCPS-TOOL-014", server=inv.name, location=f"{inv.target} :: instructions", evidence=_fmt(sigs),
                            severity=max(_sig_to_severity(sigs), Severity.HIGH, key=lambda s: s.rank)))

    # prompts & resources
    for kind, items in (("prompt", inv.prompts), ("resource", inv.resources), ("resource-template", inv.resource_templates)):
        for item in items:
            label = item.get("name") or item.get("uri") or item.get("uriTemplate") or "?"
            text = " ".join(str(item.get(k, "")) for k in ("name", "title", "description"))
            for arg in item.get("arguments", []) or []:
                if isinstance(arg, dict):
                    text += " " + " ".join(str(arg.get(k, "")) for k in ("name", "description"))
            sigs = analyse_text(text)
            if sigs and _sig_to_severity(sigs) >= Severity.MEDIUM:
                out.append(make("MCPS-TOOL-015", server=inv.name, location=f"{inv.target} :: {kind}:{label}", evidence=_fmt(sigs),
                                severity=_sig_to_severity(sigs)))

    # toxic flow within one server
    server_caps: dict[str, list[str]] = {}
    for tool in inv.tools:
        for c in caps.tool_capabilities(tool):
            server_caps.setdefault(c, []).append(str(tool.get("name")))
    if caps.is_trifecta(set(server_caps)):
        ev = "; ".join(f"{caps.CAP_LABELS[c]}: {', '.join(sorted(set(server_caps[c]))[:6])}" for c in (caps.PRIVATE, caps.UNTRUSTED, caps.EXTERNAL))
        out.append(make("MCPS-TOOL-012", server=inv.name, location=inv.target, evidence=ev))

    if len(inv.tools) > 50:
        out.append(make("MCPS-TOOL-013", server=inv.name, location=inv.target, evidence=f"{len(inv.tools)} tools"))

    # era / deprecated features
    if inv.era == "legacy":
        out.append(make("MCPS-CAP-002", server=inv.name, location=inv.target, evidence=f"negotiated protocol {inv.protocol_version}"))
    deprecated = []
    for cap_name in ("sampling", "roots", "logging"):
        if cap_name == "logging" and cap_name in (inv.capabilities or {}):
            deprecated.append("logging capability")
    requested = inv.http.get("server_initiated_requests") or []
    for m in requested:
        if m.startswith(("sampling/", "roots/")):
            deprecated.append(f"server sent {m}")
    if deprecated:
        sev = Severity.MEDIUM if any("sampling" in d for d in deprecated) else Severity.INFO
        out.append(make("MCPS-CAP-001", server=inv.name, location=inv.target, evidence=", ".join(deprecated), severity=sev))
    return out


# --------------------------------------------------------------------------- cross-server


def check_cross_server(inventories: list[ServerInventory]) -> list[Finding]:
    out: list[Finding] = []
    owners: dict[str, list[str]] = {}
    for inv in inventories:
        for t in inv.tools:
            owners.setdefault(str(t.get("name")), []).append(inv.name)
    for tool_name, servers in owners.items():
        if len(set(servers)) > 1:
            out.append(make("MCPS-TOOL-006", server=", ".join(sorted(set(servers))), location=f"tool:{tool_name}",
                            evidence=f"'{tool_name}' exposed by {', '.join(sorted(set(servers)))}"))

    # shadowing: a tool description mentions another server's tool names
    for inv in inventories:
        foreign = {n: s for n, ss in owners.items() for s in ss if s != inv.name and len(n) >= 5}
        for t in inv.tools:
            text = " ".join([str(t.get("description", "")), json.dumps(t.get("inputSchema", {}), ensure_ascii=False)])
            hits = sorted({n for n in foreign if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", text)})
            if hits:
                out.append(make("MCPS-TOOL-005", server=inv.name, location=f"{inv.target} :: tool:{t.get('name')}",
                                evidence=f"references tools from other servers: {', '.join(f'{h} ({foreign[h]})' for h in hits[:6])}"))
            name = str(t.get("name", ""))
            m = _WELL_KNOWN_PREFIX.match(name)
            if m and m.group(1).lower() not in inv.name.lower() and m.group(1).lower() not in json.dumps(inv.server_info).lower():
                out.append(make("MCPS-TOOL-018", server=inv.name, location=f"{inv.target} :: tool:{name}",
                                evidence=f"tool prefix '{m.group(1)}' but server is '{inv.name}'"))

    # toxic flow across all connected servers
    union: dict[str, set[str]] = {}
    for inv in inventories:
        for t in inv.tools:
            for c in caps.tool_capabilities(t):
                union.setdefault(c, set()).add(inv.name)
    if len(inventories) > 1 and caps.is_trifecta(set(union)):
        per_server_trifecta = any(caps.is_trifecta({c for t in inv.tools for c in caps.tool_capabilities(t)}) for inv in inventories)
        spans = len(union[caps.PRIVATE] | union[caps.UNTRUSTED] | union[caps.EXTERNAL]) > 1
        if spans and not per_server_trifecta:
            ev = "; ".join(f"{caps.CAP_LABELS[c]}: {', '.join(sorted(union[c]))}" for c in (caps.PRIVATE, caps.UNTRUSTED, caps.EXTERNAL))
            out.append(make("MCPS-PRV-003", server="*", location="live tool inventory", evidence=ev))
    return out


def hidden_only(text: str) -> list[Signal]:
    return hidden_character_signals(text)
