# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Local agent-activity viewer: turns runtime-guard audit logs into per-session timelines.

Works entirely offline on the hash-chained JSONL files written by ``mcpshield proxy``; the same activity can be
streamed to any OpenTelemetry backend with ``--otlp-endpoint`` (see docs/OBSERVABILITY.md).
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from collections.abc import Iterable

from mcpshield import __version__
from mcpshield.auditlog import verify

TIMELINE_EVENTS = {"proxy_start", "proxy_stop", "tools_listed", "tool_hidden", "tool_call", "tool_result",
                   "tool_flagged", "result_injection", "result_redacted", "alert", "server_request", "tools_list_changed",
                   "input_required", "guard_error"}


@dataclass
class Session:
    session_id: str
    server: str = ""
    started: str = ""
    ended: str = ""
    records: list[dict[str, Any]] = field(default_factory=list)

    @property
    def calls(self) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("event") == "tool_call"]

    @property
    def results(self) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("event") == "tool_result"]

    @property
    def alerts(self) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("event") == "alert"]

    @property
    def blocked(self) -> int:
        return sum(1 for r in self.calls if r.get("decision") == "block")

    @property
    def flagged(self) -> int:
        return sum(1 for r in self.calls if r.get("decision") == "flag")

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.get("is_error") and r.get("decision") != "block")

    @property
    def tools(self) -> list[str]:
        seen: dict[str, None] = {}
        for r in self.calls:
            seen.setdefault(str(r.get("tool", "")), None)
        return list(seen)

    @property
    def total_ms(self) -> float:
        return round(sum(float(r.get("duration_ms") or 0) for r in self.results), 2)

    def summary(self) -> dict[str, Any]:
        return {"session": self.session_id, "server": self.server, "started": self.started, "ended": self.ended,
                "calls": len(self.calls), "blocked": self.blocked, "flagged": self.flagged, "errors": self.errors,
                "alerts": [a.get("kind") for a in self.alerts], "tools": self.tools, "tool_time_ms": self.total_ms}


def load_records(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in paths:
        with Path(p).open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        out.append(record)
                except json.JSONDecodeError:
                    continue
    return out


def group_sessions(records: list[dict[str, Any]]) -> list[Session]:
    sessions: dict[str, Session] = {}
    for r in records:
        sid = str(r.get("session") or "legacy")
        s = sessions.setdefault(sid, Session(sid))
        s.records.append(r)
        s.server = s.server or str(r.get("server") or "")
        ts = str(r.get("ts") or "")
        s.started = min(s.started, ts) if s.started else ts
        s.ended = max(s.ended, ts)
    return sorted(sessions.values(), key=lambda s: s.started)


def verify_all(paths: Iterable[str | Path]) -> dict[str, tuple[bool, list[str], int]]:
    return {str(p): verify(p) for p in paths}


def describe(r: dict[str, Any]) -> tuple[str, str]:
    """(label, detail) for one timeline record."""
    ev = r.get("event")
    tool = r.get("tool", "")
    if ev == "tool_call":
        d = r.get("decision", "allow")
        reasons = "; ".join(r.get("reasons") or [])
        return f"call {tool}", f"{d}{' — ' + reasons if reasons else ''}  args={str(r.get('arguments', ''))[:160]}"
    if ev == "tool_result":
        state = "error" if r.get("is_error") else "ok"
        return f"result {tool}", f"{state} in {r.get('duration_ms', '?')} ms  capabilities={','.join(r.get('capabilities') or []) or '-'}"
    if ev == "alert":
        return f"ALERT {r.get('kind', '')}", f"{r.get('message', '')}  {json.dumps(r.get('detail') or {})}"
    if ev == "tools_listed":
        return "tools/list", f"{r.get('exposed', '?')}/{r.get('total', '?')} exposed, hidden={r.get('hidden', [])}"
    if ev in ("tool_hidden", "tool_flagged"):
        return f"hidden {tool}", str(r.get("reason", ""))
    if ev == "proxy_start":
        return "session start", f"mode={r.get('mode', '')}  " + " ".join(str(a) for a in r.get("command") or [])[:200]
    if ev == "proxy_stop":
        return "session end", f"exit={r.get('exit_code')} calls={r.get('calls')} blocked={r.get('blocked')}"
    rest = {k: v for k, v in r.items() if k not in ("seq", "ts", "event", "server", "session", "prev", "hash", "sig")}
    return str(ev), json.dumps(rest, ensure_ascii=False)[:200]


def severity(r: dict[str, Any]) -> str:
    ev = r.get("event")
    if ev == "alert" or (ev == "tool_call" and r.get("decision") == "block") or ev == "result_injection" or (ev == "server_request" and r.get("decision") == "block"):
        return "bad"
    if (ev == "tool_call" and r.get("decision") == "flag") or ev in ("tool_hidden", "tool_flagged", "result_redacted", "guard_error") or (ev == "tool_result" and r.get("is_error")):
        return "warn"
    return "ok"


# --------------------------------------------------------------------------- HTML
_CSS = """
:root{--bg:#f7f8fa;--fg:#14171f;--muted:#5d6475;--card:#fff;--line:#e3e6ec;--ok:#1f8a4c;--warn:#b86e00;--bad:#c62828;--accent:#3b4cca}
@media (prefers-color-scheme: dark){:root{--bg:#0f1116;--fg:#e8eaf0;--muted:#9aa1b2;--card:#171a22;--line:#2a2f3b;--ok:#4cc38a;--warn:#f0a44b;--bad:#ff6b6b;--accent:#8c9bff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:16px 0}
.stats{display:flex;flex-wrap:wrap;gap:16px;margin-top:8px}.stat b{display:block;font-size:20px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.t{white-space:nowrap;color:var(--muted);font-family:ui-monospace,monospace}
td.d{word-break:break-word;font-family:ui-monospace,monospace;font-size:12px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.bar{height:6px;background:var(--accent);border-radius:3px;min-width:2px}
.wrap{overflow-x:auto}
"""


def render_html(sessions: list[Session], integrity: dict[str, tuple[bool, list[str], int]]) -> str:
    e = html.escape
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>MCPShield agent activity</title><style>{_CSS}</style></head><body><main>",
             "<h1>Agent activity</h1>",
             f"<div class='muted'>MCPShield {e(__version__)} · {len(sessions)} session(s) · generated from runtime-guard audit logs</div>"]
    parts.append("<div class='card'><b>Audit-log integrity</b><ul>")
    for path, (ok, problems, n) in integrity.items():
        state = f"<span class='ok'>✓ chain intact ({n} records)</span>" if ok else f"<span class='bad'>✗ {len(problems)} problem(s): {e('; '.join(problems[:3]))}</span>"
        parts.append(f"<li><code>{e(Path(path).name)}</code> — {state}</li>")
    parts.append("</ul></div>")
    for s in sessions:
        sm = s.summary()
        alert_html = "".join(f"<span class='pill bad'>{e(str(a))}</span> " for a in sm["alerts"])
        parts.append(f"<div class='card'><div><b>{e(s.server or 'server')}</b> <span class='muted'>session {e(s.session_id[:12])} · "
                     f"{e(s.started)} → {e(s.ended)}</span> {alert_html}</div><div class='stats'>"
                     + "".join(f"<div class='stat'><b class='{c}'>{v}</b><span class='muted'>{k}</span></div>" for k, v, c in [
                         ("tool calls", sm["calls"], ""), ("blocked", sm["blocked"], "bad" if sm["blocked"] else ""),
                         ("flagged", sm["flagged"], "warn" if sm["flagged"] else ""), ("errors", sm["errors"], "warn" if sm["errors"] else ""),
                         ("tool time (ms)", sm["tool_time_ms"], "")]) + "</div>")
        max_ms = max([float(r.get("duration_ms") or 0) for r in s.results] or [1.0]) or 1.0
        parts.append("<div class='wrap'><table><tr><th>time</th><th>event</th><th>detail</th><th style='width:120px'>duration</th></tr>")
        for r in s.records:
            if r.get("event") not in TIMELINE_EVENTS:
                continue
            label, detail = describe(r)
            dur = float(r.get("duration_ms") or 0)
            bar = f"<div class='bar' style='width:{max(2, int(100 * dur / max_ms))}%'></div>" if r.get("event") == "tool_result" else ""
            parts.append(f"<tr><td class='t'>{e(str(r.get('ts', ''))[11:23])}</td><td><span class='{severity(r)}'>{e(label)}</span></td>"
                         f"<td class='d'>{e(detail)}</td><td>{bar}</td></tr>")
        parts.append("</table></div></div>")
    parts.append("</main></body></html>")
    return "".join(parts)


def filter_sessions(sessions: list[Session], session: Optional[str] = None, only_alerts: bool = False) -> list[Session]:
    out = [s for s in sessions if not session or s.session_id.startswith(session)]
    if only_alerts:
        out = [s for s in out if s.alerts or s.blocked or s.flagged]
    return out
