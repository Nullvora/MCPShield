# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Self-contained HTML report. Every dynamic value is HTML-escaped; the page loads no external resources."""

from __future__ import annotations

import html
import json
from pathlib import Path

from mcpshield.checks import capabilities as caps
from mcpshield.models import ScanResult, Severity
from mcpshield.taxonomy import OWASP_MCP

E = html.escape

_CSS = """
:root{--bg:#F8F9FA;--panel:#fff;--ink:#0A192F;--muted:#5b6478;--line:#e3e7ee;--accent:#0f9d84;
--crit:#d32f2f;--high:#ff5252;--med:#e0a100;--low:#2b7de9;--info:#8892B0;--ok:#00a651}
@media (prefers-color-scheme:dark){:root{--bg:#0A192F;--panel:#112240;--ink:#e6f1ff;--muted:#8892B0;--line:#233554;--accent:#64FFDA;
--crit:#ff5252;--high:#ff7b7b;--med:#FFB800;--low:#6cb6ff;--info:#8892B0;--ok:#00C853}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,Segoe UI,Inter,Roboto,sans-serif}
header{padding:28px 32px;border-bottom:1px solid var(--line);display:flex;gap:24px;align-items:center;flex-wrap:wrap}
.brand{font-weight:700;font-size:20px}.brand span{color:var(--accent)}.sub{color:var(--muted);font-size:13px}
main{max-width:1120px;margin:0 auto;padding:24px 16px 64px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:8px 0 24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.big{font-size:34px;font-weight:700;line-height:1}.lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.grade{width:74px;height:74px;border-radius:50%;display:grid;place-items:center;font-size:34px;font-weight:800;border:4px solid currentColor}
.gA,.gB{color:var(--ok)}.gC{color:var(--med)}.gD{color:var(--high)}.gF{color:var(--crit)}
h2{font-size:17px;margin:28px 0 12px}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;color:#fff}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med);color:#1b1b1b}.low{background:var(--low)}.info{background:var(--info)}
details.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:10px;margin:8px 0;padding:10px 14px}
details.f.critical-b{border-left-color:var(--crit)}details.f.high-b{border-left-color:var(--high)}details.f.medium-b{border-left-color:var(--med)}details.f.low-b{border-left-color:var(--low)}
details.f summary{cursor:pointer;list-style:none;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details.f summary::-webkit-details-marker{display:none}.rid{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted)}
.srv{margin-left:auto;font-size:12px;color:var(--muted)}
pre{white-space:pre-wrap;word-break:break-word;background:rgba(127,127,127,.08);border-radius:8px;padding:10px;font:12px/1.45 ui-monospace,Menlo,monospace;margin:6px 0}
.kv{color:var(--muted);font-size:13px}.fix{border-left:3px solid var(--ok);padding-left:10px;margin:8px 0}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.bar{height:8px;border-radius:4px;background:var(--accent)}.filters button{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:999px;padding:4px 12px;margin:0 6px 6px 0;cursor:pointer}
.filters button.on{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.tag{display:inline-block;font-size:11px;border:1px solid var(--line);border-radius:6px;padding:0 6px;margin:2px 4px 2px 0;color:var(--muted)}
code{word-break:break-all}.tw{overflow-x:auto}.bc{display:flex;align-items:center;gap:8px}.bc .bar{flex:0 0 auto}
@media (max-width:600px){header{padding:18px 16px}td,th{padding:6px 4px}.srv{margin-left:0}}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:40px}
"""

_JS = """
document.querySelectorAll('.filters button').forEach(b=>b.addEventListener('click',()=>{
 b.classList.toggle('on');const on=[...document.querySelectorAll('.filters button.on')].map(x=>x.dataset.s);
 document.querySelectorAll('details.f').forEach(d=>{d.style.display=(!on.length||on.includes(d.dataset.s))?'':'none'})}));
"""


def to_html(result: ScanResult) -> str:
    c = result.counts
    grade = result.grade
    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
                 "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                 "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">"
                 f"<title>MCPShield report — grade {E(grade)}</title><style>{_CSS}</style></head><body>")
    parts.append("<header><div><div class='brand'>MCP<span>Shield</span></div>"
                 f"<div class='sub'>Security report · v{E(result.version)} · {E(result.started_at)}</div></div></header><main>")

    # summary
    parts.append("<div class='grid'>")
    parts.append(f"<div class='card' style='display:flex;gap:14px;align-items:center'><div class='grade g{E(grade)}'>{E(grade)}</div>"
                 f"<div><div class='lbl'>Risk score</div><div class='big'>{result.risk_score}</div></div></div>")
    for s in Severity:
        parts.append(f"<div class='card'><div class='lbl'>{E(s.value)}</div><div class='big'>{c[s.value]}</div></div>")
    parts.append(f"<div class='card'><div class='lbl'>Servers</div><div class='big'>{len(result.servers)}</div>"
                 f"<div class='kv'>{len(result.inventories)} inspected live</div></div></div>")

    # OWASP
    cov = result.owasp_mcp_coverage()
    if cov:
        mx = max(cov.values())
        parts.append("<h2>OWASP MCP Top 10 exposure</h2><div class='card tw'><table><tr><th>ID</th><th>Risk</th><th style='width:40%'>Findings</th></tr>")
        for ref in OWASP_MCP:
            n = cov.get(ref, 0)
            bar = f"<div class='bar' style='width:{max(4, int(100 * n / mx))}%'></div>" if n else "<span class='kv'>—</span>"
            parts.append(f"<tr><td>{E(ref)}</td><td>{E(OWASP_MCP[ref])}</td><td><div class='bc'>{bar}{('<span>' + str(n) + '</span>') if n else ''}</div></td></tr>")
        parts.append("</table></div>")

    # findings
    parts.append(f"<h2>Findings ({len(result.findings)})</h2><div class='filters'>")
    for s in Severity:
        if c[s.value]:
            parts.append(f"<button data-s='{E(s.value)}'>{E(s.value)} ({c[s.value]})</button>")
    parts.append("</div>")
    if not result.findings:
        parts.append("<div class='card'>✅ No findings.</div>")
    for f in result.sorted_findings():
        sv = f.severity.value
        tags = "".join(f"<span class='tag'>{E(t)}</span>" for t in [*f.owasp_mcp, *f.owasp_asi, *f.cwe])
        refs = "".join(f"<div class='kv'>↗ {E(u)}</div>" for u in f.references)
        parts.append(
            f"<details class='f {E(sv)}-b' data-s='{E(sv)}'><summary><span class='sev {E(sv)}'>{E(sv)}</span>"
            f"<strong>{E(f.title)}</strong><span class='rid'>{E(f.rule_id)}</span><span class='srv'>{E(f.server)}</span></summary>"
            f"<p>{E(f.description)}</p>"
            + (f"<div class='kv'>Location: {E(f.location)}</div>" if f.location else "")
            + (f"<pre>{E(f.evidence)}</pre>" if f.evidence else "")
            + f"<div class='fix'><strong>Fix:</strong> {E(f.remediation)}</div><div>{tags}</div>{refs}</details>")

    # servers
    if result.servers:
        parts.append("<h2>Configured servers</h2><div class='card tw'><table><tr><th>Name</th><th>Transport</th><th>Command / URL</th><th>Client · source</th></tr>")
        for srv in result.servers:
            target = srv.url or " ".join(srv.command_line)
            parts.append(f"<tr><td><strong>{E(srv.name)}</strong>{' <span class=tag>disabled</span>' if srv.disabled else ''}</td><td>{E(srv.transport)}</td>"
                         f"<td><code>{E(target[:200])}</code></td><td class='kv'>{E(srv.client)} · {E(srv.source)}</td></tr>")
        parts.append("</table></div>")

    # live inventory
    for inv in result.inventories:
        flagged = {f.location.split("tool:", 1)[1] for f in result.findings if f.server == inv.name and "tool:" in f.location and f.severity >= Severity.HIGH}
        parts.append(f"<h2>Live inventory · {E(inv.name)}</h2><div class='card'>"
                     f"<div class='kv'>{E(inv.target)} · era: {E(inv.era or '—')} · protocol {E(inv.protocol_version or '—')} · "
                     f"server: {E(json.dumps(inv.server_info)[:120])}</div>")
        if inv.errors:
            parts.append("".join(f"<div class='kv'>⚠ {E(e)}</div>" for e in inv.errors))
        if inv.tools:
            parts.append("<div class='tw'><table><tr><th>Tool</th><th>Capabilities</th><th>Description</th></tr>")
            for t in inv.tools:
                name = str(t.get("name", ""))
                cl = ", ".join(caps.CAP_LABELS[x] for x in sorted(caps.tool_capabilities(t)))
                mark = " <span class='sev high'>flagged</span>" if name in flagged else ""
                parts.append(f"<tr><td><code>{E(name)}</code>{mark}</td><td class='kv'>{E(cl)}</td><td>{E(str(t.get('description', ''))[:300])}</td></tr>")
            parts.append("</table></div>")
        parts.append("</div>")

    if result.errors:
        parts.append("<h2>Scan warnings</h2><div class='card'>" + "".join(f"<div class='kv'>• {E(e)}</div>" for e in result.errors) + "</div>")
    parts.append("<footer>Generated by MCPShield — open-source MCP security by Nullvora · github.com/Nullvora/MCPShield</footer>")
    parts.append(f"</main><script>{_JS}</script></body></html>")
    return "".join(parts)


def write_html(result: ScanResult, path: str) -> None:
    Path(path).write_text(to_html(result), encoding="utf-8")
