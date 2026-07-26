"""
MCPShield Reporter — HTML Report Generator
Produces a self-contained, professional HTML security report.
"""

from __future__ import annotations

from mcpshield.models.findings import Finding, ScanResult

_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#0891b2",
    "INFO":     "#6b7280",
}

_SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fefce8",
    "LOW":      "#ecfeff",
    "INFO":     "#f9fafb",
}


def generate_html_report(result: ScanResult) -> str:
    """Return a complete, self-contained HTML report as a string."""
    findings_html = "\n".join(_finding_card(f) for f in result.findings_by_severity())
    counts = result.counts
    label_color = _SEVERITY_COLORS.get(result.risk_label, "#6b7280")

    summary_badges = "".join(
        f'<span class="badge" style="background:{_SEVERITY_COLORS[s]}">'
        f'{counts[s]} {s}</span>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if counts.get(s, 0) > 0
    )

    owasp_tags = "".join(
        f'<span class="tag">{ref}</span>' for ref in result.owasp_coverage
    )
    cve_tags = "".join(
        f'<span class="tag cve-tag">{cve}</span>' for cve in result.cves_referenced
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCPShield Security Report — {result.target.raw}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}

  /* Header */
  .header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 32px; }}
  .logo {{ font-size: 2.5rem; }}
  .header-text h1 {{ font-size: 1.8rem; font-weight: 700; color: #f8fafc; }}
  .header-text p  {{ color: #94a3b8; font-size: 0.9rem; }}

  /* Risk score card */
  .risk-card {{ background: #1e293b; border-radius: 12px; padding: 28px 32px;
                margin-bottom: 28px; border: 1px solid #334155; }}
  .risk-header {{ display: flex; justify-content: space-between; align-items: flex-start; }}
  .risk-score  {{ font-size: 3.5rem; font-weight: 800; color: {label_color}; }}
  .risk-label  {{ font-size: 1rem; color: {label_color}; font-weight: 600;
                  padding: 4px 14px; border: 2px solid {label_color};
                  border-radius: 20px; display: inline-block; }}
  .risk-bar-bg {{ background: #334155; border-radius: 8px; height: 10px;
                  margin-top: 20px; overflow: hidden; }}
  .risk-bar-fill {{ height: 100%; border-radius: 8px; background: {label_color};
                    width: {result.risk_score}%; transition: width 0.6s; }}
  .meta-grid   {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                  gap: 16px; margin-top: 24px; }}
  .meta-item   {{ background: #0f172a; padding: 14px 18px; border-radius: 8px; }}
  .meta-item .label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase;
                        letter-spacing: 0.05em; margin-bottom: 4px; }}
  .meta-item .value {{ font-size: 0.95rem; color: #e2e8f0; font-weight: 600; }}

  /* Badges */
  .badges {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 28px; }}
  .badge  {{ padding: 5px 14px; border-radius: 20px; font-size: 0.8rem;
             font-weight: 700; color: white; }}
  .tag    {{ background: #1e3a5f; color: #93c5fd; padding: 3px 10px;
             border-radius: 4px; font-size: 0.78rem; font-family: monospace; }}
  .cve-tag {{ background: #3b1818; color: #fca5a5; }}
  .tags   {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 28px; }}

  /* Section headings */
  .section-title {{ font-size: 1.1rem; font-weight: 700; color: #94a3b8;
                    text-transform: uppercase; letter-spacing: 0.08em;
                    margin: 32px 0 16px; border-bottom: 1px solid #334155;
                    padding-bottom: 8px; }}

  /* Finding cards */
  .finding  {{ background: #1e293b; border-radius: 10px; margin-bottom: 16px;
               border-left: 4px solid; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px;
                     padding: 16px 20px; cursor: pointer; }}
  .finding-sev    {{ font-size: 0.75rem; font-weight: 800; padding: 3px 10px;
                     border-radius: 12px; color: white; white-space: nowrap; }}
  .finding-id     {{ font-size: 0.75rem; color: #64748b; font-family: monospace; }}
  .finding-title  {{ font-size: 0.95rem; font-weight: 600; color: #f1f5f9; flex: 1; }}
  .finding-body   {{ padding: 0 20px 20px; }}
  .finding-section {{ margin-top: 14px; }}
  .finding-section .label {{ font-size: 0.72rem; text-transform: uppercase;
                              letter-spacing: 0.06em; color: #64748b;
                              margin-bottom: 4px; }}
  .finding-section .content {{ font-size: 0.88rem; color: #cbd5e1; line-height: 1.7; }}
  .evidence {{ background: #0f172a; padding: 12px 16px; border-radius: 6px;
               font-family: monospace; font-size: 0.82rem; color: #94a3b8;
               white-space: pre-wrap; word-break: break-all; }}
  .remediation {{ background: #0c2318; padding: 12px 16px; border-radius: 6px;
                  font-size: 0.87rem; color: #86efac; white-space: pre-line; }}
  .owasp-ref  {{ display: inline-block; background: #1e3a5f; color: #93c5fd;
                 padding: 2px 8px; border-radius: 4px; font-size: 0.78rem;
                 font-family: monospace; margin-right: 6px; }}
  .cve-ref    {{ display: inline-block; background: #3b1818; color: #fca5a5;
                 padding: 2px 8px; border-radius: 4px; font-size: 0.78rem;
                 font-family: monospace; margin-right: 4px; }}

  /* Footer */
  .footer {{ text-align: center; color: #475569; font-size: 0.8rem;
             margin-top: 48px; padding-top: 24px; border-top: 1px solid #334155; }}
  .footer a {{ color: #60a5fa; text-decoration: none; }}

  /* Executive Summary */
  .exec-summary {{ background: #1e293b; border-radius: 10px; padding: 20px 24px;
                    margin-bottom: 28px; border: 1px solid #334155; }}
  .exec-summary h2 {{ font-size: 1rem; color: #94a3b8; margin-bottom: 12px;
                        text-transform: uppercase; letter-spacing: 0.06em; }}
  .exec-summary p {{ color: #cbd5e1; font-size: 0.9rem; line-height: 1.7; }}
  .stat-row {{ display: flex; gap: 16px; margin-top: 16px; flex-wrap: wrap; }}
  .stat-box {{ background: #0f172a; border-radius: 8px; padding: 14px 18px;
                flex: 1; min-width: 120px; }}
  .stat-box .num {{ font-size: 1.5rem; font-weight: 700; }}
  .stat-box .lbl {{ font-size: 0.72rem; color: #64748b; text-transform: uppercase;
                    letter-spacing: 0.05em; margin-top: 2px; }}

  /* Print Styles */
  @media print {{
    body {{ background: white; color: #1e293b; }}
    .container {{ max-width: 100%; padding: 20px; }}
    .risk-card, .finding, .exec-summary, .stat-box {{
      border: 1px solid #cbd5e1 !important; box-shadow: none !important; }}
    .header {{ border-bottom: 2px solid #334155; padding-bottom: 12px; }}
    .footer {{ display: none; }}
    .finding {{ break-inside: avoid; page-break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="logo">🛡️</div>
    <div class="header-text">
      <h1>MCPShield Security Report</h1>
      <p>MCP Security Assessment Framework by <strong>Nullvora</strong> &nbsp;·&nbsp; v{result.scanner_version}</p>
    </div>
  </div>

  <!-- Risk Score Card -->
  <div class="risk-card">
    <div class="risk-header">
      <div>
        <div style="color:#94a3b8; font-size:0.8rem; margin-bottom:4px">COMPOSITE RISK SCORE</div>
        <div class="risk-score">{result.risk_score}<span style="font-size:1.5rem;color:#475569">/100</span></div>
      </div>
      <div class="risk-label">{result.risk_label}</div>
    </div>
    <div class="risk-bar-bg"><div class="risk-bar-fill"></div></div>
    <div class="meta-grid">
      <div class="meta-item">
        <div class="label">Target</div>
        <div class="value" style="word-break:break-all">{result.target.raw}</div>
      </div>
      <div class="meta-item">
        <div class="label">Scan Type</div>
        <div class="value">{result.target.scan_type}</div>
      </div>
      <div class="meta-item">
        <div class="label">Timestamp</div>
        <div class="value">{result.timestamp}</div>
      </div>
      <div class="meta-item">
        <div class="label">Total Findings</div>
        <div class="value">{len(result.findings)}</div>
      </div>
    </div>
  </div>

  <!-- Severity Badges -->
  <div class="badges">{summary_badges}</div>

  <!-- OWASP & CVE Tags -->
  {"<div class='section-title'>OWASP ASI Coverage</div><div class='tags'>" + owasp_tags + "</div>" if owasp_tags else ""}
  {"<div class='section-title'>CVEs Referenced</div><div class='tags'>" + cve_tags + "</div>" if cve_tags else ""}

  <!-- Executive Summary -->
  <div class="exec-summary">
    <h2>Executive Summary</h2>
    <p>
      This assessment identified <strong>{len(result.findings)}</strong> security findings
      across the MCP deployment at <strong>{result.target.raw}</strong>.
      The composite risk score is <strong>{result.risk_score}/100</strong>
      ({result.risk_label}),
      {"with " + str(len(result.cves_referenced)) + " CVE(s) referenced and coverage of " + str(len(result.owasp_coverage)) + " OWASP ASI categories." if result.cves_referenced or result.owasp_coverage else "with no CVE references or OWASP ASI categories mapped."}
      {"Immediate action is required to address the CRITICAL and HIGH severity findings." if result.risk_score >= 50 else "The deployment shows moderate risk. Address MEDIUM and above findings to improve security posture."}
    </p>
    <div class="stat-row">
      <div class="stat-box"><div class="num" style="color:{_SEVERITY_COLORS['CRITICAL']}">{counts.get('CRITICAL', 0)}</div><div class="lbl">Critical</div></div>
      <div class="stat-box"><div class="num" style="color:{_SEVERITY_COLORS['HIGH']}">{counts.get('HIGH', 0)}</div><div class="lbl">High</div></div>
      <div class="stat-box"><div class="num" style="color:{_SEVERITY_COLORS['MEDIUM']}">{counts.get('MEDIUM', 0)}</div><div class="lbl">Medium</div></div>
      <div class="stat-box"><div class="num" style="color:{_SEVERITY_COLORS['LOW']}">{counts.get('LOW', 0)}</div><div class="lbl">Low</div></div>
      <div class="stat-box"><div class="num" style="color:{_SEVERITY_COLORS['INFO']}">{counts.get('INFO', 0)}</div><div class="lbl">Info</div></div>
    </div>
  </div>

  <!-- Findings -->
  <div class="section-title">Findings ({len(result.findings)})</div>
  {findings_html if findings_html else '<p style="color:#64748b">No findings — target appears clean.</p>'}

  <!-- Footer -->
  <div class="footer">
    Generated by <a href="https://github.com/Nullvora/MCPShield">MCPShield</a> v{result.scanner_version}
    &nbsp;·&nbsp; <a href="https://nullvora.com">nullvora.com</a>
    &nbsp;·&nbsp; Mapped to <a href="https://genai.owasp.org">OWASP ASI Top 10</a>
    <br><br>
    This report is confidential and intended for the named organisation only.
  </div>

</div>
</body>
</html>"""


def _finding_card(f: Finding) -> str:
    color   = _SEVERITY_COLORS.get(f.severity.value, "#6b7280")
    cve_html = "".join(f'<span class="cve-ref">{c}</span>' for c in f.cve_refs)

    return f"""
<div class="finding" style="border-left-color:{color}">
  <div class="finding-header">
    <span class="finding-sev" style="background:{color}">{f.severity.value}</span>
    <span class="finding-id">{f.id}</span>
    <span class="finding-title">{f.title}</span>
  </div>
  <div class="finding-body">
    <div class="finding-section">
      <div class="label">Category &nbsp;·&nbsp;
        <span class="owasp-ref">{f.owasp_ref}</span>
        {cve_html}
      </div>
      <div class="content">{f.category.value}</div>
    </div>
    <div class="finding-section">
      <div class="label">Description</div>
      <div class="content">{f.description}</div>
    </div>
    <div class="finding-section">
      <div class="label">Affected Component</div>
      <div class="content">{f.affected_component}</div>
    </div>
    <div class="finding-section">
      <div class="label">Evidence</div>
      <div class="evidence">{f.evidence}</div>
    </div>
    <div class="finding-section">
      <div class="label">Remediation</div>
      <div class="remediation">{f.remediation}</div>
    </div>
  </div>
</div>"""


def save_html_report(result: ScanResult, output_path: str) -> None:
    """Write the HTML report to a file."""
    html = generate_html_report(result)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
