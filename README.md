# MCPShield 🛡️

> **The first dedicated open-source security assessment, hardening, and runtime monitoring framework for Model Context Protocol (MCP) deployments.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](CHANGELOG.md)
[![OWASP ASI Mapped](https://img.shields.io/badge/OWASP-ASI%20Top%2010%20Mapped-red.svg)](THREAT_MODEL.md)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## The Problem

The Model Context Protocol (MCP) has become the universal backbone of agentic AI — the open standard that connects AI models to tools, databases, APIs, file systems, and external services across every major platform including Claude, GPT-4o, Gemini, and their enterprise deployments.

**It is critically under-secured.**

| Finding | Source | Year |
|---|---|---|
| 200,000+ MCP server instances exposed to arbitrary OS command execution | Ox Security / CVE-2025-49596 | 2026 |
| 492 MCP servers with no client authentication or traffic encryption | Trend Micro | 2026 |
| RCE vulnerabilities confirmed in official Anthropic MCP SDKs across Python, TypeScript, Java, and Rust | The Hacker News / CVE-2026-22252 | 2026 |
| 1,184 malicious skills confirmed across ClawHub — the primary MCP skill registry | Antiy CERT | 2026 |
| 36.7% of publicly analysed MCP servers vulnerable to Server-Side Request Forgery (SSRF) | BlueRock Security | 2026 |
| A manufacturing company's procurement agent was manipulated over three weeks through memory poisoning, resulting in unauthorized fund transfers | OWASP ASI Case Study | 2025 |

Traditional API security tools, WAFs, and SIEM rules were not designed for this attack surface. MCP involves **agent-driven decision-making, shifting trust contexts, and autonomous tool execution** — a threat model that has no direct analogue in classical web application or network security.

MCPShield was built to close this gap.

---

## What MCPShield Provides

MCPShield is organized into four interlocking modules, each addressing a distinct phase of MCP security:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         MCPShield Framework                         │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
│  │  SCANNER    │  │  HARDENING  │  │   MONITOR   │  │ RED TEAM  │ │
│  │             │  │             │  │             │  │           │ │
│  │ Assess &    │  │ Remediate & │  │ Detect &    │  │ Attack &  │ │
│  │ Audit       │  │ Configure   │  │ Respond     │  │ Validate  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │
│                                                                     │
│          Mapped to: OWASP ASI Top 10 for Agentic Applications      │
└─────────────────────────────────────────────────────────────────────┘
```

### Module 1 — Scanner
Automated security assessment of MCP deployments. Discovers servers, audits transport configuration, validates authentication, tests tool definitions for injection vectors, checks supply chain integrity, and generates a structured security report with severity ratings and remediation priorities.

### Module 2 — Hardening
A practitioner-grade hardening guide covering secure MCP server configuration, authentication implementation, transport security, least-privilege tool scoping, supply chain verification, and multi-agent trust controls. Includes ready-to-use configuration templates.

### Module 3 — Monitor
A lightweight runtime monitoring agent that intercepts and logs all MCP tool calls, detects anomalous patterns (privilege escalation, unexpected data access, injection signatures), enforces policy rules, and generates tamper-evident audit trails for governance and incident response.

### Module 4 — Red Team
Documented attack scenarios against MCP deployments, including prompt injection payloads for agentic contexts, supply chain poisoning simulations, and inter-agent trust exploitation techniques. Designed for internal red teams and security assessment professionals.

---

## Threat Coverage

MCPShield maps directly to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) with additional MCP-specific threat categories:

| OWASP ASI | Risk | MCPShield Coverage |
|---|---|---|
| ASI01 | Agent Goal / Behavior Hijacking | Scanner (injection detection), Monitor (behavioral drift detection) |
| ASI02 | Tool Misuse and Exploitation | Scanner (tool definition audit), Monitor (tool call anomaly detection) |
| ASI03 | Identity and Privilege Abuse | Scanner (auth assessment), Hardening (least-privilege templates) |
| ASI04 | Supply Chain Vulnerabilities | Scanner (supply chain integrity), Red Team (supply chain attacks) |
| ASI05 | Unexpected Code Execution | Scanner (STDIO vulnerability detection), Hardening (execution sandboxing) |
| ASI06 | Memory & Context Poisoning | Monitor (context integrity checks), Red Team (poisoning simulations) |
| ASI07 | Insecure Inter-Agent Communication | Scanner (transport audit), Hardening (agent-to-agent auth templates) |
| ASI08 | Cascading Failures | Monitor (failure propagation detection), Red Team (cascade scenarios) |
| ASI09 | Human-Agent Trust Exploitation | Hardening (human oversight controls), Red Team (social engineering simulations) |
| ASI10 | Rogue Agents | Monitor (goal alignment monitoring), Hardening (containment controls) |

> Full threat taxonomy with attack chains, risk ratings, and detection logic: [THREAT_MODEL.md](THREAT_MODEL.md)

---

## Repository Structure

```
MCPShield/
│
├── README.md                          ← You are here
├── THREAT_MODEL.md                    ← Full MCP threat taxonomy (the intellectual core)
├── CHANGELOG.md                       ← Version history
├── SECURITY.md                        ← Responsible disclosure policy
├── LICENSE
├── CONTRIBUTING.md
│
├── mcpshield/                         ← Main Python package
│   ├── __init__.py
│   ├── cli.py                          ← CLI entry point (click)
│   ├── scanner/                        ← Security scanner modules
│   │   ├── core.py                     ← Scan orchestrator
│   │   ├── transport.py                ← STDIO/HTTP/SSE transport security checks
│   │   ├── auth.py                     ← Authentication and credential validation
│   │   ├── injection.py                ← Tool definition prompt injection detection
│   │   ├── supply_chain.py             ← Package and dependency integrity checks
│   │   └── privilege.py                ← Tool permission scope analysis
│   ├── monitor/                        ← Runtime monitoring
│   │   ├── agent.py                    ← Main monitoring facade (before/after API)
│   │   ├── detector.py                 ← Behavioral anomaly detection
│   │   ├── enforcer.py                 ← Policy-based allow/block/alert decisions
│   │   └── logger.py                   ← Tamper-evident hash-chained audit trail
│   ├── reporter/                       ← Report output formats
│   │   ├── console.py                  ← Rich terminal output
│   │   ├── html.py                     ← Self-contained HTML security report
│   │   └── json_report.py              ← JSON report serialization
│   └── models/                         ← Data models
│       ├── config.py                   ← MCP config parser (3 formats)
│       └── findings.py                 ← Finding, ScanResult, Severity, Category
│
├── tests/                             ← Test suite
│   ├── test_mcpshield.py
│   └── fixtures/
│       ├── vulnerable_mcp_config.json
│       └── secure_mcp_config.json
│
├── hardening/                         ← Hardening guides & templates
│   ├── HARDENING_CHECKLIST.md          ← 50-point security checklist
│   ├── config_templates/
│   └── remediation_playbooks/
│
├── redteam/                           ← Attack scenarios
│   ├── ATTACK_SCENARIOS.md
│   └── payloads/
│
└── pyproject.toml
```

---

## Quick Start

### Requirements
- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/Nullvora/MCPShield.git
cd MCPShield
pip install -r requirements.txt
```

### Running a Scan

```bash
# Scan a local MCP server
python scanner/mcp_scanner.py --target localhost:3000 --transport stdio

# Scan an HTTP-based MCP server and generate an HTML report
python scanner/mcp_scanner.py --target https://your-mcp-server.com --report html --output ./reports/

# Full assessment with supply chain checks
python scanner/mcp_scanner.py --target localhost:3000 --full --supply-chain
```

### Starting the Runtime Monitor

```bash
# Start monitoring with default policy
python monitor/agent_monitor.py --config ./monitor/alert_rules/ --log ./audit/

# Monitor with strict policy enforcement (blocking mode)
python monitor/agent_monitor.py --mode enforce --policy ./monitor/alert_rules/
```

---

## Scanner Output: Example

```
MCPShield v0.1.0 — Security Assessment Report
Target: localhost:3000
Date: 2026-05-30

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CRITICAL   [T1.1] STDIO transport permits OS command execution
           CVE-2025-49596 / CVE-2026-22252 applicable
           Affected: Python SDK transport layer
           Remediation: PB-001-transport-hardening.md

HIGH       [T2.1] No client authentication configured
           492 known exposed instances share this profile
           Remediation: PB-002-auth-implementation.md

HIGH       [T3.2] Tool definition contains unvalidated prompt interpolation
           Vector: weather_tool response → agent instruction injection
           Remediation: PB-003-injection-prevention.md

MEDIUM     [T4.1] 2 dependencies without integrity hashes (supply chain risk)
           Remediation: PB-004-supply-chain-controls.md

LOW        [T2.3] Tool scopes broader than documented use case requires
           Principle of least privilege not enforced

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RISK SCORE: 78 / 100  ⚠ HIGH RISK
OWASP ASI Coverage: ASI02, ASI03, ASI04, ASI05
Full report: ./reports/mcpshield_2026-05-30.html
```

---

## Roadmap

| Phase | Target | Status |
|---|---|---|
| **v0.1** | Threat model, repository structure, hardening checklist | 🔄 In Progress |
| **v0.2** | Scanner — transport and auth modules | 📋 Planned |
| **v0.3** | Scanner — injection detection and supply chain modules | 📋 Planned |
| **v0.4** | Runtime monitor and audit logger | 📋 Planned |
| **v0.5** | Red team toolkit and attack scenarios | 📋 Planned |
| **v1.0** | Full release with report dashboard | 📋 Planned |
| **v2.0** | MCPShield Pro — SaaS monitoring dashboard | 🔭 Future |

---

## Why MCPShield Exists

Existing agentic AI security frameworks (OWASP ASI, CSA ATF, Microsoft Agent Governance Toolkit) define the threat landscape at an architectural level. They answer the question *"what are the risks?"*

MCPShield answers the question *"is my specific MCP deployment vulnerable, and how do I fix it?"*

The framework was built because the gap between published security guidance and operational tooling is exactly where enterprises get compromised — not from unknown threats, but from known vulnerabilities left undetected and unremediated.

---

## Contributing

Contributions are welcome from security researchers, practitioners, and developers. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas actively seeking contributions:
- Additional scanner detection modules
- Framework-specific integrations (LangChain, LangGraph, CrewAI, AutoGen)
- New attack scenario documentation
- Translations of hardening guides

---

## Citing MCPShield

If you reference MCPShield in research or professional publications:

```
Boamah, J. (2026). MCPShield: A Security Assessment and Hardening Framework
for Model Context Protocol Deployments. https://github.com/Nullvora/MCPShield
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**James Boamah**
Cybersecurity Consultant | AI Security Specialist | MCP Security Researcher

- LinkedIn: [linkedin.com/in/james-boamah-986b51175](https://www.linkedin.com/in/james-boamah-986b51175)
- Email: [kwasiaffi@gmail.com]

---

> *"The attack surface is new. The principles are not. MCPShield makes them operational."*
