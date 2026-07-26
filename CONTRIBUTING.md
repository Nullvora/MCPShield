# Contributing to MCPShield

Thank you for your interest in contributing. MCPShield is an open-source security project and we welcome contributions from the community.

## Getting Started

```bash
git clone https://github.com/Nullvora/MCPShield.git
cd MCPShield
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=mcpshield --cov-report=html
```

## Areas Seeking Contributions

- Additional scanner detection modules
- LangChain, LangGraph, CrewAI, AutoGen framework integrations
- New attack scenario documentation
- Live server scanning (HTTP/SSE mode — v0.2 target)
- Additional policy rule templates
- Translations of hardening guides

## Submission Guidelines

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Write tests for new functionality
4. Ensure all tests pass: `pytest tests/ -v`
5. Submit a Pull Request with a clear description

## Responsible Disclosure

To report a security vulnerability in MCPShield itself, email: security@nullvora.com
