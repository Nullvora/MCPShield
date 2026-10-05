# MCPShield engineering review — 5 October 2026

## Decision

**Prepared for a source-only public beta after owner review and hosted CI.**
Version: **1.1.1rc1**, unpublished. Do not position it as production-grade
containment or a comprehensive prompt-injection prevention product.

The uploaded 1.1.0 has a useful modular foundation: config parsing, rule registry,
static/live scanning, structured findings, several report formats, and a separate
stdio guard with audit/OTLP. Keeping these as one Python package is appropriate.
The main architectural risk is that the guard combines parsing, state, policy,
subprocess management and observability. A typed decision engine and explicit
session state machine are the next refactor, after the beta feedback.

## Confirmed issues repaired

| Priority | Finding in uploaded code | Change |
|---|---|---|
| High | Parse and inspection errors could forward unchecked traffic | Withhold invalid messages and exceptions; reject batches, duplicate JSON keys/IDs, bad argument shapes; bound frame size and pending requests |
| High | Misspelled policy mode silently acted as monitor mode | Validate mode, structured fields, boolean/list types, limits and regexes before execution |
| High | Required pinning could operate without a lock; direct calls skipped definition verification | Require lock/server identity; lock-backed calls need inspected definitions; list changes invalidate them |
| High | Modern sampling requests bypassed the legacy deny check | Apply deny policy to `input_required` sampling requests |
| High | Audit signing key was inherited by the untrusted child | Strip that key from the child environment; document same-user limitations |
| Medium | Arguments were logged even when capture was off | Opt-in previews in audit and OTLP; omit launch arguments; owner-only new POSIX log files |
| Medium | Default shared log paths could corrupt chains across concurrent sessions | Unique default per-session filenames; document single-writer explicit paths |
| Medium | URL inspection checked only the first URL | Inspect all URLs, normalize trailing host dots, reject malformed and non-global literal destinations |
| Medium | Incomplete scans could report successful exit | Exit 2 for scan errors, including `--fail-on none`; propagate config parse errors |
| Medium | Monitor mode still changed results | Preserve valid result bytes in monitor mode |
| Medium | Telemetry buffers and child shutdown lacked bounds | Bound exporter queue; terminate/kill immediate child after grace periods |
| Release | Registry publication lacked a test gate; Windows failures were optional | Require reusable CI, exact tag/version and explicit publish enablement; make Windows required; add Docker build and legacy SDK jobs |
| Product | Privacy/safety/accuracy claims exceeded verified evidence | Document boundaries; remove unreproduced accuracy claims; provide local install/demo instructions |

## Validation performed

- Linux, Python 3.12, MCP SDK 2.3.0.
- **176 tests passed**, including **29 added regression cases**, **82% line coverage**.
- Ruff passed. Mypy passed for 33 source files; existing untyped CLI bodies are
  not comprehensively type checked by the current configuration.
- Wheel and source distribution built; both passed `twine check`.
- Wheel installed in an isolated environment and CLI/static secure-fixture scan
  ran from outside the repository. The final wheel was reinstalled after the last
  message-validation change.
- Secure-template self-scan and vulnerable-fixture report demo passed.
- Workflow/action/issue YAML parsed and `git diff --check` passed.
- A limited credential-pattern scan matched only deliberately synthetic test
  fixtures. It is not a guarantee that every possible secret format was found.
- Initial baseline: 144 passed, 3 failures caused by this environment's SOCKS proxy
  configuration. Local fixture tests now explicitly avoid inherited proxy settings.

See `VALIDATION.txt` for command output. No hosted Actions run, Docker execution,
Windows/macOS execution, dependency vulnerability audit, external accuracy study,
full historical-secret audit or independent penetration test was completed here.
Docker is unavailable in this environment. The supplied `.git` history is excluded
from the reviewed source archive; it has not been rewritten or pushed.

## Residual risks and launch conditions

Read [LIMITATIONS.md](LIMITATIONS.md). DNS rebinding remains a live metadata-fetch
risk. Runtime heuristics are not file/network containment. Unknown protocol surfaces,
log tail truncation, descendant processes and some state/resource limits still need
work. These constrain the claims and deployment guidance for the beta.

Before public launch, review license/attribution/contact details, run hosted CI,
and enable private vulnerability reporting. Registry publishing remains off by default.
On 5 October 2026, access to the private **Nullvora/MCPShield** repository was confirmed.
Its main branch contains an older implementation. The reviewed candidate is being
submitted on a separate branch for owner review, preserving existing commit history.
Public visibility is approved in principle, but merge and launch follow review and CI.

The 176-test results above are from the earlier local review, not a hosted CI result.
See the pull request checks for current cross-platform status. No package or image
has been published, and no external user feedback has been collected by this review.

## Way forward

Start with 5–10 willing beta testers and the static scan. Ask for installation
friction, time to a useful result, false positives/missed findings and repeat-use
intent. Triage feedback twice weekly and use reproducible reports to choose the
next changes. Build organizational features only after repeated demand.

Included:
- [FEEDBACK.md](FEEDBACK.md): tester instructions and issue process.
- [ROADMAP.md](ROADMAP.md): first 30 days, engineering priorities and evidence goals.
- [PUBLISHING.md](PUBLISHING.md): release checklist and announcement draft.
- `.github/ISSUE_TEMPLATE/product_feedback.yml`: structured feedback form.
- [CHANGELOG.md](../CHANGELOG.md): release candidate changes and behavior differences.
