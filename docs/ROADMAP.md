# Product direction

## Positioning

MCPShield helps developers and small security teams inspect MCP configurations,
understand risky tool capabilities, and add an optional stdio policy guard.
Lead with a fast local scan and actionable remediation. Keep the scanner and
rule tests usable offline under the existing Apache-2.0 license.

## First 30 days after an approved public beta

| Period | Work | Evidence to collect | Decision |
|---|---|---|---|
| Week 1 | Publish source beta, run hosted CI, enable issue forms and private security reports; invite 5–10 willing testers | Install success, time to first scan, setup blockers | Fix installation issues before broader promotion |
| Week 2 | Triage false positives and missed findings; add sanitized regression fixtures | Rule-level reproductions, severity agreement, repeat use | Prioritize noisy or misleading high-severity rules |
| Week 3 | Address protocol boundaries and live-probe isolation; document client compatibility | SDK/client matrix, negative tests, p50/p95 latency overhead | Decide which guard behaviors are supportable |
| Week 4 | Publish measured results and a patch release; interview active testers | Repeat use, unresolved failures, requests shared by at least 3 testers | Select next release scope from evidence |

Suggested beta targets (not achieved results): at least 5 independent testers,
4 successful installations, median first useful scan under 10 minutes, and a
reproduction attached to every confirmed detection defect. These are learning
goals, not statistical claims about accuracy.

## Engineering priorities

1. **P0 before recommending hostile-server live scans:** bind DNS validation to
   the actual metadata connection or provide a demonstrably isolated fetcher;
   add DNS rebinding and cross-origin credential-leak tests.
2. **P0 before recommending production enforcement:** formal transport validation,
   bounded session state/timeouts, full paginated tool-refresh state, deterministic
   handling of malformed responses, process-tree lifecycle tests, and fuzzing.
3. **P1:** a versioned benign/adversarial corpus with precision/recall reporting;
   independent advisory provenance and update process; SDK/client version matrix.
4. **P1:** audit checkpoints to an independent sink, documented key lifecycle,
   and privacy tests for every report and telemetry field.
5. **P1:** immutable action/dependency references and dependency auditing before
   enabling registry publishing; repeatable release builds and artifact provenance.
6. **P2 only when requested repeatedly:** organization policy packs, centrally
   managed inventory, SIEM integrations and team reporting. Do not start a hosted
   dashboard merely to collect feedback; issues and optional local reports suffice.

A CLI core is appropriate at this stage. Keep protocol transport, policy decisions,
detection rules, and report/export code separate. Next, extract a typed, side-effect
free policy decision object and a dedicated session state machine from the guard;
let I/O wrappers handle process lifecycle and audit/export sinks. This makes
security reasoning and tests clearer without introducing microservices.
