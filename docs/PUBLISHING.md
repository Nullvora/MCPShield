# Publish after owner review

Status: reviewed source candidate **1.1.1rc1**. The connected account has confirmed
access to **Nullvora/MCPShield**, currently private. The owner approved the eventual
public organization repository. Submit the update on a review branch and pull request;
retain the existing history and wait for owner review and required CI before merging
or launching publicly. CODEOWNERS is @jkboamah.

## Source beta

1. Review RELEASE_REVIEW.md and LIMITATIONS.md, the code diff and tests.
2. Confirm the Apache-2.0 license, attribution and legal entity names retained from
   the uploaded source. Confirm `security@nullvora.com` receives mail before
   announcing the security reporting policy.
3. Create an empty repository. Push the reviewed source without the uploaded
   `.git` directory. The deliverable intentionally excludes that history and
   local configuration; if updating an existing repository, use a new branch
   and pull request, never overwrite its history.
4. Run all hosted CI jobs and resolve failures. Require them on the default
   branch. Enable private vulnerability reporting and Discussions (optional).
5. Keep `MCPSHIELD_ENABLE_PUBLISH` unset for the initial source-only beta. Release
   tagging alone runs validation but does not publish packages by default.
6. Create a GitHub prerelease for `v1.1.1rc1` after CI passes, using the draft below.
   Add a brief demo and point testers at the Product feedback issue form.

Use the connected GitHub account or GitHub CLI browser authentication. Do not send
passwords, recovery codes or API tokens in chat, files, issues or commits. The
static scanner requires no product API key. Provision runtime secrets locally.

## Optional PyPI release later

Check package-name ownership first. Configure PyPI trusted publishing for the
approved owner, repository, `release.yml` and environment `pypi`. Protect the
GitHub environment with an approval requirement and release-tag restrictions.
Only then set repository variable `MCPSHIELD_ENABLE_PUBLISH=true`. The workflow
requires the reusable CI to pass, verifies the exact tag/package version, builds
and checks distributions, then publishes via OIDC and creates a draft GitHub
release. PyPI upload occurs before that draft; environment approval is therefore
the actual publication gate. Do not push a release tag casually after enabling it.

Container build validation exists in CI. Automatic GHCR publication is deferred;
there is no current claim that a hosted image is available.

References:
- https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-pypi
- https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository

## Release announcement draft (publish only after the repository exists)

I'm opening MCPShield for early feedback. It is a local MCP configuration scanner
with an optional stdio policy guard and agent activity reporting.

The first thing to try is the static scan: it checks for risky launch commands,
recognized secrets, unsafe configuration and package advisories without starting
your MCP servers. JSON, HTML and SARIF reports help turn findings into fixes.

This is a public beta. The runtime guard is defense in depth, not a sandbox, and
heuristic checks can miss attacks or flag legitimate content. Known limitations
and test results are documented in the repository.

I'd value feedback on installation, misleading findings and whether the result
helps you make a concrete change. Please use the feedback form and keep security
vulnerability reports private.

Proposed repository: https://github.com/Nullvora/MCPShield
