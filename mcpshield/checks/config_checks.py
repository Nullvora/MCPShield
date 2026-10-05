# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Static checks over MCP client configuration (no server is started)."""

from __future__ import annotations

import ipaddress
import os
import re
import stat
from pathlib import Path, PurePath
from typing import Any, Optional
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlparse

from mcpshield.checks import capabilities as caps
from mcpshield.checks.packages import extract_packages, malicious_match, matching_advisories, typosquat_of
from mcpshield.checks.registry import make
from mcpshield.checks.text import looks_like_literal_secret, redact, secret_signals
from mcpshield.config.loader import LoadedConfig, is_env_reference
from mcpshield.models import Finding, ServerSpec, Severity

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh"}
_TLS_OFF_ENV = {
    "NODE_TLS_REJECT_UNAUTHORIZED": {"0"},
    "PYTHONHTTPSVERIFY": {"0"},
    "CURL_INSECURE": {"1", "true"},
    "GIT_SSL_NO_VERIFY": {"1", "true"},
    "REQUESTS_CA_BUNDLE": {""},
}
_SENSITIVE_DIRS = re.compile(r"(^|[/\\])(\.ssh|\.aws|\.kube|\.docker|\.gnupg|\.azure|\.config[/\\]gcloud|\.password-store|Keychains)([/\\]|$)", re.I)
_URL_SECRET_PARAMS = re.compile(r"^(api[_-]?key|key|token|access[_-]?token|auth|secret|password|sig|signature|session(id)?|client[_-]?secret)$", re.I)


def _exe(cmd: Optional[str]) -> str:
    if not cmd:
        return ""
    name = PurePath(cmd.replace("\\", "/")).name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def is_loopback_host(host: Optional[str]) -> bool:
    if not host:
        return False
    if host.lower() in ("localhost", "localhost.localdomain") or host.lower().endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _loc(server: ServerSpec, suffix: str = "") -> str:
    base = server.source or "<config>"
    return f"{base}#{server.name}{('.' + suffix) if suffix else ''}"


# --------------------------------------------------------------------------- per-server checks


def check_secrets(server: ServerSpec) -> list[Finding]:
    out: list[Finding] = []
    for key, value in server.env.items():
        kinds = secret_signals(value)
        if kinds or looks_like_literal_secret(key, value):
            out.append(make("MCPS-SEC-001", server=server.name, location=_loc(server, f"env.{key}"),
                            evidence=f"{key}={redact(value)}" + (f"  (format: {', '.join(kinds)})" if kinds else ""),
                            severity=Severity.CRITICAL if kinds else None))
    argv = server.args
    for i, arg in enumerate(argv):
        kinds = secret_signals(arg)
        flag_secret = (
            i > 0 and re.match(r"^--?[\w-]*(token|key|secret|password|pass|pwd|auth)[\w-]*$", argv[i - 1], re.I)
            and not is_env_reference(arg) and len(arg) >= 8
        )
        inline = re.match(r"^--?[\w-]*(token|key|secret|password|pwd)[\w-]*=(.{8,})$", arg, re.I)
        if kinds or flag_secret or (inline and not is_env_reference(inline.group(2))):
            shown = arg if not (kinds or inline) else redact(arg)
            out.append(make("MCPS-SEC-002", server=server.name, location=_loc(server, f"args[{i}]"),
                            evidence=f"{argv[i - 1] + ' ' if flag_secret else ''}{redact(shown)}"))
    for key, value in server.headers.items():
        if is_env_reference(value):
            continue
        kinds = secret_signals(value)
        is_auth = key.lower() in ("authorization", "x-api-key", "api-key", "x-auth-token", "proxy-authorization", "cookie")
        if kinds or (is_auth and len(value.split()[-1]) >= 8):
            out.append(make("MCPS-SEC-003", server=server.name, location=_loc(server, f"headers.{key}"),
                            evidence=f"{key}: {redact(value, keep=10)}"))
    if server.url:
        u = urlparse(server.url)
        bad_params = [k for k, v in parse_qsl(u.query) if _URL_SECRET_PARAMS.match(k) and v and not is_env_reference(v)]
        if u.password or bad_params:
            out.append(make("MCPS-SEC-004", server=server.name, location=_loc(server, "url"),
                            evidence=("userinfo in URL" if u.password else "") + (f" query params: {', '.join(bad_params)}" if bad_params else "")))
    return out


def check_transport(server: ServerSpec) -> list[Finding]:
    out: list[Finding] = []
    if server.url:
        u = urlparse(server.url)
        if u.scheme in ("http", "ws") and not is_loopback_host(u.hostname):
            out.append(make("MCPS-TRN-001", server=server.name, location=_loc(server, "url"), evidence=server.url.split("?")[0]))
    if server.transport == "sse":
        out.append(make("MCPS-TRN-002", server=server.name, location=_loc(server), evidence=f"transport=sse url={server.url}"))

    joined = " ".join(server.args)
    if re.search(r"(--host|--bind|--listen|-H|--address)[= ]+(0\.0\.0\.0|::|\[::\]|\*)(\s|$|:)|\b0\.0\.0\.0:\d+", joined) or \
            any(server.env.get(k, "") in ("0.0.0.0", "::") for k in ("HOST", "BIND", "MCP_HOST", "FASTMCP_HOST", "LISTEN_ADDR")):
        out.append(make("MCPS-TRN-003", server=server.name, location=_loc(server), evidence=joined[:200] or "HOST=0.0.0.0"))

    for key, bad in _TLS_OFF_ENV.items():
        if key in server.env and server.env[key].strip().lower() in bad and key != "REQUESTS_CA_BUNDLE":
            out.append(make("MCPS-TRN-004", server=server.name, location=_loc(server, f"env.{key}"), evidence=f"{key}={server.env[key]}"))
    if re.search(r"(^|\s)(--insecure|--no-verify(-ssl)?|--disable-ssl-verification|--tls-skip-verify|--skip-tls-verify)(\s|=|$)", joined):
        out.append(make("MCPS-TRN-004", server=server.name, location=_loc(server, "args"), evidence=joined[:200]))
    return out


def check_execution(server: ServerSpec) -> list[Finding]:
    out: list[Finding] = []
    if server.transport != "stdio" or not server.command:
        return out
    exe = _exe(server.command)
    argv = server.args
    cmdline = " ".join([server.command, *argv])

    if exe in SHELLS and any(a.lower() in ("-c", "/c", "/k", "-command", "-encodedcommand", "-enc") for a in argv):
        out.append(make("MCPS-EXE-001", server=server.name, location=_loc(server, "command"), evidence=cmdline[:300]))
    if re.search(r"\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b.*\|\s*(ba|z|da)?sh\b|\|\s*(iex|Invoke-Expression)\b|"
                 r"base64\s+(-d|--decode).*\|\s*(ba)?sh|-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", cmdline, re.I):
        out.append(make("MCPS-EXE-002", server=server.name, location=_loc(server, "command"), evidence=cmdline[:300]))
    if exe in ("sudo", "doas", "runas", "pkexec", "gsudo") or re.search(r"(^|\s)sudo\s", cmdline):
        out.append(make("MCPS-EXE-003", server=server.name, location=_loc(server, "command"), evidence=cmdline[:200]))
    if exe in ("node", "deno", "bun") and any(a in ("-e", "--eval", "eval", "-p", "--print") for a in argv) or \
            exe.startswith("python") and "-c" in argv or exe in ("ruby", "perl", "php") and "-e" in argv:
        out.append(make("MCPS-EXE-005", server=server.name, location=_loc(server, "command"), evidence=cmdline[:200]))

    if exe in ("docker", "podman", "nerdctl"):
        issues: list[str] = []
        joined = " ".join(argv)
        if "--privileged" in argv:
            issues.append("--privileged")
        for flag in ("--network=host", "--net=host", "--pid=host", "--ipc=host", "--uts=host", "--userns=host"):
            if flag in joined or flag.replace("=", " ") in joined:
                issues.append(flag)
        if re.search(r"--cap-add[= ](ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|DAC_READ_SEARCH)", joined, re.I):
            issues.append("dangerous --cap-add")
        if "docker.sock" in joined:
            issues.append("Docker socket mounted")
        if re.search(r"(-v|--volume|--mount)[= ]+(type=bind,[^ ]*source=)?/(:|,|\s)", joined + " ") or re.search(r"(-v|--volume)[= ]+/:/", joined):
            issues.append("host root filesystem mounted")
        if re.search(r"(-u|--user)[= ]+(0|root)(\s|:|$)", joined + " "):
            issues.append("runs as root")
        if re.search(r"--security-opt[= ](seccomp|apparmor)[=:]unconfined", joined):
            issues.append("seccomp/apparmor disabled")
        if issues:
            out.append(make("MCPS-EXE-004", server=server.name, location=_loc(server, "args"), evidence=", ".join(issues)))
    return out


def check_supply_chain(server: ServerSpec) -> list[Finding]:
    out: list[Finding] = []
    if server.transport != "stdio":
        return out
    for ref in extract_packages(server.command, server.args):
        loc = _loc(server, "args")
        if ref.ecosystem == "url":
            out.append(make("MCPS-SUP-005", server=server.name, location=loc, evidence=ref.raw))
            continue
        bad = malicious_match(ref)
        if bad:
            out.append(make("MCPS-SUP-003", server=server.name, location=loc, evidence=f"{ref.ecosystem}:{ref.raw} — {bad['summary']}",
                            references=[bad["url"]]))
            continue
        squat = typosquat_of(ref)
        if squat:
            out.append(make("MCPS-SUP-004", server=server.name, location=loc, evidence=f"'{ref.name}' resembles '{squat}'"))
        affected, possibly = matching_advisories(ref)
        for adv in affected:
            out.append(make("MCPS-SUP-002", server=server.name, location=loc,
                            title=f"{adv['id']}: vulnerable {ref.name}@{ref.version}",
                            severity=Severity.parse(adv["severity"]),
                            evidence=f"{ref.name}@{ref.version} is in {adv['affected']} — {adv['summary']}" + (f" Fixed in {adv['fixed']}." if adv.get("fixed") else ""),
                            references=[adv["url"]]))
        if not ref.pinned:
            if possibly:
                ids = ", ".join(sorted({a["id"] for a in possibly}))
                fixed = max((a.get("fixed") or "" for a in possibly), key=lambda v: [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v or "0")])
                out.append(make("MCPS-SUP-006", server=server.name, location=loc,
                                evidence=f"{ref.name} (unpinned) has advisories: {ids}" + (f"; pin to >= {fixed}" if fixed else ""),
                                references=sorted({a["url"] for a in possibly})))
            else:
                tag = f":{ref.version}" if ref.ecosystem == "docker" and ref.version else ""
                out.append(make("MCPS-SUP-001", server=server.name, location=loc,
                                evidence=f"{ref.launcher} {ref.raw}{'' if tag or ref.ecosystem != 'docker' else ' (implicit :latest)'}"))
    return out


def check_privilege(server: ServerSpec) -> list[Finding]:
    out: list[Finding] = []
    if server.transport != "stdio":
        return out
    blob = " ".join([server.command or "", *server.args]).lower()
    home = str(Path.home())
    is_fs = bool(re.search(r"filesystem|file-?system|\bfs\b|desktop-?commander", blob)) or _exe(server.command) in ("docker", "podman")
    broad: list[str] = []
    for arg in server.args:
        a = arg.strip().rstrip("/\\") or "/"
        host_part = a.split(":", 1)[0] if _exe(server.command) in ("docker", "podman") and ":" in a and not re.match(r"^[A-Za-z]:\\", a) else a
        host_part = re.sub(r"^(type=bind,)?(source|src)=", "", host_part)
        if host_part in ("/", "~", "$HOME", "${HOME}", "%USERPROFILE%", home, "C:", "C:\\", "/Users", "/home", "/root") \
                or re.fullmatch(r"[A-Za-z]:\\?", host_part) or host_part in ("/Users/" + os.environ.get("USER", "_"),):
            broad.append(arg)
        if _SENSITIVE_DIRS.search(arg):
            out.append(make("MCPS-PRV-002", server=server.name, location=_loc(server, "args"), evidence=arg))
    if broad and is_fs:
        out.append(make("MCPS-PRV-001", server=server.name, location=_loc(server, "args"), evidence="scoped to: " + ", ".join(broad)))
    return out


def check_server(server: ServerSpec) -> list[Finding]:
    findings: list[Finding] = []
    for fn in (check_secrets, check_transport, check_execution, check_supply_chain, check_privilege):
        findings += fn(server)
    return findings


# --------------------------------------------------------------------------- multi-server / file-level


def check_toxic_combination(servers: list[ServerSpec]) -> list[Finding]:
    active = [s for s in servers if not s.disabled]
    by_cap: dict[str, list[str]] = {}
    for s in active:
        for c in caps.server_capabilities(s.name, s.command_line, s.url):
            by_cap.setdefault(c, []).append(s.name)
    if all(by_cap.get(c) for c in (caps.PRIVATE, caps.UNTRUSTED, caps.EXTERNAL)):
        ev = "; ".join(f"{caps.CAP_LABELS[c]}: {', '.join(sorted(set(by_cap[c])))}" for c in (caps.PRIVATE, caps.UNTRUSTED, caps.EXTERNAL))
        # Name-based inference only: medium. A live scan confirms with tool-level evidence (high).
        return [make("MCPS-PRV-003", server="*", location=active[0].source if active else "", evidence=ev + " (inferred from server names; confirm with --live)",
                     severity=Severity.MEDIUM)]
    return []


def check_duplicates(servers: list[ServerSpec]) -> list[Finding]:
    out: list[Finding] = []
    seen: dict[str, ServerSpec] = {}
    for s in servers:
        if s.name in seen:
            prev = seen[s.name]
            if (prev.command_line, prev.url) != (s.command_line, s.url) and prev.source != s.source:
                out.append(make("MCPS-SHD-002", server=s.name, location=f"{prev.source} vs {s.source}",
                                evidence=f"{' '.join(prev.command_line) or prev.url} ≠ {' '.join(s.command_line) or s.url}"))
        else:
            seen[s.name] = s
    return out


def check_allowlist(servers: list[ServerSpec], allowlist: dict[str, Any]) -> list[Finding]:
    """allowlist = {"servers": [names], "packages": [names], "urls": [prefixes], "commands": [exes]}"""
    names = {n.lower() for n in allowlist.get("servers", [])}
    pkgs = {p.lower() for p in allowlist.get("packages", [])}
    urls = [u.lower() for u in allowlist.get("urls", [])]
    cmds = {c.lower() for c in allowlist.get("commands", [])}
    out: list[Finding] = []
    for s in servers:
        ok = s.name.lower() in names
        if not ok and s.url:
            ok = any(s.url.lower().startswith(u) for u in urls)
        if not ok and s.command:
            refs = extract_packages(s.command, s.args)
            ok = bool(refs) and all(r.name.lower() in pkgs for r in refs)
            ok = ok or (_exe(s.command) in cmds)
        if not ok:
            out.append(make("MCPS-SHD-001", server=s.name, location=_loc(s), evidence=" ".join(s.command_line)[:200] or (s.url or "")))
    return out


def _walk(obj: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            yield p, v
            yield from _walk(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def check_agent_settings(cfg: LoadedConfig, project_scope: bool) -> list[Finding]:
    """Client/agent settings that weaken MCP consent (Claude Code, Gemini CLI, Cline, VS Code)."""
    out: list[Finding] = []
    data = cfg.data if isinstance(cfg.data, dict) else {}
    path = cfg.path
    sev_scope = None if project_scope else Severity.MEDIUM

    containers = [data] + [p for p in (data.get("projects") or {}).values() if isinstance(p, dict)] if isinstance(data.get("projects"), dict) else [data]
    for c in containers:
        if c.get("enableAllProjectMcpServers") is True:
            out.append(make("MCPS-AGT-001", location=f"{path}#enableAllProjectMcpServers", evidence="enableAllProjectMcpServers: true",
                            severity=sev_scope))
    hooks = data.get("hooks")
    if project_scope and isinstance(hooks, dict) and hooks:
        cmds = [str(v) for k, v in _walk(hooks) if k.endswith("command") and isinstance(v, str)]
        out.append(make("MCPS-AGT-002", location=f"{path}#hooks", evidence="; ".join(cmds)[:300] or f"events: {', '.join(hooks)}"))
    env: dict[str, Any] = data["env"] if isinstance(data.get("env"), dict) else {}
    for key in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE", "CLAUDE_CODE_API_BASE_URL", "GOOGLE_GEMINI_BASE_URL"):
        if key in env and project_scope:
            out.append(make("MCPS-AGT-003", location=f"{path}#env.{key}", evidence=f"{key}={env[key]}"))
    if project_scope and (data.get("apiKeyHelper")):
        out.append(make("MCPS-AGT-003", location=f"{path}#apiKeyHelper", evidence=f"apiKeyHelper={data['apiKeyHelper']}",
                        title="Project settings define an API key helper command"))

    auto: list[str] = []
    perms: dict[str, Any] = data["permissions"] if isinstance(data.get("permissions"), dict) else {}
    if perms.get("defaultMode") == "bypassPermissions":
        auto.append("permissions.defaultMode=bypassPermissions")
    for entry in perms.get("allow", []) or []:
        if isinstance(entry, str) and re.fullmatch(r"mcp__[\w-]+(__\*)?|mcp__\*|\*", entry):
            auto.append(f"permissions.allow '{entry}'")
    if data.get("chat.tools.autoApprove") is True or data.get("chat.tools.global.autoApprove") is True:
        auto.append("chat.tools.autoApprove=true")
    for s in cfg.servers:
        raw = s.raw
        if raw.get("trust") is True:
            auto.append(f"{s.name}: trust=true")
        for key in ("alwaysAllow", "autoApprove"):
            val = raw.get(key)
            if val:
                auto.append(f"{s.name}: {key}={val if isinstance(val, bool) else ','.join(map(str, val))[:80]}")
    if auto:
        out.append(make("MCPS-AGT-004", location=path, evidence="; ".join(auto)[:400]))
    return out


def check_file_permissions(cfg: LoadedConfig, findings_for_file: list[Finding]) -> list[Finding]:
    if os.name != "posix" or not any(f.rule_id in ("MCPS-SEC-001", "MCPS-SEC-003") for f in findings_for_file):
        return []
    try:
        mode = os.stat(cfg.path).st_mode
    except OSError:
        return []
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        return [make("MCPS-SEC-005", location=cfg.path, evidence=f"mode {oct(mode & 0o777)}")]
    return []


def check_config(cfg: LoadedConfig, project_scope: bool = False, allowlist: Optional[dict[str, Any]] = None) -> list[Finding]:
    findings: list[Finding] = []
    for err in cfg.errors:
        findings.append(make("MCPS-CFG-001", location=cfg.path, evidence=err))
    for s in cfg.servers:
        findings += check_server(s)
    findings += check_file_permissions(cfg, findings)
    findings += check_agent_settings(cfg, project_scope)
    if allowlist is not None:
        findings += check_allowlist(cfg.servers, allowlist)
    return findings
