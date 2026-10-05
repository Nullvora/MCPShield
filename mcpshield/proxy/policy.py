# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Runtime policy for ``mcpshield proxy``."""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from mcpshield.models import Severity

DEFAULT_DENY_PATHS = [
    "~/.ssh/**", "~/.aws/**", "~/.kube/**", "~/.docker/config.json", "~/.gnupg/**", "~/.config/gcloud/**",
    "~/.netrc", "~/.git-credentials", "~/.npmrc", "~/.pypirc", "**/.env", "**/.env.*", "/etc/shadow", "/etc/sudoers",
    "**/id_rsa", "**/id_ed25519", "**/claude_desktop_config.json", "**/.cursor/mcp.json", "**/.mcp.json",
]
DEFAULT_DENY_PATTERNS = [
    r"rm\s+-rf\s+(/|~|\$HOME)(\s|$)",
    r"\b(curl|wget)\b[^|;]*\|\s*(ba|z)?sh\b",
    r"\bmkfs(\.\w+)?\b",
    r":\(\)\s*\{\s*:\|:&\s*\};:",
    r"\bchmod\s+(-R\s+)?777\s+/",
    r"\bnc\b.*\s-e\s",
    r"/dev/tcp/",
]
METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata.azure.com", "100.100.100.200", "fd00:ec2::254"}


@dataclass
class Policy:
    mode: str = "enforce"                       # enforce | monitor
    block_severity: Severity = Severity.HIGH    # hide tools whose definitions have findings at/above this
    deny_tools: list[str] = field(default_factory=list)
    allow_tools: list[str] = field(default_factory=list)
    require_pinned: bool = False
    deny_paths: list[str] = field(default_factory=lambda: list(DEFAULT_DENY_PATHS))
    deny_url_private: bool = True
    deny_hosts: list[str] = field(default_factory=lambda: sorted(METADATA_HOSTS))
    deny_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_DENY_PATTERNS))
    max_argument_bytes: int = 200_000
    redact_secrets: bool = True
    block_injected_results: bool = False
    rate_default_per_minute: int = 120
    rate_per_tool: dict[str, int] = field(default_factory=dict)
    allow_sampling: bool = False
    _calls: dict[str, deque] = field(default_factory=lambda: defaultdict(deque), repr=False)

    @property
    def enforce(self) -> bool:
        return self.mode == "enforce"

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        if not isinstance(data, dict):
            raise ValueError("policy must be a mapping")
        for section in ("tools", "arguments", "results", "rate_limits"):
            if section in data and not isinstance(data[section], dict):
                raise ValueError(f"policy {section} must be a mapping")
        for section, keys in {"tools": ("require_pinned",), "arguments": ("deny_private_networks", "extend_defaults"),
                              "results": ("redact_secrets", "block_injection")}.items():
            for key in keys:
                if key in data.get(section, {}) and not isinstance(data[section][key], bool):
                    raise ValueError(f"{section}.{key} must be a boolean")
        for section, keys in {"tools": ("allow", "deny"), "arguments": ("deny_paths", "deny_hosts", "deny_patterns")}.items():
            for key in keys:
                value = data.get(section, {}).get(key, [])
                if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                    raise ValueError(f"{section}.{key} must be a list of strings")
        p = cls()
        p.mode = str(data.get("mode", p.mode)).lower()
        if p.mode not in ("enforce", "monitor"):
            raise ValueError("policy mode must be enforce or monitor")
        if str(data.get("sampling", "deny")).lower() not in ("allow", "deny"):
            raise ValueError("sampling must be allow or deny")
        if "block_severity" in data:
            p.block_severity = Severity.parse(str(data["block_severity"]))
        tools = data.get("tools") or {}
        p.deny_tools = list(tools.get("deny", p.deny_tools))
        p.allow_tools = list(tools.get("allow", p.allow_tools))
        p.require_pinned = bool(tools.get("require_pinned", p.require_pinned))
        args = data.get("arguments") or {}
        if "deny_paths" in args:
            p.deny_paths = list(args["deny_paths"]) + (list(DEFAULT_DENY_PATHS) if args.get("extend_defaults", True) else [])
        if "deny_hosts" in args:
            p.deny_hosts = sorted(set(args["deny_hosts"]) | METADATA_HOSTS)
        p.deny_url_private = bool(args.get("deny_private_networks", p.deny_url_private))
        if "deny_patterns" in args:
            p.deny_patterns = list(args["deny_patterns"]) + (list(DEFAULT_DENY_PATTERNS) if args.get("extend_defaults", True) else [])
        p.max_argument_bytes = int(args.get("max_bytes", p.max_argument_bytes))
        res = data.get("results") or {}
        p.redact_secrets = bool(res.get("redact_secrets", p.redact_secrets))
        p.block_injected_results = bool(res.get("block_injection", p.block_injected_results))
        rl = data.get("rate_limits") or {}
        p.rate_default_per_minute = int(rl.get("default_per_minute", p.rate_default_per_minute))
        p.rate_per_tool = {str(k): int(v) for k, v in (rl.get("per_tool") or {}).items()}
        p.allow_sampling = str(data.get("sampling", "deny")).lower() == "allow"
        if p.max_argument_bytes <= 0 or p.rate_default_per_minute < 0 or any(v < 0 for v in p.rate_per_tool.values()):
            raise ValueError("argument limit must be positive and rate limits nonnegative")
        for pattern in p.deny_patterns:
            re.compile(pattern)
        return p

    @classmethod
    def load(cls, path: Optional[str]) -> Policy:
        if not path:
            return cls()
        import yaml

        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        return cls.from_dict(data)

    # ------------------------------------------------------------------ decisions
    def tool_permitted(self, name: str) -> Optional[str]:
        if self.allow_tools and not any(fnmatch.fnmatchcase(name, pat) for pat in self.allow_tools):
            return f"tool '{name}' is not in tools.allow"
        for pat in self.deny_tools:
            if fnmatch.fnmatchcase(name, pat):
                return f"tool '{name}' matches tools.deny '{pat}'"
        return None

    def rate_limited(self, name: str, now: Optional[float] = None) -> Optional[str]:
        now = time.monotonic() if now is None else now
        limit = self.rate_per_tool.get(name, self.rate_default_per_minute)
        if limit <= 0:
            return None
        q = self._calls[name]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            return f"rate limit exceeded for '{name}' ({limit}/min)"
        q.append(now)
        return None

    def check_arguments(self, arguments: Any) -> list[str]:
        problems: list[str] = []
        import json

        blob = json.dumps(arguments, ensure_ascii=False)
        if len(blob.encode("utf-8")) > self.max_argument_bytes:
            problems.append(f"arguments exceed {self.max_argument_bytes} bytes")
        for s in _strings(arguments):
            problems += self._check_path(s)
            problems += self._check_url(s)
            for pat in self.deny_patterns:
                if re.search(pat, s, re.IGNORECASE):
                    problems.append(f"argument matches denied pattern /{pat}/")
        return sorted(set(problems))

    def _check_path(self, s: str) -> list[str]:
        if len(s) > 4096 or not re.search(r"[/\\~]|\.env", s):
            return []
        home = str(Path.home())
        candidates = {s, os.path.expanduser(s)}
        if s.startswith(home):
            candidates.add("~" + s[len(home):])
        norm = {os.path.normpath(c).replace("\\", "/") for c in candidates}
        for pat in self.deny_paths:
            for p in {pat, os.path.expanduser(pat).replace("\\", "/")}:
                for c in norm:
                    if _path_match(c, p):
                        return [f"path '{s[:120]}' matches denied path '{pat}'"]
        return []

    def _check_url(self, s: str) -> list[str]:
        problems: list[str] = []
        for match in re.finditer(r"\b(https?|ftp|gopher|file)://[^\s\"']+", s, re.I):
            try:
                u = urlparse(match.group(0))
                host = (u.hostname or "").lower().rstrip(".")
                _ = u.port
            except ValueError:
                problems.append("malformed URL in arguments")
                continue
            if u.scheme.lower() in ("file", "gopher"):
                problems.append(f"URL scheme '{u.scheme}' is not allowed")
            elif not host:
                problems.append("URL has no host")
            elif host in self.deny_hosts:
                problems.append(f"URL host '{host}' is denied (cloud metadata / denylist)")
            elif self.deny_url_private:
                try:
                    ip = ipaddress.ip_address(host)
                    if not ip.is_global or ip.is_multicast:
                        problems.append(f"URL targets non-public address {ip}")
                except ValueError:
                    if host == "localhost" or host.endswith((".localhost", ".internal", ".local")):
                        problems.append(f"URL targets internal host '{host}'")
        return problems


def _path_match(path: str, pattern: str) -> bool:
    if pattern.startswith("**/"):
        suffix = pattern[3:]
        return fnmatch.fnmatchcase(path, suffix) or fnmatch.fnmatchcase(path, "*/" + suffix)
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/")
    return fnmatch.fnmatchcase(path, pattern)


def _strings(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out += _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            out += _strings(v)
    return out


EXAMPLE_POLICY = """\
# MCPShield runtime policy — used by `mcpshield proxy --policy mcpshield-policy.yaml -- <server command>`
mode: enforce              # enforce = block; monitor = log only
block_severity: high       # hide tools whose *definitions* have findings at/above this severity

tools:
  deny: []                 # glob patterns, e.g. ["run_command", "delete_*"]
  allow: []                # if set, ONLY these tools are exposed
  require_pinned: false    # with --lock: hide tools not present/identical in the lock file

arguments:
  deny_paths: []           # added to built-in denials (~/.ssh/**, ~/.aws/**, **/.env, MCP configs, ...)
  deny_hosts: []           # added to built-in cloud-metadata hosts
  deny_private_networks: true
  deny_patterns: []        # regexes, added to built-ins (rm -rf /, curl|sh, /dev/tcp, ...)
  max_bytes: 200000

results:
  redact_secrets: true     # mask API keys/tokens/private keys in tool output before the model sees them
  block_injection: false   # replace tool output that contains prompt-injection language

rate_limits:
  default_per_minute: 120
  per_tool: {}             # e.g. {send_email: 5}

sampling: deny             # deny server-initiated LLM sampling requests
"""
