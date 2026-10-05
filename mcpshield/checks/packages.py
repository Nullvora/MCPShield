# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Identify the packages / images an MCP server launch command pulls in, and match advisories."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import PurePath
from typing import Any, Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class PackageRef:
    ecosystem: str            # npm | pypi | docker | url
    name: str
    version: Optional[str]    # exact pinned version, if any
    raw: str
    launcher: str

    @property
    def pinned(self) -> bool:
        if self.ecosystem == "docker":
            return "@sha256:" in self.raw
        return bool(self.version) and self.version not in ("latest", "next", "*")


_NPM_LAUNCHERS = {"npx", "bunx", "pnpx"}
_NPM_SUBCMD = {("npm", "exec"), ("pnpm", "dlx"), ("yarn", "dlx"), ("bun", "x"), ("pnpm", "exec")}
_PY_LAUNCHERS = {"uvx", "pipx"}


def _exe(cmd: str) -> str:
    name = PurePath(cmd.replace("\\", "/")).name.lower()
    for suffix in (".cmd", ".exe", ".bat", ".ps1"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


def _split_npm(spec: str) -> tuple[str, Optional[str]]:
    if spec.startswith("@"):
        scope_rest = spec[1:]
        if "@" in scope_rest:
            name, ver = scope_rest.rsplit("@", 1)
            return "@" + name, ver or None
        return spec, None
    if "@" in spec:
        name, ver = spec.split("@", 1)
        return name, ver or None
    return spec, None


def _split_pypi(spec: str) -> tuple[str, Optional[str]]:
    m = re.match(r"^([A-Za-z0-9_.\-\[\]]+?)\s*(==|@)\s*([A-Za-z0-9_.+!-]+)$", spec)
    if m:
        return re.sub(r"\[.*\]", "", m.group(1)), m.group(3)
    m = re.match(r"^([A-Za-z0-9_.\-]+)(\[.*\])?", spec)
    return (m.group(1) if m else spec), None


def _is_url_spec(spec: str) -> bool:
    return bool(re.match(r"^(git\+|https?://|github:|gitlab:|bitbucket:|file:|\.{0,2}/)", spec)) or spec.endswith((".tgz", ".tar.gz", ".whl"))


def extract_packages(command: Optional[str], args: list[str]) -> list[PackageRef]:
    if not command:
        return []
    exe = _exe(command)
    argv = [str(a) for a in args]
    refs: list[PackageRef] = []

    # Shell wrappers: analyse the inner command line too.
    if exe in {"bash", "sh", "zsh", "cmd", "powershell", "pwsh"}:
        for i, a in enumerate(argv):
            if a.lower() in ("-c", "/c", "/k", "-command") and i + 1 < len(argv):
                inner = argv[i + 1].split()
                if inner:
                    refs += extract_packages(inner[0], inner[1:])
        return refs

    launcher = exe
    if exe in _NPM_LAUNCHERS or (exe, argv[0].lower() if argv else "") in _NPM_SUBCMD:
        rest = argv[1:] if exe not in _NPM_LAUNCHERS else argv
        explicit: list[str] = []
        i = 0
        positional: Optional[str] = None
        while i < len(rest):
            a = rest[i]
            if a in ("-p", "--package") and i + 1 < len(rest):
                explicit.append(rest[i + 1])
                i += 2
                continue
            if a.startswith("--package="):
                explicit.append(a.split("=", 1)[1])
            elif a == "--":
                if i + 1 < len(rest) and positional is None:
                    positional = rest[i + 1]
                break
            elif a.startswith("-"):
                pass
            elif positional is None:
                positional = a
                break
            i += 1
        specs = explicit or ([positional] if positional else [])
        for spec in specs:
            if _is_url_spec(spec):
                refs.append(PackageRef("url", spec, None, spec, launcher))
            else:
                name, ver = _split_npm(spec)
                refs.append(PackageRef("npm", name, ver, spec, launcher))
        return refs

    if exe in _PY_LAUNCHERS or (exe == "uv" and argv[:2] == ["tool", "run"]):
        rest = argv[2:] if exe == "uv" else (argv[1:] if exe == "pipx" and argv[:1] == ["run"] else argv)
        py_spec: Optional[str] = None
        from_spec: Optional[str] = None
        i = 0
        while i < len(rest):
            a = rest[i]
            if a in ("--from", "--spec") and i + 1 < len(rest):
                from_spec = rest[i + 1]
                i += 2
                continue
            if a in ("--with", "--python", "-p", "--index-url", "--extra-index-url", "--index") and i + 1 < len(rest):
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            py_spec = a
            break
        chosen = from_spec or py_spec
        if chosen:
            if _is_url_spec(chosen):
                refs.append(PackageRef("url", chosen, None, chosen, launcher))
            else:
                name, ver = _split_pypi(chosen)
                refs.append(PackageRef("pypi", name, ver, chosen, launcher))
        return refs

    if exe in {"docker", "podman", "nerdctl"} and argv[:1] == ["run"]:
        i = 1
        takes_value = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--net", "-u", "--user",
                       "-w", "--workdir", "--entrypoint", "--mount", "--env-file", "-l", "--label", "--platform", "--cap-add",
                       "--cap-drop", "--security-opt", "-h", "--hostname", "--add-host", "--memory", "-m", "--cpus", "--pull"}
        while i < len(argv):
            a = argv[i]
            if a in takes_value:
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            name = a.split("@", 1)[0]
            tag = None
            last = name.rsplit("/", 1)[-1]
            if ":" in last:
                name, tag = name.rsplit(":", 1)
            refs.append(PackageRef("docker", name, tag, a, launcher))
            break
    return refs


# --------------------------------------------------------------------------- advisory data


@lru_cache(maxsize=1)
def advisory_db() -> dict[str, Any]:
    text = resources.files("mcpshield.data").joinpath("advisories.json").read_text(encoding="utf-8")
    return json.loads(text)


@lru_cache(maxsize=1)
def known_packages() -> dict[str, list[str]]:
    text = resources.files("mcpshield.data").joinpath("known_packages.json").read_text(encoding="utf-8")
    data = json.loads(text)
    return {"npm": data.get("npm", []), "pypi": data.get("pypi", [])}


def _norm(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower()) if ecosystem == "pypi" else name.lower()


def _parse_version(v: str) -> Optional[Version]:
    try:
        return Version(v.lstrip("v"))
    except InvalidVersion:
        return None


def matching_advisories(ref: PackageRef) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (affected, possibly_affected). ``possibly_affected`` is used when the version is not pinned."""
    affected: list[dict[str, Any]] = []
    possibly: list[dict[str, Any]] = []
    for adv in advisory_db()["advisories"]:
        if adv["ecosystem"] != ref.ecosystem or _norm(ref.ecosystem, adv["package"]) != _norm(ref.ecosystem, ref.name):
            continue
        ver = _parse_version(ref.version) if ref.pinned and ref.version else None
        if ver is None:
            possibly.append(adv)
            continue
        try:
            if ver in SpecifierSet(adv["affected"], prereleases=True):
                affected.append(adv)
        except InvalidSpecifier:  # pragma: no cover - data error
            continue
    return affected, possibly


def malicious_match(ref: PackageRef) -> Optional[dict[str, Any]]:
    for entry in advisory_db().get("malicious", []):
        if entry["ecosystem"] == ref.ecosystem and _norm(ref.ecosystem, entry["package"]) == _norm(ref.ecosystem, ref.name):
            versions = entry.get("versions", "*")
            if versions == "*" or (ref.version and ref.version in versions.split(",")):
                return entry
    return None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat_of(ref: PackageRef) -> Optional[str]:
    if ref.ecosystem not in ("npm", "pypi"):
        return None
    name = _norm(ref.ecosystem, ref.name)
    for known in known_packages().get(ref.ecosystem, []):
        k = _norm(ref.ecosystem, known)
        if name == k:
            return None
    for known in known_packages().get(ref.ecosystem, []):
        k = _norm(ref.ecosystem, known)
        if k.startswith("@") and not name.startswith("@") and name == k.split("/", 1)[1] and name.startswith("server-"):
            return known  # unscoped copy of an official scoped package
        if abs(len(k) - len(name)) > 2 or len(k) < 6:
            continue
        if name.startswith("@") and k.startswith("@") and name.split("/", 1)[0] == k.split("/", 1)[0]:
            continue  # same npm scope == same publisher; not a squat
        d = _levenshtein(name, k)
        if 0 < d <= (1 if len(k) < 10 else 2):
            return known
    return None
