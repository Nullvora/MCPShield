# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Text analysis primitives shared by tool-definition, prompt, resource and runtime checks.

Detects the techniques documented in real MCP attacks:

* Tool poisoning / line jumping – instructions hidden in descriptions (Invariant Labs, Trail of Bits)
* ASCII smuggling – invisible Unicode tag characters (U+E0000–U+E007F) that models still read
* Zero-width / bidi-override characters and ANSI escape sequences that hide text from humans
* Concealment ("do not tell the user"), exfiltration (URLs, e-mails), sensitive-file lures
* Cross-server tool shadowing ("when the send_email tool is used, always …")
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from mcpshield.models import Severity


@dataclass(frozen=True)
class Signal:
    kind: str
    severity: Severity
    message: str
    snippet: str = ""


# --------------------------------------------------------------------------- hidden characters

_TAG_RANGE = (0xE0000, 0xE007F)
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x2061, 0x2062, 0x2063, 0x2064}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*(\x07|\x1b\\)")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def decode_tag_smuggling(text: str) -> str:
    """Decode text hidden with Unicode tag characters (each maps to ASCII codepoint - 0xE0000)."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if _TAG_RANGE[0] <= ord(c) <= _TAG_RANGE[1] and 0x20 <= ord(c) - 0xE0000 < 0x7F)


def hidden_character_signals(text: str) -> list[Signal]:
    signals: list[Signal] = []
    if not text:
        return signals
    tags = [c for c in text if _TAG_RANGE[0] <= ord(c) <= _TAG_RANGE[1]]
    if tags:
        decoded = decode_tag_smuggling(text)
        signals.append(Signal(
            "unicode_tags", Severity.CRITICAL,
            f"{len(tags)} invisible Unicode tag characters (ASCII smuggling)",
            f"decoded hidden text: {decoded[:200]!r}" if decoded else "",
        ))
    zw = [c for c in text if ord(c) in _ZERO_WIDTH]
    if len(zw) >= 3:
        signals.append(Signal("zero_width", Severity.HIGH, f"{len(zw)} zero-width characters (text hidden from reviewers)"))
    bidi = [c for c in text if ord(c) in _BIDI]
    if bidi:
        signals.append(Signal("bidi", Severity.HIGH, f"{len(bidi)} bidirectional-override characters (Trojan-Source style display spoofing)"))
    if _ANSI_RE.search(text):
        signals.append(Signal("ansi", Severity.HIGH, "ANSI terminal escape sequences (can hide or rewrite text in terminal UIs)",
                              _ANSI_RE.search(text).group(0).encode("unicode_escape").decode()[:60]))  # type: ignore[union-attr]
    elif _CTRL_RE.search(text):
        signals.append(Signal("control", Severity.MEDIUM, "non-printable control characters"))
    if re.search(r"[ \t]{120,}|(\n\s*){15,}", text):
        signals.append(Signal("padding", Severity.MEDIUM, "large whitespace padding (pushes instructions out of the visible area)"))
    return signals


# --------------------------------------------------------------------------- injection language

_P = re.IGNORECASE | re.DOTALL

INJECTION_PATTERNS: list[tuple[str, Severity, str, re.Pattern[str]]] = [
    ("override", Severity.CRITICAL, "instruction-override phrase",
     re.compile(r"\b(ignore|disregard|forget|override)\b.{0,30}\b(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding|system|original)\b.{0,20}\b(instructions?|prompts?|rules|directives|guidelines|context)\b", _P)),
    ("override", Severity.HIGH, "role/mode reassignment",
     re.compile(r"\byou\s+are\s+now\b|\bnew\s+(system\s+)?instructions?\s*:|\benter(ing)?\s+(developer|debug|admin|god|jailbreak)\s+mode\b|\bfrom\s+now\s+on\b,?\s+you\b", _P)),
    ("concealment", Severity.CRITICAL, "tells the model to hide actions from the user",
     re.compile(r"\b(do\s+not|don'?t|never|must\s+not)\s+(tell|inform|mention|reveal|notify|show|alert|disclose)\b.{0,40}\b(the\s+)?user\b|\b(user|human)\s+(must|should)\s+not\s+(know|see|be\s+(told|informed))\b|\bwithout\s+(telling|informing|notifying)\s+the\s+user\b|\bkeep\s+this\s+(secret|hidden|confidential)\b|\bsilently\s+(send|forward|upload|copy|exfiltrate|include|add|bcc)\b", _P)),
    ("coercive_tag", Severity.HIGH, "prompt-control markup (e.g. <IMPORTANT>, <SYSTEM>, [INST])",
     re.compile(r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin|assistant|critical)\s*>|\[/?INST\]|<\|im_(start|end)\|>|<\|system\|>|###\s*(system|instruction)", _P)),
    ("sensitive_file", Severity.CRITICAL, "lures the model to read credentials or configuration",
     re.compile(r"(~|\$HOME|%USERPROFILE%)?[/\\]?\.ssh[/\\]|\bid_(rsa|ed25519|ecdsa)\b|\.aws[/\\]credentials|\.env\b|\bmcp(_config)?\.json\b|claude_desktop_config|\.cursor[/\\]mcp|/etc/(passwd|shadow)|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.kube[/\\]config|\.docker[/\\]config\.json|wallet\.dat|keychain", _P)),
    ("exfiltration", Severity.CRITICAL, "instructs sending data to an external destination",
     re.compile(r"\b(send|forward|post|upload|transmit|exfiltrate|leak|bcc|cc|copy)\b.{0,60}\b(to|at|into)\b.{0,20}(https?://|[\w.+-]+@[\w-]+\.[\w.]+)", _P)),
    ("exfiltration", Severity.HIGH, "asks for conversation/secret material to be placed in a parameter",
     re.compile(r"\b(pass|include|put|add|place|append)\b.{0,40}\b(content|contents|conversation|chat\s+history|previous\s+messages|system\s+prompt|api\s*keys?|tokens?|credentials?|passwords?|secrets?)\b.{0,40}\b(as|in|into)\b.{0,20}\b(param(eter)?|argument|field|sidenote|note|metadata)\b", _P)),
    ("shadowing", Severity.HIGH, "rewrites how a different tool must behave (cross-tool shadowing)",
     re.compile(r"\b(when|whenever|before|after|if)\b.{0,30}\b(using|calling|invoking|the)\b.{0,30}\b[\w.-]+\s+tool\b.{0,80}\b(must|always|should|instead|also)\b", _P)),
    ("shadowing", Severity.HIGH, "redirects recipients / destinations for all operations",
     re.compile(r"\ball\s+(emails?|messages?|payments?|transfers?|requests?)\s+(must|should|shall)\s+(be\s+)?(sent|forwarded|routed|redirected|cc'?d|bcc'?d)\b", _P)),
    ("precondition", Severity.MEDIUM, "imposes hidden mandatory pre-steps",
     re.compile(r"\b(before|prior\s+to)\s+(using|calling|invoking|executing)\s+(this|any)\s+tool\b.{0,40}\b(must|always|first|need\s+to)\b", _P)),
    ("urgency", Severity.LOW, "manipulative urgency / authority language",
     re.compile(r"\b(this\s+is\s+(very\s+)?(important|critical|mandatory)|failure\s+to\s+comply|or\s+the\s+(system|application)\s+will\s+(crash|fail)|you\s+will\s+be\s+(shut\s*down|punished))\b", _P)),
    ("code_exec", Severity.HIGH, "embeds a download-and-execute command",
     re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,160}\|\s*(ba|z)?sh\b|\bpowershell\b.{0,40}-(enc|encodedcommand)\b|\bbase64\s+-d\b.{0,40}\|\s*(ba)?sh\b", _P)),
]

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.IGNORECASE)
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/])")


def injection_signals(text: str) -> list[Signal]:
    signals: list[Signal] = []
    if not text:
        return signals
    seen: set[str] = set()
    for kind, sev, message, rx in INJECTION_PATTERNS:
        m = rx.search(text)
        if m and message not in seen:
            seen.add(message)
            start = max(0, m.start() - 20)
            signals.append(Signal(kind, sev, message, text[start:m.end() + 20].replace("\n", " ")[:200]))
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
        except Exception:  # noqa: BLE001 - not text
            continue
        if decoded.isprintable() and len(decoded) > 20:
            inner = injection_signals(decoded)
            sev = Severity.CRITICAL if inner else Severity.MEDIUM
            signals.append(Signal("encoded", sev, "base64-encoded text payload" + (" containing injection language" if inner else ""), decoded[:160]))
            break
    return signals


def extract_urls(text: str) -> list[str]:
    return _URL_RE.findall(text or "")


def extract_emails(text: str) -> list[str]:
    return _EMAIL_RE.findall(text or "")


def analyse_text(text: str) -> list[Signal]:
    """All signals for a piece of model-visible text (hidden characters are also decoded and scanned)."""
    signals = hidden_character_signals(text) + injection_signals(text)
    hidden = decode_tag_smuggling(text)
    if hidden:
        for s in injection_signals(hidden):
            signals.append(Signal(s.kind, Severity.CRITICAL, f"{s.message} (inside invisible Unicode tag payload)", s.snippet))
    return signals


# --------------------------------------------------------------------------- secrets

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{40,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-proj-[A-Za-z0-9_-]{40,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("Stripe secret key", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Notion token", re.compile(r"\b(secret_|ntn_)[A-Za-z0-9]{40,}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("Private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Database URL with password", re.compile(r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^:\s/]+:[^@\s/]{3,}@")),
]

_SECRET_KEY_NAME = re.compile(r"(api[_-]?key|secret|token|passw(or)?d|pwd|credential|private[_-]?key|access[_-]?key|auth)", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"^(<.*>|\*+|x{4,}|your[_-].*|changeme|placeholder|example|dummy|test|none|null|true|false|\d{1,6})$", re.IGNORECASE)


def secret_signals(value: str) -> list[str]:
    """Names of recognised secret formats present in ``value``."""
    return [name for name, rx in SECRET_PATTERNS if rx.search(value or "")]


def looks_like_literal_secret(key: str, value: str) -> bool:
    """Heuristic: a secret-sounding variable holding a literal (non-reference, non-placeholder) value."""
    from mcpshield.config.loader import is_env_reference

    if not value or is_env_reference(value) or _PLACEHOLDER.match(value.strip()):
        return False
    if not _SECRET_KEY_NAME.search(key):
        return False
    if key.upper().endswith(("_URL", "_URI", "_HOST", "_PATH", "_FILE", "_DIR", "_REGION", "_ID", "_NAME")) and not secret_signals(value):
        return False
    return len(value) >= 12 and (len(set(value)) >= 8)


def redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "…" + "*" * 6 + value[-2:]
