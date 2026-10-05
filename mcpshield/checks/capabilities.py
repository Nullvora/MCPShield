# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Heuristic capability classification for servers (from config) and tools (from live definitions).

Used to detect toxic flows — the combination of private-data access, untrusted-content ingestion and an
external communication channel in the same agent ("lethal trifecta").
"""

from __future__ import annotations

import re
from typing import Any
from collections.abc import Iterable

PRIVATE = "private_data"
UNTRUSTED = "untrusted_content"
EXTERNAL = "external_comm"
EXEC = "code_exec"
DESTRUCTIVE = "destructive"

CAP_LABELS = {
    PRIVATE: "reads private data",
    UNTRUSTED: "ingests untrusted content",
    EXTERNAL: "communicates externally",
    EXEC: "executes code",
    DESTRUCTIVE: "modifies or deletes data",
}

_SERVER_KEYWORDS: list[tuple[re.Pattern[str], set[str]]] = [
    (re.compile(r"filesystem|file-?system|\bfs\b|files?-server"), {PRIVATE, DESTRUCTIVE}),
    (re.compile(r"github|gitlab|bitbucket|gitea"), {PRIVATE, UNTRUSTED, EXTERNAL}),
    (re.compile(r"\bgit\b|server-git|mcp-server-git"), {PRIVATE, DESTRUCTIVE}),
    (re.compile(r"gmail|e-?mail|outlook|imap|smtp|postmark|sendgrid|mailgun|resend"), {PRIVATE, UNTRUSTED, EXTERNAL}),
    (re.compile(r"slack|discord|teams|telegram|whatsapp|signal|matrix"), {PRIVATE, UNTRUSTED, EXTERNAL}),
    (re.compile(r"fetch|browser|puppeteer|playwright|chrome|brave|tavily|exa|firecrawl|search|scrap|crawl|web"), {UNTRUSTED, EXTERNAL}),
    (re.compile(r"postgres|mysql|sqlite|mssql|oracle|database|\bdb\b|supabase|mongo|redis|snowflake|bigquery|clickhouse"), {PRIVATE, DESTRUCTIVE}),
    (re.compile(r"notion|gdrive|google-?drive|confluence|jira|atlassian|linear|asana|sharepoint|onedrive|dropbox|box"), {PRIVATE, UNTRUSTED}),
    (re.compile(r"memory|knowledge|calendar|contacts"), {PRIVATE}),
    (re.compile(r"shell|terminal|exec|command|code-?runner|desktop-?commander|sandbox|jupyter|python-?repl"), {EXEC, PRIVATE, EXTERNAL}),
    (re.compile(r"kubernetes|k8s|kubectl|aws|azure|gcp|cloudflare|terraform|docker"), {PRIVATE, DESTRUCTIVE, EXTERNAL}),
    (re.compile(r"stripe|paypal|payment|wallet|crypto|thirdweb"), {PRIVATE, EXTERNAL, DESTRUCTIVE}),
]


def server_capabilities(name: str, command_line: Iterable[str], url: str | None = None) -> set[str]:
    blob = " ".join([name, *command_line, url or ""]).lower()
    caps: set[str] = set()
    for rx, c in _SERVER_KEYWORDS:
        if rx.search(blob):
            caps |= c
    return caps


_TOOL_RULES: list[tuple[str, re.Pattern[str]]] = [
    (EXEC, re.compile(r"(^|[_\-\s.])(exec(ute)?|run[_\-]?(command|cmd|code|script|shell)|shell|terminal|bash|eval|spawn|subprocess|powershell)([_\-\s.]|$)")),
    (EXTERNAL, re.compile(r"(^|[_\-\s.])(send|post|publish|upload|reply|forward|notify|webhook|tweet|comment|message|email|mail|share|invite|http[_\-]?request|request|fetch|download|call[_\-]?api|create[_\-]?(issue|pr|pull[_\-]?request|message|comment))([_\-\s.]|s\b|$)")),
    (UNTRUSTED, re.compile(r"(^|[_\-\s.])(fetch|browse|navigate|scrape|crawl|web|url|urls|read[_\-]?(email|mail|message|inbox|issue|url|page)|get[_\-]?(issue|message|email|page|comments?|webpage)|list[_\-]?(messages|emails|issues|comments)|inbox|search[_\-]?(web|issues|code|repos|repositories|internet|news|emails?|messages)|web[_\-]?search|google|bing|browser)([_\-\s.]|s\b|$)")),
    (PRIVATE, re.compile(r"(^|[_\-\s.])(read[_\-]?file|get[_\-]?file|file|files|directory|list[_\-]?dir|query|sql|select|database|db|memory|calendar|contacts?|secret|credential|password|vault|drive|document|repo|repository|inbox|email|messages?|history|customer|account|record)([_\-\s.]|s\b|$)")),
    (DESTRUCTIVE, re.compile(r"(^|[_\-\s.])(delete|remove|drop|truncate|write|update|overwrite|kill|destroy|rm|move|rename|edit|patch|insert|create|set|transfer|pay|merge|push|deploy)([_\-\s.]|s\b|$)")),
]


def tool_capabilities(tool: dict[str, Any]) -> set[str]:
    name = str(tool.get("name", ""))
    desc = str(tool.get("description", ""))[:600]
    # Normalise camelCase so 'readFile' matches 'read_file'
    name_n = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    blob = f"{name_n} {desc.lower()}"
    caps: set[str] = set()
    for cap, rx in _TOOL_RULES:
        target = blob if cap == PRIVATE else name_n
        if rx.search(target):
            caps.add(cap)
    ann = tool.get("annotations") or {}
    if isinstance(ann, dict):
        if ann.get("openWorldHint") is True:
            caps |= {UNTRUSTED}
        if ann.get("destructiveHint") is True:
            caps.add(DESTRUCTIVE)
    if EXEC in caps:
        caps |= {PRIVATE, EXTERNAL}
    return caps


def is_trifecta(caps: set[str]) -> bool:
    return {PRIVATE, UNTRUSTED, EXTERNAL} <= caps
