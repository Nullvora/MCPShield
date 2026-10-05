# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nullvora Inc.
"""Tamper-evident audit log (JSON Lines, SHA-256 hash chain, optional HMAC-SHA256 signatures).

Each record carries ``prev`` (hash of the previous record) and ``hash`` (hash of this record's canonical
form). Editing or removing interior records breaks the chain; tail truncation needs an external checkpoint. When ``MCPSHIELD_AUDIT_KEY`` is set,
records are additionally HMAC-signed so an attacker who can rewrite the whole file cannot forge a valid chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    body = {k: v for k, v in record.items() if k not in ("hash", "sig")}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class AuditLog:
    def __init__(self, path: str | Path, key: Optional[bytes] = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        env_key = os.environ.get("MCPSHIELD_AUDIT_KEY")
        self.key = key if key is not None else (env_key.encode() if env_key else None)
        self._lock = threading.Lock()
        self._prev = self._last_hash()
        self._seq = self._count()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = None
        with self.path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if not last:
            return GENESIS
        try:
            return json.loads(last)["hash"]
        except (json.JSONDecodeError, KeyError):
            return GENESIS

    def _count(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("rb") as fh:
            return sum(1 for line in fh if line.strip())

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            record: dict[str, Any] = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "event": event,
                **fields,
                "prev": self._prev,
            }
            digest = hashlib.sha256(_canonical(record)).hexdigest()
            record["hash"] = digest
            if self.key:
                record["sig"] = hmac.new(self.key, digest.encode(), hashlib.sha256).hexdigest()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._prev = digest
            self._seq += 1
            return record


def verify(path: str | Path, key: Optional[bytes] = None) -> tuple[bool, list[str], int]:
    """Verify a log file. Returns (ok, problems, records_checked)."""
    env_key = os.environ.get("MCPSHIELD_AUDIT_KEY")
    key = key if key is not None else (env_key.encode() if env_key else None)
    problems: list[str] = []
    prev = GENESIS
    n = 0
    with Path(path).open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            n += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"line {lineno}: not valid JSON")
                prev = "?"
                continue
            if not isinstance(rec, dict):
                problems.append(f"line {lineno}: record must be an object")
                prev = "?"
                continue
            if rec.get("seq") != n - 1:
                problems.append(f"line {lineno}: sequence mismatch")
            if rec.get("prev") != prev:
                problems.append(f"line {lineno}: chain broken (prev hash mismatch — record inserted, removed or reordered)")
            digest = hashlib.sha256(_canonical(rec)).hexdigest()
            if digest != rec.get("hash"):
                problems.append(f"line {lineno}: content hash mismatch (record modified)")
            if key:
                expected = hmac.new(key, str(rec.get("hash", "")).encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, str(rec.get("sig", ""))):
                    problems.append(f"line {lineno}: invalid HMAC signature")
            prev = rec.get("hash", "?")
    return (not problems), problems, n
