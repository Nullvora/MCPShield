"""
MCPShield Monitor — Audit Logger
Produces tamper-evident, structured audit trails of all MCP tool calls.
Each log entry is chained via SHA-256 so any deletion or modification is detectable.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    """
    Append-only, hash-chained audit log for MCP tool calls.

    Each entry contains:
      - sequence number
      - UTC timestamp
      - agent id
      - tool name + parameters (sanitised)
      - result summary
      - previous entry hash (chain link)
      - current entry hash

    This structure means any attempt to delete, modify, or reorder entries
    will break the hash chain, providing tamper evidence.
    """

    def __init__(self, log_path: str, redact_values: bool = True) -> None:
        self.log_path     = Path(log_path)
        self.redact_values = redact_values
        self._lock         = threading.Lock()
        self._seq          = 0
        self._last_hash    = "0" * 64  # genesis hash

        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Resume chain if log file exists
        if self.log_path.exists():
            self._resume_chain()

    # ── Public API ────────────────────────────────────────────────────────────

    def log_tool_call(
        self,
        agent_id:   str,
        server:     str,
        tool:       str,
        parameters: dict,
        result:     dict | str | None = None,
        policy_action: str = "allow",
        anomaly_flags: list[str] | None = None,
    ) -> dict:
        """
        Record a single MCP tool call.
        Returns the log entry dict.
        """
        with self._lock:
            self._seq += 1
            entry = {
                "seq":           self._seq,
                "timestamp":     datetime.now(timezone.utc).isoformat(),
                "agent_id":      agent_id,
                "server":        server,
                "tool":          tool,
                "parameters":    self._sanitise(parameters) if self.redact_values else parameters,
                "result_summary": self._summarise_result(result),
                "policy_action": policy_action,
                "anomaly_flags": anomaly_flags or [],
                "prev_hash":     self._last_hash,
            }
            entry["hash"] = self._hash_entry(entry)
            self._last_hash = entry["hash"]

            self._append(entry)
            return entry

    def log_anomaly(
        self,
        agent_id:    str,
        description: str,
        severity:    str,
        context:     dict | None = None,
    ) -> dict:
        """Record an anomaly event (not tied to a specific tool call)."""
        with self._lock:
            self._seq += 1
            entry = {
                "seq":         self._seq,
                "timestamp":   datetime.now(timezone.utc).isoformat(),
                "event_type":  "ANOMALY",
                "agent_id":    agent_id,
                "description": description,
                "severity":    severity,
                "context":     context or {},
                "prev_hash":   self._last_hash,
            }
            entry["hash"] = self._hash_entry(entry)
            self._last_hash = entry["hash"]

            self._append(entry)
            return entry

    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Verify the integrity of the entire audit log.
        Returns (is_intact, list_of_violations).
        """
        violations = []
        prev_hash  = "0" * 64
        entries    = self._read_all()

        for i, entry in enumerate(entries):
            stored_hash  = entry.pop("hash", None)
            computed_hash = self._hash_entry(entry)

            if stored_hash != computed_hash:
                violations.append(
                    f"Entry {i+1} (seq={entry.get('seq')}): hash mismatch — entry was modified"
                )

            if entry.get("prev_hash") != prev_hash:
                violations.append(
                    f"Entry {i+1} (seq={entry.get('seq')}): chain break — entry was inserted or deleted"
                )

            prev_hash = stored_hash or computed_hash

        return (len(violations) == 0, violations)

    def tail(self, n: int = 20) -> list[dict]:
        """Return the last n entries without reading the entire file."""
        if not self.log_path.exists():
            return []
        lines: list[str] = []
        with open(self.log_path, encoding="utf-8") as fh:
            # Seek to near the end and read backwards
            try:
                fh.seek(0, 2)
                file_size = fh.tell()
                # Read in chunks from the end
                chunk_size = 8192
                pos = max(0, file_size - chunk_size * n)
                fh.seek(pos)
                raw = fh.read()
                lines = [l for l in raw.strip().split("\n") if l]
            except OSError:
                lines = []
        # Parse the last n valid entries
        entries = []
        for line in reversed(lines):
            if len(entries) >= n:
                break
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        entries.reverse()
        return entries

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _append(self, entry: dict) -> None:
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def _read_all(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        entries = []
        with open(self.log_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return entries

    def _resume_chain(self) -> None:
        entries = self._read_all()
        if entries:
            last = entries[-1]
            self._seq       = last.get("seq", 0)
            self._last_hash = last.get("hash", "0" * 64)

    @staticmethod
    def _hash_entry(entry: dict) -> str:
        serialised = json.dumps(entry, sort_keys=True, default=str)
        return hashlib.sha256(serialised.encode()).hexdigest()

    _SENSITIVE_KEY_RE = re.compile(
        r"(?i)(password|secret|token|key|credential|auth|api)",
    )

    @staticmethod
    def _sanitise(params: dict) -> dict:
        """Redact values whose keys suggest sensitive content."""
        result = {}
        for k, v in params.items():
            if AuditLogger._SENSITIVE_KEY_RE.search(k):
                result[k] = "[REDACTED]"
            else:
                result[k] = v if not isinstance(v, str) or len(v) < 500 else v[:200] + "...[truncated]"
        return result

    @staticmethod
    def _summarise_result(result) -> str:
        if result is None:
            return "(none)"
        s = str(result)
        return s[:300] + "...[truncated]" if len(s) > 300 else s
