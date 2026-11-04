"""Append-only JSONL log of injection attempts.

Stores a content hash and short snippets, never the full page, so the log is
safe to keep and share for analysis.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from pathlib import Path


class AttemptLogger:
    def __init__(self, path: str | Path, log_allowed: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.log_allowed = log_allowed
        self._lock = threading.Lock()

    def log(self, *, content: str, source: str | None, verdict: str, risk_score: float,
            findings: list, latency_ms: float) -> str | None:
        if verdict == "allow" and not self.log_allowed:
            return None
        event_id = uuid.uuid4().hex[:12]
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "id": event_id,
            "source": source,
            "sha256": hashlib.sha256(content.encode("utf-8", "replace")).hexdigest(),
            "verdict": verdict,
            "risk_score": risk_score,
            "latency_ms": round(latency_ms, 2),
            "findings": [
                {"rule_id": f.rule_id, "severity": f.severity.value,
                 "location": f.location, "snippet": f.snippet[:160]}
                for f in findings
            ],
        }
        line = json.dumps(record, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return event_id


def read_log(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]