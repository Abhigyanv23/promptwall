from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}

# Probability-style weights: risk = 1 - prod(1 - w).
SEVERITY_WEIGHT = {Severity.LOW: 0.15, Severity.MEDIUM: 0.45, Severity.HIGH: 0.8}

BLOCK_THRESHOLD = 0.8
SANITIZE_THRESHOLD = 0.4


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: Severity
    location: str  # "visible", "css:display-none", "html-comment", "attr:alt", ...
    snippet: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class HiddenSpan:
    reason: str
    text: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    visible_text: str = ""
    hidden_spans: list[HiddenSpan] = field(default_factory=list)

    @property
    def risk_score(self) -> float:
        # Each rule counts ONCE per page, at its highest severity. Without this,
        # a long page with many weak matches (e.g. 12 alt texts mentioning
        # "assistant") would compound toward "sanitize" on its own.
        worst: dict[str, Severity] = {}
        for f in self.findings:
            cur = worst.get(f.rule_id)
            if cur is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[cur]:
                worst[f.rule_id] = f.severity
        p_clean = 1.0
        for sev in worst.values():
            p_clean *= 1.0 - SEVERITY_WEIGHT[sev]
        return round(1.0 - p_clean, 3)

    @property
    def verdict(self) -> str:
        score = self.risk_score
        if score >= BLOCK_THRESHOLD:
            return "block"
        if score >= SANITIZE_THRESHOLD:
            return "sanitize"
        return "allow"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "hidden_spans": [
                {"reason": s.reason, "text": s.text[:200]} for s in self.hidden_spans
            ],
        }