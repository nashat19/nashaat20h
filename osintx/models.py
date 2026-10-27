"""Domain models shared across the platform."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

class TargetType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    DOMAIN = "domain"
    IP = "ip"
    UNKNOWN = "unknown"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

@dataclass
class Target:
    value: str
    type: TargetType = TargetType.UNKNOWN
    raw: str = ""

    def __post_init__(self) -> None:
        self.raw = self.raw or self.value

@dataclass
class Finding:
    provider: str
    category: str
    title: str
    data: dict[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.INFO
    url: str | None = None
    raw: Any = None

    def fingerprint(self) -> str:
        import json

        blob = json.dumps(
            {"p": self.provider, "t": self.title, "d": self.data},
            sort_keys=True,
            default=str,
        )
        return blob

@dataclass
class ProviderOutcome:
    provider: str
    category: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    elapsed: float = 0.0
    skipped: bool = False

@dataclass
class ScanResult:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    target: str = ""
    target_type: TargetType = TargetType.UNKNOWN
    status: ScanStatus = ScanStatus.PENDING
    created_at: str = field(default_factory=utcnow)
    finished_at: str | None = None
    findings: list[Finding] = field(default_factory=list)
    outcomes: list[ProviderOutcome] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.weight, f.provider, f.title),
        )

    def stats(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for finding in self.findings:
            by_sev[finding.severity.value] = by_sev.get(finding.severity.value, 0) + 1
            by_cat[finding.category] = by_cat.get(finding.category, 0) + 1
        return {
            "total": len(self.findings),
            "by_severity": by_sev,
            "by_category": by_cat,
            "providers_run": sum(1 for o in self.outcomes if not o.skipped),
            "providers_failed": sum(1 for o in self.outcomes if not o.ok and not o.skipped),
            "providers_skipped": sum(1 for o in self.outcomes if o.skipped),
        }
