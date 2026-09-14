"""
Core data models for the compliance engine.

Controls are declarative (loaded from YAML). Check functions return a
CheckResult. Nothing in this module talks to AWS — it's pure data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class ControlDefinition:
    """A single compliance control loaded from a YAML ruleset."""

    control_id: str
    framework: str
    title: str
    description: str
    severity: Severity
    check_function: str  # dotted path, e.g. "checks.iam_checks.check_root_mfa"
    remediation: str
    service: str  # primary AWS service this control targets, e.g. "iam"

    @classmethod
    def from_dict(cls, framework: str, data: dict[str, Any]) -> "ControlDefinition":
        return cls(
            control_id=data["id"],
            framework=framework,
            title=data["title"],
            description=data["description"],
            severity=Severity(data["severity"]),
            check_function=data["check_function"],
            remediation=data["remediation"],
            service=data.get("service", "unknown"),
        )


@dataclass
class CheckResult:
    """The outcome of running a single control's check function."""

    control: ControlDefinition
    status: Status
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control.control_id,
            "framework": self.control.framework,
            "title": self.control.title,
            "severity": self.control.severity.value,
            "service": self.control.service,
            "status": self.status.value,
            "message": self.message,
            "evidence": self.evidence,
            "checked_at": self.checked_at.isoformat(),
            "error": self.error,
            "remediation": self.control.remediation if self.status == Status.FAIL else None,
        }
