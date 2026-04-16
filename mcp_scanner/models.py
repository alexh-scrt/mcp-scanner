"""Data models for MCP Scanner.

Defines the core dataclasses and enums used throughout the scanner:
ScanTarget, Finding, Severity, and ScanReport.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels for security findings, ordered from most to least critical."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other: "Severity") -> bool:
        """Compare severities for ordering (CRITICAL > HIGH > MEDIUM > LOW > INFO)."""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        """Less than or equal comparison."""
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        """Greater than comparison."""
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        """Greater than or equal comparison."""
        return self == other or self > other


@dataclass
class ScanTarget:
    """Represents a target URL to be scanned."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 10.0
    verify_ssl: bool = True

    def __post_init__(self) -> None:
        """Normalize the URL by stripping trailing slashes."""
        self.url = self.url.rstrip("/")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary for JSON output."""
        return {
            "url": self.url,
            "timeout": self.timeout,
            "verify_ssl": self.verify_ssl,
        }


@dataclass
class Finding:
    """Represents a single security finding discovered during a scan."""

    title: str
    severity: Severity
    url: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    cve_references: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary for JSON output."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cve_references": self.cve_references,
            "extra": self.extra,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass
class ScanSummary:
    """Summary statistics for a completed scan."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    endpoints_probed: int = 0
    endpoints_found: int = 0
    targets_scanned: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary for JSON output."""
        return {
            "total_findings": self.total_findings,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "endpoints_probed": self.endpoints_probed,
            "endpoints_found": self.endpoints_found,
            "targets_scanned": self.targets_scanned,
        }


@dataclass
class ScanReport:
    """Complete security scan report containing all findings and metadata."""

    targets: list[ScanTarget] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    scanner_version: str = "0.1.0"

    def complete(self) -> None:
        """Mark the scan as completed by recording the completion timestamp."""
        self.completed_at = datetime.now(timezone.utc)

    def get_summary(self) -> ScanSummary:
        """Compute and return summary statistics for this report."""
        summary = ScanSummary()
        summary.total_findings = len(self.findings)
        summary.targets_scanned = len(self.targets)

        for finding in self.findings:
            if finding.severity == Severity.CRITICAL:
                summary.critical += 1
            elif finding.severity == Severity.HIGH:
                summary.high += 1
            elif finding.severity == Severity.MEDIUM:
                summary.medium += 1
            elif finding.severity == Severity.LOW:
                summary.low += 1
            elif finding.severity == Severity.INFO:
                summary.info += 1

        return summary

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Return all findings matching the given severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_for_target(self, target_url: str) -> list[Finding]:
        """Return all findings associated with a specific target URL."""
        normalized = target_url.rstrip("/")
        return [f for f in self.findings if f.url.startswith(normalized)]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full report to a dictionary for JSON output."""
        return {
            "scan_id": self.scan_id,
            "scanner_version": self.scanner_version,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "targets": [t.to_dict() for t in self.targets],
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.get_summary().to_dict(),
        }
