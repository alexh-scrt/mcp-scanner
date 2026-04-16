"""Data models for MCP Scanner.

Defines the core dataclasses and enums used throughout the scanner:
ScanTarget, Finding, Severity, ScanSummary, and ScanReport.
All structures support serialization to plain Python dicts for JSON output.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels for security findings.

    Ordered from most critical to least critical:
    CRITICAL > HIGH > MEDIUM > LOW > INFO.

    Inherits from str so that values serialise naturally to JSON strings
    and can be compared directly to string literals.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    # Internal ordering list used for rich comparisons.
    _ORDER: list[str]

    def __new__(cls, value: str) -> "Severity":
        """Create a new Severity member."""
        obj = str.__new__(cls, value)
        obj._value_ = value
        return obj

    @staticmethod
    def _severity_rank(sev: "Severity") -> int:
        """Return an integer rank where higher == more severe."""
        ranks = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return ranks[sev]

    def __lt__(self, other: object) -> bool:
        """Return True if this severity is less critical than *other*."""
        if not isinstance(other, Severity):
            return NotImplemented
        return Severity._severity_rank(self) < Severity._severity_rank(other)

    def __le__(self, other: object) -> bool:
        """Return True if this severity is less critical than or equal to *other*."""
        if not isinstance(other, Severity):
            return NotImplemented
        return Severity._severity_rank(self) <= Severity._severity_rank(other)

    def __gt__(self, other: object) -> bool:
        """Return True if this severity is more critical than *other*."""
        if not isinstance(other, Severity):
            return NotImplemented
        return Severity._severity_rank(self) > Severity._severity_rank(other)

    def __ge__(self, other: object) -> bool:
        """Return True if this severity is more critical than or equal to *other*."""
        if not isinstance(other, Severity):
            return NotImplemented
        return Severity._severity_rank(self) >= Severity._severity_rank(other)

    def __hash__(self) -> int:  # required when __eq__ is inherited from str
        """Hash based on the string value."""
        return str.__hash__(self)


@dataclass
class ScanTarget:
    """Represents a single target base URL to be scanned.

    Attributes:
        url: The base URL of the target (trailing slashes are stripped).
        headers: Per-target HTTP headers merged with any global headers.
        timeout: Per-request timeout in seconds for this target.
        verify_ssl: Whether to verify the target's TLS certificate.
    """

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 10.0
    verify_ssl: bool = True

    def __post_init__(self) -> None:
        """Normalise the URL by stripping trailing slashes."""
        self.url = self.url.rstrip("/")

    def to_dict(self) -> dict[str, Any]:
        """Serialise this target to a plain dictionary suitable for JSON output.

        Note: per-target headers are intentionally omitted from the serialised
        form to avoid leaking credentials into reports.

        Returns:
            Dictionary with ``url``, ``timeout``, and ``verify_ssl`` keys.
        """
        return {
            "url": self.url,
            "timeout": self.timeout,
            "verify_ssl": self.verify_ssl,
        }


@dataclass
class Finding:
    """Represents a single security finding discovered during a scan.

    Each finding maps to one specific issue at one specific URL and carries
    enough context for a human reader to understand the risk and act on it.

    Attributes:
        title: Short, human-readable title for the issue.
        severity: Severity rating of the finding.
        url: The full URL where the issue was observed.
        description: Detailed description of the issue and its impact.
        evidence: Raw evidence from the response (status code, body snippet, etc.).
        recommendation: Actionable remediation advice.
        cve_references: List of CVE identifiers or MCPwn vulnerability references.
        extra: Arbitrary extra metadata for downstream consumers.
        finding_id: UUID uniquely identifying this finding.
        discovered_at: UTC datetime when the finding was recorded.
    """

    title: str
    severity: Severity
    url: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    cve_references: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    discovered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialise this finding to a plain dictionary suitable for JSON output.

        Returns:
            Dictionary containing all finding fields with the severity serialised
            as its string value and the timestamp as an ISO-8601 string.
        """
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cve_references": list(self.cve_references),
            "extra": dict(self.extra),
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass
class ScanSummary:
    """Aggregated statistics for a completed scan.

    Attributes:
        total_findings: Total number of findings across all severities.
        critical: Number of CRITICAL-severity findings.
        high: Number of HIGH-severity findings.
        medium: Number of MEDIUM-severity findings.
        low: Number of LOW-severity findings.
        info: Number of INFO-severity findings.
        endpoints_probed: Total number of URL probes attempted.
        endpoints_found: Number of probed URLs that returned MCP content.
        targets_scanned: Number of distinct target base URLs scanned.
    """

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
        """Serialise the summary to a plain dictionary for JSON output.

        Returns:
            Dictionary with one key per attribute.
        """
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
    """Complete security scan report produced by a single scanner run.

    A ``ScanReport`` is the top-level artifact of the tool.  It aggregates
    all :class:`Finding` objects from all probed :class:`ScanTarget` objects
    and carries metadata about when the scan ran and which tool version
    produced it.

    Attributes:
        targets: List of targets that were (or will be) scanned.
        findings: All findings accumulated during the scan.
        scan_id: UUID uniquely identifying this scan run.
        started_at: UTC datetime when scanning began.
        completed_at: UTC datetime when scanning ended; ``None`` until
            :meth:`complete` is called.
        scanner_version: Version string of the MCP Scanner that ran the scan.
    """

    targets: list[ScanTarget] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    completed_at: datetime | None = None
    scanner_version: str = "0.1.0"

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def complete(self) -> None:
        """Mark the scan as finished by recording the current UTC time.

        Must be called once all probing is finished so that duration
        information is available for reports.
        """
        self.completed_at = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_summary(self) -> ScanSummary:
        """Compute and return aggregated statistics for this report.

        Iterates over :attr:`findings` once to count severities and
        populate all :class:`ScanSummary` fields.

        Returns:
            A :class:`ScanSummary` reflecting the current state of
            :attr:`findings` and :attr:`targets`.
        """
        summary = ScanSummary(
            total_findings=len(self.findings),
            targets_scanned=len(self.targets),
        )

        # Count unique finding URLs as a proxy for endpoints found
        found_urls: set[str] = set()

        for finding in self.findings:
            found_urls.add(finding.url)
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

        summary.endpoints_found = len(found_urls)
        return summary

    def get_findings_by_severity(
        self, severity: Severity
    ) -> list[Finding]:
        """Return all findings that match the given severity level.

        Args:
            severity: The :class:`Severity` to filter by.

        Returns:
            Possibly-empty list of :class:`Finding` objects whose
            :attr:`~Finding.severity` equals *severity*.
        """
        return [f for f in self.findings if f.severity == severity]

    def get_findings_for_target(self, target_url: str) -> list[Finding]:
        """Return all findings associated with a specific target base URL.

        Matching is performed by checking whether each finding's URL starts
        with the normalised *target_url* (trailing slash stripped).

        Args:
            target_url: Base URL of the target to filter by.

        Returns:
            Possibly-empty list of :class:`Finding` objects for *target_url*.
        """
        normalised = target_url.rstrip("/")
        return [
            f for f in self.findings if f.url.startswith(normalised)
        ]

    def get_findings_sorted_by_severity(
        self, descending: bool = True
    ) -> list[Finding]:
        """Return all findings sorted by severity.

        Args:
            descending: When ``True`` (default) the most critical findings
                come first.  Pass ``False`` for ascending order.

        Returns:
            Sorted list of all :class:`Finding` objects.
        """
        return sorted(
            self.findings,
            key=lambda f: f.severity,
            reverse=descending,
        )

    def has_critical_or_high_findings(self) -> bool:
        """Return ``True`` if any CRITICAL or HIGH finding exists.

        Useful for CI/CD integration where a non-zero exit code should be
        returned whenever serious issues are discovered.

        Returns:
            Boolean indicating the presence of severe findings.
        """
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )

    def add_finding(self, finding: Finding) -> None:
        """Append a single finding to the report.

        Args:
            finding: The :class:`Finding` to add.
        """
        self.findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        """Append a list of findings to the report.

        Args:
            findings: List of :class:`Finding` objects to add.
        """
        self.findings.extend(findings)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialise the full report to a plain dictionary for JSON output.

        The resulting structure matches the JSON schema documented in
        ``README.md`` and is safe to pass directly to ``json.dumps``.

        Returns:
            Dictionary containing all report fields, targets, findings,
            and a pre-computed summary.
        """
        return {
            "scan_id": self.scan_id,
            "scanner_version": self.scanner_version,
            "started_at": self.started_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "targets": [t.to_dict() for t in self.targets],
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.get_summary().to_dict(),
        }
