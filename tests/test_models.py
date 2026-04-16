"""Unit tests for mcp_scanner.models.

Verifies that all dataclasses serialise correctly, that Severity ordering
behaves as expected, and that ScanReport helper methods return accurate results.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from mcp_scanner.models import (
    Finding,
    ScanReport,
    ScanSummary,
    ScanTarget,
    Severity,
)


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

class TestSeverityOrdering:
    """Tests for Severity comparison operators."""

    def test_critical_greater_than_high(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH

    def test_high_greater_than_medium(self) -> None:
        assert Severity.HIGH > Severity.MEDIUM

    def test_medium_greater_than_low(self) -> None:
        assert Severity.MEDIUM > Severity.LOW

    def test_low_greater_than_info(self) -> None:
        assert Severity.LOW > Severity.INFO

    def test_info_less_than_critical(self) -> None:
        assert Severity.INFO < Severity.CRITICAL

    def test_equal_severities(self) -> None:
        assert Severity.HIGH == Severity.HIGH

    def test_ge_same(self) -> None:
        assert Severity.MEDIUM >= Severity.MEDIUM

    def test_ge_higher(self) -> None:
        assert Severity.HIGH >= Severity.LOW

    def test_le_same(self) -> None:
        assert Severity.LOW <= Severity.LOW

    def test_le_lower(self) -> None:
        assert Severity.INFO <= Severity.MEDIUM

    def test_sorting_descending(self) -> None:
        """Sorting a list of severities should produce descending order."""
        severities = [
            Severity.LOW,
            Severity.CRITICAL,
            Severity.INFO,
            Severity.HIGH,
            Severity.MEDIUM,
        ]
        result = sorted(severities, reverse=True)
        assert result == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

    def test_severity_is_string(self) -> None:
        """Severity values should compare equal to plain strings."""
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH == "HIGH"

    def test_severity_value_attribute(self) -> None:
        assert Severity.CRITICAL.value == "CRITICAL"

    def test_severity_not_implemented_for_wrong_type(self) -> None:
        result = Severity.HIGH.__lt__("not a severity")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# ScanTarget
# ---------------------------------------------------------------------------

class TestScanTarget:
    """Tests for ScanTarget dataclass."""

    def test_trailing_slash_stripped(self) -> None:
        target = ScanTarget(url="https://example.com/")
        assert target.url == "https://example.com"

    def test_multiple_trailing_slashes_stripped(self) -> None:
        target = ScanTarget(url="https://example.com///")
        assert target.url == "https://example.com"

    def test_no_trailing_slash_unchanged(self) -> None:
        target = ScanTarget(url="https://example.com")
        assert target.url == "https://example.com"

    def test_default_timeout(self) -> None:
        target = ScanTarget(url="https://example.com")
        assert target.timeout == 10.0

    def test_custom_timeout(self) -> None:
        target = ScanTarget(url="https://example.com", timeout=5.0)
        assert target.timeout == 5.0

    def test_default_verify_ssl(self) -> None:
        target = ScanTarget(url="https://example.com")
        assert target.verify_ssl is True

    def test_to_dict_contains_required_keys(self) -> None:
        target = ScanTarget(url="https://example.com", timeout=7.5, verify_ssl=False)
        d = target.to_dict()
        assert d["url"] == "https://example.com"
        assert d["timeout"] == 7.5
        assert d["verify_ssl"] is False

    def test_to_dict_does_not_expose_headers(self) -> None:
        """Headers should not appear in the serialised form."""
        target = ScanTarget(
            url="https://example.com",
            headers={"Authorization": "Bearer secret"},
        )
        d = target.to_dict()
        assert "headers" not in d

    def test_default_headers_empty(self) -> None:
        target = ScanTarget(url="https://example.com")
        assert target.headers == {}


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class TestFinding:
    """Tests for Finding dataclass."""

    def _make_finding(self, **kwargs) -> Finding:
        defaults = dict(
            title="Test Finding",
            severity=Severity.HIGH,
            url="https://example.com/mcp",
            description="A test finding.",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_finding_id_is_uuid(self) -> None:
        finding = self._make_finding()
        parsed = uuid.UUID(finding.finding_id)
        assert str(parsed) == finding.finding_id

    def test_unique_finding_ids(self) -> None:
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert f1.finding_id != f2.finding_id

    def test_discovered_at_is_utc(self) -> None:
        finding = self._make_finding()
        assert finding.discovered_at.tzinfo is not None

    def test_default_empty_evidence(self) -> None:
        finding = self._make_finding()
        assert finding.evidence == ""

    def test_default_empty_recommendation(self) -> None:
        finding = self._make_finding()
        assert finding.recommendation == ""

    def test_default_empty_cve_references(self) -> None:
        finding = self._make_finding()
        assert finding.cve_references == []

    def test_default_empty_extra(self) -> None:
        finding = self._make_finding()
        assert finding.extra == {}

    def test_to_dict_severity_is_string(self) -> None:
        finding = self._make_finding(severity=Severity.CRITICAL)
        d = finding.to_dict()
        assert d["severity"] == "CRITICAL"
        assert isinstance(d["severity"], str)

    def test_to_dict_discovered_at_is_isoformat(self) -> None:
        finding = self._make_finding()
        d = finding.to_dict()
        # Should be parseable as ISO-8601
        parsed = datetime.fromisoformat(d["discovered_at"])
        assert parsed is not None

    def test_to_dict_contains_all_required_keys(self) -> None:
        finding = self._make_finding(
            evidence="HTTP 200 | body",
            recommendation="Fix it",
            cve_references=["CVE-2024-001"],
            extra={"method": "GET"},
        )
        d = finding.to_dict()
        expected_keys = {
            "finding_id",
            "title",
            "severity",
            "url",
            "description",
            "evidence",
            "recommendation",
            "cve_references",
            "extra",
            "discovered_at",
        }
        assert expected_keys == set(d.keys())

    def test_to_dict_cve_references_is_list_copy(self) -> None:
        """Mutating the returned list should not affect the finding."""
        finding = self._make_finding(cve_references=["MCPwn-2024-001"])
        d = finding.to_dict()
        d["cve_references"].append("NEW-REF")
        assert "NEW-REF" not in finding.cve_references

    def test_to_dict_extra_is_dict_copy(self) -> None:
        """Mutating the returned dict should not affect the finding."""
        finding = self._make_finding(extra={"key": "value"})
        d = finding.to_dict()
        d["extra"]["injected"] = True
        assert "injected" not in finding.extra


# ---------------------------------------------------------------------------
# ScanSummary
# ---------------------------------------------------------------------------

class TestScanSummary:
    """Tests for ScanSummary dataclass."""

    def test_defaults_are_zero(self) -> None:
        s = ScanSummary()
        assert s.total_findings == 0
        assert s.critical == 0
        assert s.high == 0
        assert s.medium == 0
        assert s.low == 0
        assert s.info == 0
        assert s.endpoints_probed == 0
        assert s.endpoints_found == 0
        assert s.targets_scanned == 0

    def test_to_dict_keys(self) -> None:
        s = ScanSummary(total_findings=3, critical=1, high=2)
        d = s.to_dict()
        expected_keys = {
            "total_findings",
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "endpoints_probed",
            "endpoints_found",
            "targets_scanned",
        }
        assert expected_keys == set(d.keys())

    def test_to_dict_values_match(self) -> None:
        s = ScanSummary(total_findings=5, critical=2, high=1, medium=1, low=1)
        d = s.to_dict()
        assert d["total_findings"] == 5
        assert d["critical"] == 2
        assert d["high"] == 1
        assert d["medium"] == 1
        assert d["low"] == 1
        assert d["info"] == 0


# ---------------------------------------------------------------------------
# ScanReport
# ---------------------------------------------------------------------------

def _make_finding(severity: Severity, url: str = "https://example.com/mcp") -> Finding:
    """Helper to create a minimal Finding for tests."""
    return Finding(
        title="Test",
        severity=severity,
        url=url,
        description="desc",
    )


class TestScanReport:
    """Tests for ScanReport dataclass."""

    def test_scan_id_is_uuid(self) -> None:
        report = ScanReport()
        parsed = uuid.UUID(report.scan_id)
        assert str(parsed) == report.scan_id

    def test_unique_scan_ids(self) -> None:
        r1 = ScanReport()
        r2 = ScanReport()
        assert r1.scan_id != r2.scan_id

    def test_started_at_is_utc(self) -> None:
        report = ScanReport()
        assert report.started_at.tzinfo is not None

    def test_completed_at_initially_none(self) -> None:
        report = ScanReport()
        assert report.completed_at is None

    def test_complete_sets_completed_at(self) -> None:
        report = ScanReport()
        report.complete()
        assert report.completed_at is not None
        assert report.completed_at.tzinfo is not None

    def test_complete_called_twice_updates_timestamp(self) -> None:
        report = ScanReport()
        report.complete()
        first = report.completed_at
        report.complete()
        second = report.completed_at
        assert second >= first  # type: ignore[operator]

    # ------------------------------------------------------------------
    # get_summary
    # ------------------------------------------------------------------

    def test_get_summary_empty_report(self) -> None:
        report = ScanReport()
        s = report.get_summary()
        assert s.total_findings == 0
        assert s.targets_scanned == 0

    def test_get_summary_counts_severities(self) -> None:
        report = ScanReport(
            targets=[ScanTarget(url="https://example.com")],
            findings=[
                _make_finding(Severity.CRITICAL),
                _make_finding(Severity.CRITICAL),
                _make_finding(Severity.HIGH),
                _make_finding(Severity.MEDIUM),
                _make_finding(Severity.LOW),
                _make_finding(Severity.INFO),
            ],
        )
        s = report.get_summary()
        assert s.total_findings == 6
        assert s.critical == 2
        assert s.high == 1
        assert s.medium == 1
        assert s.low == 1
        assert s.info == 1
        assert s.targets_scanned == 1

    def test_get_summary_endpoints_found(self) -> None:
        report = ScanReport(
            findings=[
                _make_finding(Severity.HIGH, url="https://example.com/mcp"),
                _make_finding(Severity.HIGH, url="https://example.com/mcp"),  # duplicate
                _make_finding(Severity.HIGH, url="https://example.com/sse"),
            ]
        )
        s = report.get_summary()
        assert s.endpoints_found == 2  # unique URLs

    # ------------------------------------------------------------------
    # get_findings_by_severity
    # ------------------------------------------------------------------

    def test_get_findings_by_severity_returns_correct_subset(self) -> None:
        critical = _make_finding(Severity.CRITICAL)
        high = _make_finding(Severity.HIGH)
        medium = _make_finding(Severity.MEDIUM)
        report = ScanReport(findings=[critical, high, medium])
        result = report.get_findings_by_severity(Severity.HIGH)
        assert result == [high]

    def test_get_findings_by_severity_empty_when_none(self) -> None:
        report = ScanReport(findings=[_make_finding(Severity.INFO)])
        result = report.get_findings_by_severity(Severity.CRITICAL)
        assert result == []

    # ------------------------------------------------------------------
    # get_findings_for_target
    # ------------------------------------------------------------------

    def test_get_findings_for_target_matches_prefix(self) -> None:
        f1 = _make_finding(Severity.HIGH, url="https://example.com/mcp")
        f2 = _make_finding(Severity.HIGH, url="https://example.com/sse")
        f3 = _make_finding(Severity.HIGH, url="https://other.com/mcp")
        report = ScanReport(findings=[f1, f2, f3])
        result = report.get_findings_for_target("https://example.com")
        assert f1 in result
        assert f2 in result
        assert f3 not in result

    def test_get_findings_for_target_strips_trailing_slash(self) -> None:
        f1 = _make_finding(Severity.HIGH, url="https://example.com/mcp")
        report = ScanReport(findings=[f1])
        result = report.get_findings_for_target("https://example.com/")
        assert f1 in result

    def test_get_findings_for_target_empty_when_no_match(self) -> None:
        f1 = _make_finding(Severity.HIGH, url="https://example.com/mcp")
        report = ScanReport(findings=[f1])
        result = report.get_findings_for_target("https://other.com")
        assert result == []

    # ------------------------------------------------------------------
    # get_findings_sorted_by_severity
    # ------------------------------------------------------------------

    def test_get_findings_sorted_by_severity_descending(self) -> None:
        low = _make_finding(Severity.LOW)
        critical = _make_finding(Severity.CRITICAL)
        medium = _make_finding(Severity.MEDIUM)
        report = ScanReport(findings=[low, critical, medium])
        result = report.get_findings_sorted_by_severity()
        assert result[0].severity == Severity.CRITICAL
        assert result[1].severity == Severity.MEDIUM
        assert result[2].severity == Severity.LOW

    def test_get_findings_sorted_by_severity_ascending(self) -> None:
        low = _make_finding(Severity.LOW)
        critical = _make_finding(Severity.CRITICAL)
        report = ScanReport(findings=[critical, low])
        result = report.get_findings_sorted_by_severity(descending=False)
        assert result[0].severity == Severity.LOW
        assert result[1].severity == Severity.CRITICAL

    # ------------------------------------------------------------------
    # has_critical_or_high_findings
    # ------------------------------------------------------------------

    def test_has_critical_or_high_findings_true_for_critical(self) -> None:
        report = ScanReport(findings=[_make_finding(Severity.CRITICAL)])
        assert report.has_critical_or_high_findings() is True

    def test_has_critical_or_high_findings_true_for_high(self) -> None:
        report = ScanReport(findings=[_make_finding(Severity.HIGH)])
        assert report.has_critical_or_high_findings() is True

    def test_has_critical_or_high_findings_false_for_medium(self) -> None:
        report = ScanReport(findings=[_make_finding(Severity.MEDIUM)])
        assert report.has_critical_or_high_findings() is False

    def test_has_critical_or_high_findings_false_for_empty(self) -> None:
        report = ScanReport()
        assert report.has_critical_or_high_findings() is False

    # ------------------------------------------------------------------
    # add_finding / add_findings
    # ------------------------------------------------------------------

    def test_add_finding(self) -> None:
        report = ScanReport()
        f = _make_finding(Severity.HIGH)
        report.add_finding(f)
        assert f in report.findings

    def test_add_findings(self) -> None:
        report = ScanReport()
        findings = [_make_finding(Severity.HIGH), _make_finding(Severity.LOW)]
        report.add_findings(findings)
        assert len(report.findings) == 2
        for f in findings:
            assert f in report.findings

    # ------------------------------------------------------------------
    # to_dict
    # ------------------------------------------------------------------

    def test_to_dict_keys(self) -> None:
        report = ScanReport()
        report.complete()
        d = report.to_dict()
        expected_keys = {
            "scan_id",
            "scanner_version",
            "started_at",
            "completed_at",
            "targets",
            "findings",
            "summary",
        }
        assert expected_keys == set(d.keys())

    def test_to_dict_completed_at_none_when_not_completed(self) -> None:
        report = ScanReport()
        d = report.to_dict()
        assert d["completed_at"] is None

    def test_to_dict_completed_at_isoformat_when_completed(self) -> None:
        report = ScanReport()
        report.complete()
        d = report.to_dict()
        assert d["completed_at"] is not None
        datetime.fromisoformat(d["completed_at"])  # must not raise

    def test_to_dict_targets_serialised(self) -> None:
        target = ScanTarget(url="https://example.com")
        report = ScanReport(targets=[target])
        d = report.to_dict()
        assert len(d["targets"]) == 1
        assert d["targets"][0]["url"] == "https://example.com"

    def test_to_dict_findings_serialised(self) -> None:
        f = _make_finding(Severity.CRITICAL)
        report = ScanReport(findings=[f])
        d = report.to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["severity"] == "CRITICAL"

    def test_to_dict_summary_embedded(self) -> None:
        f = _make_finding(Severity.HIGH)
        report = ScanReport(findings=[f])
        d = report.to_dict()
        assert d["summary"]["total_findings"] == 1
        assert d["summary"]["high"] == 1

    def test_to_dict_scanner_version(self) -> None:
        report = ScanReport(scanner_version="1.2.3")
        d = report.to_dict()
        assert d["scanner_version"] == "1.2.3"
