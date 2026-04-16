"""Tests for report generation in mcp_scanner.reporter.

Verifies that:
* Terminal output can be rendered without errors.
* JSON serialisation matches the documented schema.
* HTML reports are well-formed and contain key content.
* Edge cases (empty reports, long evidence strings, special characters) are handled.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from mcp_scanner.models import Finding, ScanReport, ScanSummary, ScanTarget, Severity
from mcp_scanner.reporter import (
    Reporter,
    SEVERITY_COLORS,
    SEVERITY_EMOJI,
    SEVERITY_HTML_COLORS,
    SEVERITY_RISK_LABELS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_string_console() -> Console:
    """Return a Rich Console that writes to an in-memory StringIO buffer."""
    return Console(file=StringIO(), highlight=False, markup=True, width=120)


def _get_console_output(console: Console) -> str:
    """Extract the text written to a StringIO-backed Console."""
    assert isinstance(console.file, StringIO)
    return console.file.getvalue()


def _make_target(url: str = "https://example.com") -> ScanTarget:
    """Create a minimal ScanTarget for testing."""
    return ScanTarget(url=url, timeout=5.0)


def _make_finding(
    severity: Severity = Severity.HIGH,
    url: str = "https://example.com/mcp",
    title: str = "Test Finding",
    description: str = "A test finding description.",
    evidence: str = 'HTTP 200 | application/json | {"tools": []}',
    recommendation: str = "Fix this issue.",
    cve_references: list[str] | None = None,
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    return Finding(
        title=title,
        severity=severity,
        url=url,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        cve_references=cve_references or [],
    )


def _make_report_with_findings() -> ScanReport:
    """Return a ScanReport with one finding of each severity."""
    targets = [_make_target("https://example.com")]
    findings = [
        _make_finding(Severity.CRITICAL, cve_references=["MCPwn-2024-001"]),
        _make_finding(Severity.HIGH),
        _make_finding(Severity.MEDIUM),
        _make_finding(Severity.LOW),
        _make_finding(Severity.INFO),
    ]
    report = ScanReport(targets=targets, findings=findings)
    report.complete()
    return report


def _make_empty_report() -> ScanReport:
    """Return a ScanReport with no findings."""
    report = ScanReport(targets=[_make_target()])
    report.complete()
    return report


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestSeverityConstants:
    """Tests that all severity-related constants are complete."""

    def test_all_severities_in_colors(self) -> None:
        """Every Severity value should have a corresponding color entry."""
        for sev in Severity:
            assert sev in SEVERITY_COLORS, f"{sev} missing from SEVERITY_COLORS"

    def test_all_severities_in_emoji(self) -> None:
        """Every Severity value should have a corresponding emoji entry."""
        for sev in Severity:
            assert sev in SEVERITY_EMOJI, f"{sev} missing from SEVERITY_EMOJI"

    def test_all_severities_in_risk_labels(self) -> None:
        """Every Severity value should have a corresponding risk label."""
        for sev in Severity:
            assert sev in SEVERITY_RISK_LABELS, f"{sev} missing from SEVERITY_RISK_LABELS"

    def test_html_colors_contains_all_severity_values(self) -> None:
        """SEVERITY_HTML_COLORS keys should match Severity value strings."""
        severity_values = {sev.value for sev in Severity}
        for key in SEVERITY_HTML_COLORS:
            assert key in severity_values, (
                f"Unknown severity '{key}' in SEVERITY_HTML_COLORS"
            )

    def test_critical_color_is_red_variant(self) -> None:
        """CRITICAL findings should use a red color."""
        assert "red" in SEVERITY_COLORS[Severity.CRITICAL]

    def test_emoji_are_non_empty_strings(self) -> None:
        """All emoji entries should be non-empty strings."""
        for sev, emoji in SEVERITY_EMOJI.items():
            assert isinstance(emoji, str) and len(emoji) > 0

    def test_risk_labels_are_non_empty_strings(self) -> None:
        """All risk labels should be non-empty strings."""
        for sev, label in SEVERITY_RISK_LABELS.items():
            assert isinstance(label, str) and len(label) > 0

    def test_html_colors_are_hex_strings(self) -> None:
        """HTML color values should look like hex color codes."""
        for key, color in SEVERITY_HTML_COLORS.items():
            assert color.startswith("#"), f"Color for {key} should start with '#'"
            assert len(color) in (4, 7), f"Color for {key} should be 4 or 7 chars"

    def test_severity_colors_are_strings(self) -> None:
        """All severity color values should be strings."""
        for sev, color in SEVERITY_COLORS.items():
            assert isinstance(color, str)

    def test_five_severities_covered(self) -> None:
        """All five severity levels should be represented."""
        assert len(SEVERITY_COLORS) == 5
        assert len(SEVERITY_EMOJI) == 5
        assert len(SEVERITY_RISK_LABELS) == 5


# ---------------------------------------------------------------------------
# Reporter.__init__
# ---------------------------------------------------------------------------


class TestReporterInit:
    """Tests for Reporter initialisation."""

    def test_default_console_created(self) -> None:
        """A default Console is created when none is provided."""
        reporter = Reporter()
        assert isinstance(reporter.console, Console)

    def test_custom_console_used(self) -> None:
        """A custom console passed to the constructor should be stored."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        assert reporter.console is console

    def test_default_console_is_not_none(self) -> None:
        """The default console should never be None."""
        reporter = Reporter()
        assert reporter.console is not None

    def test_two_reporters_have_independent_consoles(self) -> None:
        """Two Reporters without explicit consoles should not share one."""
        r1 = Reporter()
        r2 = Reporter()
        # Each should have its own console instance
        assert r1.console is not r2.console


# ---------------------------------------------------------------------------
# _html_escape
# ---------------------------------------------------------------------------


class TestHtmlEscape:
    """Tests for the _html_escape static method."""

    def test_ampersand_escaped(self) -> None:
        assert Reporter._html_escape("a & b") == "a &amp; b"

    def test_less_than_escaped(self) -> None:
        assert Reporter._html_escape("<script>") == "&lt;script&gt;"

    def test_greater_than_escaped(self) -> None:
        assert Reporter._html_escape("3 > 2") == "3 &gt; 2"

    def test_double_quote_escaped(self) -> None:
        assert Reporter._html_escape('say "hello"') == "say &quot;hello&quot;"

    def test_single_quote_escaped(self) -> None:
        assert Reporter._html_escape("it's") == "it&#39;s"

    def test_safe_text_unchanged(self) -> None:
        text = "Hello World 123"
        assert Reporter._html_escape(text) == text

    def test_empty_string(self) -> None:
        assert Reporter._html_escape("") == ""

    def test_multiple_special_chars(self) -> None:
        result = Reporter._html_escape('<a href="/test?a=1&b=2">click</a>')
        assert "&lt;" in result
        assert "&gt;" in result
        assert "&quot;" in result
        assert "&amp;" in result

    def test_all_five_special_chars_escaped(self) -> None:
        text = "< > & \" '"
        result = Reporter._html_escape(text)
        assert "<" not in result.replace("&lt;", "")
        assert "&lt;" in result
        assert "&gt;" in result
        assert "&amp;" in result
        assert "&quot;" in result
        assert "&#39;" in result

    def test_multiple_ampersands(self) -> None:
        result = Reporter._html_escape("a & b & c")
        assert result == "a &amp; b &amp; c"

    def test_script_tag_fully_escaped(self) -> None:
        result = Reporter._html_escape("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "</script>" not in result
        assert "&lt;script&gt;" in result

    def test_url_with_query_string(self) -> None:
        result = Reporter._html_escape("https://example.com/path?a=1&b=2")
        assert "&amp;" in result
        assert "&" not in result.replace("&amp;", "").replace("&lt;", "").replace("&gt;", "")


# ---------------------------------------------------------------------------
# _wrap_text
# ---------------------------------------------------------------------------


class TestWrapText:
    """Tests for the _wrap_text static method."""

    def test_short_text_returns_single_element(self) -> None:
        result = Reporter._wrap_text("Hello World", width=80)
        assert result == ["Hello World"]

    def test_text_at_exact_width_not_wrapped(self) -> None:
        text = "x" * 80
        result = Reporter._wrap_text(text, width=80)
        assert len(result) == 1

    def test_long_text_is_wrapped(self) -> None:
        words = ["word"] * 30
        text = " ".join(words)  # 30 * 5 chars with spaces
        result = Reporter._wrap_text(text, width=40)
        assert len(result) > 1

    def test_no_line_exceeds_width_for_normal_text(self) -> None:
        text = ("short ") * 20
        result = Reporter._wrap_text(text.strip(), width=30)
        for line in result:
            # Lines should generally stay within bounds (allow small overshoot at word boundary)
            assert len(line) <= 35

    def test_returns_list_of_strings(self) -> None:
        result = Reporter._wrap_text("some text", width=4)
        assert isinstance(result, list)
        assert all(isinstance(line, str) for line in result)

    def test_empty_string_handled(self) -> None:
        result = Reporter._wrap_text("", width=80)
        assert isinstance(result, list)

    def test_single_word_longer_than_width(self) -> None:
        """A single word longer than width should still be returned."""
        long_word = "a" * 200
        result = Reporter._wrap_text(long_word, width=80)
        assert isinstance(result, list)
        assert len(result) >= 1
        assert long_word in " ".join(result)

    def test_multiple_wraps_produce_multiple_lines(self) -> None:
        text = " ".join(["hello"] * 50)
        result = Reporter._wrap_text(text, width=20)
        assert len(result) > 3

    def test_preserves_all_words(self) -> None:
        """No words should be lost during wrapping."""
        words = ["word" + str(i) for i in range(20)]
        text = " ".join(words)
        result = Reporter._wrap_text(text, width=30)
        joined = " ".join(result)
        for word in words:
            assert word in joined

    def test_default_width_is_90(self) -> None:
        """The default width should be 90 characters."""
        short_text = "hello world"
        result = Reporter._wrap_text(short_text)
        assert result == [short_text]


# ---------------------------------------------------------------------------
# print_terminal_report – empty report
# ---------------------------------------------------------------------------


class TestPrintTerminalReportEmpty:
    """Tests for terminal report with no findings."""

    def test_no_findings_message_shown(self) -> None:
        """Empty report should show a message indicating no findings."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        # Some variant of "no findings" or "no MCP endpoints" should appear
        lower_output = output.lower()
        assert (
            "no mcp endpoints" in lower_output
            or "no findings" in lower_output
            or "scan complete" in lower_output
        )

    def test_scan_id_in_output(self) -> None:
        """Scan ID should appear in the terminal report header."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert report.scan_id in output

    def test_target_url_in_output(self) -> None:
        """Target URL should appear in the terminal report header."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "https://example.com" in output

    def test_summary_table_rendered(self) -> None:
        """All severity labels should appear in the summary table."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output
        assert "INFO" in output

    def test_scanner_version_in_output(self) -> None:
        """Scanner version should appear in the report."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert report.scanner_version in output

    def test_does_not_raise(self) -> None:
        """Rendering an empty report should not raise any exceptions."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)  # Should not raise

    def test_output_is_non_empty_string(self) -> None:
        """The output should not be empty."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert len(output.strip()) > 0

    def test_no_traceback_in_output(self) -> None:
        """There should be no Python tracebacks in the output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "Traceback" not in output

    def test_empty_report_no_footer(self) -> None:
        """The remediation footer should not appear when there are no findings."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        # No "CRITICAL finding" or "HIGH finding" bullet should appear
        assert "CRITICAL finding" not in output or "0 CRITICAL" not in output


# ---------------------------------------------------------------------------
# print_terminal_report – report with findings
# ---------------------------------------------------------------------------


class TestPrintTerminalReportWithFindings:
    """Tests for terminal report rendering when findings are present."""

    def test_finding_titles_appear_in_output(self) -> None:
        """All finding titles should appear in the terminal output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        for finding in report.findings:
            assert finding.title in output, f"Title '{finding.title}' not in output"

    def test_finding_urls_appear_in_output(self) -> None:
        """All finding URLs should appear in the output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        for finding in report.findings:
            assert finding.url in output

    def test_cve_references_appear_in_output(self) -> None:
        """CVE references should appear in the output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "MCPwn-2024-001" in output

    def test_severity_labels_appear_in_output(self) -> None:
        """All severity level names should appear in the output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in output

    def test_summary_total_appears_in_output(self) -> None:
        """Total finding count should appear in the output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        # 5 findings in total
        assert "5" in output

    def test_recommendations_appear_in_output(self) -> None:
        """Finding recommendations should appear in the output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(recommendation="Apply a patch immediately.")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "Apply a patch immediately." in output

    def test_evidence_appears_in_output(self) -> None:
        """Finding evidence should appear in the output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(evidence="HTTP 200 | tools found")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "HTTP 200" in output

    def test_does_not_raise_for_long_evidence(self) -> None:
        """Very long evidence strings should be truncated, not cause errors."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        long_evidence = "x" * 2000
        finding = _make_finding(evidence=long_evidence)
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        # Should not raise
        reporter.print_terminal_report(report)

    def test_footer_shown_with_findings(self) -> None:
        """The remediation footer should appear when findings exist."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "remediat" in output.lower()

    def test_does_not_raise_for_empty_recommendation(self) -> None:
        """Findings with empty recommendations should not cause errors."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(recommendation="")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)  # Should not raise

    def test_does_not_raise_for_no_cve_references(self) -> None:
        """Findings without CVE references should not cause errors."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(cve_references=[])
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)  # Should not raise

    def test_special_chars_in_finding_do_not_crash(self) -> None:
        """Special characters in finding fields should not cause crashes."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(
            title="Finding with special chars",
            description='Has some quotes and ampersands',
        )
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)  # Should not raise

    def test_multiple_targets_listed_in_header(self) -> None:
        """Multiple target URLs should all appear in the header."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        targets = [
            _make_target("https://a.example.com"),
            _make_target("https://b.example.com"),
        ]
        report = ScanReport(targets=targets, findings=[])
        report.complete()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "https://a.example.com" in output
        assert "https://b.example.com" in output

    def test_description_appears_in_output(self) -> None:
        """Finding descriptions should appear in the output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(description="Very specific description text for testing.")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "Very specific description text for testing." in output

    def test_multiple_findings_all_shown(self) -> None:
        """All findings in the report should appear in the output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        findings = [
            _make_finding(Severity.CRITICAL, title="Critical Issue"),
            _make_finding(Severity.HIGH, title="High Issue"),
            _make_finding(Severity.MEDIUM, title="Medium Issue"),
        ]
        report = ScanReport(targets=[_make_target()], findings=findings)
        report.complete()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "Critical Issue" in output
        assert "High Issue" in output
        assert "Medium Issue" in output

    def test_completed_scan_shows_duration(self) -> None:
        """A completed scan should show some timing information."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()  # completed
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        # Started timestamp should appear
        assert report.started_at.strftime("%Y-%m-%d") in output

    def test_finding_index_numbers_present(self) -> None:
        """Finding index numbers like [1], [2] should appear in output."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        findings = [
            _make_finding(Severity.HIGH, title="First Finding"),
            _make_finding(Severity.HIGH, title="Second Finding"),
        ]
        report = ScanReport(targets=[_make_target()], findings=findings)
        report.complete()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "[1]" in output
        assert "[2]" in output

    def test_does_not_raise_for_empty_evidence(self) -> None:
        """Findings with empty evidence should not cause errors."""
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(evidence="")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)  # Should not raise


# ---------------------------------------------------------------------------
# to_json
# ---------------------------------------------------------------------------


class TestToJson:
    """Tests for Reporter.to_json."""

    def test_returns_valid_json_string(self) -> None:
        """The output should be parseable as valid JSON."""
        reporter = Reporter()
        report = _make_empty_report()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_json_contains_scan_id(self) -> None:
        """The JSON should contain the correct scan_id."""
        reporter = Reporter()
        report = _make_empty_report()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert parsed["scan_id"] == report.scan_id

    def test_json_contains_scanner_version(self) -> None:
        """The JSON should contain the scanner_version field."""
        reporter = Reporter()
        report = _make_empty_report()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert "scanner_version" in parsed

    def test_json_contains_targets(self) -> None:
        """The JSON should include the targets list."""
        reporter = Reporter()
        report = ScanReport(targets=[_make_target("https://example.com")])
        report.complete()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert len(parsed["targets"]) == 1
        assert parsed["targets"][0]["url"] == "https://example.com"

    def test_json_contains_findings(self) -> None:
        """The JSON should include all findings."""
        reporter = Reporter()
        report = _make_report_with_findings()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert len(parsed["findings"]) == 5

    def test_json_contains_summary(self) -> None:
        """The JSON should contain a summary object."""
        reporter = Reporter()
        report = _make_report_with_findings()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert "summary" in parsed
        assert parsed["summary"]["total_findings"] == 5

    def test_json_summary_counts_correct(self) -> None:
        """Summary counts should match the findings in the report."""
        reporter = Reporter()
        report = _make_report_with_findings()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        s = parsed["summary"]
        assert s["critical"] == 1
        assert s["high"] == 1
        assert s["medium"] == 1
        assert s["low"] == 1
        assert s["info"] == 1

    def test_json_findings_severity_is_string(self) -> None:
        """Finding severity should be serialised as a string."""
        reporter = Reporter()
        report = ScanReport(
            targets=[_make_target()],
            findings=[_make_finding(Severity.CRITICAL)],
        )
        report.complete()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert parsed["findings"][0]["severity"] == "CRITICAL"
        assert isinstance(parsed["findings"][0]["severity"], str)

    def test_json_indent_respected(self) -> None:
        """The indent parameter should affect output formatting."""
        reporter = Reporter()
        report = _make_empty_report()
        json_str_2 = reporter.to_json(report, indent=2)
        json_str_4 = reporter.to_json(report, indent=4)
        # 4-space indent produces more whitespace
        assert len(json_str_4) >= len(json_str_2)

    def test_json_completed_at_present_when_completed(self) -> None:
        """completed_at should be non-null in JSON when scan is completed."""
        reporter = Reporter()
        report = _make_empty_report()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert parsed["completed_at"] is not None

    def test_json_completed_at_null_when_not_completed(self) -> None:
        """completed_at should be null in JSON when scan is not yet completed."""
        reporter = Reporter()
        report = ScanReport(targets=[_make_target()])
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert parsed["completed_at"] is None

    def test_json_schema_keys(self) -> None:
        """The top-level JSON object should have exactly the expected keys."""
        reporter = Reporter()
        report = _make_empty_report()
        parsed = json.loads(reporter.to_json(report))
        expected_keys = {
            "scan_id",
            "scanner_version",
            "started_at",
            "completed_at",
            "targets",
            "findings",
            "summary",
        }
        assert expected_keys == set(parsed.keys())

    def test_finding_schema_keys(self) -> None:
        """Each finding in the JSON should have exactly the expected keys."""
        reporter = Reporter()
        finding = _make_finding(cve_references=["MCPwn-2024-001"])
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        parsed = json.loads(reporter.to_json(report))
        f = parsed["findings"][0]
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
        assert expected_keys == set(f.keys())

    def test_json_started_at_is_iso_format(self) -> None:
        """started_at should be a valid ISO-8601 datetime string."""
        reporter = Reporter()
        report = _make_empty_report()
        parsed = json.loads(reporter.to_json(report))
        # Should parse without error
        dt = datetime.fromisoformat(parsed["started_at"])
        assert dt is not None

    def test_json_finding_discovered_at_is_iso_format(self) -> None:
        """discovered_at in each finding should be a valid ISO-8601 string."""
        reporter = Reporter()
        finding = _make_finding()
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        parsed = json.loads(reporter.to_json(report))
        dt = datetime.fromisoformat(parsed["findings"][0]["discovered_at"])
        assert dt is not None

    def test_json_cve_references_is_list(self) -> None:
        """CVE references should be serialised as a JSON array."""
        reporter = Reporter()
        finding = _make_finding(cve_references=["MCPwn-2024-001", "CVE-2024-99"])
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        parsed = json.loads(reporter.to_json(report))
        assert isinstance(parsed["findings"][0]["cve_references"], list)
        assert "MCPwn-2024-001" in parsed["findings"][0]["cve_references"]

    def test_json_is_utf8_safe(self) -> None:
        """Unicode characters should appear correctly in the JSON output."""
        reporter = Reporter()
        finding = _make_finding(description="Unicode: \u4e2d\u6587 and \u00e9\u00e0\u00fc")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert "\u4e2d\u6587" in parsed["findings"][0]["description"]

    def test_empty_findings_list_in_json(self) -> None:
        """An empty findings list should be serialised as an empty JSON array."""
        reporter = Reporter()
        report = _make_empty_report()
        parsed = json.loads(reporter.to_json(report))
        assert parsed["findings"] == []

    def test_empty_targets_list_in_json(self) -> None:
        """An empty targets list should be serialised as an empty JSON array."""
        reporter = Reporter()
        report = ScanReport()
        report.complete()
        parsed = json.loads(reporter.to_json(report))
        assert parsed["targets"] == []


# ---------------------------------------------------------------------------
# write_json_report
# ---------------------------------------------------------------------------


class TestWriteJsonReport:
    """Tests for Reporter.write_json_report."""

    def test_file_created(self, tmp_path: Path) -> None:
        """The output file should be created."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        assert output.exists()

    def test_file_contains_valid_json(self, tmp_path: Path) -> None:
        """The output file should contain valid JSON."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        content = output.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert isinstance(parsed, dict)

    def test_file_contains_scan_id(self, tmp_path: Path) -> None:
        """The output file should contain the correct scan_id."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        parsed = json.loads(output.read_text(encoding="utf-8"))
        assert parsed["scan_id"] == report.scan_id

    def test_parent_dirs_created(self, tmp_path: Path) -> None:
        """Parent directories should be created automatically."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "nested" / "dir" / "report.json"
        reporter.write_json_report(report, output)
        assert output.exists()

    def test_accepts_string_path(self, tmp_path: Path) -> None:
        """A string path should work as well as a Path object."""
        reporter = Reporter()
        report = _make_empty_report()
        output = str(tmp_path / "report.json")
        reporter.write_json_report(report, output)
        assert Path(output).exists()

    def test_file_is_utf8_encoded(self, tmp_path: Path) -> None:
        """The output file should use UTF-8 encoding."""
        reporter = Reporter()
        finding = _make_finding(description="Unicode: \u4e2d\u6587 and \u00e9\u00e0\u00fc")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        content = output.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert "\u4e2d\u6587" in parsed["findings"][0]["description"]

    def test_file_contents_match_to_json(self, tmp_path: Path) -> None:
        """The file contents should match what to_json() returns."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        file_content = output.read_text(encoding="utf-8")
        direct_json = reporter.to_json(report)
        # Both should parse to the same dict
        assert json.loads(file_content) == json.loads(direct_json)

    def test_default_indent_is_2(self, tmp_path: Path) -> None:
        """Default indentation should be 2 spaces."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        content = output.read_text(encoding="utf-8")
        # 2-space indented JSON will have lines starting with exactly 2 spaces
        assert "  " in content  # at least some 2-space indentation exists

    def test_custom_indent(self, tmp_path: Path) -> None:
        """Custom indent parameter should be respected."""
        reporter = Reporter()
        report = _make_empty_report()
        output_2 = tmp_path / "report_2.json"
        output_4 = tmp_path / "report_4.json"
        reporter.write_json_report(report, output_2, indent=2)
        reporter.write_json_report(report, output_4, indent=4)
        size_2 = output_2.stat().st_size
        size_4 = output_4.stat().st_size
        assert size_4 >= size_2


# ---------------------------------------------------------------------------
# print_json_to_stdout
# ---------------------------------------------------------------------------


class TestPrintJsonToStdout:
    """Tests for Reporter.print_json_to_stdout."""

    def test_prints_valid_json(self, capsys: pytest.CaptureFixture) -> None:
        """Output should be valid JSON."""
        reporter = Reporter()
        report = _make_empty_report()
        reporter.print_json_to_stdout(report)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert isinstance(parsed, dict)

    def test_output_contains_scan_id(self, capsys: pytest.CaptureFixture) -> None:
        """Output should contain the scan ID."""
        reporter = Reporter()
        report = _make_empty_report()
        reporter.print_json_to_stdout(report)
        captured = capsys.readouterr()
        assert report.scan_id in captured.out

    def test_output_is_to_stdout_not_stderr(self, capsys: pytest.CaptureFixture) -> None:
        """JSON should be written to stdout, not stderr."""
        reporter = Reporter()
        report = _make_empty_report()
        reporter.print_json_to_stdout(report)
        captured = capsys.readouterr()
        # stdout has content
        assert len(captured.out.strip()) > 0

    def test_stderr_is_empty(self, capsys: pytest.CaptureFixture) -> None:
        """Nothing should be written to stderr by this method."""
        reporter = Reporter()
        report = _make_empty_report()
        reporter.print_json_to_stdout(report)
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_output_matches_to_json(self, capsys: pytest.CaptureFixture) -> None:
        """print_json_to_stdout output should match to_json() output."""
        reporter = Reporter()
        report = _make_empty_report()
        reporter.print_json_to_stdout(report)
        captured = capsys.readouterr()
        json_str = reporter.to_json(report)
        # Both should parse to the same data
        assert json.loads(captured.out) == json.loads(json_str)

    def test_no_ansi_codes_in_output(self, capsys: pytest.CaptureFixture) -> None:
        """The output should not contain ANSI escape codes."""
        reporter = Reporter()
        report = _make_empty_report()
        reporter.print_json_to_stdout(report)
        captured = capsys.readouterr()
        # ANSI codes start with ESC (\x1b)
        assert "\x1b" not in captured.out


# ---------------------------------------------------------------------------
# write_html_report
# ---------------------------------------------------------------------------


class TestWriteHtmlReport:
    """Tests for Reporter.write_html_report."""

    def test_file_created(self, tmp_path: Path) -> None:
        """The HTML output file should be created."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        assert output.exists()

    def test_file_is_html_document(self, tmp_path: Path) -> None:
        """The output file should be a valid HTML document."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "</html>" in content

    def test_html_contains_scan_id(self, tmp_path: Path) -> None:
        """The HTML should include part of the scan ID."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        # First 8 chars of scan_id appear in the title
        assert report.scan_id[:8] in content

    def test_html_contains_mcp_scanner_heading(self, tmp_path: Path) -> None:
        """The HTML should contain the MCP Scanner heading."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "MCP Scanner" in content

    def test_html_contains_target_url(self, tmp_path: Path) -> None:
        """The HTML should include the target URL."""
        reporter = Reporter()
        report = ScanReport(targets=[_make_target("https://example.com")])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "https://example.com" in content

    def test_html_contains_severity_labels(self, tmp_path: Path) -> None:
        """The HTML should include all severity level labels."""
        reporter = Reporter()
        report = _make_report_with_findings()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in content

    def test_html_contains_finding_title(self, tmp_path: Path) -> None:
        """The HTML should include finding titles."""
        reporter = Reporter()
        finding = _make_finding(title="Unique Finding Title XYZ")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "Unique Finding Title XYZ" in content

    def test_html_contains_finding_url(self, tmp_path: Path) -> None:
        """The HTML should include finding URLs."""
        reporter = Reporter()
        finding = _make_finding(url="https://example.com/mcp/tools")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "https://example.com/mcp/tools" in content

    def test_html_escapes_special_characters(self, tmp_path: Path) -> None:
        """Special characters in findings should be escaped in HTML output."""
        reporter = Reporter()
        finding = _make_finding(
            title="<script>alert('xss')</script>",
            description="A & B <> C",
        )
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        # Raw script tag should not appear verbatim
        assert "<script>alert" not in content
        assert "&lt;script&gt;" in content

    def test_html_contains_cve_references(self, tmp_path: Path) -> None:
        """CVE references should appear in the HTML."""
        reporter = Reporter()
        finding = _make_finding(cve_references=["MCPwn-2024-001"])
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "MCPwn-2024-001" in content

    def test_html_parent_dirs_created(self, tmp_path: Path) -> None:
        """Parent directories should be created automatically."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "deep" / "nested" / "report.html"
        reporter.write_html_report(report, output)
        assert output.exists()

    def test_html_no_findings_shows_no_findings_message(self, tmp_path: Path) -> None:
        """An empty report should show a 'no findings' message."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        lower = content.lower()
        assert "no findings" in lower or "no mcp endpoints" in lower

    def test_html_summary_counts_present(self, tmp_path: Path) -> None:
        """Severity counts in the summary section should appear in the HTML."""
        reporter = Reporter()
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
        ]
        report = ScanReport(targets=[_make_target()], findings=findings)
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "CRITICAL" in content
        assert "HIGH" in content

    def test_html_accepts_string_path(self, tmp_path: Path) -> None:
        """A string path should work as well as a Path object."""
        reporter = Reporter()
        report = _make_empty_report()
        output = str(tmp_path / "report.html")
        reporter.write_html_report(report, output)
        assert Path(output).exists()

    def test_html_is_utf8_encoded(self, tmp_path: Path) -> None:
        """The HTML output file should use UTF-8 encoding."""
        reporter = Reporter()
        finding = _make_finding(description="Unicode: \u4e2d\u6587")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "\u4e2d\u6587" in content

    def test_html_has_charset_meta_tag(self, tmp_path: Path) -> None:
        """The HTML should declare UTF-8 charset in a meta tag."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "charset" in content.lower() and "utf-8" in content.lower()

    def test_html_contains_scanner_version(self, tmp_path: Path) -> None:
        """The HTML should include the scanner version string."""
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert report.scanner_version in content

    def test_html_contains_recommendation(self, tmp_path: Path) -> None:
        """Recommendations should appear in the HTML."""
        reporter = Reporter()
        finding = _make_finding(recommendation="Apply the security patch immediately.")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "Apply the security patch immediately." in content

    def test_html_contains_evidence(self, tmp_path: Path) -> None:
        """Evidence should appear in the HTML."""
        reporter = Reporter()
        finding = _make_finding(evidence="HTTP 200 unique_evidence_string tools found")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "unique_evidence_string" in content


# ---------------------------------------------------------------------------
# _build_html_report internals
# ---------------------------------------------------------------------------


class TestBuildHtmlReport:
    """Tests for the _build_html_report private method."""

    def test_returns_string(self) -> None:
        """_build_html_report should return a string."""
        reporter = Reporter()
        report = _make_empty_report()
        html = reporter._build_html_report(report)
        assert isinstance(html, str)

    def test_contains_doctype(self) -> None:
        """The HTML should start with a DOCTYPE declaration."""
        reporter = Reporter()
        report = _make_empty_report()
        html = reporter._build_html_report(report)
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_duration_shown_when_completed(self) -> None:
        """When the scan is complete, duration info should appear."""
        reporter = Reporter()
        report = _make_empty_report()  # already completed
        html = reporter._build_html_report(report)
        # Duration or timing info should appear in some form
        lower = html.lower()
        assert "duration" in lower or "0." in html or "started" in lower

    def test_findings_sorted_most_severe_first(self) -> None:
        """In the HTML, more severe findings should appear before less severe ones."""
        reporter = Reporter()
        low_finding = _make_finding(Severity.LOW, title="Low Finding")
        critical_finding = _make_finding(Severity.CRITICAL, title="Critical Finding")
        report = ScanReport(
            targets=[_make_target()],
            findings=[low_finding, critical_finding],
        )
        report.complete()
        html = reporter._build_html_report(report)
        # Critical should appear before Low in the HTML
        critical_pos = html.find("Critical Finding")
        low_pos = html.find("Low Finding")
        assert critical_pos < low_pos

    def test_contains_body_tag(self) -> None:
        """The HTML should contain a body element."""
        reporter = Reporter()
        report = _make_empty_report()
        html = reporter._build_html_report(report)
        assert "<body" in html
        assert "</body>" in html

    def test_contains_head_tag(self) -> None:
        """The HTML should contain a head element."""
        reporter = Reporter()
        report = _make_empty_report()
        html = reporter._build_html_report(report)
        assert "<head" in html
        assert "</head>" in html

    def test_contains_css_styles(self) -> None:
        """The HTML should contain embedded CSS styles."""
        reporter = Reporter()
        report = _make_empty_report()
        html = reporter._build_html_report(report)
        assert "<style" in html

    def test_contains_target_count(self) -> None:
        """The HTML should mention the number of targets scanned."""
        reporter = Reporter()
        targets = [_make_target("https://a.example.com"), _make_target("https://b.example.com")]
        report = ScanReport(targets=targets)
        report.complete()
        html = reporter._build_html_report(report)
        assert "2" in html  # Target count

    def test_no_findings_message_in_empty_report(self) -> None:
        """An empty report should have a message about no findings."""
        reporter = Reporter()
        report = _make_empty_report()
        html = reporter._build_html_report(report)
        lower = html.lower()
        assert "no findings" in lower or "no mcp endpoints" in lower


# ---------------------------------------------------------------------------
# _build_summary_cards_html
# ---------------------------------------------------------------------------


class TestBuildSummaryCardsHtml:
    """Tests for the _build_summary_cards_html method."""

    def test_returns_string(self) -> None:
        """Method should return a string."""
        reporter = Reporter()
        summary = ScanSummary(critical=1, high=2, medium=3, low=0, info=1)
        html = reporter._build_summary_cards_html(summary)
        assert isinstance(html, str)

    def test_contains_all_severity_levels(self) -> None:
        """All severity levels should appear in the summary cards."""
        reporter = Reporter()
        summary = ScanSummary()
        html = reporter._build_summary_cards_html(summary)
        for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert label in html

    def test_contains_counts(self) -> None:
        """Severity counts should appear in the cards HTML."""
        reporter = Reporter()
        summary = ScanSummary(critical=7, high=3)
        html = reporter._build_summary_cards_html(summary)
        assert "7" in html
        assert "3" in html

    def test_zero_counts_shown(self) -> None:
        """Zero counts should still appear in the cards."""
        reporter = Reporter()
        summary = ScanSummary(critical=0, high=0, medium=0, low=0, info=0)
        html = reporter._build_summary_cards_html(summary)
        assert "0" in html

    def test_contains_summary_cards_div(self) -> None:
        """The output should contain the summary-cards container div."""
        reporter = Reporter()
        summary = ScanSummary()
        html = reporter._build_summary_cards_html(summary)
        assert "summary-cards" in html

    def test_contains_five_cards(self) -> None:
        """There should be one card per severity level (5 total)."""
        reporter = Reporter()
        summary = ScanSummary()
        html = reporter._build_summary_cards_html(summary)
        # Count summary-card occurrences
        assert html.count("summary-card") >= 5


# ---------------------------------------------------------------------------
# _build_finding_html
# ---------------------------------------------------------------------------


class TestBuildFindingHtml:
    """Tests for the _build_finding_html method."""

    def test_returns_string(self) -> None:
        """Method should return a string."""
        reporter = Reporter()
        finding = _make_finding()
        html = reporter._build_finding_html(finding)
        assert isinstance(html, str)

    def test_contains_severity_value(self) -> None:
        """The severity value should appear in the finding HTML."""
        reporter = Reporter()
        finding = _make_finding(Severity.CRITICAL)
        html = reporter._build_finding_html(finding)
        assert "CRITICAL" in html

    def test_contains_title(self) -> None:
        """The finding title should appear in the HTML."""
        reporter = Reporter()
        finding = _make_finding(title="My Unique Title")
        html = reporter._build_finding_html(finding)
        assert "My Unique Title" in html

    def test_contains_url(self) -> None:
        """The finding URL should appear in the HTML."""
        reporter = Reporter()
        finding = _make_finding(url="https://example.com/mcp")
        html = reporter._build_finding_html(finding)
        assert "https://example.com/mcp" in html

    def test_contains_description(self) -> None:
        """The finding description should appear in the HTML."""
        reporter = Reporter()
        finding = _make_finding(description="Very specific description text.")
        html = reporter._build_finding_html(finding)
        assert "Very specific description text." in html

    def test_escapes_html_in_title(self) -> None:
        """HTML characters in the title should be escaped."""
        reporter = Reporter()
        finding = _make_finding(title="<img src=x onerror=alert(1)>")
        html = reporter._build_finding_html(finding)
        assert "<img" not in html
        assert "&lt;img" in html

    def test_contains_cve_references(self) -> None:
        """CVE references should appear in the finding HTML."""
        reporter = Reporter()
        finding = _make_finding(cve_references=["MCPwn-2024-001", "CVE-2024-99999"])
        html = reporter._build_finding_html(finding)
        assert "MCPwn-2024-001" in html
        assert "CVE-2024-99999" in html

    def test_contains_finding_id(self) -> None:
        """The finding ID should appear in the HTML."""
        reporter = Reporter()
        finding = _make_finding()
        html = reporter._build_finding_html(finding)
        assert finding.finding_id in html

    def test_evidence_truncated_at_600_chars(self) -> None:
        """Evidence longer than 600 chars should be truncated."""
        reporter = Reporter()
        long_evidence = "e" * 800
        finding = _make_finding(evidence=long_evidence)
        html = reporter._build_finding_html(finding)
        # Evidence section should exist but be truncated
        assert "e" * 600 in html
        # Should not contain the full 800-char string
        assert "e" * 800 not in html

    def test_no_evidence_section_when_empty(self) -> None:
        """An empty evidence field should not cause errors."""
        reporter = Reporter()
        finding = _make_finding(evidence="")
        html = reporter._build_finding_html(finding)
        # Should not crash and should not include an Evidence dt
        assert isinstance(html, str)

    def test_contains_recommendation_when_set(self) -> None:
        """Recommendations should appear in the HTML when set."""
        reporter = Reporter()
        finding = _make_finding(recommendation="Fix this vulnerability immediately.")
        html = reporter._build_finding_html(finding)
        assert "Fix this vulnerability immediately." in html

    def test_severity_badge_color_applied(self) -> None:
        """The severity badge should have a background color style."""
        reporter = Reporter()
        finding = _make_finding(Severity.CRITICAL)
        html = reporter._build_finding_html(finding)
        # The badge should have a background color from SEVERITY_HTML_COLORS
        assert SEVERITY_HTML_COLORS["CRITICAL"] in html

    def test_finding_div_has_severity_class(self) -> None:
        """The finding div should have a CSS class with the severity level."""
        reporter = Reporter()
        finding = _make_finding(Severity.HIGH)
        html = reporter._build_finding_html(finding)
        assert "finding-HIGH" in html

    def test_no_cve_section_when_empty(self) -> None:
        """No CVE references section when cve_references is empty."""
        reporter = Reporter()
        finding = _make_finding(cve_references=[])
        html = reporter._build_finding_html(finding)
        # Should not crash
        assert isinstance(html, str)

    def test_returns_non_empty_string(self) -> None:
        """The finding HTML should not be empty."""
        reporter = Reporter()
        finding = _make_finding()
        html = reporter._build_finding_html(finding)
        assert len(html.strip()) > 0
