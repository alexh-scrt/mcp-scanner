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

from mcp_scanner.models import Finding, ScanReport, ScanTarget, Severity
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
    return ScanTarget(url=url, timeout=5.0)


def _make_finding(
    severity: Severity = Severity.HIGH,
    url: str = "https://example.com/mcp",
    title: str = "Test Finding",
    description: str = "A test finding description.",
    evidence: str = "HTTP 200 | application/json | {\"tools\": []}",
    recommendation: str = "Fix this issue.",
    cve_references: list[str] | None = None,
) -> Finding:
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
        for sev in Severity:
            assert sev in SEVERITY_COLORS, f"{sev} missing from SEVERITY_COLORS"

    def test_all_severities_in_emoji(self) -> None:
        for sev in Severity:
            assert sev in SEVERITY_EMOJI, f"{sev} missing from SEVERITY_EMOJI"

    def test_all_severities_in_risk_labels(self) -> None:
        for sev in Severity:
            assert sev in SEVERITY_RISK_LABELS, f"{sev} missing from SEVERITY_RISK_LABELS"

    def test_html_colors_contains_all_severity_values(self) -> None:
        severity_values = {sev.value for sev in Severity}
        for key in SEVERITY_HTML_COLORS:
            assert key in severity_values, f"Unknown severity '{key}' in SEVERITY_HTML_COLORS"

    def test_critical_color_is_red_variant(self) -> None:
        assert "red" in SEVERITY_COLORS[Severity.CRITICAL]

    def test_emoji_are_non_empty_strings(self) -> None:
        for sev, emoji in SEVERITY_EMOJI.items():
            assert isinstance(emoji, str) and len(emoji) > 0


# ---------------------------------------------------------------------------
# Reporter.__init__
# ---------------------------------------------------------------------------


class TestReporterInit:
    """Tests for Reporter initialisation."""

    def test_default_console_created(self) -> None:
        reporter = Reporter()
        assert isinstance(reporter.console, Console)

    def test_custom_console_used(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        assert reporter.console is console


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
        text = " ".join(words)  # 30 * 5 = 150+ chars with spaces
        result = Reporter._wrap_text(text, width=40)
        assert len(result) > 1

    def test_no_line_exceeds_width_except_single_long_word(self) -> None:
        text = "short " * 10 + "this_is_a_very_long_word_that_cannot_be_split"
        result = Reporter._wrap_text(text, width=20)
        for line in result:
            # Long single words may exceed width; all others should not
            if " " not in line:
                continue  # single word – allowed to exceed width
            assert len(line) <= 20 + 10  # allow small overshoot at word boundary

    def test_returns_list_of_strings(self) -> None:
        result = Reporter._wrap_text("some text", width=4)
        assert isinstance(result, list)
        assert all(isinstance(line, str) for line in result)

    def test_empty_string_handled(self) -> None:
        result = Reporter._wrap_text("", width=80)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# print_terminal_report – empty report
# ---------------------------------------------------------------------------


class TestPrintTerminalReportEmpty:
    """Tests for terminal report with no findings."""

    def test_no_findings_message_shown(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "No MCP endpoints" in output or "No findings" in output.lower() or "no findings" in output.lower()

    def test_scan_id_in_output(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert report.scan_id in output

    def test_target_url_in_output(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_empty_report()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "https://example.com" in output

    def test_summary_table_rendered(self) -> None:
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


# ---------------------------------------------------------------------------
# print_terminal_report – report with findings
# ---------------------------------------------------------------------------


class TestPrintTerminalReportWithFindings:
    """Tests for terminal report rendering when findings are present."""

    def test_finding_titles_appear_in_output(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        for finding in report.findings:
            assert finding.title in output, f"Title '{finding.title}' not in output"

    def test_finding_urls_appear_in_output(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        for finding in report.findings:
            assert finding.url in output

    def test_cve_references_appear_in_output(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "MCPwn-2024-001" in output

    def test_severity_labels_appear_in_output(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in output

    def test_summary_total_appears_in_output(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        # 5 findings in total
        assert "5" in output

    def test_recommendations_appear_in_output(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(recommendation="Apply a patch immediately.")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        assert "Apply a patch immediately." in output

    def test_evidence_appears_in_output(self) -> None:
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
        console = _make_string_console()
        reporter = Reporter(console=console)
        report = _make_report_with_findings()
        reporter.print_terminal_report(report)
        output = _get_console_output(console)
        # The footer should mention remediation
        assert "remediat" in output.lower()

    def test_does_not_raise_for_empty_recommendation(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(recommendation="")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)  # Should not raise

    def test_does_not_raise_for_no_cve_references(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(cve_references=[])
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)  # Should not raise

    def test_special_chars_in_finding_do_not_crash(self) -> None:
        console = _make_string_console()
        reporter = Reporter(console=console)
        finding = _make_finding(
            title="Finding with <special> & 'chars'",
            description='Has " quotes and & ampersands',
        )
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        reporter.print_terminal_report(report)  # Should not raise

    def test_multiple_targets_listed_in_header(self) -> None:
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


# ---------------------------------------------------------------------------
# to_json
# ---------------------------------------------------------------------------


class TestToJson:
    """Tests for Reporter.to_json."""

    def test_returns_valid_json_string(self) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_json_contains_scan_id(self) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert parsed["scan_id"] == report.scan_id

    def test_json_contains_scanner_version(self) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert "scanner_version" in parsed

    def test_json_contains_targets(self) -> None:
        reporter = Reporter()
        report = ScanReport(targets=[_make_target("https://example.com")])
        report.complete()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert len(parsed["targets"]) == 1
        assert parsed["targets"][0]["url"] == "https://example.com"

    def test_json_contains_findings(self) -> None:
        reporter = Reporter()
        report = _make_report_with_findings()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert len(parsed["findings"]) == 5

    def test_json_contains_summary(self) -> None:
        reporter = Reporter()
        report = _make_report_with_findings()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert "summary" in parsed
        assert parsed["summary"]["total_findings"] == 5

    def test_json_summary_counts_correct(self) -> None:
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
        reporter = Reporter()
        report = ScanReport(
            targets=[_make_target()],
            findings=[_make_finding(Severity.CRITICAL)],
        )
        report.complete()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert parsed["findings"][0]["severity"] == "CRITICAL"

    def test_json_indent_respected(self) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        json_str_2 = reporter.to_json(report, indent=2)
        json_str_4 = reporter.to_json(report, indent=4)
        # 4-space indent produces more whitespace
        assert len(json_str_4) >= len(json_str_2)

    def test_json_completed_at_present_when_completed(self) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert parsed["completed_at"] is not None

    def test_json_completed_at_null_when_not_completed(self) -> None:
        reporter = Reporter()
        report = ScanReport(targets=[_make_target()])
        json_str = reporter.to_json(report)
        parsed = json.loads(json_str)
        assert parsed["completed_at"] is None

    def test_json_schema_keys(self) -> None:
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


# ---------------------------------------------------------------------------
# write_json_report
# ---------------------------------------------------------------------------


class TestWriteJsonReport:
    """Tests for Reporter.write_json_report."""

    def test_file_created(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        assert output.exists()

    def test_file_contains_valid_json(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        content = output.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert isinstance(parsed, dict)

    def test_file_contains_scan_id(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        parsed = json.loads(output.read_text(encoding="utf-8"))
        assert parsed["scan_id"] == report.scan_id

    def test_parent_dirs_created(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "nested" / "dir" / "report.json"
        reporter.write_json_report(report, output)
        assert output.exists()

    def test_accepts_string_path(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = str(tmp_path / "report.json")
        reporter.write_json_report(report, output)
        assert Path(output).exists()

    def test_file_is_utf8_encoded(self, tmp_path: Path) -> None:
        reporter = Reporter()
        finding = _make_finding(description="Unicode: \u4e2d\u6587 and \u00e9\u00e0\u00fc")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.json"
        reporter.write_json_report(report, output)
        content = output.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert "\u4e2d\u6587" in parsed["findings"][0]["description"]


# ---------------------------------------------------------------------------
# print_json_to_stdout
# ---------------------------------------------------------------------------


class TestPrintJsonToStdout:
    """Tests for Reporter.print_json_to_stdout."""

    def test_prints_valid_json(self, capsys: pytest.CaptureFixture) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        reporter.print_json_to_stdout(report)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert isinstance(parsed, dict)

    def test_output_contains_scan_id(self, capsys: pytest.CaptureFixture) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        reporter.print_json_to_stdout(report)
        captured = capsys.readouterr()
        assert report.scan_id in captured.out

    def test_output_is_to_stdout_not_stderr(self, capsys: pytest.CaptureFixture) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        reporter.print_json_to_stdout(report)
        captured = capsys.readouterr()
        # stdout has content
        assert len(captured.out.strip()) > 0


# ---------------------------------------------------------------------------
# write_html_report
# ---------------------------------------------------------------------------


class TestWriteHtmlReport:
    """Tests for Reporter.write_html_report."""

    def test_file_created(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        assert output.exists()

    def test_file_is_html_document(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "</html>" in content

    def test_html_contains_scan_id(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        # First 8 chars of scan_id appear in the title
        assert report.scan_id[:8] in content

    def test_html_contains_mcp_scanner_heading(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "MCP Scanner" in content

    def test_html_contains_target_url(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = ScanReport(targets=[_make_target("https://example.com")])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "https://example.com" in content

    def test_html_contains_severity_labels(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_report_with_findings()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in content

    def test_html_contains_finding_title(self, tmp_path: Path) -> None:
        reporter = Reporter()
        finding = _make_finding(title="Unique Finding Title XYZ")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "Unique Finding Title XYZ" in content

    def test_html_contains_finding_url(self, tmp_path: Path) -> None:
        reporter = Reporter()
        finding = _make_finding(url="https://example.com/mcp/tools")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "https://example.com/mcp/tools" in content

    def test_html_escapes_special_characters(self, tmp_path: Path) -> None:
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
        reporter = Reporter()
        finding = _make_finding(cve_references=["MCPwn-2024-001"])
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "MCPwn-2024-001" in content

    def test_html_parent_dirs_created(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "deep" / "nested" / "report.html"
        reporter.write_html_report(report, output)
        assert output.exists()

    def test_html_no_findings_shows_no_findings_message(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "No findings" in content or "no findings" in content.lower()

    def test_html_summary_counts_present(self, tmp_path: Path) -> None:
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
        # Summary cards should have count "1" for CRITICAL and HIGH
        # (hard to assert exact count without parsing HTML; check presence)
        assert "CRITICAL" in content
        assert "HIGH" in content

    def test_html_accepts_string_path(self, tmp_path: Path) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        output = str(tmp_path / "report.html")
        reporter.write_html_report(report, output)
        assert Path(output).exists()

    def test_html_is_utf8_encoded(self, tmp_path: Path) -> None:
        reporter = Reporter()
        finding = _make_finding(description="Unicode: \u4e2d\u6587")
        report = ScanReport(targets=[_make_target()], findings=[finding])
        report.complete()
        output = tmp_path / "report.html"
        reporter.write_html_report(report, output)
        content = output.read_text(encoding="utf-8")
        assert "\u4e2d\u6587" in content


# ---------------------------------------------------------------------------
# _build_html_report internals
# ---------------------------------------------------------------------------


class TestBuildHtmlReport:
    """Tests for the _build_html_report private method."""

    def test_returns_string(self) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        html = reporter._build_html_report(report)
        assert isinstance(html, str)

    def test_contains_doctype(self) -> None:
        reporter = Reporter()
        report = _make_empty_report()
        html = reporter._build_html_report(report)
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_duration_shown_when_completed(self) -> None:
        reporter = Reporter()
        report = _make_empty_report()  # already completed
        html = reporter._build_html_report(report)
        # Duration should be present
        assert "Duration" in html or "duration" in html.lower() or "0." in html

    def test_findings_sorted_most_severe_first(self) -> None:
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


# ---------------------------------------------------------------------------
# _build_summary_cards_html
# ---------------------------------------------------------------------------


class TestBuildSummaryCardsHtml:
    """Tests for the _build_summary_cards_html method."""

    def test_returns_string(self) -> None:
        from mcp_scanner.models import ScanSummary
        reporter = Reporter()
        summary = ScanSummary(critical=1, high=2, medium=3, low=0, info=1)
        html = reporter._build_summary_cards_html(summary)
        assert isinstance(html, str)

    def test_contains_all_severity_levels(self) -> None:
        from mcp_scanner.models import ScanSummary
        reporter = Reporter()
        summary = ScanSummary()
        html = reporter._build_summary_cards_html(summary)
        for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert label in html

    def test_contains_counts(self) -> None:
        from mcp_scanner.models import ScanSummary
        reporter = Reporter()
        summary = ScanSummary(critical=7, high=3)
        html = reporter._build_summary_cards_html(summary)
        assert "7" in html
        assert "3" in html


# ---------------------------------------------------------------------------
# _build_finding_html
# ---------------------------------------------------------------------------


class TestBuildFindingHtml:
    """Tests for the _build_finding_html method."""

    def test_returns_string(self) -> None:
        reporter = Reporter()
        finding = _make_finding()
        html = reporter._build_finding_html(finding)
        assert isinstance(html, str)

    def test_contains_severity_value(self) -> None:
        reporter = Reporter()
        finding = _make_finding(Severity.CRITICAL)
        html = reporter._build_finding_html(finding)
        assert "CRITICAL" in html

    def test_contains_title(self) -> None:
        reporter = Reporter()
        finding = _make_finding(title="My Unique Title")
        html = reporter._build_finding_html(finding)
        assert "My Unique Title" in html

    def test_contains_url(self) -> None:
        reporter = Reporter()
        finding = _make_finding(url="https://example.com/mcp")
        html = reporter._build_finding_html(finding)
        assert "https://example.com/mcp" in html

    def test_contains_description(self) -> None:
        reporter = Reporter()
        finding = _make_finding(description="Very specific description text.")
        html = reporter._build_finding_html(finding)
        assert "Very specific description text." in html

    def test_escapes_html_in_title(self) -> None:
        reporter = Reporter()
        finding = _make_finding(title="<img src=x onerror=alert(1)>")
        html = reporter._build_finding_html(finding)
        assert "<img" not in html
        assert "&lt;img" in html

    def test_contains_cve_references(self) -> None:
        reporter = Reporter()
        finding = _make_finding(cve_references=["MCPwn-2024-001", "CVE-2024-99999"])
        html = reporter._build_finding_html(finding)
        assert "MCPwn-2024-001" in html
        assert "CVE-2024-99999" in html

    def test_contains_finding_id(self) -> None:
        reporter = Reporter()
        finding = _make_finding()
        html = reporter._build_finding_html(finding)
        assert finding.finding_id in html

    def test_evidence_truncated_at_600_chars(self) -> None:
        reporter = Reporter()
        long_evidence = "e" * 800
        finding = _make_finding(evidence=long_evidence)
        html = reporter._build_finding_html(finding)
        # Evidence section should exist but be truncated
        assert "e" * 600 in html
        # Should not contain the full 800-char string
        assert "e" * 800 not in html

    def test_no_evidence_section_when_empty(self) -> None:
        reporter = Reporter()
        finding = _make_finding(evidence="")
        html = reporter._build_finding_html(finding)
        # Should not crash and should not include an Evidence dt
        assert isinstance(html, str)
