"""Report generation for MCP Scanner.

Produces color-coded Rich terminal summaries and machine-readable
JSON (and optional HTML) security reports from completed ScanReport objects.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from mcp_scanner.models import Finding, ScanReport, Severity


SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}

SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class Reporter:
    """Generates security reports from ScanReport objects.

    Supports Rich terminal output (colored, human-readable) and
    machine-readable JSON output for CI/CD integration.
    """

    def __init__(self, console: Console | None = None) -> None:
        """Initialize the reporter.

        Args:
            console: Optional Rich Console instance; creates a default one if not provided.
        """
        self.console = console or Console(stderr=False)

    def print_terminal_report(self, report: ScanReport) -> None:
        """Print a full color-coded security report to the terminal.

        Args:
            report: The completed ScanReport to display.
        """
        self._print_header(report)
        self._print_summary(report)

        if not report.findings:
            self.console.print(
                Panel(
                    "[green]No MCP endpoints or vulnerabilities found.[/green]\n"
                    "This may mean the target is secure, or the endpoints use non-standard paths.",
                    title="[green]Scan Complete[/green]",
                    border_style="green",
                )
            )
            return

        self._print_findings_by_severity(report)

    def _print_header(self, report: ScanReport) -> None:
        """Print the report header banner."""
        duration = ""
        if report.completed_at and report.started_at:
            delta = report.completed_at - report.started_at
            duration = f" | Duration: {delta.total_seconds():.1f}s"

        header_text = Text()
        header_text.append("MCP Scanner Security Report", style="bold white")
        header_text.append(f"\nScan ID: {report.scan_id}", style="dim")
        header_text.append(f"\nStarted: {report.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}{duration}", style="dim")
        header_text.append(f"\nTargets scanned: {len(report.targets)}", style="dim")

        self.console.print(Panel(header_text, title="[bold cyan]🔍 MCP Scanner[/bold cyan]", border_style="cyan"))

    def _print_summary(self, report: ScanReport) -> None:
        """Print the findings summary table."""
        summary = report.get_summary()

        table = Table(
            title="Findings Summary",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white",
        )
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Risk", width=40)

        severity_info = [
            (Severity.CRITICAL, summary.critical, "Immediate action required - system is compromised"),
            (Severity.HIGH, summary.high, "Urgent remediation needed"),
            (Severity.MEDIUM, summary.medium, "Should be addressed soon"),
            (Severity.LOW, summary.low, "Address in normal workflow"),
            (Severity.INFO, summary.info, "Informational, no action required"),
        ]

        for severity, count, risk in severity_info:
            color = SEVERITY_COLORS[severity]
            emoji = SEVERITY_EMOJI[severity]
            count_str = str(count) if count == 0 else f"[{color}]{count}[/{color}]"
            table.add_row(
                f"{emoji} [{color}]{severity.value}[/{color}]",
                count_str,
                risk if count > 0 else f"[dim]{risk}[/dim]",
            )

        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{summary.total_findings}[/bold]",
            f"Endpoints probed: {summary.endpoints_probed}",
        )

        self.console.print(table)
        self.console.print()

    def _print_findings_by_severity(self, report: ScanReport) -> None:
        """Print detailed finding information grouped by severity."""
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

        for severity in severity_order:
            findings = report.get_findings_by_severity(severity)
            if not findings:
                continue

            color = SEVERITY_COLORS[severity]
            emoji = SEVERITY_EMOJI[severity]

            self.console.print(
                f"\n{emoji} [{color}][bold]{severity.value} FINDINGS ({len(findings)})[/bold][/{color}]"
            )
            self.console.print("─" * 60)

            for i, finding in enumerate(findings, 1):
                self._print_finding(finding, index=i, color=color)

    def _print_finding(
        self,
        finding: Finding,
        index: int,
        color: str,
    ) -> None:
        """Print a single finding in detail."""
        self.console.print(f"\n  [{color}][{index}] {finding.title}[/{color}]")
        self.console.print(f"      [dim]URL:[/dim] {finding.url}")
        self.console.print(f"      [dim]Description:[/dim] {finding.description}")

        if finding.evidence:
            evidence_snippet = finding.evidence[:300] + "..." if len(finding.evidence) > 300 else finding.evidence
            self.console.print(f"      [dim]Evidence:[/dim] [italic]{evidence_snippet}[/italic]")

        if finding.recommendation:
            self.console.print(f"      [dim]Recommendation:[/dim] [green]{finding.recommendation}[/green]")

        if finding.cve_references:
            refs = ", ".join(finding.cve_references)
            self.console.print(f"      [dim]References:[/dim] [yellow]{refs}[/yellow]")

    def to_json(self, report: ScanReport, indent: int = 2) -> str:
        """Serialize the scan report to a JSON string.

        Args:
            report: The completed ScanReport.
            indent: JSON indentation level.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)

    def write_json_report(
        self,
        report: ScanReport,
        output_path: str | Path,
        indent: int = 2,
    ) -> None:
        """Write the scan report to a JSON file.

        Args:
            report: The completed ScanReport.
            output_path: Path to the output file.
            indent: JSON indentation level.

        Raises:
            OSError: If the file cannot be written.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        json_content = self.to_json(report, indent=indent)
        path.write_text(json_content, encoding="utf-8")

    def write_html_report(self, report: ScanReport, output_path: str | Path) -> None:
        """Write the scan report as a standalone HTML file.

        Args:
            report: The completed ScanReport.
            output_path: Path to the output HTML file.

        Raises:
            OSError: If the file cannot be written.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        html_content = self._build_html_report(report)
        path.write_text(html_content, encoding="utf-8")

    def _build_html_report(self, report: ScanReport) -> str:
        """Build an HTML string for the security report."""
        summary = report.get_summary()
        duration = ""
        if report.completed_at and report.started_at:
            delta = report.completed_at - report.started_at
            duration = f"{delta.total_seconds():.1f}s"

        severity_badge_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#0891b2",
            "INFO": "#6366f1",
        }

        findings_html = ""
        for finding in sorted(report.findings, key=lambda f: f.severity, reverse=True):
            color = severity_badge_colors.get(finding.severity.value, "#6b7280")
            cve_refs = ", ".join(finding.cve_references) if finding.cve_references else "N/A"
            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity-badge" style="background:{color}">{finding.severity.value}</span>
                    <span class="finding-title">{self._html_escape(finding.title)}</span>
                </div>
                <div class="finding-body">
                    <p><strong>URL:</strong> <code>{self._html_escape(finding.url)}</code></p>
                    <p><strong>Description:</strong> {self._html_escape(finding.description)}</p>
                    <p><strong>Evidence:</strong> <em>{self._html_escape(finding.evidence[:500])}</em></p>
                    <p><strong>Recommendation:</strong> {self._html_escape(finding.recommendation)}</p>
                    <p><strong>References:</strong> {self._html_escape(cve_refs)}</p>
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Scanner Report - {report.scan_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                margin: 0; padding: 20px; background: #0f172a; color: #e2e8f0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #1e40af; padding-bottom: 10px; }}
        h2 {{ color: #94a3b8; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 20px 0; }}
        .summary-card {{ background: #1e293b; border-radius: 8px; padding: 15px; text-align: center; }}
        .summary-card .count {{ font-size: 2em; font-weight: bold; }}
        .finding {{ background: #1e293b; border-radius: 8px; margin: 15px 0; overflow: hidden; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; padding: 12px 15px;
                           background: #0f172a; }}
        .finding-title {{ font-weight: bold; font-size: 1.1em; }}
        .finding-body {{ padding: 15px; }}
        .severity-badge {{ padding: 4px 10px; border-radius: 4px; color: white;
                           font-weight: bold; font-size: 0.85em; }}
        code {{ background: #334155; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
        .meta {{ color: #64748b; font-size: 0.9em; margin-top: 20px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 MCP Scanner Security Report</h1>
    <div class="meta">
        <p>Scan ID: {report.scan_id} | Version: {report.scanner_version}</p>
        <p>Started: {report.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
           {f'| Duration: {duration}' if duration else ''}</p>
        <p>Targets: {', '.join(t.url for t in report.targets)}</p>
    </div>
    <h2>Summary</h2>
    <div class="summary">
        <div class="summary-card">
            <div class="count" style="color:#dc2626">{summary.critical}</div>
            <div>CRITICAL</div>
        </div>
        <div class="summary-card">
            <div class="count" style="color:#ea580c">{summary.high}</div>
            <div>HIGH</div>
        </div>
        <div class="summary-card">
            <div class="count" style="color:#ca8a04">{summary.medium}</div>
            <div>MEDIUM</div>
        </div>
        <div class="summary-card">
            <div class="count" style="color:#0891b2">{summary.low}</div>
            <div>LOW</div>
        </div>
        <div class="summary-card">
            <div class="count" style="color:#6366f1">{summary.info}</div>
            <div>INFO</div>
        </div>
    </div>
    <h2>Findings ({summary.total_findings})</h2>
    {findings_html if findings_html else '<p>No findings detected.</p>'}
</div>
</body>
</html>"""

    @staticmethod
    def _html_escape(text: str) -> str:
        """Escape HTML special characters in a string."""
        return (
            text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    def print_json_to_stdout(self, report: ScanReport) -> None:
        """Print the JSON report directly to stdout.

        Args:
            report: The completed ScanReport.
        """
        print(self.to_json(report))
