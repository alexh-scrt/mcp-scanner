"""Report generation for MCP Scanner.

Produces color-coded Rich terminal summaries and machine-readable
JSON (and optional HTML) security reports from completed ScanReport objects.

The :class:`Reporter` class is the main entry point.  It accepts a
:class:`~mcp_scanner.models.ScanReport` and can:

* Print a color-coded summary to a Rich :class:`~rich.console.Console`.
* Serialise the report to a JSON string or file.
* Write a self-contained dark-themed HTML report file.

All public methods are synchronous; they do not perform I/O beyond writing
to the provided console or to a file path.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.padding import Padding

from mcp_scanner.models import Finding, ScanReport, ScanSummary, Severity


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maps each :class:`~mcp_scanner.models.Severity` level to a Rich markup
#: colour string used throughout terminal output.
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}

#: Maps each severity to a unicode emoji bullet for terminal output.
SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "\U0001f534",  # 🔴
    Severity.HIGH: "\U0001f7e0",      # 🟠
    Severity.MEDIUM: "\U0001f7e1",    # 🟡
    Severity.LOW: "\U0001f535",       # 🔵
    Severity.INFO: "\u26aa",          # ⚪
}

#: CSS hex colours used for severity badges in the HTML report.
SEVERITY_HTML_COLORS: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#0891b2",
    "INFO": "#6366f1",
}

#: Human-readable risk descriptions used in the summary table.
SEVERITY_RISK_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "Immediate action required – system likely compromised",
    Severity.HIGH: "Urgent remediation needed",
    Severity.MEDIUM: "Should be addressed soon",
    Severity.LOW: "Address in normal workflow",
    Severity.INFO: "Informational, no action required",
}


# ---------------------------------------------------------------------------
# Reporter class
# ---------------------------------------------------------------------------


class Reporter:
    """Generates security reports from :class:`~mcp_scanner.models.ScanReport` objects.

    Supports:

    * Rich terminal output – color-coded, human-readable summary with
      per-finding details grouped by severity.
    * JSON output – machine-readable report serialised via
      :meth:`~mcp_scanner.models.ScanReport.to_dict`.  Can be written to
      a file or returned as a string.
    * HTML output – a self-contained dark-themed HTML report suitable for
      sharing with stakeholders.

    Usage::

        reporter = Reporter()
        reporter.print_terminal_report(report)
        reporter.write_json_report(report, "report.json")
        reporter.write_html_report(report, "report.html")
    """

    def __init__(self, console: Console | None = None) -> None:
        """Initialise the reporter.

        Args:
            console: Optional :class:`~rich.console.Console` instance.  When
                not provided a default stdout console is created.  Callers
                can pass a console configured for stderr, a no-colour
                console, or a ``StringIO``-backed console for testing.
        """
        self.console: Console = console or Console()

    # ------------------------------------------------------------------
    # Terminal report
    # ------------------------------------------------------------------

    def print_terminal_report(self, report: ScanReport) -> None:
        """Print a full color-coded security report to the terminal.

        Renders the following sections in order:

        1. Header banner with scan metadata.
        2. Findings summary table (counts by severity).
        3. Per-severity finding detail sections (omitted when no findings).
        4. Footer with remediation priority guidance.

        Args:
            report: The completed :class:`~mcp_scanner.models.ScanReport`
                to display.
        """
        self._print_header(report)
        self._print_summary(report)

        if not report.findings:
            self.console.print(
                Panel(
                    "[green]No MCP endpoints or vulnerabilities were detected.[/green]\n"
                    "[dim]This may mean the target is secure, or that MCP endpoints "
                    "are hosted at non-standard paths not covered by the probe set.\n"
                    "Consider running with a custom wordlist (--wordlist) to extend coverage.[/dim]",
                    title="[green]\u2713 Scan Complete – No Findings[/green]",
                    border_style="green",
                    padding=(1, 2),
                )
            )
            return

        self._print_findings_by_severity(report)
        self._print_footer(report)

    def _print_header(self, report: ScanReport) -> None:
        """Print the scan header banner panel.

        Args:
            report: The scan report providing metadata for the header.
        """
        duration_str = ""
        if report.completed_at and report.started_at:
            delta = report.completed_at - report.started_at
            seconds = delta.total_seconds()
            if seconds < 60:
                duration_str = f" | Duration: {seconds:.1f}s"
            else:
                minutes = int(seconds // 60)
                remaining_secs = seconds % 60
                duration_str = f" | Duration: {minutes}m {remaining_secs:.0f}s"

        target_urls = ", ".join(t.url for t in report.targets) or "(none)"

        header = Text()
        header.append("MCP Scanner Security Report\n", style="bold white")
        header.append(f"Scan ID:   ", style="dim")
        header.append(f"{report.scan_id}\n", style="white")
        header.append(f"Version:   ", style="dim")
        header.append(f"mcp-scanner {report.scanner_version}\n", style="white")
        header.append(f"Started:   ", style="dim")
        header.append(
            f"{report.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}{duration_str}\n",
            style="white",
        )
        header.append(f"Targets:   ", style="dim")
        header.append(target_urls, style="cyan")

        self.console.print(
            Panel(
                header,
                title="[bold cyan]\U0001f50d MCP Scanner[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

    def _print_summary(self, report: ScanReport) -> None:
        """Print the findings summary table.

        The table lists each severity level with its count and a brief risk
        description, followed by a total row.

        Args:
            report: The scan report from which the summary is computed.
        """
        summary = report.get_summary()

        table = Table(
            title="Findings Summary",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white",
            title_style="bold white",
            border_style="bright_black",
            padding=(0, 1),
        )
        table.add_column("Severity", style="bold", width=14, no_wrap=True)
        table.add_column("Count", justify="right", width=7)
        table.add_column("Risk", min_width=42)

        severity_rows: list[tuple[Severity, int]] = [
            (Severity.CRITICAL, summary.critical),
            (Severity.HIGH, summary.high),
            (Severity.MEDIUM, summary.medium),
            (Severity.LOW, summary.low),
            (Severity.INFO, summary.info),
        ]

        for severity, count in severity_rows:
            color = SEVERITY_COLORS[severity]
            emoji = SEVERITY_EMOJI[severity]
            risk_label = SEVERITY_RISK_LABELS[severity]

            if count > 0:
                count_markup = f"[{color}][bold]{count}[/bold][/{color}]"
                risk_markup = f"[{color}]{risk_label}[/{color}]"
            else:
                count_markup = "[dim]0[/dim]"
                risk_markup = f"[dim]{risk_label}[/dim]"

            table.add_row(
                f"{emoji} [{color}]{severity.value}[/{color}]",
                count_markup,
                risk_markup,
            )

        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{summary.total_findings}[/bold]",
            f"[dim]Across {summary.targets_scanned} target(s) "
            f"| {summary.endpoints_found} unique endpoint(s) found[/dim]",
        )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def _print_findings_by_severity(self, report: ScanReport) -> None:
        """Print detailed finding information grouped by severity level.

        Iterates severity levels from CRITICAL down to INFO.  Levels with
        no findings are skipped entirely.

        Args:
            report: The scan report whose findings are to be displayed.
        """
        severity_order: list[Severity] = [
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
            section_title = (
                f"{emoji} [{color}][bold]{severity.value} FINDINGS "
                f"({len(findings)})[/bold][/{color}]"
            )

            self.console.print(Rule(section_title, style=color.replace("bold ", "")))

            for index, finding in enumerate(findings, start=1):
                self._print_finding(finding, index=index, color=color)

            self.console.print()

    def _print_finding(
        self,
        finding: Finding,
        index: int,
        color: str,
    ) -> None:
        """Print a single finding in a formatted detail block.

        Each finding is rendered as an indented block showing the title,
        URL, description, evidence snippet, recommendation, and any CVE
        references.

        Args:
            finding: The :class:`~mcp_scanner.models.Finding` to display.
            index: 1-based index within the current severity group.
            color: Rich markup colour string for the severity level.
        """
        self.console.print(
            Padding(
                Text.assemble(
                    (f"[{index}] ", "bold dim"),
                    (finding.title, color),
                ),
                pad=(1, 0, 0, 2),
            )
        )

        indent = "      "  # 6 spaces

        self.console.print(f"{indent}[dim]URL:[/dim]         [link]{finding.url}[/link]")

        # Word-wrap long descriptions at ~100 chars per visual line.
        desc_lines = self._wrap_text(finding.description, width=90)
        if desc_lines:
            self.console.print(f"{indent}[dim]Description:[/dim]  {desc_lines[0]}")
            for line in desc_lines[1:]:
                self.console.print(f"{indent}               {line}")

        if finding.evidence:
            evidence_snippet = finding.evidence
            if len(evidence_snippet) > 400:
                evidence_snippet = evidence_snippet[:400] + "\u2026"
            evid_lines = self._wrap_text(evidence_snippet, width=88)
            if evid_lines:
                self.console.print(
                    f"{indent}[dim]Evidence:[/dim]     [italic dim]{evid_lines[0]}[/italic dim]"
                )
                for line in evid_lines[1:]:
                    self.console.print(
                        f"{indent}               [italic dim]{line}[/italic dim]"
                    )

        if finding.recommendation:
            rec_lines = self._wrap_text(finding.recommendation, width=90)
            if rec_lines:
                self.console.print(
                    f"{indent}[dim]Remediation:[/dim]  [green]{rec_lines[0]}[/green]"
                )
                for line in rec_lines[1:]:
                    self.console.print(f"{indent}               [green]{line}[/green]")

        if finding.cve_references:
            refs = ", ".join(finding.cve_references)
            self.console.print(f"{indent}[dim]References:[/dim]   [yellow]{refs}[/yellow]")

    def _print_footer(self, report: ScanReport) -> None:
        """Print a brief remediation priority footer.

        Only printed when there are findings.  Gives quick guidance on
        what to fix first.

        Args:
            report: The completed scan report.
        """
        summary = report.get_summary()
        lines: list[str] = []

        if summary.critical > 0:
            lines.append(
                f"[bold red]\u25cf {summary.critical} CRITICAL finding(s)[/bold red] – "
                "remediate immediately before continuing operation."
            )
        if summary.high > 0:
            lines.append(
                f"[red]\u25cf {summary.high} HIGH finding(s)[/red] – "
                "schedule remediation within 24 hours."
            )
        if summary.medium > 0:
            lines.append(
                f"[yellow]\u25cf {summary.medium} MEDIUM finding(s)[/yellow] – "
                "address in next sprint or release."
            )
        if summary.low > 0 or summary.info > 0:
            remaining = summary.low + summary.info
            lines.append(
                f"[cyan]\u25cf {remaining} LOW/INFO finding(s)[/cyan] – "
                "review and address in normal workflow."
            )

        if not lines:
            return

        footer_text = "\n".join(lines)
        self.console.print(
            Panel(
                footer_text,
                title="[bold white]Remediation Priority[/bold white]",
                border_style="bright_black",
                padding=(1, 2),
            )
        )

    # ------------------------------------------------------------------
    # JSON serialisation
    # ------------------------------------------------------------------

    def to_json(self, report: ScanReport, indent: int = 2) -> str:
        """Serialise the scan report to a pretty-printed JSON string.

        The JSON structure matches the schema documented in ``README.md``
        and is safe to pass to other tools or store in CI/CD artefacts.

        Args:
            report: The completed :class:`~mcp_scanner.models.ScanReport`.
            indent: JSON indentation level (default 2).

        Returns:
            UTF-8 compatible JSON string with the full report.
        """
        return json.dumps(
            report.to_dict(),
            indent=indent,
            ensure_ascii=False,
            default=str,  # Fallback for any non-serialisable types
        )

    def write_json_report(
        self,
        report: ScanReport,
        output_path: str | Path,
        indent: int = 2,
    ) -> None:
        """Write the scan report to a JSON file.

        Parent directories are created automatically if they do not exist.

        Args:
            report: The completed :class:`~mcp_scanner.models.ScanReport`.
            output_path: Filesystem path for the output ``.json`` file.
            indent: JSON indentation level (default 2).

        Raises:
            OSError: If the file cannot be created or written.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        json_content = self.to_json(report, indent=indent)
        path.write_text(json_content, encoding="utf-8")

    def print_json_to_stdout(self, report: ScanReport) -> None:
        """Write the JSON report directly to stdout via ``print``.

        This bypasses the Rich console so that the output is clean and
        pipe-friendly.  No ANSI codes or Rich markup are included.

        Args:
            report: The completed :class:`~mcp_scanner.models.ScanReport`.
        """
        print(self.to_json(report))

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def write_html_report(
        self,
        report: ScanReport,
        output_path: str | Path,
    ) -> None:
        """Write a self-contained HTML security report to a file.

        The HTML report is a dark-themed, single-file document that
        includes all findings, a summary table, and scan metadata.  It
        has no external dependencies and can be shared as a standalone
        attachment.

        Parent directories are created automatically if they do not exist.

        Args:
            report: The completed :class:`~mcp_scanner.models.ScanReport`.
            output_path: Filesystem path for the output ``.html`` file.

        Raises:
            OSError: If the file cannot be created or written.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        html_content = self._build_html_report(report)
        path.write_text(html_content, encoding="utf-8")

    def _build_html_report(self, report: ScanReport) -> str:
        """Build and return the full HTML report string.

        Args:
            report: The completed :class:`~mcp_scanner.models.ScanReport`.

        Returns:
            Complete HTML document as a string.
        """
        summary = report.get_summary()

        # --- Duration -------------------------------------------------------
        duration_str = ""
        if report.completed_at and report.started_at:
            delta = report.completed_at - report.started_at
            seconds = delta.total_seconds()
            if seconds < 60:
                duration_str = f"{seconds:.1f}s"
            else:
                duration_str = f"{int(seconds // 60)}m {int(seconds % 60)}s"

        # --- Target list ----------------------------------------------------
        target_list_html = ""
        for target in report.targets:
            target_list_html += (
                f'<li><a href="{self._html_escape(target.url)}" '
                f'target="_blank" rel="noopener noreferrer">'
                f"{self._html_escape(target.url)}</a></li>\n"
            )

        # --- Summary cards --------------------------------------------------
        summary_cards_html = self._build_summary_cards_html(summary)

        # --- Findings list --------------------------------------------------
        sorted_findings = sorted(
            report.findings, key=lambda f: f.severity, reverse=True
        )
        findings_html = ""
        if sorted_findings:
            for finding in sorted_findings:
                findings_html += self._build_finding_html(finding)
        else:
            findings_html = (
                '<p class="no-findings">\u2713 No findings detected. '
                "The target appears to have no exposed MCP endpoints.</p>"
            )

        # --- Completed at ---------------------------------------------------
        completed_at_str = (
            report.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if report.completed_at
            else "In progress"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Scanner Report &ndash; {self._html_escape(report.scan_id[:8])}</title>
    <style>
        *, *::before, *::after {{ box-sizing: border-box; }}
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface2: #334155;
            --border: #475569;
            --text: #e2e8f0;
            --text-dim: #94a3b8;
            --link: #38bdf8;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #0891b2;
            --info: #6366f1;
            --green: #22c55e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                         'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}
        a {{ color: var(--link); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        code {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo,
                         monospace;
            background: var(--surface2);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.88em;
            word-break: break-all;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 24px 20px; }}
        /* Header */
        .report-header {{
            border-bottom: 2px solid var(--link);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .report-header h1 {{
            color: var(--link);
            font-size: 1.8rem;
            margin: 0 0 8px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 6px;
            color: var(--text-dim);
            font-size: 0.88rem;
        }}
        .meta-grid span {{ color: var(--text); }}
        /* Summary cards */
        .summary-section {{ margin: 24px 0; }}
        .summary-section h2 {{ color: var(--text-dim); font-size: 1.1rem;
                               text-transform: uppercase; letter-spacing: 0.05em;
                               margin: 0 0 12px; }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
        }}
        @media (max-width: 640px) {{
            .summary-cards {{ grid-template-columns: repeat(3, 1fr); }}
        }}
        .summary-card {{
            background: var(--surface);
            border-radius: 8px;
            padding: 14px 10px;
            text-align: center;
            border-top: 3px solid transparent;
        }}
        .summary-card .count {{
            font-size: 2.2rem;
            font-weight: 700;
            line-height: 1;
        }}
        .summary-card .label {{
            font-size: 0.78rem;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-top: 4px;
        }}
        .card-critical {{ border-color: var(--critical); }}
        .card-critical .count {{ color: var(--critical); }}
        .card-high {{ border-color: var(--high); }}
        .card-high .count {{ color: var(--high); }}
        .card-medium {{ border-color: var(--medium); }}
        .card-medium .count {{ color: var(--medium); }}
        .card-low {{ border-color: var(--low); }}
        .card-low .count {{ color: var(--low); }}
        .card-info {{ border-color: var(--info); }}
        .card-info .count {{ color: var(--info); }}
        /* Findings */
        .findings-section {{ margin: 24px 0; }}
        .findings-section h2 {{ color: var(--text-dim); font-size: 1.1rem;
                               text-transform: uppercase; letter-spacing: 0.05em;
                               margin: 0 0 16px; }}
        .finding {{
            background: var(--surface);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
            border-left: 4px solid transparent;
        }}
        .finding-CRITICAL {{ border-left-color: var(--critical); }}
        .finding-HIGH {{ border-left-color: var(--high); }}
        .finding-MEDIUM {{ border-left-color: var(--medium); }}
        .finding-LOW {{ border-left-color: var(--low); }}
        .finding-INFO {{ border-left-color: var(--info); }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            background: rgba(0,0,0,0.2);
            cursor: pointer;
            user-select: none;
        }}
        .finding-header:hover {{ background: rgba(0,0,0,0.3); }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 9px;
            border-radius: 4px;
            color: #fff;
            font-weight: 700;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            white-space: nowrap;
            flex-shrink: 0;
        }}
        .finding-title {{ font-weight: 600; font-size: 1rem; flex: 1; }}
        .finding-url {{ font-size: 0.82rem; color: var(--text-dim); margin-top: 2px; }}
        .finding-body {{
            padding: 14px 16px;
            border-top: 1px solid var(--border);
        }}
        .finding-body dl {{ margin: 0; }}
        .finding-body dt {{
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-dim);
            margin-top: 12px;
        }}
        .finding-body dt:first-child {{ margin-top: 0; }}
        .finding-body dd {{
            margin: 4px 0 0;
            font-size: 0.92rem;
            word-break: break-word;
        }}
        .evidence-text {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.82rem;
            background: var(--surface2);
            padding: 8px 12px;
            border-radius: 4px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .recommendation {{ color: #86efac; }}
        .cve-ref {{
            display: inline-block;
            background: var(--surface2);
            color: #fde68a;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.82rem;
            margin-right: 4px;
        }}
        .no-findings {{
            color: var(--green);
            font-size: 1rem;
            padding: 20px;
            background: var(--surface);
            border-radius: 8px;
            border-left: 4px solid var(--green);
        }}
        /* Targets */
        .targets-section {{ margin: 24px 0; }}
        .targets-section h2 {{ color: var(--text-dim); font-size: 1.1rem;
                              text-transform: uppercase; letter-spacing: 0.05em;
                              margin: 0 0 10px; }}
        .targets-section ul {{ margin: 0; padding-left: 20px; }}
        .targets-section li {{ margin: 4px 0; font-size: 0.92rem; }}
        /* Footer */
        .report-footer {{
            border-top: 1px solid var(--border);
            margin-top: 32px;
            padding-top: 16px;
            font-size: 0.80rem;
            color: var(--text-dim);
            text-align: center;
        }}
    </style>
</head>
<body>
<div class="container">
    <!-- Header -->
    <div class="report-header">
        <h1>&#128269; MCP Scanner Security Report</h1>
        <div class="meta-grid">
            <div>Scan ID: <span>{self._html_escape(report.scan_id)}</span></div>
            <div>Version: <span>mcp-scanner {self._html_escape(report.scanner_version)}</span></div>
            <div>Started: <span>{self._html_escape(report.started_at.strftime('%Y-%m-%d %H:%M:%S UTC'))}</span></div>
            <div>Completed: <span>{self._html_escape(completed_at_str)}</span></div>
            {f'<div>Duration: <span>{self._html_escape(duration_str)}</span></div>' if duration_str else ''}
        </div>
    </div>

    <!-- Targets -->
    <div class="targets-section">
        <h2>Scanned Targets ({len(report.targets)})</h2>
        <ul>
            {target_list_html}
        </ul>
    </div>

    <!-- Summary cards -->
    <div class="summary-section">
        <h2>Summary</h2>
        {summary_cards_html}
    </div>

    <!-- Findings -->
    <div class="findings-section">
        <h2>Findings ({summary.total_findings})</h2>
        {findings_html}
    </div>

    <!-- Footer -->
    <div class="report-footer">
        <p>Generated by <strong>mcp-scanner {self._html_escape(report.scanner_version)}</strong>
        &mdash; for authorised security testing only.</p>
    </div>
</div>
</body>
</html>"""

    def _build_summary_cards_html(self, summary: ScanSummary) -> str:
        """Build the HTML for the five severity summary cards.

        Args:
            summary: Pre-computed :class:`~mcp_scanner.models.ScanSummary`.

        Returns:
            HTML string containing the cards grid.
        """
        rows = [
            ("CRITICAL", summary.critical, "card-critical"),
            ("HIGH", summary.high, "card-high"),
            ("MEDIUM", summary.medium, "card-medium"),
            ("LOW", summary.low, "card-low"),
            ("INFO", summary.info, "card-info"),
        ]
        cards = ""
        for label, count, css_class in rows:
            cards += (
                f'<div class="summary-card {css_class}">'
                f'<div class="count">{count}</div>'
                f'<div class="label">{label}</div>'
                f"</div>\n"
            )
        return f'<div class="summary-cards">\n{cards}</div>'

    def _build_finding_html(self, finding: Finding) -> str:
        """Build the HTML block for a single finding.

        Args:
            finding: The :class:`~mcp_scanner.models.Finding` to render.

        Returns:
            HTML string for the finding card.
        """
        severity_val = finding.severity.value
        badge_color = SEVERITY_HTML_COLORS.get(severity_val, "#6b7280")

        cve_refs_html = ""
        if finding.cve_references:
            for ref in finding.cve_references:
                cve_refs_html += (
                    f'<span class="cve-ref">{self._html_escape(ref)}</span>'
                )

        evidence_html = ""
        if finding.evidence:
            snippet = finding.evidence[:600]
            if len(finding.evidence) > 600:
                snippet += "\u2026"
            evidence_html = (
                f"<dt>Evidence</dt>"
                f'<dd><div class="evidence-text">{self._html_escape(snippet)}</div></dd>'
            )

        recommendation_html = ""
        if finding.recommendation:
            recommendation_html = (
                f"<dt>Recommendation</dt>"
                f'<dd class="recommendation">{self._html_escape(finding.recommendation)}</dd>'
            )

        cve_html = ""
        if cve_refs_html:
            cve_html = f"<dt>References</dt><dd>{cve_refs_html}</dd>"

        return f"""
    <div class="finding finding-{self._html_escape(severity_val)}">
        <div class="finding-header">
            <span class="severity-badge"
                  style="background:{badge_color}">{self._html_escape(severity_val)}</span>
            <div>
                <div class="finding-title">{self._html_escape(finding.title)}</div>
                <div class="finding-url"><code>{self._html_escape(finding.url)}</code></div>
            </div>
        </div>
        <div class="finding-body">
            <dl>
                <dt>Description</dt>
                <dd>{self._html_escape(finding.description)}</dd>
                {evidence_html}
                {recommendation_html}
                {cve_html}
                <dt>Finding ID</dt>
                <dd><code>{self._html_escape(finding.finding_id)}</code></dd>
            </dl>
        </div>
    </div>
"""

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _html_escape(text: str) -> str:
        """Escape HTML special characters to prevent injection in HTML output.

        Handles the five characters that must be escaped in HTML content:
        ``&``, ``<``, ``>``, ``"``, and ``'``.

        Args:
            text: Raw text that may contain HTML special characters.

        Returns:
            HTML-safe escaped string.
        """
        return (
            text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    @staticmethod
    def _wrap_text(text: str, width: int = 90) -> list[str]:
        """Soft-wrap a string to a list of lines no wider than *width* characters.

        Wrapping is performed on whitespace boundaries.  Words longer than
        *width* are never broken.

        Args:
            text: The text to wrap.
            width: Maximum line width in characters.

        Returns:
            List of line strings (may be a single element if *text* is short).
        """
        if len(text) <= width:
            return [text]

        lines: list[str] = []
        words = text.split(" ")
        current_line = ""

        for word in words:
            if not word:
                current_line += " "
                continue
            # Would adding this word exceed the limit?
            test = (current_line + " " + word).lstrip() if current_line else word
            if len(test) <= width:
                current_line = test
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word

        if current_line:
            lines.append(current_line)

        return lines if lines else [text]
