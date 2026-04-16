"""Click-based CLI entry point for MCP Scanner.

Parses user arguments and orchestrates scan execution,
authentication testing, and report generation.  This module is the
primary interface between the user and the scanner engine.
"""

from __future__ import annotations

import asyncio
import sys
import traceback
from typing import Any

import click
from rich.console import Console

from mcp_scanner import __version__

# Module-level console for progress/status messages (stderr so JSON stdout
# output is not polluted when --format json is used).
console = Console(stderr=True)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(
    version=__version__,
    prog_name="mcp-scanner",
    message="%(prog)s %(version)s",
)
def main() -> None:
    """MCP Scanner – discover and audit Model Context Protocol endpoints.

    \b
    Probes web servers for exposed MCP endpoints, tests authentication
    requirements, and generates structured security reports.

    \b
    Examples:

      # Scan a single host
      mcp-scanner scan https://example.com

      # Scan multiple hosts with higher concurrency
      mcp-scanner scan --concurrency 20 https://a.com https://b.com

      # Output a machine-readable JSON report to a file
      mcp-scanner scan --format json --output report.json https://example.com

      # Output a self-contained HTML report
      mcp-scanner scan --format html --output report.html https://example.com

      # Print JSON to stdout (e.g. for piping)
      mcp-scanner scan --format json https://example.com

      # Use a custom URL path wordlist
      mcp-scanner scan --wordlist paths.txt https://example.com

      # Inject an API key header
      mcp-scanner scan --header "Authorization: Bearer mytoken" https://example.com

      # Disable SSL verification (not recommended in production)
      mcp-scanner scan --no-verify-ssl https://localhost:8443

      # Skip auth bypass testing (discovery only)
      mcp-scanner scan --skip-auth-tests https://example.com

      # Verbose debug output
      mcp-scanner scan --verbose https://example.com
    """


# ---------------------------------------------------------------------------
# scan sub-command
# ---------------------------------------------------------------------------


@main.command("scan")
@click.argument("targets", nargs=-1, required=True, metavar="TARGET...")
@click.option(
    "--concurrency",
    "-c",
    default=10,
    show_default=True,
    type=click.IntRange(1, 200),
    help="Maximum simultaneous HTTP requests (1-200).",
)
@click.option(
    "--timeout",
    "-t",
    default=10.0,
    show_default=True,
    type=click.FloatRange(0.5, 300.0),
    help="Per-request timeout in seconds.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    default="terminal",
    show_default=True,
    type=click.Choice(["terminal", "json", "html"], case_sensitive=False),
    help="Output format for the security report.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help=(
        "Write the report to this file path.  "
        "Required for --format html.  "
        "When omitted with --format json the JSON is printed to stdout."
    ),
)
@click.option(
    "--wordlist",
    "-w",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help=(
        "Path to a custom URL path wordlist.  "
        "Each non-comment line is used as an additional path to probe.  "
        "When supplied the custom paths *replace* the built-in defaults."
    ),
)
@click.option(
    "--header",
    "-H",
    "headers",
    multiple=True,
    metavar="NAME: VALUE",
    help=(
        "Extra HTTP header to include in every request, in 'Name: Value' format.  "
        "Can be specified multiple times.  "
        "Example: --header \"Authorization: Bearer token123\""
    ),
)
@click.option(
    "--no-verify-ssl",
    is_flag=True,
    default=False,
    help="Disable TLS/SSL certificate verification (use with caution).",
)
@click.option(
    "--skip-auth-tests",
    is_flag=True,
    default=False,
    help=(
        "Skip authentication bypass testing.  "
        "Only discovery probes are run; no auth bypass attempts are made."
    ),
)
@click.option(
    "--min-severity",
    "-s",
    default="info",
    show_default=True,
    type=click.Choice(
        ["critical", "high", "medium", "low", "info"],
        case_sensitive=False,
    ),
    help="Minimum severity level to include in the report.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose debug-level logging to stderr.",
)
def scan_command(
    targets: tuple[str, ...],
    concurrency: int,
    timeout: float,
    output_format: str,
    output: str | None,
    wordlist: str | None,
    headers: tuple[str, ...],
    no_verify_ssl: bool,
    skip_auth_tests: bool,
    min_severity: str,
    verbose: bool,
) -> None:
    """Scan one or more TARGET URLs for MCP endpoints and vulnerabilities.

    \b
    TARGET: One or more base URLs to scan.
      Examples: https://example.com  https://api.example.com:8080

    \b
    Exit codes:
      0   – Scan completed; no CRITICAL or HIGH findings.
      1   – User interrupted (Ctrl-C).
      2   – Fatal error during scan initialisation.
      10  – Scan completed; CRITICAL or HIGH findings present.
    """
    output_format = output_format.lower()
    min_severity = min_severity.lower()

    # ------------------------------------------------------------------
    # Validate HTML format requires --output
    # ------------------------------------------------------------------
    if output_format == "html" and not output:
        console.print(
            "[red]Error:[/red] --format html requires --output to specify a file path.  "
            "Example: --output report.html"
        )
        sys.exit(2)

    # ------------------------------------------------------------------
    # Parse extra headers
    # ------------------------------------------------------------------
    extra_headers: dict[str, str] = {}
    for raw_header in headers:
        if ":" not in raw_header:
            console.print(
                f"[yellow]Warning:[/yellow] ignoring malformed header "
                f"'{raw_header}' (expected 'Name: Value' format)."
            )
            continue
        name, _, value = raw_header.partition(":")
        name = name.strip()
        value = value.strip()
        if not name:
            console.print(
                f"[yellow]Warning:[/yellow] ignoring header with empty name: "
                f"'{raw_header}'."
            )
            continue
        extra_headers[name] = value
        if verbose:
            console.print(
                f"[dim]Header injected: {name}: "
                f"{'*' * min(len(value), 6)}...[/dim]"
            )

    verify_ssl = not no_verify_ssl
    target_list = list(targets)

    # ------------------------------------------------------------------
    # Pre-flight banner (terminal mode only)
    # ------------------------------------------------------------------
    if output_format == "terminal":
        _print_startup_banner(target_list, concurrency, timeout, verify_ssl, verbose)

    # ------------------------------------------------------------------
    # Run the async scan
    # ------------------------------------------------------------------
    try:
        report = asyncio.run(
            _run_full_scan(
                targets=target_list,
                concurrency=concurrency,
                timeout=timeout,
                verify_ssl=verify_ssl,
                wordlist=wordlist,
                extra_headers=extra_headers,
                skip_auth_tests=skip_auth_tests,
                verbose=verbose,
                output_format=output_format,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user (Ctrl-C).[/yellow]")
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Fatal error during scan:[/red] {exc}")
        if verbose:
            console.print_exception(show_locals=False)
        sys.exit(2)

    # ------------------------------------------------------------------
    # Filter findings by minimum severity
    # ------------------------------------------------------------------
    from mcp_scanner.models import Severity

    severity_map: dict[str, Severity] = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    threshold = severity_map[min_severity]
    if threshold != Severity.INFO:
        before = len(report.findings)
        report.findings = [
            f for f in report.findings if f.severity >= threshold
        ]
        after = len(report.findings)
        if verbose and before != after:
            console.print(
                f"[dim]Filtered {before - after} finding(s) below "
                f"--min-severity {min_severity.upper()}.[/dim]"
            )

    # ------------------------------------------------------------------
    # Generate output
    # ------------------------------------------------------------------
    from mcp_scanner.reporter import Reporter

    # Use a stdout console for terminal format so findings go to stdout;
    # use stderr console for status messages in other formats.
    if output_format == "terminal":
        report_console = Console(stderr=False)
    else:
        report_console = console  # status messages only

    reporter = Reporter(console=report_console)

    if output_format == "terminal":
        reporter.print_terminal_report(report)

    elif output_format == "json":
        if output:
            try:
                reporter.write_json_report(report, output)
                console.print(f"[green]\u2713 JSON report written to:[/green] {output}")
            except OSError as exc:
                console.print(f"[red]Error writing JSON report:[/red] {exc}")
                sys.exit(2)
        else:
            # Print clean JSON to stdout (no Rich markup).
            reporter.print_json_to_stdout(report)

    elif output_format == "html":
        # output is guaranteed to be set here (validated above).
        try:
            reporter.write_html_report(report, output)  # type: ignore[arg-type]
            console.print(f"[green]\u2713 HTML report written to:[/green] {output}")
        except OSError as exc:
            console.print(f"[red]Error writing HTML report:[/red] {exc}")
            sys.exit(2)

    # ------------------------------------------------------------------
    # Print a brief machine-readable summary to stderr for CI pipelines
    # ------------------------------------------------------------------
    if output_format != "terminal":
        summary = report.get_summary()
        console.print(
            f"[dim]Summary: "
            f"{summary.total_findings} finding(s) – "
            f"CRITICAL: {summary.critical}, "
            f"HIGH: {summary.high}, "
            f"MEDIUM: {summary.medium}, "
            f"LOW: {summary.low}, "
            f"INFO: {summary.info}[/dim]"
        )

    # ------------------------------------------------------------------
    # Exit code
    # ------------------------------------------------------------------
    summary = report.get_summary()
    if summary.critical > 0 or summary.high > 0:
        sys.exit(10)
    # Implicit sys.exit(0)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _print_startup_banner(
    targets: list[str],
    concurrency: int,
    timeout: float,
    verify_ssl: bool,
    verbose: bool,
) -> None:
    """Print a startup status banner to stderr before scanning begins.

    Args:
        targets: List of target base URLs.
        concurrency: Maximum simultaneous requests.
        timeout: Per-request timeout.
        verify_ssl: Whether SSL is being verified.
        verbose: Whether verbose mode is enabled.
    """
    console.print(
        f"[bold cyan]\u2501\u2501 MCP Scanner v{__version__} \u2501\u2501[/bold cyan]"
    )
    console.print(
        f"[dim]Targets:[/dim]     "
        + ", ".join(f"[cyan]{t}[/cyan]" for t in targets)
    )
    console.print(
        f"[dim]Concurrency:[/dim]  {concurrency} "
        f"| [dim]Timeout:[/dim] {timeout}s "
        f"| [dim]SSL verify:[/dim] {'yes' if verify_ssl else '[yellow]no[/yellow]'}"
    )
    if verbose:
        console.print("[dim]Verbose mode enabled.[/dim]")
    console.print()


async def _run_full_scan(
    targets: list[str],
    concurrency: int,
    timeout: float,
    verify_ssl: bool,
    wordlist: str | None,
    extra_headers: dict[str, str],
    skip_auth_tests: bool,
    verbose: bool,
    output_format: str,
) -> Any:
    """Async orchestrator that runs discovery and (optionally) auth testing.

    This coroutine:

    1. Validates that all target URLs begin with ``http://`` or ``https://``.
    2. Runs the :class:`~mcp_scanner.scanner.MCPScanner` against all targets.
    3. Optionally runs :class:`~mcp_scanner.auth_tester.AuthTester` against
       every discovered endpoint URL.
    4. Returns the completed :class:`~mcp_scanner.models.ScanReport`.

    Args:
        targets: List of base URLs to scan.
        concurrency: Maximum simultaneous HTTP requests.
        timeout: Per-request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.
        wordlist: Optional path to custom URL wordlist.
        extra_headers: Additional HTTP headers for every request.
        skip_auth_tests: When True, skip auth bypass probing.
        verbose: Enable debug-level logging.
        output_format: Output format string (used only for status messages).

    Returns:
        Completed :class:`~mcp_scanner.models.ScanReport`.

    Raises:
        click.UsageError: If any target URL is invalid.
        Exception: Propagated from the scanner/auth tester on fatal errors.
    """
    import anyio
    import httpx

    from mcp_scanner.models import ScanTarget
    from mcp_scanner.scanner import MCPScanner
    from mcp_scanner.auth_tester import AuthTester

    # ------------------------------------------------------------------
    # Validate target URLs
    # ------------------------------------------------------------------
    validated_targets: list[str] = []
    for raw in targets:
        url = raw.strip()
        if not url.startswith(("http://", "https://")):
            raise click.UsageError(
                f"Invalid target URL '{url}': must start with http:// or https://."
            )
        validated_targets.append(url)

    # ------------------------------------------------------------------
    # Build ScanTarget objects
    # ------------------------------------------------------------------
    scan_targets = [
        ScanTarget(
            url=url,
            timeout=timeout,
            verify_ssl=verify_ssl,
            headers=extra_headers,
        )
        for url in validated_targets
    ]

    # ------------------------------------------------------------------
    # Discovery scan
    # ------------------------------------------------------------------
    if output_format == "terminal":
        _show_progress_message(
            f"Running discovery scan against {len(scan_targets)} target(s) "
            f"({len(scan_targets)} × probes)\u2026"
        )

    scanner = MCPScanner(
        concurrency=concurrency,
        timeout=timeout,
        verify_ssl=verify_ssl,
        custom_wordlist=wordlist,
        extra_headers=extra_headers,
        verbose=verbose,
    )
    report = await scanner.scan_targets(scan_targets)

    if output_format == "terminal":
        _show_progress_message(
            f"Discovery complete: {len(report.findings)} raw finding(s) found."
        )

    # ------------------------------------------------------------------
    # Authentication bypass testing
    # ------------------------------------------------------------------
    if not skip_auth_tests:
        # Collect unique endpoint URLs that look like genuine MCP endpoints.
        discovered_urls = list({f.url for f in report.findings})

        if discovered_urls:
            if output_format == "terminal":
                _show_progress_message(
                    f"Running auth bypass tests against "
                    f"{len(discovered_urls)} discovered endpoint(s)\u2026"
                )

            auth_tester = AuthTester(
                timeout=timeout,
                verify_ssl=verify_ssl,
                extra_headers=extra_headers,
                verbose=verbose,
            )

            # Use the same concurrency limit for auth probes.
            sem = anyio.Semaphore(concurrency)

            async with httpx.AsyncClient(
                timeout=timeout,
                verify=verify_ssl,
                follow_redirects=True,
                headers={
                    "User-Agent": f"mcp-scanner/{__version__}",
                    **extra_headers,
                },
            ) as client:
                import asyncio as _asyncio

                auth_tasks = [
                    _auth_probe_with_sem(
                        auth_tester=auth_tester,
                        client=client,
                        url=url,
                        target=scan_targets[0] if scan_targets else ScanTarget(url=url),
                        sem=sem,
                    )
                    for url in discovered_urls
                ]
                auth_results = await _asyncio.gather(
                    *auth_tasks, return_exceptions=True
                )

            auth_findings_added = 0
            for result in auth_results:
                if isinstance(result, list):
                    report.findings.extend(result)
                    auth_findings_added += len(result)
                elif isinstance(result, Exception):
                    if verbose:
                        console.print(
                            f"[yellow]Auth probe error:[/yellow] {result}"
                        )

            if output_format == "terminal":
                _show_progress_message(
                    f"Auth testing complete: "
                    f"{auth_findings_added} additional finding(s) from bypass tests."
                )
        else:
            if output_format == "terminal" and verbose:
                _show_progress_message(
                    "No MCP endpoints discovered; skipping auth bypass testing."
                )
    else:
        if output_format == "terminal" and verbose:
            _show_progress_message("Auth bypass testing skipped (--skip-auth-tests).")

    # Mark the report as completed now that auth testing is done.
    # (scanner.scan_targets already called complete(), but we call it again
    # to update the timestamp after auth testing.)
    report.complete()

    return report


async def _auth_probe_with_sem(
    auth_tester: Any,
    client: Any,
    url: str,
    target: Any,
    sem: Any,
) -> list[Any]:
    """Run an auth probe under a semaphore to limit concurrency.

    Args:
        auth_tester: Configured :class:`~mcp_scanner.auth_tester.AuthTester`.
        client: Shared :class:`httpx.AsyncClient`.
        url: Endpoint URL to test.
        target: Parent :class:`~mcp_scanner.models.ScanTarget`.
        sem: :class:`anyio.Semaphore` for concurrency control.

    Returns:
        List of :class:`~mcp_scanner.models.Finding` objects.
    """
    async with sem:
        return await auth_tester.test_endpoint(
            client=client,
            url=url,
            target=target,
        )


def _show_progress_message(message: str) -> None:
    """Print a dim progress status message to stderr.

    Args:
        message: The status message to display.
    """
    console.print(f"[dim]\u2192 {message}[/dim]")


# ---------------------------------------------------------------------------
# Additional sub-commands
# ---------------------------------------------------------------------------


@main.command("list-probes")
@click.option(
    "--format",
    "-f",
    "output_format",
    default="table",
    show_default=True,
    type=click.Choice(["table", "json", "paths"], case_sensitive=False),
    help="Output format for the probe listing.",
)
def list_probes_command(output_format: str) -> None:
    """List all built-in MCP URL probe patterns.

    \b
    Output formats:
      table  – formatted table (default)
      json   – machine-readable JSON array
      paths  – one path per line (suitable for use as a wordlist)
    """
    import json as _json
    from mcp_scanner.probes import DEFAULT_MCP_PATHS

    output_format = output_format.lower()

    if output_format == "paths":
        for probe in DEFAULT_MCP_PATHS:
            click.echo(probe.path)
        return

    if output_format == "json":
        data = [
            {
                "path": p.path,
                "probe_type": p.probe_type.value,
                "description": p.description,
                "expected_indicators": p.expected_indicators,
            }
            for p in DEFAULT_MCP_PATHS
        ]
        click.echo(_json.dumps(data, indent=2))
        return

    # Default: rich table
    from rich.table import Table
    from rich import box

    list_console = Console()
    table = Table(
        title=f"Built-in MCP Probe Patterns ({len(DEFAULT_MCP_PATHS)} total)",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="bright_black",
    )
    table.add_column("#", width=4, justify="right", style="dim")
    table.add_column("Path", style="cyan", min_width=30)
    table.add_column("Type", width=12)
    table.add_column("Description", min_width=40)

    type_colors = {
        "HTTP_GET": "green",
        "HTTP_POST": "yellow",
        "SSE": "magenta",
        "JSON_RPC": "blue",
    }
    for i, probe in enumerate(DEFAULT_MCP_PATHS, start=1):
        type_val = probe.probe_type.value
        color = type_colors.get(type_val, "white")
        table.add_row(
            str(i),
            probe.path,
            f"[{color}]{type_val}[/{color}]",
            probe.description,
        )

    list_console.print(table)


@main.command("list-auth-probes")
@click.option(
    "--format",
    "-f",
    "output_format",
    default="table",
    show_default=True,
    type=click.Choice(["table", "json"], case_sensitive=False),
    help="Output format for the auth probe listing.",
)
def list_auth_probes_command(output_format: str) -> None:
    """List all built-in authentication bypass probe strategies.

    \b
    Each auth probe represents a real-world bypass technique that the
    scanner uses to test whether discovered MCP endpoints can be accessed
    without valid credentials.
    """
    import json as _json
    from mcp_scanner.probes import DEFAULT_AUTH_PROBES

    output_format = output_format.lower()

    if output_format == "json":
        data = [
            {
                "name": p.name,
                "description": p.description,
                "missing_header": p.missing_header,
                "bypass_headers": p.bypass_headers,
                "expected_bypass_indicators": p.expected_bypass_indicators,
            }
            for p in DEFAULT_AUTH_PROBES
        ]
        click.echo(_json.dumps(data, indent=2))
        return

    from rich.table import Table
    from rich import box

    list_console = Console()
    table = Table(
        title=f"Built-in Auth Bypass Probes ({len(DEFAULT_AUTH_PROBES)} total)",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="bright_black",
    )
    table.add_column("#", width=4, justify="right", style="dim")
    table.add_column("Name", style="cyan", min_width=28)
    table.add_column("Missing Header", width=18)
    table.add_column("Bypass Headers", min_width=30)
    table.add_column("Description", min_width=40)

    for i, probe in enumerate(DEFAULT_AUTH_PROBES, start=1):
        missing = probe.missing_header or "[dim]–[/dim]"
        bypass = ", ".join(
            f"{k}: {v[:20]}{'…' if len(v) > 20 else ''}"
            for k, v in probe.bypass_headers.items()
        ) or "[dim]–[/dim]"
        table.add_row(
            str(i),
            probe.name,
            missing,
            bypass,
            probe.description[:80] + ("…" if len(probe.description) > 80 else ""),
        )

    list_console.print(table)
