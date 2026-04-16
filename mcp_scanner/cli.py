"""Click-based CLI entry point for MCP Scanner.

Parses user arguments and orchestrates scan execution,
auth testing, and report generation.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import click
from rich.console import Console

from mcp_scanner import __version__

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="mcp-scanner")
def main() -> None:
    """MCP Scanner - Discover and audit Model Context Protocol endpoints.

    \b
    Probes web servers for exposed MCP endpoints, tests authentication
    requirements, and generates security reports.

    \b
    Examples:
        mcp-scanner scan https://example.com
        mcp-scanner scan --format json --output report.json https://example.com
        mcp-scanner scan --concurrency 20 https://example.com https://api.example.com
    """


@main.command("scan")
@click.argument("targets", nargs=-1, required=True)
@click.option(
    "--concurrency",
    "-c",
    default=10,
    show_default=True,
    type=click.IntRange(1, 100),
    help="Maximum simultaneous HTTP requests.",
)
@click.option(
    "--timeout",
    "-t",
    default=10.0,
    show_default=True,
    type=float,
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
    help="Write report to this file path (JSON/HTML formats).",
)
@click.option(
    "--wordlist",
    "-w",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="Custom wordlist file with additional URL paths to probe.",
)
@click.option(
    "--header",
    "-H",
    "headers",
    multiple=True,
    help="Extra HTTP header in 'Name: Value' format (can be repeated).",
)
@click.option(
    "--no-verify-ssl",
    is_flag=True,
    default=False,
    help="Disable SSL certificate verification.",
)
@click.option(
    "--skip-auth-tests",
    is_flag=True,
    default=False,
    help="Skip authentication bypass testing.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose debug output.",
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
    verbose: bool,
) -> None:
    """Scan one or more target URLs for MCP endpoints and vulnerabilities.

    TARGETS: One or more base URLs to scan (e.g., https://example.com).
    """
    # Parse extra headers
    extra_headers: dict[str, str] = {}
    for header in headers:
        if ":" in header:
            name, _, value = header.partition(":")
            extra_headers[name.strip()] = value.strip()
        else:
            console.print(f"[yellow]Warning: ignoring malformed header '{header}' (expected 'Name: Value')[/yellow]")

    verify_ssl = not no_verify_ssl
    target_list = list(targets)

    if output_format == "terminal":
        console.print(f"[cyan]MCP Scanner v{__version__}[/cyan]")
        console.print(f"[dim]Scanning {len(target_list)} target(s) with concurrency={concurrency}...[/dim]\n")

    try:
        report = asyncio.run(
            _run_scan(
                targets=target_list,
                concurrency=concurrency,
                timeout=timeout,
                verify_ssl=verify_ssl,
                wordlist=wordlist,
                extra_headers=extra_headers,
                skip_auth_tests=skip_auth_tests,
                verbose=verbose,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Fatal error during scan: {exc}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)

    # Generate output
    from mcp_scanner.reporter import Reporter
    reporter = Reporter(console=console)

    if output_format == "terminal":
        reporter.print_terminal_report(report)
    elif output_format == "json":
        if output:
            reporter.write_json_report(report, output)
            console.print(f"[green]JSON report written to {output}[/green]")
        else:
            reporter.print_json_to_stdout(report)
    elif output_format == "html":
        if output:
            reporter.write_html_report(report, output)
            console.print(f"[green]HTML report written to {output}[/green]")
        else:
            console.print("[red]HTML format requires --output to specify a file path.[/red]")
            sys.exit(1)

    # Exit with non-zero code if critical/high findings exist
    summary = report.get_summary()
    if summary.critical > 0 or summary.high > 0:
        sys.exit(10)


async def _run_scan(
    targets: list[str],
    concurrency: int,
    timeout: float,
    verify_ssl: bool,
    wordlist: str | None,
    extra_headers: dict[str, str],
    skip_auth_tests: bool,
    verbose: bool,
) -> Any:
    """Internal async function that orchestrates the full scan."""
    from mcp_scanner.scanner import MCPScanner
    from mcp_scanner.auth_tester import AuthTester
    from mcp_scanner.models import ScanTarget
    import anyio

    scan_targets = [
        ScanTarget(url=url, timeout=timeout, verify_ssl=verify_ssl)
        for url in targets
    ]

    scanner = MCPScanner(
        concurrency=concurrency,
        timeout=timeout,
        verify_ssl=verify_ssl,
        custom_wordlist=wordlist,
        extra_headers=extra_headers,
        verbose=verbose,
    )

    report = await scanner.scan_targets(scan_targets)

    if not skip_auth_tests and report.findings:
        # Collect unique endpoint URLs discovered by the scanner
        discovered_urls = list({f.url for f in report.findings})

        import httpx
        auth_tester = AuthTester(
            timeout=timeout,
            verify_ssl=verify_ssl,
            extra_headers=extra_headers,
            verbose=verbose,
        )

        sem = anyio.Semaphore(concurrency)

        async with httpx.AsyncClient(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=True,
            headers={"User-Agent": "mcp-scanner/0.1.0", **extra_headers},
        ) as client:
            import asyncio as _asyncio
            auth_tasks = [
                auth_tester.test_endpoint(
                    client=client,
                    url=url,
                    target=scan_targets[0] if scan_targets else ScanTarget(url=url),
                )
                for url in discovered_urls
            ]
            auth_results = await _asyncio.gather(*auth_tasks, return_exceptions=True)

        for result in auth_results:
            if isinstance(result, list):
                report.findings.extend(result)

    return report
