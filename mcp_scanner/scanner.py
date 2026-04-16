"""Async scanning engine for MCP Scanner.

Probes target URLs for MCP endpoint patterns using httpx,
producing Finding objects for discovered endpoints and issues.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import anyio
import httpx

from mcp_scanner.models import Finding, Severity, ScanReport, ScanTarget
from mcp_scanner.probes import (
    ALL_JSONRPC_PAYLOADS,
    DEFAULT_MCP_PATHS,
    MCP_CONTENT_TYPES,
    MCP_RESPONSE_INDICATORS,
    ProbeType,
    UrlProbe,
    build_probes_from_paths,
    load_custom_wordlist,
)

logger = logging.getLogger(__name__)


class ScannerError(Exception):
    """Raised when the scanner encounters a non-recoverable error."""


class MCPScanner:
    """Async MCP endpoint scanner.

    Probes one or more targets for MCP endpoints using configurable
    URL patterns and reports findings for each discovered endpoint.
    """

    def __init__(
        self,
        concurrency: int = 10,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        custom_wordlist: str | None = None,
        extra_headers: dict[str, str] | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize the scanner.

        Args:
            concurrency: Maximum number of simultaneous HTTP requests.
            timeout: Per-request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            custom_wordlist: Optional path to a file containing custom URL paths.
            extra_headers: Optional additional HTTP headers sent with every request.
            verbose: Whether to emit verbose debug-level log messages.
        """
        self.concurrency = concurrency
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.custom_wordlist = custom_wordlist
        self.extra_headers: dict[str, str] = extra_headers or {}
        self.verbose = verbose

        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.WARNING)

    def _build_probes(self) -> list[UrlProbe]:
        """Build the list of probes to run, merging defaults with any custom wordlist."""
        if self.custom_wordlist:
            try:
                custom_paths = load_custom_wordlist(self.custom_wordlist)
                logger.debug("Loaded %d custom paths from %s", len(custom_paths), self.custom_wordlist)
                return build_probes_from_paths(custom_paths)
            except (FileNotFoundError, PermissionError) as exc:
                logger.warning("Could not load custom wordlist %s: %s", self.custom_wordlist, exc)
        return list(DEFAULT_MCP_PATHS)

    async def scan_targets(self, targets: list[ScanTarget]) -> ScanReport:
        """Scan a list of targets and return a completed ScanReport.

        Args:
            targets: List of ScanTarget objects to probe.

        Returns:
            A ScanReport containing all findings from all targets.
        """
        report = ScanReport(targets=targets)
        probes = self._build_probes()

        sem = anyio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=True,
            headers={"User-Agent": "mcp-scanner/0.1.0", **self.extra_headers},
        ) as client:
            tasks = [
                self._scan_target(client, target, probes, sem)
                for target in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                report.findings.extend(result)
            elif isinstance(result, Exception):
                logger.warning("Target scan raised an exception: %s", result)

        report.complete()
        return report

    async def _scan_target(
        self,
        client: httpx.AsyncClient,
        target: ScanTarget,
        probes: list[UrlProbe],
        sem: anyio.Semaphore,
    ) -> list[Finding]:
        """Scan a single target with all configured probes.

        Args:
            client: Shared httpx AsyncClient.
            target: The target to probe.
            probes: List of URL probes to execute.
            sem: Semaphore for concurrency control.

        Returns:
            List of Finding objects discovered for this target.
        """
        findings: list[Finding] = []

        probe_tasks = [
            self._run_probe(client, target, probe, sem)
            for probe in probes
        ]
        results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug("Probe raised exception: %s", result)

        return findings

    async def _run_probe(
        self,
        client: httpx.AsyncClient,
        target: ScanTarget,
        probe: UrlProbe,
        sem: anyio.Semaphore,
    ) -> list[Finding]:
        """Execute a single probe against a target.

        Args:
            client: Shared httpx AsyncClient.
            target: The target being probed.
            probe: The URL probe to execute.
            sem: Semaphore for concurrency control.

        Returns:
            List of findings for this probe, possibly empty.
        """
        findings: list[Finding] = []
        url = f"{target.url}{probe.path}"
        merged_headers = {**self.extra_headers, **probe.headers}

        async with sem:
            try:
                if probe.probe_type in (ProbeType.HTTP_GET, ProbeType.SSE):
                    findings.extend(
                        await self._probe_get(client, url, probe, merged_headers, target)
                    )
                elif probe.probe_type == ProbeType.HTTP_POST:
                    findings.extend(
                        await self._probe_post(client, url, probe, merged_headers, target)
                    )
                elif probe.probe_type == ProbeType.JSON_RPC:
                    findings.extend(
                        await self._probe_jsonrpc(client, url, probe, merged_headers, target)
                    )
            except httpx.TimeoutException:
                logger.debug("Timeout probing %s", url)
            except httpx.ConnectError:
                logger.debug("Connection error probing %s", url)
            except httpx.HTTPError as exc:
                logger.debug("HTTP error probing %s: %s", url, exc)

        return findings

    async def _probe_get(
        self,
        client: httpx.AsyncClient,
        url: str,
        probe: UrlProbe,
        headers: dict[str, str],
        target: ScanTarget,
    ) -> list[Finding]:
        """Execute an HTTP GET or SSE probe and analyse the response."""
        findings: list[Finding] = []

        response = await client.get(url, headers=headers)
        logger.debug("GET %s -> %d", url, response.status_code)

        if response.status_code not in (200, 201, 206):
            return findings

        endpoint_findings = self._analyse_response(
            url=url,
            probe=probe,
            status_code=response.status_code,
            content_type=response.headers.get("content-type", ""),
            body=response.text,
        )
        findings.extend(endpoint_findings)
        return findings

    async def _probe_post(
        self,
        client: httpx.AsyncClient,
        url: str,
        probe: UrlProbe,
        headers: dict[str, str],
        target: ScanTarget,
    ) -> list[Finding]:
        """Execute an HTTP POST probe and analyse the response."""
        findings: list[Finding] = []
        post_headers = {"Content-Type": "application/json", **headers}
        payload = probe.payload or ALL_JSONRPC_PAYLOADS[0]

        response = await client.post(url, json=payload, headers=post_headers)
        logger.debug("POST %s -> %d", url, response.status_code)

        if response.status_code not in (200, 201):
            return findings

        endpoint_findings = self._analyse_response(
            url=url,
            probe=probe,
            status_code=response.status_code,
            content_type=response.headers.get("content-type", ""),
            body=response.text,
        )
        findings.extend(endpoint_findings)
        return findings

    async def _probe_jsonrpc(
        self,
        client: httpx.AsyncClient,
        url: str,
        probe: UrlProbe,
        headers: dict[str, str],
        target: ScanTarget,
    ) -> list[Finding]:
        """Send JSON-RPC payloads and look for MCP indicators."""
        findings: list[Finding] = []
        post_headers = {"Content-Type": "application/json", **headers}

        for payload in ALL_JSONRPC_PAYLOADS:
            try:
                response = await client.post(url, json=payload, headers=post_headers)
                logger.debug("JSONRPC %s method=%s -> %d", url, payload.get("method"), response.status_code)

                if response.status_code not in (200, 201):
                    continue

                body = response.text
                if self._body_has_mcp_indicators(body):
                    finding = Finding(
                        title="Unauthenticated JSON-RPC MCP Method Accessible",
                        severity=Severity.HIGH,
                        url=url,
                        description=(
                            f"The MCP JSON-RPC method '{payload.get('method')}' responded successfully "
                            "without authentication. This may allow attackers to enumerate tools, "
                            "resources, and capabilities of the MCP server."
                        ),
                        evidence=f"Method: {payload.get('method')} | HTTP {response.status_code} | "
                                 f"Body snippet: {body[:200]}",
                        recommendation=(
                            "Require authentication (e.g., Bearer token) for all JSON-RPC MCP endpoints. "
                            "Implement server-side authorization checks on each method."
                        ),
                        extra={"method": payload.get("method"), "status_code": response.status_code},
                    )
                    findings.append(finding)
                    break  # One finding per URL is sufficient for discovery

            except httpx.HTTPError as exc:
                logger.debug("JSONRPC probe error at %s: %s", url, exc)

        return findings

    def _analyse_response(
        self,
        url: str,
        probe: UrlProbe,
        status_code: int,
        content_type: str,
        body: str,
    ) -> list[Finding]:
        """Analyse an HTTP response and generate findings if MCP is detected.

        Args:
            url: The full URL that was probed.
            probe: The probe that generated this response.
            status_code: HTTP response status code.
            content_type: Value of the Content-Type response header.
            body: Response body text.

        Returns:
            List of findings, possibly empty.
        """
        findings: list[Finding] = []
        body_lower = body.lower()
        ct_lower = content_type.lower()

        is_mcp_content_type = any(ct in ct_lower for ct in MCP_CONTENT_TYPES)
        has_indicators = self._body_has_mcp_indicators(body_lower)
        is_sse = "text/event-stream" in ct_lower

        if not (is_mcp_content_type or has_indicators):
            return findings

        # Endpoint discovery finding
        if is_sse:
            finding = Finding(
                title="Unauthenticated MCP SSE Stream Exposed",
                severity=Severity.HIGH,
                url=url,
                description=(
                    f"An unauthenticated Server-Sent Events (SSE) stream was found at '{url}'. "
                    "MCP uses SSE as a transport layer; exposing it without authentication allows "
                    "attackers to intercept AI tool calls and server messages in real time."
                ),
                evidence=f"HTTP {status_code} | Content-Type: {content_type} | Body snippet: {body[:200]}",
                recommendation=(
                    "Protect SSE endpoints with authentication middleware. "
                    "Validate session tokens or API keys before establishing SSE connections."
                ),
                extra={"probe": probe.description, "content_type": content_type},
            )
            findings.append(finding)
        elif "tools" in body_lower or "inputschema" in body_lower:
            finding = Finding(
                title="Unauthenticated MCP Tool Listing Exposed",
                severity=Severity.CRITICAL,
                url=url,
                description=(
                    f"MCP tool definitions were returned unauthenticated at '{url}'. "
                    "This exposes the full capability surface of the AI agent, enabling attackers "
                    "to enumerate and invoke sensitive tools without credentials. "
                    "This pattern matches the MCPwn class of vulnerabilities."
                ),
                evidence=f"HTTP {status_code} | Content-Type: {content_type} | Body snippet: {body[:200]}",
                recommendation=(
                    "Immediately require authentication for all MCP tool listing endpoints. "
                    "Apply the principle of least privilege to tool exposure."
                ),
                cve_references=["MCPwn-2024-001"],
                extra={"probe": probe.description},
            )
            findings.append(finding)
        elif "resources" in body_lower or "uri" in body_lower:
            finding = Finding(
                title="Unauthenticated MCP Resource Listing Exposed",
                severity=Severity.HIGH,
                url=url,
                description=(
                    f"MCP resource definitions were returned unauthenticated at '{url}'. "
                    "This exposes internal data sources accessible to the AI agent, "
                    "potentially revealing file paths, database URIs, or API endpoints."
                ),
                evidence=f"HTTP {status_code} | Content-Type: {content_type} | Body snippet: {body[:200]}",
                recommendation=(
                    "Require authentication for all MCP resource listing endpoints. "
                    "Audit which resources are exposed and restrict access accordingly."
                ),
                extra={"probe": probe.description},
            )
            findings.append(finding)
        elif "jsonrpc" in body_lower or "protocolversion" in body_lower:
            finding = Finding(
                title="Unauthenticated MCP Endpoint Discovered",
                severity=Severity.MEDIUM,
                url=url,
                description=(
                    f"An MCP endpoint responding with JSON-RPC data was found at '{url}' "
                    "without requiring authentication. Further investigation is recommended "
                    "to determine the extent of the exposure."
                ),
                evidence=f"HTTP {status_code} | Content-Type: {content_type} | Body snippet: {body[:200]}",
                recommendation=(
                    "Review whether this endpoint should be publicly accessible. "
                    "Implement authentication if it is not intended to be public."
                ),
                extra={"probe": probe.description},
            )
            findings.append(finding)
        else:
            finding = Finding(
                title="Potential MCP Endpoint Discovered",
                severity=Severity.LOW,
                url=url,
                description=(
                    f"A response with MCP-like indicators was found at '{url}'. "
                    "Manual verification is recommended to confirm whether this is an MCP endpoint."
                ),
                evidence=f"HTTP {status_code} | Content-Type: {content_type} | Body snippet: {body[:200]}",
                recommendation="Manually verify this endpoint and apply appropriate access controls.",
                extra={"probe": probe.description},
            )
            findings.append(finding)

        return findings

    def _body_has_mcp_indicators(self, body: str) -> bool:
        """Check whether a response body contains MCP-related keywords."""
        body_lower = body.lower()
        return any(indicator.lower() in body_lower for indicator in MCP_RESPONSE_INDICATORS)


async def scan(
    targets: list[str],
    concurrency: int = 10,
    timeout: float = 10.0,
    verify_ssl: bool = True,
    custom_wordlist: str | None = None,
    extra_headers: dict[str, str] | None = None,
    verbose: bool = False,
) -> ScanReport:
    """Convenience function to create a scanner and run a scan.

    Args:
        targets: List of target base URLs to scan.
        concurrency: Maximum simultaneous HTTP requests.
        timeout: Per-request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.
        custom_wordlist: Optional path to custom URL path wordlist.
        extra_headers: Optional additional HTTP headers.
        verbose: Enable verbose logging.

    Returns:
        Completed ScanReport.
    """
    scanner = MCPScanner(
        concurrency=concurrency,
        timeout=timeout,
        verify_ssl=verify_ssl,
        custom_wordlist=custom_wordlist,
        extra_headers=extra_headers,
        verbose=verbose,
    )
    scan_targets = [
        ScanTarget(url=url, timeout=timeout, verify_ssl=verify_ssl)
        for url in targets
    ]
    return await scanner.scan_targets(scan_targets)
