"""Async scanning engine for MCP Scanner.

Probes target URLs for MCP endpoint patterns using httpx,
producing Finding objects for discovered endpoints and security issues.

The scanner uses a semaphore to limit concurrent requests, and processes
all probes for all targets concurrently within those limits.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import anyio
import httpx

from mcp_scanner.models import Finding, ScanReport, ScanTarget, Severity
from mcp_scanner.probes import (
    ALL_JSONRPC_PAYLOADS,
    DEFAULT_MCP_PATHS,
    MCP_CONTENT_TYPES,
    MCP_RESPONSE_INDICATORS,
    SUCCESSFUL_STATUS_CODES,
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

    Probes one or more targets for MCP endpoints using configurable URL
    patterns and reports findings for each discovered endpoint.  The scanner
    is designed for concurrent operation using an ``anyio`` semaphore so that
    the caller can control the maximum number of simultaneous HTTP requests.

    Usage::

        scanner = MCPScanner(concurrency=20)
        report = await scanner.scan_targets(targets)
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
        """Initialise the scanner.

        Args:
            concurrency: Maximum number of simultaneous HTTP requests.
            timeout: Per-request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            custom_wordlist: Optional path to a file containing custom URL
                paths.  When provided, the custom paths replace the default
                probe set entirely.
            extra_headers: Optional additional HTTP headers sent with every
                request (e.g. API keys injected by the operator).
            verbose: When ``True``, emit DEBUG-level log messages.
        """
        self.concurrency = concurrency
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.custom_wordlist = custom_wordlist
        self.extra_headers: dict[str, str] = extra_headers or {}
        self.verbose = verbose

        if verbose:
            logging.basicConfig(level=logging.DEBUG)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan_targets(self, targets: list[ScanTarget]) -> ScanReport:
        """Scan a list of targets and return a completed :class:`~mcp_scanner.models.ScanReport`.

        Creates a single shared :class:`httpx.AsyncClient` for the entire scan
        run and probes all targets concurrently within the configured
        concurrency limit.

        Args:
            targets: List of :class:`~mcp_scanner.models.ScanTarget` objects
                to probe.

        Returns:
            A :class:`~mcp_scanner.models.ScanReport` containing all findings
            from all targets, with :meth:`~mcp_scanner.models.ScanReport.complete`
            already called.
        """
        report = ScanReport(targets=targets)
        probes = self._build_probes()

        logger.debug(
            "Starting scan: %d target(s), %d probe(s), concurrency=%d",
            len(targets),
            len(probes),
            self.concurrency,
        )

        # Build a semaphore for concurrency control.  anyio semaphores are
        # compatible with asyncio because anyio auto-detects the running
        # backend.
        sem = anyio.Semaphore(self.concurrency)

        base_headers: dict[str, str] = {
            "User-Agent": "mcp-scanner/0.1.0",
            **self.extra_headers,
        }

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=True,
            headers=base_headers,
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
        logger.debug(
            "Scan complete: %d finding(s) across %d target(s)",
            len(report.findings),
            len(targets),
        )
        return report

    # ------------------------------------------------------------------
    # Internal helpers – target and probe orchestration
    # ------------------------------------------------------------------

    def _build_probes(self) -> list[UrlProbe]:
        """Build the list of probes, merging defaults with any custom wordlist.

        Returns:
            List of :class:`~mcp_scanner.probes.UrlProbe` objects to run
            against every target.
        """
        if self.custom_wordlist:
            try:
                custom_paths = load_custom_wordlist(self.custom_wordlist)
                logger.debug(
                    "Loaded %d custom path(s) from '%s'",
                    len(custom_paths),
                    self.custom_wordlist,
                )
                return build_probes_from_paths(custom_paths)
            except (FileNotFoundError, PermissionError, OSError) as exc:
                logger.warning(
                    "Could not load custom wordlist '%s': %s – using defaults.",
                    self.custom_wordlist,
                    exc,
                )
        return list(DEFAULT_MCP_PATHS)

    async def _scan_target(
        self,
        client: httpx.AsyncClient,
        target: ScanTarget,
        probes: list[UrlProbe],
        sem: anyio.Semaphore,
    ) -> list[Finding]:
        """Scan a single target with all configured probes concurrently.

        Args:
            client: Shared :class:`httpx.AsyncClient`.
            target: The :class:`~mcp_scanner.models.ScanTarget` to probe.
            probes: List of :class:`~mcp_scanner.probes.UrlProbe` objects.
            sem: Semaphore controlling maximum concurrent requests.

        Returns:
            Aggregated list of :class:`~mcp_scanner.models.Finding` objects
            for this target.
        """
        logger.debug("Scanning target: %s (%d probes)", target.url, len(probes))
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
        """Execute a single probe against a target under the concurrency semaphore.

        Dispatches to the appropriate method based on the probe's
        :class:`~mcp_scanner.probes.ProbeType`.  Network-level exceptions
        (timeouts, connection errors) are swallowed here and logged at DEBUG
        level so that a single unreachable path does not abort the whole scan.

        Args:
            client: Shared :class:`httpx.AsyncClient`.
            target: The :class:`~mcp_scanner.models.ScanTarget` being probed.
            probe: The :class:`~mcp_scanner.probes.UrlProbe` to execute.
            sem: Semaphore for concurrency control.

        Returns:
            List of findings for this probe, possibly empty.
        """
        findings: list[Finding] = []
        url = f"{target.url}{probe.path}"
        # Merge global extra headers with any probe-specific headers.
        # Probe-specific headers take precedence.
        merged_headers = {**self.extra_headers, **probe.headers}

        async with sem:
            try:
                if probe.probe_type in (ProbeType.HTTP_GET, ProbeType.SSE):
                    findings.extend(
                        await self._probe_get(client, url, probe, merged_headers)
                    )
                elif probe.probe_type == ProbeType.HTTP_POST:
                    findings.extend(
                        await self._probe_post(client, url, probe, merged_headers)
                    )
                elif probe.probe_type == ProbeType.JSON_RPC:
                    findings.extend(
                        await self._probe_jsonrpc(client, url, probe, merged_headers)
                    )
            except httpx.TimeoutException:
                logger.debug("Timeout probing %s", url)
            except httpx.ConnectError as exc:
                logger.debug("Connection error probing %s: %s", url, exc)
            except httpx.TooManyRedirects:
                logger.debug("Too many redirects probing %s", url)
            except httpx.HTTPStatusError as exc:
                logger.debug("HTTP status error probing %s: %s", url, exc)
            except httpx.HTTPError as exc:
                logger.debug("HTTP error probing %s: %s", url, exc)

        return findings

    # ------------------------------------------------------------------
    # HTTP interaction methods
    # ------------------------------------------------------------------

    async def _probe_get(
        self,
        client: httpx.AsyncClient,
        url: str,
        probe: UrlProbe,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Execute an HTTP GET (or SSE) probe and analyse the response.

        Args:
            client: Shared :class:`httpx.AsyncClient`.
            url: Full URL to request.
            probe: The originating :class:`~mcp_scanner.probes.UrlProbe`.
            headers: Merged request headers.

        Returns:
            List of :class:`~mcp_scanner.models.Finding` objects.
        """
        response = await client.get(url, headers=headers)
        logger.debug(
            "GET %s -> HTTP %d (Content-Type: %s)",
            url,
            response.status_code,
            response.headers.get("content-type", "unknown"),
        )

        if response.status_code not in SUCCESSFUL_STATUS_CODES:
            return []

        return self._analyse_response(
            url=url,
            probe=probe,
            status_code=response.status_code,
            content_type=response.headers.get("content-type", ""),
            body=response.text,
        )

    async def _probe_post(
        self,
        client: httpx.AsyncClient,
        url: str,
        probe: UrlProbe,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Execute an HTTP POST probe and analyse the response.

        Uses the probe's own payload if one is defined; otherwise falls back
        to the first JSON-RPC payload (``initialize``) as a sensible default.

        Args:
            client: Shared :class:`httpx.AsyncClient`.
            url: Full URL to POST to.
            probe: The originating :class:`~mcp_scanner.probes.UrlProbe`.
            headers: Merged request headers.

        Returns:
            List of :class:`~mcp_scanner.models.Finding` objects.
        """
        post_headers = {"Content-Type": "application/json", **headers}
        payload = probe.payload or ALL_JSONRPC_PAYLOADS[0]

        response = await client.post(url, json=payload, headers=post_headers)
        logger.debug("POST %s -> HTTP %d", url, response.status_code)

        if response.status_code not in SUCCESSFUL_STATUS_CODES:
            return []

        return self._analyse_response(
            url=url,
            probe=probe,
            status_code=response.status_code,
            content_type=response.headers.get("content-type", ""),
            body=response.text,
        )

    async def _probe_jsonrpc(
        self,
        client: httpx.AsyncClient,
        url: str,
        probe: UrlProbe,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Send JSON-RPC 2.0 payloads in sequence and look for MCP indicators.

        Iterates over :data:`~mcp_scanner.probes.ALL_JSONRPC_PAYLOADS` and
        stops after the first successful MCP response to avoid generating
        duplicate findings for the same URL.

        Args:
            client: Shared :class:`httpx.AsyncClient`.
            url: Full URL to POST JSON-RPC payloads to.
            probe: The originating :class:`~mcp_scanner.probes.UrlProbe`.
            headers: Merged request headers.

        Returns:
            List containing at most one :class:`~mcp_scanner.models.Finding`.
        """
        findings: list[Finding] = []
        post_headers = {"Content-Type": "application/json", **headers}

        for payload in ALL_JSONRPC_PAYLOADS:
            try:
                response = await client.post(url, json=payload, headers=post_headers)
                logger.debug(
                    "JSON-RPC %s method='%s' -> HTTP %d",
                    url,
                    payload.get("method"),
                    response.status_code,
                )

                if response.status_code not in SUCCESSFUL_STATUS_CODES:
                    continue

                body = response.text
                content_type = response.headers.get("content-type", "")

                if self._body_has_mcp_indicators(body):
                    finding = Finding(
                        title="Unauthenticated JSON-RPC MCP Method Accessible",
                        severity=Severity.HIGH,
                        url=url,
                        description=(
                            f"The MCP JSON-RPC method '{payload.get('method')}' responded "
                            "successfully without authentication.  This may allow attackers "
                            "to enumerate tools, resources, and capabilities of the MCP server."
                        ),
                        evidence=(
                            f"Method: {payload.get('method')} | "
                            f"HTTP {response.status_code} | "
                            f"Content-Type: {content_type} | "
                            f"Body snippet: {body[:300]}"
                        ),
                        recommendation=(
                            "Require authentication (e.g. Bearer token) for all JSON-RPC MCP "
                            "endpoints.  Implement server-side authorisation checks on each "
                            "method call before executing the requested operation."
                        ),
                        extra={
                            "method": payload.get("method"),
                            "status_code": response.status_code,
                            "probe": probe.description,
                        },
                    )
                    findings.append(finding)
                    # One finding per endpoint URL is sufficient for discovery.
                    break

            except httpx.TimeoutException:
                logger.debug("JSON-RPC timeout at %s for method '%s'", url, payload.get("method"))
                break  # If the endpoint times out once, skip remaining payloads.
            except httpx.HTTPError as exc:
                logger.debug("JSON-RPC HTTP error at %s: %s", url, exc)

        return findings

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _analyse_response(
        self,
        url: str,
        probe: UrlProbe,
        status_code: int,
        content_type: str,
        body: str,
    ) -> list[Finding]:
        """Analyse an HTTP response and generate findings if MCP content is detected.

        The method classifies responses into several finding categories:

        * **CRITICAL** – unauthenticated MCP tool listing (MCPwn class)
        * **HIGH** – unauthenticated SSE stream or resource listing
        * **MEDIUM** – JSON-RPC or MCP protocol version strings visible
        * **LOW** – generic MCP keyword hit, manual verification needed

        Args:
            url: The full URL that was probed.
            probe: The :class:`~mcp_scanner.probes.UrlProbe` that generated
                this response.
            status_code: HTTP response status code.
            content_type: Value of the ``Content-Type`` response header.
            body: Response body text (may be large; sliced to 300 chars in
                evidence strings).

        Returns:
            List of :class:`~mcp_scanner.models.Finding` objects, possibly
            empty if the response does not look like MCP traffic.
        """
        body_lower = body.lower()
        ct_lower = content_type.lower()

        is_mcp_content_type = any(ct in ct_lower for ct in MCP_CONTENT_TYPES)
        has_mcp_indicators = self._body_has_mcp_indicators(body_lower)
        is_sse = "text/event-stream" in ct_lower

        # If neither the content-type nor the body indicates MCP, skip.
        if not (is_mcp_content_type or has_mcp_indicators):
            return []

        evidence_prefix = (
            f"HTTP {status_code} | Content-Type: {content_type} | "
            f"Body snippet: {body[:300]}"
        )

        # --- SSE stream exposed ------------------------------------------
        if is_sse:
            return [
                Finding(
                    title="Unauthenticated MCP SSE Stream Exposed",
                    severity=Severity.HIGH,
                    url=url,
                    description=(
                        f"An unauthenticated Server-Sent Events (SSE) stream was found at "
                        f"'{url}'.  MCP uses SSE as its primary transport layer; exposing "
                        "it without authentication allows attackers to intercept AI tool "
                        "calls and server messages in real time."
                    ),
                    evidence=evidence_prefix,
                    recommendation=(
                        "Protect all SSE endpoints with authentication middleware.  "
                        "Validate session tokens or API keys before establishing any "
                        "SSE connection and terminate streams for unauthenticated clients."
                    ),
                    extra={"probe": probe.description, "content_type": content_type},
                )
            ]

        # --- Tool listing exposed (MCPwn class) --------------------------
        if "tools" in body_lower or "inputschema" in body_lower:
            return [
                Finding(
                    title="Unauthenticated MCP Tool Listing Exposed",
                    severity=Severity.CRITICAL,
                    url=url,
                    description=(
                        f"MCP tool definitions were returned unauthenticated at '{url}'.  "
                        "This exposes the full capability surface of the AI agent, enabling "
                        "attackers to enumerate and potentially invoke sensitive tools without "
                        "credentials.  This pattern matches the MCPwn class of vulnerabilities "
                        "where unauthenticated tool exposure enables AI agent abuse."
                    ),
                    evidence=evidence_prefix,
                    recommendation=(
                        "Immediately require authentication for all MCP tool listing endpoints.  "
                        "Apply the principle of least privilege to tool exposure and audit "
                        "which tools are accessible to unauthenticated callers."
                    ),
                    cve_references=["MCPwn-2024-001"],
                    extra={"probe": probe.description, "content_type": content_type},
                )
            ]

        # --- Resource listing exposed ------------------------------------
        if "resources" in body_lower or "uri" in body_lower:
            return [
                Finding(
                    title="Unauthenticated MCP Resource Listing Exposed",
                    severity=Severity.HIGH,
                    url=url,
                    description=(
                        f"MCP resource definitions were returned unauthenticated at '{url}'.  "
                        "This exposes internal data sources accessible to the AI agent, "
                        "potentially revealing file paths, database URIs, or API endpoints "
                        "that should remain private."
                    ),
                    evidence=evidence_prefix,
                    recommendation=(
                        "Require authentication for all MCP resource listing endpoints.  "
                        "Audit which resources are exposed and restrict access to only those "
                        "needed by authenticated callers."
                    ),
                    extra={"probe": probe.description, "content_type": content_type},
                )
            ]

        # --- Prompt listing exposed --------------------------------------
        if "prompts" in body_lower:
            return [
                Finding(
                    title="Unauthenticated MCP Prompt Listing Exposed",
                    severity=Severity.MEDIUM,
                    url=url,
                    description=(
                        f"MCP prompt templates were returned unauthenticated at '{url}'.  "
                        "Exposed prompts may reveal internal system instructions, business "
                        "logic encoded in prompts, or sensitive context injected into the AI."
                    ),
                    evidence=evidence_prefix,
                    recommendation=(
                        "Require authentication for all MCP prompt listing endpoints.  "
                        "Review prompt templates for embedded secrets or sensitive data."
                    ),
                    extra={"probe": probe.description, "content_type": content_type},
                )
            ]

        # --- Generic JSON-RPC / protocol version string visible ----------
        if "jsonrpc" in body_lower or "protocolversion" in body_lower or "serverinfo" in body_lower:
            return [
                Finding(
                    title="Unauthenticated MCP Endpoint Discovered",
                    severity=Severity.MEDIUM,
                    url=url,
                    description=(
                        f"An MCP endpoint responding with JSON-RPC data was found at '{url}' "
                        "without requiring authentication.  Further investigation is recommended "
                        "to determine the full extent of the exposure."
                    ),
                    evidence=evidence_prefix,
                    recommendation=(
                        "Review whether this endpoint should be publicly accessible.  "
                        "Implement authentication if it is not intentionally public and "
                        "audit what data can be retrieved without credentials."
                    ),
                    extra={"probe": probe.description, "content_type": content_type},
                )
            ]

        # --- Low-confidence MCP keyword hit ------------------------------
        return [
            Finding(
                title="Potential MCP Endpoint Discovered",
                severity=Severity.LOW,
                url=url,
                description=(
                    f"A response with MCP-like indicators was found at '{url}'.  "
                    "Manual verification is recommended to confirm whether this is "
                    "a genuine MCP endpoint and to assess the actual exposure."
                ),
                evidence=evidence_prefix,
                recommendation=(
                    "Manually verify this endpoint and apply appropriate access controls "
                    "if confirmed to be an MCP server."
                ),
                extra={"probe": probe.description, "content_type": content_type},
            )
        ]

    def _body_has_mcp_indicators(self, body: str) -> bool:
        """Return ``True`` if *body* contains any MCP-related keyword.

        Comparison is case-insensitive; *body* may already be lowercased by
        the caller.

        Args:
            body: Response body text (or its lowercased equivalent).

        Returns:
            ``True`` if at least one :data:`~mcp_scanner.probes.MCP_RESPONSE_INDICATORS`
            keyword is found.
        """
        body_lower = body.lower()
        return any(
            indicator.lower() in body_lower
            for indicator in MCP_RESPONSE_INDICATORS
        )


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

async def scan(
    targets: list[str],
    concurrency: int = 10,
    timeout: float = 10.0,
    verify_ssl: bool = True,
    custom_wordlist: str | None = None,
    extra_headers: dict[str, str] | None = None,
    verbose: bool = False,
) -> ScanReport:
    """Convenience coroutine that creates an :class:`MCPScanner` and runs a scan.

    This is the primary public API entry-point for programmatic use.  The
    :mod:`mcp_scanner.cli` module calls this function internally.

    Args:
        targets: List of target base URLs to scan
            (e.g. ``["https://example.com"]``).
        concurrency: Maximum number of simultaneous HTTP requests.
        timeout: Per-request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.
        custom_wordlist: Optional filesystem path to a custom URL path wordlist
            file.  Each non-comment line is treated as a path to probe.
        extra_headers: Optional dictionary of additional HTTP headers to include
            with every request.
        verbose: When ``True``, enable DEBUG-level logging.

    Returns:
        Completed :class:`~mcp_scanner.models.ScanReport`.
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
