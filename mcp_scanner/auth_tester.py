"""Authentication bypass detection for MCP Scanner.

Tests discovered MCP endpoints for missing authentication,
authentication bypass, and unauthenticated access patterns.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from mcp_scanner.models import Finding, Severity, ScanTarget
from mcp_scanner.probes import (
    ALL_JSONRPC_PAYLOADS,
    DEFAULT_AUTH_PROBES,
    MCP_RESPONSE_INDICATORS,
    AuthProbe,
)

logger = logging.getLogger(__name__)


class AuthTester:
    """Tests MCP endpoints for authentication weaknesses.

    For each discovered endpoint, runs a battery of authentication bypass
    probes and returns findings for any vulnerabilities detected.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        extra_headers: dict[str, str] | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize the auth tester.

        Args:
            timeout: Per-request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            extra_headers: Optional baseline headers sent with every request.
            verbose: Whether to emit verbose debug-level log messages.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.extra_headers: dict[str, str] = extra_headers or {}
        self.verbose = verbose

    async def test_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        target: ScanTarget,
        auth_probes: list[AuthProbe] | None = None,
    ) -> list[Finding]:
        """Run authentication bypass tests against a single endpoint.

        Args:
            client: Shared httpx AsyncClient.
            url: The full URL of the endpoint to test.
            target: The ScanTarget this endpoint belongs to.
            auth_probes: List of auth probes to run; defaults to DEFAULT_AUTH_PROBES.

        Returns:
            List of findings from authentication tests.
        """
        findings: list[Finding] = []
        probes = auth_probes or DEFAULT_AUTH_PROBES

        for probe in probes:
            try:
                probe_findings = await self._run_auth_probe(client, url, probe, target)
                findings.extend(probe_findings)
            except httpx.TimeoutException:
                logger.debug("Auth probe timeout at %s with probe '%s'", url, probe.name)
            except httpx.ConnectError:
                logger.debug("Auth probe connect error at %s with probe '%s'", url, probe.name)
            except httpx.HTTPError as exc:
                logger.debug("Auth probe HTTP error at %s with probe '%s': %s", url, probe.name, exc)

        return findings

    async def _run_auth_probe(
        self,
        client: httpx.AsyncClient,
        url: str,
        probe: AuthProbe,
        target: ScanTarget,
    ) -> list[Finding]:
        """Execute a single authentication bypass probe.

        Args:
            client: Shared httpx AsyncClient.
            url: The endpoint URL to probe.
            probe: The auth probe to execute.
            target: The parent ScanTarget.

        Returns:
            List of findings, possibly empty.
        """
        findings: list[Finding] = []
        headers = {**self.extra_headers}

        if probe.missing_header and probe.missing_header in headers:
            del headers[probe.missing_header]

        headers.update(probe.bypass_headers)

        # Try GET request first
        get_finding = await self._check_unauthenticated_access(
            client=client,
            url=url,
            method="GET",
            headers=headers,
            probe=probe,
        )
        if get_finding:
            findings.append(get_finding)
            return findings  # Confirmed bypass, no need to continue with POST

        # Try POST with JSON-RPC payload
        post_finding = await self._check_unauthenticated_jsonrpc(
            client=client,
            url=url,
            headers=headers,
            probe=probe,
        )
        if post_finding:
            findings.append(post_finding)

        return findings

    async def _check_unauthenticated_access(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        headers: dict[str, str],
        probe: AuthProbe,
    ) -> Finding | None:
        """Check if the endpoint returns MCP data without proper authentication.

        Args:
            client: Shared httpx AsyncClient.
            url: The endpoint URL.
            method: HTTP method to use.
            headers: Headers to send (may be missing auth or have bypass values).
            probe: The auth probe being executed.

        Returns:
            A Finding if unauthenticated access is confirmed, otherwise None.
        """
        response = await client.get(url, headers=headers) if method == "GET" else None

        if response is None or response.status_code not in (200, 201, 206):
            return None

        body = response.text
        content_type = response.headers.get("content-type", "")

        if not self._response_indicates_mcp(body, content_type):
            return None

        return self._build_auth_bypass_finding(
            url=url,
            probe=probe,
            status_code=response.status_code,
            content_type=content_type,
            body=body,
            method=method,
        )

    async def _check_unauthenticated_jsonrpc(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        probe: AuthProbe,
    ) -> Finding | None:
        """Check if the endpoint accepts unauthenticated JSON-RPC calls.

        Args:
            client: Shared httpx AsyncClient.
            url: The endpoint URL.
            headers: Headers to send.
            probe: The auth probe being executed.

        Returns:
            A Finding if unauthenticated JSON-RPC access is confirmed, otherwise None.
        """
        post_headers = {"Content-Type": "application/json", **headers}

        for payload in ALL_JSONRPC_PAYLOADS:
            try:
                response = await client.post(url, json=payload, headers=post_headers)

                if response.status_code not in (200, 201):
                    continue

                body = response.text
                content_type = response.headers.get("content-type", "")

                if self._response_indicates_mcp(body, content_type):
                    return self._build_auth_bypass_finding(
                        url=url,
                        probe=probe,
                        status_code=response.status_code,
                        content_type=content_type,
                        body=body,
                        method=f"POST ({payload.get('method')})",
                    )

            except httpx.HTTPError as exc:
                logger.debug("JSON-RPC auth probe error at %s: %s", url, exc)

        return None

    def _response_indicates_mcp(
        self,
        body: str,
        content_type: str,
    ) -> bool:
        """Determine whether a response looks like an MCP response.

        Args:
            body: Response body text.
            content_type: Value of the Content-Type header.

        Returns:
            True if MCP-like content is detected.
        """
        ct_lower = content_type.lower()
        body_lower = body.lower()

        if "text/event-stream" in ct_lower:
            return True
        if "application/json" in ct_lower:
            return any(indicator.lower() in body_lower for indicator in MCP_RESPONSE_INDICATORS)
        return any(indicator.lower() in body_lower for indicator in MCP_RESPONSE_INDICATORS)

    def _build_auth_bypass_finding(
        self,
        url: str,
        probe: AuthProbe,
        status_code: int,
        content_type: str,
        body: str,
        method: str,
    ) -> Finding:
        """Build a Finding for a confirmed authentication bypass.

        Args:
            url: The endpoint URL where bypass was found.
            probe: The auth probe that detected the bypass.
            status_code: HTTP status code of the bypassed response.
            content_type: Content-Type of the bypassed response.
            body: Response body snippet.
            method: HTTP method used for the bypass.

        Returns:
            A Finding describing the authentication bypass.
        """
        if probe.name == "no_auth_header":
            severity = Severity.CRITICAL
            title = "MCP Endpoint Accessible Without Authentication"
            description = (
                f"The MCP endpoint at '{url}' returns sensitive data without requiring "
                "any Authorization header. This is the MCPwn vulnerability class: "
                "unauthenticated access to AI tool/resource endpoints allows attackers "
                "to enumerate and potentially invoke the AI agent's capabilities."
            )
            recommendation = (
                "Immediately add authentication middleware to all MCP endpoints. "
                "Use Bearer token authentication and validate tokens server-side "
                "before serving any MCP data."
            )
            cve_references = ["MCPwn-2024-001"]
        elif "forwarded" in probe.name.lower() or "ip" in probe.name.lower():
            severity = Severity.HIGH
            title = "MCP Endpoint Authentication Bypassable via IP Spoofing"
            description = (
                f"The MCP endpoint at '{url}' can be accessed by spoofing the source IP "
                "address using X-Forwarded-For or X-Real-IP headers. This indicates the "
                "server relies on IP-based access control, which can be trivially bypassed."
            )
            recommendation = (
                "Do not rely on IP address for MCP endpoint authentication. "
                "Use cryptographic token-based authentication instead. "
                "Ensure reverse proxies strip untrusted forwarding headers."
            )
            cve_references = []
        else:
            severity = Severity.HIGH
            title = "MCP Endpoint Authentication Bypass Detected"
            description = (
                f"The MCP endpoint at '{url}' was accessible using the auth bypass technique "
                f"'{probe.name}': {probe.description}. "
                "This may allow unauthorized access to AI tools, resources, and capabilities."
            )
            recommendation = (
                "Strengthen authentication on MCP endpoints. "
                "Reject requests with missing, empty, or clearly invalid credentials. "
                "Implement proper server-side token validation."
            )
            cve_references = []

        return Finding(
            title=title,
            severity=severity,
            url=url,
            description=description,
            evidence=(
                f"Probe: {probe.name} | Method: {method} | HTTP {status_code} | "
                f"Content-Type: {content_type} | Body snippet: {body[:200]}"
            ),
            recommendation=recommendation,
            cve_references=cve_references,
            extra={
                "auth_probe": probe.name,
                "bypass_headers": probe.bypass_headers,
                "missing_header": probe.missing_header,
                "http_method": method,
                "status_code": status_code,
            },
        )


async def test_auth_for_endpoints(
    endpoints: list[str],
    target: ScanTarget,
    timeout: float = 10.0,
    verify_ssl: bool = True,
    extra_headers: dict[str, str] | None = None,
    verbose: bool = False,
) -> list[Finding]:
    """Convenience function to run auth tests against a list of endpoint URLs.

    Args:
        endpoints: List of full endpoint URLs to test.
        target: The ScanTarget these endpoints belong to.
        timeout: Per-request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.
        extra_headers: Optional additional HTTP headers.
        verbose: Enable verbose logging.

    Returns:
        List of all findings from all auth tests.
    """
    tester = AuthTester(
        timeout=timeout,
        verify_ssl=verify_ssl,
        extra_headers=extra_headers,
        verbose=verbose,
    )
    findings: list[Finding] = []

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=verify_ssl,
        follow_redirects=True,
        headers={"User-Agent": "mcp-scanner/0.1.0"},
    ) as client:
        for endpoint in endpoints:
            endpoint_findings = await tester.test_endpoint(
                client=client,
                url=endpoint,
                target=target,
            )
            findings.extend(endpoint_findings)

    return findings
