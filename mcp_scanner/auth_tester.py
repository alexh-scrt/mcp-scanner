"""Authentication bypass detection for MCP Scanner.

Tests discovered MCP endpoints for missing authentication, authentication
bypass techniques, and unauthenticated access patterns.  Each test
corresponds to a real-world attack vector documented in the MCPwn
vulnerability class and related research.

The :class:`AuthTester` is designed to be used *after* the main scanner
has already identified candidate endpoints; it then runs a focused battery
of bypass probes against those specific URLs.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from mcp_scanner.models import Finding, ScanTarget, Severity
from mcp_scanner.probes import (
    ALL_JSONRPC_PAYLOADS,
    DEFAULT_AUTH_PROBES,
    MCP_CONTENT_TYPES,
    MCP_RESPONSE_INDICATORS,
    SUCCESSFUL_STATUS_CODES,
    AuthProbe,
)

logger = logging.getLogger(__name__)


class AuthTester:
    """Tests MCP endpoints for authentication weaknesses.

    For each discovered endpoint, runs a battery of
    :class:`~mcp_scanner.probes.AuthProbe` strategies and returns
    :class:`~mcp_scanner.models.Finding` objects for any confirmed
    authentication bypass.

    The tester performs two types of check per auth-probe strategy:

    1. **GET check** – sends a GET request with modified/missing headers
       and checks whether the response contains MCP data.
    2. **POST/JSON-RPC check** – sends JSON-RPC ``initialize`` / list calls
       and checks whether the server responds with MCP capability data.

    Usage::

        tester = AuthTester(timeout=10.0)
        async with httpx.AsyncClient() as client:
            findings = await tester.test_endpoint(client, url, target)
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        extra_headers: dict[str, str] | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialise the auth tester.

        Args:
            timeout: Per-request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            extra_headers: Optional baseline headers sent with every request
                (e.g. session cookies injected by the operator).  Auth probe
                bypass headers are merged on top of these.
            verbose: When ``True``, emit DEBUG-level log messages.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.extra_headers: dict[str, str] = extra_headers or {}
        self.verbose = verbose

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def test_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        target: ScanTarget,
        auth_probes: list[AuthProbe] | None = None,
    ) -> list[Finding]:
        """Run all authentication bypass strategies against a single endpoint.

        Iterates over *auth_probes* (defaulting to
        :data:`~mcp_scanner.probes.DEFAULT_AUTH_PROBES`) and accumulates
        findings.  Network errors for individual probes are logged and
        skipped rather than propagated so that a single unresponsive
        endpoint does not abort the entire run.

        Args:
            client: Shared :class:`httpx.AsyncClient`.
            url: The full URL of the endpoint to test.
            target: The :class:`~mcp_scanner.models.ScanTarget` this
                endpoint belongs to.
            auth_probes: List of :class:`~mcp_scanner.probes.AuthProbe`
                objects to execute; defaults to
                :data:`~mcp_scanner.probes.DEFAULT_AUTH_PROBES`.

        Returns:
            List of :class:`~mcp_scanner.models.Finding` objects from all
            successful bypass detections.
        """
        findings: list[Finding] = []
        probes = auth_probes if auth_probes is not None else DEFAULT_AUTH_PROBES

        # Track which finding titles we have already emitted for this URL
        # to avoid duplicate findings when multiple probes trigger on the
        # same underlying weakness.
        seen_titles: set[str] = set()

        for probe in probes:
            try:
                probe_findings = await self._run_auth_probe(
                    client=client,
                    url=url,
                    probe=probe,
                    target=target,
                )
                for finding in probe_findings:
                    if finding.title not in seen_titles:
                        findings.append(finding)
                        seen_titles.add(finding.title)
            except httpx.TimeoutException:
                logger.debug(
                    "Auth probe '%s' timed out at %s", probe.name, url
                )
            except httpx.ConnectError as exc:
                logger.debug(
                    "Auth probe '%s' connect error at %s: %s",
                    probe.name,
                    url,
                    exc,
                )
            except httpx.TooManyRedirects:
                logger.debug(
                    "Auth probe '%s' too many redirects at %s",
                    probe.name,
                    url,
                )
            except httpx.HTTPError as exc:
                logger.debug(
                    "Auth probe '%s' HTTP error at %s: %s",
                    probe.name,
                    url,
                    exc,
                )

        return findings

    # ------------------------------------------------------------------
    # Internal probe execution
    # ------------------------------------------------------------------

    async def _run_auth_probe(
        self,
        client: httpx.AsyncClient,
        url: str,
        probe: AuthProbe,
        target: ScanTarget,
    ) -> list[Finding]:
        """Execute a single authentication bypass probe.

        Builds the effective header set for this probe by:

        1. Starting from the tester's global ``extra_headers``.
        2. Removing ``probe.missing_header`` if set.
        3. Merging in ``probe.bypass_headers``.

        Then performs a GET check followed by a JSON-RPC POST check.  If
        the GET check already confirms a bypass the POST check is skipped.

        Args:
            client: Shared :class:`httpx.AsyncClient`.
            url: The endpoint URL to probe.
            probe: The :class:`~mcp_scanner.probes.AuthProbe` strategy.
            target: The parent :class:`~mcp_scanner.models.ScanTarget`.

        Returns:
            List of findings (0 or 1 items) for this probe.
        """
        # Build effective headers for this probe.
        headers: dict[str, str] = dict(self.extra_headers)

        # Remove the specified header to test for open access.
        if probe.missing_header and probe.missing_header in headers:
            del headers[probe.missing_header]

        # Apply bypass headers on top.
        headers.update(probe.bypass_headers)

        logger.debug(
            "Running auth probe '%s' against %s (headers: %s)",
            probe.name,
            url,
            list(headers.keys()),
        )

        # 1. GET-based check.
        get_finding = await self._check_get_access(
            client=client,
            url=url,
            headers=headers,
            probe=probe,
        )
        if get_finding is not None:
            return [get_finding]

        # 2. JSON-RPC POST-based check.
        post_finding = await self._check_jsonrpc_access(
            client=client,
            url=url,
            headers=headers,
            probe=probe,
        )
        if post_finding is not None:
            return [post_finding]

        return []

    async def _check_get_access(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        probe: AuthProbe,
    ) -> Finding | None:
        """Check whether the endpoint returns MCP data via an unauthenticated GET.

        Args:
            client: Shared :class:`httpx.AsyncClient`.
            url: The endpoint URL.
            headers: Effective headers for this probe (may be missing auth or
                contain bypass values).
            probe: The :class:`~mcp_scanner.probes.AuthProbe` being executed.

        Returns:
            A :class:`~mcp_scanner.models.Finding` if unauthenticated access
            is confirmed, otherwise ``None``.
        """
        try:
            response = await client.get(url, headers=headers)
        except httpx.HTTPError:
            return None

        logger.debug(
            "Auth GET %s probe='%s' -> HTTP %d",
            url,
            probe.name,
            response.status_code,
        )

        if response.status_code not in SUCCESSFUL_STATUS_CODES:
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
            method="GET",
        )

    async def _check_jsonrpc_access(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        probe: AuthProbe,
    ) -> Finding | None:
        """Check whether the endpoint accepts unauthenticated JSON-RPC calls.

        Iterates over a curated set of JSON-RPC payloads and stops as soon
        as a response with MCP indicators is received, returning a single
        finding for the first confirmed bypass.

        Args:
            client: Shared :class:`httpx.AsyncClient`.
            url: The endpoint URL.
            headers: Effective headers for this probe.
            probe: The :class:`~mcp_scanner.probes.AuthProbe` being executed.

        Returns:
            A :class:`~mcp_scanner.models.Finding` if unauthenticated JSON-RPC
            access is confirmed, otherwise ``None``.
        """
        post_headers = {"Content-Type": "application/json", **headers}

        for payload in ALL_JSONRPC_PAYLOADS:
            try:
                response = await client.post(
                    url, json=payload, headers=post_headers
                )
            except httpx.HTTPError as exc:
                logger.debug(
                    "Auth JSON-RPC probe '%s' error at %s method='%s': %s",
                    probe.name,
                    url,
                    payload.get("method"),
                    exc,
                )
                continue

            logger.debug(
                "Auth POST %s probe='%s' method='%s' -> HTTP %d",
                url,
                probe.name,
                payload.get("method"),
                response.status_code,
            )

            if response.status_code not in SUCCESSFUL_STATUS_CODES:
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

        return None

    # ------------------------------------------------------------------
    # Response analysis helpers
    # ------------------------------------------------------------------

    def _response_indicates_mcp(
        self,
        body: str,
        content_type: str,
    ) -> bool:
        """Return ``True`` if a response looks like it came from an MCP server.

        The check prioritises ``text/event-stream`` (MCP SSE transport) and
        then falls back to keyword scanning of the body for any
        :data:`~mcp_scanner.probes.MCP_RESPONSE_INDICATORS`.

        Args:
            body: Full or partial response body text.
            content_type: Value of the ``Content-Type`` response header.

        Returns:
            ``True`` if MCP-like content is detected.
        """
        ct_lower = content_type.lower()
        body_lower = body.lower()

        # SSE streams are unambiguously MCP transport.
        if "text/event-stream" in ct_lower:
            return True

        has_keyword = any(
            indicator.lower() in body_lower
            for indicator in MCP_RESPONSE_INDICATORS
        )

        return has_keyword

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    def _build_auth_bypass_finding(
        self,
        url: str,
        probe: AuthProbe,
        status_code: int,
        content_type: str,
        body: str,
        method: str,
    ) -> Finding:
        """Construct a :class:`~mcp_scanner.models.Finding` for a confirmed bypass.

        The severity, title, description, and recommendations are customised
        per probe type to reflect the specific nature of the weakness.

        Args:
            url: The endpoint URL where the bypass was confirmed.
            probe: The :class:`~mcp_scanner.probes.AuthProbe` that succeeded.
            status_code: HTTP status code of the bypassed response.
            content_type: ``Content-Type`` of the bypassed response.
            body: Response body (used for evidence; truncated to 300 chars).
            method: Human-readable description of the HTTP method used
                (e.g. ``"GET"`` or ``"POST (tools/list)"``).

        Returns:
            A fully populated :class:`~mcp_scanner.models.Finding`.
        """
        evidence = (
            f"Auth probe: {probe.name} | "
            f"Method: {method} | "
            f"HTTP {status_code} | "
            f"Content-Type: {content_type} | "
            f"Body snippet: {body[:300]}"
        )

        # --- No auth header at all (MCPwn class) -----------------------
        if probe.name == "no_auth_header":
            return Finding(
                title="MCP Endpoint Accessible Without Authentication",
                severity=Severity.CRITICAL,
                url=url,
                description=(
                    f"The MCP endpoint at '{url}' returns sensitive data without "
                    "requiring any Authorization header.  This is the MCPwn "
                    "vulnerability class: unauthenticated access to AI tool/resource "
                    "endpoints allows attackers to enumerate and potentially invoke "
                    "the AI agent's full capability surface without any credentials."
                ),
                evidence=evidence,
                recommendation=(
                    "Immediately add authentication middleware to all MCP endpoints.  "
                    "Use Bearer token authentication and validate tokens server-side "
                    "before serving any MCP data.  Consider network-level controls "
                    "(firewall rules) as a defence-in-depth measure."
                ),
                cve_references=["MCPwn-2024-001"],
                extra=self._build_extra(probe, method, status_code),
            )

        # --- IP spoofing / forwarding-header bypass --------------------
        if any(
            kw in probe.name.lower()
            for kw in ("forwarded", "x_real_ip", "x_forwarded", "private_range", "localhost")
        ):
            return Finding(
                title="MCP Endpoint Authentication Bypassable via IP Spoofing",
                severity=Severity.HIGH,
                url=url,
                description=(
                    f"The MCP endpoint at '{url}' can be accessed by spoofing the "
                    "source IP address using X-Forwarded-For or X-Real-IP headers.  "
                    "This indicates the server relies on IP-based access control, "
                    "which can be trivially bypassed by any client that can set "
                    "arbitrary HTTP headers."
                ),
                evidence=evidence,
                recommendation=(
                    "Do not rely on client-supplied IP address headers for MCP endpoint "
                    "authentication.  Use cryptographic token-based authentication "
                    "instead.  Configure reverse proxies to strip or overwrite "
                    "X-Forwarded-For / X-Real-IP headers from untrusted sources."
                ),
                cve_references=[],
                extra=self._build_extra(probe, method, status_code),
            )

        # --- Empty or obviously invalid Bearer token -------------------
        if "bearer" in probe.name.lower():
            return Finding(
                title="MCP Endpoint Accepts Invalid Bearer Token",
                severity=Severity.HIGH,
                url=url,
                description=(
                    f"The MCP endpoint at '{url}' accepted a request with an "
                    f"invalid/empty Bearer token (probe: '{probe.name}').  "
                    "This indicates the server does not properly validate the "
                    "Authorization header value, allowing anyone who can send HTTP "
                    "requests to access MCP capabilities."
                ),
                evidence=evidence,
                recommendation=(
                    "Implement strict server-side Bearer token validation.  "
                    "Reject requests with missing, empty, 'null', 'undefined', or "
                    "otherwise malformed tokens before processing any MCP request."
                ),
                cve_references=[],
                extra=self._build_extra(probe, method, status_code),
            )

        # --- Empty or weak API key ------------------------------------
        if "api_key" in probe.name.lower():
            return Finding(
                title="MCP Endpoint Accepts Weak or Default API Key",
                severity=Severity.HIGH,
                url=url,
                description=(
                    f"The MCP endpoint at '{url}' accepted a request using a weak "
                    f"or default API key value (probe: '{probe.name}').  "
                    "Default or trivially guessable API keys provide no real "
                    "security and should be treated as equivalent to no authentication."
                ),
                evidence=evidence,
                recommendation=(
                    "Generate cryptographically random API keys of at least 32 bytes "
                    "for MCP endpoint authentication.  Rotate any default keys "
                    "immediately and implement rate limiting on authentication attempts."
                ),
                cve_references=[],
                extra=self._build_extra(probe, method, status_code),
            )

        # --- Basic auth bypass ----------------------------------------
        if "basic" in probe.name.lower():
            return Finding(
                title="MCP Endpoint Accepts Invalid Basic Authentication",
                severity=Severity.HIGH,
                url=url,
                description=(
                    f"The MCP endpoint at '{url}' accepted a request with an "
                    f"invalid or empty Basic authentication credential "
                    f"(probe: '{probe.name}').  "
                    "The server does not properly validate Basic auth credentials, "
                    "allowing unauthenticated access to MCP capabilities."
                ),
                evidence=evidence,
                recommendation=(
                    "Implement proper Basic authentication validation server-side.  "
                    "Prefer token-based authentication (Bearer) over Basic auth for "
                    "MCP endpoints and reject empty or anonymous credentials explicitly."
                ),
                cve_references=[],
                extra=self._build_extra(probe, method, status_code),
            )

        # --- CORS / origin bypass -------------------------------------
        if "cors" in probe.name.lower() or "origin" in probe.name.lower():
            return Finding(
                title="MCP Endpoint Accessible via CORS Origin Bypass",
                severity=Severity.MEDIUM,
                url=url,
                description=(
                    f"The MCP endpoint at '{url}' returned MCP data when accessed "
                    "with a localhost Origin header.  If the server trusts the Origin "
                    "header for access control decisions, browser-based cross-site "
                    "scripts on localhost or trusted origins can access MCP capabilities."
                ),
                evidence=evidence,
                recommendation=(
                    "Do not use the Origin header as an authentication mechanism.  "
                    "Configure strict CORS policies and rely on token-based auth rather "
                    "than origin allowlists for MCP endpoint security."
                ),
                cve_references=[],
                extra=self._build_extra(probe, method, status_code),
            )

        # --- Generic / catch-all --------------------------------------
        return Finding(
            title="MCP Endpoint Authentication Bypass Detected",
            severity=Severity.HIGH,
            url=url,
            description=(
                f"The MCP endpoint at '{url}' was accessible using the auth bypass "
                f"technique '{probe.name}': {probe.description}  "
                "This may allow unauthorised access to AI tools, resources, and "
                "capabilities without valid credentials."
            ),
            evidence=evidence,
            recommendation=(
                "Strengthen authentication on all MCP endpoints.  "
                "Reject requests with missing, empty, or clearly invalid credentials.  "
                "Implement proper server-side token validation and avoid relying on "
                "header-based or IP-based access controls alone."
            ),
            cve_references=[],
            extra=self._build_extra(probe, method, status_code),
        )

    @staticmethod
    def _build_extra(
        probe: AuthProbe,
        method: str,
        status_code: int,
    ) -> dict[str, Any]:
        """Build the ``extra`` metadata dictionary for a finding.

        Args:
            probe: The :class:`~mcp_scanner.probes.AuthProbe` that triggered
                the finding.
            method: HTTP method string used for the bypass.
            status_code: HTTP response status code.

        Returns:
            Dictionary with probe metadata.
        """
        return {
            "auth_probe": probe.name,
            "bypass_headers": dict(probe.bypass_headers),
            "missing_header": probe.missing_header,
            "http_method": method,
            "status_code": status_code,
        }


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

async def test_auth_for_endpoints(
    endpoints: list[str],
    target: ScanTarget,
    timeout: float = 10.0,
    verify_ssl: bool = True,
    extra_headers: dict[str, str] | None = None,
    auth_probes: list[AuthProbe] | None = None,
    verbose: bool = False,
) -> list[Finding]:
    """Convenience coroutine to run auth tests against a list of endpoint URLs.

    Creates a single :class:`httpx.AsyncClient` shared across all endpoint
    tests, then runs :class:`AuthTester` against each URL in sequence.

    Args:
        endpoints: List of full endpoint URLs to test
            (e.g. ``["https://example.com/mcp", "https://example.com/sse"]``).
        target: The :class:`~mcp_scanner.models.ScanTarget` these endpoints
            belong to (used for context in findings).
        timeout: Per-request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.
        extra_headers: Optional additional HTTP headers.
        auth_probes: Optional list of custom
            :class:`~mcp_scanner.probes.AuthProbe` objects.  Defaults to
            :data:`~mcp_scanner.probes.DEFAULT_AUTH_PROBES`.
        verbose: When ``True``, enable DEBUG-level logging.

    Returns:
        Aggregated list of :class:`~mcp_scanner.models.Finding` objects from
        all auth tests across all endpoints.
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
        headers={
            "User-Agent": "mcp-scanner/0.1.0",
            **(extra_headers or {}),
        },
    ) as client:
        for endpoint in endpoints:
            endpoint_findings = await tester.test_endpoint(
                client=client,
                url=endpoint,
                target=target,
                auth_probes=auth_probes,
            )
            findings.extend(endpoint_findings)

    return findings
