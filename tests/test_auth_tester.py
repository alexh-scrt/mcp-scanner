"""Unit tests for mcp_scanner.auth_tester.

Uses pytest-httpx to mock HTTP responses for authentication bypass
detection logic tests.
"""

from __future__ import annotations

import pytest
import httpx

from mcp_scanner.models import Finding, ScanTarget, Severity
from mcp_scanner.probes import AuthProbe, DEFAULT_AUTH_PROBES
from mcp_scanner.auth_tester import AuthTester, test_auth_for_endpoints


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_target(url: str = "https://example.com") -> ScanTarget:
    return ScanTarget(url=url, timeout=5.0)


MCP_JSON_BODY = '{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}'
NON_MCP_BODY = '{"status": "ok", "message": "hello"}'


# ---------------------------------------------------------------------------
# AuthTester.__init__
# ---------------------------------------------------------------------------

class TestAuthTesterInit:
    """Tests for AuthTester initialisation."""

    def test_defaults(self) -> None:
        tester = AuthTester()
        assert tester.timeout == 10.0
        assert tester.verify_ssl is True
        assert tester.extra_headers == {}
        assert tester.verbose is False

    def test_custom_values(self) -> None:
        tester = AuthTester(
            timeout=3.0,
            verify_ssl=False,
            extra_headers={"X-Custom": "val"},
            verbose=True,
        )
        assert tester.timeout == 3.0
        assert tester.verify_ssl is False
        assert tester.extra_headers == {"X-Custom": "val"}


# ---------------------------------------------------------------------------
# _response_indicates_mcp
# ---------------------------------------------------------------------------

class TestResponseIndicatesMcp:
    """Tests for AuthTester._response_indicates_mcp."""

    def setup_method(self) -> None:
        self.tester = AuthTester()

    def test_sse_content_type_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp("", "text/event-stream")

    def test_json_with_jsonrpc_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"jsonrpc": "2.0"}', "application/json"
        )

    def test_json_with_tools_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"tools": []}', "application/json"
        )

    def test_plain_json_no_mcp_keywords_returns_false(self) -> None:
        assert not self.tester._response_indicates_mcp(
            '{"status": "ok"}', "application/json"
        )

    def test_empty_body_json_returns_false(self) -> None:
        assert not self.tester._response_indicates_mcp("", "application/json")

    def test_mcp_keyword_in_plain_text_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp("mcp server", "text/plain")

    def test_no_keywords_plain_text_returns_false(self) -> None:
        assert not self.tester._response_indicates_mcp("Hello World", "text/plain")

    def test_case_insensitive_keyword_match(self) -> None:
        assert self.tester._response_indicates_mcp('{"JSONRPC": "2.0"}', "application/json")


# ---------------------------------------------------------------------------
# _build_auth_bypass_finding
# ---------------------------------------------------------------------------

class TestBuildAuthBypassFinding:
    """Tests for AuthTester._build_auth_bypass_finding."""

    def setup_method(self) -> None:
        self.tester = AuthTester()

    def _make_probe(self, name: str = "test_probe") -> AuthProbe:
        return AuthProbe(
            name=name,
            description=f"Test probe: {name}",
        )

    def test_no_auth_probe_returns_critical_finding(self) -> None:
        probe = self._make_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.CRITICAL
        assert "MCPwn-2024-001" in finding.cve_references
        assert "Without Authentication" in finding.title

    def test_x_forwarded_probe_returns_high_finding(self) -> None:
        probe = self._make_probe("x_forwarded_for_localhost")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH
        assert "IP Spoofing" in finding.title

    def test_bearer_probe_returns_high_finding(self) -> None:
        probe = self._make_probe("empty_bearer_token")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH
        assert "Bearer" in finding.title

    def test_api_key_probe_returns_high_finding(self) -> None:
        probe = self._make_probe("admin_api_key_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH
        assert "API Key" in finding.title

    def test_basic_auth_probe_returns_high_finding(self) -> None:
        probe = self._make_probe("basic_auth_empty")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH
        assert "Basic" in finding.title

    def test_cors_probe_returns_medium_finding(self) -> None:
        probe = self._make_probe("cors_origin_bypass")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.MEDIUM
        assert "CORS" in finding.title

    def test_generic_probe_returns_high_finding(self) -> None:
        probe = self._make_probe("some_unknown_probe")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="POST (tools/list)",
        )
        assert finding.severity == Severity.HIGH
        assert "Bypass" in finding.title

    def test_finding_url_matches_input(self) -> None:
        probe = self._make_probe("no_auth_header")
        url = "https://example.com/mcp/tools"
        finding = self.tester._build_auth_bypass_finding(
            url=url,
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.url == url

    def test_finding_evidence_contains_probe_name(self) -> None:
        probe = self._make_probe("my_test_probe")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "my_test_probe" in finding.evidence

    def test_finding_evidence_contains_status_code(self) -> None:
        probe = self._make_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "200" in finding.evidence

    def test_extra_contains_probe_name(self) -> None:
        probe = self._make_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.extra["auth_probe"] == "no_auth_header"

    def test_extra_contains_http_method(self) -> None:
        probe = self._make_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.extra["http_method"] == "GET"


# ---------------------------------------------------------------------------
# _build_extra
# ---------------------------------------------------------------------------

class TestBuildExtra:
    """Tests for AuthTester._build_extra."""

    def test_contains_all_expected_keys(self) -> None:
        probe = AuthProbe(
            name="test",
            description="test",
            missing_header="Authorization",
            bypass_headers={"X-Test": "val"},
        )
        extra = AuthTester._build_extra(probe, "GET", 200)
        assert "auth_probe" in extra
        assert "bypass_headers" in extra
        assert "missing_header" in extra
        assert "http_method" in extra
        assert "status_code" in extra

    def test_bypass_headers_is_copy(self) -> None:
        probe = AuthProbe(
            name="test",
            description="test",
            bypass_headers={"X-Test": "val"},
        )
        extra = AuthTester._build_extra(probe, "GET", 200)
        extra["bypass_headers"]["injected"] = True
        assert "injected" not in probe.bypass_headers


# ---------------------------------------------------------------------------
# test_endpoint (mocked HTTP)
# ---------------------------------------------------------------------------

class TestTestEndpoint:
    """Integration tests for AuthTester.test_endpoint with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_no_findings_when_endpoint_returns_non_mcp(self, httpx_mock) -> None:
        """Non-MCP responses should produce no findings."""
        httpx_mock.add_response(
            status_code=200,
            content=NON_MCP_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        single_probe = AuthProbe(
            name="no_auth_header",
            description="No auth",
            missing_header="Authorization",
        )

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/api",
                target=target,
                auth_probes=[single_probe],
            )

        assert findings == []

    @pytest.mark.asyncio
    async def test_critical_finding_for_open_mcp_endpoint(self, httpx_mock) -> None:
        """An open MCP endpoint with no auth should produce a CRITICAL finding."""
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        single_probe = AuthProbe(
            name="no_auth_header",
            description="No auth header",
            missing_header="Authorization",
            expected_bypass_indicators=["tools", "jsonrpc"],
        )

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=[single_probe],
            )

        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_findings_for_401_response(self, httpx_mock) -> None:
        """A 401 Unauthorized response should not trigger any findings."""
        httpx_mock.add_response(
            status_code=401,
            content=b'{"error": "Unauthorized"}',
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        probes = [
            AuthProbe(
                name="no_auth_header",
                description="No auth",
                missing_header="Authorization",
            )
        ]

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=probes,
            )

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_findings_for_403_response(self, httpx_mock) -> None:
        """A 403 Forbidden response should not trigger any findings."""
        httpx_mock.add_response(
            status_code=403,
            content=b'{"error": "Forbidden"}',
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        probes = [
            AuthProbe(
                name="empty_bearer_token",
                description="Empty bearer",
                bypass_headers={"Authorization": "Bearer "},
            )
        ]

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=probes,
            )

        assert findings == []

    @pytest.mark.asyncio
    async def test_timeout_does_not_raise(self, httpx_mock) -> None:
        """Timeout errors during auth probes should be silently skipped."""
        httpx_mock.add_exception(httpx.TimeoutException("Timeout"))

        tester = AuthTester(timeout=1.0)
        target = _make_target()
        probes = [
            AuthProbe(name="no_auth_header", description="No auth", missing_header="Authorization")
        ]

        async with httpx.AsyncClient(timeout=1.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=probes,
            )

        assert findings == []

    @pytest.mark.asyncio
    async def test_connect_error_does_not_raise(self, httpx_mock) -> None:
        """Connection errors during auth probes should be silently skipped."""
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

        tester = AuthTester(timeout=1.0)
        target = _make_target()
        probes = [
            AuthProbe(name="no_auth_header", description="No auth", missing_header="Authorization")
        ]

        async with httpx.AsyncClient(timeout=1.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=probes,
            )

        assert findings == []

    @pytest.mark.asyncio
    async def test_duplicate_findings_deduplicated(self, httpx_mock) -> None:
        """Two probes that trigger the same finding title should not duplicate."""
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        # Two bearer probes that will produce the same finding title.
        probes = [
            AuthProbe(
                name="empty_bearer_token",
                description="Empty bearer",
                bypass_headers={"Authorization": "Bearer "},
            ),
            AuthProbe(
                name="null_bearer_token",
                description="Null bearer",
                bypass_headers={"Authorization": "Bearer null"},
            ),
        ]

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=probes,
            )

        titles = [f.title for f in findings]
        # Titles should be unique
        assert len(titles) == len(set(titles))

    @pytest.mark.asyncio
    async def test_sse_response_triggers_finding(self, httpx_mock) -> None:
        """An SSE (text/event-stream) response should trigger a finding."""
        httpx_mock.add_response(
            status_code=200,
            content=b"data: {}\n\n",
            headers={"content-type": "text/event-stream"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        probes = [
            AuthProbe(
                name="no_auth_header",
                description="No auth",
                missing_header="Authorization",
            )
        ]

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/sse",
                target=target,
                auth_probes=probes,
            )

        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# test_auth_for_endpoints convenience function
# ---------------------------------------------------------------------------

class TestTestAuthForEndpoints:
    """Tests for the test_auth_for_endpoints convenience function."""

    @pytest.mark.asyncio
    async def test_returns_findings_list(self, httpx_mock) -> None:
        httpx_mock.add_response(status_code=404)

        target = _make_target()
        probes = [
            AuthProbe(name="no_auth_header", description="No auth", missing_header="Authorization")
        ]
        findings = await test_auth_for_endpoints(
            endpoints=["https://example.com/mcp"],
            target=target,
            timeout=5.0,
            auth_probes=probes,
        )
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_non_mcp_endpoints(self, httpx_mock) -> None:
        httpx_mock.add_response(
            status_code=200,
            content=NON_MCP_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        target = _make_target()
        probes = [
            AuthProbe(name="no_auth_header", description="No auth", missing_header="Authorization")
        ]
        findings = await test_auth_for_endpoints(
            endpoints=["https://example.com/api"],
            target=target,
            timeout=5.0,
            auth_probes=probes,
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_multiple_endpoints_tested(self, httpx_mock) -> None:
        httpx_mock.add_response(status_code=404)

        target = _make_target()
        probes = [
            AuthProbe(name="no_auth_header", description="No auth", missing_header="Authorization")
        ]
        findings = await test_auth_for_endpoints(
            endpoints=[
                "https://example.com/mcp",
                "https://example.com/sse",
            ],
            target=target,
            timeout=5.0,
            auth_probes=probes,
        )
        assert isinstance(findings, list)
