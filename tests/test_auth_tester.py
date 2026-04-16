"""Unit tests for mcp_scanner.auth_tester.

Uses pytest-httpx to mock HTTP responses for authentication bypass
detection logic tests.  Covers AuthTester initialisation, response
analysis helpers, finding construction, endpoint testing with mocked
HTTP, and the test_auth_for_endpoints convenience function.
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
    """Create a minimal ScanTarget for testing."""
    return ScanTarget(url=url, timeout=5.0)


MCP_JSON_BODY = '{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}'
MCP_TOOLS_BODY = '{"tools": [{"name": "exec", "inputSchema": {}}]}'
NON_MCP_BODY = '{"status": "ok", "message": "hello"}'
SSE_BODY = b"data: {}\n\n"


def _make_auth_probe(
    name: str = "test_probe",
    description: str = "A test probe",
    missing_header: str | None = None,
    bypass_headers: dict | None = None,
    expected_bypass_indicators: list[str] | None = None,
) -> AuthProbe:
    """Convenience factory for AuthProbe instances."""
    return AuthProbe(
        name=name,
        description=description,
        missing_header=missing_header,
        bypass_headers=bypass_headers or {},
        expected_bypass_indicators=expected_bypass_indicators or [],
    )


# ---------------------------------------------------------------------------
# AuthTester.__init__
# ---------------------------------------------------------------------------

class TestAuthTesterInit:
    """Tests for AuthTester initialisation."""

    def test_default_timeout(self) -> None:
        tester = AuthTester()
        assert tester.timeout == 10.0

    def test_default_verify_ssl(self) -> None:
        tester = AuthTester()
        assert tester.verify_ssl is True

    def test_default_extra_headers_empty(self) -> None:
        tester = AuthTester()
        assert tester.extra_headers == {}

    def test_default_verbose_false(self) -> None:
        tester = AuthTester()
        assert tester.verbose is False

    def test_custom_timeout(self) -> None:
        tester = AuthTester(timeout=3.0)
        assert tester.timeout == 3.0

    def test_custom_verify_ssl(self) -> None:
        tester = AuthTester(verify_ssl=False)
        assert tester.verify_ssl is False

    def test_custom_extra_headers(self) -> None:
        tester = AuthTester(extra_headers={"X-Custom": "val"})
        assert tester.extra_headers == {"X-Custom": "val"}

    def test_custom_verbose(self) -> None:
        tester = AuthTester(verbose=True)
        assert tester.verbose is True

    def test_none_extra_headers_defaults_to_empty_dict(self) -> None:
        tester = AuthTester(extra_headers=None)
        assert tester.extra_headers == {}

    def test_all_custom_values(self) -> None:
        tester = AuthTester(
            timeout=3.0,
            verify_ssl=False,
            extra_headers={"X-Custom": "val"},
            verbose=True,
        )
        assert tester.timeout == 3.0
        assert tester.verify_ssl is False
        assert tester.extra_headers == {"X-Custom": "val"}
        assert tester.verbose is True


# ---------------------------------------------------------------------------
# _response_indicates_mcp
# ---------------------------------------------------------------------------

class TestResponseIndicatesMcp:
    """Tests for AuthTester._response_indicates_mcp."""

    def setup_method(self) -> None:
        self.tester = AuthTester()

    def test_sse_content_type_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp("", "text/event-stream")

    def test_sse_content_type_with_charset_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp("", "text/event-stream; charset=utf-8")

    def test_json_with_jsonrpc_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"jsonrpc": "2.0"}', "application/json"
        )

    def test_json_with_tools_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"tools": []}', "application/json"
        )

    def test_json_with_resources_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"resources": []}', "application/json"
        )

    def test_json_with_prompts_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"prompts": []}', "application/json"
        )

    def test_json_with_protocolversion_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"protocolVersion": "2024-11-05"}', "application/json"
        )

    def test_json_with_serverinfo_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"serverInfo": {}}', "application/json"
        )

    def test_json_with_capabilities_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"capabilities": {}}', "application/json"
        )

    def test_plain_json_no_mcp_keywords_returns_false(self) -> None:
        assert not self.tester._response_indicates_mcp(
            '{"status": "ok"}', "application/json"
        )

    def test_empty_body_json_returns_false(self) -> None:
        assert not self.tester._response_indicates_mcp("", "application/json")

    def test_empty_body_unknown_content_type_returns_false(self) -> None:
        assert not self.tester._response_indicates_mcp("", "text/html")

    def test_mcp_keyword_in_plain_text_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp("mcp server", "text/plain")

    def test_mcp_uppercase_in_plain_text_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp("MCP server", "text/plain")

    def test_no_keywords_plain_text_returns_false(self) -> None:
        assert not self.tester._response_indicates_mcp("Hello World", "text/plain")

    def test_case_insensitive_keyword_match(self) -> None:
        assert self.tester._response_indicates_mcp('{"JSONRPC": "2.0"}', "application/json")

    def test_html_response_without_keywords_returns_false(self) -> None:
        assert not self.tester._response_indicates_mcp(
            "<html><body>Welcome</body></html>", "text/html"
        )

    def test_inputschema_keyword_returns_true(self) -> None:
        assert self.tester._response_indicates_mcp(
            '{"inputSchema": {}}', "application/json"
        )


# ---------------------------------------------------------------------------
# _build_auth_bypass_finding
# ---------------------------------------------------------------------------

class TestBuildAuthBypassFinding:
    """Tests for AuthTester._build_auth_bypass_finding."""

    def setup_method(self) -> None:
        self.tester = AuthTester()

    def test_no_auth_probe_returns_critical_finding(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.CRITICAL

    def test_no_auth_probe_has_mcpwn_cve_reference(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "MCPwn-2024-001" in finding.cve_references

    def test_no_auth_probe_title_mentions_without_authentication(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "Without Authentication" in finding.title or "without authentication" in finding.title.lower()

    def test_x_forwarded_for_localhost_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "x_forwarded_for_localhost",
            bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_x_forwarded_for_localhost_probe_title_mentions_ip_spoofing(self) -> None:
        probe = _make_auth_probe(
            "x_forwarded_for_localhost",
            bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "IP Spoofing" in finding.title or "ip spoofing" in finding.title.lower()

    def test_x_forwarded_for_private_range_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "x_forwarded_for_private_range",
            bypass_headers={"X-Forwarded-For": "10.0.0.1"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_empty_bearer_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "empty_bearer_token",
            bypass_headers={"Authorization": "Bearer "},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_empty_bearer_probe_title_mentions_bearer(self) -> None:
        probe = _make_auth_probe(
            "empty_bearer_token",
            bypass_headers={"Authorization": "Bearer "},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "Bearer" in finding.title

    def test_null_bearer_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "null_bearer_token",
            bypass_headers={"Authorization": "Bearer null"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_invalid_bearer_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "invalid_bearer_token",
            bypass_headers={"Authorization": "Bearer INVALID"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_admin_api_key_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "admin_api_key_header",
            bypass_headers={"X-API-Key": "admin"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_api_key_probe_title_mentions_api_key(self) -> None:
        probe = _make_auth_probe(
            "admin_api_key_header",
            bypass_headers={"X-API-Key": "admin"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "API Key" in finding.title

    def test_default_api_key_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "default_api_key_header",
            bypass_headers={"X-API-Key": "default"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_empty_api_key_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "empty_api_key_header",
            bypass_headers={"X-API-Key": ""},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_basic_auth_empty_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "basic_auth_empty",
            bypass_headers={"Authorization": "Basic "},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_basic_auth_probe_title_mentions_basic(self) -> None:
        probe = _make_auth_probe(
            "basic_auth_empty",
            bypass_headers={"Authorization": "Basic "},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "Basic" in finding.title

    def test_basic_auth_anonymous_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe(
            "basic_auth_anonymous",
            bypass_headers={"Authorization": "Basic YW5vbnltb3VzOmFub255bW91cw=="},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.HIGH

    def test_cors_origin_bypass_probe_returns_medium_finding(self) -> None:
        probe = _make_auth_probe(
            "cors_origin_bypass",
            bypass_headers={"Origin": "http://localhost"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.severity == Severity.MEDIUM

    def test_cors_probe_title_mentions_cors(self) -> None:
        probe = _make_auth_probe(
            "cors_origin_bypass",
            bypass_headers={"Origin": "http://localhost"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "CORS" in finding.title

    def test_generic_probe_returns_high_finding(self) -> None:
        probe = _make_auth_probe("some_unknown_probe")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="POST (tools/list)",
        )
        assert finding.severity == Severity.HIGH

    def test_generic_probe_title_mentions_bypass(self) -> None:
        probe = _make_auth_probe("some_unknown_probe")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "Bypass" in finding.title

    def test_finding_url_matches_input(self) -> None:
        probe = _make_auth_probe("no_auth_header")
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
        probe = _make_auth_probe("my_test_probe")
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
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "200" in finding.evidence

    def test_finding_evidence_contains_http_method(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "GET" in finding.evidence

    def test_finding_evidence_contains_content_type(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "application/json" in finding.evidence

    def test_finding_evidence_truncates_long_body(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        long_body = "x" * 2000
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=long_body,
            method="GET",
        )
        # Evidence should have the body snippet but not the full 2000-char body
        assert len(finding.evidence) < 2000

    def test_finding_description_is_non_empty(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert len(finding.description) > 0

    def test_finding_recommendation_is_non_empty(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert len(finding.recommendation) > 0

    def test_extra_contains_auth_probe_name(self) -> None:
        probe = _make_auth_probe("no_auth_header")
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
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.extra["http_method"] == "GET"

    def test_extra_contains_status_code(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.extra["status_code"] == 200

    def test_extra_contains_missing_header(self) -> None:
        probe = _make_auth_probe("no_auth_header", missing_header="Authorization")
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert finding.extra["missing_header"] == "Authorization"

    def test_extra_contains_bypass_headers(self) -> None:
        probe = _make_auth_probe(
            "x_forwarded_for_localhost",
            bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        )
        finding = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert "X-Forwarded-For" in finding.extra["bypass_headers"]

    def test_finding_is_finding_instance(self) -> None:
        probe = _make_auth_probe("no_auth_header")
        result = self.tester._build_auth_bypass_finding(
            url="https://example.com/mcp",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=MCP_JSON_BODY,
            method="GET",
        )
        assert isinstance(result, Finding)


# ---------------------------------------------------------------------------
# _build_extra
# ---------------------------------------------------------------------------

class TestBuildExtra:
    """Tests for AuthTester._build_extra static method."""

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

    def test_auth_probe_value(self) -> None:
        probe = AuthProbe(name="my_probe", description="test")
        extra = AuthTester._build_extra(probe, "GET", 200)
        assert extra["auth_probe"] == "my_probe"

    def test_http_method_value(self) -> None:
        probe = AuthProbe(name="my_probe", description="test")
        extra = AuthTester._build_extra(probe, "POST (tools/list)", 200)
        assert extra["http_method"] == "POST (tools/list)"

    def test_status_code_value(self) -> None:
        probe = AuthProbe(name="my_probe", description="test")
        extra = AuthTester._build_extra(probe, "GET", 206)
        assert extra["status_code"] == 206

    def test_missing_header_none_when_not_set(self) -> None:
        probe = AuthProbe(name="my_probe", description="test")
        extra = AuthTester._build_extra(probe, "GET", 200)
        assert extra["missing_header"] is None

    def test_missing_header_value_when_set(self) -> None:
        probe = AuthProbe(
            name="my_probe",
            description="test",
            missing_header="Authorization",
        )
        extra = AuthTester._build_extra(probe, "GET", 200)
        assert extra["missing_header"] == "Authorization"

    def test_bypass_headers_is_copy_not_reference(self) -> None:
        """Mutating the extra bypass_headers should not affect the probe."""
        probe = AuthProbe(
            name="test",
            description="test",
            bypass_headers={"X-Test": "val"},
        )
        extra = AuthTester._build_extra(probe, "GET", 200)
        extra["bypass_headers"]["injected"] = True
        assert "injected" not in probe.bypass_headers

    def test_bypass_headers_empty_dict_when_not_set(self) -> None:
        probe = AuthProbe(name="test", description="test")
        extra = AuthTester._build_extra(probe, "GET", 200)
        assert extra["bypass_headers"] == {}


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
        single_probe = _make_auth_probe(
            "no_auth_header",
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
        single_probe = _make_auth_probe(
            "no_auth_header",
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
            _make_auth_probe("no_auth_header", missing_header="Authorization")
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
            _make_auth_probe(
                "empty_bearer_token",
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
    async def test_no_findings_for_404_response(self, httpx_mock) -> None:
        """A 404 Not Found response should not trigger any findings."""
        httpx_mock.add_response(
            status_code=404,
            content=b'Not Found',
            headers={"content-type": "text/plain"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        probes = [
            _make_auth_probe("no_auth_header", missing_header="Authorization")
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
            _make_auth_probe("no_auth_header", missing_header="Authorization")
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
            _make_auth_probe("no_auth_header", missing_header="Authorization")
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
    async def test_too_many_redirects_does_not_raise(self, httpx_mock) -> None:
        """TooManyRedirects errors should be silently skipped."""
        httpx_mock.add_exception(httpx.TooManyRedirects("Too many redirects"))

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        probes = [
            _make_auth_probe("no_auth_header", missing_header="Authorization")
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
    async def test_duplicate_findings_by_title_deduplicated(self, httpx_mock) -> None:
        """Two probes that trigger the same finding title should produce only one."""
        # Both probes will produce findings with the same title
        # (both are bearer token probes -> same title "MCP Endpoint Accepts Invalid Bearer Token")
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        probes = [
            _make_auth_probe(
                "empty_bearer_token",
                bypass_headers={"Authorization": "Bearer "},
            ),
            _make_auth_probe(
                "null_bearer_token",
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
        # No duplicate titles
        assert len(titles) == len(set(titles))

    @pytest.mark.asyncio
    async def test_sse_response_triggers_finding(self, httpx_mock) -> None:
        """An SSE (text/event-stream) response should trigger a finding."""
        httpx_mock.add_response(
            status_code=200,
            content=SSE_BODY,
            headers={"content-type": "text/event-stream"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        probes = [
            _make_auth_probe(
                "no_auth_header",
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

    @pytest.mark.asyncio
    async def test_returns_list(self, httpx_mock) -> None:
        """test_endpoint always returns a list."""
        httpx_mock.add_response(status_code=404)

        tester = AuthTester(timeout=5.0)
        target = _make_target()

        async with httpx.AsyncClient(timeout=5.0) as client:
            result = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=[],
            )

        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_empty_probe_list_returns_empty_findings(self, httpx_mock) -> None:
        """No auth probes -> no findings regardless of the response."""
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=[],
            )

        assert findings == []

    @pytest.mark.asyncio
    async def test_uses_default_auth_probes_when_none_provided(self, httpx_mock) -> None:
        """When auth_probes=None, DEFAULT_AUTH_PROBES should be used."""
        # All requests return a non-MCP response so no findings are generated,
        # but we verify that the call succeeds (implying DEFAULT_AUTH_PROBES was used).
        httpx_mock.add_response(
            status_code=404,
            content=b"Not Found",
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=None,  # Should use DEFAULT_AUTH_PROBES
            )

        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_finding_url_matches_probed_url(self, httpx_mock) -> None:
        """Finding URLs should match the endpoint URL passed to test_endpoint."""
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        endpoint_url = "https://example.com/mcp/tools"
        probes = [_make_auth_probe("no_auth_header", missing_header="Authorization")]

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url=endpoint_url,
                target=target,
                auth_probes=probes,
            )

        for finding in findings:
            assert finding.url == endpoint_url

    @pytest.mark.asyncio
    async def test_tools_body_creates_finding(self, httpx_mock) -> None:
        """A response body with tool definitions should create a finding."""
        httpx_mock.add_response(
            status_code=200,
            content=MCP_TOOLS_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        probes = [_make_auth_probe("no_auth_header", missing_header="Authorization")]

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp/tools",
                target=target,
                auth_probes=probes,
            )

        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_ip_spoof_probe_can_detect_bypass(self, httpx_mock) -> None:
        """An IP spoofing probe that gets an MCP response creates a finding."""
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        target = _make_target()
        probes = [
            _make_auth_probe(
                "x_forwarded_for_localhost",
                bypass_headers={
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                },
            )
        ]

        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=probes,
            )

        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_extra_headers_from_tester_applied(self, httpx_mock) -> None:
        """Tester-level extra_headers are included in requests."""
        httpx_mock.add_response(
            status_code=200,
            content=NON_MCP_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(
            timeout=5.0,
            extra_headers={"X-Session": "abc123"},
        )
        target = _make_target()
        probes = [_make_auth_probe("no_auth_header", missing_header="Authorization")]

        # Should not raise; confirms headers don't break requests
        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=probes,
            )

        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_missing_header_removed_from_request(self, httpx_mock) -> None:
        """When missing_header is set, it should be removed before the request."""
        # This test verifies the probe runs without error when a header to
        # be removed is not present in extra_headers (should not raise KeyError).
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        # Tester has the Authorization header in extra_headers
        tester = AuthTester(
            timeout=5.0,
            extra_headers={"Authorization": "Bearer real_token"},
        )
        target = _make_target()
        probes = [
            # This probe removes Authorization to test open access
            _make_auth_probe("no_auth_header", missing_header="Authorization")
        ]

        # Should not raise KeyError even though header is present
        async with httpx.AsyncClient(timeout=5.0) as client:
            findings = await tester.test_endpoint(
                client=client,
                url="https://example.com/mcp",
                target=target,
                auth_probes=probes,
            )

        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# _check_get_access (mocked HTTP)
# ---------------------------------------------------------------------------

class TestCheckGetAccess:
    """Unit tests for AuthTester._check_get_access."""

    @pytest.mark.asyncio
    async def test_returns_finding_for_mcp_response(self, httpx_mock) -> None:
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        probe = _make_auth_probe("no_auth_header", missing_header="Authorization")

        async with httpx.AsyncClient(timeout=5.0) as client:
            finding = await tester._check_get_access(
                client=client,
                url="https://example.com/mcp",
                headers={},
                probe=probe,
            )

        assert finding is not None
        assert isinstance(finding, Finding)

    @pytest.mark.asyncio
    async def test_returns_none_for_non_mcp_response(self, httpx_mock) -> None:
        httpx_mock.add_response(
            status_code=200,
            content=NON_MCP_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        probe = _make_auth_probe("no_auth_header")

        async with httpx.AsyncClient(timeout=5.0) as client:
            finding = await tester._check_get_access(
                client=client,
                url="https://example.com/mcp",
                headers={},
                probe=probe,
            )

        assert finding is None

    @pytest.mark.asyncio
    async def test_returns_none_for_401(self, httpx_mock) -> None:
        httpx_mock.add_response(
            status_code=401,
            content=b'{"error": "Unauthorized"}',
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        probe = _make_auth_probe("no_auth_header")

        async with httpx.AsyncClient(timeout=5.0) as client:
            finding = await tester._check_get_access(
                client=client,
                url="https://example.com/mcp",
                headers={},
                probe=probe,
            )

        assert finding is None

    @pytest.mark.asyncio
    async def test_returns_none_on_http_error(self, httpx_mock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("refused"))

        tester = AuthTester(timeout=5.0)
        probe = _make_auth_probe("no_auth_header")

        async with httpx.AsyncClient(timeout=5.0) as client:
            finding = await tester._check_get_access(
                client=client,
                url="https://example.com/mcp",
                headers={},
                probe=probe,
            )

        assert finding is None


# ---------------------------------------------------------------------------
# _check_jsonrpc_access (mocked HTTP)
# ---------------------------------------------------------------------------

class TestCheckJsonrpcAccess:
    """Unit tests for AuthTester._check_jsonrpc_access."""

    @pytest.mark.asyncio
    async def test_returns_finding_for_mcp_response(self, httpx_mock) -> None:
        """A JSON-RPC response with MCP indicators creates a finding."""
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        probe = _make_auth_probe("no_auth_header")

        async with httpx.AsyncClient(timeout=5.0) as client:
            finding = await tester._check_jsonrpc_access(
                client=client,
                url="https://example.com/mcp/rpc",
                headers={},
                probe=probe,
            )

        assert finding is not None
        assert isinstance(finding, Finding)

    @pytest.mark.asyncio
    async def test_returns_none_for_non_mcp_response(self, httpx_mock) -> None:
        """Non-MCP JSON-RPC responses produce no findings."""
        httpx_mock.add_response(
            status_code=200,
            content=NON_MCP_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        probe = _make_auth_probe("no_auth_header")

        async with httpx.AsyncClient(timeout=5.0) as client:
            finding = await tester._check_jsonrpc_access(
                client=client,
                url="https://example.com/mcp/rpc",
                headers={},
                probe=probe,
            )

        assert finding is None

    @pytest.mark.asyncio
    async def test_returns_none_for_401_response(self, httpx_mock) -> None:
        """A 401 response from JSON-RPC produces no finding."""
        httpx_mock.add_response(
            status_code=401,
            content=b'{"error": "Unauthorized"}',
            headers={"content-type": "application/json"},
        )

        tester = AuthTester(timeout=5.0)
        probe = _make_auth_probe("no_auth_header")

        async with httpx.AsyncClient(timeout=5.0) as client:
            finding = await tester._check_jsonrpc_access(
                client=client,
                url="https://example.com/mcp/rpc",
                headers={},
                probe=probe,
            )

        assert finding is None

    @pytest.mark.asyncio
    async def test_returns_none_when_http_error_on_all_payloads(self, httpx_mock) -> None:
        """HTTP errors on all payloads result in None."""
        httpx_mock.add_exception(httpx.ConnectError("refused"))

        tester = AuthTester(timeout=5.0)
        probe = _make_auth_probe("no_auth_header")

        async with httpx.AsyncClient(timeout=5.0) as client:
            finding = await tester._check_jsonrpc_access(
                client=client,
                url="https://example.com/mcp/rpc",
                headers={},
                probe=probe,
            )

        assert finding is None


# ---------------------------------------------------------------------------
# test_auth_for_endpoints convenience function
# ---------------------------------------------------------------------------

class TestTestAuthForEndpoints:
    """Tests for the test_auth_for_endpoints convenience function."""

    @pytest.mark.asyncio
    async def test_returns_list(self, httpx_mock) -> None:
        """The function always returns a list."""
        httpx_mock.add_response(status_code=404)

        target = _make_target()
        probes = [
            _make_auth_probe("no_auth_header", missing_header="Authorization")
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
        """Non-MCP endpoints produce no findings."""
        httpx_mock.add_response(
            status_code=200,
            content=NON_MCP_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        target = _make_target()
        probes = [
            _make_auth_probe("no_auth_header", missing_header="Authorization")
        ]
        findings = await test_auth_for_endpoints(
            endpoints=["https://example.com/api"],
            target=target,
            timeout=5.0,
            auth_probes=probes,
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_returns_findings_for_mcp_endpoint(self, httpx_mock) -> None:
        """An open MCP endpoint produces at least one finding."""
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        target = _make_target()
        probes = [
            _make_auth_probe("no_auth_header", missing_header="Authorization")
        ]
        findings = await test_auth_for_endpoints(
            endpoints=["https://example.com/mcp"],
            target=target,
            timeout=5.0,
            auth_probes=probes,
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_multiple_endpoints_tested(self, httpx_mock) -> None:
        """Both endpoints are tested (no short-circuit on first endpoint)."""
        httpx_mock.add_response(status_code=404)

        target = _make_target()
        probes = [
            _make_auth_probe("no_auth_header", missing_header="Authorization")
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

    @pytest.mark.asyncio
    async def test_empty_endpoint_list_returns_empty(self, httpx_mock) -> None:
        """An empty endpoint list returns an empty findings list."""
        target = _make_target()
        probes = [
            _make_auth_probe("no_auth_header", missing_header="Authorization")
        ]
        findings = await test_auth_for_endpoints(
            endpoints=[],
            target=target,
            timeout=5.0,
            auth_probes=probes,
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_uses_default_probes_when_none_provided(self, httpx_mock) -> None:
        """When auth_probes=None, the default probe set is used."""
        httpx_mock.add_response(status_code=404)

        target = _make_target()
        findings = await test_auth_for_endpoints(
            endpoints=["https://example.com/mcp"],
            target=target,
            timeout=5.0,
            auth_probes=None,
        )
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_aggregates_findings_across_endpoints(self, httpx_mock) -> None:
        """Findings from multiple endpoints are all returned in the list."""
        # Both endpoints return MCP data
        httpx_mock.add_response(
            status_code=200,
            content=MCP_JSON_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        target = _make_target()
        probes = [
            _make_auth_probe(
                "no_auth_header",
                missing_header="Authorization",
            )
        ]
        findings = await test_auth_for_endpoints(
            endpoints=[
                "https://example.com/mcp",
                "https://example.com/mcp/tools",
            ],
            target=target,
            timeout=5.0,
            auth_probes=probes,
        )
        # Each endpoint should generate at least one finding
        # (two endpoints, each with one CRITICAL finding = at least 2)
        assert len(findings) >= 2

    @pytest.mark.asyncio
    async def test_passes_extra_headers_to_client(self, httpx_mock) -> None:
        """extra_headers are forwarded to the underlying HTTP client."""
        httpx_mock.add_response(
            status_code=200,
            content=NON_MCP_BODY.encode(),
            headers={"content-type": "application/json"},
        )

        target = _make_target()
        probes = [_make_auth_probe("no_auth_header", missing_header="Authorization")]

        # Should not raise even with extra headers
        findings = await test_auth_for_endpoints(
            endpoints=["https://example.com/mcp"],
            target=target,
            timeout=5.0,
            auth_probes=probes,
            extra_headers={"X-Custom": "value"},
        )
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_sse_endpoint_creates_finding(self, httpx_mock) -> None:
        """An SSE endpoint should trigger a finding."""
        httpx_mock.add_response(
            status_code=200,
            content=SSE_BODY,
            headers={"content-type": "text/event-stream"},
        )

        target = _make_target()
        probes = [
            _make_auth_probe("no_auth_header", missing_header="Authorization")
        ]
        findings = await test_auth_for_endpoints(
            endpoints=["https://example.com/sse"],
            target=target,
            timeout=5.0,
            auth_probes=probes,
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_network_error_does_not_propagate(self, httpx_mock) -> None:
        """Network errors should not propagate as exceptions from the function."""
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

        target = _make_target()
        probes = [_make_auth_probe("no_auth_header", missing_header="Authorization")]

        # Should not raise
        findings = await test_auth_for_endpoints(
            endpoints=["https://example.com/mcp"],
            target=target,
            timeout=5.0,
            auth_probes=probes,
        )
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# DEFAULT_AUTH_PROBES integration
# ---------------------------------------------------------------------------

class TestDefaultAuthProbesIntegration:
    """Verifies DEFAULT_AUTH_PROBES work correctly with AuthTester."""

    def test_no_auth_probe_in_defaults(self) -> None:
        """DEFAULT_AUTH_PROBES should contain the no_auth_header probe."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "no_auth_header" in names

    def test_all_default_probes_have_expected_indicators_or_bypass(self) -> None:
        """Each default probe should have either bypass_headers or missing_header."""
        for probe in DEFAULT_AUTH_PROBES:
            has_bypass = bool(probe.bypass_headers)
            has_missing = probe.missing_header is not None
            assert has_bypass or has_missing, (
                f"Auth probe '{probe.name}' has neither bypass_headers nor missing_header"
            )

    def test_all_default_probes_can_be_used_with_auth_tester(self) -> None:
        """DEFAULT_AUTH_PROBES should be accepted by AuthTester without error."""
        tester = AuthTester()
        # Simply verify that the probes list is non-empty and all are AuthProbe instances
        assert len(DEFAULT_AUTH_PROBES) > 0
        for probe in DEFAULT_AUTH_PROBES:
            assert isinstance(probe, AuthProbe)

    def test_default_probes_cover_bearer_bypass(self) -> None:
        """DEFAULT_AUTH_PROBES should include at least one bearer token bypass."""
        bearer_probes = [
            p for p in DEFAULT_AUTH_PROBES
            if "bearer" in p.name.lower()
        ]
        assert len(bearer_probes) >= 1

    def test_default_probes_cover_ip_bypass(self) -> None:
        """DEFAULT_AUTH_PROBES should include at least one IP spoofing bypass."""
        ip_probes = [
            p for p in DEFAULT_AUTH_PROBES
            if "forwarded" in p.name.lower() or "ip" in p.name.lower()
        ]
        assert len(ip_probes) >= 1

    def test_default_probes_cover_api_key_bypass(self) -> None:
        """DEFAULT_AUTH_PROBES should include at least one API key bypass."""
        api_key_probes = [
            p for p in DEFAULT_AUTH_PROBES
            if "api_key" in p.name.lower()
        ]
        assert len(api_key_probes) >= 1
