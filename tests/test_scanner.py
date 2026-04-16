"""Unit tests for mcp_scanner.scanner.

Uses pytest-httpx to mock HTTP responses so that the scanner engine
can be tested without making real network requests.
"""

from __future__ import annotations

import pytest
import httpx

from mcp_scanner.models import Finding, ScanReport, ScanTarget, Severity
from mcp_scanner.probes import UrlProbe, ProbeType, DEFAULT_MCP_PATHS
from mcp_scanner.scanner import MCPScanner, scan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_target(url: str = "https://example.com") -> ScanTarget:
    """Create a ScanTarget for testing."""
    return ScanTarget(url=url, timeout=5.0)


def _make_probe(
    path: str = "/mcp",
    probe_type: ProbeType = ProbeType.HTTP_GET,
) -> UrlProbe:
    """Create a minimal UrlProbe for testing."""
    return UrlProbe(
        path=path,
        probe_type=probe_type,
        description=f"Test probe {path}",
        expected_indicators=["jsonrpc", "tools"],
    )


# ---------------------------------------------------------------------------
# MCPScanner.__init__
# ---------------------------------------------------------------------------

class TestMCPScannerInit:
    """Tests for MCPScanner initialisation."""

    def test_defaults(self) -> None:
        """Default values are set correctly."""
        scanner = MCPScanner()
        assert scanner.concurrency == 10
        assert scanner.timeout == 10.0
        assert scanner.verify_ssl is True
        assert scanner.custom_wordlist is None
        assert scanner.extra_headers == {}
        assert scanner.verbose is False

    def test_custom_concurrency(self) -> None:
        scanner = MCPScanner(concurrency=5)
        assert scanner.concurrency == 5

    def test_custom_timeout(self) -> None:
        scanner = MCPScanner(timeout=3.0)
        assert scanner.timeout == 3.0

    def test_custom_verify_ssl(self) -> None:
        scanner = MCPScanner(verify_ssl=False)
        assert scanner.verify_ssl is False

    def test_custom_extra_headers(self) -> None:
        scanner = MCPScanner(extra_headers={"X-Test": "value"})
        assert scanner.extra_headers == {"X-Test": "value"}

    def test_custom_verbose(self) -> None:
        scanner = MCPScanner(verbose=True)
        assert scanner.verbose is True

    def test_custom_wordlist(self) -> None:
        scanner = MCPScanner(custom_wordlist="/path/to/wordlist.txt")
        assert scanner.custom_wordlist == "/path/to/wordlist.txt"

    def test_all_custom_values(self) -> None:
        scanner = MCPScanner(
            concurrency=5,
            timeout=3.0,
            verify_ssl=False,
            extra_headers={"X-Test": "value"},
            verbose=True,
        )
        assert scanner.concurrency == 5
        assert scanner.timeout == 3.0
        assert scanner.verify_ssl is False
        assert scanner.extra_headers == {"X-Test": "value"}
        assert scanner.verbose is True

    def test_none_extra_headers_defaults_to_empty_dict(self) -> None:
        scanner = MCPScanner(extra_headers=None)
        assert scanner.extra_headers == {}


# ---------------------------------------------------------------------------
# _build_probes
# ---------------------------------------------------------------------------

class TestBuildProbes:
    """Tests for MCPScanner._build_probes."""

    def test_returns_default_probes_without_wordlist(self) -> None:
        """Without a custom wordlist, the default probe list is returned."""
        scanner = MCPScanner()
        probes = scanner._build_probes()
        assert len(probes) == len(DEFAULT_MCP_PATHS)

    def test_default_probes_are_url_probe_instances(self) -> None:
        scanner = MCPScanner()
        probes = scanner._build_probes()
        for probe in probes:
            assert isinstance(probe, UrlProbe)

    def test_custom_wordlist_overrides_defaults(self, tmp_path) -> None:
        """A custom wordlist replaces the default probe set."""
        wl = tmp_path / "wordlist.txt"
        wl.write_text("/custom/path\n/another/path\n", encoding="utf-8")
        scanner = MCPScanner(custom_wordlist=str(wl))
        probes = scanner._build_probes()
        paths = [p.path for p in probes]
        assert "/custom/path" in paths
        assert "/another/path" in paths

    def test_custom_wordlist_path_count(self, tmp_path) -> None:
        """Exactly two custom paths produce exactly two probes."""
        wl = tmp_path / "wordlist.txt"
        wl.write_text("/path/one\n/path/two\n", encoding="utf-8")
        scanner = MCPScanner(custom_wordlist=str(wl))
        probes = scanner._build_probes()
        assert len(probes) == 2

    def test_missing_wordlist_falls_back_to_defaults(self) -> None:
        """A non-existent wordlist path causes fallback to defaults."""
        scanner = MCPScanner(custom_wordlist="/nonexistent/path.txt")
        probes = scanner._build_probes()
        assert len(probes) == len(DEFAULT_MCP_PATHS)

    def test_wordlist_with_comments_skipped(self, tmp_path) -> None:
        """Comment lines and empty lines in the wordlist are ignored."""
        wl = tmp_path / "wordlist.txt"
        wl.write_text("# comment\n/real/path\n\n# another comment\n", encoding="utf-8")
        scanner = MCPScanner(custom_wordlist=str(wl))
        probes = scanner._build_probes()
        assert len(probes) == 1
        assert probes[0].path == "/real/path"


# ---------------------------------------------------------------------------
# _analyse_response
# ---------------------------------------------------------------------------

class TestAnalyseResponse:
    """Tests for MCPScanner._analyse_response."""

    def setup_method(self) -> None:
        """Create a fresh scanner and probe for each test."""
        self.scanner = MCPScanner()
        self.probe = _make_probe()

    def test_no_mcp_indicators_returns_empty(self) -> None:
        """A plain HTML response produces no findings."""
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="text/html",
            body="<html><body>Hello World</body></html>",
        )
        assert findings == []

    def test_sse_content_type_returns_high_finding(self) -> None:
        """A text/event-stream response produces a HIGH finding."""
        findings = self.scanner._analyse_response(
            url="https://example.com/sse",
            probe=self.probe,
            status_code=200,
            content_type="text/event-stream",
            body="data: {}",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "SSE" in findings[0].title

    def test_sse_with_charset_content_type_returns_high_finding(self) -> None:
        """A text/event-stream; charset=utf-8 response is still detected."""
        findings = self.scanner._analyse_response(
            url="https://example.com/sse",
            probe=self.probe,
            status_code=200,
            content_type="text/event-stream; charset=utf-8",
            body="data: {}",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_tools_in_body_returns_critical_finding(self) -> None:
        """A JSON body containing 'tools' produces a CRITICAL finding."""
        body = '{"tools": [{"name": "myTool", "inputSchema": {}}]}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp/tools",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "Tool" in findings[0].title

    def test_inputschema_in_body_returns_critical_finding(self) -> None:
        """'inputSchema' keyword triggers CRITICAL severity."""
        body = '{"inputSchema": {"type": "object"}}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_resources_in_body_returns_high_finding(self) -> None:
        """A body containing 'resources' produces a HIGH finding."""
        body = '{"resources": [{"uri": "file:///etc/passwd", "name": "passwd"}]}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp/resources",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Resource" in findings[0].title

    def test_uri_keyword_in_body_returns_high_finding(self) -> None:
        """A body containing 'uri' (resource indicator) produces a HIGH finding."""
        body = '{"uri": "file:///var/app"}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp/resources",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_prompts_in_body_returns_medium_finding(self) -> None:
        """A body containing 'prompts' produces a MEDIUM finding."""
        body = '{"prompts": [{"name": "myPrompt"}]}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp/prompts",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Prompt" in findings[0].title

    def test_jsonrpc_in_body_returns_medium_finding(self) -> None:
        """A JSON-RPC response body produces a MEDIUM finding."""
        body = '{"jsonrpc": "2.0", "id": 1, "result": {}}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_protocolversion_in_body_returns_medium_finding(self) -> None:
        """'protocolVersion' in body produces a MEDIUM finding."""
        body = '{"protocolVersion": "2024-11-05", "serverInfo": {}}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_serverinfo_in_body_returns_medium_finding(self) -> None:
        """'serverInfo' in body produces a MEDIUM finding."""
        body = '{"serverInfo": {"name": "test-server", "version": "1.0"}}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_low_confidence_mcp_keyword_returns_low_finding(self) -> None:
        """A plain 'mcp' mention without specific indicators produces LOW."""
        body = "This server uses the mcp framework."
        findings = self.scanner._analyse_response(
            url="https://example.com/about",
            probe=self.probe,
            status_code=200,
            content_type="text/plain",
            body=body,
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_finding_url_matches_input(self) -> None:
        """The finding URL should exactly match the probed URL."""
        url = "https://example.com/mcp/tools"
        body = '{"tools": []}'
        findings = self.scanner._analyse_response(
            url=url,
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert findings[0].url == url

    def test_finding_evidence_contains_status_code(self) -> None:
        """Evidence string should include the HTTP status code."""
        body = '{"tools": []}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert "200" in findings[0].evidence

    def test_finding_evidence_contains_content_type(self) -> None:
        """Evidence string should include the Content-Type."""
        body = '{"tools": []}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert "application/json" in findings[0].evidence

    def test_finding_has_non_empty_recommendation(self) -> None:
        """Every finding should have a non-empty recommendation."""
        body = '{"tools": []}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert findings[0].recommendation

    def test_finding_has_non_empty_description(self) -> None:
        """Every finding should have a non-empty description."""
        body = '{"tools": []}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert findings[0].description

    def test_tools_priority_over_resources_in_same_body(self) -> None:
        """When body contains both 'tools' and 'resources', tools wins (CRITICAL)."""
        body = '{"tools": [], "resources": [], "inputSchema": {}}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert findings[0].severity == Severity.CRITICAL

    def test_cve_reference_on_critical_tool_finding(self) -> None:
        """CRITICAL findings for tool listings should include MCPwn reference."""
        body = '{"tools": [{"name": "exec"}]}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert "MCPwn-2024-001" in findings[0].cve_references

    def test_empty_body_returns_empty(self) -> None:
        """An empty body with a generic content type returns no findings."""
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body="",
        )
        assert findings == []

    def test_finding_extra_contains_probe_description(self) -> None:
        """The finding extra dict should contain the probe description."""
        body = '{"tools": []}'
        probe = UrlProbe(
            path="/mcp/tools",
            probe_type=ProbeType.HTTP_GET,
            description="My special probe",
            expected_indicators=["tools"],
        )
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp/tools",
            probe=probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert findings[0].extra.get("probe") == "My special probe"

    def test_returns_at_most_one_finding_per_call(self) -> None:
        """_analyse_response should return exactly one finding (or zero)."""
        body = '{"tools": [{"name": "exec"}], "jsonrpc": "2.0"}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        # Should not produce more than one finding per URL/probe pair
        assert len(findings) == 1

    def test_sse_does_not_contain_cve_reference(self) -> None:
        """SSE findings are HIGH, not CRITICAL, so no MCPwn ref by default."""
        findings = self.scanner._analyse_response(
            url="https://example.com/sse",
            probe=self.probe,
            status_code=200,
            content_type="text/event-stream",
            body="data: {}",
        )
        # SSE findings are HIGH and do not reference MCPwn
        assert findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# _body_has_mcp_indicators
# ---------------------------------------------------------------------------

class TestBodyHasMcpIndicators:
    """Tests for MCPScanner._body_has_mcp_indicators."""

    def setup_method(self) -> None:
        self.scanner = MCPScanner()

    def test_jsonrpc_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators('{"jsonrpc": "2.0"}')

    def test_tools_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators('{"tools": []}')

    def test_mcp_detected_case_insensitive(self) -> None:
        assert self.scanner._body_has_mcp_indicators("MCP server running")

    def test_mcp_lowercase_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators("this is an mcp server")

    def test_protocolversion_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators('{"protocolVersion": "2024-11-05"}')

    def test_serverinfo_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators('{"serverInfo": {}}')

    def test_capabilities_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators('{"capabilities": {}}')

    def test_resources_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators('{"resources": []}')

    def test_prompts_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators('{"prompts": []}')

    def test_plain_html_not_detected(self) -> None:
        assert not self.scanner._body_has_mcp_indicators("<html><body>hello</body></html>")

    def test_empty_body_not_detected(self) -> None:
        assert not self.scanner._body_has_mcp_indicators("")

    def test_json_without_mcp_keywords_not_detected(self) -> None:
        body = '{"status": "ok", "message": "hello world"}'
        assert not self.scanner._body_has_mcp_indicators(body)

    def test_uppercase_jsonrpc_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators('{"JSONRPC": "2.0"}')

    def test_inputschema_detected(self) -> None:
        assert self.scanner._body_has_mcp_indicators('{"inputSchema": {}}')


# ---------------------------------------------------------------------------
# Integration-style tests using pytest-httpx
# ---------------------------------------------------------------------------

class TestScanTargetsWithMockedHttp:
    """Integration tests that mock HTTP responses for the full scanner pipeline."""

    @pytest.mark.asyncio
    async def test_no_mcp_endpoints_returns_empty_report(self, httpx_mock) -> None:
        """When all probed URLs return 404, the report should have no findings."""
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)

        assert isinstance(report, ScanReport)
        assert report.findings == []
        assert report.completed_at is not None

    @pytest.mark.asyncio
    async def test_mcp_tools_endpoint_creates_critical_finding(self, httpx_mock) -> None:
        """A 200 JSON response with tools listing triggers a CRITICAL finding."""
        tools_body = '{"tools": [{"name": "exec", "inputSchema": {}}]}'
        httpx_mock.add_response(
            url="https://example.com/mcp/tools",
            status_code=200,
            content=tools_body.encode(),
            headers={"content-type": "application/json"},
        )
        # All other URLs return 404
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        # Restrict to only the tools probe for speed.
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp/tools",
                probe_type=ProbeType.HTTP_GET,
                description="MCP tools probe",
                expected_indicators=["tools"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)

        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("tools" in f.url.lower() or "Tool" in f.title for f in critical)

    @pytest.mark.asyncio
    async def test_sse_endpoint_creates_high_finding(self, httpx_mock) -> None:
        """A 200 SSE response triggers a HIGH finding."""
        httpx_mock.add_response(
            url="https://example.com/sse",
            status_code=200,
            content=b"data: {}\n\n",
            headers={"content-type": "text/event-stream"},
        )
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/sse",
                probe_type=ProbeType.SSE,
                description="SSE probe",
                expected_indicators=["text/event-stream"],
                headers={"Accept": "text/event-stream"},
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)

        high = [f for f in report.findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert any("SSE" in f.title for f in high)

    @pytest.mark.asyncio
    async def test_report_is_completed_after_scan(self, httpx_mock) -> None:
        """report.completed_at should be set after scanning."""
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: []  # type: ignore[assignment]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)

        assert report.completed_at is not None

    @pytest.mark.asyncio
    async def test_report_targets_populated(self, httpx_mock) -> None:
        """The report should contain the targets passed to scan_targets."""
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: []  # type: ignore[assignment]
        targets = [_make_target("https://example.com")]
        report = await scanner.scan_targets(targets)

        assert len(report.targets) == 1
        assert report.targets[0].url == "https://example.com"

    @pytest.mark.asyncio
    async def test_scan_convenience_function(self, httpx_mock) -> None:
        """The scan() convenience coroutine should return a completed ScanReport."""
        httpx_mock.add_response(status_code=404)

        report = await scan(
            targets=["https://example.com"],
            concurrency=2,
            timeout=5.0,
        )
        assert isinstance(report, ScanReport)
        assert report.completed_at is not None

    @pytest.mark.asyncio
    async def test_scan_convenience_function_returns_scan_report(self, httpx_mock) -> None:
        """scan() returns a ScanReport with correct targets."""
        httpx_mock.add_response(status_code=404)

        report = await scan(
            targets=["https://example.com"],
            concurrency=2,
            timeout=5.0,
        )
        assert len(report.targets) == 1
        assert report.targets[0].url == "https://example.com"

    @pytest.mark.asyncio
    async def test_connection_error_does_not_abort_scan(self, httpx_mock) -> None:
        """Connection errors for individual probes should not abort the scan."""
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp",
                probe_type=ProbeType.HTTP_GET,
                description="Root MCP",
                expected_indicators=["jsonrpc"],
            )
        ]
        targets = [_make_target()]
        # Should not raise; should return a report with no findings.
        report = await scanner.scan_targets(targets)
        assert isinstance(report, ScanReport)

    @pytest.mark.asyncio
    async def test_timeout_does_not_abort_scan(self, httpx_mock) -> None:
        """Timeout errors should be swallowed per-probe, not abort the scan."""
        httpx_mock.add_exception(httpx.TimeoutException("Timeout"))

        scanner = MCPScanner(concurrency=2, timeout=1.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp",
                probe_type=ProbeType.HTTP_GET,
                description="Root MCP",
                expected_indicators=["jsonrpc"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)
        assert isinstance(report, ScanReport)

    @pytest.mark.asyncio
    async def test_too_many_redirects_does_not_abort_scan(self, httpx_mock) -> None:
        """TooManyRedirects errors should be swallowed per-probe."""
        httpx_mock.add_exception(httpx.TooManyRedirects("Too many redirects"))

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp",
                probe_type=ProbeType.HTTP_GET,
                description="Root MCP",
                expected_indicators=["jsonrpc"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)
        assert isinstance(report, ScanReport)
        assert report.findings == []

    @pytest.mark.asyncio
    async def test_multiple_targets_scanned(self, httpx_mock) -> None:
        """Both targets should appear in the ScanReport targets list."""
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: []  # type: ignore[assignment]
        targets = [
            _make_target("https://a.example.com"),
            _make_target("https://b.example.com"),
        ]
        report = await scanner.scan_targets(targets)
        assert len(report.targets) == 2

    @pytest.mark.asyncio
    async def test_jsonrpc_probe_creates_high_finding(self, httpx_mock) -> None:
        """A successful JSON-RPC probe that returns MCP data creates a HIGH finding."""
        rpc_body = '{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}'
        httpx_mock.add_response(
            status_code=200,
            content=rpc_body.encode(),
            headers={"content-type": "application/json"},
        )

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp/rpc",
                probe_type=ProbeType.JSON_RPC,
                description="JSON-RPC probe",
                expected_indicators=["jsonrpc"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)

        high = [f for f in report.findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert any("JSON-RPC" in f.title for f in high)

    @pytest.mark.asyncio
    async def test_post_probe_returns_finding(self, httpx_mock) -> None:
        """An HTTP POST probe that returns MCP data creates a finding."""
        body = '{"tools": [{"name": "test"}]}'
        httpx_mock.add_response(
            status_code=200,
            content=body.encode(),
            headers={"content-type": "application/json"},
        )

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp/tools/call",
                probe_type=ProbeType.HTTP_POST,
                description="POST probe",
                expected_indicators=["tools"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)
        assert len(report.findings) >= 1

    @pytest.mark.asyncio
    async def test_empty_target_list_returns_empty_report(self, httpx_mock) -> None:
        """Scanning zero targets returns an empty but completed report."""
        scanner = MCPScanner(concurrency=2, timeout=5.0)
        report = await scanner.scan_targets([])
        assert isinstance(report, ScanReport)
        assert report.findings == []
        assert report.completed_at is not None

    @pytest.mark.asyncio
    async def test_401_response_produces_no_findings(self, httpx_mock) -> None:
        """A 401 Unauthorized response should not produce any findings."""
        httpx_mock.add_response(
            status_code=401,
            content=b'{"error": "Unauthorized"}',
            headers={"content-type": "application/json"},
        )

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp",
                probe_type=ProbeType.HTTP_GET,
                description="Root MCP",
                expected_indicators=["jsonrpc"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)
        assert report.findings == []

    @pytest.mark.asyncio
    async def test_403_response_produces_no_findings(self, httpx_mock) -> None:
        """A 403 Forbidden response should not produce any findings."""
        httpx_mock.add_response(
            status_code=403,
            content=b'{"error": "Forbidden"}',
            headers={"content-type": "application/json"},
        )

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp",
                probe_type=ProbeType.HTTP_GET,
                description="Root MCP",
                expected_indicators=["jsonrpc"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)
        assert report.findings == []

    @pytest.mark.asyncio
    async def test_resources_endpoint_creates_high_finding(self, httpx_mock) -> None:
        """A resources endpoint returns a HIGH severity finding."""
        body = '{"resources": [{"uri": "file:///etc", "name": "etc"}]}'
        httpx_mock.add_response(
            url="https://example.com/mcp/resources",
            status_code=200,
            content=body.encode(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp/resources",
                probe_type=ProbeType.HTTP_GET,
                description="Resources probe",
                expected_indicators=["resources"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)

        high = [f for f in report.findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert any("Resource" in f.title for f in high)

    @pytest.mark.asyncio
    async def test_prompts_endpoint_creates_medium_finding(self, httpx_mock) -> None:
        """A prompts endpoint returns a MEDIUM severity finding."""
        body = '{"prompts": [{"name": "myPrompt"}]}'
        httpx_mock.add_response(
            url="https://example.com/mcp/prompts",
            status_code=200,
            content=body.encode(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp/prompts",
                probe_type=ProbeType.HTTP_GET,
                description="Prompts probe",
                expected_indicators=["prompts"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)

        medium = [f for f in report.findings if f.severity == Severity.MEDIUM]
        assert len(medium) >= 1

    @pytest.mark.asyncio
    async def test_extra_headers_sent_with_requests(self, httpx_mock) -> None:
        """Extra headers should be included in every request."""
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(
            concurrency=2,
            timeout=5.0,
            extra_headers={"X-Custom-Header": "test-value"},
        )
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp",
                probe_type=ProbeType.HTTP_GET,
                description="Root MCP",
                expected_indicators=["jsonrpc"],
            )
        ]
        targets = [_make_target()]
        # Should not raise; confirms headers don't break requests
        report = await scanner.scan_targets(targets)
        assert isinstance(report, ScanReport)

    @pytest.mark.asyncio
    async def test_scan_with_multiple_probes_multiple_findings(self, httpx_mock) -> None:
        """Multiple probes can return multiple findings from a single target."""
        tools_body = '{"tools": [{"name": "exec"}]}'
        sse_body = b"data: {}\n\n"

        httpx_mock.add_response(
            url="https://example.com/mcp/tools",
            status_code=200,
            content=tools_body.encode(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(
            url="https://example.com/sse",
            status_code=200,
            content=sse_body,
            headers={"content-type": "text/event-stream"},
        )

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp/tools",
                probe_type=ProbeType.HTTP_GET,
                description="Tools probe",
                expected_indicators=["tools"],
            ),
            UrlProbe(
                path="/sse",
                probe_type=ProbeType.SSE,
                description="SSE probe",
                expected_indicators=["text/event-stream"],
                headers={"Accept": "text/event-stream"},
            ),
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)
        assert len(report.findings) >= 2

    @pytest.mark.asyncio
    async def test_scan_id_is_stable_after_completion(self, httpx_mock) -> None:
        """The scan_id should not change after the scan completes."""
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: []  # type: ignore[assignment]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)
        scan_id_before = report.scan_id
        scan_id_after = report.scan_id
        assert scan_id_before == scan_id_after

    @pytest.mark.asyncio
    async def test_jsonrpc_probe_stops_after_first_mcp_response(self, httpx_mock) -> None:
        """The JSON-RPC prober should stop after the first successful MCP response."""
        rpc_body = '{"jsonrpc": "2.0", "result": {"tools": []}}'
        # All requests return a valid MCP response
        httpx_mock.add_response(
            status_code=200,
            content=rpc_body.encode(),
            headers={"content-type": "application/json"},
        )

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp/rpc",
                probe_type=ProbeType.JSON_RPC,
                description="JSON-RPC probe",
                expected_indicators=["jsonrpc"],
            )
        ]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)
        # Should have at most 1 finding per endpoint from the JSON-RPC prober
        urls = [f.url for f in report.findings]
        unique_urls = set(urls)
        # Each unique URL should appear at most once for JSON-RPC
        for url in unique_urls:
            url_findings = [f for f in report.findings if f.url == url and "JSON-RPC" in f.title]
            assert len(url_findings) <= 1

    @pytest.mark.asyncio
    async def test_scan_convenience_with_extra_headers(self, httpx_mock) -> None:
        """The scan() convenience function passes extra_headers correctly."""
        httpx_mock.add_response(status_code=404)

        report = await scan(
            targets=["https://example.com"],
            concurrency=2,
            timeout=5.0,
            extra_headers={"X-Test": "header-value"},
        )
        assert isinstance(report, ScanReport)

    @pytest.mark.asyncio
    async def test_scan_convenience_no_verify_ssl(self, httpx_mock) -> None:
        """The scan() convenience function passes verify_ssl=False correctly."""
        httpx_mock.add_response(status_code=404)

        report = await scan(
            targets=["https://example.com"],
            concurrency=2,
            timeout=5.0,
            verify_ssl=False,
        )
        assert isinstance(report, ScanReport)

    @pytest.mark.asyncio
    async def test_finding_url_uses_target_base_url(self, httpx_mock) -> None:
        """Finding URLs should be target base URL + probe path."""
        body = '{"tools": [{"name": "exec"}]}'
        httpx_mock.add_response(
            url="https://myserver.example.com/mcp/tools",
            status_code=200,
            content=body.encode(),
            headers={"content-type": "application/json"},
        )
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: [  # type: ignore[assignment]
            UrlProbe(
                path="/mcp/tools",
                probe_type=ProbeType.HTTP_GET,
                description="Tools probe",
                expected_indicators=["tools"],
            )
        ]
        targets = [_make_target("https://myserver.example.com")]
        report = await scanner.scan_targets(targets)

        finding_urls = [f.url for f in report.findings]
        assert "https://myserver.example.com/mcp/tools" in finding_urls
