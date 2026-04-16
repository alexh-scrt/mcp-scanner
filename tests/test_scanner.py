"""Unit tests for mcp_scanner.scanner.

Uses pytest-httpx to mock HTTP responses so that the scanner engine
can be tested without making real network requests.
"""

from __future__ import annotations

import pytest
import httpx

from mcp_scanner.models import Finding, ScanReport, ScanTarget, Severity
from mcp_scanner.probes import UrlProbe, ProbeType
from mcp_scanner.scanner import MCPScanner, scan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_target(url: str = "https://example.com") -> ScanTarget:
    return ScanTarget(url=url, timeout=5.0)


def _make_probe(
    path: str = "/mcp",
    probe_type: ProbeType = ProbeType.HTTP_GET,
) -> UrlProbe:
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
        scanner = MCPScanner()
        assert scanner.concurrency == 10
        assert scanner.timeout == 10.0
        assert scanner.verify_ssl is True
        assert scanner.custom_wordlist is None
        assert scanner.extra_headers == {}
        assert scanner.verbose is False

    def test_custom_values(self) -> None:
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


# ---------------------------------------------------------------------------
# _build_probes
# ---------------------------------------------------------------------------

class TestBuildProbes:
    """Tests for MCPScanner._build_probes."""

    def test_returns_default_probes_without_wordlist(self) -> None:
        from mcp_scanner.probes import DEFAULT_MCP_PATHS
        scanner = MCPScanner()
        probes = scanner._build_probes()
        assert len(probes) == len(DEFAULT_MCP_PATHS)

    def test_custom_wordlist_overrides_defaults(self, tmp_path) -> None:
        wl = tmp_path / "wordlist.txt"
        wl.write_text("/custom/path\n/another/path\n", encoding="utf-8")
        scanner = MCPScanner(custom_wordlist=str(wl))
        probes = scanner._build_probes()
        paths = [p.path for p in probes]
        assert "/custom/path" in paths
        assert "/another/path" in paths

    def test_missing_wordlist_falls_back_to_defaults(self) -> None:
        from mcp_scanner.probes import DEFAULT_MCP_PATHS
        scanner = MCPScanner(custom_wordlist="/nonexistent/path.txt")
        probes = scanner._build_probes()
        assert len(probes) == len(DEFAULT_MCP_PATHS)


# ---------------------------------------------------------------------------
# _analyse_response
# ---------------------------------------------------------------------------

class TestAnalyseResponse:
    """Tests for MCPScanner._analyse_response."""

    def setup_method(self) -> None:
        self.scanner = MCPScanner()
        self.probe = _make_probe()

    def test_no_mcp_indicators_returns_empty(self) -> None:
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="text/html",
            body="<html><body>Hello World</body></html>",
        )
        assert findings == []

    def test_sse_content_type_returns_high_finding(self) -> None:
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

    def test_tools_in_body_returns_critical_finding(self) -> None:
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

    def test_prompts_in_body_returns_medium_finding(self) -> None:
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

    def test_low_confidence_mcp_keyword_returns_low_finding(self) -> None:
        # "mcp" alone without any more specific indicator
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
        body = '{"tools": []}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert "200" in findings[0].evidence

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
        body = '{"tools": [{"name": "exec"}]}'
        findings = self.scanner._analyse_response(
            url="https://example.com/mcp",
            probe=self.probe,
            status_code=200,
            content_type="application/json",
            body=body,
        )
        assert "MCPwn-2024-001" in findings[0].cve_references


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

    def test_plain_html_not_detected(self) -> None:
        assert not self.scanner._body_has_mcp_indicators("<html><body>hello</body></html>")

    def test_empty_body_not_detected(self) -> None:
        assert not self.scanner._body_has_mcp_indicators("")


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
        # All URLs return 404 except the one we care about.
        httpx_mock.add_response(status_code=404)
        httpx_mock.add_response(
            url="https://example.com/mcp/tools",
            status_code=200,
            content=tools_body.encode(),
            headers={"content-type": "application/json"},
        )

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
        httpx_mock.add_response(status_code=404)
        httpx_mock.add_response(
            url="https://example.com/sse",
            status_code=200,
            content=b"data: {}\n\n",
            headers={"content-type": "text/event-stream"},
        )

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
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: []  # type: ignore[assignment]
        targets = [_make_target()]
        report = await scanner.scan_targets(targets)

        assert report.completed_at is not None

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
    async def test_multiple_targets_scanned(self, httpx_mock) -> None:
        """Both targets should appear in the ScanReport targets list."""
        httpx_mock.add_response(status_code=404)

        scanner = MCPScanner(concurrency=2, timeout=5.0)
        scanner._build_probes = lambda: []  # type: ignore[assignment]
        targets = [_make_target("https://a.example.com"), _make_target("https://b.example.com")]
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
