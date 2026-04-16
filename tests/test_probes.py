"""Unit tests for mcp_scanner.probes.

Verifies that probe patterns are complete and well-formed, JSON-RPC payloads
have correct structure, helper functions work correctly, and authentication
probe descriptors cover the expected bypass strategies.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from mcp_scanner.probes import (
    ALL_JSONRPC_PAYLOADS,
    AUTH_REQUIRED_STATUS_CODES,
    DEFAULT_AUTH_PROBES,
    DEFAULT_MCP_PATHS,
    DISCOVERY_JSONRPC_PAYLOADS,
    JSONRPC_INITIALIZE_PAYLOAD,
    JSONRPC_PING_PAYLOAD,
    JSONRPC_PROMPTS_LIST_PAYLOAD,
    JSONRPC_RESOURCES_LIST_PAYLOAD,
    JSONRPC_TOOLS_LIST_PAYLOAD,
    MCP_CONTENT_TYPES,
    MCP_RESPONSE_INDICATORS,
    SUCCESSFUL_STATUS_CODES,
    AuthProbe,
    ProbeType,
    UrlProbe,
    build_probes_from_paths,
    get_default_paths,
    get_probe_for_path,
    is_mcp_response,
    load_custom_wordlist,
)


# ---------------------------------------------------------------------------
# ProbeType enum
# ---------------------------------------------------------------------------

class TestProbeType:
    """Tests for the ProbeType enum."""

    def test_all_members_present(self) -> None:
        members = {pt.value for pt in ProbeType}
        assert "HTTP_GET" in members
        assert "HTTP_POST" in members
        assert "SSE" in members
        assert "JSON_RPC" in members

    def test_is_string_subclass(self) -> None:
        assert isinstance(ProbeType.HTTP_GET, str)

    def test_value_equals_name(self) -> None:
        assert ProbeType.HTTP_GET == "HTTP_GET"
        assert ProbeType.SSE == "SSE"
        assert ProbeType.JSON_RPC == "JSON_RPC"


# ---------------------------------------------------------------------------
# UrlProbe dataclass
# ---------------------------------------------------------------------------

class TestUrlProbe:
    """Tests for the UrlProbe dataclass."""

    def test_minimal_construction(self) -> None:
        probe = UrlProbe(
            path="/test",
            probe_type=ProbeType.HTTP_GET,
            description="A test probe",
        )
        assert probe.path == "/test"
        assert probe.probe_type == ProbeType.HTTP_GET
        assert probe.description == "A test probe"
        assert probe.expected_indicators == []
        assert probe.payload is None
        assert probe.headers == {}
        assert probe.follow_redirects is True

    def test_full_construction(self) -> None:
        probe = UrlProbe(
            path="/mcp",
            probe_type=ProbeType.JSON_RPC,
            description="Full probe",
            expected_indicators=["jsonrpc"],
            payload={"jsonrpc": "2.0", "method": "ping", "id": 1},
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )
        assert probe.payload is not None
        assert probe.payload["method"] == "ping"
        assert probe.headers["Accept"] == "application/json"
        assert probe.follow_redirects is False


# ---------------------------------------------------------------------------
# AuthProbe dataclass
# ---------------------------------------------------------------------------

class TestAuthProbe:
    """Tests for the AuthProbe dataclass."""

    def test_minimal_construction(self) -> None:
        probe = AuthProbe(
            name="test",
            description="A test auth probe",
        )
        assert probe.name == "test"
        assert probe.missing_header is None
        assert probe.bypass_headers == {}
        assert probe.expected_bypass_indicators == []

    def test_missing_header_set(self) -> None:
        probe = AuthProbe(
            name="no_auth",
            description="Strip auth header",
            missing_header="Authorization",
        )
        assert probe.missing_header == "Authorization"

    def test_bypass_headers_set(self) -> None:
        probe = AuthProbe(
            name="ip_spoof",
            description="IP spoof",
            bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        )
        assert probe.bypass_headers["X-Forwarded-For"] == "127.0.0.1"


# ---------------------------------------------------------------------------
# DEFAULT_MCP_PATHS coverage
# ---------------------------------------------------------------------------

class TestDefaultMcpPaths:
    """Tests that DEFAULT_MCP_PATHS has adequate coverage."""

    def test_list_is_non_empty(self) -> None:
        assert len(DEFAULT_MCP_PATHS) > 0

    def test_every_probe_has_valid_path(self) -> None:
        for probe in DEFAULT_MCP_PATHS:
            assert probe.path.startswith("/"), (
                f"Probe path '{probe.path}' must start with '/'"
            )

    def test_every_probe_has_description(self) -> None:
        for probe in DEFAULT_MCP_PATHS:
            assert probe.description, f"Probe for '{probe.path}' has no description"

    def test_every_probe_has_valid_type(self) -> None:
        valid_types = set(ProbeType)
        for probe in DEFAULT_MCP_PATHS:
            assert probe.probe_type in valid_types

    def test_sse_probes_have_accept_header(self) -> None:
        for probe in DEFAULT_MCP_PATHS:
            if probe.probe_type == ProbeType.SSE:
                assert probe.headers.get("Accept") == "text/event-stream", (
                    f"SSE probe '{probe.path}' missing Accept: text/event-stream header"
                )

    def test_root_mcp_path_present(self) -> None:
        paths = get_default_paths()
        assert "/mcp" in paths

    def test_sse_path_present(self) -> None:
        paths = get_default_paths()
        assert "/sse" in paths

    def test_mcp_sse_path_present(self) -> None:
        paths = get_default_paths()
        assert "/mcp/sse" in paths

    def test_well_known_mcp_present(self) -> None:
        paths = get_default_paths()
        assert "/.well-known/mcp" in paths

    def test_tools_path_present(self) -> None:
        paths = get_default_paths()
        assert "/mcp/tools" in paths

    def test_resources_path_present(self) -> None:
        paths = get_default_paths()
        assert "/mcp/resources" in paths

    def test_prompts_path_present(self) -> None:
        paths = get_default_paths()
        assert "/mcp/prompts" in paths

    def test_api_mcp_path_present(self) -> None:
        paths = get_default_paths()
        assert "/api/mcp" in paths

    def test_no_duplicate_paths(self) -> None:
        paths = get_default_paths()
        assert len(paths) == len(set(paths)), "Duplicate paths found in DEFAULT_MCP_PATHS"

    def test_at_least_ten_paths(self) -> None:
        assert len(DEFAULT_MCP_PATHS) >= 10

    def test_multiple_probe_types_covered(self) -> None:
        types_used = {p.probe_type for p in DEFAULT_MCP_PATHS}
        assert ProbeType.HTTP_GET in types_used
        assert ProbeType.SSE in types_used
        # At least HTTP_GET and SSE must be present
        assert len(types_used) >= 2


# ---------------------------------------------------------------------------
# JSON-RPC payloads
# ---------------------------------------------------------------------------

class TestJsonRpcPayloads:
    """Tests that all JSON-RPC payloads have correct structure."""

    @pytest.mark.parametrize("payload", ALL_JSONRPC_PAYLOADS)
    def test_payload_has_jsonrpc_version(self, payload: dict) -> None:
        assert payload.get("jsonrpc") == "2.0"

    @pytest.mark.parametrize("payload", ALL_JSONRPC_PAYLOADS)
    def test_payload_has_method(self, payload: dict) -> None:
        assert "method" in payload
        assert isinstance(payload["method"], str)
        assert len(payload["method"]) > 0

    def test_initialize_has_correct_fields(self) -> None:
        p = JSONRPC_INITIALIZE_PAYLOAD
        assert p["method"] == "initialize"
        assert "protocolVersion" in p["params"]
        assert "clientInfo" in p["params"]
        assert p["params"]["clientInfo"]["name"] == "mcp-scanner"

    def test_tools_list_payload_method(self) -> None:
        assert JSONRPC_TOOLS_LIST_PAYLOAD["method"] == "tools/list"

    def test_resources_list_payload_method(self) -> None:
        assert JSONRPC_RESOURCES_LIST_PAYLOAD["method"] == "resources/list"

    def test_prompts_list_payload_method(self) -> None:
        assert JSONRPC_PROMPTS_LIST_PAYLOAD["method"] == "prompts/list"

    def test_ping_payload_method(self) -> None:
        assert JSONRPC_PING_PAYLOAD["method"] == "ping"

    def test_all_payloads_have_unique_ids(self) -> None:
        # Payloads with an id field should have unique IDs
        ids = [
            p["id"] for p in ALL_JSONRPC_PAYLOADS if "id" in p
        ]
        assert len(ids) == len(set(ids)), "Duplicate JSON-RPC IDs found"

    def test_discovery_payloads_subset_of_all(self) -> None:
        all_methods = {p["method"] for p in ALL_JSONRPC_PAYLOADS}
        discovery_methods = {p["method"] for p in DISCOVERY_JSONRPC_PAYLOADS}
        assert discovery_methods.issubset(all_methods)

    def test_discovery_payloads_contains_initialize(self) -> None:
        methods = {p["method"] for p in DISCOVERY_JSONRPC_PAYLOADS}
        assert "initialize" in methods

    def test_all_payloads_list_not_empty(self) -> None:
        assert len(ALL_JSONRPC_PAYLOADS) >= 5


# ---------------------------------------------------------------------------
# Constant lists
# ---------------------------------------------------------------------------

class TestConstants:
    """Tests for MCP_RESPONSE_INDICATORS and MCP_CONTENT_TYPES."""

    def test_mcp_response_indicators_non_empty(self) -> None:
        assert len(MCP_RESPONSE_INDICATORS) > 0

    def test_jsonrpc_in_indicators(self) -> None:
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "jsonrpc" in lower_indicators

    def test_tools_in_indicators(self) -> None:
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "tools" in lower_indicators

    def test_mcp_content_types_non_empty(self) -> None:
        assert len(MCP_CONTENT_TYPES) > 0

    def test_application_json_in_content_types(self) -> None:
        assert "application/json" in MCP_CONTENT_TYPES

    def test_text_event_stream_in_content_types(self) -> None:
        assert "text/event-stream" in MCP_CONTENT_TYPES

    def test_successful_status_codes_contains_200(self) -> None:
        assert 200 in SUCCESSFUL_STATUS_CODES

    def test_auth_required_status_codes_contains_401(self) -> None:
        assert 401 in AUTH_REQUIRED_STATUS_CODES

    def test_auth_required_status_codes_contains_403(self) -> None:
        assert 403 in AUTH_REQUIRED_STATUS_CODES


# ---------------------------------------------------------------------------
# DEFAULT_AUTH_PROBES coverage
# ---------------------------------------------------------------------------

class TestDefaultAuthProbes:
    """Tests that DEFAULT_AUTH_PROBES cover expected bypass strategies."""

    def test_list_is_non_empty(self) -> None:
        assert len(DEFAULT_AUTH_PROBES) > 0

    def test_every_probe_has_name(self) -> None:
        for probe in DEFAULT_AUTH_PROBES:
            assert probe.name, f"Auth probe has empty name: {probe}"

    def test_every_probe_has_description(self) -> None:
        for probe in DEFAULT_AUTH_PROBES:
            assert probe.description, f"Auth probe '{probe.name}' has no description"

    def test_no_auth_header_probe_present(self) -> None:
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "no_auth_header" in names

    def test_no_auth_probe_strips_authorization(self) -> None:
        probe = next(p for p in DEFAULT_AUTH_PROBES if p.name == "no_auth_header")
        assert probe.missing_header == "Authorization"

    def test_ip_bypass_probe_present(self) -> None:
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        # At least one IP-based bypass probe must exist
        ip_probes = [n for n in names if "forwarded" in n or "ip" in n]
        assert len(ip_probes) >= 1

    def test_empty_bearer_probe_present(self) -> None:
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "empty_bearer_token" in names

    def test_unique_probe_names(self) -> None:
        names = [p.name for p in DEFAULT_AUTH_PROBES]
        assert len(names) == len(set(names)), "Duplicate auth probe names found"

    def test_at_least_five_auth_probes(self) -> None:
        assert len(DEFAULT_AUTH_PROBES) >= 5

    def test_no_auth_probe_has_expected_bypass_indicators(self) -> None:
        probe = next(p for p in DEFAULT_AUTH_PROBES if p.name == "no_auth_header")
        assert len(probe.expected_bypass_indicators) > 0


# ---------------------------------------------------------------------------
# get_default_paths
# ---------------------------------------------------------------------------

class TestGetDefaultPaths:
    """Tests for the get_default_paths() helper."""

    def test_returns_list_of_strings(self) -> None:
        paths = get_default_paths()
        assert isinstance(paths, list)
        assert all(isinstance(p, str) for p in paths)

    def test_length_matches_default_mcp_paths(self) -> None:
        paths = get_default_paths()
        assert len(paths) == len(DEFAULT_MCP_PATHS)

    def test_all_paths_start_with_slash(self) -> None:
        for path in get_default_paths():
            assert path.startswith("/"), f"Path '{path}' does not start with '/'"


# ---------------------------------------------------------------------------
# get_probe_for_path
# ---------------------------------------------------------------------------

class TestGetProbeForPath:
    """Tests for the get_probe_for_path() helper."""

    def test_returns_probe_for_known_path(self) -> None:
        probe = get_probe_for_path("/mcp")
        assert probe is not None
        assert probe.path == "/mcp"

    def test_returns_none_for_unknown_path(self) -> None:
        probe = get_probe_for_path("/nonexistent/path")
        assert probe is None

    def test_returns_correct_probe_type_for_sse(self) -> None:
        probe = get_probe_for_path("/sse")
        assert probe is not None
        assert probe.probe_type == ProbeType.SSE

    def test_returns_correct_probe_type_for_mcp(self) -> None:
        probe = get_probe_for_path("/mcp")
        assert probe is not None
        assert probe.probe_type == ProbeType.HTTP_GET

    def test_returns_probe_for_tools_path(self) -> None:
        probe = get_probe_for_path("/mcp/tools")
        assert probe is not None
        assert probe.path == "/mcp/tools"


# ---------------------------------------------------------------------------
# load_custom_wordlist
# ---------------------------------------------------------------------------

class TestLoadCustomWordlist:
    """Tests for the load_custom_wordlist() helper."""

    def _write_wordlist(self, content: str) -> str:
        """Write content to a temp file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        Path(path).write_text(content, encoding="utf-8")
        return path

    def test_basic_paths_loaded(self) -> None:
        path = self._write_wordlist("/mcp\n/sse\n/api/mcp\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse", "/api/mcp"]

    def test_comments_skipped(self) -> None:
        path = self._write_wordlist("# comment\n/mcp\n# another comment\n/sse\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse"]

    def test_empty_lines_skipped(self) -> None:
        path = self._write_wordlist("\n\n/mcp\n\n/sse\n\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse"]

    def test_slash_prepended_if_missing(self) -> None:
        path = self._write_wordlist("mcp\nsse\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse"]

    def test_existing_slash_not_doubled(self) -> None:
        path = self._write_wordlist("/mcp\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp"]

    def test_file_not_found_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_custom_wordlist("/nonexistent/path/wordlist.txt")

    def test_empty_file_returns_empty_list(self) -> None:
        path = self._write_wordlist("")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == []

    def test_only_comments_returns_empty_list(self) -> None:
        path = self._write_wordlist("# just comments\n# more comments\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == []

    def test_whitespace_stripped(self) -> None:
        path = self._write_wordlist("  /mcp  \n  /sse  \n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse"]


# ---------------------------------------------------------------------------
# build_probes_from_paths
# ---------------------------------------------------------------------------

class TestBuildProbesFromPaths:
    """Tests for the build_probes_from_paths() helper."""

    def test_known_path_returns_existing_probe(self) -> None:
        probes = build_probes_from_paths(["/mcp"])
        assert len(probes) == 1
        # Should reuse the rich default probe
        assert probes[0].description != "Custom probe: /mcp"
        assert any(
            ind in probes[0].expected_indicators for ind in ["mcp", "jsonrpc"]
        )

    def test_unknown_path_creates_get_probe(self) -> None:
        probes = build_probes_from_paths(["/unknown/path"])
        assert len(probes) == 1
        assert probes[0].probe_type == ProbeType.HTTP_GET
        assert probes[0].path == "/unknown/path"

    def test_sse_keyword_creates_sse_probe(self) -> None:
        probes = build_probes_from_paths(["/custom/sse"])
        assert probes[0].probe_type == ProbeType.SSE
        assert probes[0].headers.get("Accept") == "text/event-stream"

    def test_stream_keyword_creates_sse_probe(self) -> None:
        probes = build_probes_from_paths(["/custom/stream"])
        assert probes[0].probe_type == ProbeType.SSE

    def test_event_keyword_creates_sse_probe(self) -> None:
        probes = build_probes_from_paths(["/custom/events"])
        assert probes[0].probe_type == ProbeType.SSE

    def test_rpc_keyword_creates_jsonrpc_probe(self) -> None:
        probes = build_probes_from_paths(["/custom/rpc"])
        assert probes[0].probe_type == ProbeType.JSON_RPC

    def test_mixed_paths(self) -> None:
        paths = ["/mcp", "/custom/sse", "/unknown"]
        probes = build_probes_from_paths(paths)
        assert len(probes) == 3
        assert probes[1].probe_type == ProbeType.SSE
        assert probes[2].probe_type == ProbeType.HTTP_GET

    def test_empty_input_returns_empty_list(self) -> None:
        probes = build_probes_from_paths([])
        assert probes == []

    def test_custom_probe_has_expected_indicators(self) -> None:
        probes = build_probes_from_paths(["/totally/unknown"])
        assert len(probes[0].expected_indicators) > 0

    def test_preserves_order(self) -> None:
        paths = ["/mcp/tools", "/mcp/resources", "/mcp/prompts"]
        probes = build_probes_from_paths(paths)
        assert [p.path for p in probes] == paths


# ---------------------------------------------------------------------------
# is_mcp_response
# ---------------------------------------------------------------------------

class TestIsMcpResponse:
    """Tests for the is_mcp_response() helper function."""

    def test_sse_content_type_returns_true(self) -> None:
        assert is_mcp_response("", "text/event-stream") is True

    def test_sse_content_type_with_charset_returns_true(self) -> None:
        assert is_mcp_response("", "text/event-stream; charset=utf-8") is True

    def test_json_with_jsonrpc_keyword_returns_true(self) -> None:
        body = '{"jsonrpc": "2.0", "result": {}}'
        assert is_mcp_response(body, "application/json") is True

    def test_json_with_tools_keyword_returns_true(self) -> None:
        body = '{"tools": [{"name": "myTool"}]}'
        assert is_mcp_response(body, "application/json") is True

    def test_json_without_mcp_keywords_returns_false(self) -> None:
        body = '{"status": "ok", "message": "hello world"}'
        assert is_mcp_response(body, "application/json") is False

    def test_empty_body_json_returns_false(self) -> None:
        assert is_mcp_response("", "application/json") is False

    def test_unknown_content_type_with_keyword_returns_true(self) -> None:
        body = "protocolVersion: 2024-11-05"
        assert is_mcp_response(body, "text/plain") is True

    def test_unknown_content_type_without_keyword_returns_false(self) -> None:
        body = "<html><body>Hello</body></html>"
        assert is_mcp_response(body, "text/html") is False

    def test_case_insensitive_keyword_match(self) -> None:
        body = '{"JSONRPC": "2.0"}'
        assert is_mcp_response(body, "application/json") is True

    def test_mcp_keyword_alone_returns_true(self) -> None:
        body = "This is an mcp server"
        assert is_mcp_response(body, "text/plain") is True

    def test_json_rpc_content_type_variant(self) -> None:
        body = '{"jsonrpc": "2.0", "result": {}}'
        assert is_mcp_response(body, "application/json-rpc") is True
