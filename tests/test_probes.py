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
    JSONRPC_COMPLETION_PAYLOAD,
    JSONRPC_INITIALIZE_PAYLOAD,
    JSONRPC_NOTIFICATIONS_INITIALIZED_PAYLOAD,
    JSONRPC_PING_PAYLOAD,
    JSONRPC_PROMPTS_LIST_PAYLOAD,
    JSONRPC_RESOURCES_LIST_PAYLOAD,
    JSONRPC_RESOURCES_READ_PAYLOAD,
    JSONRPC_SERVER_INFO_PAYLOAD,
    JSONRPC_TOOLS_CALL_PAYLOAD,
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
        """All four probe types should be defined."""
        members = {pt.value for pt in ProbeType}
        assert "HTTP_GET" in members
        assert "HTTP_POST" in members
        assert "SSE" in members
        assert "JSON_RPC" in members

    def test_exactly_four_members(self) -> None:
        """There should be exactly four ProbeType members."""
        assert len(list(ProbeType)) == 4

    def test_is_string_subclass(self) -> None:
        """ProbeType should be a str subclass."""
        assert isinstance(ProbeType.HTTP_GET, str)
        assert isinstance(ProbeType.SSE, str)
        assert isinstance(ProbeType.JSON_RPC, str)
        assert isinstance(ProbeType.HTTP_POST, str)

    def test_value_equals_name_http_get(self) -> None:
        assert ProbeType.HTTP_GET == "HTTP_GET"

    def test_value_equals_name_http_post(self) -> None:
        assert ProbeType.HTTP_POST == "HTTP_POST"

    def test_value_equals_name_sse(self) -> None:
        assert ProbeType.SSE == "SSE"

    def test_value_equals_name_json_rpc(self) -> None:
        assert ProbeType.JSON_RPC == "JSON_RPC"

    def test_probe_type_value_attribute(self) -> None:
        assert ProbeType.HTTP_GET.value == "HTTP_GET"
        assert ProbeType.JSON_RPC.value == "JSON_RPC"

    def test_probe_type_comparable_to_string(self) -> None:
        assert ProbeType.SSE == "SSE"
        assert ProbeType.HTTP_POST == "HTTP_POST"

    def test_probe_type_iteration(self) -> None:
        """Should be iterable like any enum."""
        types = list(ProbeType)
        assert len(types) == 4


# ---------------------------------------------------------------------------
# UrlProbe dataclass
# ---------------------------------------------------------------------------


class TestUrlProbe:
    """Tests for the UrlProbe dataclass."""

    def test_minimal_construction(self) -> None:
        """Minimal UrlProbe should set defaults correctly."""
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
        """All fields should be settable."""
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

    def test_expected_indicators_mutable_default(self) -> None:
        """Each UrlProbe should have its own independent expected_indicators list."""
        probe1 = UrlProbe(path="/a", probe_type=ProbeType.HTTP_GET, description="a")
        probe2 = UrlProbe(path="/b", probe_type=ProbeType.HTTP_GET, description="b")
        probe1.expected_indicators.append("test")
        assert "test" not in probe2.expected_indicators

    def test_headers_mutable_default(self) -> None:
        """Each UrlProbe should have its own independent headers dict."""
        probe1 = UrlProbe(path="/a", probe_type=ProbeType.HTTP_GET, description="a")
        probe2 = UrlProbe(path="/b", probe_type=ProbeType.HTTP_GET, description="b")
        probe1.headers["X-Test"] = "value"
        assert "X-Test" not in probe2.headers

    def test_follow_redirects_default_true(self) -> None:
        probe = UrlProbe(path="/test", probe_type=ProbeType.HTTP_GET, description="test")
        assert probe.follow_redirects is True

    def test_payload_default_none(self) -> None:
        probe = UrlProbe(path="/test", probe_type=ProbeType.HTTP_POST, description="test")
        assert probe.payload is None

    def test_sse_probe_with_accept_header(self) -> None:
        """SSE probes should be constructable with the Accept header."""
        probe = UrlProbe(
            path="/sse",
            probe_type=ProbeType.SSE,
            description="SSE probe",
            headers={"Accept": "text/event-stream"},
        )
        assert probe.headers["Accept"] == "text/event-stream"

    def test_jsonrpc_probe_with_payload(self) -> None:
        """JSON-RPC probes should be constructable with a payload."""
        probe = UrlProbe(
            path="/rpc",
            probe_type=ProbeType.JSON_RPC,
            description="RPC probe",
            payload=JSONRPC_INITIALIZE_PAYLOAD,
        )
        assert probe.payload is not None
        assert probe.payload["method"] == "initialize"


# ---------------------------------------------------------------------------
# AuthProbe dataclass
# ---------------------------------------------------------------------------


class TestAuthProbe:
    """Tests for the AuthProbe dataclass."""

    def test_minimal_construction(self) -> None:
        """Minimal AuthProbe should set defaults correctly."""
        probe = AuthProbe(
            name="test",
            description="A test auth probe",
        )
        assert probe.name == "test"
        assert probe.description == "A test auth probe"
        assert probe.missing_header is None
        assert probe.bypass_headers == {}
        assert probe.expected_bypass_indicators == []

    def test_missing_header_set(self) -> None:
        """missing_header should be stored correctly."""
        probe = AuthProbe(
            name="no_auth",
            description="Strip auth header",
            missing_header="Authorization",
        )
        assert probe.missing_header == "Authorization"

    def test_bypass_headers_set(self) -> None:
        """bypass_headers dict should be stored correctly."""
        probe = AuthProbe(
            name="ip_spoof",
            description="IP spoof",
            bypass_headers={"X-Forwarded-For": "127.0.0.1"},
        )
        assert probe.bypass_headers["X-Forwarded-For"] == "127.0.0.1"

    def test_expected_bypass_indicators_set(self) -> None:
        """expected_bypass_indicators should be stored correctly."""
        probe = AuthProbe(
            name="test",
            description="test",
            expected_bypass_indicators=["tools", "jsonrpc"],
        )
        assert "tools" in probe.expected_bypass_indicators
        assert "jsonrpc" in probe.expected_bypass_indicators

    def test_bypass_headers_mutable_default(self) -> None:
        """Each AuthProbe should have its own independent bypass_headers dict."""
        probe1 = AuthProbe(name="a", description="a")
        probe2 = AuthProbe(name="b", description="b")
        probe1.bypass_headers["X-Test"] = "value"
        assert "X-Test" not in probe2.bypass_headers

    def test_expected_bypass_indicators_mutable_default(self) -> None:
        """Each AuthProbe should have its own independent indicators list."""
        probe1 = AuthProbe(name="a", description="a")
        probe2 = AuthProbe(name="b", description="b")
        probe1.expected_bypass_indicators.append("test")
        assert "test" not in probe2.expected_bypass_indicators

    def test_full_construction(self) -> None:
        """All fields should be settable."""
        probe = AuthProbe(
            name="full_probe",
            description="Full probe description",
            missing_header="Authorization",
            bypass_headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
            expected_bypass_indicators=["tools", "resources", "jsonrpc"],
        )
        assert probe.name == "full_probe"
        assert probe.missing_header == "Authorization"
        assert len(probe.bypass_headers) == 2
        assert len(probe.expected_bypass_indicators) == 3


# ---------------------------------------------------------------------------
# DEFAULT_MCP_PATHS coverage
# ---------------------------------------------------------------------------


class TestDefaultMcpPaths:
    """Tests that DEFAULT_MCP_PATHS has adequate coverage."""

    def test_list_is_non_empty(self) -> None:
        """DEFAULT_MCP_PATHS should not be empty."""
        assert len(DEFAULT_MCP_PATHS) > 0

    def test_every_probe_has_valid_path(self) -> None:
        """Every probe path should start with '/'."""
        for probe in DEFAULT_MCP_PATHS:
            assert probe.path.startswith("/"), (
                f"Probe path '{probe.path}' must start with '/'"
            )

    def test_every_probe_has_description(self) -> None:
        """Every probe should have a non-empty description."""
        for probe in DEFAULT_MCP_PATHS:
            assert probe.description, f"Probe for '{probe.path}' has no description"

    def test_every_probe_has_valid_type(self) -> None:
        """Every probe type should be a valid ProbeType member."""
        valid_types = set(ProbeType)
        for probe in DEFAULT_MCP_PATHS:
            assert probe.probe_type in valid_types

    def test_sse_probes_have_accept_header(self) -> None:
        """All SSE probes should include Accept: text/event-stream header."""
        for probe in DEFAULT_MCP_PATHS:
            if probe.probe_type == ProbeType.SSE:
                assert probe.headers.get("Accept") == "text/event-stream", (
                    f"SSE probe '{probe.path}' missing Accept: text/event-stream header"
                )

    def test_root_mcp_path_present(self) -> None:
        """The /mcp path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp" in paths

    def test_sse_path_present(self) -> None:
        """The /sse path should be in the defaults."""
        paths = get_default_paths()
        assert "/sse" in paths

    def test_mcp_sse_path_present(self) -> None:
        """The /mcp/sse path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp/sse" in paths

    def test_well_known_mcp_present(self) -> None:
        """The /.well-known/mcp path should be in the defaults."""
        paths = get_default_paths()
        assert "/.well-known/mcp" in paths

    def test_tools_path_present(self) -> None:
        """The /mcp/tools path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp/tools" in paths

    def test_resources_path_present(self) -> None:
        """The /mcp/resources path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp/resources" in paths

    def test_prompts_path_present(self) -> None:
        """The /mcp/prompts path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp/prompts" in paths

    def test_api_mcp_path_present(self) -> None:
        """The /api/mcp path should be in the defaults."""
        paths = get_default_paths()
        assert "/api/mcp" in paths

    def test_no_duplicate_paths(self) -> None:
        """There should be no duplicate paths in DEFAULT_MCP_PATHS."""
        paths = get_default_paths()
        assert len(paths) == len(set(paths)), "Duplicate paths found in DEFAULT_MCP_PATHS"

    def test_at_least_ten_paths(self) -> None:
        """There should be at least 10 default probe paths."""
        assert len(DEFAULT_MCP_PATHS) >= 10

    def test_multiple_probe_types_covered(self) -> None:
        """At least HTTP_GET and SSE probe types should be present."""
        types_used = {p.probe_type for p in DEFAULT_MCP_PATHS}
        assert ProbeType.HTTP_GET in types_used
        assert ProbeType.SSE in types_used
        assert len(types_used) >= 2

    def test_all_probes_are_url_probe_instances(self) -> None:
        """Every item in DEFAULT_MCP_PATHS should be a UrlProbe."""
        for probe in DEFAULT_MCP_PATHS:
            assert isinstance(probe, UrlProbe)

    def test_well_known_mcp_json_present(self) -> None:
        """The /.well-known/mcp.json path should be in the defaults."""
        paths = get_default_paths()
        assert "/.well-known/mcp.json" in paths

    def test_mcp_tools_list_path_present(self) -> None:
        """The /mcp/tools/list path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp/tools/list" in paths

    def test_mcp_resources_list_path_present(self) -> None:
        """The /mcp/resources/list path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp/resources/list" in paths

    def test_mcp_initialize_path_present(self) -> None:
        """The /mcp/initialize path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp/initialize" in paths

    def test_jsonrpc_probe_type_present(self) -> None:
        """At least one JSON_RPC probe type should be in the defaults."""
        types_used = {p.probe_type for p in DEFAULT_MCP_PATHS}
        assert ProbeType.JSON_RPC in types_used

    def test_http_post_probe_type_present(self) -> None:
        """At least one HTTP_POST probe type should be in the defaults."""
        types_used = {p.probe_type for p in DEFAULT_MCP_PATHS}
        assert ProbeType.HTTP_POST in types_used

    def test_mcp_health_path_present(self) -> None:
        """The /mcp/health path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp/health" in paths

    def test_mcp_info_path_present(self) -> None:
        """The /mcp/info path should be in the defaults."""
        paths = get_default_paths()
        assert "/mcp/info" in paths

    def test_stream_path_present(self) -> None:
        """The /stream path should be in the defaults."""
        paths = get_default_paths()
        assert "/stream" in paths

    def test_all_sse_probes_count(self) -> None:
        """There should be multiple SSE probes in the defaults."""
        sse_probes = [p for p in DEFAULT_MCP_PATHS if p.probe_type == ProbeType.SSE]
        assert len(sse_probes) >= 3

    def test_paths_are_strings(self) -> None:
        """All probe paths should be plain strings."""
        for probe in DEFAULT_MCP_PATHS:
            assert isinstance(probe.path, str)

    def test_descriptions_are_strings(self) -> None:
        """All probe descriptions should be plain strings."""
        for probe in DEFAULT_MCP_PATHS:
            assert isinstance(probe.description, str)

    def test_nginx_mcpwn_path_present(self) -> None:
        """The MCPwn-inspired nginx path should be in the defaults."""
        paths = get_default_paths()
        assert "/nginx/mcp" in paths or "/api/v1/mcp" in paths


# ---------------------------------------------------------------------------
# JSON-RPC payloads
# ---------------------------------------------------------------------------


class TestJsonRpcPayloads:
    """Tests that all JSON-RPC payloads have correct structure."""

    @pytest.mark.parametrize("payload", ALL_JSONRPC_PAYLOADS)
    def test_payload_has_jsonrpc_version(self, payload: dict) -> None:
        """Every payload should declare JSON-RPC version 2.0."""
        assert payload.get("jsonrpc") == "2.0"

    @pytest.mark.parametrize("payload", ALL_JSONRPC_PAYLOADS)
    def test_payload_has_method(self, payload: dict) -> None:
        """Every payload should have a non-empty 'method' field."""
        assert "method" in payload
        assert isinstance(payload["method"], str)
        assert len(payload["method"]) > 0

    def test_initialize_has_correct_fields(self) -> None:
        """The initialize payload should have the required MCP fields."""
        p = JSONRPC_INITIALIZE_PAYLOAD
        assert p["method"] == "initialize"
        assert "protocolVersion" in p["params"]
        assert "clientInfo" in p["params"]
        assert p["params"]["clientInfo"]["name"] == "mcp-scanner"

    def test_initialize_has_protocol_version(self) -> None:
        """The initialize payload should include a protocolVersion."""
        assert "protocolVersion" in JSONRPC_INITIALIZE_PAYLOAD["params"]
        assert isinstance(JSONRPC_INITIALIZE_PAYLOAD["params"]["protocolVersion"], str)

    def test_initialize_has_capabilities(self) -> None:
        """The initialize payload should include a capabilities field."""
        assert "capabilities" in JSONRPC_INITIALIZE_PAYLOAD["params"]

    def test_tools_list_payload_method(self) -> None:
        assert JSONRPC_TOOLS_LIST_PAYLOAD["method"] == "tools/list"

    def test_resources_list_payload_method(self) -> None:
        assert JSONRPC_RESOURCES_LIST_PAYLOAD["method"] == "resources/list"

    def test_prompts_list_payload_method(self) -> None:
        assert JSONRPC_PROMPTS_LIST_PAYLOAD["method"] == "prompts/list"

    def test_ping_payload_method(self) -> None:
        assert JSONRPC_PING_PAYLOAD["method"] == "ping"

    def test_server_info_payload_method(self) -> None:
        assert JSONRPC_SERVER_INFO_PAYLOAD["method"] == "server/info"

    def test_tools_call_payload_method(self) -> None:
        assert JSONRPC_TOOLS_CALL_PAYLOAD["method"] == "tools/call"

    def test_tools_call_has_params(self) -> None:
        """tools/call payload should include the params with a name field."""
        assert "params" in JSONRPC_TOOLS_CALL_PAYLOAD
        assert "name" in JSONRPC_TOOLS_CALL_PAYLOAD["params"]

    def test_resources_read_payload_method(self) -> None:
        assert JSONRPC_RESOURCES_READ_PAYLOAD["method"] == "resources/read"

    def test_resources_read_has_uri_param(self) -> None:
        """resources/read payload should include a URI parameter."""
        assert "uri" in JSONRPC_RESOURCES_READ_PAYLOAD["params"]

    def test_completion_payload_method(self) -> None:
        assert JSONRPC_COMPLETION_PAYLOAD["method"] == "completion/complete"

    def test_notifications_initialized_has_no_id(self) -> None:
        """notifications/initialized is a notification, should have no id."""
        assert "id" not in JSONRPC_NOTIFICATIONS_INITIALIZED_PAYLOAD

    def test_notifications_initialized_method(self) -> None:
        assert JSONRPC_NOTIFICATIONS_INITIALIZED_PAYLOAD["method"] == "notifications/initialized"

    def test_all_payloads_have_unique_ids(self) -> None:
        """Payloads with an id field should have unique IDs."""
        ids = [
            p["id"] for p in ALL_JSONRPC_PAYLOADS if "id" in p
        ]
        assert len(ids) == len(set(ids)), "Duplicate JSON-RPC IDs found"

    def test_discovery_payloads_subset_of_all(self) -> None:
        """DISCOVERY_JSONRPC_PAYLOADS methods should all be in ALL_JSONRPC_PAYLOADS."""
        all_methods = {p["method"] for p in ALL_JSONRPC_PAYLOADS}
        discovery_methods = {p["method"] for p in DISCOVERY_JSONRPC_PAYLOADS}
        assert discovery_methods.issubset(all_methods)

    def test_discovery_payloads_contains_initialize(self) -> None:
        """DISCOVERY_JSONRPC_PAYLOADS should include the initialize method."""
        methods = {p["method"] for p in DISCOVERY_JSONRPC_PAYLOADS}
        assert "initialize" in methods

    def test_discovery_payloads_contains_tools_list(self) -> None:
        """DISCOVERY_JSONRPC_PAYLOADS should include tools/list."""
        methods = {p["method"] for p in DISCOVERY_JSONRPC_PAYLOADS}
        assert "tools/list" in methods

    def test_discovery_payloads_contains_resources_list(self) -> None:
        """DISCOVERY_JSONRPC_PAYLOADS should include resources/list."""
        methods = {p["method"] for p in DISCOVERY_JSONRPC_PAYLOADS}
        assert "resources/list" in methods

    def test_discovery_payloads_contains_prompts_list(self) -> None:
        """DISCOVERY_JSONRPC_PAYLOADS should include prompts/list."""
        methods = {p["method"] for p in DISCOVERY_JSONRPC_PAYLOADS}
        assert "prompts/list" in methods

    def test_all_payloads_list_not_empty(self) -> None:
        """ALL_JSONRPC_PAYLOADS should contain at least 5 entries."""
        assert len(ALL_JSONRPC_PAYLOADS) >= 5

    def test_all_payloads_have_params(self) -> None:
        """Every payload (except maybe notifications) should have params."""
        for payload in ALL_JSONRPC_PAYLOADS:
            assert "params" in payload, (
                f"Payload for method '{payload.get('method')}' missing 'params'"
            )

    def test_payload_jsonrpc_is_string_two_zero(self) -> None:
        """The jsonrpc field should be the string '2.0'."""
        for payload in ALL_JSONRPC_PAYLOADS:
            assert isinstance(payload["jsonrpc"], str)
            assert payload["jsonrpc"] == "2.0"

    def test_discovery_payloads_non_empty(self) -> None:
        """DISCOVERY_JSONRPC_PAYLOADS should not be empty."""
        assert len(DISCOVERY_JSONRPC_PAYLOADS) >= 4

    def test_all_payloads_methods_are_strings(self) -> None:
        """All method fields should be non-empty strings."""
        for payload in ALL_JSONRPC_PAYLOADS:
            assert isinstance(payload["method"], str)
            assert len(payload["method"]) > 0

    def test_client_info_has_version(self) -> None:
        """The initialize payload clientInfo should include a version."""
        client_info = JSONRPC_INITIALIZE_PAYLOAD["params"]["clientInfo"]
        assert "version" in client_info
        assert isinstance(client_info["version"], str)


# ---------------------------------------------------------------------------
# Constant lists
# ---------------------------------------------------------------------------


class TestConstants:
    """Tests for MCP_RESPONSE_INDICATORS and MCP_CONTENT_TYPES."""

    def test_mcp_response_indicators_non_empty(self) -> None:
        """MCP_RESPONSE_INDICATORS should not be empty."""
        assert len(MCP_RESPONSE_INDICATORS) > 0

    def test_jsonrpc_in_indicators(self) -> None:
        """'jsonrpc' should be an MCP response indicator."""
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "jsonrpc" in lower_indicators

    def test_tools_in_indicators(self) -> None:
        """'tools' should be an MCP response indicator."""
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "tools" in lower_indicators

    def test_resources_in_indicators(self) -> None:
        """'resources' should be an MCP response indicator."""
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "resources" in lower_indicators

    def test_prompts_in_indicators(self) -> None:
        """'prompts' should be an MCP response indicator."""
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "prompts" in lower_indicators

    def test_capabilities_in_indicators(self) -> None:
        """'capabilities' should be an MCP response indicator."""
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "capabilities" in lower_indicators

    def test_mcp_in_indicators(self) -> None:
        """'mcp' should be an MCP response indicator."""
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "mcp" in lower_indicators

    def test_serverinfo_in_indicators(self) -> None:
        """'serverInfo' should be an MCP response indicator."""
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "serverinfo" in lower_indicators

    def test_protocolversion_in_indicators(self) -> None:
        """'protocolVersion' should be an MCP response indicator."""
        lower_indicators = [i.lower() for i in MCP_RESPONSE_INDICATORS]
        assert "protocolversion" in lower_indicators

    def test_mcp_content_types_non_empty(self) -> None:
        """MCP_CONTENT_TYPES should not be empty."""
        assert len(MCP_CONTENT_TYPES) > 0

    def test_application_json_in_content_types(self) -> None:
        """'application/json' should be a recognised MCP content type."""
        assert "application/json" in MCP_CONTENT_TYPES

    def test_text_event_stream_in_content_types(self) -> None:
        """'text/event-stream' should be a recognised MCP content type."""
        assert "text/event-stream" in MCP_CONTENT_TYPES

    def test_successful_status_codes_contains_200(self) -> None:
        """200 should be in SUCCESSFUL_STATUS_CODES."""
        assert 200 in SUCCESSFUL_STATUS_CODES

    def test_successful_status_codes_contains_201(self) -> None:
        """201 should be in SUCCESSFUL_STATUS_CODES."""
        assert 201 in SUCCESSFUL_STATUS_CODES

    def test_successful_status_codes_is_frozenset(self) -> None:
        """SUCCESSFUL_STATUS_CODES should be a frozenset."""
        assert isinstance(SUCCESSFUL_STATUS_CODES, frozenset)

    def test_auth_required_status_codes_contains_401(self) -> None:
        """401 should be in AUTH_REQUIRED_STATUS_CODES."""
        assert 401 in AUTH_REQUIRED_STATUS_CODES

    def test_auth_required_status_codes_contains_403(self) -> None:
        """403 should be in AUTH_REQUIRED_STATUS_CODES."""
        assert 403 in AUTH_REQUIRED_STATUS_CODES

    def test_auth_required_status_codes_is_frozenset(self) -> None:
        """AUTH_REQUIRED_STATUS_CODES should be a frozenset."""
        assert isinstance(AUTH_REQUIRED_STATUS_CODES, frozenset)

    def test_successful_and_auth_required_disjoint(self) -> None:
        """Successful and auth-required status codes should not overlap."""
        overlap = SUCCESSFUL_STATUS_CODES & AUTH_REQUIRED_STATUS_CODES
        assert len(overlap) == 0, f"Status codes overlap: {overlap}"

    def test_mcp_content_types_are_strings(self) -> None:
        """All MCP content type values should be strings."""
        for ct in MCP_CONTENT_TYPES:
            assert isinstance(ct, str)

    def test_mcp_response_indicators_are_strings(self) -> None:
        """All MCP response indicator values should be strings."""
        for indicator in MCP_RESPONSE_INDICATORS:
            assert isinstance(indicator, str)

    def test_application_json_rpc_in_content_types(self) -> None:
        """'application/json-rpc' should be in MCP_CONTENT_TYPES."""
        assert "application/json-rpc" in MCP_CONTENT_TYPES

    def test_at_least_five_indicators(self) -> None:
        """There should be at least 5 MCP response indicators."""
        assert len(MCP_RESPONSE_INDICATORS) >= 5


# ---------------------------------------------------------------------------
# DEFAULT_AUTH_PROBES coverage
# ---------------------------------------------------------------------------


class TestDefaultAuthProbes:
    """Tests that DEFAULT_AUTH_PROBES cover expected bypass strategies."""

    def test_list_is_non_empty(self) -> None:
        """DEFAULT_AUTH_PROBES should not be empty."""
        assert len(DEFAULT_AUTH_PROBES) > 0

    def test_every_probe_has_name(self) -> None:
        """Every auth probe should have a non-empty name."""
        for probe in DEFAULT_AUTH_PROBES:
            assert probe.name, f"Auth probe has empty name: {probe}"

    def test_every_probe_has_description(self) -> None:
        """Every auth probe should have a non-empty description."""
        for probe in DEFAULT_AUTH_PROBES:
            assert probe.description, f"Auth probe '{probe.name}' has no description"

    def test_no_auth_header_probe_present(self) -> None:
        """The 'no_auth_header' probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "no_auth_header" in names

    def test_no_auth_probe_strips_authorization(self) -> None:
        """The no_auth_header probe should strip the Authorization header."""
        probe = next(p for p in DEFAULT_AUTH_PROBES if p.name == "no_auth_header")
        assert probe.missing_header == "Authorization"

    def test_ip_bypass_probe_present(self) -> None:
        """At least one IP-based bypass probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        ip_probes = [n for n in names if "forwarded" in n or "ip" in n or "localhost" in n]
        assert len(ip_probes) >= 1

    def test_empty_bearer_probe_present(self) -> None:
        """The 'empty_bearer_token' probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "empty_bearer_token" in names

    def test_null_bearer_probe_present(self) -> None:
        """The 'null_bearer_token' probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "null_bearer_token" in names

    def test_invalid_bearer_probe_present(self) -> None:
        """The 'invalid_bearer_token' probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "invalid_bearer_token" in names

    def test_basic_auth_probe_present(self) -> None:
        """At least one basic auth probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        basic_probes = [n for n in names if "basic" in n]
        assert len(basic_probes) >= 1

    def test_api_key_probe_present(self) -> None:
        """At least one API key probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        api_key_probes = [n for n in names if "api_key" in n]
        assert len(api_key_probes) >= 1

    def test_cors_bypass_probe_present(self) -> None:
        """The 'cors_origin_bypass' probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "cors_origin_bypass" in names

    def test_unique_probe_names(self) -> None:
        """All auth probe names should be unique."""
        names = [p.name for p in DEFAULT_AUTH_PROBES]
        assert len(names) == len(set(names)), "Duplicate auth probe names found"

    def test_at_least_five_auth_probes(self) -> None:
        """There should be at least 5 auth bypass probes."""
        assert len(DEFAULT_AUTH_PROBES) >= 5

    def test_no_auth_probe_has_expected_bypass_indicators(self) -> None:
        """The no_auth_header probe should have expected bypass indicators."""
        probe = next(p for p in DEFAULT_AUTH_PROBES if p.name == "no_auth_header")
        assert len(probe.expected_bypass_indicators) > 0

    def test_every_probe_has_bypass_strategy(self) -> None:
        """Every probe should have either bypass_headers or missing_header."""
        for probe in DEFAULT_AUTH_PROBES:
            has_bypass = bool(probe.bypass_headers)
            has_missing = probe.missing_header is not None
            assert has_bypass or has_missing, (
                f"Auth probe '{probe.name}' has neither bypass_headers nor missing_header"
            )

    def test_bearer_probes_have_authorization_header(self) -> None:
        """Bearer token probes should include an Authorization header."""
        bearer_probes = [p for p in DEFAULT_AUTH_PROBES if "bearer" in p.name.lower()]
        assert len(bearer_probes) >= 1
        for probe in bearer_probes:
            assert "Authorization" in probe.bypass_headers

    def test_ip_bypass_probes_have_forwarded_headers(self) -> None:
        """IP spoofing probes should include X-Forwarded-For or similar headers."""
        ip_probes = [
            p for p in DEFAULT_AUTH_PROBES
            if "forwarded" in p.name.lower() or "localhost" in p.name.lower() or "private" in p.name.lower()
        ]
        assert len(ip_probes) >= 1
        for probe in ip_probes:
            has_forwarded = (
                "X-Forwarded-For" in probe.bypass_headers
                or "X-Real-IP" in probe.bypass_headers
            )
            assert has_forwarded, (
                f"IP spoof probe '{probe.name}' missing X-Forwarded-For/X-Real-IP header"
            )

    def test_admin_api_key_probe_present(self) -> None:
        """The 'admin_api_key_header' probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "admin_api_key_header" in names

    def test_empty_api_key_probe_present(self) -> None:
        """The 'empty_api_key_header' probe should be present."""
        names = {p.name for p in DEFAULT_AUTH_PROBES}
        assert "empty_api_key_header" in names

    def test_all_probes_are_auth_probe_instances(self) -> None:
        """Every item in DEFAULT_AUTH_PROBES should be an AuthProbe instance."""
        for probe in DEFAULT_AUTH_PROBES:
            assert isinstance(probe, AuthProbe)

    def test_probe_names_are_lowercase_with_underscores(self) -> None:
        """Probe names should use lowercase and underscores (snake_case)."""
        for probe in DEFAULT_AUTH_PROBES:
            assert probe.name == probe.name.lower(), (
                f"Probe name '{probe.name}' should be lowercase"
            )
            assert " " not in probe.name, (
                f"Probe name '{probe.name}' should not contain spaces"
            )

    def test_at_least_ten_auth_probes(self) -> None:
        """There should be at least 10 auth bypass probes for good coverage."""
        assert len(DEFAULT_AUTH_PROBES) >= 10


# ---------------------------------------------------------------------------
# get_default_paths
# ---------------------------------------------------------------------------


class TestGetDefaultPaths:
    """Tests for the get_default_paths() helper."""

    def test_returns_list_of_strings(self) -> None:
        """get_default_paths() should return a list of strings."""
        paths = get_default_paths()
        assert isinstance(paths, list)
        assert all(isinstance(p, str) for p in paths)

    def test_length_matches_default_mcp_paths(self) -> None:
        """Length should match the number of DEFAULT_MCP_PATHS entries."""
        paths = get_default_paths()
        assert len(paths) == len(DEFAULT_MCP_PATHS)

    def test_all_paths_start_with_slash(self) -> None:
        """Every returned path should start with '/'."""
        for path in get_default_paths():
            assert path.startswith("/"), f"Path '{path}' does not start with '/'"

    def test_order_preserved(self) -> None:
        """Paths should be in the same order as DEFAULT_MCP_PATHS."""
        paths = get_default_paths()
        expected_paths = [p.path for p in DEFAULT_MCP_PATHS]
        assert paths == expected_paths

    def test_returns_copy_each_call(self) -> None:
        """Each call should return a fresh list (not a shared reference)."""
        paths1 = get_default_paths()
        paths2 = get_default_paths()
        # Modifying one should not affect the other
        paths1.append("/injected")
        assert "/injected" not in paths2

    def test_contains_mcp_path(self) -> None:
        paths = get_default_paths()
        assert "/mcp" in paths

    def test_contains_sse_path(self) -> None:
        paths = get_default_paths()
        assert "/sse" in paths

    def test_result_is_non_empty(self) -> None:
        assert len(get_default_paths()) > 0


# ---------------------------------------------------------------------------
# get_probe_for_path
# ---------------------------------------------------------------------------


class TestGetProbeForPath:
    """Tests for the get_probe_for_path() helper."""

    def test_returns_probe_for_known_path(self) -> None:
        """Should return the UrlProbe for a known path."""
        probe = get_probe_for_path("/mcp")
        assert probe is not None
        assert probe.path == "/mcp"

    def test_returns_none_for_unknown_path(self) -> None:
        """Should return None for a path not in DEFAULT_MCP_PATHS."""
        probe = get_probe_for_path("/nonexistent/path")
        assert probe is None

    def test_returns_correct_probe_type_for_sse(self) -> None:
        """The /sse path should be a SSE probe."""
        probe = get_probe_for_path("/sse")
        assert probe is not None
        assert probe.probe_type == ProbeType.SSE

    def test_returns_correct_probe_type_for_mcp(self) -> None:
        """The /mcp path should be an HTTP_GET probe."""
        probe = get_probe_for_path("/mcp")
        assert probe is not None
        assert probe.probe_type == ProbeType.HTTP_GET

    def test_returns_probe_for_tools_path(self) -> None:
        """The /mcp/tools path should return a probe."""
        probe = get_probe_for_path("/mcp/tools")
        assert probe is not None
        assert probe.path == "/mcp/tools"

    def test_returns_probe_for_well_known_mcp(self) -> None:
        """The /.well-known/mcp path should return a probe."""
        probe = get_probe_for_path("/.well-known/mcp")
        assert probe is not None
        assert probe.path == "/.well-known/mcp"

    def test_returns_probe_for_api_mcp(self) -> None:
        """The /api/mcp path should return a probe."""
        probe = get_probe_for_path("/api/mcp")
        assert probe is not None
        assert probe.probe_type == ProbeType.HTTP_GET

    def test_returns_url_probe_instance(self) -> None:
        """The returned object should be a UrlProbe instance."""
        probe = get_probe_for_path("/mcp")
        assert isinstance(probe, UrlProbe)

    def test_exact_path_matching(self) -> None:
        """Matching should be exact, not prefix-based."""
        # /mcp should not match /mcp/tools
        probe = get_probe_for_path("/mcp")
        assert probe is not None
        assert probe.path == "/mcp"
        assert probe.path != "/mcp/tools"

    def test_none_for_partial_path(self) -> None:
        """A partial path that is a prefix of a real path should return None."""
        # /mc is not in the list
        probe = get_probe_for_path("/mc")
        assert probe is None

    def test_sse_probe_has_accept_header(self) -> None:
        """The SSE probe for /sse should have the Accept header."""
        probe = get_probe_for_path("/sse")
        assert probe is not None
        assert probe.headers.get("Accept") == "text/event-stream"

    def test_returns_probe_with_expected_indicators(self) -> None:
        """The returned probe should have expected_indicators populated."""
        probe = get_probe_for_path("/mcp/tools")
        assert probe is not None
        assert len(probe.expected_indicators) > 0


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
        """Basic paths should be loaded correctly."""
        path = self._write_wordlist("/mcp\n/sse\n/api/mcp\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse", "/api/mcp"]

    def test_comments_skipped(self) -> None:
        """Lines starting with '#' should be ignored."""
        path = self._write_wordlist("# comment\n/mcp\n# another comment\n/sse\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse"]

    def test_empty_lines_skipped(self) -> None:
        """Empty lines should be ignored."""
        path = self._write_wordlist("\n\n/mcp\n\n/sse\n\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse"]

    def test_slash_prepended_if_missing(self) -> None:
        """Paths without a leading '/' should have one prepended."""
        path = self._write_wordlist("mcp\nsse\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse"]

    def test_existing_slash_not_doubled(self) -> None:
        """Paths that already start with '/' should not get a double '/'."""
        path = self._write_wordlist("/mcp\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp"]
        assert "//mcp" not in result

    def test_file_not_found_raises(self) -> None:
        """A non-existent file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_custom_wordlist("/nonexistent/path/wordlist.txt")

    def test_empty_file_returns_empty_list(self) -> None:
        """An empty file should produce an empty list."""
        path = self._write_wordlist("")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == []

    def test_only_comments_returns_empty_list(self) -> None:
        """A file with only comments should produce an empty list."""
        path = self._write_wordlist("# just comments\n# more comments\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == []

    def test_whitespace_stripped(self) -> None:
        """Surrounding whitespace should be stripped from paths."""
        path = self._write_wordlist("  /mcp  \n  /sse  \n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/mcp", "/sse"]

    def test_returns_list(self) -> None:
        """Return value should be a list."""
        path = self._write_wordlist("/mcp\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert isinstance(result, list)

    def test_returns_strings(self) -> None:
        """All items in the returned list should be strings."""
        path = self._write_wordlist("/mcp\n/sse\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert all(isinstance(p, str) for p in result)

    def test_order_preserved(self) -> None:
        """The order of paths in the file should be preserved."""
        path = self._write_wordlist("/z-path\n/a-path\n/m-path\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert result == ["/z-path", "/a-path", "/m-path"]

    def test_inline_comment_is_not_stripped(self) -> None:
        """Only whole-line comments (starting with #) are stripped; inline # is part of path."""
        # A line like '/path#fragment' should be kept as-is (the # is not at the start)
        path = self._write_wordlist("/path-no-hash\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert "/path-no-hash" in result

    def test_path_with_query_string(self) -> None:
        """Paths containing query strings should be loaded as-is."""
        path = self._write_wordlist("/mcp?format=json\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert "/mcp?format=json" in result

    def test_single_path_file(self) -> None:
        """A file with a single path should return a single-element list."""
        path = self._write_wordlist("/single/path\n")
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert len(result) == 1
        assert result[0] == "/single/path"

    def test_large_wordlist(self) -> None:
        """A large wordlist should be loaded completely."""
        paths = [f"/path/{i}" for i in range(100)]
        content = "\n".join(paths) + "\n"
        path = self._write_wordlist(content)
        try:
            result = load_custom_wordlist(path)
        finally:
            os.unlink(path)
        assert len(result) == 100

    def test_path_object_not_accepted_only_string(self) -> None:
        """The function expects a string path; a Path object may or may not work."""
        # This tests the documented interface: file_path is str
        fd, str_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        Path(str_path).write_text("/mcp\n", encoding="utf-8")
        try:
            # String path should always work
            result = load_custom_wordlist(str_path)
            assert result == ["/mcp"]
        finally:
            os.unlink(str_path)


# ---------------------------------------------------------------------------
# build_probes_from_paths
# ---------------------------------------------------------------------------


class TestBuildProbesFromPaths:
    """Tests for the build_probes_from_paths() helper."""

    def test_known_path_returns_existing_probe(self) -> None:
        """A known path should reuse the rich default probe definition."""
        probes = build_probes_from_paths(["/mcp"])
        assert len(probes) == 1
        # Should reuse the rich default probe (not a custom probe)
        assert probes[0].description != "Custom probe: /mcp"
        assert any(
            ind in probes[0].expected_indicators for ind in ["mcp", "jsonrpc", "tools"]
        )

    def test_unknown_path_creates_get_probe(self) -> None:
        """An unknown path should produce an HTTP_GET probe."""
        probes = build_probes_from_paths(["/unknown/path"])
        assert len(probes) == 1
        assert probes[0].probe_type == ProbeType.HTTP_GET
        assert probes[0].path == "/unknown/path"

    def test_sse_keyword_creates_sse_probe(self) -> None:
        """A path containing 'sse' should produce a SSE probe."""
        probes = build_probes_from_paths(["/custom/sse"])
        assert probes[0].probe_type == ProbeType.SSE
        assert probes[0].headers.get("Accept") == "text/event-stream"

    def test_stream_keyword_creates_sse_probe(self) -> None:
        """A path containing 'stream' should produce a SSE probe."""
        probes = build_probes_from_paths(["/custom/stream"])
        assert probes[0].probe_type == ProbeType.SSE

    def test_event_keyword_creates_sse_probe(self) -> None:
        """A path containing 'event' should produce a SSE probe."""
        probes = build_probes_from_paths(["/custom/events"])
        assert probes[0].probe_type == ProbeType.SSE

    def test_rpc_keyword_creates_jsonrpc_probe(self) -> None:
        """A path containing 'rpc' should produce a JSON_RPC probe."""
        probes = build_probes_from_paths(["/custom/rpc"])
        assert probes[0].probe_type == ProbeType.JSON_RPC

    def test_jsonrpc_keyword_creates_jsonrpc_probe(self) -> None:
        """A path containing 'jsonrpc' should produce a JSON_RPC probe."""
        probes = build_probes_from_paths(["/custom/jsonrpc"])
        assert probes[0].probe_type == ProbeType.JSON_RPC

    def test_mixed_paths(self) -> None:
        """Mixed known and unknown paths should produce correctly typed probes."""
        paths = ["/mcp", "/custom/sse", "/unknown"]
        probes = build_probes_from_paths(paths)
        assert len(probes) == 3
        assert probes[1].probe_type == ProbeType.SSE
        assert probes[2].probe_type == ProbeType.HTTP_GET

    def test_empty_input_returns_empty_list(self) -> None:
        """An empty input list should return an empty list."""
        probes = build_probes_from_paths([])
        assert probes == []

    def test_custom_probe_has_expected_indicators(self) -> None:
        """Custom probes should have at least some expected indicators."""
        probes = build_probes_from_paths(["/totally/unknown"])
        assert len(probes[0].expected_indicators) > 0

    def test_preserves_order(self) -> None:
        """The output probe order should match the input path order."""
        paths = ["/mcp/tools", "/mcp/resources", "/mcp/prompts"]
        probes = build_probes_from_paths(paths)
        assert [p.path for p in probes] == paths

    def test_returns_list_of_url_probes(self) -> None:
        """All returned items should be UrlProbe instances."""
        probes = build_probes_from_paths(["/mcp", "/unknown"])
        for probe in probes:
            assert isinstance(probe, UrlProbe)

    def test_custom_sse_probe_has_accept_header(self) -> None:
        """Custom SSE probes should have the Accept: text/event-stream header."""
        probes = build_probes_from_paths(["/my/stream"])
        assert probes[0].headers.get("Accept") == "text/event-stream"

    def test_custom_get_probe_has_no_accept_header_by_default(self) -> None:
        """Custom HTTP_GET probes should not have an Accept header injected."""
        probes = build_probes_from_paths(["/plain/path"])
        assert probes[0].probe_type == ProbeType.HTTP_GET
        # Accept header should not be forced for plain GET probes
        assert probes[0].headers.get("Accept") is None

    def test_known_path_reuses_probe_object(self) -> None:
        """A known path should return the exact same UrlProbe object from the defaults."""
        probes = build_probes_from_paths(["/mcp"])
        default_probe = get_probe_for_path("/mcp")
        assert probes[0] is default_probe

    def test_single_known_path(self) -> None:
        """A single known path should return a single probe."""
        probes = build_probes_from_paths(["/mcp/tools"])
        assert len(probes) == 1
        assert probes[0].path == "/mcp/tools"

    def test_duplicate_paths_produce_duplicate_probes(self) -> None:
        """Duplicate paths in input should produce duplicate probes in output."""
        probes = build_probes_from_paths(["/mcp", "/mcp"])
        assert len(probes) == 2
        assert probes[0].path == "/mcp"
        assert probes[1].path == "/mcp"

    def test_case_insensitive_keyword_detection_for_sse(self) -> None:
        """SSE keyword detection should be case-insensitive."""
        probes = build_probes_from_paths(["/MySSEEndpoint"])
        assert probes[0].probe_type == ProbeType.SSE

    def test_case_insensitive_keyword_detection_for_rpc(self) -> None:
        """RPC keyword detection should be case-insensitive."""
        probes = build_probes_from_paths(["/MyRPCEndpoint"])
        assert probes[0].probe_type == ProbeType.JSON_RPC

    def test_custom_probe_description_contains_path(self) -> None:
        """Custom probe descriptions should reference the path."""
        probes = build_probes_from_paths(["/totally/custom/path"])
        assert "/totally/custom/path" in probes[0].description


# ---------------------------------------------------------------------------
# is_mcp_response
# ---------------------------------------------------------------------------


class TestIsMcpResponse:
    """Tests for the is_mcp_response() helper function."""

    def test_sse_content_type_returns_true(self) -> None:
        """text/event-stream should always indicate MCP."""
        assert is_mcp_response("", "text/event-stream") is True

    def test_sse_content_type_with_charset_returns_true(self) -> None:
        """text/event-stream with charset should still be detected."""
        assert is_mcp_response("", "text/event-stream; charset=utf-8") is True

    def test_sse_empty_body_returns_true(self) -> None:
        """SSE detection should not depend on body content."""
        assert is_mcp_response("", "text/event-stream") is True

    def test_json_with_jsonrpc_keyword_returns_true(self) -> None:
        """application/json with 'jsonrpc' keyword should be detected."""
        body = '{"jsonrpc": "2.0", "result": {}}'
        assert is_mcp_response(body, "application/json") is True

    def test_json_with_tools_keyword_returns_true(self) -> None:
        """application/json with 'tools' keyword should be detected."""
        body = '{"tools": [{"name": "myTool"}]}'
        assert is_mcp_response(body, "application/json") is True

    def test_json_with_resources_keyword_returns_true(self) -> None:
        """application/json with 'resources' keyword should be detected."""
        body = '{"resources": [{"uri": "file:///etc"}]}'
        assert is_mcp_response(body, "application/json") is True

    def test_json_with_prompts_keyword_returns_true(self) -> None:
        """application/json with 'prompts' keyword should be detected."""
        body = '{"prompts": [{"name": "test"}]}'
        assert is_mcp_response(body, "application/json") is True

    def test_json_with_capabilities_keyword_returns_true(self) -> None:
        """application/json with 'capabilities' keyword should be detected."""
        body = '{"capabilities": {}}'
        assert is_mcp_response(body, "application/json") is True

    def test_json_with_protocolversion_keyword_returns_true(self) -> None:
        """application/json with 'protocolVersion' should be detected."""
        body = '{"protocolVersion": "2024-11-05"}'
        assert is_mcp_response(body, "application/json") is True

    def test_json_with_serverinfo_keyword_returns_true(self) -> None:
        """application/json with 'serverInfo' should be detected."""
        body = '{"serverInfo": {"name": "test"}}'
        assert is_mcp_response(body, "application/json") is True

    def test_json_without_mcp_keywords_returns_false(self) -> None:
        """application/json without MCP keywords should return False."""
        body = '{"status": "ok", "message": "hello world"}'
        assert is_mcp_response(body, "application/json") is False

    def test_empty_body_json_returns_false(self) -> None:
        """Empty body with application/json should return False."""
        assert is_mcp_response("", "application/json") is False

    def test_unknown_content_type_with_keyword_returns_true(self) -> None:
        """Unknown content type with MCP keyword should still be detected."""
        body = "protocolVersion: 2024-11-05"
        assert is_mcp_response(body, "text/plain") is True

    def test_unknown_content_type_without_keyword_returns_false(self) -> None:
        """Unknown content type without MCP keywords should return False."""
        body = "<html><body>Hello</body></html>"
        assert is_mcp_response(body, "text/html") is False

    def test_case_insensitive_keyword_match(self) -> None:
        """Keyword matching should be case-insensitive."""
        body = '{"JSONRPC": "2.0"}'
        assert is_mcp_response(body, "application/json") is True

    def test_mcp_keyword_alone_returns_true(self) -> None:
        """The 'mcp' keyword alone should trigger detection."""
        body = "This is an mcp server"
        assert is_mcp_response(body, "text/plain") is True

    def test_json_rpc_content_type_variant(self) -> None:
        """application/json-rpc content type should be treated like application/json."""
        body = '{"jsonrpc": "2.0", "result": {}}'
        assert is_mcp_response(body, "application/json-rpc") is True

    def test_empty_body_text_plain_returns_false(self) -> None:
        """Empty body with text/plain should return False."""
        assert is_mcp_response("", "text/plain") is False

    def test_inputschema_keyword_returns_true(self) -> None:
        """'inputSchema' keyword should trigger MCP detection."""
        body = '{"inputSchema": {"type": "object"}}'
        assert is_mcp_response(body, "application/json") is True

    def test_mcp_uppercase_returns_true(self) -> None:
        """Uppercase 'MCP' should trigger detection."""
        body = "MCP server running"
        assert is_mcp_response(body, "text/plain") is True

    def test_model_context_protocol_returns_true(self) -> None:
        """'model context protocol' phrase should trigger detection."""
        body = "model context protocol server"
        assert is_mcp_response(body, "text/plain") is True

    def test_status_code_parameter_accepted(self) -> None:
        """The status_code parameter should be accepted without error."""
        body = '{"jsonrpc": "2.0"}'
        result = is_mcp_response(body, "application/json", status_code=200)
        assert result is True

    def test_json_with_mcp_keyword_returns_true(self) -> None:
        """application/json body with 'mcp' keyword should be detected."""
        body = '{"framework": "mcp"}'
        assert is_mcp_response(body, "application/json") is True

    def test_html_without_keywords_returns_false(self) -> None:
        """A standard HTML page without MCP keywords should not be detected."""
        body = "<html><head><title>Welcome</title></head><body><p>Hello</p></body></html>"
        assert is_mcp_response(body, "text/html") is False
