"""MCP probe definitions for the scanner.

Contains all MCP URL patterns, JSON-RPC payloads, SSE probe strategies,
and authentication test descriptors consumed by the scanner and auth tester.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProbeType(str, Enum):
    """Type of probe being executed."""

    HTTP_GET = "HTTP_GET"
    HTTP_POST = "HTTP_POST"
    SSE = "SSE"
    JSON_RPC = "JSON_RPC"


@dataclass
class UrlProbe:
    """Defines a URL path pattern to probe on target hosts."""

    path: str
    probe_type: ProbeType
    description: str
    expected_indicators: list[str] = field(default_factory=list)
    payload: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True


@dataclass
class AuthProbe:
    """Defines an authentication bypass test strategy."""

    name: str
    description: str
    missing_header: str | None = None
    bypass_headers: dict[str, str] = field(default_factory=dict)
    expected_bypass_indicators: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Default MCP URL patterns to probe
# ---------------------------------------------------------------------------

DEFAULT_MCP_PATHS: list[UrlProbe] = [
    UrlProbe(
        path="/mcp",
        probe_type=ProbeType.HTTP_GET,
        description="Root MCP endpoint",
        expected_indicators=["mcp", "jsonrpc", "tools", "resources", "prompts"],
    ),
    UrlProbe(
        path="/mcp/v1",
        probe_type=ProbeType.HTTP_GET,
        description="MCP v1 versioned endpoint",
        expected_indicators=["mcp", "jsonrpc", "version"],
    ),
    UrlProbe(
        path="/mcp/v2",
        probe_type=ProbeType.HTTP_GET,
        description="MCP v2 versioned endpoint",
        expected_indicators=["mcp", "jsonrpc", "version"],
    ),
    UrlProbe(
        path="/sse",
        probe_type=ProbeType.SSE,
        description="Server-Sent Events endpoint (common MCP transport)",
        expected_indicators=["text/event-stream", "data:", "event:"],
        headers={"Accept": "text/event-stream"},
    ),
    UrlProbe(
        path="/mcp/sse",
        probe_type=ProbeType.SSE,
        description="MCP-specific SSE endpoint",
        expected_indicators=["text/event-stream", "data:", "event:"],
        headers={"Accept": "text/event-stream"},
    ),
    UrlProbe(
        path="/api/mcp",
        probe_type=ProbeType.HTTP_GET,
        description="API-prefixed MCP endpoint",
        expected_indicators=["mcp", "jsonrpc", "tools"],
    ),
    UrlProbe(
        path="/api/mcp/v1",
        probe_type=ProbeType.HTTP_GET,
        description="API-prefixed MCP v1 endpoint",
        expected_indicators=["mcp", "jsonrpc", "tools"],
    ),
    UrlProbe(
        path="/api/mcp/sse",
        probe_type=ProbeType.SSE,
        description="API-prefixed MCP SSE endpoint",
        expected_indicators=["text/event-stream", "data:"],
        headers={"Accept": "text/event-stream"},
    ),
    UrlProbe(
        path="/.well-known/mcp",
        probe_type=ProbeType.HTTP_GET,
        description="Well-known MCP discovery endpoint",
        expected_indicators=["mcp", "endpoint", "version"],
    ),
    UrlProbe(
        path="/.well-known/mcp.json",
        probe_type=ProbeType.HTTP_GET,
        description="Well-known MCP JSON discovery endpoint",
        expected_indicators=["mcp", "endpoint", "version"],
    ),
    UrlProbe(
        path="/mcp/tools",
        probe_type=ProbeType.HTTP_GET,
        description="MCP tools listing endpoint",
        expected_indicators=["tools", "name", "description", "inputSchema"],
    ),
    UrlProbe(
        path="/mcp/tools/list",
        probe_type=ProbeType.HTTP_GET,
        description="MCP tools list sub-endpoint",
        expected_indicators=["tools", "name", "description"],
    ),
    UrlProbe(
        path="/mcp/resources",
        probe_type=ProbeType.HTTP_GET,
        description="MCP resources listing endpoint",
        expected_indicators=["resources", "uri", "name"],
    ),
    UrlProbe(
        path="/mcp/resources/list",
        probe_type=ProbeType.HTTP_GET,
        description="MCP resources list sub-endpoint",
        expected_indicators=["resources", "uri", "name"],
    ),
    UrlProbe(
        path="/mcp/prompts",
        probe_type=ProbeType.HTTP_GET,
        description="MCP prompts listing endpoint",
        expected_indicators=["prompts", "name", "description"],
    ),
    UrlProbe(
        path="/mcp/prompts/list",
        probe_type=ProbeType.HTTP_GET,
        description="MCP prompts list sub-endpoint",
        expected_indicators=["prompts", "name", "description"],
    ),
    UrlProbe(
        path="/v1/mcp",
        probe_type=ProbeType.HTTP_GET,
        description="Version-prefixed MCP endpoint",
        expected_indicators=["mcp", "jsonrpc"],
    ),
    UrlProbe(
        path="/mcp/messages",
        probe_type=ProbeType.HTTP_POST,
        description="MCP messages endpoint",
        expected_indicators=["jsonrpc", "result", "method"],
    ),
    UrlProbe(
        path="/mcp/rpc",
        probe_type=ProbeType.JSON_RPC,
        description="MCP JSON-RPC endpoint",
        expected_indicators=["jsonrpc", "result", "id"],
    ),
    UrlProbe(
        path="/rpc",
        probe_type=ProbeType.JSON_RPC,
        description="Generic JSON-RPC endpoint (may be MCP)",
        expected_indicators=["jsonrpc", "result", "id"],
    ),
    UrlProbe(
        path="/api/sse",
        probe_type=ProbeType.SSE,
        description="API SSE endpoint",
        expected_indicators=["text/event-stream", "data:"],
        headers={"Accept": "text/event-stream"},
    ),
    UrlProbe(
        path="/stream",
        probe_type=ProbeType.SSE,
        description="Generic stream endpoint (may be MCP SSE)",
        expected_indicators=["text/event-stream", "data:"],
        headers={"Accept": "text/event-stream"},
    ),
    UrlProbe(
        path="/mcp/stream",
        probe_type=ProbeType.SSE,
        description="MCP stream endpoint",
        expected_indicators=["text/event-stream", "data:", "mcp"],
        headers={"Accept": "text/event-stream"},
    ),
    UrlProbe(
        path="/events",
        probe_type=ProbeType.SSE,
        description="Generic events endpoint (may be MCP SSE)",
        expected_indicators=["text/event-stream"],
        headers={"Accept": "text/event-stream"},
    ),
    UrlProbe(
        path="/mcp/events",
        probe_type=ProbeType.SSE,
        description="MCP events endpoint",
        expected_indicators=["text/event-stream", "mcp"],
        headers={"Accept": "text/event-stream"},
    ),
    UrlProbe(
        path="/openapi.json",
        probe_type=ProbeType.HTTP_GET,
        description="OpenAPI spec (may reveal MCP endpoints)",
        expected_indicators=["mcp", "/mcp", "/sse"],
    ),
    UrlProbe(
        path="/docs",
        probe_type=ProbeType.HTTP_GET,
        description="API docs page (may reveal MCP endpoints)",
        expected_indicators=["mcp", "model context protocol", "sse"],
    ),
]


# ---------------------------------------------------------------------------
# JSON-RPC payloads for MCP method probing
# ---------------------------------------------------------------------------

JSONRPC_INITIALIZE_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {
            "name": "mcp-scanner",
            "version": "0.1.0",
        },
    },
}

JSONRPC_TOOLS_LIST_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {},
}

JSONRPC_RESOURCES_LIST_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 3,
    "method": "resources/list",
    "params": {},
}

JSONRPC_PROMPTS_LIST_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 4,
    "method": "prompts/list",
    "params": {},
}

JSONRPC_PING_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 5,
    "method": "ping",
    "params": {},
}

JSONRPC_SERVER_INFO_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 6,
    "method": "server/info",
    "params": {},
}

ALL_JSONRPC_PAYLOADS: list[dict[str, Any]] = [
    JSONRPC_INITIALIZE_PAYLOAD,
    JSONRPC_TOOLS_LIST_PAYLOAD,
    JSONRPC_RESOURCES_LIST_PAYLOAD,
    JSONRPC_PROMPTS_LIST_PAYLOAD,
    JSONRPC_PING_PAYLOAD,
    JSONRPC_SERVER_INFO_PAYLOAD,
]


# ---------------------------------------------------------------------------
# Indicators that a response body looks like MCP
# ---------------------------------------------------------------------------

MCP_RESPONSE_INDICATORS: list[str] = [
    "jsonrpc",
    "protocolVersion",
    "serverInfo",
    "tools",
    "resources",
    "prompts",
    "capabilities",
    "model context protocol",
    "mcp",
    "inputSchema",
    "uri",
    "text/event-stream",
]

MCP_CONTENT_TYPES: list[str] = [
    "application/json",
    "text/event-stream",
    "application/json-rpc",
]


# ---------------------------------------------------------------------------
# Authentication probe strategies
# ---------------------------------------------------------------------------

DEFAULT_AUTH_PROBES: list[AuthProbe] = [
    AuthProbe(
        name="no_auth_header",
        description="Request sent without any Authorization header to check for open access",
        missing_header="Authorization",
        expected_bypass_indicators=["tools", "resources", "jsonrpc", "protocolVersion"],
    ),
    AuthProbe(
        name="empty_bearer_token",
        description="Request sent with an empty Bearer token",
        bypass_headers={"Authorization": "Bearer "},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="null_bearer_token",
        description="Request sent with 'null' as the Bearer token",
        bypass_headers={"Authorization": "Bearer null"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="invalid_bearer_token",
        description="Request sent with an obviously invalid Bearer token",
        bypass_headers={"Authorization": "Bearer INVALID_TOKEN_12345"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="basic_auth_bypass",
        description="Request sent with empty Basic auth credentials",
        bypass_headers={"Authorization": "Basic "},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="x_forwarded_for_bypass",
        description="Request sent with X-Forwarded-For localhost to test IP allowlist bypass",
        bypass_headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="admin_api_key",
        description="Request sent with common default admin API keys",
        bypass_headers={"X-API-Key": "admin"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
]


def get_default_paths() -> list[str]:
    """Return the list of default MCP URL path strings."""
    return [probe.path for probe in DEFAULT_MCP_PATHS]


def get_probe_for_path(path: str) -> UrlProbe | None:
    """Find and return a UrlProbe matching the given path, or None if not found."""
    for probe in DEFAULT_MCP_PATHS:
        if probe.path == path:
            return probe
    return None


def load_custom_wordlist(file_path: str) -> list[str]:
    """Load custom URL paths from a wordlist file.

    Each non-empty, non-comment line is treated as a URL path.
    Lines starting with '#' are treated as comments and skipped.

    Args:
        file_path: Path to the wordlist text file.

    Returns:
        List of URL path strings.

    Raises:
        FileNotFoundError: If the wordlist file does not exist.
        PermissionError: If the file cannot be read.
    """
    paths: list[str] = []
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                # Ensure path starts with /
                if not stripped.startswith("/"):
                    stripped = "/" + stripped
                paths.append(stripped)
    return paths


def build_probes_from_paths(paths: list[str]) -> list[UrlProbe]:
    """Build UrlProbe objects from a list of path strings.

    If a path matches a default probe, that probe is reused.
    Otherwise, a generic HTTP GET probe is created.

    Args:
        paths: List of URL path strings.

    Returns:
        List of UrlProbe objects.
    """
    probes: list[UrlProbe] = []
    default_map = {p.path: p for p in DEFAULT_MCP_PATHS}

    for path in paths:
        if path in default_map:
            probes.append(default_map[path])
        else:
            probe_type = ProbeType.SSE if any(kw in path for kw in ["sse", "stream", "event"]) else ProbeType.HTTP_GET
            headers = {"Accept": "text/event-stream"} if probe_type == ProbeType.SSE else {}
            probes.append(
                UrlProbe(
                    path=path,
                    probe_type=probe_type,
                    description=f"Custom probe: {path}",
                    expected_indicators=MCP_RESPONSE_INDICATORS[:5],
                    headers=headers,
                )
            )

    return probes
