"""MCP probe definitions for MCP Scanner.

Contains all MCP URL patterns, JSON-RPC payloads, SSE probe strategies,
and authentication test descriptors consumed by the scanner and auth tester.

This module is the single source of truth for:
  - Default URL paths to probe on every target
  - JSON-RPC method payloads for MCP capability enumeration
  - Indicators used to recognise MCP responses
  - Authentication bypass strategies
  - Helper functions for loading custom wordlists and building probe objects
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ProbeType(str, Enum):
    """Categorises the HTTP interaction strategy used by a :class:`UrlProbe`.

    Attributes:
        HTTP_GET: Plain GET request expecting a JSON or text response.
        HTTP_POST: POST request with a JSON body (non-RPC).
        SSE: GET request with ``Accept: text/event-stream`` expecting an
            SSE stream.
        JSON_RPC: POST request carrying a JSON-RPC 2.0 envelope.
    """

    HTTP_GET = "HTTP_GET"
    HTTP_POST = "HTTP_POST"
    SSE = "SSE"
    JSON_RPC = "JSON_RPC"


# ---------------------------------------------------------------------------
# Probe dataclasses
# ---------------------------------------------------------------------------

@dataclass
class UrlProbe:
    """Describes a single URL path to probe on a target host.

    Attributes:
        path: URL path component to append to the target base URL
            (must start with ``/``).
        probe_type: The type of HTTP interaction to perform.
        description: Human-readable description of what this probe tests.
        expected_indicators: Strings whose presence in the response
            body or Content-Type header suggests an MCP endpoint.
        payload: Optional JSON-serialisable body for POST probes.
        headers: Additional HTTP headers to include in this probe's
            request (merged with global headers).
        follow_redirects: Whether to follow HTTP redirects.
    """

    path: str
    probe_type: ProbeType
    description: str
    expected_indicators: list[str] = field(default_factory=list)
    payload: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True


@dataclass
class AuthProbe:
    """Describes an authentication bypass test strategy.

    Each ``AuthProbe`` represents one way an attacker might try to access
    an MCP endpoint without proper credentials.

    Attributes:
        name: Short identifier used in findings and logs.
        description: Human-readable explanation of the technique.
        missing_header: If set, this header will be *removed* from the
            request (e.g. ``"Authorization"``) to test open access.
        bypass_headers: Headers to *add* to the request to attempt a
            bypass (e.g. a spoofed IP or an empty Bearer token).
        expected_bypass_indicators: Response body strings whose presence
            confirms that the bypass succeeded.
    """

    name: str
    description: str
    missing_header: str | None = None
    bypass_headers: dict[str, str] = field(default_factory=dict)
    expected_bypass_indicators: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Default MCP URL patterns
# ---------------------------------------------------------------------------

DEFAULT_MCP_PATHS: list[UrlProbe] = [
    # ---- Core MCP paths ------------------------------------------------
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
        path="/mcp/v3",
        probe_type=ProbeType.HTTP_GET,
        description="MCP v3 versioned endpoint",
        expected_indicators=["mcp", "jsonrpc", "version"],
    ),
    # ---- SSE transport paths -------------------------------------------
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
        path="/api/sse",
        probe_type=ProbeType.SSE,
        description="API-namespaced SSE endpoint",
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
        description="MCP events SSE endpoint",
        expected_indicators=["text/event-stream", "mcp"],
        headers={"Accept": "text/event-stream"},
    ),
    # ---- API-prefixed paths --------------------------------------------
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
        path="/api/mcp/v2",
        probe_type=ProbeType.HTTP_GET,
        description="API-prefixed MCP v2 endpoint",
        expected_indicators=["mcp", "jsonrpc", "tools"],
    ),
    UrlProbe(
        path="/api/mcp/sse",
        probe_type=ProbeType.SSE,
        description="API-prefixed MCP SSE endpoint",
        expected_indicators=["text/event-stream", "data:"],
        headers={"Accept": "text/event-stream"},
    ),
    # ---- Well-known discovery paths ------------------------------------
    UrlProbe(
        path="/.well-known/mcp",
        probe_type=ProbeType.HTTP_GET,
        description="Well-known MCP discovery endpoint",
        expected_indicators=["mcp", "endpoint", "version"],
    ),
    UrlProbe(
        path="/.well-known/mcp.json",
        probe_type=ProbeType.HTTP_GET,
        description="Well-known MCP JSON discovery file",
        expected_indicators=["mcp", "endpoint", "version"],
    ),
    UrlProbe(
        path="/.well-known/ai-plugin.json",
        probe_type=ProbeType.HTTP_GET,
        description="OpenAI plugin manifest (may reference MCP)",
        expected_indicators=["mcp", "api", "schema_version"],
    ),
    # ---- Tool / resource / prompt sub-paths ----------------------------
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
        path="/mcp/tools/call",
        probe_type=ProbeType.HTTP_POST,
        description="MCP tool call endpoint",
        expected_indicators=["result", "content", "isError"],
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
        path="/mcp/resources/read",
        probe_type=ProbeType.HTTP_POST,
        description="MCP resource read endpoint",
        expected_indicators=["contents", "uri", "text"],
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
        path="/mcp/prompts/get",
        probe_type=ProbeType.HTTP_POST,
        description="MCP prompt retrieval endpoint",
        expected_indicators=["messages", "role", "content"],
    ),
    # ---- JSON-RPC paths ------------------------------------------------
    UrlProbe(
        path="/mcp/messages",
        probe_type=ProbeType.HTTP_POST,
        description="MCP messages / JSON-RPC dispatch endpoint",
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
        path="/jsonrpc",
        probe_type=ProbeType.JSON_RPC,
        description="Explicit JSON-RPC path (may be MCP)",
        expected_indicators=["jsonrpc", "result", "id"],
    ),
    # ---- Version-prefixed paths ----------------------------------------
    UrlProbe(
        path="/v1/mcp",
        probe_type=ProbeType.HTTP_GET,
        description="Version-prefixed MCP endpoint (v1)",
        expected_indicators=["mcp", "jsonrpc"],
    ),
    UrlProbe(
        path="/v2/mcp",
        probe_type=ProbeType.HTTP_GET,
        description="Version-prefixed MCP endpoint (v2)",
        expected_indicators=["mcp", "jsonrpc"],
    ),
    # ---- Discovery / documentation paths ------------------------------
    UrlProbe(
        path="/openapi.json",
        probe_type=ProbeType.HTTP_GET,
        description="OpenAPI specification (may reveal MCP endpoint paths)",
        expected_indicators=["mcp", "/mcp", "/sse"],
    ),
    UrlProbe(
        path="/openapi.yaml",
        probe_type=ProbeType.HTTP_GET,
        description="OpenAPI YAML spec (may reveal MCP endpoint paths)",
        expected_indicators=["mcp", "/mcp", "/sse"],
    ),
    UrlProbe(
        path="/docs",
        probe_type=ProbeType.HTTP_GET,
        description="API documentation page (may mention MCP)",
        expected_indicators=["mcp", "model context protocol", "sse"],
    ),
    UrlProbe(
        path="/swagger.json",
        probe_type=ProbeType.HTTP_GET,
        description="Swagger JSON spec (may reveal MCP endpoints)",
        expected_indicators=["mcp", "/mcp", "/sse"],
    ),
    UrlProbe(
        path="/swagger.yaml",
        probe_type=ProbeType.HTTP_GET,
        description="Swagger YAML spec (may reveal MCP endpoints)",
        expected_indicators=["mcp", "/mcp", "/sse"],
    ),
    # ---- Framework-specific paths (FastAPI, LangChain, etc.) -----------
    UrlProbe(
        path="/mcp/ws",
        probe_type=ProbeType.HTTP_GET,
        description="MCP WebSocket upgrade endpoint",
        expected_indicators=["websocket", "upgrade", "mcp"],
    ),
    UrlProbe(
        path="/mcp/health",
        probe_type=ProbeType.HTTP_GET,
        description="MCP health-check endpoint (reveals server existence)",
        expected_indicators=["ok", "healthy", "mcp", "status"],
    ),
    UrlProbe(
        path="/mcp/info",
        probe_type=ProbeType.HTTP_GET,
        description="MCP server information endpoint",
        expected_indicators=["mcp", "version", "serverInfo", "name"],
    ),
    UrlProbe(
        path="/mcp/capabilities",
        probe_type=ProbeType.HTTP_GET,
        description="MCP capabilities endpoint",
        expected_indicators=["capabilities", "tools", "resources", "prompts"],
    ),
    UrlProbe(
        path="/mcp/initialize",
        probe_type=ProbeType.HTTP_POST,
        description="MCP initialize handshake endpoint",
        expected_indicators=["protocolVersion", "capabilities", "serverInfo"],
    ),
    # ---- Nginx UI / admin paths (MCPwn-inspired) -----------------------
    UrlProbe(
        path="/api/v1/mcp",
        probe_type=ProbeType.HTTP_GET,
        description="Versioned API MCP endpoint (nginx-UI pattern)",
        expected_indicators=["mcp", "jsonrpc", "tools"],
    ),
    UrlProbe(
        path="/nginx/mcp",
        probe_type=ProbeType.HTTP_GET,
        description="Nginx-namespaced MCP endpoint (MCPwn target pattern)",
        expected_indicators=["mcp", "jsonrpc", "tools"],
    ),
]


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 payloads for MCP method enumeration
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

JSONRPC_NOTIFICATIONS_INITIALIZED_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
    "params": {},
}

JSONRPC_TOOLS_CALL_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 7,
    "method": "tools/call",
    "params": {
        "name": "__mcp_scanner_probe__",
        "arguments": {},
    },
}

JSONRPC_RESOURCES_READ_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 8,
    "method": "resources/read",
    "params": {
        "uri": "file:///etc/passwd",
    },
}

JSONRPC_COMPLETION_PAYLOAD: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 9,
    "method": "completion/complete",
    "params": {
        "ref": {"type": "ref/prompt", "name": "test"},
        "argument": {"name": "arg", "value": "test"},
    },
}

# Ordered list used when iterating over all RPC methods to probe.
# initialize and list methods come first as they are the most informative.
ALL_JSONRPC_PAYLOADS: list[dict[str, Any]] = [
    JSONRPC_INITIALIZE_PAYLOAD,
    JSONRPC_TOOLS_LIST_PAYLOAD,
    JSONRPC_RESOURCES_LIST_PAYLOAD,
    JSONRPC_PROMPTS_LIST_PAYLOAD,
    JSONRPC_PING_PAYLOAD,
    JSONRPC_SERVER_INFO_PAYLOAD,
    JSONRPC_TOOLS_CALL_PAYLOAD,
    JSONRPC_RESOURCES_READ_PAYLOAD,
    JSONRPC_COMPLETION_PAYLOAD,
]

# Subset used for quick-fire discovery probes (only enumeration methods).
DISCOVERY_JSONRPC_PAYLOADS: list[dict[str, Any]] = [
    JSONRPC_INITIALIZE_PAYLOAD,
    JSONRPC_TOOLS_LIST_PAYLOAD,
    JSONRPC_RESOURCES_LIST_PAYLOAD,
    JSONRPC_PROMPTS_LIST_PAYLOAD,
]


# ---------------------------------------------------------------------------
# Response indicator constants
# ---------------------------------------------------------------------------

# Strings whose presence in a response body suggest it is an MCP response.
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
    "text/event-stream",
    "MCP",
    "ModelContextProtocol",
]

# Content-Type values that indicate JSON or event-stream MCP traffic.
MCP_CONTENT_TYPES: list[str] = [
    "application/json",
    "text/event-stream",
    "application/json-rpc",
    "application/jsonrpc",
]

# HTTP status codes that indicate a potentially accessible endpoint.
SUCCESSFUL_STATUS_CODES: frozenset[int] = frozenset({
    200,
    201,
    206,  # Partial Content (common for SSE)
})

# HTTP status codes that indicate authentication is required
# (useful for confirming that auth is enforced when it should be).
AUTH_REQUIRED_STATUS_CODES: frozenset[int] = frozenset({
    401,  # Unauthorized
    403,  # Forbidden
})


# ---------------------------------------------------------------------------
# Default authentication probe strategies
# ---------------------------------------------------------------------------

DEFAULT_AUTH_PROBES: list[AuthProbe] = [
    AuthProbe(
        name="no_auth_header",
        description=(
            "Request sent without any Authorization header to check for "
            "completely open (unauthenticated) access."
        ),
        missing_header="Authorization",
        expected_bypass_indicators=[
            "tools",
            "resources",
            "jsonrpc",
            "protocolVersion",
            "serverInfo",
        ],
    ),
    AuthProbe(
        name="empty_bearer_token",
        description=(
            "Request sent with an empty Bearer token (\"Bearer \") "
            "to test whether the server validates token presence."
        ),
        bypass_headers={"Authorization": "Bearer "},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="null_bearer_token",
        description=(
            "Request sent with \"null\" as the Bearer token value "
            "to catch servers that compare against literal null."
        ),
        bypass_headers={"Authorization": "Bearer null"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="undefined_bearer_token",
        description=(
            "Request sent with \"undefined\" as the Bearer token, "
            "a common JavaScript serialisation artefact."
        ),
        bypass_headers={"Authorization": "Bearer undefined"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="invalid_bearer_token",
        description=(
            "Request sent with an obviously invalid Bearer token to "
            "confirm the server properly rejects bad credentials."
        ),
        bypass_headers={"Authorization": "Bearer INVALID_TOKEN_MCP_SCANNER_PROBE"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="basic_auth_empty",
        description=(
            "Request sent with an empty Basic auth credential string "
            "to test whether the parser short-circuits on empty values."
        ),
        bypass_headers={"Authorization": "Basic "},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="basic_auth_anonymous",
        description=(
            "Request sent with anonymous:anonymous base64 encoded Basic "
            "credentials (YW5vbnltb3VzOmFub255bW91cw==)."
        ),
        bypass_headers={"Authorization": "Basic YW5vbnltb3VzOmFub255bW91cw=="},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="x_forwarded_for_localhost",
        description=(
            "Request sent with X-Forwarded-For and X-Real-IP set to "
            "127.0.0.1 to test IP allowlist bypass via header spoofing."
        ),
        bypass_headers={
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
        },
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="x_forwarded_for_private_range",
        description=(
            "Request spoofing a private RFC-1918 address "
            "(10.0.0.1) to bypass IP-based access control."
        ),
        bypass_headers={
            "X-Forwarded-For": "10.0.0.1",
            "X-Real-IP": "10.0.0.1",
        },
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="admin_api_key_header",
        description=(
            "Request sent with X-API-Key: admin to test for default "
            "or weak API key acceptance."
        ),
        bypass_headers={"X-API-Key": "admin"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="default_api_key_header",
        description=(
            "Request sent with X-API-Key: default, a common default "
            "credential in misconfigured deployments."
        ),
        bypass_headers={"X-API-Key": "default"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="empty_api_key_header",
        description=(
            "Request sent with an empty X-API-Key header to test "
            "whether the server rejects blank keys."
        ),
        bypass_headers={"X-API-Key": ""},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
    AuthProbe(
        name="cors_origin_bypass",
        description=(
            "Request sent with a localhost Origin header to test "
            "CORS-based access controls that trust localhost origins."
        ),
        bypass_headers={"Origin": "http://localhost"},
        expected_bypass_indicators=["tools", "resources", "jsonrpc"],
    ),
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_default_paths() -> list[str]:
    """Return the ordered list of default MCP URL path strings.

    Returns:
        List of path strings (each starting with ``/``) for every probe
        in :data:`DEFAULT_MCP_PATHS`.
    """
    return [probe.path for probe in DEFAULT_MCP_PATHS]


def get_probe_for_path(path: str) -> UrlProbe | None:
    """Look up the :class:`UrlProbe` whose path exactly matches *path*.

    Args:
        path: URL path string to look up (e.g. ``"/mcp/tools"``).

    Returns:
        The matching :class:`UrlProbe`, or ``None`` if no match is found.
    """
    for probe in DEFAULT_MCP_PATHS:
        if probe.path == path:
            return probe
    return None


def load_custom_wordlist(file_path: str) -> list[str]:
    """Load URL path strings from a plain-text wordlist file.

    Rules:
    * Empty lines are ignored.
    * Lines whose first non-whitespace character is ``#`` are treated as
      comments and skipped.
    * Paths that do not begin with ``/`` have ``/`` prepended automatically.

    Args:
        file_path: Filesystem path to the wordlist text file.

    Returns:
        Ordered list of normalised URL path strings.

    Raises:
        FileNotFoundError: If *file_path* does not exist.
        PermissionError: If *file_path* cannot be read.
        UnicodeDecodeError: If the file is not valid UTF-8.
    """
    paths: list[str] = []
    with open(file_path, encoding="utf-8") as fh:
        for raw_line in fh:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not stripped.startswith("/"):
                stripped = "/" + stripped
            paths.append(stripped)
    return paths


def build_probes_from_paths(paths: list[str]) -> list[UrlProbe]:
    """Construct a list of :class:`UrlProbe` objects from raw path strings.

    If a path already exists in :data:`DEFAULT_MCP_PATHS` the existing rich
    probe definition (with indicators, headers, etc.) is reused.  Unknown
    paths receive a generic probe whose type is inferred from path keywords:

    * Paths containing ``sse``, ``stream``, or ``event`` become
      :attr:`ProbeType.SSE` probes with the appropriate ``Accept`` header.
    * Paths containing ``rpc`` or ``jsonrpc`` become
      :attr:`ProbeType.JSON_RPC` probes.
    * All other paths receive a plain :attr:`ProbeType.HTTP_GET` probe.

    Args:
        paths: List of URL path strings to convert.

    Returns:
        List of :class:`UrlProbe` instances in the same order as *paths*.
    """
    probes: list[UrlProbe] = []
    default_map: dict[str, UrlProbe] = {p.path: p for p in DEFAULT_MCP_PATHS}

    for path in paths:
        if path in default_map:
            probes.append(default_map[path])
            continue

        path_lower = path.lower()
        if any(kw in path_lower for kw in ("sse", "stream", "event")):
            probe_type = ProbeType.SSE
            extra_headers: dict[str, str] = {"Accept": "text/event-stream"}
        elif any(kw in path_lower for kw in ("rpc", "jsonrpc")):
            probe_type = ProbeType.JSON_RPC
            extra_headers = {}
        else:
            probe_type = ProbeType.HTTP_GET
            extra_headers = {}

        probes.append(
            UrlProbe(
                path=path,
                probe_type=probe_type,
                description=f"Custom probe: {path}",
                expected_indicators=MCP_RESPONSE_INDICATORS[:6],
                headers=extra_headers,
            )
        )

    return probes


def is_mcp_response(
    body: str,
    content_type: str,
    status_code: int | None = None,
) -> bool:
    """Determine heuristically whether an HTTP response looks like MCP traffic.

    The check is intentionally broad to minimise false negatives:

    1. If Content-Type includes ``text/event-stream`` → MCP (SSE transport).
    2. If Content-Type includes ``application/json`` **and** the body
       contains any :data:`MCP_RESPONSE_INDICATORS` keyword → MCP.
    3. If Content-Type is unknown, fall back to body-only keyword scan.

    Args:
        body: Full or partial response body text.
        content_type: Value of the ``Content-Type`` response header.
        status_code: Optional HTTP status code (currently unused but
            reserved for future logic).

    Returns:
        ``True`` if the response appears to be from an MCP server.
    """
    ct_lower = content_type.lower()
    body_lower = body.lower()

    if "text/event-stream" in ct_lower:
        return True

    has_keyword = any(
        indicator.lower() in body_lower for indicator in MCP_RESPONSE_INDICATORS
    )

    if "application/json" in ct_lower or "application/json-rpc" in ct_lower:
        return has_keyword

    return has_keyword
