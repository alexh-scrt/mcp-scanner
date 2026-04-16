# MCP Scanner

A focused CLI security tool that discovers and audits **Model Context Protocol (MCP)** endpoints on web servers and APIs.

Inspired by the critical 'MCPwn' nginx UI vulnerability, MCP Scanner probes common MCP URL patterns, tests authentication requirements, checks for unauthenticated tool/resource exposure, and generates a structured security report.

## Why MCP Scanner?

As AI integrations rapidly adopt MCP, developers and security engineers need a way to audit their own deployments before attackers do. The MCPwn class of vulnerabilities demonstrates that unauthenticated MCP endpoints can expose sensitive tool listings, allow arbitrary JSON-RPC method calls, and leak server-sent event (SSE) streams — all without any authentication.

## Installation

```bash
pip install mcp-scanner
```

Or install from source:

```bash
git clone https://github.com/example/mcp-scanner.git
cd mcp-scanner
pip install -e ".[dev]"
```

## Quick Start

```bash
# Scan a single target
mcp-scanner scan https://example.com

# Scan multiple targets
mcp-scanner scan https://example.com https://api.example.com

# Scan with custom concurrency
mcp-scanner scan --concurrency 20 https://example.com

# Output JSON report
mcp-scanner scan --format json --output report.json https://example.com

# Use a custom wordlist
mcp-scanner scan --wordlist custom_paths.txt https://example.com

# Inject custom headers (e.g., API keys)
mcp-scanner scan --header "Authorization: Bearer mytoken" https://example.com

# Verbose output
mcp-scanner scan --verbose https://example.com
```

## Features

- **Async multi-target scanning** with configurable concurrency
- **Authentication auditing** for missing Authorization headers, unauthenticated SSE streams, exposed tool listings, and open JSON-RPC method calls
- **Severity-rated findings** with CVE-style descriptions
- **Dual-format reporting**: Rich terminal summary and machine-readable JSON
- **Custom wordlist and header injection** support

## MCP Endpoint Patterns Probed

- `/mcp`
- `/mcp/v1`
- `/sse`
- `/mcp/sse`
- `/api/mcp`
- `/api/mcp/v1`
- `/.well-known/mcp`
- `/mcp/tools`
- `/mcp/resources`
- `/mcp/prompts`
- And many more...

## Report Format

### Terminal Output

Color-coded findings grouped by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO).

### JSON Output

```json
{
  "scan_id": "...",
  "started_at": "2024-01-01T00:00:00Z",
  "completed_at": "2024-01-01T00:01:00Z",
  "targets": [...],
  "findings": [...],
  "summary": {
    "total_findings": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1,
    "info": 0
  }
}
```

## Security Context

This tool is intended for **authorized security testing only**. Only scan systems you own or have explicit written permission to test.

## License

MIT
