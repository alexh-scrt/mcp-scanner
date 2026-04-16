# MCP Scanner

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A focused CLI security tool that discovers and audits **Model Context Protocol
(MCP)** endpoints on web servers and APIs.

Inspired by the critical **MCPwn** nginx UI vulnerability, MCP Scanner probes
common MCP URL patterns, tests authentication requirements, checks for
unauthenticated tool/resource exposure, and generates a structured security
report in JSON, HTML, or color-coded terminal format.

## Why MCP Scanner?

As AI integrations rapidly adopt MCP, developers and security engineers need a
way to audit their own deployments before attackers do. The MCPwn class of
vulnerabilities demonstrates that unauthenticated MCP endpoints can expose
sensitive tool listings, allow arbitrary JSON-RPC method calls, and leak
Server-Sent Event (SSE) streams — all without any authentication.

MCP Scanner was built to fill this gap:

- **Fast async scanning** – probes dozens of paths in parallel.
- **Auth bypass testing** – tests 13+ real-world bypass techniques.
- **Severity-rated findings** – maps each issue to real-world impact.
- **CI/CD ready** – exits with code 10 when critical/high findings are found.
- **Dual-format reports** – Rich terminal output and machine-readable JSON/HTML.

---

## Installation

### From PyPI (recommended)

```bash
pip install mcp-scanner
```

### From source

```bash
git clone https://github.com/example/mcp-scanner.git
cd mcp-scanner
pip install -e ".[dev]"
```

### Requirements

- Python 3.11 or newer
- `httpx[http2]>=0.27.0`
- `click>=8.1.0`
- `rich>=13.7.0`
- `anyio>=4.3.0`

---

## Quick Start

```bash
# Scan a single target
mcp-scanner scan https://example.com

# Scan multiple targets
mcp-scanner scan https://example.com https://api.example.com

# Higher concurrency for large deployments
mcp-scanner scan --concurrency 30 https://example.com

# Output a JSON report to a file
mcp-scanner scan --format json --output report.json https://example.com

# Output a self-contained HTML report
mcp-scanner scan --format html --output report.html https://example.com

# Print JSON to stdout (pipe-friendly)
mcp-scanner scan --format json https://example.com | jq .summary

# Use a custom URL path wordlist
mcp-scanner scan --wordlist custom_paths.txt https://example.com

# Inject a custom header (e.g. API key or session token)
mcp-scanner scan --header "Authorization: Bearer mytoken" https://example.com
mcp-scanner scan --header "X-API-Key: secret" --header "X-Tenant: acme" https://example.com

# Disable SSL certificate verification (use with caution)
mcp-scanner scan --no-verify-ssl https://localhost:8443

# Discovery only – skip auth bypass testing
mcp-scanner scan --skip-auth-tests https://example.com

# Filter findings below a minimum severity
mcp-scanner scan --min-severity high https://example.com

# Verbose debug output
mcp-scanner scan --verbose https://example.com
```

---

## CLI Reference

### `mcp-scanner scan`

Scan one or more target URLs for MCP endpoints and security vulnerabilities.

```
Usage: mcp-scanner scan [OPTIONS] TARGET...

Options:
  -c, --concurrency INTEGER RANGE  Maximum simultaneous HTTP requests (1-200).
                                   [default: 10]
  -t, --timeout FLOAT RANGE        Per-request timeout in seconds.
                                   [default: 10.0]
  -f, --format [terminal|json|html]
                                   Output format for the security report.
                                   [default: terminal]
  -o, --output PATH                Write the report to this file path.
                                   Required for --format html.
  -w, --wordlist FILE              Path to a custom URL path wordlist.
  -H, --header NAME: VALUE         Extra HTTP header (repeatable).
  --no-verify-ssl                  Disable TLS/SSL certificate verification.
  --skip-auth-tests                Skip authentication bypass testing.
  -s, --min-severity [critical|high|medium|low|info]
                                   Minimum severity level to include.
                                   [default: info]
  -v, --verbose                    Enable verbose debug-level logging.
  --help                           Show this message and exit.
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0`  | Scan completed successfully; no CRITICAL or HIGH findings. |
| `1`  | Scan interrupted by user (Ctrl-C). |
| `2`  | Fatal error during initialisation or report writing. |
| `10` | Scan completed; at least one CRITICAL or HIGH finding was detected. |

### `mcp-scanner list-probes`

List all built-in MCP URL probe patterns.

```
Usage: mcp-scanner list-probes [OPTIONS]

Options:
  -f, --format [table|json|paths]  Output format.  [default: table]
  --help                           Show this message and exit.
```

The `paths` format prints one path per line, making it easy to generate a
custom wordlist based on the defaults:

```bash
mcp-scanner list-probes --format paths > default_paths.txt
echo "/my/custom/mcp" >> default_paths.txt
mcp-scanner scan --wordlist default_paths.txt https://example.com
```

### `mcp-scanner list-auth-probes`

List all built-in authentication bypass probe strategies.

```
Usage: mcp-scanner list-auth-probes [OPTIONS]

Options:
  -f, --format [table|json]  Output format.  [default: table]
  --help                     Show this message and exit.
```

---

## Features

### Async Multi-Target Scanning

MCP Scanner probes all configured URL patterns against all targets
concurrently, bounded by the `--concurrency` limit. This allows you to scan
large numbers of hosts quickly without overwhelming the target.

### MCP Endpoint Patterns Probed

The built-in probe set covers 40+ URL patterns across multiple categories:

| Category | Example Paths |
|----------|---------------|
| Core MCP | `/mcp`, `/mcp/v1`, `/mcp/v2` |
| SSE Transport | `/sse`, `/mcp/sse`, `/stream`, `/events` |
| API-Prefixed | `/api/mcp`, `/api/mcp/v1`, `/api/mcp/sse` |
| Well-Known | `/.well-known/mcp`, `/.well-known/mcp.json` |
| Capability Endpoints | `/mcp/tools`, `/mcp/resources`, `/mcp/prompts` |
| JSON-RPC | `/mcp/rpc`, `/rpc`, `/jsonrpc` |
| Version-Prefixed | `/v1/mcp`, `/v2/mcp` |
| Discovery | `/openapi.json`, `/swagger.json`, `/docs` |
| MCPwn-Inspired | `/nginx/mcp`, `/api/v1/mcp` |

Run `mcp-scanner list-probes` to see the full list.

### Authentication Bypass Testing

For every discovered MCP endpoint, MCP Scanner runs a battery of 13+
authentication bypass probes:

| Probe | Technique |
|-------|-----------|
| `no_auth_header` | No Authorization header (open access test) |
| `empty_bearer_token` | `Authorization: Bearer ` (empty value) |
| `null_bearer_token` | `Authorization: Bearer null` |
| `undefined_bearer_token` | `Authorization: Bearer undefined` |
| `invalid_bearer_token` | Obviously invalid Bearer token |
| `basic_auth_empty` | `Authorization: Basic ` (empty) |
| `basic_auth_anonymous` | `Authorization: Basic YW5vbnltb3VzOmFub255bW91cw==` |
| `x_forwarded_for_localhost` | X-Forwarded-For: 127.0.0.1 (IP spoof) |
| `x_forwarded_for_private_range` | X-Forwarded-For: 10.0.0.1 |
| `admin_api_key_header` | `X-API-Key: admin` |
| `default_api_key_header` | `X-API-Key: default` |
| `empty_api_key_header` | `X-API-Key: ` (empty) |
| `cors_origin_bypass` | `Origin: http://localhost` |

Run `mcp-scanner list-auth-probes` to see the full list.

### Severity-Rated Findings

Each finding is assigned a severity level with remediation guidance:

| Severity | Description | Example |
|----------|-------------|------|
| **CRITICAL** | Immediate action required | Unauthenticated tool listing (MCPwn class) |
| **HIGH** | Urgent remediation needed | Unauthenticated SSE stream or resource listing |
| **MEDIUM** | Address soon | Open JSON-RPC endpoint or prompt listing |
| **LOW** | Review when possible | Potential MCP keyword match, unconfirmed |
| **INFO** | Informational | Discovery metadata |

### Dual-Format Reporting

**Terminal** (default) – color-coded, grouped by severity with per-finding
detail panels. Suitable for interactive security assessments.

**JSON** – machine-readable report for CI/CD pipelines, SIEM integration, or
further processing with tools like `jq`.

**HTML** – self-contained dark-themed document suitable for sharing with
stakeholders. No external dependencies.

---

## Output Formats

### Terminal Output

```
╭───────────────────── 🔍 MCP Scanner ───────────────────────╮
│ MCP Scanner Security Report                                  │
│ Scan ID:   3f2a1c8d-...                                      │
│ Version:   mcp-scanner 0.1.0                                 │
│ Started:   2024-01-15 12:34:56 UTC | Duration: 4.2s          │
│ Targets:   https://example.com                               │
╰──────────────────────────────────────────────────────────────╯

  Findings Summary
 ╭──────────────┬───────┬──────────────────────────────────────╮
 │ Severity     │ Count │ Risk                                 │
 ├──────────────┼───────┼──────────────────────────────────────┤
 │ 🔴 CRITICAL  │     1 │ Immediate action required            │
 │ 🟠 HIGH      │     2 │ Urgent remediation needed            │
 │ 🟡 MEDIUM    │     0 │ Should be addressed soon             │
 │ 🔵 LOW       │     0 │ Address in normal workflow           │
 │ ⚪ INFO      │     0 │ Informational, no action required    │
 ├──────────────┼───────┼──────────────────────────────────────┤
 │ TOTAL        │     3 │ Across 1 target(s)                   │
 ╰──────────────┴───────┴──────────────────────────────────────╯
```

### JSON Output Schema

```json
{
  "scan_id": "3f2a1c8d-...",
  "scanner_version": "0.1.0",
  "started_at": "2024-01-15T12:34:56.000000+00:00",
  "completed_at": "2024-01-15T12:35:00.000000+00:00",
  "targets": [
    {
      "url": "https://example.com",
      "timeout": 10.0,
      "verify_ssl": true
    }
  ],
  "findings": [
    {
      "finding_id": "a1b2c3d4-...",
      "title": "Unauthenticated MCP Tool Listing Exposed",
      "severity": "CRITICAL",
      "url": "https://example.com/mcp/tools",
      "description": "MCP tool definitions were returned unauthenticated...",
      "evidence": "HTTP 200 | Content-Type: application/json | Body snippet: ...",
      "recommendation": "Immediately require authentication...",
      "cve_references": ["MCPwn-2024-001"],
      "extra": {},
      "discovered_at": "2024-01-15T12:34:57.000000+00:00"
    }
  ],
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "endpoints_probed": 0,
    "endpoints_found": 1,
    "targets_scanned": 1
  }
}
```

---

## CI/CD Integration

Use the exit code to fail your pipeline when critical or high issues are found:

```yaml
# GitHub Actions example
- name: Run MCP Scanner
  run: |
    pip install mcp-scanner
    mcp-scanner scan \
      --format json \
      --output mcp-report.json \
      --min-severity high \
      https://staging.example.com
  # Exit code 10 means critical/high findings were detected
  # Exit code 0 means clean scan

- name: Upload MCP Report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: mcp-security-report
    path: mcp-report.json
```

```bash
# Shell script example
mcp-scanner scan --format json --output report.json https://example.com
EXIT_CODE=$?
if [ $EXIT_CODE -eq 10 ]; then
  echo "CRITICAL/HIGH findings detected – review report.json"
  exit 1
elif [ $EXIT_CODE -ne 0 ]; then
  echo "Scanner error (exit code $EXIT_CODE)"
  exit 1
fi
echo "No critical/high findings."
```

---

## Custom Wordlists

Create a plain-text file with one URL path per line:

```text
# My custom MCP paths
/internal/mcp
/admin/mcp
/ai/mcp/v1
/api/internal/sse
```

Lines starting with `#` are comments and ignored. Paths without a leading `/`
have one added automatically.

```bash
mcp-scanner scan --wordlist my_paths.txt https://example.com
```

> **Note:** When `--wordlist` is provided, the custom paths **replace** the
> built-in defaults entirely. To extend the defaults, first export them:
>
> ```bash
> mcp-scanner list-probes --format paths > combined.txt
> echo "/my/custom/path" >> combined.txt
> mcp-scanner scan --wordlist combined.txt https://example.com
> ```

---

## Programmatic API

MCP Scanner can be used as a Python library:

```python
import asyncio
from mcp_scanner.scanner import scan
from mcp_scanner.reporter import Reporter

async def main():
    report = await scan(
        targets=["https://example.com"],
        concurrency=10,
        timeout=10.0,
        verify_ssl=True,
        extra_headers={"Authorization": "Bearer mytoken"},
    )

    reporter = Reporter()
    reporter.print_terminal_report(report)

    # Or get the JSON:
    json_str = reporter.to_json(report)
    print(json_str)

asyncio.run(main())
```

### Auth testing only

```python
import asyncio
from mcp_scanner.models import ScanTarget
from mcp_scanner.auth_tester import test_auth_for_endpoints

async def main():
    target = ScanTarget(url="https://example.com")
    findings = await test_auth_for_endpoints(
        endpoints=["https://example.com/mcp", "https://example.com/sse"],
        target=target,
    )
    for finding in findings:
        print(f"[{finding.severity.value}] {finding.title}: {finding.url}")

asyncio.run(main())
```

---

## Security Context

> ⚠️ **This tool is intended for authorised security testing only.**
>
> Only scan systems you own or have explicit written permission to test.
> Unauthorised scanning may violate computer fraud laws in your jurisdiction.

MCP Scanner performs active probing of the target, including:
- Sending HTTP GET/POST requests to many URL paths
- Submitting JSON-RPC payloads to discovered endpoints
- Attempting authentication bypass techniques

All probes are read-only (no data is modified) and the tool does not attempt
to exploit any vulnerabilities beyond demonstrating unauthenticated access.

---

## MCPwn Vulnerability Class

The **MCPwn** class of vulnerabilities refers to unauthenticated access to
MCP server endpoints, first documented in the nginx UI MCP integration.
Key characteristics:

- MCP server endpoints exposed without any authentication middleware
- Tool listings (`/mcp/tools`) accessible without credentials, revealing the
  full capability surface of the AI agent
- Unauthenticated SSE streams allowing interception of AI tool calls
- JSON-RPC methods callable without authorisation, enabling tool invocation

MCP Scanner detects all of these patterns and rates them **CRITICAL** or
**HIGH** severity with actionable remediation guidance.

**Remediation:**
1. Add authentication middleware to all MCP endpoints.
2. Use Bearer token authentication validated server-side.
3. Apply network-level controls (firewall rules) as defence-in-depth.
4. Audit which tools and resources are exposed and apply least-privilege.
5. Monitor MCP endpoint access logs for anomalous activity.

---

## Development

### Setup

```bash
git clone https://github.com/example/mcp-scanner.git
cd mcp-scanner
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest

# With coverage
pytest --cov=mcp_scanner --cov-report=term-missing

# Run a specific test file
pytest tests/test_scanner.py -v
```

### Project Structure

```
mcp_scanner/
├── __init__.py      # Package init, version
├── cli.py           # Click CLI entry point
├── scanner.py       # Async scanning engine
├── auth_tester.py   # Authentication bypass detection
├── probes.py        # URL patterns, payloads, auth strategies
├── reporter.py      # Terminal, JSON, and HTML report generation
└── models.py        # Data classes: ScanTarget, Finding, ScanReport

tests/
├── test_scanner.py
├── test_auth_tester.py
├── test_reporter.py
├── test_probes.py
└── test_models.py
```

---

## License

MIT – see [LICENSE](LICENSE) for details.
