# MCP Scanner 🔍

> Audit your MCP endpoints before attackers do.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

MCP Scanner is a focused CLI security tool that discovers and audits **Model Context Protocol (MCP)** endpoints on web servers and APIs. Inspired by the critical **MCPwn** nginx UI vulnerability, it probes common MCP URL patterns, tests authentication requirements, and checks for unauthenticated tool and resource exposure. It generates structured security reports in JSON, HTML, or color-coded terminal format — ready for both interactive use and CI/CD pipelines.

---

## Quick Start

```bash
# Install from PyPI
pip install mcp-scanner

# Scan a single target
mcp-scanner scan https://your-api.example.com

# Scan multiple targets and save a JSON report
mcp-scanner scan https://api1.example.com https://api2.example.com --output report.json

# Scan with increased concurrency and verbose output
mcp-scanner scan https://your-api.example.com --concurrency 20 --verbose
```

That's it. MCP Scanner will probe common MCP paths, test authentication, and print a severity-rated findings summary to your terminal.

---

## Why MCP Scanner?

As AI integrations rapidly adopt MCP, unauthenticated endpoints can expose sensitive tool listings, allow arbitrary JSON-RPC method calls, and leak Server-Sent Event (SSE) streams — all without credentials. The MCPwn vulnerability class demonstrated this risk in production nginx deployments. MCP Scanner gives developers and security engineers a fast, automated way to find these issues in their own infrastructure.

---

## Features

- **Async multi-target scanning** — Concurrently probes large sets of hosts for common MCP endpoint patterns (`/mcp`, `/sse`, `/api/mcp`, `/.well-known/mcp`, and more) with configurable concurrency limits.
- **Authentication auditing** — Tests each discovered endpoint for missing `Authorization` headers, unauthenticated SSE streams, exposed tool listings, and open JSON-RPC method calls.
- **Severity-rated findings** — Each issue is assigned a `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` severity with CVE-style descriptions mapping to real-world impact, referencing the MCPwn vulnerability class.
- **Dual-format reporting** — Color-coded Rich terminal summary for interactive use; machine-readable JSON and HTML reports for CI/CD pipeline integration.
- **Custom wordlists and header injection** — Extend default probes with internal URL patterns and test with specific API keys or session tokens.

---

## Usage Examples

### Basic single-host scan

```bash
mcp-scanner scan https://myapp.example.com
```

```
╭─────────────────────────────────────────╮
│         MCP Scanner v0.1.0              │
╰─────────────────────────────────────────╯

  Scanning 1 target(s)...

  [CRITICAL] Unauthenticated MCP endpoint exposed
             URL: https://myapp.example.com/mcp
             Tools listing accessible without credentials.

  [HIGH]     Open SSE stream detected
             URL: https://myapp.example.com/sse
             Server-Sent Events stream requires no authentication.

  Summary: 2 findings across 1 target (1 CRITICAL, 1 HIGH)
```

### Scan multiple hosts from a file

```bash
mcp-scanner scan --targets-file hosts.txt --concurrency 30 --output results.json
```

### Use a custom wordlist for internal path patterns

```bash
mcp-scanner scan https://internal.corp.net \
  --wordlist internal-paths.txt \
  --header "X-Internal-Token: secret123"
```

### JSON report output (for CI/CD)

```bash
mcp-scanner scan https://staging.example.com --output report.json --format json
```

```json
{
  "scan_id": "a3f1c8e2-...",
  "started_at": "2024-07-01T12:00:00Z",
  "targets": ["https://staging.example.com"],
  "findings": [
    {
      "severity": "CRITICAL",
      "title": "Unauthenticated MCP endpoint exposed",
      "url": "https://staging.example.com/mcp",
      "description": "The /mcp endpoint responds to unauthenticated requests and exposes a tools listing.",
      "evidence": "HTTP 200 with Content-Type: application/json"
    }
  ],
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

### All CLI options

```bash
mcp-scanner scan --help
```

```
Usage: mcp-scanner scan [OPTIONS] [TARGETS]...

Options:
  --targets-file PATH        File containing one target URL per line.
  --concurrency INTEGER      Max concurrent requests. [default: 10]
  --timeout FLOAT            Per-request timeout in seconds. [default: 10.0]
  --wordlist PATH            Custom URL path wordlist file.
  --header TEXT              Extra request header (repeatable: -H "K: V").
  --output PATH              Write report to file.
  --format [terminal|json|html]  Output format. [default: terminal]
  --verbose / --no-verbose   Enable verbose logging.
  --version                  Show version and exit.
  --help                     Show this message and exit.
```

---

## Project Structure

```
mcp_scanner/
├── pyproject.toml          # Project metadata, dependencies, CLI entry point
├── README.md               # This file
├── mcp_scanner/
│   ├── __init__.py         # Package init, version, top-level symbols
│   ├── cli.py              # Click-based CLI entry point
│   ├── scanner.py          # Core async scanning engine
│   ├── probes.py           # MCP URL patterns, payloads, auth test strategies
│   ├── auth_tester.py      # Authentication bypass detection
│   ├── reporter.py         # Terminal, JSON, and HTML report generation
│   └── models.py           # ScanTarget, Finding, Severity, ScanReport dataclasses
└── tests/
    ├── __init__.py
    ├── test_scanner.py     # Scanner engine tests (mocked HTTP)
    ├── test_auth_tester.py # Auth bypass detection tests
    ├── test_reporter.py    # Report generation and schema tests
    ├── test_probes.py      # Probe pattern completeness tests
    └── test_models.py      # Dataclass serialization and helper tests
```

---

## Configuration

MCP Scanner is configured entirely via CLI flags — no config file required. Key options:

| Option | Description | Default |
|---|---|---|
| `--concurrency` | Maximum number of concurrent HTTP requests | `10` |
| `--timeout` | Per-request timeout in seconds | `10.0` |
| `--wordlist` | Path to a custom URL path wordlist (one path per line) | Built-in list |
| `--header` | Additional HTTP header to send with every request (repeatable) | None |
| `--format` | Report output format: `terminal`, `json`, or `html` | `terminal` |
| `--output` | File path to write the report (stdout if omitted) | None |

### Custom wordlist format

One URL path per line, with or without a leading slash:

```
/mcp
/api/mcp
/internal/mcp/tools
/.well-known/mcp
custom-mcp-endpoint
```

---

## Installation from Source

```bash
git clone https://github.com/example/mcp-scanner.git
cd mcp-scanner
pip install -e .
```

### Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*
