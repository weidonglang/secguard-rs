# SecGuard RS User Guide (v1.0.0)

## Overview

SecGuard RS (version 1.0.0) is a defensive Rust cybersecurity CLI tool for offline log analysis, IOC matching, integrity checking, and report generation. It processes only local files and never makes network connections.

## Installation

### Prerequisites

- Rust toolchain (rustc, cargo)
- Windows OS (for native .exe support)

### Build from Source

```bash
git clone https://github.com/<YOUR_USERNAME>/secguard-rs.git
cd secguard-rs
cargo build --release
```

The executable will be at `target/release/secguard.exe`.

### Download Release

Download the latest `secguard-rs-v1.0.0.zip` from the GitHub Releases page and extract it.

## Quick Start

```bash
secguard --help
secguard schema check --kind auth --input examples/auth_events.csv
secguard analyze auth --input examples/auth_events.csv --output reports/auth_report.md
secguard analyze network --input examples/network_flows.csv --output reports/network_report.md
secguard analyze dns --dns examples/dns_queries.csv --ioc-domains examples/ioc_domains.csv --output reports/dns_report.md
secguard analyze windows --input examples/windows_events.csv --output reports/windows_report.md
```

## CLI Commands

### `secguard --help`

Displays the help menu with all available commands.

### `secguard schema`

Validate CSV schema against the data dictionary.

```bash
secguard schema auth --input examples/auth_events.csv
```

**Options:**
- `--input`: Path to the CSV file to validate

### `secguard analyze`

Analyze security logs for threats.

#### `secguard analyze auth`

Analyze authentication logs for brute force and password spray attacks.

```bash
secguard analyze auth --input examples/auth_events.csv --output reports/auth_report.md
```

**Options:**
- `--input`: Path to `auth_events.csv`
- `--output`: (Optional) Output report path. If omitted, prints to stdout.

**Detections:**
- SG-AUTH-001: Brute Force Login
- SG-AUTH-002: Password Spray

#### `secguard analyze network`

Analyze network flow logs for blocked outbound bursts and high data egress.

```bash
secguard analyze network --input examples/network_flows.csv --output reports/network_report.md
```

**Options:**
- `--input`: Path to `network_flows.csv`
- `--output`: (Optional) Output report path

**Detections:**
- SG-NET-001: Blocked Outbound Burst
- SG-NET-002: High Data Egress

#### `secguard analyze dns`

Analyze DNS query logs for IOC domain matches.

```bash
secguard analyze dns --dns examples/dns_queries.csv --ioc-domains examples/ioc_domains.csv --output reports/dns_report.md
```

**Options:**
- `--dns`: Path to `dns_queries.csv`
- `--ioc-domains`: (Optional) Path to `ioc_domains.csv`
- `--output`: (Optional) Output report path

**Detections:**
- SG-DNS-001: IOC Domain Match

#### `secguard analyze windows`

Analyze Windows event logs for suspicious PowerShell commands.

```bash
secguard analyze windows --input examples/windows_events.csv --output reports/windows_report.md
```

**Options:**
- `--input`: Path to `windows_events.csv`
- `--output`: (Optional) Output report path

**Detections:**
- SG-WIN-001: Suspicious PowerShell Encoded Command

### `secguard ioc match`

Match indicators of compromise against local data files.

```bash
secguard ioc match --dns examples/dns_queries.csv --ips examples/ioc_ips.csv --domains examples/ioc_domains.csv --hashes examples/ioc_hashes.csv
```

**Options:**
- `--dns`: (Optional) Path to `dns_queries.csv`
- `--ips`: (Optional) Path to `ioc_ips.csv`
- `--domains`: (Optional) Path to `ioc_domains.csv`
- `--hashes`: (Optional) Path to `ioc_hashes.csv`

All parameters are optional but at least one should be provided for meaningful analysis.

**Detections:**
- SG-DNS-001: IOC Domain Match (DNS queries matching `ioc_domains.csv`)
- SG-IP-001: IOC IP Match (network flows matching `ioc_ips.csv`)
- SG-HASH-001: IOC Hash Match (file hashes matching `ioc_hashes.csv`)

### `secguard integrity`

File integrity baseline generation and verification.

#### `secguard integrity baseline`

Generate SHA256 baseline for files in a directory.

```bash
secguard integrity baseline --path examples --output examples/file_hashes.csv
```

**Options:**
- `--path`: Directory path to scan
- `--output`: (Optional) Output baseline CSV path

#### `secguard integrity verify`

Verify files against a baseline.

```bash
secguard integrity verify --baseline examples/file_hashes.csv --path examples --output reports/integrity_report.md
```

**Options:**
- `--baseline`: Path to baseline CSV
- `--path`: Directory path to verify
- `--output`: (Optional) Output report path

**Detections:**
- SG-FIM-001: File Modified
- SG-FIM-002: File Missing

### `secguard report summarize`

Generate summary reports from detection findings.

```bash
secguard report summarize --input reports/detections.csv --format markdown --output reports/summary.md
```

**Options:**
- `--input`: Path to detection findings (CSV or Markdown)
- `--format`: Output format: `markdown`, `json`, `csv` (default: `markdown`)
- `--output`: (Optional) Output report path

## Example Data

The `examples/` directory contains sample data files:

| File | Description | Rows |
|------|-------------|------|
| `auth_events.csv` | Authentication events with login attempts | 30+ |
| `network_flows.csv` | Network flow logs with blocked traffic | 30+ |
| `dns_queries.csv` | DNS query logs with suspicious domains | 30+ |
| `windows_events.csv` | Windows event logs with PowerShell commands | 30+ |
| `file_hashes.csv` | Baseline file hash data | 30+ |
| `ioc_domains.csv` | Known malicious domain indicators | 30+ |
| `ioc_ips.csv` | Known malicious IP indicators | 30+ |
| `ioc_hashes.csv` | Known malicious file hash indicators | 30+ |
| `config.json` | Default configuration | 1 |

## Output Formats

### Markdown Report

Contains human-readable findings with severity indicators, evidence excerpts, and remediation recommendations.

### JSON Report

Machine-readable format for further processing by other tools.

### CSV Findings

Tabular format compatible with spreadsheet applications.

## Error Handling

If a command fails, SecGuard RS will:
- Return a non-zero exit code
- Print an error message to stderr
- Never panic or unwrap user input

Common errors:
- **File not found**: The specified input file does not exist
- **Output directory not found**: The parent directory of the output path does not exist
- **Schema mismatch**: CSV headers do not match the expected schema
- **Parse error**: Invalid data in the input file

## Security Boundaries

SecGuard RS is strictly a **defensive** tool. It:
- ✅ Processes only local files
- ✅ Performs offline log analysis
- ✅ Matches local IOCs
- ❌ Does not scan ports or external targets
- ❌ Does not brute force passwords
- ❌ Does not execute attack payloads
- ❌ Does not make network connections
- ❌ Does not download threat intelligence automatically

See `docs/security_boundaries.md` for the complete security policy.