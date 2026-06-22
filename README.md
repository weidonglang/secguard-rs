# SecGuard RS

*A defensive Rust cybersecurity CLI for offline log analysis, IOC matching, integrity checking, and report generation.*

## Project Positioning

SecGuard RS is a **defensive** cybersecurity command-line tool. It operates exclusively on **local files** and performs:

- Offline authentication log analysis (brute force detection, password spray)
- Network traffic log analysis (blocked burst, high data egress)
- DNS query log analysis with IOC domain matching
- Windows event log analysis (suspicious PowerShell commands)
- Local IOC matching (domains, IPs, file hashes)
- File integrity baseline generation and verification
- Structured report generation (Markdown, JSON, CSV)

## Security Boundaries

This tool is designed for **defensive security analysis only**. It:

- ✅ Processes only local CSV/JSON files
- ✅ Performs offline pattern matching
- ✅ Generates SHA256 file hashes locally
- ✅ Evaluates detection rules against local data
- ❌ Does NOT make network connections
- ❌ Does NOT scan ports or vulnerabilities
- ❌ Does NOT execute payloads or commands
- ❌ Does NOT bypass security controls
- ❌ Does NOT download threat intelligence

## Installation

### Prerequisites

- Rust 1.70+ (https://rustup.rs/)
- Windows, macOS, or Linux

### Build from Source

```bash
git clone https://github.com/weidonglang/secguard-rs.git
cd secguard-rs
cargo build --release
```

The compiled binary will be at `target/release/secguard` (or `secguard.exe` on Windows).

## Quick Start

```bash
# Display help
cargo run -- --help

# Schema validation
cargo run -- schema check --kind auth --input examples/auth_events.csv

# Analyze authentication logs
cargo run -- analyze auth --input examples/auth_events.csv --output reports/auth_report.md

# Generate file integrity baseline
cargo run -- integrity baseline --path examples --output examples/file_hashes.csv

# Verify file integrity
cargo run -- integrity verify --baseline examples/file_hashes.csv --path examples --output reports/integrity_report.md

# IOC matching
cargo run -- ioc match --dns examples/dns_queries.csv --domains examples/ioc_domains.csv

# Generate summary report
cargo run -- report summarize --input reports/detections.csv --format markdown --output reports/summary.md
```

## Example Data

Sample log data is provided in the `examples/` directory:

- `auth_events.csv` — Authentication log events
- `network_flows.csv` — Network traffic flows
- `dns_queries.csv` — DNS query logs
- `windows_events.csv` — Windows event logs
- `file_hashes.csv` — File integrity baseline
- `ioc_domains.csv`, `ioc_ips.csv`, `ioc_hashes.csv` — IOC indicators

## Testing

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test parser
cargo test detection
cargo test cli
cargo test edge_case
```

## Detection Rules

| Rule ID | Description | Severity |
|---------|-------------|----------|
| SG-AUTH-001 | Brute Force Login | high |
| SG-AUTH-002 | Password Spray | high |
| SG-WIN-001 | Suspicious PowerShell Encoded Command | medium |
| SG-NET-001 | Blocked Outbound Burst | medium |
| SG-NET-002 | High Data Egress | low |
| SG-DNS-001 | IOC Domain Match | high |
| SG-IP-001 | IOC IP Match | high |
| SG-HASH-001 | IOC Hash Match | critical |
| SG-FIM-001 | File Modified | high |
| SG-FIM-002 | File Missing | high |

## License

MIT