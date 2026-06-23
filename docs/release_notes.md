# Release Notes

## v1.0.0 (2026-06-23)

### Overview

SecGuard RS v1.0.0 is the initial release of a defensive Rust cybersecurity CLI tool for offline log analysis, IOC matching, file integrity verification, and security report generation.

### Features

- **Authentication Log Analysis**
  - SG-AUTH-001: Brute Force Login detection
  - SG-AUTH-002: Password Spray detection

- **Network Traffic Analysis**
  - SG-NET-001: Blocked Outbound Burst detection
  - SG-NET-002: High Data Egress detection

- **DNS Query Analysis**
  - SG-DNS-001: IOC Domain Match against local domain lists

- **Windows Event Analysis**
  - SG-WIN-001: Suspicious PowerShell Encoded Command detection

- **IOC Matching**
  - SG-IP-001: IOC IP Match against local IP lists
  - SG-HASH-001: IOC Hash Match against local hash lists

- **File Integrity Monitoring**
  - SG-FIM-001: File Modified detection (SHA256 comparison)
  - SG-FIM-002: File Missing detection

- **Report Generation**
  - Markdown reports with severity indicators and recommendations
  - JSON reports for machine processing
  - CSV findings for spreadsheet compatibility
  - Summary reports with risk scoring

### CLI Commands

- `secguard --help` — Display help
- `secguard schema check` — Validate CSV schema
- `secguard analyze auth` — Analyze authentication logs
- `secguard analyze network` — Analyze network flow logs
- `secguard analyze dns` — Analyze DNS query logs
- `secguard analyze windows` — Analyze Windows event logs
- `secguard ioc match` — Match indicators of compromise
- `secguard integrity baseline` — Generate SHA256 baseline
- `secguard integrity verify` — Verify file integrity against baseline
- `secguard report summarize` — Generate summary reports

### Known Limitations

- Offline analysis only — no real-time monitoring
- Windows event log analysis requires exported CSV files
- IOC lists must be prepared locally (no automatic updates)
- Network traffic analysis supports PCAP-derived CSV only

### Installation

```bash
# Build from source
git clone https://github.com/weidonglang/secguard-rs.git
cd secguard-rs
cargo build --release

# Binary location: target/release/secguard.exe
```

### Dependencies

- Rust 1.70+
- clap 4.x (CLI argument parsing)
- serde/serde_json 1.x (serialization)
- csv 1.x (CSV parsing)
- chrono 0.4.x (timestamp handling)
- sha2 0.10.x (SHA256 hashing)
- walkdir 2.x (directory traversal)
- thiserror 1.x (error handling)

### Security

This release contains strictly defensive functionality only:
- No network connections (no std::net, reqwest, hyper, tokio::net)
- No port scanning or vulnerability exploitation
- No payload generation or command execution
- Local file processing only