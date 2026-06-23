# SecGuard RS Release Notes

## v1.0.1 (Current)

### Bug Fixes

- **IOC IP and Hash matching integrated into CLI**: The `secguard ioc match` command now supports IP IOC matching (via `--flows` flag) and hash IOC matching (via `--file-hashes` flag), enabling comprehensive IOC analysis in a single command.
- **IOC finding timestamps use source data time**: All IOC detection findings now correctly use timestamps from the original log data rather than the current system time, ensuring deterministic and reproducible detection results.
- **CLI help text alignment with schema field names**: CLI argument descriptions and help text now consistently use the same field names as defined in the global data schema (`data_dictionary.md`), reducing confusion for users.

### Chores

- Added GitHub Actions CI workflow for automated testing on push/PR.
- Updated all version references to 1.0.1 across `Cargo.toml`, `README.md`, `docs/user_guide.md`, `cli.rs`, and `docs/release_notes.md`.

## v1.0.0 (Initial Release)

### Features

- **Schema Validation**: Validate CSV files against the defined data dictionary schemas for all supported log types.
- **Authentication Log Analysis**: Detect brute force attacks (SG-AUTH-001) and password spray attacks (SG-AUTH-002) from authentication event logs.
- **Network Flow Analysis**: Identify blocked outbound bursts (SG-NET-001) and high data egress events (SG-NET-002).
- **DNS Query Analysis**: Match DNS queries against local IOC domain indicators (SG-DNS-001).
- **Windows Event Analysis**: Detect suspicious PowerShell encoded commands in Windows event logs (SG-WIN-001) via offline string matching.
- **IOC Matching**: Match network flows against IOC IPs (SG-IP-001) and file hashes against IOC hashes (SG-HASH-001).
- **File Integrity Monitoring**: Generate SHA256 baselines (SG-FIM-001) and verify file integrity, detecting modified or missing files (SG-FIM-002).
- **Report Generation**: Output findings in Markdown, JSON, and CSV formats with stable sorting and consistent metadata.
- **Risk Scoring**: Built-in risk scoring model using weighted severity-based evaluation.

### Detection Rules

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

### Supported Data Formats

- CSV: Authentication events, network flows, DNS queries, Windows events, file hashes, IOC indicators
- JSON: Configuration and rule definitions
- Markdown: Human-readable reports with severity indicators and remediation recommendations

### Security Boundaries

SecGuard RS is strictly a **defensive** cybersecurity tool. It:
- Processes only local files
- Performs offline pattern matching
- Generates SHA256 file hashes locally
- Evaluates detection rules against local data
- Does NOT make network connections
- Does NOT scan ports or vulnerabilities
- Does NOT execute payloads or commands
- Does NOT bypass security controls
- Does NOT download threat intelligence

### System Requirements

- Rust 1.70+ (for building from source)
- Windows, macOS, or Linux
- No external database or network services required