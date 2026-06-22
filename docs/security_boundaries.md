# Security Boundaries

## Project Mandate

SecGuard RS is a **strictly defensive** cybersecurity tool. It is designed for offline, local-file-based security log analysis, IOC matching, file integrity verification, and report generation. It must never be used for offensive security operations.

## Permitted Operations

The following operations are explicitly permitted:

- Parsing local CSV, JSON, and plain text files
- CSV schema validation against predefined data dictionaries
- Local pattern matching for threat detection rules
- Local SHA-256 file hashing for integrity baselines
- Comparing file hashes against known-good baselines
- Matching DNS queries against local IOC domain lists
- Matching IP addresses against local IOC IP lists
- Matching file hashes against local IOC hash lists
- Brute force login attempt detection from auth logs
- Password spray detection from auth logs
- Suspicious PowerShell command detection from Windows event logs
- Outbound blocked connection burst detection from network logs
- High data egress detection from network logs
- Risk scoring based on detection severity
- Output of findings in Markdown, JSON, and CSV formats
- Local evaluation of built-in detection rules

## Prohibited Operations

The following operations are explicitly prohibited and **must never be implemented**:

- Port scanning or network reconnaissance
- Vulnerability scanning against remote targets
- Password cracking or brute forcing against live systems
- Exploit proof-of-concept or demonstration code
- Trojan, backdoor, or persistence mechanisms
- Credential theft or dumping
- Antivirus, EDR, or logging bypass techniques
- Lateral movement tools or techniques
- Command execution payloads of any kind
- Network connections to real third-party targets
- Automatic download of threat intelligence from the internet
- Any use of `std::net`, `TcpStream`, `UdpSocket`, `reqwest`, `hyper`, `tokio::net`

## Code Restrictions

1. No dependency on `reqwest`, `hyper`, `tokio`, `ureq`, `surf`, or `socket2`
2. No use of `std::net`, `TcpStream`, `UdpSocket`, or `tokio::net`
3. All data processing must be offline and local
4. All file paths must be passed explicitly by the user (no default targets)
5. Detection evidence must be limited to log excerpts; no generated attack payloads

## Enforcement

Before each commit, the following must be verified:

1. Run `scripts/check_no_network_code.ps1` to scan for prohibited dependencies and imports
2. Run `scripts/run_all_tests.ps1` to ensure all tests pass
3. Code review to confirm no offensive functionality was introduced

## Liability

This tool is provided as-is for defensive security education and authorized testing. Misuse for unauthorized access or attacks is prohibited and the responsibility of the user.