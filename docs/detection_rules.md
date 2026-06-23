# Detection Rules (v1.0.0)

## Overview

SecGuard RS includes 10 built-in detection rules covering authentication, Windows events, network traffic, DNS, IOC matching, and file integrity monitoring.

## Rule Format

Each detection produces a finding with the following fields:

| Field          | Description                                      |
|----------------|--------------------------------------------------|
| detection_id   | Stable unique ID (e.g., `SG-AUTH-001-0001`)      |
| timestamp      | UTC timestamp from source event                   |
| rule_id        | Rule identifier (e.g., `SG-AUTH-001`)             |
| severity       | info/low/medium/high/critical                     |
| entity         | Subject of detection (user, host, IP, path)       |
| summary        | Human-readable summary                            |
| evidence       | Supporting log evidence (truncated)               |
| recommendation | Remediation guidance                              |

## Severity Levels

| Level    | Weight | Description                        |
|----------|--------|------------------------------------|
| info     | 1      | Informational, no action required  |
| low      | 2      | Minor concern, review recommended  |
| medium   | 4      | Moderate risk, investigate          |
| high     | 7      | Significant risk, take action       |
| critical | 10     | Critical, immediate response needed |

## Detection Rules

### SG-AUTH-001: Brute Force Login

- **Category:** Authentication
- **Severity:** high
- **Data Source:** auth_events.csv

Detects multiple failed login attempts from the same source IP and user within a configurable time window (default: 10 minutes). Threshold: 5 failed attempts.

**Recommendation:** Lock account temporarily, review source IP, enforce MFA.

### SG-AUTH-002: Password Spray

- **Category:** Authentication
- **Severity:** high
- **Data Source:** auth_events.csv

Detects a single source IP attempting logins against multiple different users within a time window. Threshold: 5 distinct users.

**Recommendation:** Block source IP, investigate authentication logs, enforce rate limiting.

### SG-WIN-001: Suspicious PowerShell Encoded Command

- **Category:** Windows Events
- **Severity:** high
- **Data Source:** windows_events.csv

Detects PowerShell commands containing encoded command patterns: `-enc`, `-encodedcommand`, `frombase64string` (case-insensitive match on command_line field).

**Note:** This rule performs log string matching only. It does NOT decode, execute, or generate payloads.

**Recommendation:** Investigate the process ancestry, review for legitimate administrative use.

### SG-NET-001: Blocked Outbound Burst

- **Category:** Network
- **Severity:** medium
- **Data Source:** network_flows.csv

Detects a high volume of blocked/denied outbound connections from a single source host within a time window (default: 15 minutes). Threshold: 10 blocked events.

**Recommendation:** Review host for malware or unauthorized outbound traffic.

### SG-NET-002: High Data Egress

- **Category:** Network
- **Severity:** medium
- **Data Source:** network_flows.csv

Detects network flows where `bytes_out` exceeds 100,000,000 (100 MB).

**Recommendation:** Review destination and process for data exfiltration indicators.

### SG-DNS-001: IOC Domain Match

- **Category:** DNS
- **Severity:** high
- **Data Source:** dns_queries.csv, ioc_domains.csv

Matches DNS query domains against a local IOC domain list. Matching is case-insensitive.

**Recommendation:** Block domain, investigate host for malware.

### SG-IP-001: IOC IP Match

- **Category:** Network
- **Severity:** high
- **Data Source:** network_flows.csv, ioc_ips.csv

Matches destination IP addresses against a local IOC IP list. Matching is exact.

**Recommendation:** Block IP address, investigate associated traffic.

### SG-HASH-001: IOC Hash Match

- **Category:** Integrity
- **Severity:** critical
- **Data Source:** file_hashes.csv, ioc_hashes.csv

Matches file SHA256 hashes against a local IOC hash list. Matching is exact.

**Recommendation:** Quarantine affected files immediately.

### SG-FIM-001: File Modified

- **Category:** Integrity
- **Severity:** medium
- **Data Source:** File Integrity Baseline

Detects files whose current SHA256 hash differs from the baseline snapshot.

**Recommendation:** Review file changes, verify with change management.

### SG-FIM-002: File Missing

- **Category:** Integrity
- **Severity:** high
- **Data Source:** File Integrity Baseline

Detects files present in the baseline but missing from the current filesystem path.

**Recommendation:** Investigate file deletion, restore from backup if needed.

## Risk Scoring

Risk score is computed as:

```
risk_score = min(sum(weight * count per severity), 100)
```

Risk score is capped at a maximum of 100.