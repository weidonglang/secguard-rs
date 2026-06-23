# Data Dictionary (v1.0.0)

## Global Schema Reference

All CSV files in SecGuard RS follow strict schemas. Fields are case-sensitive and must appear in the exact order specified below.

## Auth Events (`auth_events.csv`)

| Field | Type | Description |
|-------|------|-------------|
| event_id | String | Log event unique identifier |
| timestamp | DateTime (UTC) | ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` |
| source_host | String | Hostname where event originated |
| user | String | Username involved in the event |
| source_ip | String | Source IP address (IPv4 or IPv6) |
| action | String | One of: `login`, `logout`, `password_change`, `privilege_use` |
| auth_method | String | One of: `password`, `mfa`, `token`, `ssh_key` |
| status | String | One of: `success`, `failure` |
| reason | String | One of: `success`, `bad_password`, `locked`, `unknown_user`, `mfa_failed` |

## Network Flows (`network_flows.csv`)

| Field | Type | Description |
|-------|------|-------------|
| flow_id | String | Flow record unique identifier |
| timestamp | DateTime (UTC) | ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` |
| src_host | String | Source hostname |
| src_ip | String | Source IP address |
| src_port | Integer (u16) | Source port number |
| dst_ip | String | Destination IP address |
| dst_port | Integer (u16) | Destination port number |
| protocol | String | Transport protocol: `TCP`, `UDP`, `ICMP` |
| bytes_out | Integer (u64) | Bytes sent from source to destination |
| bytes_in | Integer (u64) | Bytes received from destination to source |
| action | String | Firewall action: `allow`, `block`, `deny`, `drop` |
| process | String | Process name that initiated the connection |

## DNS Queries (`dns_queries.csv`)

| Field | Type | Description |
|-------|------|-------------|
| query_id | String | Query unique identifier |
| timestamp | DateTime (UTC) | ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` |
| host | String | Hostname that made the query |
| user | String | Username associated with the query |
| query | String | Domain being queried (fully qualified) |
| record_type | String | DNS record type: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `PTR` |
| response | String | DNS response (IP address or domain alias) |
| rcode | String | DNS response code: `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED` |

## Windows Events (`windows_events.csv`)

| Field | Type | Description |
|-------|------|-------------|
| event_id | String | Windows Event Log event ID |
| timestamp | DateTime (UTC) | ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` |
| host | String | Hostname where event occurred |
| provider | String | Event provider name (e.g., `Microsoft-Windows-Security-Auditing`) |
| user | String | Username associated with the event |
| process | String | Process name that triggered the event |
| parent_process | String | Parent process name |
| command_line | String | Full command line (may contain encoded content) |
| status | String | Event status: `success`, `failure`, `warning`, `information` |

## File Hashes (`file_hashes.csv`)

| Field | Type | Description |
|-------|------|-------------|
| path | String | Absolute or relative file path |
| sha256 | String | SHA-256 hex digest (64 lowercase hex characters) |
| size_bytes | Integer (u64) | File size in bytes |
| modified_utc | DateTime (UTC) | Last modified timestamp in ISO 8601 format |

## IOC Domains (`ioc_domains.csv`)

| Field | Type | Description |
|-------|------|-------------|
| indicator | String | Malicious domain name |
| severity | String | Severity: `info`, `low`, `medium`, `high`, `critical` |
| description | String | Context about the indicator |

## IOC IPs (`ioc_ips.csv`)

| Field | Type | Description |
|-------|------|-------------|
| indicator | String | Malicious IP address |
| severity | String | Severity: `info`, `low`, `medium`, `high`, `critical` |
| description | String | Context about the indicator |

## IOC Hashes (`ioc_hashes.csv`)

| Field | Type | Description |
|-------|------|-------------|
| sha256 | String | Malicious file SHA-256 hash |
| severity | String | Severity: `info`, `low`, `medium`, `high`, `critical` |
| description | String | Context about the indicator |

## Detection Findings (`detections.csv` output)

| Field | Type | Description |
|-------|------|-------------|
| detection_id | String | Stable detection identifier (rule-based) |
| timestamp | DateTime (UTC) | Detection timestamp |
| rule_id | String | Rule identifier (e.g., `SG-AUTH-001`) |
| severity | String | Severity: `info`, `low`, `medium`, `high`, `critical` |
| entity | String | Affected entity (user, host, IP, file path) |
| summary | String | Human-readable detection summary |
| evidence | String | Supporting evidence excerpt |
| recommendation | String | Remediation recommendation |

## Schema Enforcement Rules

1. All parsers must validate CSV headers match exactly (case-sensitive, field order)
2. Timestamp fields must parse as valid UTC ISO 8601
3. Integer fields must parse as valid unsigned integers
4. Missing columns must produce readable errors
5. Extra columns beyond the schema are tolerated but ignored