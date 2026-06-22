use crate::errors::{SecGuardError, SecGuardResult};

/// Expected CSV headers for auth events.
pub const AUTH_EVENTS_HEADER: &[&str] = &[
    "event_id",
    "timestamp",
    "source_host",
    "user",
    "source_ip",
    "action",
    "auth_method",
    "status",
    "reason",
];

/// Expected CSV headers for network flows.
pub const NETWORK_FLOWS_HEADER: &[&str] = &[
    "flow_id",
    "timestamp",
    "src_host",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "bytes_out",
    "bytes_in",
    "action",
    "process",
];

/// Expected CSV headers for DNS queries.
pub const DNS_QUERIES_HEADER: &[&str] = &[
    "query_id",
    "timestamp",
    "host",
    "user",
    "query",
    "record_type",
    "response",
    "rcode",
];

/// Expected CSV headers for Windows events.
pub const WINDOWS_EVENTS_HEADER: &[&str] = &[
    "event_id",
    "timestamp",
    "host",
    "provider",
    "user",
    "process",
    "parent_process",
    "command_line",
    "status",
];

/// Expected CSV headers for file hashes.
pub const FILE_HASHES_HEADER: &[&str] = &["path", "sha256", "size_bytes", "modified_utc"];

/// Expected CSV headers for IOC domains.
pub const IOC_DOMAINS_HEADER: &[&str] = &["indicator", "severity", "description"];

/// Expected CSV headers for IOC IPs.
pub const IOC_IPS_HEADER: &[&str] = &["indicator", "severity", "description"];

/// Expected CSV headers for IOC hashes.
pub const IOC_HASHES_HEADER: &[&str] = &["sha256", "severity", "description"];

/// Expected CSV headers for detection output.
pub const DETECTIONS_HEADER: &[&str] = &[
    "detection_id",
    "timestamp",
    "rule_id",
    "severity",
    "entity",
    "summary",
    "evidence",
    "recommendation",
];

/// Validate CSV headers match expected.
pub fn validate_csv_headers(actual: &[String], expected: &[&str]) -> SecGuardResult<()> {
    let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    if actual != exp.as_slice() {
        return Err(SecGuardError::CsvHeaderMismatch {
            expected: exp,
            actual: actual.to_vec(),
        });
    }
    Ok(())
}

/// Check if a string is an allowed status value.
pub fn is_valid_status(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "success" | "failure")
}

/// Check if a string is an allowed action for auth events.
pub fn is_valid_auth_action(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "login" | "logout" | "password_change" | "privilege_use"
    )
}

/// Check if a string is an allowed auth method.
pub fn is_valid_auth_method(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "password" | "mfa" | "token" | "ssh_key"
    )
}

/// Check if a string is an allowed failure reason.
pub fn is_valid_failure_reason(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "success" | "bad_password" | "locked" | "unknown_user" | "mfa_failed"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_csv_headers_match() {
        let actual = vec![
            "event_id".to_string(),
            "timestamp".to_string(),
            "source_host".to_string(),
        ];
        let expected = &["event_id", "timestamp", "source_host"];
        assert!(validate_csv_headers(&actual, expected).is_ok());
    }

    #[test]
    fn test_validate_csv_headers_mismatch() {
        let actual = vec![
            "event_id".to_string(),
            "timestamp".to_string(),
            "wrong_field".to_string(),
        ];
        let expected = &["event_id", "timestamp", "source_host"];
        assert!(validate_csv_headers(&actual, expected).is_err());
    }

    #[test]
    fn test_validate_csv_headers_extra_column() {
        let actual = vec![
            "event_id".to_string(),
            "timestamp".to_string(),
            "source_host".to_string(),
            "extra".to_string(),
        ];
        let expected = &["event_id", "timestamp", "source_host"];
        assert!(validate_csv_headers(&actual, expected).is_err());
    }

    #[test]
    fn test_valid_status() {
        assert!(is_valid_status("success"));
        assert!(is_valid_status("failure"));
        assert!(is_valid_status("SUCCESS"));
        assert!(!is_valid_status("unknown"));
    }

    #[test]
    fn test_valid_auth_action() {
        assert!(is_valid_auth_action("login"));
        assert!(is_valid_auth_action("logout"));
        assert!(is_valid_auth_action("password_change"));
        assert!(is_valid_auth_action("privilege_use"));
        assert!(!is_valid_auth_action("delete"));
    }
}
