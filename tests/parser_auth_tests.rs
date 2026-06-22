use secguard::errors::SecGuardError;
use secguard::parsers::auth_events::parse_auth_events;
use std::path::PathBuf;

fn testdata_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p
}

#[test]
fn test_auth_parser_valid() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("auth_events.csv");
    let events = parse_auth_events(&p).unwrap();
    assert!(!events.is_empty());
    // Verify first event
    assert_eq!(events[0].event_id, "AUTH001");
    assert_eq!(events[0].action, "login");
    assert_eq!(events[0].status, "success");
}

#[test]
fn test_auth_parser_empty() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("empty.csv");
    let events = parse_auth_events(&p).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_auth_parser_header_only() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("header_only.csv");
    let events = parse_auth_events(&p).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_auth_parser_missing_columns() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("missing_columns_auth.csv");
    let result = parse_auth_events(&p);
    assert!(result.is_err());
    match result.unwrap_err() {
        SecGuardError::CsvHeaderMismatch { .. } => {}
        e => panic!("expected CsvHeaderMismatch error, got: {}", e),
    }
}

#[test]
fn test_auth_parser_bad_timestamp() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("bad_timestamp.csv");
    let result = parse_auth_events(&p);
    assert!(result.is_err());
}

#[test]
fn test_auth_parser_nonexistent() {
    let p = PathBuf::from("does_not_exist.csv");
    let result = parse_auth_events(&p);
    assert!(result.is_err());
    match result.unwrap_err() {
        SecGuardError::FileNotFound(_) => {}
        _ => panic!("expected FileNotFound"),
    }
}

#[test]
fn test_auth_parser_path_with_spaces() {
    let mut p = testdata_path();
    p.push("paths with spaces");
    p.push("auth events sample.csv");
    let events = parse_auth_events(&p).unwrap();
    assert!(!events.is_empty());
}

#[test]
fn test_auth_parser_wrong_header() {
    // Try parsing a network flow file as auth events
    let mut p = testdata_path();
    p.push("valid");
    p.push("network_flows.csv");
    let result = parse_auth_events(&p);
    assert!(result.is_err());
}
