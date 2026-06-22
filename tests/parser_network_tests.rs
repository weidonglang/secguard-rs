use secguard::errors::SecGuardError;
use secguard::parsers::network_flows::parse_network_flows;
use std::path::PathBuf;

fn testdata_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p
}

#[test]
fn test_network_parser_valid() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("network_flows.csv");
    let flows = parse_network_flows(&p).unwrap();
    assert!(!flows.is_empty());
    assert_eq!(flows[0].flow_id, "NF001");
    assert!(flows[0].bytes_out > 0);
}

#[test]
fn test_network_parser_empty() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("empty.csv");
    let flows = parse_network_flows(&p).unwrap();
    assert!(flows.is_empty());
}

#[test]
fn test_network_parser_header_only() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("header_only_network.csv");
    let flows = parse_network_flows(&p).unwrap();
    assert!(flows.is_empty());
}

#[test]
fn test_network_parser_bad_integer() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("bad_integer.csv");
    let result = parse_network_flows(&p);
    assert!(result.is_err());
}

#[test]
fn test_network_parser_nonexistent() {
    let p = PathBuf::from("does_not_exist.csv");
    let result = parse_network_flows(&p);
    assert!(result.is_err());
    match result.unwrap_err() {
        SecGuardError::FileNotFound(_) => {}
        _ => panic!("expected FileNotFound"),
    }
}

#[test]
fn test_network_parser_wrong_header() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("auth_events.csv");
    let result = parse_network_flows(&p);
    assert!(result.is_err());
}

#[test]
fn test_network_parser_long_line() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("long_line.csv");
    let result = parse_network_flows(&p);
    // The csv crate handles long lines gracefully; should parse successfully
    assert!(result.is_ok());
}

#[test]
fn test_network_large_bytes_out() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("network_flows.csv");
    let flows = parse_network_flows(&p).unwrap();
    // Find flows with large egress
    let large: Vec<_> = flows
        .iter()
        .filter(|f| f.bytes_out >= 100_000_000)
        .collect();
    assert!(!large.is_empty());
}
