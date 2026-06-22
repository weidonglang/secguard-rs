use secguard::errors::SecGuardError;
use secguard::parsers::dns_queries::parse_dns_queries;
use std::path::PathBuf;

fn testdata_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p
}

#[test]
fn test_dns_parser_valid() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("dns_queries.csv");
    let queries = parse_dns_queries(&p).unwrap();
    assert!(!queries.is_empty());
    assert_eq!(queries[0].query_id, "DNS001");
}

#[test]
fn test_dns_parser_empty() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("empty.csv");
    let queries = parse_dns_queries(&p).unwrap();
    assert!(queries.is_empty());
}

#[test]
fn test_dns_parser_header_only() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("header_only_dns.csv");
    let queries = parse_dns_queries(&p).unwrap();
    assert!(queries.is_empty());
}

#[test]
fn test_dns_parser_nonexistent() {
    let p = PathBuf::from("does_not_exist.csv");
    let result = parse_dns_queries(&p);
    assert!(result.is_err());
    match result.unwrap_err() {
        SecGuardError::FileNotFound(_) => {}
        _ => panic!("expected FileNotFound"),
    }
}

#[test]
fn test_dns_parser_wrong_header() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("auth_events.csv");
    let result = parse_dns_queries(&p);
    assert!(result.is_err());
}

#[test]
fn test_dns_parser_bad_timestamp() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("bad_timestamp.csv");
    let result = parse_dns_queries(&p);
    assert!(result.is_err());
}

#[test]
fn test_dns_ioc_matchable_queries() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("dns_queries.csv");
    let queries = parse_dns_queries(&p).unwrap();
    // Should contain evil.example.com queries for IOC testing
    let evil: Vec<_> = queries
        .iter()
        .filter(|q| q.query.contains("evil"))
        .collect();
    assert!(!evil.is_empty());
}
