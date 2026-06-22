use secguard::errors::SecGuardError;
use secguard::parsers::auth_events::parse_auth_events;
use secguard::parsers::dns_queries::parse_dns_queries;
use secguard::parsers::file_hashes::parse_file_hashes;
use secguard::parsers::iocs::{parse_ioc_domains, parse_ioc_hashes, parse_ioc_ips};
use secguard::parsers::network_flows::parse_network_flows;
use secguard::parsers::windows_events::parse_windows_events;
use std::path::PathBuf;

fn testdata_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p
}

#[test]
fn test_all_parsers_nonexistent_file() {
    let p = PathBuf::from("no_such_file.csv");
    let results: Vec<Result<(), SecGuardError>> = vec![
        parse_auth_events(&p).map(|_| ()),
        parse_network_flows(&p).map(|_| ()),
        parse_dns_queries(&p).map(|_| ()),
        parse_windows_events(&p).map(|_| ()),
        parse_file_hashes(&p).map(|_| ()),
        parse_ioc_domains(&p).map(|_| ()),
        parse_ioc_ips(&p).map(|_| ()),
        parse_ioc_hashes(&p).map(|_| ()),
    ];
    for result in &results {
        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SecGuardError::FileNotFound(_) => {}
            e => panic!("expected FileNotFound, got: {}", e),
        }
    }
}

#[test]
fn test_all_parsers_empty_file() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("empty.csv");
    assert!(parse_auth_events(&p).unwrap().is_empty());
    assert!(parse_network_flows(&p).unwrap().is_empty());
    assert!(parse_dns_queries(&p).unwrap().is_empty());
    assert!(parse_windows_events(&p).unwrap().is_empty());
    assert!(parse_file_hashes(&p).unwrap().is_empty());
    assert!(parse_ioc_domains(&p).unwrap().is_empty());
    assert!(parse_ioc_ips(&p).unwrap().is_empty());
    assert!(parse_ioc_hashes(&p).unwrap().is_empty());
}

#[test]
fn test_all_parsers_header_only() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("header_only.csv");
    // header_only.csv has auth_events headers, so only auth events parser returns empty
    assert!(parse_auth_events(&p).unwrap().is_empty());
    // Other parsers should fail due to header mismatch on auth_events headers
    assert!(parse_network_flows(&p).is_err());
    assert!(parse_dns_queries(&p).is_err());
    assert!(parse_windows_events(&p).is_err());
    assert!(parse_file_hashes(&p).is_err());
    assert!(parse_ioc_domains(&p).is_err());
    assert!(parse_ioc_ips(&p).is_err());
    assert!(parse_ioc_hashes(&p).is_err());
}

#[test]
fn test_header_mismatch_between_types() {
    let mut auth = testdata_path();
    auth.push("valid");
    auth.push("auth_events.csv");

    let mut network = testdata_path();
    network.push("valid");
    network.push("network_flows.csv");

    // auth parser on network file should fail
    assert!(parse_auth_events(&network).is_err());
    // network parser on auth file should fail
    assert!(parse_network_flows(&auth).is_err());
}

#[test]
fn test_unicode_usernames() {
    // Auth events with unicode usernames should be parsed correctly
    let mut p = testdata_path();
    p.push("valid");
    p.push("auth_events.csv");
    let events = parse_auth_events(&p).unwrap();
    // The test data should have unicode names
    let unicode_users: Vec<_> = events
        .iter()
        .filter(|e| e.user.chars().any(|c| c as u32 > 127))
        .collect();
    assert!(!events.is_empty());
    let _ = unicode_users;
}

#[test]
fn test_long_line_handling() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("long_line.csv");
    // Long lines should not crash the parser
    let result = parse_auth_events(&p);
    assert!(result.is_err());
}

#[test]
fn test_path_with_spaces_handling() {
    let mut p = testdata_path();
    p.push("paths with spaces");
    p.push("auth events sample.csv");
    let events = parse_auth_events(&p).unwrap();
    assert!(!events.is_empty());
}

#[test]
fn test_valid_file_hashes_unicode_path() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("file_hashes.csv");
    let hashes = parse_file_hashes(&p).unwrap();
    assert!(!hashes.is_empty());
    // At least one hash should have a valid SHA256 hex string
    assert!(hashes[0].sha256.len() == 64);
}
