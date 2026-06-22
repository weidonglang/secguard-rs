use secguard::errors::SecGuardError;
use secguard::parsers::windows_events::parse_windows_events;
use std::path::PathBuf;

fn testdata_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p
}

#[test]
fn test_windows_parser_valid() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("windows_events.csv");
    let events = parse_windows_events(&p).unwrap();
    assert!(!events.is_empty());
}

#[test]
fn test_windows_parser_empty() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("empty.csv");
    let events = parse_windows_events(&p).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_windows_parser_header_only() {
    let mut p = testdata_path();
    p.push("invalid");
    p.push("header_only_windows.csv");
    let events = parse_windows_events(&p).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_windows_parser_nonexistent() {
    let p = PathBuf::from("does_not_exist.csv");
    let result = parse_windows_events(&p);
    assert!(result.is_err());
    match result.unwrap_err() {
        SecGuardError::FileNotFound(_) => {}
        _ => panic!("expected FileNotFound"),
    }
}

#[test]
fn test_windows_parser_wrong_header() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("auth_events.csv");
    let result = parse_windows_events(&p);
    assert!(result.is_err());
}

#[test]
fn test_windows_parser_suspicious_powershell() {
    let mut p = testdata_path();
    p.push("valid");
    p.push("windows_events.csv");
    let events = parse_windows_events(&p).unwrap();
    // Should contain encoded PowerShell commands
    let encoded: Vec<_> = events
        .iter()
        .filter(|e| {
            let cl = e.command_line.to_lowercase();
            cl.contains("-enc") || cl.contains("-encodedcommand") || cl.contains("frombase64string")
        })
        .collect();
    assert!(!encoded.is_empty());
}
