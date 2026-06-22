use std::path::Path;

use crate::errors::{SecGuardError, SecGuardResult};
use crate::models::AuthEvent;
use crate::time_utils::parse_utc_timestamp;
use crate::validation::{validate_csv_headers, AUTH_EVENTS_HEADER};

/// Parse authentication events from a CSV file with strict header validation.
///
/// Returns an error if:
/// - The file does not exist
/// - The CSV headers do not exactly match the expected schema
/// - Any timestamp field is not valid UTC
pub fn parse_auth_events(path: &Path) -> SecGuardResult<Vec<AuthEvent>> {
    if !path.exists() {
        return Err(SecGuardError::FileNotFound(path.to_path_buf()));
    }

    // Check for empty file
    let metadata = std::fs::metadata(path)?;
    if metadata.len() == 0 {
        return Ok(Vec::new());
    }

    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .flexible(false)
        .from_path(path)?;

    let headers: Vec<String> = reader.headers()?.iter().map(|h| h.to_string()).collect();

    validate_csv_headers(&headers, AUTH_EVENTS_HEADER)?;

    let mut events = Vec::new();

    for result in reader.records() {
        let record = result.map_err(SecGuardError::Csv)?;

        if record.len() < AUTH_EVENTS_HEADER.len() {
            return Err(SecGuardError::Msg(format!(
                "row has {} columns, expected {}",
                record.len(),
                AUTH_EVENTS_HEADER.len()
            )));
        }

        let event = AuthEvent {
            event_id: record[0].to_string(),
            timestamp: parse_utc_timestamp(&record[1])?,
            source_host: record[2].to_string(),
            user: record[3].to_string(),
            source_ip: record[4].to_string(),
            action: record[5].to_string(),
            auth_method: record[6].to_string(),
            status: record[7].to_string(),
            reason: record[8].to_string(),
        };

        events.push(event);
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn testdata_path() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("testdata");
        p
    }

    #[test]
    fn test_parse_valid_auth_events() {
        let mut p = testdata_path();
        p.push("valid");
        p.push("auth_events.csv");
        let result = parse_auth_events(&p);
        assert!(result.is_ok());
        let events = result.unwrap();
        assert!(!events.is_empty());
        assert_eq!(events[0].event_id, "AUTH001");
    }

    #[test]
    fn test_parse_empty_file() {
        let mut p = testdata_path();
        p.push("invalid");
        p.push("empty.csv");
        let result = parse_auth_events(&p);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_header_only() {
        let mut p = testdata_path();
        p.push("invalid");
        p.push("header_only.csv");
        let result = parse_auth_events(&p);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_missing_columns() {
        let mut p = testdata_path();
        p.push("invalid");
        p.push("missing_columns_auth.csv");
        let result = parse_auth_events(&p);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bad_timestamp() {
        let mut p = testdata_path();
        p.push("invalid");
        p.push("bad_timestamp.csv");
        let result = parse_auth_events(&p);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_long_line() {
        let mut p = testdata_path();
        p.push("invalid");
        p.push("long_line.csv");
        let result = parse_auth_events(&p);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_with_spaces() {
        let mut p = testdata_path();
        p.push("paths with spaces");
        p.push("auth events sample.csv");
        let result = parse_auth_events(&p);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let p = PathBuf::from("nonexistent_file.csv");
        let result = parse_auth_events(&p);
        assert!(result.is_err());
        match result.unwrap_err() {
            SecGuardError::FileNotFound(_) => {}
            _ => panic!("expected FileNotFound error"),
        }
    }
}
