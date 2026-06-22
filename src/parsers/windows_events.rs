use std::path::Path;

use crate::errors::{SecGuardError, SecGuardResult};
use crate::models::WindowsEvent;
use crate::time_utils::parse_utc_timestamp;
use crate::validation::{validate_csv_headers, WINDOWS_EVENTS_HEADER};

/// Parse Windows events from a CSV file with strict header validation.
///
/// Returns an error if:
/// - The file does not exist
/// - The CSV headers do not exactly match the expected schema
pub fn parse_windows_events(path: &Path) -> SecGuardResult<Vec<WindowsEvent>> {
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

    validate_csv_headers(&headers, WINDOWS_EVENTS_HEADER)?;

    let mut events = Vec::new();

    for result in reader.records() {
        let record = result.map_err(SecGuardError::Csv)?;

        if record.len() < WINDOWS_EVENTS_HEADER.len() {
            return Err(SecGuardError::Msg(format!(
                "row has {} columns, expected {}",
                record.len(),
                WINDOWS_EVENTS_HEADER.len()
            )));
        }

        let event = WindowsEvent {
            event_id: record[0].to_string(),
            timestamp: parse_utc_timestamp(&record[1])?,
            host: record[2].to_string(),
            provider: record[3].to_string(),
            user: record[4].to_string(),
            process: record[5].to_string(),
            parent_process: record[6].to_string(),
            command_line: record[7].to_string(),
            status: record[8].to_string(),
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
    fn test_parse_valid_windows_events() {
        let mut p = testdata_path();
        p.push("valid");
        p.push("windows_events.csv");
        let result = parse_windows_events(&p);
        assert!(result.is_ok());
        let events = result.unwrap();
        assert!(!events.is_empty());
        assert_eq!(events[0].event_id, "WE001");
    }

    #[test]
    fn test_parse_empty_file() {
        let mut p = testdata_path();
        p.push("invalid");
        p.push("empty.csv");
        let result = parse_windows_events(&p);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let p = PathBuf::from("nonexistent.csv");
        let result = parse_windows_events(&p);
        assert!(result.is_err());
    }
}
