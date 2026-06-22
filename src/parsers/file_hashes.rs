use std::path::Path;

use crate::errors::{SecGuardError, SecGuardResult};
use crate::models::FileHash;
use crate::validation::{validate_csv_headers, FILE_HASHES_HEADER};

/// Parse file hashes from a CSV file with strict header validation.
///
/// Returns an error if:
/// - The file does not exist
/// - The CSV headers do not exactly match the expected schema
pub fn parse_file_hashes(path: &Path) -> SecGuardResult<Vec<FileHash>> {
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

    validate_csv_headers(&headers, FILE_HASHES_HEADER)?;

    let mut hashes = Vec::new();

    for result in reader.records() {
        let record = result.map_err(SecGuardError::Csv)?;

        if record.len() < FILE_HASHES_HEADER.len() {
            return Err(SecGuardError::Msg(format!(
                "row has {} columns, expected {}",
                record.len(),
                FILE_HASHES_HEADER.len()
            )));
        }

        let hash = FileHash {
            path: record[0].to_string(),
            sha256: record[1].to_string(),
            size_bytes: record[2]
                .parse::<u64>()
                .map_err(|e| SecGuardError::Msg(format!("invalid size_bytes: {}", e)))?,
            modified_utc: record[3].to_string(),
        };

        hashes.push(hash);
    }

    Ok(hashes)
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
    fn test_parse_valid_file_hashes() {
        let mut p = testdata_path();
        p.push("valid");
        p.push("file_hashes.csv");
        let result = parse_file_hashes(&p);
        assert!(result.is_ok());
        let hashes = result.unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].sha256.len(), 64);
    }

    #[test]
    fn test_parse_empty_file() {
        let mut p = testdata_path();
        p.push("invalid");
        p.push("empty.csv");
        let result = parse_file_hashes(&p);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let p = PathBuf::from("nonexistent.csv");
        let result = parse_file_hashes(&p);
        assert!(result.is_err());
    }
}
