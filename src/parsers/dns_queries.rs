use std::path::Path;

use crate::errors::{SecGuardError, SecGuardResult};
use crate::models::DnsQuery;
use crate::time_utils::parse_utc_timestamp;
use crate::validation::{validate_csv_headers, DNS_QUERIES_HEADER};

/// Parse DNS queries from a CSV file with strict header validation.
///
/// Returns an error if:
/// - The file does not exist
/// - The CSV headers do not exactly match the expected schema
pub fn parse_dns_queries(path: &Path) -> SecGuardResult<Vec<DnsQuery>> {
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

    validate_csv_headers(&headers, DNS_QUERIES_HEADER)?;

    let mut queries = Vec::new();

    for result in reader.records() {
        let record = result.map_err(SecGuardError::Csv)?;

        if record.len() < DNS_QUERIES_HEADER.len() {
            return Err(SecGuardError::Msg(format!(
                "row has {} columns, expected {}",
                record.len(),
                DNS_QUERIES_HEADER.len()
            )));
        }

        let query = DnsQuery {
            query_id: record[0].to_string(),
            timestamp: parse_utc_timestamp(&record[1])?,
            host: record[2].to_string(),
            user: record[3].to_string(),
            query: record[4].to_string(),
            record_type: record[5].to_string(),
            response: record[6].to_string(),
            rcode: record[7].to_string(),
        };

        queries.push(query);
    }

    Ok(queries)
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
    fn test_parse_valid_dns_queries() {
        let mut p = testdata_path();
        p.push("valid");
        p.push("dns_queries.csv");
        let result = parse_dns_queries(&p);
        assert!(result.is_ok());
        let queries = result.unwrap();
        assert!(!queries.is_empty());
        assert_eq!(queries[0].query_id, "DNS001");
    }

    #[test]
    fn test_parse_empty_file() {
        let mut p = testdata_path();
        p.push("invalid");
        p.push("empty.csv");
        let result = parse_dns_queries(&p);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let p = PathBuf::from("nonexistent.csv");
        let result = parse_dns_queries(&p);
        assert!(result.is_err());
    }
}
