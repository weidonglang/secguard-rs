use std::path::Path;

use crate::errors::{SecGuardError, SecGuardResult};
use crate::models::NetworkFlow;
use crate::time_utils::parse_utc_timestamp;
use crate::validation::{validate_csv_headers, NETWORK_FLOWS_HEADER};

/// Parse network flow logs from a CSV file with strict header validation.
///
/// Returns an error if:
/// - The file does not exist
/// - The CSV headers do not exactly match the expected schema
/// - Any u64 field is not a valid integer
pub fn parse_network_flows(path: &Path) -> SecGuardResult<Vec<NetworkFlow>> {
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

    validate_csv_headers(&headers, NETWORK_FLOWS_HEADER)?;

    let mut flows = Vec::new();

    for result in reader.records() {
        let record = result.map_err(SecGuardError::Csv)?;

        if record.len() < NETWORK_FLOWS_HEADER.len() {
            return Err(SecGuardError::Msg(format!(
                "row has {} columns, expected {}",
                record.len(),
                NETWORK_FLOWS_HEADER.len()
            )));
        }

        let flow = NetworkFlow {
            flow_id: record[0].to_string(),
            timestamp: parse_utc_timestamp(&record[1])?,
            src_host: record[2].to_string(),
            src_ip: record[3].to_string(),
            src_port: record[4]
                .parse::<u16>()
                .map_err(|e| SecGuardError::Msg(format!("invalid src_port: {}", e)))?,
            dst_ip: record[5].to_string(),
            dst_port: record[6]
                .parse::<u16>()
                .map_err(|e| SecGuardError::Msg(format!("invalid dst_port: {}", e)))?,
            protocol: record[7].to_string(),
            bytes_out: record[8]
                .parse::<u64>()
                .map_err(|e| SecGuardError::Msg(format!("invalid bytes_out: {}", e)))?,
            bytes_in: record[9]
                .parse::<u64>()
                .map_err(|e| SecGuardError::Msg(format!("invalid bytes_in: {}", e)))?,
            action: record[10].to_string(),
            process: record[11].to_string(),
        };

        flows.push(flow);
    }

    Ok(flows)
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
    fn test_parse_valid_network_flows() {
        let mut p = testdata_path();
        p.push("valid");
        p.push("network_flows.csv");
        let result = parse_network_flows(&p);
        assert!(result.is_ok());
        let flows = result.unwrap();
        assert!(!flows.is_empty());
        assert_eq!(flows[0].flow_id, "NF001");
    }

    #[test]
    fn test_parse_empty_file() {
        let mut p = testdata_path();
        p.push("invalid");
        p.push("empty.csv");
        let result = parse_network_flows(&p);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let p = PathBuf::from("nonexistent.csv");
        let result = parse_network_flows(&p);
        assert!(result.is_err());
    }
}
