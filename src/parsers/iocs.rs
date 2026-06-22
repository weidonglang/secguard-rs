use std::path::Path;

use crate::errors::{SecGuardError, SecGuardResult};
use crate::models::{IocDomain, IocHash, IocIp};
use crate::validation::{
    validate_csv_headers, IOC_DOMAINS_HEADER, IOC_HASHES_HEADER, IOC_IPS_HEADER,
};

/// Parse IOC domains from a CSV file.
///
/// Returns an error if:
/// - The file does not exist
/// - The CSV headers do not match `ioc_domains.csv` schema
pub fn parse_ioc_domains(path: &Path) -> SecGuardResult<Vec<IocDomain>> {
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

    validate_csv_headers(&headers, IOC_DOMAINS_HEADER)?;

    let mut domains = Vec::new();

    for result in reader.records() {
        let record = result.map_err(SecGuardError::Csv)?;
        domains.push(IocDomain {
            indicator: record[0].to_string(),
            severity: record[1].to_string(),
            description: record[2].to_string(),
        });
    }

    Ok(domains)
}

/// Parse IOC IPs from a CSV file.
pub fn parse_ioc_ips(path: &Path) -> SecGuardResult<Vec<IocIp>> {
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

    validate_csv_headers(&headers, IOC_IPS_HEADER)?;

    let mut ips = Vec::new();

    for result in reader.records() {
        let record = result.map_err(SecGuardError::Csv)?;
        ips.push(IocIp {
            indicator: record[0].to_string(),
            severity: record[1].to_string(),
            description: record[2].to_string(),
        });
    }

    Ok(ips)
}

/// Parse IOC hashes from a CSV file.
pub fn parse_ioc_hashes(path: &Path) -> SecGuardResult<Vec<IocHash>> {
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

    validate_csv_headers(&headers, IOC_HASHES_HEADER)?;

    let mut hashes = Vec::new();

    for result in reader.records() {
        let record = result.map_err(SecGuardError::Csv)?;
        hashes.push(IocHash {
            sha256: record[0].to_string(),
            severity: record[1].to_string(),
            description: record[2].to_string(),
        });
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
    fn test_parse_valid_ioc_domains() {
        let mut p = testdata_path();
        p.push("valid");
        p.push("ioc_domains.csv");
        let result = parse_ioc_domains(&p);
        assert!(result.is_ok());
        let domains = result.unwrap();
        assert!(!domains.is_empty());
    }

    #[test]
    fn test_parse_valid_ioc_ips() {
        let mut p = testdata_path();
        p.push("valid");
        p.push("ioc_ips.csv");
        let result = parse_ioc_ips(&p);
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
    }

    #[test]
    fn test_parse_valid_ioc_hashes() {
        let mut p = testdata_path();
        p.push("valid");
        p.push("ioc_hashes.csv");
        let result = parse_ioc_hashes(&p);
        assert!(result.is_ok());
        let hashes = result.unwrap();
        assert!(!hashes.is_empty());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let p = PathBuf::from("nonexistent.csv");
        let result = parse_ioc_domains(&p);
        assert!(result.is_err());
    }
}
