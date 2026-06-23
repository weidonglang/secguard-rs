use crate::detections::engine::DetectionIdGenerator;
use crate::models::{Detection, FileHash, IocHash};

/// Rule ID for IOC hash match detection.
pub const SG_HASH_001: &str = "SG-HASH-001";

/// Detect file hashes matching known malicious hashes (SG-HASH-001).
///
/// Matches are exact SHA256 string matches. Each match generates a severity level
/// based on the IOC severity. Timestamps are taken from the source file hash data.
pub fn detect_hash_ioc(
    file_hashes: &[FileHash],
    ioc_hashes: &[IocHash],
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    if file_hashes.is_empty() || ioc_hashes.is_empty() {
        return Vec::new();
    }

    // Build a set of known malicious hashes for O(1) lookup
    let ioc_hash_set: std::collections::HashMap<&str, &IocHash> = ioc_hashes
        .iter()
        .map(|ioc| (ioc.sha256.as_str(), ioc))
        .collect();

    let mut findings = Vec::new();

    for fh in file_hashes {
        if let Some(ioc) = ioc_hash_set.get(fh.sha256.as_str()) {
            let severity = crate::models::Severity::from_string(&ioc.severity)
                .unwrap_or(crate::models::Severity::Critical);
            // Use source file hash modified_utc as timestamp instead of current system time
            let timestamp = fh.modified_utc.clone();

            findings.push(Detection {
                detection_id: id_gen.generate(SG_HASH_001),
                timestamp,
                rule_id: SG_HASH_001.to_string(),
                severity: severity.as_str().to_string(),
                entity: fh.path.clone(),
                summary: format!(
                    "File hash matches known malicious hash: {}",
                    ioc.sha256
                ),
                evidence: format!(
                    "path={}, sha256={}, size_bytes={}, modified_utc={}, ioc_description={}",
                    fh.path, fh.sha256, fh.size_bytes, fh.modified_utc, ioc.description
                ),
                recommendation: "Quarantine the file, investigate how it was introduced, check for related IOCs.".to_string(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file_hash(path: &str, sha256: &str) -> FileHash {
        FileHash {
            path: path.to_string(),
            sha256: sha256.to_string(),
            size_bytes: 1024,
            modified_utc: "2026-03-05T10:15:30Z".to_string(),
        }
    }

    fn make_ioc(sha256: &str, severity: &str) -> IocHash {
        IocHash {
            sha256: sha256.to_string(),
            severity: severity.to_string(),
            description: "Known malware hash".to_string(),
        }
    }

    #[test]
    fn test_hash_ioc_exact_match() {
        let file_hashes = vec![make_file_hash(
            "/usr/bin/malware.exe",
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        )];
        let iocs = vec![make_ioc(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "critical",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_hash_ioc(&file_hashes, &iocs, &mut id_gen);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].rule_id.contains("SG-HASH-001"));
        assert_eq!(findings[0].severity, "critical");
        // Verify timestamp is from source data, not current time
        assert!(findings[0].timestamp.starts_with("2026-03-05"));
    }

    #[test]
    fn test_hash_ioc_no_match() {
        let file_hashes = vec![make_file_hash(
            "/usr/bin/clean.exe",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )];
        let iocs = vec![make_ioc(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "critical",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_hash_ioc(&file_hashes, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hash_ioc_empty_file_hashes() {
        let file_hashes = vec![];
        let iocs = vec![make_ioc(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "critical",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_hash_ioc(&file_hashes, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hash_ioc_empty_iocs() {
        let file_hashes = vec![make_file_hash(
            "/usr/bin/malware.exe",
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        )];
        let iocs = vec![];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_hash_ioc(&file_hashes, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hash_ioc_multiple_matches() {
        let file_hashes = vec![
            make_file_hash(
                "/usr/bin/malware1.exe",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            make_file_hash(
                "/usr/bin/malware2.exe",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ];
        let iocs = vec![
            make_ioc(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "critical",
            ),
            make_ioc(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "high",
            ),
        ];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_hash_ioc(&file_hashes, &iocs, &mut id_gen);
        assert_eq!(findings.len(), 2);
    }
}
