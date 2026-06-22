use crate::detections::engine::DetectionIdGenerator;
use crate::errors::SecGuardResult;
use crate::integrity::baseline::read_baseline_csv;
use crate::integrity::hashing::compute_sha256;
use crate::models::Detection;
use std::path::Path;
use walkdir::WalkDir;

/// SG-FIM-001: File Modified — sha256 of current file differs from baseline.
/// SG-FIM-002: File Missing — baseline entry exists but file is not found.
///
/// Returns a sorted list of findings.
pub fn verify_integrity(
    baseline_path: &Path,
    scan_path: &Path,
    id_gen: &mut DetectionIdGenerator,
) -> SecGuardResult<Vec<Detection>> {
    let baseline_entries = read_baseline_csv(baseline_path)?;
    let mut findings: Vec<Detection> = Vec::new();

    // Build a set of current file paths for quick lookup
    let mut current_files: std::collections::HashSet<String> = std::collections::HashSet::new();
    if scan_path.exists() {
        for entry in WalkDir::new(scan_path)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if entry.file_type().is_file() {
                let full_path = entry.path().to_string_lossy().to_string();
                // Normalize path for comparison
                let normalized = full_path.replace('\\', "/");
                current_files.insert(normalized);
            }
        }
    }

    for baseline_entry in &baseline_entries {
        let normalized_baseline_path = baseline_entry.path.replace('\\', "/");
        let current_path = Path::new(&baseline_entry.path);

        // Check SG-FIM-002: File Missing
        if !current_path.exists() {
            let normalized_baseline = &normalized_baseline_path;
            let detection = Detection {
                detection_id: id_gen.generate("SG-FIM-002"),
                timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                rule_id: "SG-FIM-002".to_string(),
                severity: "high".to_string(),
                entity: normalized_baseline.clone(),
                summary: format!("File missing: {}", normalized_baseline),
                evidence: format!(
                    "File '{}' was in baseline but no longer exists on disk",
                    normalized_baseline
                ),
                recommendation: "Investigate file deletion, restore from backup if needed."
                    .to_string(),
            };
            findings.push(detection);
            continue;
        }

        // Check SG-FIM-001: File Modified
        let current_hash = compute_sha256(current_path)?;
        if current_hash != baseline_entry.sha256 {
            let detection = Detection {
                detection_id: id_gen.generate("SG-FIM-001"),
                timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                rule_id: "SG-FIM-001".to_string(),
                severity: "medium".to_string(),
                entity: normalized_baseline_path.clone(),
                summary: format!("File modified: {}", normalized_baseline_path),
                evidence: format!(
                    "Baseline SHA256: {}, Current SHA256: {}",
                    baseline_entry.sha256, current_hash
                ),
                recommendation: "Review file changes, verify integrity, re-baseline if legitimate."
                    .to_string(),
            };
            findings.push(detection);
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::baseline::{write_baseline_csv, BaselineEntry};
    use tempfile::TempDir;

    #[test]
    fn test_verify_integrity_no_changes() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        // Generate baseline
        let hash = compute_sha256(&file_path).unwrap();
        let baseline_path = dir.path().join("baseline.csv");
        let entries = vec![BaselineEntry {
            path: file_path.to_string_lossy().to_string(),
            sha256: hash.clone(),
            size_bytes: 11,
            modified_utc: "2026-01-01T00:00:00Z".to_string(),
        }];
        write_baseline_csv(&baseline_path, &entries).unwrap();

        let mut id_gen = DetectionIdGenerator::new();
        let findings = verify_integrity(&baseline_path, dir.path(), &mut id_gen).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_verify_integrity_file_modified() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "original content").unwrap();

        // Generate baseline with wrong hash
        let baseline_path = dir.path().join("baseline.csv");
        let entries = vec![BaselineEntry {
            path: file_path.to_string_lossy().to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            size_bytes: 16,
            modified_utc: "2026-01-01T00:00:00Z".to_string(),
        }];
        write_baseline_csv(&baseline_path, &entries).unwrap();

        let mut id_gen = DetectionIdGenerator::new();
        let findings = verify_integrity(&baseline_path, dir.path(), &mut id_gen).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SG-FIM-001");
    }

    #[test]
    fn test_verify_integrity_file_missing() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("missing.txt");

        // Write baseline referencing a file that doesn't exist
        let baseline_path = dir.path().join("baseline.csv");
        let entries = vec![BaselineEntry {
            path: file_path.to_string_lossy().to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            size_bytes: 100,
            modified_utc: "2026-01-01T00:00:00Z".to_string(),
        }];
        write_baseline_csv(&baseline_path, &entries).unwrap();

        let mut id_gen = DetectionIdGenerator::new();
        let findings = verify_integrity(&baseline_path, dir.path(), &mut id_gen).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SG-FIM-002");
    }

    #[test]
    fn test_verify_integrity_empty_baseline() {
        let dir = TempDir::new().unwrap();
        let baseline_path = dir.path().join("empty.csv");
        write_baseline_csv(&baseline_path, &[]).unwrap();

        let mut id_gen = DetectionIdGenerator::new();
        let findings = verify_integrity(&baseline_path, dir.path(), &mut id_gen).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_verify_integrity_baseline_not_found() {
        let mut id_gen = DetectionIdGenerator::new();
        let result = verify_integrity(
            Path::new("nonexistent_baseline.csv"),
            Path::new("."),
            &mut id_gen,
        );
        assert!(result.is_err());
    }
}
