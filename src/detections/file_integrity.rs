use crate::detections::engine::DetectionIdGenerator;
use crate::errors::SecGuardResult;
use crate::integrity::hashing::compute_sha256;
use crate::models::Detection;
use std::path::Path;
use walkdir::WalkDir;

/// Run file integrity detections (SG-FIM-001, SG-FIM-002) by comparing
/// a baseline CSV against the current state of files on disk.
///
/// SG-FIM-001: File modified (SHA256 mismatch)
/// SG-FIM-002: File missing
pub fn run_file_integrity_detections(
    baseline_path: &Path,
    scan_path: &Path,
    id_gen: &mut DetectionIdGenerator,
) -> SecGuardResult<Vec<Detection>> {
    let baseline_entries = crate::integrity::baseline::read_baseline_csv(baseline_path)?;
    let mut findings: Vec<Detection> = Vec::new();

    // Build a map of current file paths to their SHA256 hashes
    let mut current_files: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    if scan_path.exists() {
        for entry in WalkDir::new(scan_path)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if entry.file_type().is_file() {
                let file_path = entry.path().to_path_buf();
                if let Ok(hash) = compute_sha256(&file_path) {
                    current_files.insert(
                        file_path.to_string_lossy().to_string().replace('\\', "/"),
                        hash,
                    );
                }
            }
        }
    }

    for entry in &baseline_entries {
        let normalized_baseline = entry.path.replace('\\', "/");

        // SG-FIM-002: File missing
        if !Path::new(&entry.path).exists() {
            findings.push(Detection {
                detection_id: id_gen.generate("SG-FIM-002"),
                timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                rule_id: "SG-FIM-002".to_string(),
                severity: "high".to_string(),
                entity: normalized_baseline.clone(),
                summary: format!("File missing: {}", normalized_baseline),
                evidence: format!(
                    "Baseline file '{}' no longer exists on disk",
                    normalized_baseline
                ),
                recommendation: "Investigate file deletion, restore from backup if needed."
                    .to_string(),
            });
            continue;
        }

        // SG-FIM-001: File modified
        if let Some(current_hash) = current_files.get(&normalized_baseline) {
            if *current_hash != entry.sha256 {
                findings.push(Detection {
                    detection_id: id_gen.generate("SG-FIM-001"),
                    timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    rule_id: "SG-FIM-001".to_string(),
                    severity: "medium".to_string(),
                    entity: normalized_baseline.clone(),
                    summary: format!("File modified: {}", normalized_baseline),
                    evidence: format!(
                        "Baseline SHA256: {}, Current SHA256: {}",
                        entry.sha256, current_hash
                    ),
                    recommendation: "Review file changes, re-baseline if legitimate.".to_string(),
                });
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::baseline::write_baseline_csv;
    use crate::integrity::baseline::BaselineEntry;
    use tempfile::TempDir;

    #[test]
    fn test_no_changes_no_findings() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let hash = compute_sha256(&file_path).unwrap();
        let baseline_path = dir.path().join("baseline.csv");
        let entries = vec![BaselineEntry {
            path: file_path.to_string_lossy().to_string(),
            sha256: hash,
            size_bytes: 11,
            modified_utc: "2026-01-01T00:00:00Z".to_string(),
        }];
        write_baseline_csv(&baseline_path, &entries).unwrap();

        let mut id_gen = DetectionIdGenerator::new();
        let findings =
            run_file_integrity_detections(&baseline_path, dir.path(), &mut id_gen).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_file_modified_detected() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "original").unwrap();

        let baseline_path = dir.path().join("baseline.csv");
        let entries = vec![BaselineEntry {
            path: file_path.to_string_lossy().to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            size_bytes: 8,
            modified_utc: "2026-01-01T00:00:00Z".to_string(),
        }];
        write_baseline_csv(&baseline_path, &entries).unwrap();

        let mut id_gen = DetectionIdGenerator::new();
        let findings =
            run_file_integrity_detections(&baseline_path, dir.path(), &mut id_gen).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SG-FIM-001");
    }

    #[test]
    fn test_file_missing_detected() {
        let dir = TempDir::new().unwrap();
        let baseline_path = dir.path().join("baseline.csv");
        let entries = vec![BaselineEntry {
            path: dir.path().join("missing.txt").to_string_lossy().to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            size_bytes: 100,
            modified_utc: "2026-01-01T00:00:00Z".to_string(),
        }];
        write_baseline_csv(&baseline_path, &entries).unwrap();

        let mut id_gen = DetectionIdGenerator::new();
        let findings =
            run_file_integrity_detections(&baseline_path, dir.path(), &mut id_gen).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SG-FIM-002");
    }

    #[test]
    fn test_empty_baseline_no_findings() {
        let dir = TempDir::new().unwrap();
        let baseline_path = dir.path().join("empty.csv");
        write_baseline_csv(&baseline_path, &[]).unwrap();

        let mut id_gen = DetectionIdGenerator::new();
        let findings =
            run_file_integrity_detections(&baseline_path, dir.path(), &mut id_gen).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_multiple_entries_sorted() {
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("a.txt");
        let file2 = dir.path().join("b.txt");
        std::fs::write(&file1, "content a").unwrap();
        std::fs::write(&file2, "content b").unwrap();

        let baseline_path = dir.path().join("baseline.csv");
        let entries = vec![
            BaselineEntry {
                path: file1.to_string_lossy().to_string(),
                sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                size_bytes: 9,
                modified_utc: "2026-01-01T00:00:00Z".to_string(),
            },
            BaselineEntry {
                path: file2.to_string_lossy().to_string(),
                sha256: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                size_bytes: 9,
                modified_utc: "2026-01-01T00:00:00Z".to_string(),
            },
        ];
        write_baseline_csv(&baseline_path, &entries).unwrap();

        let mut id_gen = DetectionIdGenerator::new();
        let findings =
            run_file_integrity_detections(&baseline_path, dir.path(), &mut id_gen).unwrap();
        assert_eq!(findings.len(), 2);
    }
}
