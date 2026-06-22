use secguard::integrity::{baseline, hashing, verify};
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

#[test]
fn test_baseline_generate_and_write() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test.txt");
    std::fs::write(&file_path, "integrity test data").unwrap();

    let entries = baseline::generate_baseline(dir.path()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].size_bytes, 19);

    let csv_path = dir.path().join("baseline.csv");
    baseline::write_baseline_csv(&csv_path, &entries).unwrap();
    assert!(csv_path.exists());
}

#[test]
fn test_baseline_read_roundtrip() {
    let dir = TempDir::new().unwrap();
    let csv_path = dir.path().join("baseline.csv");

    let entries = vec![baseline::BaselineEntry {
        path: dir.path().join("a.txt").to_string_lossy().to_string(),
        sha256: "abc123".to_string(),
        size_bytes: 42,
        modified_utc: "2026-01-01T00:00:00Z".to_string(),
    }];
    baseline::write_baseline_csv(&csv_path, &entries).unwrap();
    let loaded = baseline::read_baseline_csv(&csv_path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].sha256, "abc123");
}

#[test]
fn test_hashing_sha256_known() {
    let mut tmp = NamedTempFile::new().unwrap();
    write!(tmp, "hello world").unwrap();
    let hash = hashing::compute_sha256(tmp.path()).unwrap();
    assert_eq!(
        hash,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[test]
fn test_hashing_empty_file() {
    let tmp = NamedTempFile::new().unwrap();
    let hash = hashing::compute_sha256(tmp.path()).unwrap();
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_hashing_nonexistent_file() {
    let result = hashing::compute_sha256(std::path::Path::new("nonexistent_file_for_test_xyz"));
    assert!(result.is_err());
}

#[test]
fn test_verify_no_changes() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test.txt");
    std::fs::write(&file_path, "hello world").unwrap();
    let hash = hashing::compute_sha256(&file_path).unwrap();

    let csv_path = dir.path().join("baseline.csv");
    let entries = vec![baseline::BaselineEntry {
        path: file_path.to_string_lossy().to_string(),
        sha256: hash,
        size_bytes: 11,
        modified_utc: "2026-01-01T00:00:00Z".to_string(),
    }];
    baseline::write_baseline_csv(&csv_path, &entries).unwrap();

    let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
    let findings = verify::verify_integrity(&csv_path, dir.path(), &mut id_gen).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_verify_file_modified() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test.txt");
    std::fs::write(&file_path, "original").unwrap();

    let csv_path = dir.path().join("baseline.csv");
    let entries = vec![baseline::BaselineEntry {
        path: file_path.to_string_lossy().to_string(),
        sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        size_bytes: 8,
        modified_utc: "2026-01-01T00:00:00Z".to_string(),
    }];
    baseline::write_baseline_csv(&csv_path, &entries).unwrap();

    let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
    let findings = verify::verify_integrity(&csv_path, dir.path(), &mut id_gen).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SG-FIM-001");
}

#[test]
fn test_verify_file_missing() {
    let dir = TempDir::new().unwrap();
    let csv_path = dir.path().join("baseline.csv");

    let entries = vec![baseline::BaselineEntry {
        path: dir.path().join("missing.txt").to_string_lossy().to_string(),
        sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        size_bytes: 100,
        modified_utc: "2026-01-01T00:00:00Z".to_string(),
    }];
    baseline::write_baseline_csv(&csv_path, &entries).unwrap();

    let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
    let findings = verify::verify_integrity(&csv_path, dir.path(), &mut id_gen).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SG-FIM-002");
}

#[test]
fn test_verify_empty_baseline() {
    let dir = TempDir::new().unwrap();
    let csv_path = dir.path().join("empty.csv");
    baseline::write_baseline_csv(&csv_path, &[]).unwrap();

    let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
    let findings = verify::verify_integrity(&csv_path, dir.path(), &mut id_gen).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_verify_baseline_not_found() {
    let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
    let result = verify::verify_integrity(
        std::path::Path::new("nonexistent_baseline.csv"),
        std::path::Path::new("."),
        &mut id_gen,
    );
    assert!(result.is_err());
}

#[test]
fn test_paths_with_spaces() {
    let dir = TempDir::new().unwrap();
    let subdir = dir.path().join("path with spaces");
    std::fs::create_dir_all(&subdir).unwrap();
    let file_path = subdir.join("auth events sample.csv");
    std::fs::write(&file_path, "data").unwrap();

    let entries = baseline::generate_baseline(dir.path()).unwrap();
    assert!(
        entries.iter().any(|e| e.path.contains("path with spaces")),
        "Expected path with spaces in baseline entries"
    );

    // Write baseline and verify roundtrip
    let csv_path = dir.path().join("baseline with spaces.csv");
    baseline::write_baseline_csv(&csv_path, &entries).unwrap();
    let loaded = baseline::read_baseline_csv(&csv_path).unwrap();
    assert!(!loaded.is_empty());
}

#[test]
fn test_baseline_empty_directory() {
    let dir = TempDir::new().unwrap();
    let entries = baseline::generate_baseline(dir.path()).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_baseline_nonexistent_path() {
    let result = baseline::generate_baseline(std::path::Path::new("nonexistent_dir_xyz_123"));
    assert!(result.is_err());
}

#[test]
fn test_baseline_multiple_files() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), "aaa").unwrap();
    std::fs::write(dir.path().join("b.txt"), "bbb").unwrap();
    std::fs::write(dir.path().join("c.txt"), "ccc").unwrap();

    let entries = baseline::generate_baseline(dir.path()).unwrap();
    assert_eq!(entries.len(), 3);

    // Verify sorted by path
    assert!(entries[0].path.ends_with("a.txt"));
    assert!(entries[1].path.ends_with("b.txt"));
    assert!(entries[2].path.ends_with("c.txt"));
}

#[test]
fn test_baseline_csv_header_mismatch() {
    let dir = TempDir::new().unwrap();
    let bad_csv = dir.path().join("bad.csv");
    let mut f = std::fs::File::create(&bad_csv).unwrap();
    writeln!(f, "bad,header,line").unwrap();

    let result = baseline::read_baseline_csv(&bad_csv);
    assert!(result.is_err());
}
