use crate::errors::{SecGuardError, SecGuardResult};
use crate::integrity::hashing::compute_sha256;
use std::path::Path;
use walkdir::WalkDir;

/// A single file hash entry for integrity baseline.
#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub modified_utc: String,
}

/// Generate a baseline by recursively scanning files under `path`.
/// Skips directories, symlinks, and non-regular files.
pub fn generate_baseline(path: &Path) -> SecGuardResult<Vec<BaselineEntry>> {
    if !path.exists() {
        return Err(SecGuardError::FileNotFound(path.to_path_buf()));
    }
    let mut entries = Vec::new();
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let file_path = entry.path().to_path_buf();
            let sha256 = compute_sha256(&file_path)?;
            let metadata = std::fs::metadata(&file_path)?;
            let modified = metadata
                .modified()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                })
                .unwrap_or_else(|_| "unknown".to_string());
            entries.push(BaselineEntry {
                path: file_path.to_string_lossy().to_string(),
                sha256,
                size_bytes: metadata.len(),
                modified_utc: modified,
            });
        }
    }
    // Sort by path for stable output
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// Write baseline entries to a CSV file matching the file_hashes.csv schema.
pub fn write_baseline_csv(path: &Path, entries: &[BaselineEntry]) -> SecGuardResult<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(["path", "sha256", "size_bytes", "modified_utc"])?;
    for entry in entries {
        wtr.write_record([
            &entry.path,
            &entry.sha256,
            &entry.size_bytes.to_string(),
            &entry.modified_utc,
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

/// Read baseline entries from a CSV file matching the file_hashes.csv schema.
pub fn read_baseline_csv(path: &Path) -> SecGuardResult<Vec<BaselineEntry>> {
    let mut rdr = csv::Reader::from_path(path)?;
    let headers = rdr.headers()?;
    let expected = vec!["path", "sha256", "size_bytes", "modified_utc"];
    let actual: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    if actual != expected {
        return Err(SecGuardError::CsvHeaderMismatch {
            expected: expected.iter().map(|s| s.to_string()).collect(),
            actual,
        });
    }
    let mut entries = Vec::new();
    for result in rdr.records() {
        let record = result?;
        let size_bytes: u64 = record
            .get(2)
            .ok_or_else(|| SecGuardError::Validation("missing size_bytes".to_string()))?
            .parse()
            .map_err(|e| SecGuardError::IntegerParse(format!("size_bytes: {}", e)))?;
        entries.push(BaselineEntry {
            path: record
                .get(0)
                .ok_or_else(|| SecGuardError::Validation("missing path".to_string()))?
                .to_string(),
            sha256: record
                .get(1)
                .ok_or_else(|| SecGuardError::Validation("missing sha256".to_string()))?
                .to_string(),
            size_bytes,
            modified_utc: record
                .get(3)
                .ok_or_else(|| SecGuardError::Validation("missing modified_utc".to_string()))?
                .to_string(),
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_generate_baseline_empty_dir() {
        let dir = TempDir::new().unwrap();
        let entries = generate_baseline(dir.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_generate_baseline_with_files() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();
        let entries = generate_baseline(dir.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].path.contains("test.txt"));
        assert_eq!(entries[0].size_bytes, 11);
    }

    #[test]
    fn test_write_and_read_baseline() {
        let dir = TempDir::new().unwrap();
        let csv_path = dir.path().join("baseline.csv");
        let entries = vec![BaselineEntry {
            path: "/tmp/a.txt".to_string(),
            sha256: "abc123".to_string(),
            size_bytes: 100,
            modified_utc: "2026-01-01T00:00:00Z".to_string(),
        }];
        write_baseline_csv(&csv_path, &entries).unwrap();
        let loaded = read_baseline_csv(&csv_path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].path, "/tmp/a.txt");
        assert_eq!(loaded[0].size_bytes, 100);
    }

    #[test]
    fn test_read_baseline_header_mismatch() {
        let dir = TempDir::new().unwrap();
        let csv_path = dir.path().join("bad.csv");
        let mut f = std::fs::File::create(&csv_path).unwrap();
        writeln!(f, "wrong,header,here").unwrap();
        let result = read_baseline_csv(&csv_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_baseline_nonexistent_path() {
        let result = generate_baseline(Path::new("nonexistent_dir_xyz"));
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_baseline_with_spaces_in_path() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("path with spaces");
        std::fs::create_dir_all(&subdir).unwrap();
        let file_path = subdir.join("auth events sample.csv");
        std::fs::write(&file_path, "data").unwrap();
        let entries = generate_baseline(dir.path()).unwrap();
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.path.contains("path with spaces")));
    }
}
