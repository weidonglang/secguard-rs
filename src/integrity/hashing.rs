use crate::errors::SecGuardResult;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Compute SHA256 hex digest for a file at the given path.
pub fn compute_sha256(path: &Path) -> SecGuardResult<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compute_sha256_known_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "hello world").unwrap();
        let hash = compute_sha256(tmp.path()).unwrap();
        // SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_sha256_empty_file() {
        let tmp = NamedTempFile::new().unwrap();
        let hash = compute_sha256(tmp.path()).unwrap();
        // SHA256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_sha256_nonexistent_file() {
        let result = compute_sha256(Path::new("nonexistent_file_xyz123.tmp"));
        assert!(result.is_err());
    }
}
