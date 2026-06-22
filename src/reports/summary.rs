use crate::errors::SecGuardError;
use crate::models::Detection;
use crate::reports::csv::generate_csv_report;
use crate::reports::json::generate_json_report;
use crate::reports::markdown::generate_markdown_report;
use crate::models::ReportSummary;
use std::io::Read;
use std::path::Path;

/// Generate a summary report from an input file in the specified format.
///
/// `input_path` can be a CSV detections file or JSON findings file.
/// `format` can be "markdown", "json", or "csv" (defaults to "markdown").
pub fn generate_summary(input_path: &Path, format: &str) -> Result<String, SecGuardError> {
    let data = read_file_to_string(input_path)?;
    let findings = parse_findings(&data, input_path)?;
    let input_name = input_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| input_path.to_string_lossy().to_string());
    let summary = ReportSummary::new(input_name, findings);

    let out = match format.to_lowercase().as_str() {
        "json" => generate_json_report(&summary)?,
        "csv" => generate_csv_report(&summary)?,
        _ => generate_markdown_report(&summary)?,
    };
    Ok(out)
}

fn read_file_to_string(path: &Path) -> Result<String, SecGuardError> {
    if !path.exists() {
        return Err(SecGuardError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Input file not found: {}", path.display()),
        )));
    }
    let mut file = std::fs::File::open(path).map_err(|e| {
        SecGuardError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Cannot open {}: {}", path.display(), e),
        ))
    })?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| {
        SecGuardError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Cannot read {}: {}", path.display(), e),
        ))
    })?;
    Ok(contents)
}

fn parse_findings(data: &str, path: &Path) -> Result<Vec<Detection>, SecGuardError> {
    // Try JSON first
    if let Ok(summary) = serde_json::from_str::<ReportSummary>(data) {
        return Ok(summary.findings);
    }
    // Try CSV
    if let Some(ext) = path.extension() {
        if ext == "csv" || data.contains("detection_id") {
            return parse_csv_findings(data);
        }
    }
    // If we can't determine format, try parsing as JSON report summary
    Err(SecGuardError::ParseError(format!(
        "Cannot parse findings from {}: unsupported format",
        path.display()
    )))
}

fn parse_csv_findings(data: &str) -> Result<Vec<Detection>, SecGuardError> {
    let mut reader = csv::Reader::from_reader(data.as_bytes());
    let headers = reader
        .headers()
        .map_err(|e| SecGuardError::ParseError(format!("CSV header error: {}", e)))?;

    let expected = [
        "detection_id",
        "timestamp",
        "rule_id",
        "severity",
        "entity",
        "summary",
        "evidence",
        "recommendation",
    ];

    for (i, h) in headers.iter().enumerate() {
        if i >= expected.len() || h != expected[i] {
            return Err(SecGuardError::ParseError(format!(
                "CSV header mismatch at column {}: expected '{}', got '{}'",
                i,
                expected.get(i).unwrap_or(&"?"),
                h
            )));
        }
    }

    let mut findings = Vec::new();
    for result in reader.deserialize() {
        let detection: Detection = result.map_err(|e| {
            SecGuardError::ParseError(format!("CSV row parse error: {}", e))
        })?;
        findings.push(detection);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::io::Write;

    fn create_temp_file(content: &str) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("findings.csv");
        let mut file = std::fs::File::create(&path).unwrap();
        write!(file, "{}", content).unwrap();
        (dir, path)
    }

    #[test]
    fn test_summary_csv_empty() {
        let header = "detection_id,timestamp,rule_id,severity,entity,summary,evidence,recommendation\n";
        let (_dir, path) = create_temp_file(header);
        let result = generate_summary(&path, "markdown").unwrap();
        assert!(result.contains("No detections found"));
    }

    #[test]
    fn test_summary_csv_with_findings() {
        let content = "detection_id,timestamp,rule_id,severity,entity,summary,evidence,recommendation\n\
                       DET-001,2025-06-01T10:00:00Z,SG-AUTH-001,high,admin@10.0.0.5,Brute force,5 failures,Lock account\n";
        let (_dir, path) = create_temp_file(content);
        let result = generate_summary(&path, "markdown").unwrap();
        assert!(result.contains("DET-001"));
        assert!(result.contains("SG-AUTH-001"));
    }

    #[test]
    fn test_summary_json_output() {
        let content = "detection_id,timestamp,rule_id,severity,entity,summary,evidence,recommendation\n\
                       DET-001,2025-06-01T10:00:00Z,SG-AUTH-001,high,admin@10.0.0.5,Brute force,5 failures,Lock account\n";
        let (_dir, path) = create_temp_file(content);
        let result = generate_summary(&path, "json").unwrap();
        assert!(result.contains("\"detection_id\": \"DET-001\""));
    }

    #[test]
    fn test_summary_csv_output() {
        let content = "detection_id,timestamp,rule_id,severity,entity,summary,evidence,recommendation\n\
                       DET-001,2025-06-01T10:00:00Z,SG-AUTH-001,high,admin@10.0.0.5,Brute force,5 failures,Lock account\n";
        let (_dir, path) = create_temp_file(content);
        let result = generate_summary(&path, "csv").unwrap();
        assert!(result.contains("DET-001"));
        assert!(result.contains("detection_id,timestamp"));
    }

    #[test]
    fn test_summary_file_not_found() {
        let path = Path::new("nonexistent.csv");
        let result = generate_summary(path, "markdown");
        assert!(result.is_err());
    }

    #[test]
    fn test_summary_bad_csv_header() {
        let content = "wrong,header\nval1,val2\n";
        let (_dir, path) = create_temp_file(content);
        let result = generate_summary(&path, "markdown");
        assert!(result.is_err());
    }

    #[test]
    fn test_summary_default_format_markdown() {
        let content = "detection_id,timestamp,rule_id,severity,entity,summary,evidence,recommendation\n";
        let (_dir, path) = create_temp_file(content);
        let result = generate_summary(&path, "markdown").unwrap();
        assert!(result.starts_with("# SecGuard RS"));
    }
}