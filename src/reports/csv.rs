use crate::models::ReportSummary;
use std::io;

/// Generate findings CSV output string from a ReportSummary.
pub fn generate_csv_report(summary: &ReportSummary) -> io::Result<String> {
    let mut wtr = csv::Writer::from_writer(vec![]);

    // Write detections.csv header
    wtr.write_record([
        "detection_id",
        "timestamp",
        "rule_id",
        "severity",
        "entity",
        "summary",
        "evidence",
        "recommendation",
    ])
    .map_err(|e| io::Error::other(e.to_string()))?;

    for f in &summary.findings {
        wtr.write_record([
            &f.detection_id,
            &f.timestamp,
            &f.rule_id,
            &f.severity,
            &f.entity,
            &f.summary,
            &f.evidence,
            &f.recommendation,
        ])
        .map_err(|e| io::Error::other(e.to_string()))?;
    }

    wtr.flush().map_err(|e| io::Error::other(e.to_string()))?;

    let data = wtr
        .into_inner()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let csv_string = String::from_utf8(data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(csv_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Detection, ReportSummary};

    #[test]
    fn test_csv_empty_findings() {
        let summary = ReportSummary::new("test.csv".to_string(), vec![]);
        let csv = generate_csv_report(&summary).unwrap();
        assert!(csv.starts_with("detection_id,"));
        // Only header line + trailing newline
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_csv_with_findings() {
        let findings = vec![Detection {
            detection_id: "DET-001".to_string(),
            timestamp: "2025-06-01T10:00:00Z".to_string(),
            rule_id: "SG-AUTH-001".to_string(),
            severity: "high".to_string(),
            entity: "admin@10.0.0.5".to_string(),
            summary: "Brute force detected".to_string(),
            evidence: "5 failures".to_string(),
            recommendation: "Lock account".to_string(),
        }];
        let summary = ReportSummary::new("test.csv".to_string(), findings);
        let csv = generate_csv_report(&summary).unwrap();
        assert!(csv.contains("DET-001"));
        assert!(csv.contains("SG-AUTH-001"));
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 finding
    }

    #[test]
    fn test_csv_all_fields_present() {
        let findings = vec![Detection {
            detection_id: "DET-001".to_string(),
            timestamp: "2025-06-01T10:00:00Z".to_string(),
            rule_id: "SG-AUTH-001".to_string(),
            severity: "high".to_string(),
            entity: "admin@10.0.0.5".to_string(),
            summary: "Brute force detected".to_string(),
            evidence: "5 failures".to_string(),
            recommendation: "Lock account".to_string(),
        }];
        let summary = ReportSummary::new("test.csv".to_string(), findings);
        let csv = generate_csv_report(&summary).unwrap();
        assert!(csv.contains(
            "detection_id,timestamp,rule_id,severity,entity,summary,evidence,recommendation"
        ));
    }

    #[test]
    fn test_csv_multiple_findings_sorted() {
        let findings = vec![
            Detection {
                detection_id: "DET-002".to_string(),
                timestamp: "2025-01-01T01:00:00Z".to_string(),
                rule_id: "RULE-2".to_string(),
                severity: "medium".to_string(),
                entity: "user2".to_string(),
                summary: "test2".to_string(),
                evidence: "ev2".to_string(),
                recommendation: "rec2".to_string(),
            },
            Detection {
                detection_id: "DET-001".to_string(),
                timestamp: "2025-01-01T00:00:00Z".to_string(),
                rule_id: "RULE-1".to_string(),
                severity: "high".to_string(),
                entity: "user1".to_string(),
                summary: "test1".to_string(),
                evidence: "ev1".to_string(),
                recommendation: "rec1".to_string(),
            },
        ];
        // Order preserved as given
        let summary = ReportSummary::new("test.csv".to_string(), findings);
        let csv = generate_csv_report(&summary).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 findings
        assert!(lines[1].starts_with("DET-002"));
        assert!(lines[2].starts_with("DET-001"));
    }
}
