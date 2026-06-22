use crate::models::ReportSummary;
use std::io;

/// Generate a JSON report string from a ReportSummary.
pub fn generate_json_report(summary: &ReportSummary) -> io::Result<String> {
    let json = serde_json::to_string_pretty(summary)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Detection, ReportSummary};

    #[test]
    fn test_json_empty_findings() {
        let summary = ReportSummary::new("test.csv".to_string(), vec![]);
        let json = generate_json_report(&summary).unwrap();
        assert!(json.contains("\"generated_by\": \"SecGuard RS\""));
        assert!(json.contains("\"finding_count\": 0"));
        assert!(json.contains("\"findings\": []"));
    }

    #[test]
    fn test_json_with_findings() {
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
        let json = generate_json_report(&summary).unwrap();
        assert!(json.contains("\"detection_id\": \"DET-001\""));
        assert!(json.contains("\"finding_count\": 1"));
    }

    #[test]
    fn test_json_valid_parse() {
        let summary = ReportSummary::new("input.csv".to_string(), vec![]);
        let json = generate_json_report(&summary).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["generated_by"], "SecGuard RS");
        assert_eq!(parsed["version"], "1.0.0");
        assert_eq!(parsed["finding_count"], 0);
    }

    #[test]
    fn test_json_version_field() {
        let summary = ReportSummary::new("test.csv".to_string(), vec![]);
        let json = generate_json_report(&summary).unwrap();
        assert!(json.contains("\"version\": \"1.0.0\""));
    }

    #[test]
    fn test_json_multiple_findings() {
        let findings = vec![
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
        ];
        let summary = ReportSummary::new("test.csv".to_string(), findings);
        let json = generate_json_report(&summary).unwrap();
        assert!(json.contains("DET-001"));
        assert!(json.contains("DET-002"));
        assert!(json.contains("\"finding_count\": 2"));
    }
}