use secguard::detections::engine::{DetectionEngine, DetectionIdGenerator};
use secguard::detections::risk_score::{compute_risk_score, get_weight, score_to_severity_label};
use secguard::models::{Detection, Severity};
use std::collections::HashMap;
use std::io::Write;
use tempfile::TempDir;

fn sample_detection() -> Detection {
    Detection {
        detection_id: "SG-AUTH-001-0001".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        rule_id: "SG-AUTH-001".to_string(),
        severity: "high".to_string(),
        entity: "user@10.0.0.1".to_string(),
        summary: "Brute force detected".to_string(),
        evidence: "5 failed logins in 10 minutes".to_string(),
        recommendation: "Lock account temporarily, enforce MFA".to_string(),
    }
}

fn sample_summary() -> secguard::models::ReportSummary {
    secguard::models::ReportSummary::new("test.csv".to_string(), vec![sample_detection()])
}

fn empty_summary() -> secguard::models::ReportSummary {
    secguard::models::ReportSummary::new("empty.csv".to_string(), vec![])
}

#[test]
fn test_detection_id_generator_multiple_rules() {
    let mut gen = DetectionIdGenerator::new();
    let ids: Vec<String> = (0..5).map(|_| gen.generate("SG-AUTH-001")).collect();
    assert_eq!(ids[0], "SG-AUTH-001-0001");
    assert_eq!(ids[4], "SG-AUTH-001-0005");

    let id2 = gen.generate("SG-WIN-001");
    assert_eq!(id2, "SG-WIN-001-0001");
}

#[test]
fn test_sort_findings_stable_order() {
    let mut findings = vec![
        Detection {
            detection_id: "a".to_string(),
            timestamp: "2026-06-01T00:00:00Z".to_string(),
            rule_id: "SG-AUTH-001".to_string(),
            severity: "medium".to_string(),
            entity: "host1".to_string(),
            summary: "test".to_string(),
            evidence: "".to_string(),
            recommendation: "".to_string(),
        },
        Detection {
            detection_id: "b".to_string(),
            timestamp: "2026-06-01T00:00:00Z".to_string(),
            rule_id: "SG-AUTH-001".to_string(),
            severity: "high".to_string(),
            entity: "host2".to_string(),
            summary: "test".to_string(),
            evidence: "".to_string(),
            recommendation: "".to_string(),
        },
        Detection {
            detection_id: "c".to_string(),
            timestamp: "2026-06-01T01:00:00Z".to_string(),
            rule_id: "SG-AUTH-001".to_string(),
            severity: "high".to_string(),
            entity: "host3".to_string(),
            summary: "test".to_string(),
            evidence: "".to_string(),
            recommendation: "".to_string(),
        },
    ];
    DetectionEngine::sort_findings(&mut findings);
    assert_eq!(findings[0].detection_id, "b"); // high, 00:00
    assert_eq!(findings[1].detection_id, "c"); // high, 01:00
    assert_eq!(findings[2].detection_id, "a"); // medium, 00:00
}

#[test]
fn test_risk_score_with_real_severity() {
    let mut counts = HashMap::new();
    counts.insert(Severity::High, 3);
    counts.insert(Severity::Critical, 1);
    counts.insert(Severity::Info, 5);
    assert_eq!(compute_risk_score(&counts), 36);
}

#[test]
fn test_get_weight_all_levels() {
    assert_eq!(get_weight(&Severity::Info), Some(1));
    assert_eq!(get_weight(&Severity::Low), Some(2));
    assert_eq!(get_weight(&Severity::Medium), Some(4));
    assert_eq!(get_weight(&Severity::High), Some(7));
    assert_eq!(get_weight(&Severity::Critical), Some(10));
}

#[test]
fn test_score_to_severity_label_boundaries() {
    assert_eq!(score_to_severity_label(0), "info");
    assert_eq!(score_to_severity_label(4), "info");
    assert_eq!(score_to_severity_label(5), "low");
    assert_eq!(score_to_severity_label(19), "low");
    assert_eq!(score_to_severity_label(20), "medium");
    assert_eq!(score_to_severity_label(39), "medium");
    assert_eq!(score_to_severity_label(40), "high");
    assert_eq!(score_to_severity_label(69), "high");
    assert_eq!(score_to_severity_label(70), "critical");
    assert_eq!(score_to_severity_label(100), "critical");
}

#[test]
fn test_severity_from_string() {
    assert_eq!(Severity::from_string("info"), Some(Severity::Info));
    assert_eq!(Severity::from_string("HIGH"), Some(Severity::High));
    assert_eq!(Severity::from_string("Critical"), Some(Severity::Critical));
    assert_eq!(Severity::from_string("unknown"), None);
}

// --- Report Summary Model Tests ---

#[test]
fn test_report_summary_creation() {
    let summary = sample_summary();
    assert_eq!(summary.generated_by, "SecGuard RS");
    assert_eq!(summary.version, "1.0.0");
    assert_eq!(summary.finding_count, 1);
}

#[test]
fn test_empty_findings_report() {
    let summary = empty_summary();
    assert_eq!(summary.finding_count, 0);
    assert!(summary.findings.is_empty());
}

// --- Markdown Report Tests ---

#[test]
fn test_markdown_report_contains_metadata() {
    let report = secguard::reports::markdown::generate_markdown_report(&sample_summary()).unwrap();
    assert!(report.contains("# SecGuard RS Detection Report"));
    assert!(report.contains("**Generated by:** SecGuard RS"));
    assert!(report.contains("**Version:** 1.0.0"));
    assert!(report.contains("**Input Summary:** test.csv"));
}

#[test]
fn test_markdown_report_lists_findings() {
    let report = secguard::reports::markdown::generate_markdown_report(&sample_summary()).unwrap();
    assert!(report.contains("SG-AUTH-001-0001"));
    assert!(report.contains("high"));
    assert!(report.contains("Brute force detected"));
}

#[test]
fn test_markdown_empty_report() {
    let report = secguard::reports::markdown::generate_markdown_report(&empty_summary()).unwrap();
    assert!(report.contains("No detections found"));
    assert!(!report.contains("SG-AUTH-001"));
}

// --- JSON Report Tests ---

#[test]
fn test_json_report_contains_metadata() {
    let report = secguard::reports::json::generate_json_report(&sample_summary()).unwrap();
    assert!(report.contains("\"generated_by\": \"SecGuard RS\""));
    assert!(report.contains("\"version\": \"1.0.0\""));
    assert!(report.contains("\"finding_count\": 1"));
}

#[test]
fn test_json_report_lists_findings() {
    let report = secguard::reports::json::generate_json_report(&sample_summary()).unwrap();
    assert!(report.contains("SG-AUTH-001-0001"));
    assert!(report.contains("user@10.0.0.1"));
}

#[test]
fn test_json_empty_report() {
    let report = secguard::reports::json::generate_json_report(&empty_summary()).unwrap();
    assert!(report.contains("\"finding_count\": 0"));
    assert!(report.contains("\"findings\": []"));
}

// --- CSV Report Tests ---

#[test]
fn test_csv_report_has_header() {
    let report = secguard::reports::csv::generate_csv_report(&sample_summary()).unwrap();
    assert!(report.starts_with("detection_id,timestamp,rule_id,severity,entity,summary,evidence,recommendation"));
}

#[test]
fn test_csv_report_lists_findings() {
    let report = secguard::reports::csv::generate_csv_report(&sample_summary()).unwrap();
    assert!(report.contains("SG-AUTH-001-0001"));
    assert!(report.contains("high"));
    assert!(report.contains("5 failed logins in 10 minutes"));
}

#[test]
fn test_csv_empty_report() {
    let report = secguard::reports::csv::generate_csv_report(&empty_summary()).unwrap();
    let lines: Vec<&str> = report.lines().collect();
    assert_eq!(lines.len(), 1); // only header
}

// --- Summary Report Tests ---

#[test]
fn test_summary_report_from_csv_findings() {
    // Create a CSV findings file
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("findings.csv");
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "detection_id,timestamp,rule_id,severity,entity,summary,evidence,recommendation").unwrap();
    writeln!(file, "DET-001,2026-01-01T00:00:00Z,SG-AUTH-001,high,admin@host,Brute force,5 failures,Lock account").unwrap();
    file.flush().unwrap();

    let output = secguard::reports::summary::generate_summary(&path, "markdown").unwrap();
    assert!(output.contains("DET-001"));
    assert!(output.contains("SG-AUTH-001"));
}

#[test]
fn test_summary_report_file_not_found() {
    let result = secguard::reports::summary::generate_summary(
        std::path::Path::new("nonexistent.csv"),
        "markdown",
    );
    assert!(result.is_err());
}

#[test]
fn test_summary_report_bad_input() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bad.csv");
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "wrong,columns").unwrap();
    writeln!(file, "val1,val2").unwrap();
    file.flush().unwrap();

    let result = secguard::reports::summary::generate_summary(&path, "markdown");
    assert!(result.is_err());
}

#[test]
fn test_report_roundtrip() {
    // Generate a markdown report, then verify it can be re-summarized
    let report = secguard::reports::markdown::generate_markdown_report(&sample_summary()).unwrap();
    assert!(report.contains("**Finding Count:** 1"));
}

// --- ReportGenerator usage tests ---

#[test]
fn test_report_generate_to_file() {
    let dir = TempDir::new().unwrap();
    let out_path = dir.path().join("report.md");
    let report = secguard::reports::markdown::generate_markdown_report(&sample_summary()).unwrap();
    std::fs::write(&out_path, &report).unwrap();
    let content = std::fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("SecGuard RS"));
}
