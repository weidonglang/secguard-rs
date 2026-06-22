use secguard::detections::engine::{DetectionEngine, DetectionIdGenerator};
use secguard::detections::risk_score::{compute_risk_score, get_weight, score_to_severity_label};
use secguard::models::{Detection, Severity};
use std::collections::HashMap;

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
    // high severity first, then earliest timestamp
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
    // 3*7 + 1*10 + 5*1 = 21 + 10 + 5 = 36
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

#[test]
fn test_report_summary_creation() {
    let findings = vec![Detection {
        detection_id: "SG-AUTH-001-0001".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        rule_id: "SG-AUTH-001".to_string(),
        severity: "high".to_string(),
        entity: "user@10.0.0.1".to_string(),
        summary: "Brute force detected".to_string(),
        evidence: "5 failed logins".to_string(),
        recommendation: "Lock account".to_string(),
    }];
    let summary = secguard::models::ReportSummary::new("auth_events.csv".to_string(), findings);
    assert_eq!(summary.generated_by, "SecGuard RS");
    assert_eq!(summary.version, "1.0.0");
    assert_eq!(summary.finding_count, 1);
}

#[test]
fn test_empty_findings_report() {
    let summary = secguard::models::ReportSummary::new("empty.csv".to_string(), vec![]);
    assert_eq!(summary.finding_count, 0);
    assert!(summary.findings.is_empty());
}
