use chrono::{DateTime, Duration, TimeZone, Utc};
use secguard::detections::brute_force::{
    detect_brute_force, detect_password_spray, run_auth_detections,
};
use secguard::detections::engine::DetectionIdGenerator;
use secguard::models::{AuthEvent, Config};

fn make_event(
    event_id: &str,
    timestamp: DateTime<Utc>,
    user: &str,
    source_ip: &str,
    status: &str,
) -> AuthEvent {
    AuthEvent {
        event_id: event_id.to_string(),
        timestamp,
        source_host: "test-host".to_string(),
        user: user.to_string(),
        source_ip: source_ip.to_string(),
        action: "login".to_string(),
        auth_method: "password".to_string(),
        status: status.to_string(),
        reason: if status == "failure" {
            "bad_password".to_string()
        } else {
            "success".to_string()
        },
    }
}

#[test]
fn test_brute_force_exact_threshold() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let mut events = Vec::new();
    // Exactly 5 failures within window
    for i in 0..5 {
        events.push(make_event(
            &format!("E{:04}", i + 1),
            base + Duration::minutes(i as i64),
            "target_user",
            "192.168.1.100",
            "failure",
        ));
    }
    let mut id_gen = DetectionIdGenerator::new();
    let result = detect_brute_force(&events, 5, 10, &mut id_gen);
    assert_eq!(result.len(), 1, "should detect brute force at threshold");
    assert_eq!(result[0].rule_id, "SG-AUTH-001");
    assert_eq!(result[0].severity, "high");
}

#[test]
fn test_brute_force_mixed_success_failure() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let mut events = Vec::new();
    // 5 failures + some successes from same IP+user
    for i in 0..5 {
        events.push(make_event(
            &format!("E{:04}", i + 1),
            base + Duration::minutes(i as i64),
            "alice",
            "10.0.0.50",
            "failure",
        ));
    }
    events.push(make_event(
        "E006",
        base + Duration::minutes(5),
        "alice",
        "10.0.0.50",
        "success",
    ));
    events.push(make_event(
        "E007",
        base + Duration::minutes(6),
        "alice",
        "10.0.0.50",
        "success",
    ));

    let mut id_gen = DetectionIdGenerator::new();
    let result = detect_brute_force(&events, 5, 10, &mut id_gen);
    assert_eq!(
        result.len(),
        1,
        "should detect brute force despite successes"
    );
}

#[test]
fn test_brute_force_different_ips_independent() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let mut events = Vec::new();
    // IP1: 5 failures for user1
    for i in 0..5 {
        events.push(make_event(
            &format!("E1_{:04}", i + 1),
            base + Duration::minutes(i as i64),
            "user1",
            "10.0.0.1",
            "failure",
        ));
    }
    // IP2: only 3 failures for user2 (below threshold)
    for i in 0..3 {
        events.push(make_event(
            &format!("E2_{:04}", i + 1),
            base + Duration::minutes(i as i64),
            "user2",
            "10.0.0.2",
            "failure",
        ));
    }

    let mut id_gen = DetectionIdGenerator::new();
    let result = detect_brute_force(&events, 5, 10, &mut id_gen);
    assert_eq!(result.len(), 1, "only one IP should trigger brute force");
    assert!(
        result[0].entity.contains("user1"),
        "entity should reference user1"
    );
}

#[test]
fn test_password_spray_different_times() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 8, 0, 0).unwrap();
    let mut events = Vec::new();
    let users = ["admin", "bob", "carol", "dave", "eve"];
    // All within 10 min window
    for (i, user) in users.iter().enumerate() {
        events.push(make_event(
            &format!("S{:04}", i + 1),
            base + Duration::minutes(i as i64 * 2), // 0, 2, 4, 6, 8 minutes
            user,
            "10.0.0.99",
            "failure",
        ));
    }
    let mut id_gen = DetectionIdGenerator::new();
    let result = detect_password_spray(&events, 5, 10, &mut id_gen);
    assert_eq!(result.len(), 1, "should detect password spray");
    assert_eq!(result[0].rule_id, "SG-AUTH-002");
}

#[test]
fn test_password_spray_outside_window() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let mut events = Vec::new();
    let users = ["admin", "bob", "carol", "dave", "eve"];
    // Spread over 30 minutes (outside 10 min window)
    for (i, user) in users.iter().enumerate() {
        events.push(make_event(
            &format!("S{:04}", i + 1),
            base + Duration::minutes(i as i64 * 7), // 0, 7, 14, 21, 28
            user,
            "10.0.0.99",
            "failure",
        ));
    }
    let mut id_gen = DetectionIdGenerator::new();
    let result = detect_password_spray(&events, 5, 10, &mut id_gen);
    assert!(
        result.is_empty(),
        "should NOT detect password spray outside window"
    );
}

#[test]
fn test_password_spray_same_user_multiple_failures() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let mut events = Vec::new();
    // Only 2 unique users, but many failures each
    for i in 0..5 {
        events.push(make_event(
            &format!("E{:04}", i + 1),
            base + Duration::minutes(i as i64),
            "alice",
            "10.0.0.99",
            "failure",
        ));
    }
    for i in 0..5 {
        events.push(make_event(
            &format!("F{:04}", i + 1),
            base + Duration::minutes(i as i64),
            "bob",
            "10.0.0.99",
            "failure",
        ));
    }
    let mut id_gen = DetectionIdGenerator::new();
    let result = detect_password_spray(&events, 5, 10, &mut id_gen);
    assert!(
        result.is_empty(),
        "should NOT detect password spray with only 2 users"
    );
}

#[test]
fn test_run_auth_detections_output_stable() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let mut events = Vec::new();
    // Trigger both brute force and password spray
    let users = ["admin", "bob", "carol", "dave", "eve"];
    for (i, user) in users.iter().enumerate() {
        events.push(make_event(
            &format!("P{:04}", i + 1),
            base + Duration::minutes(i as i64),
            user,
            "10.0.0.99",
            "failure",
        ));
    }
    for i in 0..5 {
        events.push(make_event(
            &format!("B{:04}", i + 1),
            base + Duration::minutes(i as i64),
            "target",
            "10.0.0.88",
            "failure",
        ));
    }
    let config = Config::default();
    let mut id_gen = DetectionIdGenerator::new();
    let findings1 = run_auth_detections(&events, &config, &mut id_gen);
    let mut id_gen2 = DetectionIdGenerator::new();
    let findings2 = run_auth_detections(&events, &config, &mut id_gen2);

    assert_eq!(
        findings1.len(),
        findings2.len(),
        "detection output should be stable"
    );
    for (a, b) in findings1.iter().zip(findings2.iter()) {
        assert_eq!(a.severity, b.severity);
        assert_eq!(a.rule_id, b.rule_id);
        assert_eq!(a.entity, b.entity);
        assert_eq!(a.summary, b.summary);
    }
}

#[test]
fn test_no_findings_returns_empty() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let events = vec![make_event(
        "E001",
        base,
        "normal_user",
        "10.0.0.1",
        "success",
    )];
    let config = Config::default();
    let mut id_gen = DetectionIdGenerator::new();
    let findings = run_auth_detections(&events, &config, &mut id_gen);
    assert!(findings.is_empty(), "no findings for normal activity");
}
