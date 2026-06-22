use crate::detections::engine::DetectionIdGenerator;
use crate::models::AuthEvent;
use chrono::Duration;
use std::collections::HashMap;

use crate::models::Detection;

/// Rule ID for brute force login detection.
pub const SG_AUTH_001: &str = "SG-AUTH-001";

/// Rule ID for password spray detection.
pub const SG_AUTH_002: &str = "SG-AUTH-002";

/// Detect brute force login attempts (SG-AUTH-001).
///
/// Condition: Same `source_ip` + `user` has >= 5 failed logins within 10 minutes.
pub fn detect_brute_force(
    events: &[AuthEvent],
    threshold: u32,
    window_minutes: i64,
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    let failed: Vec<&AuthEvent> = events.iter().filter(|e| e.status == "failure").collect();
    if failed.len() < threshold as usize {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Group by source_ip + user
    let mut groups: HashMap<(String, String), Vec<&AuthEvent>> = HashMap::new();
    for event in &failed {
        let key = (event.source_ip.clone(), event.user.clone());
        groups.entry(key).or_default().push(event);
    }

    for ((ip, user), group) in &groups {
        if group.len() < threshold as usize {
            continue;
        }
        // Sort by timestamp
        let mut sorted = group.clone();
        sorted.sort_by_key(|a| a.timestamp);

        // Sliding window check: find any window of `window_minutes` with >= threshold failures
        let window = Duration::minutes(window_minutes);
        for i in 0..sorted.len() {
            let window_end = sorted[i].timestamp + window;
            let count = sorted
                .iter()
                .filter(|e| {
                    let ts = e.timestamp;
                    ts >= sorted[i].timestamp && ts <= window_end
                })
                .count();

            if count as u32 >= threshold {
                findings.push(Detection {
                    detection_id: id_gen.generate(SG_AUTH_001),
                    timestamp: sorted[i].timestamp.to_rfc3339(),
                    rule_id: SG_AUTH_001.to_string(),
                    severity: "high".to_string(),
                    entity: format!("{}@{}", user, ip),
                    summary: format!(
                        "Brute force: {} failed logins from {} for user {} within {} minutes",
                        count, ip, user, window_minutes
                    ),
                    evidence: format!(
                        "{} failures from {}:{} between {} and {}",
                        count,
                        ip,
                        user,
                        sorted[i].timestamp.to_rfc3339(),
                        window_end.to_rfc3339(),
                    ),
                    recommendation: "Lock account temporarily, review source IP, enforce MFA."
                        .to_string(),
                });
                break; // One finding per group
            }
        }
    }

    findings
}

/// Detect password spray attacks (SG-AUTH-002).
///
/// Condition: Same `source_ip` has failed logins for >= 5 different users within 10 minutes.
pub fn detect_password_spray(
    events: &[AuthEvent],
    user_threshold: u32,
    window_minutes: i64,
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    let failed: Vec<&AuthEvent> = events.iter().filter(|e| e.status == "failure").collect();
    if failed.len() < user_threshold as usize {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Group by source_ip
    let mut groups: HashMap<String, Vec<&AuthEvent>> = HashMap::new();
    for event in &failed {
        groups
            .entry(event.source_ip.clone())
            .or_default()
            .push(event);
    }

    for (ip, group) in &groups {
        if group.len() < user_threshold as usize {
            continue;
        }
        // Sort by timestamp
        let mut sorted = group.clone();
        sorted.sort_by_key(|a| a.timestamp);

        let window = Duration::minutes(window_minutes);
        for i in 0..sorted.len() {
            let window_end = sorted[i].timestamp + window;
            let in_window: Vec<&&AuthEvent> = sorted
                .iter()
                .filter(|e| {
                    let ts = e.timestamp;
                    ts >= sorted[i].timestamp && ts <= window_end
                })
                .collect();

            let mut unique_users: Vec<&str> = in_window.iter().map(|e| e.user.as_str()).collect();
            unique_users.sort();
            unique_users.dedup();

            if unique_users.len() as u32 >= user_threshold {
                findings.push(Detection {
                    detection_id: id_gen.generate(SG_AUTH_002),
                    timestamp: sorted[i].timestamp.to_rfc3339(),
                    rule_id: SG_AUTH_002.to_string(),
                    severity: "high".to_string(),
                    entity: ip.clone(),
                    summary: format!(
                        "Password spray: {} from {} targeting {} different users within {} minutes",
                        in_window.len(),
                        ip,
                        unique_users.len(),
                        window_minutes
                    ),
                    evidence: format!(
                        "IP {} targeted {} users: {:?}",
                        ip,
                        unique_users.len(),
                        unique_users
                    ),
                    recommendation: "Block source IP, review user accounts, enforce MFA."
                        .to_string(),
                });
                break;
            }
        }
    }

    findings
}

/// Run all auth-related detections.
pub fn run_auth_detections(
    events: &[AuthEvent],
    config: &crate::models::Config,
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    let mut findings = Vec::new();

    // SG-AUTH-001
    let threshold = config.brute_force_threshold.unwrap_or(5);
    let window = config.brute_force_window_minutes.unwrap_or(10);
    findings.extend(detect_brute_force(events, threshold, window, id_gen));

    // SG-AUTH-002
    let user_threshold = config.password_spray_user_threshold.unwrap_or(5);
    findings.extend(detect_password_spray(
        events,
        user_threshold,
        window,
        id_gen,
    ));

    crate::detections::engine::DetectionEngine::sort_findings(&mut findings);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Config;
    use chrono::{DateTime, TimeZone, Utc};

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
            source_host: "host1".to_string(),
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
    fn test_brute_force_detection() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // 5 failures from same IP+user within 10 minutes
        for i in 0..5 {
            events.push(make_event(
                &format!("E{:04}", i + 1),
                base + Duration::minutes(i),
                "alice",
                "10.0.0.1",
                "failure",
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_auth_detections(&events, &config, &mut id_gen);
        assert!(!findings.is_empty(), "should detect brute force");
        let bf: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_AUTH_001)
            .collect();
        assert!(!bf.is_empty(), "should have SG-AUTH-001 finding");
    }

    #[test]
    fn test_brute_force_below_threshold() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // Only 3 failures
        for i in 0..3 {
            events.push(make_event(
                &format!("E{:04}", i + 1),
                base + Duration::minutes(i),
                "bob",
                "10.0.0.2",
                "failure",
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_auth_detections(&events, &config, &mut id_gen);
        let bf: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_AUTH_001)
            .collect();
        assert!(
            bf.is_empty(),
            "should not detect brute force below threshold"
        );
    }

    #[test]
    fn test_password_spray_detection() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // Same IP fails login for 5 different users within 10 minutes
        let users = ["alice", "bob", "charlie", "dave", "eve"];
        for (i, user) in users.iter().enumerate() {
            events.push(make_event(
                &format!("E{:04}", i + 1),
                base + Duration::minutes(i as i64),
                user,
                "10.0.0.100",
                "failure",
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_auth_detections(&events, &config, &mut id_gen);
        let spray: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_AUTH_002)
            .collect();
        assert!(!spray.is_empty(), "should detect password spray");
    }

    #[test]
    fn test_password_spray_below_threshold() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // Only 2 users
        let users = ["alice", "bob"];
        for (i, user) in users.iter().enumerate() {
            events.push(make_event(
                &format!("E{:04}", i + 1),
                base + Duration::minutes(i as i64),
                user,
                "10.0.0.200",
                "failure",
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_auth_detections(&events, &config, &mut id_gen);
        let spray: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_AUTH_002)
            .collect();
        assert!(
            spray.is_empty(),
            "should not detect password spray below threshold"
        );
    }

    #[test]
    fn test_no_failed_events_no_detection() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let events = vec![make_event("E001", base, "alice", "10.0.0.1", "success")];
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_auth_detections(&events, &config, &mut id_gen);
        assert!(findings.is_empty(), "no findings for successful logins");
    }

    #[test]
    fn test_empty_events() {
        let events = Vec::new();
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_auth_detections(&events, &config, &mut id_gen);
        assert!(findings.is_empty(), "no findings for empty events");
    }

    #[test]
    fn test_brute_force_outside_window() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // 5 failures from same IP+user but spread over 30 minutes (outside 10min window)
        for i in 0..5 {
            events.push(make_event(
                &format!("E{:04}", i + 1),
                base + Duration::minutes(i as i64 * 8), // 0, 8, 16, 24, 32
                "carol",
                "10.0.0.3",
                "failure",
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_auth_detections(&events, &config, &mut id_gen);
        let bf: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_AUTH_001)
            .collect();
        assert!(bf.is_empty(), "no brute force when spread beyond window");
    }
}
