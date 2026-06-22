use crate::detections::engine::DetectionIdGenerator;
use crate::models::Detection;
use crate::models::NetworkFlow;
use chrono::Duration;
use std::collections::HashMap;

/// Rule ID for blocked outbound burst detection.
pub const SG_NET_001: &str = "SG-NET-001";

/// Rule ID for high data egress detection.
pub const SG_NET_002: &str = "SG-NET-002";

/// Detect blocked outbound burst (SG-NET-001).
///
/// Condition: Same `src_host` has >= `threshold` blocked/deny events within `window_minutes`.
pub fn detect_blocked_burst(
    events: &[NetworkFlow],
    threshold: u32,
    window_minutes: i64,
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    // Filter blocked/deny events (case-insensitive)
    let blocked: Vec<&NetworkFlow> = events
        .iter()
        .filter(|e| {
            let action = e.action.to_lowercase();
            action == "blocked" || action == "deny" || action == "denied"
        })
        .collect();

    if blocked.len() < threshold as usize {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Group by src_host
    let mut groups: HashMap<String, Vec<&NetworkFlow>> = HashMap::new();
    for event in &blocked {
        groups
            .entry(event.src_host.clone())
            .or_default()
            .push(event);
    }

    let window = Duration::minutes(window_minutes);

    for (host, group) in &groups {
        if group.len() < threshold as usize {
            continue;
        }
        // Sort by timestamp
        let mut sorted = group.clone();
        sorted.sort_by_key(|a| a.timestamp);

        // Sliding window check
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
                    detection_id: id_gen.generate(SG_NET_001),
                    timestamp: sorted[i].timestamp.to_rfc3339(),
                    rule_id: SG_NET_001.to_string(),
                    severity: "medium".to_string(),
                    entity: host.clone(),
                    summary: format!(
                        "Blocked outbound burst: {} blocked/deny events from {} within {} minutes",
                        count, host, window_minutes
                    ),
                    evidence: format!(
                        "{} blocked outbound flows from {} between {} and {}",
                        count,
                        host,
                        sorted[i].timestamp.to_rfc3339(),
                        window_end.to_rfc3339(),
                    ),
                    recommendation: "Review outbound firewall rules, investigate compromised host."
                        .to_string(),
                });
                break;
            }
        }
    }

    findings
}

/// Detect high data egress (SG-NET-002).
///
/// Condition: `bytes_out` >= `threshold` (default 100,000,000 bytes ~ 100 MB).
pub fn detect_high_egress(
    events: &[NetworkFlow],
    threshold: u64,
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    let mut findings: Vec<Detection> = events
        .iter()
        .filter(|e| e.bytes_out >= threshold)
        .map(|e| Detection {
            detection_id: id_gen.generate(SG_NET_002),
            timestamp: e.timestamp.to_rfc3339(),
            rule_id: SG_NET_002.to_string(),
            severity: "high".to_string(),
            entity: format!("{} -> {}", e.src_host, e.dst_ip),
            summary: format!(
                "High data egress: {} bytes out from {} to {}",
                e.bytes_out, e.src_host, e.dst_ip
            ),
            evidence: format!(
                "Flow {}: {} bytes out, protocol {}, process {}",
                e.flow_id, e.bytes_out, e.protocol, e.process
            ),
            recommendation: "Investigate data exfiltration, review destination IP.".to_string(),
        })
        .collect();

    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    findings
}

/// Run all network-related detections.
pub fn run_network_detections(
    events: &[NetworkFlow],
    config: &crate::models::Config,
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    let mut findings = Vec::new();

    // SG-NET-001
    let burst_threshold = config.blocked_burst_threshold.unwrap_or(10);
    let burst_window = config.blocked_burst_window_minutes.unwrap_or(15);
    findings.extend(detect_blocked_burst(
        events,
        burst_threshold,
        burst_window,
        id_gen,
    ));

    // SG-NET-002
    let egress_threshold = config.high_egress_threshold.unwrap_or(100_000_000);
    findings.extend(detect_high_egress(events, egress_threshold, id_gen));

    crate::detections::engine::DetectionEngine::sort_findings(&mut findings);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Config;
    use chrono::{DateTime, TimeZone, Utc};

    fn make_flow(
        flow_id: &str,
        timestamp: DateTime<Utc>,
        src_host: &str,
        dst_ip: &str,
        bytes_out: u64,
        action: &str,
    ) -> NetworkFlow {
        NetworkFlow {
            flow_id: flow_id.to_string(),
            timestamp,
            src_host: src_host.to_string(),
            src_ip: "10.0.0.1".to_string(),
            src_port: 12345,
            dst_ip: dst_ip.to_string(),
            dst_port: 80,
            protocol: "TCP".to_string(),
            bytes_out,
            bytes_in: 0,
            action: action.to_string(),
            process: "test.exe".to_string(),
        }
    }

    #[test]
    fn test_blocked_burst_detection() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // 10 blocked events from same host within 15 minutes
        for i in 0..10 {
            events.push(make_flow(
                &format!("F{:04}", i + 1),
                base + Duration::minutes(i),
                "workstation-01",
                "203.0.113.1",
                1000,
                "blocked",
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_network_detections(&events, &config, &mut id_gen);
        let burst: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_NET_001)
            .collect();
        assert!(!burst.is_empty(), "should detect blocked burst");
    }

    #[test]
    fn test_blocked_burst_below_threshold() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // Only 5 blocked events (below threshold 10)
        for i in 0..5 {
            events.push(make_flow(
                &format!("F{:04}", i + 1),
                base + Duration::minutes(i),
                "workstation-02",
                "203.0.113.2",
                1000,
                "blocked",
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_network_detections(&events, &config, &mut id_gen);
        let burst: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_NET_001)
            .collect();
        assert!(burst.is_empty(), "should not detect burst below threshold");
    }

    #[test]
    fn test_blocked_burst_outside_window() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // 10 blocked events spread over 30 minutes (outside 15min window)
        for i in 0..10 {
            events.push(make_flow(
                &format!("F{:04}", i + 1),
                base + Duration::minutes(i as i64 * 3), // 0, 3, 6, ..., 27
                "workstation-03",
                "203.0.113.3",
                1000,
                "blocked",
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_network_detections(&events, &config, &mut id_gen);
        let burst: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_NET_001)
            .collect();
        assert!(
            burst.is_empty(),
            "no burst detection when spread beyond window"
        );
    }

    #[test]
    fn test_high_egress_detection() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let events = vec![make_flow(
            "F001",
            base,
            "server-01",
            "10.0.0.99",
            200_000_000, // 200 MB > 100 MB threshold
            "allow",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_network_detections(&events, &config, &mut id_gen);
        let egress: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_NET_002)
            .collect();
        assert!(!egress.is_empty(), "should detect high egress");
    }

    #[test]
    fn test_high_egress_below_threshold() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let events = vec![make_flow(
            "F001",
            base,
            "server-01",
            "10.0.0.99",
            50_000_000, // 50 MB < 100 MB threshold
            "allow",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_network_detections(&events, &config, &mut id_gen);
        let egress: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_NET_002)
            .collect();
        assert!(egress.is_empty(), "should not detect low egress");
    }

    #[test]
    fn test_empty_events() {
        let events = Vec::new();
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_network_detections(&events, &config, &mut id_gen);
        assert!(findings.is_empty(), "no findings for empty events");
    }

    #[test]
    fn test_deny_action_normalized() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // Test "deny" and "denied" also match
        for i in 0..10 {
            let action = if i < 5 { "deny" } else { "denied" };
            events.push(make_flow(
                &format!("F{:04}", i + 1),
                base + Duration::minutes(i),
                "workstation-04",
                "203.0.113.4",
                1000,
                action,
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_network_detections(&events, &config, &mut id_gen);
        let burst: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_NET_001)
            .collect();
        assert!(!burst.is_empty(), "deny/denied actions should match");
    }

    #[test]
    fn test_multiple_hosts_independent() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // Host A: 10 blocked events (detect)
        for i in 0..10 {
            events.push(make_flow(
                &format!("F{:04}A", i + 1),
                base + Duration::minutes(i),
                "host-a",
                "203.0.113.10",
                1000,
                "blocked",
            ));
        }
        // Host B: only 3 blocked events (no detect)
        for i in 0..3 {
            events.push(make_flow(
                &format!("F{:04}B", i + 1),
                base + Duration::minutes(i),
                "host-b",
                "203.0.113.11",
                1000,
                "blocked",
            ));
        }
        let mut id_gen = DetectionIdGenerator::new();
        let config = Config::default();
        let findings = run_network_detections(&events, &config, &mut id_gen);
        let burst_a: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_NET_001 && d.entity == "host-a")
            .collect();
        let burst_b: Vec<&Detection> = findings
            .iter()
            .filter(|d| d.rule_id == SG_NET_001 && d.entity == "host-b")
            .collect();
        assert!(!burst_a.is_empty(), "host-a should trigger burst");
        assert!(burst_b.is_empty(), "host-b should not trigger burst");
    }
}
