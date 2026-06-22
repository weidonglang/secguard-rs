use chrono::{DateTime, Duration, TimeZone, Utc};
use secguard::detections::engine::DetectionIdGenerator;
use secguard::detections::network_egress;
use secguard::models::{Config, NetworkFlow};

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
fn test_sg_net_001_blocked_burst_triggered() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let mut events = Vec::new();
    for i in 0..10 {
        events.push(make_flow(
            &format!("F{:04}", i + 1),
            base + Duration::minutes(i),
            "dc-01",
            "203.0.113.1",
            5000,
            "blocked",
        ));
    }
    let mut id_gen = DetectionIdGenerator::new();
    let config = Config::default();
    let findings = network_egress::run_network_detections(&events, &config, &mut id_gen);
    let burst: Vec<_> = findings
        .iter()
        .filter(|d| d.rule_id == network_egress::SG_NET_001)
        .collect();
    assert_eq!(burst.len(), 1, "SG-NET-001 should fire exactly once");
    assert_eq!(burst[0].severity, "medium");
    assert!(burst[0].summary.contains("blocked"));
}

#[test]
fn test_sg_net_002_high_egress_triggered() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let events = vec![make_flow(
        "F100",
        base,
        "web-01",
        "10.0.0.200",
        150_000_000,
        "allow",
    )];
    let mut id_gen = DetectionIdGenerator::new();
    let config = Config::default();
    let findings = network_egress::run_network_detections(&events, &config, &mut id_gen);
    let egress: Vec<_> = findings
        .iter()
        .filter(|d| d.rule_id == network_egress::SG_NET_002)
        .collect();
    assert_eq!(egress.len(), 1, "SG-NET-002 should fire once");
    assert_eq!(egress[0].severity, "high");
    assert!(egress[0].summary.contains("150000000"));
}

#[test]
fn test_sg_net_001_blocked_burst_not_triggered() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let events = vec![
        make_flow("F001", base, "dc-02", "203.0.113.2", 1000, "allow"),
        make_flow(
            "F002",
            base + Duration::seconds(30),
            "dc-02",
            "203.0.113.2",
            1000,
            "allow",
        ),
    ];
    let mut id_gen = DetectionIdGenerator::new();
    let config = Config::default();
    let findings = network_egress::run_network_detections(&events, &config, &mut id_gen);
    let burst: Vec<_> = findings
        .iter()
        .filter(|d| d.rule_id == network_egress::SG_NET_001)
        .collect();
    assert!(
        burst.is_empty(),
        "SG-NET-001 should not fire for allow actions"
    );
}

#[test]
fn test_sg_net_002_high_egress_not_triggered() {
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let events = vec![make_flow("F001", base, "web-02", "10.0.0.2", 5000, "allow")];
    let mut id_gen = DetectionIdGenerator::new();
    let config = Config::default();
    let findings = network_egress::run_network_detections(&events, &config, &mut id_gen);
    let egress: Vec<_> = findings
        .iter()
        .filter(|d| d.rule_id == network_egress::SG_NET_002)
        .collect();
    assert!(
        egress.is_empty(),
        "SG-NET-002 should not fire for 5000 bytes"
    );
}

#[test]
fn test_empty_network_events() {
    let events = Vec::new();
    let mut id_gen = DetectionIdGenerator::new();
    let config = Config::default();
    let findings = network_egress::run_network_detections(&events, &config, &mut id_gen);
    assert!(findings.is_empty(), "no findings for empty events");
}
