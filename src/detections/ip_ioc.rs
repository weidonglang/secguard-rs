use crate::detections::engine::DetectionIdGenerator;
use crate::models::{Detection, IocIp, NetworkFlow};
use chrono::Utc;

/// Rule ID for IOC IP match detection.
pub const SG_IP_001: &str = "SG-IP-001";

/// Detect network flows with destination IPs matching known malicious IPs (SG-IP-001).
///
/// Matches are exact IP string matches. Each match generates a severity level
/// based on the IOC severity.
pub fn detect_ip_ioc(
    flows: &[NetworkFlow],
    ioc_ips: &[IocIp],
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    if flows.is_empty() || ioc_ips.is_empty() {
        return Vec::new();
    }

    // Build a set of known malicious IPs for O(1) lookup
    let ioc_ip_set: std::collections::HashMap<&str, &IocIp> = ioc_ips
        .iter()
        .map(|ioc| (ioc.indicator.as_str(), ioc))
        .collect();

    let mut findings = Vec::new();
    let now = Utc::now();

    for flow in flows {
        if let Some(ioc) = ioc_ip_set.get(flow.dst_ip.as_str()) {
            let severity = crate::models::Severity::from_string(&ioc.severity)
                .unwrap_or(crate::models::Severity::High);
            let timestamp = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

            findings.push(Detection {
                detection_id: id_gen.generate(SG_IP_001),
                timestamp,
                rule_id: SG_IP_001.to_string(),
                severity: severity.as_str().to_string(),
                entity: format!("{}->{}", flow.src_host, flow.dst_ip),
                summary: format!("Network flow to known malicious IP: {}", ioc.indicator),
                evidence: format!(
                    "flow_id={}, src_host={}, dst_ip={}, dst_port={}, protocol={}, bytes_out={}",
                    flow.flow_id,
                    flow.src_host,
                    flow.dst_ip,
                    flow.dst_port,
                    flow.protocol,
                    flow.bytes_out
                ),
                recommendation: "Block the IP, investigate affected host, check for related IOCs."
                    .to_string(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_flow(dst_ip: &str) -> NetworkFlow {
        NetworkFlow {
            flow_id: "F001".to_string(),
            timestamp: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            src_host: "host-01".to_string(),
            src_ip: "10.0.0.1".to_string(),
            src_port: 49152,
            dst_ip: dst_ip.to_string(),
            dst_port: 443,
            protocol: "TCP".to_string(),
            bytes_out: 1024,
            bytes_in: 2048,
            action: "allow".to_string(),
            process: "curl.exe".to_string(),
        }
    }

    fn make_ioc(ip: &str, severity: &str) -> IocIp {
        IocIp {
            indicator: ip.to_string(),
            severity: severity.to_string(),
            description: "Test IOC IP".to_string(),
        }
    }

    #[test]
    fn test_ip_ioc_exact_match() {
        let flows = vec![make_flow("5.6.7.8")];
        let iocs = vec![make_ioc("5.6.7.8", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_ip_ioc(&flows, &iocs, &mut id_gen);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].rule_id.contains("SG-IP-001"));
        assert_eq!(findings[0].severity, "high");
    }

    #[test]
    fn test_ip_ioc_no_match() {
        let flows = vec![make_flow("10.0.0.1")];
        let iocs = vec![make_ioc("5.6.7.8", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_ip_ioc(&flows, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ip_ioc_empty_flows() {
        let flows = vec![];
        let iocs = vec![make_ioc("5.6.7.8", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_ip_ioc(&flows, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ip_ioc_empty_iocs() {
        let flows = vec![make_flow("5.6.7.8")];
        let iocs = vec![];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_ip_ioc(&flows, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ip_ioc_multiple_flows_same_ioc() {
        let flows = vec![make_flow("5.6.7.8"), make_flow("5.6.7.8")];
        let iocs = vec![make_ioc("5.6.7.8", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_ip_ioc(&flows, &iocs, &mut id_gen);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_ip_ioc_different_severities() {
        let flows = vec![make_flow("1.1.1.1"), make_flow("2.2.2.2")];
        let iocs = vec![
            make_ioc("1.1.1.1", "medium"),
            make_ioc("2.2.2.2", "critical"),
        ];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_ip_ioc(&flows, &iocs, &mut id_gen);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, "medium");
        assert_eq!(findings[1].severity, "critical");
    }
}
