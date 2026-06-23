use crate::detections::engine::DetectionIdGenerator;
use crate::models::{Detection, DnsQuery, IocDomain};

/// Rule ID for IOC domain match detection.
pub const SG_DNS_001: &str = "SG-DNS-001";

/// Detect DNS queries matching known malicious domains (SG-DNS-001).
///
/// Matches are case-insensitive. Each match generates a `high` severity finding.
/// Timestamps are taken from the source DNS query data, not the current system time.
pub fn detect_dns_ioc(
    queries: &[DnsQuery],
    ioc_domains: &[IocDomain],
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    if queries.is_empty() || ioc_domains.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for query in queries {
        let query_lower = query.query.to_lowercase();
        for ioc in ioc_domains {
            let ioc_lower = ioc.indicator.to_lowercase();
            if query_lower == ioc_lower || query_lower.ends_with(&format!(".{}", ioc_lower)) {
                let severity = crate::models::Severity::from_string(&ioc.severity)
                    .unwrap_or(crate::models::Severity::High);
                // Use source query timestamp instead of current system time
                let timestamp = query.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string();

                findings.push(Detection {
                    detection_id: id_gen.generate(SG_DNS_001),
                    timestamp,
                    rule_id: SG_DNS_001.to_string(),
                    severity: severity.as_str().to_string(),
                    entity: format!("{}@{}", query.host, query.query),
                    summary: format!(
                        "DNS query matches known malicious domain: {}",
                        ioc.indicator
                    ),
                    evidence: format!(
                        "query_id={}, host={}, query={}, rcode={}, ioc_severity={}",
                        query.query_id, query.host, query.query, query.rcode, ioc.severity
                    ),
                    recommendation:
                        "Block the domain, investigate affected host, check for related IOCs."
                            .to_string(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn make_query(query_str: &str) -> DnsQuery {
        DnsQuery {
            query_id: "Q001".to_string(),
            timestamp: Utc.with_ymd_and_hms(2026, 1, 15, 8, 30, 0).unwrap(),
            host: "host-01".to_string(),
            user: "user1".to_string(),
            query: query_str.to_string(),
            record_type: "A".to_string(),
            response: "1.2.3.4".to_string(),
            rcode: "NOERROR".to_string(),
        }
    }

    fn make_ioc(domain: &str, severity: &str) -> IocDomain {
        IocDomain {
            indicator: domain.to_string(),
            severity: severity.to_string(),
            description: "Test IOC".to_string(),
        }
    }

    #[test]
    fn test_dns_ioc_exact_match() {
        let queries = vec![make_query("evil.com")];
        let iocs = vec![make_ioc("evil.com", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_dns_ioc(&queries, &iocs, &mut id_gen);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].rule_id.contains("SG-DNS-001"));
        assert_eq!(findings[0].severity, "high");
        // Verify timestamp is from source data, not current time
        assert!(findings[0].timestamp.starts_with("2026-01-15"));
    }

    #[test]
    fn test_dns_ioc_subdomain_match() {
        let queries = vec![make_query("sub.evil.com")];
        let iocs = vec![make_ioc("evil.com", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_dns_ioc(&queries, &iocs, &mut id_gen);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_dns_ioc_case_insensitive() {
        let queries = vec![make_query("EVIL.COM")];
        let iocs = vec![make_ioc("evil.com", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_dns_ioc(&queries, &iocs, &mut id_gen);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_dns_ioc_no_match() {
        let queries = vec![make_query("safe.example.com")];
        let iocs = vec![make_ioc("evil.com", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_dns_ioc(&queries, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_dns_ioc_empty_queries() {
        let queries = vec![];
        let iocs = vec![make_ioc("evil.com", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_dns_ioc(&queries, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_dns_ioc_empty_iocs() {
        let queries = vec![make_query("evil.com")];
        let iocs = vec![];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_dns_ioc(&queries, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_dns_ioc_multiple_matches() {
        let queries = vec![make_query("evil.com"), make_query("bad.org")];
        let iocs = vec![
            make_ioc("evil.com", "high"),
            make_ioc("bad.org", "critical"),
        ];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_dns_ioc(&queries, &iocs, &mut id_gen);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_dns_ioc_non_matching_subdomain() {
        let queries = vec![make_query("notevil.com")];
        let iocs = vec![make_ioc("evil.com", "high")];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_dns_ioc(&queries, &iocs, &mut id_gen);
        assert!(findings.is_empty());
    }
}
