use crate::models::{Config, Detection, Severity};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// A stable detection ID generator using rule_id and an incrementing counter.
#[derive(Debug, Clone, Default)]
pub struct DetectionIdGenerator {
    counters: HashMap<String, u64>,
}

impl DetectionIdGenerator {
    /// Create a new generator with empty counters.
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
        }
    }

    /// Generate a stable, unique detection ID for the given rule.
    pub fn generate(&mut self, rule_id: &str) -> String {
        let counter = self.counters.entry(rule_id.to_string()).or_insert(0);
        *counter += 1;
        format!("{}-{:04}", rule_id, counter)
    }
}

/// The detection engine coordinates all detection rules.
#[derive(Debug, Clone, Default)]
pub struct DetectionEngine {
    pub config: Config,
}

impl DetectionEngine {
    /// Create a new detection engine with the given config.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Sort findings by severity (most severe first), then timestamp, then rule_id.
    pub fn sort_findings(findings: &mut [Detection]) {
        findings.sort_by(|a, b| {
            let sev_a = Severity::from_string(&a.severity).unwrap_or(Severity::Info);
            let sev_b = Severity::from_string(&b.severity).unwrap_or(Severity::Info);
            sev_b.cmp(&sev_a).then_with(|| {
                let ts_a = DateTime::parse_from_rfc3339(&a.timestamp)
                    .map(|dt| dt.to_utc())
                    .unwrap_or_else(|_| DateTime::<Utc>::MIN_UTC);
                let ts_b = DateTime::parse_from_rfc3339(&b.timestamp)
                    .map(|dt| dt.to_utc())
                    .unwrap_or_else(|_| DateTime::<Utc>::MIN_UTC);
                ts_a.cmp(&ts_b).then_with(|| a.rule_id.cmp(&b.rule_id))
            })
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_id_generator() {
        let mut gen = DetectionIdGenerator::new();
        let id1 = gen.generate("SG-AUTH-001");
        let id2 = gen.generate("SG-AUTH-001");
        let id3 = gen.generate("SG-AUTH-002");
        assert_eq!(id1, "SG-AUTH-001-0001");
        assert_eq!(id2, "SG-AUTH-001-0002");
        assert_eq!(id3, "SG-AUTH-002-0001");
    }

    #[test]
    fn test_sort_findings() {
        let mut findings = vec![
            Detection {
                detection_id: "3".to_string(),
                timestamp: "2026-01-01T01:00:00Z".to_string(),
                rule_id: "SG-AUTH-001".to_string(),
                severity: "low".to_string(),
                entity: "b".to_string(),
                summary: "".to_string(),
                evidence: "".to_string(),
                recommendation: "".to_string(),
            },
            Detection {
                detection_id: "2".to_string(),
                timestamp: "2026-01-01T01:00:00Z".to_string(),
                rule_id: "SG-AUTH-001".to_string(),
                severity: "high".to_string(),
                entity: "a".to_string(),
                summary: "".to_string(),
                evidence: "".to_string(),
                recommendation: "".to_string(),
            },
            Detection {
                detection_id: "1".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                rule_id: "SG-AUTH-001".to_string(),
                severity: "high".to_string(),
                entity: "c".to_string(),
                summary: "".to_string(),
                evidence: "".to_string(),
                recommendation: "".to_string(),
            },
        ];
        DetectionEngine::sort_findings(&mut findings);
        // First: highest severity first, then earliest timestamp
        assert_eq!(findings[0].detection_id, "1"); // high, 00:00
        assert_eq!(findings[1].detection_id, "2"); // high, 01:00
        assert_eq!(findings[2].detection_id, "3"); // low, 01:00
    }

    #[test]
    fn test_engine_default_config() {
        let engine = DetectionEngine::default();
        assert_eq!(engine.config.brute_force_threshold, Some(5));
        assert_eq!(engine.config.high_egress_threshold, Some(100_000_000));
    }

    #[test]
    fn test_empty_findings_sort() {
        let mut findings: Vec<Detection> = vec![];
        DetectionEngine::sort_findings(&mut findings);
        assert!(findings.is_empty());
    }
}
