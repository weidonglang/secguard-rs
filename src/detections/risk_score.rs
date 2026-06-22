use crate::models::Severity;
use std::collections::HashMap;

/// Risk score weights for each severity level.
const RISK_WEIGHTS: &[(Severity, u64)] = &[
    (Severity::Info, 1),
    (Severity::Low, 2),
    (Severity::Medium, 4),
    (Severity::High, 7),
    (Severity::Critical, 10),
];

/// Maximum risk score cap.
pub const MAX_RISK_SCORE: u64 = 100;

/// Compute the total risk score from a map of severity to count.
/// The score is the sum of (weight * count) for each severity, capped at MAX_RISK_SCORE.
pub fn compute_risk_score(severity_counts: &HashMap<Severity, u64>) -> u64 {
    let mut total: u64 = 0;
    for (sev, count) in severity_counts {
        if let Some(weight) = get_weight(sev) {
            total = total.saturating_add(weight.saturating_mul(*count));
        }
    }
    total.min(MAX_RISK_SCORE)
}

/// Get the weight for a severity level.
pub fn get_weight(severity: &Severity) -> Option<u64> {
    RISK_WEIGHTS
        .iter()
        .find(|(s, _)| s == severity)
        .map(|(_, w)| *w)
}

/// Convert a risk score to a severity label string.
pub fn score_to_severity_label(score: u64) -> &'static str {
    if score >= 70 {
        "critical"
    } else if score >= 40 {
        "high"
    } else if score >= 20 {
        "medium"
    } else if score >= 5 {
        "low"
    } else {
        "info"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_weight() {
        assert_eq!(get_weight(&Severity::Info), Some(1));
        assert_eq!(get_weight(&Severity::Low), Some(2));
        assert_eq!(get_weight(&Severity::Medium), Some(4));
        assert_eq!(get_weight(&Severity::High), Some(7));
        assert_eq!(get_weight(&Severity::Critical), Some(10));
    }

    #[test]
    fn test_compute_risk_score_single() {
        let mut counts = HashMap::new();
        counts.insert(Severity::High, 3);
        assert_eq!(compute_risk_score(&counts), 21);
    }

    #[test]
    fn test_compute_risk_score_mixed() {
        let mut counts = HashMap::new();
        counts.insert(Severity::Info, 10);
        counts.insert(Severity::Medium, 2);
        counts.insert(Severity::Critical, 1);
        // 10*1 + 2*4 + 1*10 = 10 + 8 + 10 = 28
        assert_eq!(compute_risk_score(&counts), 28);
    }

    #[test]
    fn test_compute_risk_score_capped() {
        let mut counts = HashMap::new();
        counts.insert(Severity::Critical, 20); // 20*10 = 200
        assert_eq!(compute_risk_score(&counts), MAX_RISK_SCORE);
    }

    #[test]
    fn test_score_to_severity_label() {
        assert_eq!(score_to_severity_label(0), "info");
        assert_eq!(score_to_severity_label(5), "low");
        assert_eq!(score_to_severity_label(20), "medium");
        assert_eq!(score_to_severity_label(40), "high");
        assert_eq!(score_to_severity_label(70), "critical");
    }

    #[test]
    fn test_empty_counts() {
        let counts = HashMap::new();
        assert_eq!(compute_risk_score(&counts), 0);
        assert_eq!(score_to_severity_label(0), "info");
    }
}
