use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Auth event log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub source_host: String,
    pub user: String,
    pub source_ip: String,
    pub action: String,
    pub auth_method: String,
    pub status: String,
    pub reason: String,
}

/// Network flow log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub flow_id: String,
    pub timestamp: DateTime<Utc>,
    pub src_host: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub action: String,
    pub process: String,
}

/// DNS query log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub user: String,
    pub query: String,
    pub record_type: String,
    pub response: String,
    pub rcode: String,
}

/// Windows event log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub provider: String,
    pub user: String,
    pub process: String,
    pub parent_process: String,
    pub command_line: String,
    pub status: String,
}

/// File hash entry for integrity baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub modified_utc: String,
}

/// IOC domain entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocDomain {
    pub indicator: String,
    pub severity: String,
    pub description: String,
}

/// IOC IP entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocIp {
    pub indicator: String,
    pub severity: String,
    pub description: String,
}

/// IOC hash entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocHash {
    pub sha256: String,
    pub severity: String,
    pub description: String,
}

/// Detection finding output entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub detection_id: String,
    pub timestamp: String,
    pub rule_id: String,
    pub severity: String,
    pub entity: String,
    pub summary: String,
    pub evidence: String,
    pub recommendation: String,
}

/// Configuration for analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub brute_force_threshold: Option<u32>,
    pub brute_force_window_minutes: Option<i64>,
    pub password_spray_user_threshold: Option<u32>,
    pub blocked_burst_threshold: Option<u32>,
    pub blocked_burst_window_minutes: Option<i64>,
    pub high_egress_threshold: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            brute_force_threshold: Some(5),
            brute_force_window_minutes: Some(10),
            password_spray_user_threshold: Some(5),
            blocked_burst_threshold: Some(10),
            blocked_burst_window_minutes: Some(15),
            high_egress_threshold: Some(100_000_000),
        }
    }
}

/// Severity levels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parse severity from string.
    pub fn from_string(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Return string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Analysis summary for reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub generated_by: String,
    pub version: String,
    pub input_summary: String,
    pub finding_count: usize,
    pub findings: Vec<Detection>,
}

impl ReportSummary {
    /// Create a new report summary.
    pub fn new(input_summary: String, findings: Vec<Detection>) -> Self {
        Self {
            generated_by: "SecGuard RS".to_string(),
            version: "1.0.0".to_string(),
            input_summary,
            finding_count: findings.len(),
            findings,
        }
    }
}
