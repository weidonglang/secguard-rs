use crate::detections::engine::DetectionIdGenerator;
use crate::models::Detection;
use crate::models::WindowsEvent;

/// Rule ID for suspicious PowerShell encoded command detection.
pub const SG_WIN_001: &str = "SG-WIN-001";

/// Indicators of suspicious PowerShell encoded commands (lowercase).
const SUSPICIOUS_PATTERNS: &[&str] = &["-encodedcommand", "-enc", "frombase64string"];

/// Detect suspicious PowerShell encoded commands (SG-WIN-001).
///
/// Condition: `command_line` contains `-enc`, `-encodedcommand`, or `frombase64string`
/// (case-insensitive string match only).
///
/// This detection performs purely offline log string matching.
/// It does NOT decode, generate, or execute any payload.
pub fn detect_suspicious_powershell(
    events: &[WindowsEvent],
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    let mut findings = Vec::new();

    for event in events {
        let cmd_lower = event.command_line.to_lowercase();
        let matched_pattern = SUSPICIOUS_PATTERNS.iter().find(|&&p| cmd_lower.contains(p));

        if let Some(pattern) = matched_pattern {
            // Truncate command_line to a safe summary length for evidence
            let summary = if event.command_line.len() > 80 {
                format!("{}...", &event.command_line[..80])
            } else {
                event.command_line.clone()
            };

            findings.push(Detection {
                detection_id: id_gen.generate(SG_WIN_001),
                timestamp: event.timestamp.to_rfc3339(),
                rule_id: SG_WIN_001.to_string(),
                severity: "medium".to_string(),
                entity: format!("{}@{}", event.user, event.host),
                summary: format!(
                    "Suspicious PowerShell encoded command detected on {} by user {}",
                    event.host, event.user
                ),
                evidence: format!(
                    "Pattern '{}' matched in command_line: {} [process: {}]",
                    pattern, summary, event.process
                ),
                recommendation:
                    "Review the PowerShell command execution context. Investigate encoded commands for malicious intent. Ensure PowerShell logging is enabled."
                        .to_string(),
            });
        }
    }

    findings
}

/// Run all Windows event detections.
pub fn run_windows_detections(
    events: &[WindowsEvent],
    id_gen: &mut DetectionIdGenerator,
) -> Vec<Detection> {
    let mut findings = Vec::new();

    // SG-WIN-001
    findings.extend(detect_suspicious_powershell(events, id_gen));

    crate::detections::engine::DetectionEngine::sort_findings(&mut findings);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::WindowsEvent;
    use chrono::{DateTime, Utc};

    fn make_event(
        event_id: &str,
        timestamp: DateTime<Utc>,
        host: &str,
        user: &str,
        process: &str,
        command_line: &str,
    ) -> WindowsEvent {
        WindowsEvent {
            event_id: event_id.to_string(),
            timestamp,
            host: host.to_string(),
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            user: user.to_string(),
            process: process.to_string(),
            parent_process: "explorer.exe".to_string(),
            command_line: command_line.to_string(),
            status: "success".to_string(),
        }
    }

    fn ts() -> DateTime<Utc> {
        "2026-01-01T12:00:00Z".parse::<DateTime<Utc>>().unwrap()
    }

    #[test]
    fn test_detect_encoded_command_full() {
        let events = vec![make_event(
            "W001",
            ts(),
            "SRV-WEB01",
            "jdoe",
            "powershell.exe",
            "powershell.exe -EncodedCommand SQBFAFIARQAgAEQAZQBsAGUAdABlAAoA",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_suspicious_powershell(&events, &mut id_gen);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, SG_WIN_001);
        assert_eq!(findings[0].severity, "medium");
        assert!(findings[0].evidence.contains("-encodedcommand"));
    }

    #[test]
    fn test_detect_enc_short_form() {
        let events = vec![make_event(
            "W002",
            ts(),
            "SRV-WEB02",
            "jsmith",
            "powershell.exe",
            "powershell.exe -Enc SQBFAFIARQAgAEQAZQBsAGUAdABlAA==",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_suspicious_powershell(&events, &mut id_gen);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("-enc"));
    }

    #[test]
    fn test_detect_frombase64string() {
        let events = vec![make_event(
            "W003",
            ts(),
            "SRV-WEB02",
            "jsmith",
            "powershell.exe",
            "powershell.exe -frombase64string -Command \"test\"",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_suspicious_powershell(&events, &mut id_gen);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("frombase64string"));
    }

    #[test]
    fn test_no_match_for_normal_command() {
        let events = vec![make_event(
            "W004",
            ts(),
            "SRV-WEB01",
            "jdoe",
            "cmd.exe",
            "cmd.exe /c dir c:\\users",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_suspicious_powershell(&events, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_case_insensitive_match() {
        let events = vec![make_event(
            "W005",
            ts(),
            "SRV-WEB01",
            "admin",
            "powershell.exe",
            "powershell.exe -ENCODEDCOMMAND VABlAHMAdAA=",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_suspicious_powershell(&events, &mut id_gen);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_empty_events() {
        let events = Vec::new();
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_suspicious_powershell(&events, &mut id_gen);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_non_powershell_process_ignored() {
        let events = vec![make_event(
            "W006",
            ts(),
            "SRV-DB01",
            "svc_db",
            "sqlservr.exe",
            "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe -sMSSQLSERVER",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_suspicious_powershell(&events, &mut id_gen);
        assert!(findings.is_empty(), "non-powershell should not match");
    }

    #[test]
    fn test_multiple_suspicious_events() {
        let events = vec![
            make_event(
                "W010",
                ts(),
                "SRV-WEB01",
                "user1",
                "powershell.exe",
                "powershell.exe -EncodedCommand AAA",
            ),
            make_event(
                "W011",
                ts(),
                "SRV-WEB02",
                "user2",
                "powershell.exe",
                "powershell.exe -enc BBB",
            ),
            make_event(
                "W012",
                ts(),
                "SRV-WEB03",
                "user3",
                "powershell.exe",
                "powershell.exe -frombase64string CCC",
            ),
            make_event(
                "W013",
                ts(),
                "SRV-WEB01",
                "user4",
                "cmd.exe",
                "cmd.exe /c dir",
            ),
        ];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_suspicious_powershell(&events, &mut id_gen);
        assert_eq!(findings.len(), 3, "should detect 3 suspicious commands");
        assert_eq!(findings[0].detection_id, "SG-WIN-001-0001");
        assert_eq!(findings[1].detection_id, "SG-WIN-001-0002");
        assert_eq!(findings[2].detection_id, "SG-WIN-001-0003");
    }

    #[test]
    fn test_evidence_no_raw_payload() {
        let events = vec![make_event(
            "W020",
            ts(),
            "SRV-WEB01",
            "attacker",
            "powershell.exe",
            "powershell.exe -EncodedCommand SQBFAFIARQAgAEQAZQBsAGUAdABlAAoA",
        )];
        let mut id_gen = DetectionIdGenerator::new();
        let findings = detect_suspicious_powershell(&events, &mut id_gen);
        assert_eq!(findings.len(), 1);
        // Evidence should NOT contain the decoded payload or command generation
        assert!(
            !findings[0].evidence.contains("IEX")
                && !findings[0].evidence.contains("Invoke-Expression"),
            "evidence must not contain decoded payload"
        );
    }
}
