use crate::errors::{SecGuardError, SecGuardResult};
use chrono::{DateTime, NaiveDateTime, Utc};

/// Parse a UTC timestamp string in format YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DD HH:MM:SS.
pub fn parse_utc_timestamp(s: &str) -> SecGuardResult<DateTime<Utc>> {
    // Try ISO 8601 format first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try YYYY-MM-DDTHH:MM:SSZ (without timezone offset)
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ") {
        return Ok(DateTime::from_naive_utc_and_offset(dt, Utc));
    }

    // Try YYYY-MM-DD HH:MM:SS
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Ok(DateTime::from_naive_utc_and_offset(dt, Utc));
    }

    Err(SecGuardError::TimestampParse(s.to_string()))
}

/// Parse a u16 integer from string.
pub fn parse_u16(s: &str) -> SecGuardResult<u16> {
    s.trim()
        .parse::<u16>()
        .map_err(|e| SecGuardError::IntegerParse(format!("invalid u16 '{}': {}", s, e)))
}

/// Parse a u64 integer from string.
pub fn parse_u64(s: &str) -> SecGuardResult<u64> {
    s.trim()
        .parse::<u64>()
        .map_err(|e| SecGuardError::IntegerParse(format!("invalid u64 '{}': {}", s, e)))
}

/// Parse a u32 integer from string.
pub fn parse_u32(s: &str) -> SecGuardResult<u32> {
    s.trim()
        .parse::<u32>()
        .map_err(|e| SecGuardError::IntegerParse(format!("invalid u32 '{}': {}", s, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc3339_timestamp() {
        let result = parse_utc_timestamp("2026-06-22T10:30:00Z");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "2026-06-22T10:30:00Z"
        );
    }

    #[test]
    fn test_parse_naive_timestamp() {
        let result = parse_utc_timestamp("2026-06-22 10:30:00");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_bad_timestamp() {
        let result = parse_utc_timestamp("not-a-timestamp");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_u16_valid() {
        assert_eq!(parse_u16("8080").unwrap(), 8080);
    }

    #[test]
    fn test_parse_u16_invalid() {
        assert!(parse_u16("not-a-number").is_err());
    }

    #[test]
    fn test_parse_u16_overflow() {
        assert!(parse_u16("99999").is_err());
    }

    #[test]
    fn test_parse_u64_valid() {
        assert_eq!(parse_u64("100000000").unwrap(), 100000000);
    }
}
