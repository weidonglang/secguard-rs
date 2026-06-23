use std::path::PathBuf;
use thiserror::Error;

/// Unified error type for all SecGuard operations.
#[derive(Error, Debug)]
pub enum SecGuardError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("CSV parse error: {0}")]
    Csv(#[from] csv::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("WalkDir error: {0}")]
    Walk(#[from] walkdir::Error),

    #[error("CLI argument error: {0}")]
    Cli(String),

    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    #[error("Output directory does not exist: {0}")]
    OutputDirNotFound(PathBuf),

    #[error("CSV header mismatch: expected {expected:?}, got {actual:?}")]
    CsvHeaderMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },

    #[error("Timestamp parse error: {0}")]
    TimestampParse(String),

    #[error("Integer parse error: {0}")]
    IntegerParse(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Schema error: {0}")]
    Schema(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unknown format: {0}, expected one of: markdown, json, csv")]
    UnknownFormat(String),

    #[error("{0}")]
    Msg(String),
}

pub type SecGuardResult<T> = Result<T, SecGuardError>;
