pub mod cli;
pub mod detections;
pub mod errors;
pub mod models;
pub mod parsers;
pub mod time_utils;
pub mod validation;

pub use errors::SecGuardError;

/// Returns the application version string.
pub fn version() -> &'static str {
    "1.0.0"
}
