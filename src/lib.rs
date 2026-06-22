pub mod cli;
pub mod errors;

pub use errors::SecGuardError;

/// Returns the application version string.
pub fn version() -> &'static str {
    "1.0.0"
}
