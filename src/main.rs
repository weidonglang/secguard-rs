use clap::Parser;
use secguard::cli::Cli;
use secguard::errors::{SecGuardError, SecGuardResult};

fn main() -> SecGuardResult<()> {
    let cli = Cli::parse();
    match &cli.command {
        secguard::cli::Commands::Schema { kind } => {
            handle_schema(kind)?;
        }
        secguard::cli::Commands::Analyze { kind } => {
            handle_analyze(kind)?;
        }
        secguard::cli::Commands::Ioc { kind } => {
            handle_ioc(kind)?;
        }
        secguard::cli::Commands::Integrity { kind } => {
            handle_integrity(kind)?;
        }
        secguard::cli::Commands::Report { kind } => {
            handle_report(kind)?;
        }
    }
    Ok(())
}

fn handle_schema(kind: &secguard::cli::SchemaKind) -> SecGuardResult<()> {
    match kind {
        secguard::cli::SchemaKind::Auth { input } => {
            // Placeholder: will validate CSV auth schema later
            if !std::path::Path::new(input).exists() {
                return Err(SecGuardError::FileNotFound(std::path::PathBuf::from(input)));
            }
            println!("Schema validation passed for: {}", input);
            Ok(())
        }
    }
}

fn handle_analyze(kind: &secguard::cli::AnalyzeKind) -> SecGuardResult<()> {
    match kind {
        secguard::cli::AnalyzeKind::Auth { input, output: _ } => {
            if !std::path::Path::new(input).exists() {
                return Err(SecGuardError::FileNotFound(std::path::PathBuf::from(input)));
            }
            println!("Analyze auth: {}", input);
            Ok(())
        }
        secguard::cli::AnalyzeKind::Network { input, output: _ } => {
            if !std::path::Path::new(input).exists() {
                return Err(SecGuardError::FileNotFound(std::path::PathBuf::from(input)));
            }
            println!("Analyze network: {}", input);
            Ok(())
        }
        secguard::cli::AnalyzeKind::Dns {
            dns,
            ioc_domains: _,
            output: _,
        } => {
            if !std::path::Path::new(dns).exists() {
                return Err(SecGuardError::FileNotFound(std::path::PathBuf::from(dns)));
            }
            println!("Analyze DNS: {}", dns);
            Ok(())
        }
        secguard::cli::AnalyzeKind::Windows { input, output: _ } => {
            if !std::path::Path::new(input).exists() {
                return Err(SecGuardError::FileNotFound(std::path::PathBuf::from(input)));
            }
            println!("Analyze Windows events: {}", input);
            Ok(())
        }
    }
}

fn handle_ioc(kind: &secguard::cli::IocKind) -> SecGuardResult<()> {
    match kind {
        secguard::cli::IocKind::Match {
            dns: _,
            ips: _,
            domains: _,
            hashes: _,
        } => {
            println!("IOC matching (placeholder)");
            Ok(())
        }
    }
}

fn handle_integrity(kind: &secguard::cli::IntegrityKind) -> SecGuardResult<()> {
    match kind {
        secguard::cli::IntegrityKind::Baseline { path, output: _ } => {
            if !std::path::Path::new(path).exists() {
                return Err(SecGuardError::FileNotFound(std::path::PathBuf::from(path)));
            }
            println!("Integrity baseline: {}", path);
            Ok(())
        }
        secguard::cli::IntegrityKind::Verify {
            baseline,
            path: _,
            output: _,
        } => {
            if !std::path::Path::new(baseline).exists() {
                return Err(SecGuardError::FileNotFound(std::path::PathBuf::from(
                    baseline,
                )));
            }
            println!("Integrity verify: {}", baseline);
            Ok(())
        }
    }
}

fn handle_report(kind: &secguard::cli::ReportKind) -> SecGuardResult<()> {
    match kind {
        secguard::cli::ReportKind::Summarize {
            input,
            format: _,
            output: _,
        } => {
            if !std::path::Path::new(input).exists() {
                return Err(SecGuardError::FileNotFound(std::path::PathBuf::from(input)));
            }
            println!("Report summarize: {}", input);
            Ok(())
        }
    }
}
