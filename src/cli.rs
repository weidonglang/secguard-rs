use clap::{Parser, Subcommand};

/// SecGuard RS — A defensive Rust cybersecurity CLI for offline log analysis,
/// IOC matching, integrity checking, and report generation.
#[derive(Parser, Debug)]
#[command(name = "secguard")]
#[command(version = "1.0.0")]
#[command(about = "Defensive cybersecurity CLI for offline analysis")]
#[command(
    long_about = "SecGuard RS is a defensive Rust cybersecurity CLI for offline log analysis,\nIOC matching, integrity checking, and report generation.\n\nThis tool only processes local files. It does not make network connections,\nscan ports, or execute attack payloads."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Validate CSV schema against data dictionary
    Schema {
        #[command(subcommand)]
        kind: SchemaKind,
    },

    /// Analyze security logs for threats
    Analyze {
        #[command(subcommand)]
        kind: AnalyzeKind,
    },

    /// Match indicators of compromise
    Ioc {
        #[command(subcommand)]
        kind: IocKind,
    },

    /// File integrity baseline and verification
    Integrity {
        #[command(subcommand)]
        kind: IntegrityKind,
    },

    /// Generate summary reports
    Report {
        #[command(subcommand)]
        kind: ReportKind,
    },
}

#[derive(Subcommand, Debug)]
pub enum SchemaKind {
    /// Validate auth events CSV schema
    Auth {
        /// Path to auth_events.csv
        #[arg(long)]
        input: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AnalyzeKind {
    /// Analyze authentication logs
    Auth {
        /// Path to auth_events.csv
        #[arg(long)]
        input: String,
        /// Output report path
        #[arg(long)]
        output: Option<String>,
    },
    /// Analyze network flow logs
    Network {
        /// Path to network_flows.csv
        #[arg(long)]
        input: String,
        /// Output report path
        #[arg(long)]
        output: Option<String>,
    },
    /// Analyze DNS query logs
    Dns {
        /// Path to dns_queries.csv
        #[arg(long)]
        dns: String,
        /// Path to ioc_domains.csv
        #[arg(long)]
        ioc_domains: Option<String>,
        /// Output report path
        #[arg(long)]
        output: Option<String>,
    },
    /// Analyze Windows event logs
    Windows {
        /// Path to windows_events.csv
        #[arg(long)]
        input: String,
        /// Output report path
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum IocKind {
    /// Match DNS queries against IOC indicators
    Match {
        /// Path to dns_queries.csv
        #[arg(long)]
        dns: Option<String>,
        /// Path to ioc_ips.csv
        #[arg(long)]
        ips: Option<String>,
        /// Path to ioc_domains.csv
        #[arg(long)]
        domains: Option<String>,
        /// Path to ioc_hashes.csv
        #[arg(long)]
        hashes: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum IntegrityKind {
    /// Generate SHA256 baseline for files
    Baseline {
        /// Directory path to scan
        #[arg(long)]
        path: String,
        /// Output baseline CSV path
        #[arg(long)]
        output: Option<String>,
    },
    /// Verify files against a baseline
    Verify {
        /// Path to baseline CSV
        #[arg(long)]
        baseline: String,
        /// Directory path to verify
        #[arg(long)]
        path: String,
        /// Output report path
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ReportKind {
    /// Generate summary from detection findings
    Summarize {
        /// Path to detection findings (CSV or JSON)
        #[arg(long)]
        input: String,
        /// Output format: markdown, json, csv
        #[arg(long)]
        format: Option<String>,
        /// Output report path
        #[arg(long)]
        output: Option<String>,
    },
}
