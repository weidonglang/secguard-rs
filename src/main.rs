use clap::Parser;
use secguard::cli::Cli;
use secguard::errors::{SecGuardError, SecGuardResult};
use std::path::Path;

fn check_input_file(path_str: &str) -> SecGuardResult<()> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Err(SecGuardError::FileNotFound(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_output_dir(path_str: &str) -> SecGuardResult<()> {
    let path = Path::new(path_str);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Err(SecGuardError::OutputDirNotFound(parent.to_path_buf()));
        }
    }
    Ok(())
}

fn write_report(output: &Option<String>, content: &str) -> SecGuardResult<()> {
    if let Some(out_path) = output {
        ensure_output_dir(out_path)?;
        std::fs::write(out_path, content)?;
        println!("Report written to: {}", out_path);
    } else {
        println!("{}", content);
    }
    Ok(())
}

fn main() -> SecGuardResult<()> {
    let cli = Cli::parse();
    match &cli.command {
        secguard::cli::Commands::Schema { kind } => {
            handle_schema(kind)?;
        }
        secguard::cli::Commands::Check { kind, input } => {
            handle_check(kind, input)?;
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
            check_input_file(input)?;
            let _events = secguard::parsers::auth_events::parse_auth_events(Path::new(input))?;
            println!("Schema validation passed for auth events: {}", input);
            Ok(())
        }
        secguard::cli::SchemaKind::Network { input } => {
            check_input_file(input)?;
            let _events = secguard::parsers::network_flows::parse_network_flows(Path::new(input))?;
            println!("Schema validation passed for network flows: {}", input);
            Ok(())
        }
        secguard::cli::SchemaKind::Dns { input } => {
            check_input_file(input)?;
            let _queries = secguard::parsers::dns_queries::parse_dns_queries(Path::new(input))?;
            println!("Schema validation passed for DNS queries: {}", input);
            Ok(())
        }
        secguard::cli::SchemaKind::Windows { input } => {
            check_input_file(input)?;
            let _events =
                secguard::parsers::windows_events::parse_windows_events(Path::new(input))?;
            println!("Schema validation passed for Windows events: {}", input);
            Ok(())
        }
        secguard::cli::SchemaKind::FileHashes { input } => {
            check_input_file(input)?;
            let _hashes = secguard::parsers::file_hashes::parse_file_hashes(Path::new(input))?;
            println!("Schema validation passed for file hashes: {}", input);
            Ok(())
        }
        secguard::cli::SchemaKind::IocDomains { input } => {
            check_input_file(input)?;
            let _domains = secguard::parsers::iocs::parse_ioc_domains(Path::new(input))?;
            println!("Schema validation passed for IOC domains: {}", input);
            Ok(())
        }
        secguard::cli::SchemaKind::IocIps { input } => {
            check_input_file(input)?;
            let _ips = secguard::parsers::iocs::parse_ioc_ips(Path::new(input))?;
            println!("Schema validation passed for IOC IPs: {}", input);
            Ok(())
        }
        secguard::cli::SchemaKind::IocHashes { input } => {
            check_input_file(input)?;
            let _hashes = secguard::parsers::iocs::parse_ioc_hashes(Path::new(input))?;
            println!("Schema validation passed for IOC hashes: {}", input);
            Ok(())
        }
    }
}

/// Handle `schema check --kind <kind> --input <path>` compatibility command.
/// Maps to the same parser logic as the `schema <kind>` subcommand.
fn handle_check(kind: &str, input: &str) -> SecGuardResult<()> {
    check_input_file(input)?;
    let path = Path::new(input);
    match kind.to_lowercase().as_str() {
        "auth" => {
            let _events = secguard::parsers::auth_events::parse_auth_events(path)?;
        }
        "network" | "netflow" | "network-flows" => {
            let _events = secguard::parsers::network_flows::parse_network_flows(path)?;
        }
        "dns" => {
            let _queries = secguard::parsers::dns_queries::parse_dns_queries(path)?;
        }
        "windows" => {
            let _events = secguard::parsers::windows_events::parse_windows_events(path)?;
        }
        "file-hashes" | "filehashes" => {
            let _hashes = secguard::parsers::file_hashes::parse_file_hashes(path)?;
        }
        "ioc-domains" | "iocdomains" => {
            let _domains = secguard::parsers::iocs::parse_ioc_domains(path)?;
        }
        "ioc-ips" | "iocips" => {
            let _ips = secguard::parsers::iocs::parse_ioc_ips(path)?;
        }
        "ioc-hashes" | "iochashes" => {
            let _hashes = secguard::parsers::iocs::parse_ioc_hashes(path)?;
        }
        other => {
            return Err(SecGuardError::InvalidArgument(format!(
                "Unknown schema kind: {}. Valid kinds: auth, network, dns, windows, file-hashes, ioc-domains, ioc-ips, ioc-hashes",
                other
            )));
        }
    }
    println!("Schema validation passed for {}: {}", kind, input);
    Ok(())
}

fn handle_analyze(kind: &secguard::cli::AnalyzeKind) -> SecGuardResult<()> {
    match kind {
        secguard::cli::AnalyzeKind::Auth { input, output } => {
            check_input_file(input)?;
            let events = secguard::parsers::auth_events::parse_auth_events(Path::new(input))?;
            let config = secguard::models::Config::default();
            let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
            let mut findings = secguard::detections::brute_force::run_auth_detections(
                &events,
                &config,
                &mut id_gen,
            );
            secguard::detections::engine::DetectionEngine::sort_findings(&mut findings);
            let summary = secguard::models::ReportSummary::new(input.to_string(), findings);
            let report = secguard::reports::markdown::generate_markdown_report(&summary)?;
            write_report(output, &report)?;
            Ok(())
        }
        secguard::cli::AnalyzeKind::Network { input, output } => {
            check_input_file(input)?;
            let events = secguard::parsers::network_flows::parse_network_flows(Path::new(input))?;
            let config = secguard::models::Config::default();
            let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
            let mut findings = secguard::detections::network_egress::run_network_detections(
                &events,
                &config,
                &mut id_gen,
            );
            secguard::detections::engine::DetectionEngine::sort_findings(&mut findings);
            let summary = secguard::models::ReportSummary::new(input.to_string(), findings);
            let report = secguard::reports::markdown::generate_markdown_report(&summary)?;
            write_report(output, &report)?;
            Ok(())
        }
        secguard::cli::AnalyzeKind::Dns {
            dns,
            ioc_domains,
            output,
        } => {
            check_input_file(dns)?;
            let queries = secguard::parsers::dns_queries::parse_dns_queries(Path::new(dns))?;
            let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
            let mut all_findings = Vec::new();

            if let Some(domains_path) = ioc_domains {
                check_input_file(domains_path)?;
                let ioc_domains_list =
                    secguard::parsers::iocs::parse_ioc_domains(Path::new(domains_path))?;
                let dns_findings = secguard::detections::dns_ioc::detect_dns_ioc(
                    &queries,
                    &ioc_domains_list,
                    &mut id_gen,
                );
                all_findings.extend(dns_findings);
            }

            secguard::detections::engine::DetectionEngine::sort_findings(&mut all_findings);
            let summary = secguard::models::ReportSummary::new(dns.to_string(), all_findings);
            let report = secguard::reports::markdown::generate_markdown_report(&summary)?;
            write_report(output, &report)?;
            Ok(())
        }
        secguard::cli::AnalyzeKind::Windows { input, output } => {
            check_input_file(input)?;
            let events = secguard::parsers::windows_events::parse_windows_events(Path::new(input))?;
            let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
            let mut findings = secguard::detections::suspicious_powershell::run_windows_detections(
                &events,
                &mut id_gen,
            );
            secguard::detections::engine::DetectionEngine::sort_findings(&mut findings);
            let summary = secguard::models::ReportSummary::new(input.to_string(), findings);
            let report = secguard::reports::markdown::generate_markdown_report(&summary)?;
            write_report(output, &report)?;
            Ok(())
        }
    }
}

fn handle_ioc(kind: &secguard::cli::IocKind) -> SecGuardResult<()> {
    match kind {
        secguard::cli::IocKind::Match {
            dns,
            ips,
            domains,
            hashes,
            flows,
            file_hashes,
        } => {
            let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
            let mut all_findings = Vec::new();

            // DNS IOC matching
            if let Some(dns_path) = dns {
                check_input_file(dns_path)?;
                let queries =
                    secguard::parsers::dns_queries::parse_dns_queries(Path::new(dns_path))?;
                if let Some(domains_path) = domains {
                    check_input_file(domains_path)?;
                    let ioc_domains =
                        secguard::parsers::iocs::parse_ioc_domains(Path::new(domains_path))?;
                    let findings = secguard::detections::dns_ioc::detect_dns_ioc(
                        &queries,
                        &ioc_domains,
                        &mut id_gen,
                    );
                    all_findings.extend(findings);
                }
            }

            // IP IOC matching (requires network flow data)
            if let Some(ips_path) = ips {
                check_input_file(ips_path)?;
                let ioc_ips = secguard::parsers::iocs::parse_ioc_ips(Path::new(ips_path))?;
                if let Some(flows_path) = flows {
                    check_input_file(flows_path)?;
                    let flow_events = secguard::parsers::network_flows::parse_network_flows(
                        Path::new(flows_path),
                    )?;
                    let findings = secguard::detections::ip_ioc::detect_ip_ioc(
                        &flow_events,
                        &ioc_ips,
                        &mut id_gen,
                    );
                    all_findings.extend(findings);
                } else {
                    println!(
                        "IOC IP file loaded: {} ({} indicators). Use --flows to match against network flows.",
                        ips_path,
                        ioc_ips.len()
                    );
                }
            }

            // Hash IOC matching (requires file hash data)
            if let Some(hashes_path) = hashes {
                check_input_file(hashes_path)?;
                let ioc_hashes = secguard::parsers::iocs::parse_ioc_hashes(Path::new(hashes_path))?;
                if let Some(file_hashes_path) = file_hashes {
                    check_input_file(file_hashes_path)?;
                    let file_hash_entries = secguard::parsers::file_hashes::parse_file_hashes(
                        Path::new(file_hashes_path),
                    )?;
                    let findings = secguard::detections::hash_ioc::detect_hash_ioc(
                        &file_hash_entries,
                        &ioc_hashes,
                        &mut id_gen,
                    );
                    all_findings.extend(findings);
                } else {
                    println!(
                        "IOC hash file loaded: {} ({} indicators). Use --file-hashes to match against file hashes.",
                        hashes_path,
                        ioc_hashes.len()
                    );
                }
            }

            // Print IOC matching results
            if all_findings.is_empty() {
                println!("No IOC matches found.");
            } else {
                secguard::detections::engine::DetectionEngine::sort_findings(&mut all_findings);
                println!("IOC Match Results ({} total):", all_findings.len());
                for finding in &all_findings {
                    println!(
                        "- {} [{}] {}: {}",
                        finding.detection_id, finding.severity, finding.rule_id, finding.summary
                    );
                }
            }

            Ok(())
        }
    }
}

fn handle_integrity(kind: &secguard::cli::IntegrityKind) -> SecGuardResult<()> {
    match kind {
        secguard::cli::IntegrityKind::Baseline { path, output } => {
            let scan_path = Path::new(path);
            if !scan_path.exists() {
                return Err(SecGuardError::FileNotFound(scan_path.to_path_buf()));
            }
            let entries = secguard::integrity::baseline::generate_baseline(scan_path)?;
            if let Some(out_path) = output {
                ensure_output_dir(out_path)?;
                secguard::integrity::baseline::write_baseline_csv(Path::new(out_path), &entries)?;
                println!(
                    "Baseline written to: {} ({} files)",
                    out_path,
                    entries.len()
                );
            } else {
                println!(
                    "Baseline generated ({} files). Use --output to save.",
                    entries.len()
                );
                for e in &entries {
                    println!("{}  {}", e.sha256, e.path);
                }
            }
            Ok(())
        }
        secguard::cli::IntegrityKind::Verify {
            baseline,
            path,
            output,
        } => {
            check_input_file(baseline)?;
            let scan_path = Path::new(path);
            if !scan_path.exists() {
                return Err(SecGuardError::FileNotFound(scan_path.to_path_buf()));
            }
            let mut id_gen = secguard::detections::engine::DetectionIdGenerator::new();
            let mut findings = secguard::detections::file_integrity::run_file_integrity_detections(
                Path::new(baseline),
                scan_path,
                &mut id_gen,
            )?;
            secguard::detections::engine::DetectionEngine::sort_findings(&mut findings);
            let summary = secguard::models::ReportSummary::new(
                format!("baseline={},path={}", baseline, path),
                findings,
            );
            let report = secguard::reports::markdown::generate_markdown_report(&summary)?;
            write_report(output, &report)?;
            Ok(())
        }
    }
}

fn handle_report(kind: &secguard::cli::ReportKind) -> SecGuardResult<()> {
    match kind {
        secguard::cli::ReportKind::Summarize {
            input,
            format,
            output,
        } => {
            check_input_file(input)?;
            let fmt = format.as_deref().unwrap_or("markdown");
            let report = secguard::reports::summary::generate_summary(Path::new(input), fmt)?;
            write_report(output, &report)?;
            Ok(())
        }
    }
}
