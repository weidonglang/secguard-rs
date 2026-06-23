use std::process::Command;

fn secguard_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_secguard"))
}

#[test]
fn test_cli_help() {
    let output = secguard_bin()
        .arg("--help")
        .output()
        .expect("Failed to run secguard --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("secguard") || stdout.contains("SecGuard"));
    assert!(stdout.contains("schema"));
    assert!(stdout.contains("analyze"));
    assert!(stdout.contains("ioc"));
    assert!(stdout.contains("integrity"));
    assert!(stdout.contains("report"));
}

#[test]
fn test_cli_schema_help() {
    let output = secguard_bin()
        .args(["schema", "--help"])
        .output()
        .expect("Failed to run secguard schema --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("auth"));
    assert!(stdout.contains("network"));
    assert!(stdout.contains("dns"));
    assert!(stdout.contains("windows"));
    assert!(stdout.contains("file-hashes"));
}

#[test]
fn test_cli_analyze_help() {
    let output = secguard_bin()
        .args(["analyze", "--help"])
        .output()
        .expect("Failed to run secguard analyze --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("auth"));
    assert!(stdout.contains("network"));
    assert!(stdout.contains("dns"));
    assert!(stdout.contains("windows"));
}

#[test]
fn test_cli_ioc_help() {
    let output = secguard_bin()
        .args(["ioc", "--help"])
        .output()
        .expect("Failed to run secguard ioc --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("match") || stdout.contains("Match"));
}

#[test]
fn test_cli_integrity_help() {
    let output = secguard_bin()
        .args(["integrity", "--help"])
        .output()
        .expect("Failed to run secguard integrity --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("baseline") || stdout.contains("Baseline"));
    assert!(stdout.contains("verify") || stdout.contains("Verify"));
}

#[test]
fn test_cli_report_help() {
    let output = secguard_bin()
        .args(["report", "--help"])
        .output()
        .expect("Failed to run secguard report --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("summarize") || stdout.contains("Summarize"));
}

#[test]
fn test_cli_version() {
    let output = secguard_bin()
        .arg("--version")
        .output()
        .expect("Failed to run secguard --version");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1.0.0"));
}

#[test]
fn test_schema_auth_missing_file() {
    let output = secguard_bin()
        .args(["schema", "auth", "--input", "nonexistent.csv"])
        .output()
        .expect("Failed to run schema auth");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FileNotFound") || stderr.contains("error") || stderr.contains("Error")
    );
}

#[test]
fn test_analyze_auth_missing_file() {
    let output = secguard_bin()
        .args(["analyze", "auth", "--input", "nonexistent.csv"])
        .output()
        .expect("Failed to run analyze auth");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FileNotFound") || stderr.contains("error") || stderr.contains("Error")
    );
}

#[test]
fn test_integrity_baseline_missing_path() {
    let output = secguard_bin()
        .args(["integrity", "baseline", "--path", "nonexistent_dir"])
        .output()
        .expect("Failed to run integrity baseline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FileNotFound") || stderr.contains("error") || stderr.contains("Error")
    );
}

#[test]
fn test_report_summarize_missing_file() {
    let output = secguard_bin()
        .args(["report", "summarize", "--input", "nonexistent.csv"])
        .output()
        .expect("Failed to run report summarize");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FileNotFound") || stderr.contains("error") || stderr.contains("Error")
    );
}

#[test]
fn test_schema_auth_valid_file() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("auth_events.csv");
    let output = secguard_bin()
        .args(["schema", "auth", "--input", path.to_str().unwrap()])
        .output()
        .expect("Failed to run schema auth on valid file");
    assert!(
        output.status.success(),
        "stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_analyze_auth_valid_file() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("auth_events.csv");
    let output = secguard_bin()
        .args(["analyze", "auth", "--input", path.to_str().unwrap()])
        .output()
        .expect("Failed to run analyze auth on valid file");
    assert!(
        output.status.success(),
        "stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_analyze_auth_output_to_stdout() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("auth_events.csv");
    let output = secguard_bin()
        .args(["analyze", "auth", "--input", path.to_str().unwrap()])
        .output()
        .expect("Failed to run analyze auth");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should have markdown content - look for report structure
    assert!(
        stdout.contains("#")
            || stdout.contains("Security")
            || stdout.contains("Report")
            || stdout.contains("Finding")
    );
}

#[test]
fn test_schema_network_valid_file() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("network_flows.csv");
    let output = secguard_bin()
        .args(["schema", "network", "--input", path.to_str().unwrap()])
        .output()
        .expect("Failed to run schema network");
    assert!(
        output.status.success(),
        "stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_schema_dns_valid_file() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("dns_queries.csv");
    let output = secguard_bin()
        .args(["schema", "dns", "--input", path.to_str().unwrap()])
        .output()
        .expect("Failed to run schema dns");
    assert!(
        output.status.success(),
        "stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_schema_windows_valid_file() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("windows_events.csv");
    let output = secguard_bin()
        .args(["schema", "windows", "--input", path.to_str().unwrap()])
        .output()
        .expect("Failed to run schema windows");
    assert!(
        output.status.success(),
        "stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_schema_file_hashes_valid_file() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("file_hashes.csv");
    let output = secguard_bin()
        .args(["schema", "file-hashes", "--input", path.to_str().unwrap()])
        .output()
        .expect("Failed to run schema file-hashes");
    assert!(
        output.status.success(),
        "stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_schema_ioc_domains_valid_file() {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("ioc_domains.csv");
    let output = secguard_bin()
        .args(["schema", "ioc-domains", "--input", path.to_str().unwrap()])
        .output()
        .expect("Failed to run schema ioc-domains");
    assert!(
        output.status.success(),
        "stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_invalid_command_returns_error() {
    let output = secguard_bin()
        .arg("nonexistent-command")
        .output()
        .expect("Failed to run secguard with bad command");
    assert!(!output.status.success());
}

#[test]
fn test_schema_auth_header_mismatch_returns_error() {
    // Use network flows file with auth schema checker — should fail
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("network_flows.csv");
    let output = secguard_bin()
        .args(["schema", "auth", "--input", path.to_str().unwrap()])
        .output()
        .expect("Failed to run schema auth on wrong file type");
    assert!(
        !output.status.success(),
        "Expected error for header mismatch"
    );
}

#[test]
fn test_ioc_match_minimal() {
    let mut dns = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dns.push("examples");
    dns.push("dns_queries.csv");

    let mut domains = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    domains.push("examples");
    domains.push("ioc_domains.csv");

    let output = secguard_bin()
        .args([
            "ioc",
            "match",
            "--dns",
            dns.to_str().unwrap(),
            "--domains",
            domains.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run ioc match");
    assert!(
        output.status.success(),
        "stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
