use std::path::PathBuf;
use std::process::Command;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn examples_path() -> PathBuf {
    let mut p = project_root();
    p.push("examples");
    p
}

#[test]
fn test_ioc_dns_match_integration() {
    let dns_csv = examples_path().join("dns_queries.csv");
    let domains_csv = examples_path().join("ioc_domains.csv");
    let ips_csv = examples_path().join("ioc_ips.csv");
    let hashes_csv = examples_path().join("ioc_hashes.csv");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secguard"));
    cmd.arg("ioc")
        .arg("match")
        .arg("--dns")
        .arg(dns_csv.to_str().unwrap())
        .arg("--domains")
        .arg(domains_csv.to_str().unwrap())
        .arg("--ips")
        .arg(ips_csv.to_str().unwrap())
        .arg("--hashes")
        .arg(hashes_csv.to_str().unwrap());

    let output = cmd.output().expect("Failed to execute secguard ioc match");
    assert!(
        output.status.success(),
        "secguard ioc match failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("IOC Match Results") || stdout.contains("No IOC matches found"));
}

#[test]
fn test_ioc_match_nonexistent_dns_file() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secguard"));
    cmd.arg("ioc")
        .arg("match")
        .arg("--dns")
        .arg("nonexistent_dns.csv");
    let output = cmd.output().expect("Failed to execute");
    assert!(!output.status.success());
}

#[test]
fn test_ioc_match_nonexistent_domains_file() {
    let dns_csv = examples_path().join("dns_queries.csv");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secguard"));
    cmd.arg("ioc")
        .arg("match")
        .arg("--dns")
        .arg(dns_csv.to_str().unwrap())
        .arg("--domains")
        .arg("nonexistent_domains.csv");
    let output = cmd.output().expect("Failed to execute");
    assert!(!output.status.success());
}

#[test]
fn test_ioc_help_available() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secguard"));
    cmd.arg("ioc").arg("match").arg("--help");
    let output = cmd.output().expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--dns"));
    assert!(stdout.contains("--domains"));
    assert!(stdout.contains("--ips"));
    assert!(stdout.contains("--hashes"));
}

#[test]
fn test_ioc_match_ips_only() {
    let ips_csv = examples_path().join("ioc_ips.csv");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secguard"));
    cmd.arg("ioc")
        .arg("match")
        .arg("--ips")
        .arg(ips_csv.to_str().unwrap());
    let output = cmd.output().expect("Failed to execute");
    assert!(
        output.status.success(),
        "secguard ioc match (ips only) failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_ioc_match_hashes_only() {
    let hashes_csv = examples_path().join("ioc_hashes.csv");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secguard"));
    cmd.arg("ioc")
        .arg("match")
        .arg("--hashes")
        .arg(hashes_csv.to_str().unwrap());
    let output = cmd.output().expect("Failed to execute");
    assert!(
        output.status.success(),
        "secguard ioc match (hashes only) failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_ioc_match_dns_without_domains() {
    let dns_csv = examples_path().join("dns_queries.csv");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secguard"));
    cmd.arg("ioc")
        .arg("match")
        .arg("--dns")
        .arg(dns_csv.to_str().unwrap());
    let output = cmd.output().expect("Failed to execute");
    assert!(
        output.status.success(),
        "secguard ioc match (dns only, no domains) should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
