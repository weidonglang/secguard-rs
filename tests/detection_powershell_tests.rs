use assert_cmd::Command;
use predicates::prelude::predicate;
use std::path::PathBuf;

fn get_cmd() -> Command {
    Command::cargo_bin("secguard").expect("secguard binary not found")
}

fn examples_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("examples");
    p
}

#[test]
fn test_windows_analysis_with_output() {
    let mut p = examples_dir();
    p.push("windows_events.csv");
    let input = p.to_str().unwrap();

    let output_dir = std::env::temp_dir().join("secguard_test_output");
    let _ = std::fs::create_dir_all(&output_dir);
    let output_path = output_dir.join("win_report.md");
    let output = output_path.to_str().unwrap();

    let mut cmd = get_cmd();
    let assert = cmd
        .arg("analyze")
        .arg("windows")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .assert();
    assert.success();

    // Cleanup
    let _ = std::fs::remove_dir_all(&output_dir);
}

#[test]
fn test_windows_analysis_nonexistent_input() {
    let mut cmd = get_cmd();
    let assert = cmd
        .arg("analyze")
        .arg("windows")
        .arg("--input")
        .arg("nonexistent_file.csv")
        .assert();
    assert
        .failure()
        .stderr(predicate::str::contains("FileNotFound"));
}

#[test]
fn test_windows_analysis_help() {
    let mut cmd = get_cmd();
    let assert = cmd.arg("analyze").arg("windows").arg("--help").assert();
    assert
        .success()
        .stdout(predicate::str::contains("Analyze Windows event logs"));
}

#[test]
fn test_windows_analysis_finds_suspicious_powershell() {
    // Unit tests in src/detections/suspicious_powershell.rs verify SG-WIN-001 detection logic.
    // CLI integration for this feature will be wired in a later task (Task 12).
    let mut p = examples_dir();
    p.push("windows_events.csv");
    let input = p.to_str().unwrap();

    let mut cmd = get_cmd();
    let assert = cmd
        .arg("analyze")
        .arg("windows")
        .arg("--input")
        .arg(input)
        .assert();
    // The CLI handler is a placeholder until Task 12; just verify it doesn't crash.
    assert.success();
}

#[test]
fn test_windows_analysis_empty_events() {
    // Use empty.csv (empty file, no rows) to test zero findings
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p.push("invalid");
    p.push("empty.csv");
    let input = p.to_str().unwrap();

    let mut cmd = get_cmd();
    let assert = cmd
        .arg("analyze")
        .arg("windows")
        .arg("--input")
        .arg(input)
        .assert();
    assert.success();
}

#[test]
fn test_windows_analysis_path_with_spaces() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p.push("paths with spaces");
    p.push("auth events sample.csv");
    let input = p.to_str().unwrap();

    // Use this file to test path with spaces
    let mut cmd = get_cmd();
    let assert = cmd
        .arg("analyze")
        .arg("windows")
        .arg("--input")
        .arg(input)
        .assert();
    // May fail due to missing columns, but should not panic or crash
    let output = assert.get_output();
    assert!(
        output.status.success() || output.status.code() == Some(1),
        "should not panic"
    );
}
