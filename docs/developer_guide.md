# Developer Guide

## Development Workflow

This project uses a strict task-based workflow with 16 development tasks (Task 1-16).

### Task Lifecycle

1. **Checkout main** and pull latest
2. **Create issue** for the task
3. **Create branch** from main: `task-N-short-name`
4. **Implement** changes (only allowed files per task)
5. **Test locally** with validation scripts
6. **Commit** a single commit
7. **Push** branch and create PR
8. **Merge** PR, delete branch
9. **Verify** main is clean before next task

### Branch Naming

```
task-01-init-repo
task-02-guardrails
task-03-schema-examples
task-04-parsers
task-05-detection-engine
task-06-auth-detections
task-07-windows-detections
task-08-network-detections
task-09-ioc-matching
task-10-file-integrity
task-11-reports
task-12-cli-integration
task-13-docs
task-14-build-smoke
task-15-package-release
task-16-final-release
```

### Commit Rules

- Only 1 commit per task
- Message format: `Task N: summary`
- No `git add .` — always use explicit paths

## Directory Structure

```
secguard-rs/
  README.md, LICENSE, VERSION, Cargo.toml, Cargo.lock, .gitignore
  src/           — Rust source code
  tests/         — Integration tests
  examples/      — Example CSV/JSON data
  testdata/      — Test fixtures (valid/invalid/edge)
  scripts/       — PowerShell build/test scripts
  rules/         — Detection rules (JSON)
  docs/          — Documentation
  dist/          — Release packages (not committed)
```

## Testing

Run all tests:

```bash
powershell -ExecutionPolicy Bypass -File scripts/run_all_tests.ps1
```

Or manually:

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Edge Cases to Test

All parsers, detectors, and reporters must cover:
1. Normal files
2. Empty files
3. Header only
4. Missing columns
5. Extra columns
6. Bad timestamp format
7. Bad integer fields
8. Long lines
9. Paths with spaces
10. Unicode usernames
11. Windows paths
12. Unix paths
13. Output directory not found
14. Output file already exists
15. Empty findings report
16. Stable sort order

### Rust Code Requirements

- No `unwrap` on user input
- No `expect` on user input
- `unwrap` allowed in tests only
- All public functions need doc comments
- Errors use `SecGuardError`
- CLI exit codes must be testable

## Validation Scripts

| Script | Purpose |
|--------|---------|
| `run_all_tests.ps1` | Run fmt, clippy, and cargo test |
| `check_version.ps1` | Verify VERSION matches Cargo.toml |
| `check_no_artifacts.ps1` | Ensure no exe/zip/target/dist tracked |
| `check_no_network_code.ps1` | Ensure no network dependencies or code |
| `count_lines.ps1` | Count total project lines |
| `build_release.ps1` | Build release binary |
| `smoke_test.ps1` | Quick smoke test of release binary |
| `package_release.ps1` | Create release zip package |
| `check_no_artifacts.ps1` | Verify no artifacts in git tracking |

## Security Boundaries

- Offline only — no network connections
- No std::net, TcpStream, UdpSocket, reqwest, hyper, tokio::net
- No port scanning, exploitation, or payload execution
- Local file analysis only

## Version Management

Version is defined in `VERSION` file. Run `scripts/check_version.ps1` to ensure consistency across `Cargo.toml`, `README.md`, `docs/user_guide.md`, and `docs/release_notes.md`.