//! Basic integration tests for RuZip CLI operations
//!
//! These tests ensure that the CLI interface works correctly
//! and provides proper error handling and output.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::{NamedTempFile, TempDir};
use std::fs;

/// Test that the binary can be executed
#[test]
fn test_binary_exists() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.arg("--help")
        .assert()
        .success();
}

/// Test version command
#[test]
fn test_version_command() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ruzip"));
}

/// Test version command with JSON output
#[test]
fn test_version_json() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&["--output-format", "json", "version"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\":\"ruzip\""))
        .stdout(predicate::str::contains("\"version\""));
}

/// Test help command
#[test]
fn test_help_command() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("A modern, fast, and secure compression tool"));
}

/// Test subcommand help
#[test]
fn test_subcommand_help() {
    let subcommands = ["a", "x", "e", "l", "t", "d", "u"];
    
    for subcommand in &subcommands {
        let mut cmd = Command::cargo_bin("ruzip").unwrap();
        cmd.args(&[subcommand, "--help"])
            .assert()
            .success();
    }
}

/// Test add command dry run
#[test]
fn test_add_dry_run() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(&temp_file, "test content").unwrap();
    
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&[
        "--dry-run",
        "a",
        "test.rzp",
        temp_file.path().to_str().unwrap()
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("DRY RUN"));
}

/// Test add command with nonexistent file
#[test]
fn test_add_nonexistent_file() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&["--dry-run", "a", "test.rzp", "nonexistent.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("File does not exist"));
}

/// Test extract command dry run
#[test]
fn test_extract_dry_run() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&["--dry-run", "x", "test.rzp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DRY RUN"));
}

/// Test list command dry run
#[test]
fn test_list_dry_run() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&["--dry-run", "l", "test.rzp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DRY RUN"));
}

/// Test test command dry run
#[test]
fn test_test_dry_run() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&["--dry-run", "t", "test.rzp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DRY RUN"));
}

/// Test invalid compression level
#[test]
fn test_invalid_compression_level() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(&temp_file, "test content").unwrap();
    
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&[
        "a",
        "-x", "25", // Invalid compression level
        "test.rzp",
        temp_file.path().to_str().unwrap()
    ])
    .assert()
    .failure();
}

/// Test conflicting flags
#[test]
fn test_conflicting_flags() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&["--verbose", "--quiet", "version"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("conflicts with"));
}

/// Test thread configuration
#[test]
fn test_thread_configuration() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(&temp_file, "test content").unwrap();
    
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&[
        "--dry-run",
        "--threads", "4",
        "a",
        "test.rzp",
        temp_file.path().to_str().unwrap()
    ])
    .assert()
    .success();
}

/// Test verbose output
#[test]
fn test_verbose_output() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&["--verbose", "version"])
        .assert()
        .success();
}

/// Test quiet output
#[test]
fn test_quiet_output() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&["--quiet", "version"])
        .assert()
        .success();
}

/// Test completion generation
#[test]
fn test_completion_generation() {
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("completion.bash");
    
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&[
        "completion",
        "bash",
        "-o", output_file.to_str().unwrap()
    ])
    .assert()
    .success();
    
    // Check that the file was created
    assert!(output_file.exists());
    
    // Check that it has content
    let content = fs::read_to_string(&output_file).unwrap();
    assert!(!content.is_empty());
}

/// Test completion to stdout
#[test]
fn test_completion_stdout() {
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&["completion", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

/// Test JSON output format
#[test]
fn test_json_output_format() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(&temp_file, "test content").unwrap();
    
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&[
        "--output-format", "json",
        "--dry-run",
        "a",
        "test.rzp",
        temp_file.path().to_str().unwrap()
    ])
    .assert()
    .success();
}

/// Test progress flag
#[test]
fn test_progress_flag() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(&temp_file, "test content").unwrap();
    
    let mut cmd = Command::cargo_bin("ruzip").unwrap();
    cmd.args(&[
        "--progress",
        "--dry-run",
        "a",
        "test.rzp",
        temp_file.path().to_str().unwrap()
    ])
    .assert()
    .success();
}