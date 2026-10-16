use std::path::Path;
use std::process::{Command, Stdio};

use ai_signing_protocol::GroupDto;
use tracing::info;

pub fn progress(message: impl std::fmt::Display) {
    info!("slint_group_e2e: {message}");
}

pub fn write_plan(path: &Path, body: &str) {
    std::fs::write(path, body).expect("plan json");
}

pub fn spawn_gui(
    config: &Path,
    database: &Path,
    plan: &Path,
    log: &Path,
) -> std::process::Output {
    let stderr = std::fs::File::create(log).expect("log");
    Command::new(env!("CARGO_BIN_EXE_ai-signing-gui-slint-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .arg("--test-script")
        .arg(plan)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr))
        .output()
        .expect("ai-signing-gui-slint-e2e")
}

pub fn admin(config: &Path, args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-admin-e2e"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("admin");
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

pub fn cli<T: serde::de::DeserializeOwned>(config: &Path, database: &Path, args: &[&str]) -> T {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .args(args)
        .output()
        .expect("cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[allow(dead_code)]
pub fn groups(config: &Path, database: &Path) -> Vec<GroupDto> {
    cli(config, database, &["groups"])
}
