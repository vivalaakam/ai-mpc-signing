use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::{self, JoinHandle};

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
) -> Output {
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

pub fn assert_gui_ok(output: Output, log: &Path, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout: {}\nlog: {}",
        String::from_utf8_lossy(&output.stdout),
        log.display()
    );
}

pub struct GuiJob {
    pub label: String,
    pub handle: JoinHandle<(Output, PathBuf)>,
}

impl GuiJob {
    pub fn spawn(
        label: impl Into<String>,
        config: PathBuf,
        database: PathBuf,
        plan: PathBuf,
        log: PathBuf,
    ) -> Self {
        let label = label.into();
        let label_thread = label.clone();
        let handle = thread::spawn(move || {
            progress(format!("{} headless", label_thread));
            let output = spawn_gui(&config, &database, &plan, &log);
            (output, log)
        });
        Self { label, handle }
    }

    pub fn join(self) {
        let (output, log) = self.handle.join().expect("gui thread");
        assert_gui_ok(output, &log, &self.label);
    }
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

pub fn cli_fail(config: &Path, database: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .args(args)
        .output()
        .expect("cli");
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).into()
}

pub fn group_by_name(config: &Path, database: &Path, name: &str) -> GroupDto {
    let groups: Vec<GroupDto> = cli(config, database, &["groups"]);
    groups
        .into_iter()
        .find(|group| group.name == name)
        .unwrap_or_else(|| panic!("group {name}"))
}

#[allow(dead_code)]
pub fn group_id(config: &Path, database: &Path, name: &str) -> String {
    group_by_name(config, database, name).id.to_string()
}
