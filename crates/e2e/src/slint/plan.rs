use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TestPlan {
    pub steps: Vec<TestStep>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum TestStep {
    Login {
        username: String,
        password: String,
    },
    Wait {
        #[serde(default)]
        connected: Option<bool>,
        #[serde(default)]
        unlocked: Option<bool>,
        #[serde(default)]
        signers_min: Option<usize>,
        #[serde(default)]
        signers_present: Option<Vec<String>>,
        #[serde(default)]
        notice: Option<String>,
        #[serde(default)]
        completed_transfers_min: Option<usize>,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    Refresh,
    WaitGroup {
        #[serde(default)]
        status: Option<String>,
        #[serde(default)]
        members: Option<usize>,
        #[serde(default)]
        members_with_keys: Option<usize>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    CreateGroup {
        name: String,
        threshold: u16,
        members: Vec<String>,
    },
    SelectGroup {
        name: String,
    },
    AcceptParticipation,
    StartDkg,
    Reshare {
        add: Vec<String>,
        remove: Vec<String>,
    },
    RequestSolana {
        recipient: String,
        lamports: u64,
    },
    ApproveFirstPending,
    WaitPending,
    Sleep {
        millis: u64,
    },
    Done,
}

pub fn load_plan(path: &Path) -> Result<TestPlan, String> {
    let text = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
    serde_json::from_str(&text).map_err(|err| err.to_string())
}
