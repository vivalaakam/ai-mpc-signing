use std::time::{Duration, Instant};

use ai_signing_desktop_slint::test_harness::{Controller, SharedController};

pub(crate) fn with_controller<T, F>(shared: &SharedController, f: F) -> Result<T, String>
where
    F: FnOnce(&mut Controller) -> T,
{
    let mut controller = shared.lock().map_err(|_| "controller lock".to_string())?;
    Ok(f(&mut controller))
}

struct Snapshot {
    connected: bool,
    unlocked: bool,
    username: Option<String>,
    signers: usize,
    signer_names: Vec<String>,
    notice: Option<String>,
    error: Option<String>,
    completed_transfers: usize,
    has_pending: bool,
}

fn snapshot(shared: &SharedController) -> Result<Snapshot, String> {
    with_controller(shared, |controller| Snapshot {
        connected: controller.state.connected,
        unlocked: controller.state.unlocked,
        username: controller.state.username.clone(),
        signers: controller.state.signers.len(),
        signer_names: controller
            .state
            .signers
            .iter()
            .map(|signer| signer.username.clone())
            .collect(),
        notice: controller.state.notice.clone(),
        error: controller.state.error.clone(),
        completed_transfers: controller.completed_transfers(),
        has_pending: controller.first_pending_request().is_some(),
    })
}

pub(crate) fn wait_logged_in(
    shared: &SharedController,
    username: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let snap = snapshot(shared)?;
        if snap.username.as_deref() == Some(username) {
            return Ok(());
        }
        if let Some(err) = snap.error {
            return Err(err);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let snap = snapshot(shared)?;
    Err(format!(
        "не дождались входа {username}: username={:?}, notice={:?}",
        snap.username, snap.notice
    ))
}

pub(crate) struct WaitSpec {
    pub connected: Option<bool>,
    pub unlocked: Option<bool>,
    pub signers_min: Option<usize>,
    pub signers_present: Option<Vec<String>>,
    pub notice: Option<String>,
    pub completed_transfers_min: Option<usize>,
    pub pending: bool,
    pub timeout: Duration,
}

impl Default for WaitSpec {
    fn default() -> Self {
        Self {
            connected: None,
            unlocked: None,
            signers_min: None,
            signers_present: None,
            notice: None,
            completed_transfers_min: None,
            pending: false,
            timeout: Duration::from_secs(120),
        }
    }
}

impl WaitSpec {
    pub(crate) fn with_pending(mut self, pending: bool) -> Self {
        self.pending = pending;
        self
    }
}

fn signers_ready(names: &[String], present: &[String]) -> bool {
    names.iter().all(|name| present.iter().any(|one| one == name))
}

pub(crate) fn wait(shared: &SharedController, spec: WaitSpec) -> Result<(), String> {
    let deadline = Instant::now() + spec.timeout;
    while Instant::now() < deadline {
        if spec.completed_transfers_min.is_some()
            || spec.pending
            || spec.signers_min.is_some()
            || spec.signers_present.is_some()
        {
            let _ = with_controller(shared, |controller| controller.refresh());
            std::thread::sleep(Duration::from_millis(200));
        }
        let snap = snapshot(shared)?;
        if spec
            .connected
            .is_none_or(|want| snap.connected == want)
            && spec.unlocked.is_none_or(|want| snap.unlocked == want)
            && spec.signers_min.is_none_or(|min| snap.signers >= min)
            && spec
                .signers_present
                .as_ref()
                .is_none_or(|want| signers_ready(want, &snap.signer_names))
            && spec
                .notice
                .as_ref()
                .is_none_or(|want| snap.notice.as_deref() == Some(want.as_str()))
            && spec
                .completed_transfers_min
                .is_none_or(|min| snap.completed_transfers >= min)
            && (!spec.pending || snap.has_pending)
        {
            return Ok(());
        }
        if let Some(err) = snap.error {
            return Err(err);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let snap = snapshot(shared)?;
    Err(format!(
        "таймаут ожидания {:?}: connected={}, signers={}, notice={:?}, transfers={}",
        spec.notice, snap.connected, snap.signers, snap.notice, snap.completed_transfers
    ))
}

pub(crate) struct GroupWait {
    pub status: Option<String>,
    pub members: Option<usize>,
    pub members_with_keys: Option<usize>,
    pub name: Option<String>,
    pub timeout: Duration,
}

impl Default for GroupWait {
    fn default() -> Self {
        Self {
            status: None,
            members: None,
            members_with_keys: None,
            name: None,
            timeout: Duration::from_secs(120),
        }
    }
}

pub(crate) fn wait_group(shared: &SharedController, spec: GroupWait) -> Result<(), String> {
    let deadline = Instant::now() + spec.timeout;
    while Instant::now() < deadline {
        let ready = with_controller(shared, |controller| -> Option<()> {
            let group = match spec.name.as_deref() {
                Some(name) => controller
                    .state
                    .groups
                    .iter()
                    .find(|group| group.name == name),
                None => controller.selected_group(),
            }?;
            let keys = group
                .members
                .iter()
                .filter(|member| member.box_public_hex.is_some())
                .count();
            if spec.status.as_deref().is_none_or(|want| group.status == want)
                && spec.members.is_none_or(|want| group.members.len() == want)
                && spec
                    .members_with_keys
                    .is_none_or(|want| keys == want)
            {
                controller.select_group(group.id);
                Some(())
            } else {
                None
            }
        })?;
        if ready.is_some() {
            return Ok(());
        }
        if let Some(err) = snapshot(shared)?.error {
            return Err(err);
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    Err("таймаут ожидания группы".into())
}
