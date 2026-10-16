use std::time::Duration;

use ai_signing_desktop_slint::test_harness::SharedController;

use super::plan::TestStep;
use super::wait::{wait, wait_group, wait_logged_in, with_controller, GroupWait, WaitSpec};

pub fn run_plan(shared: &SharedController, steps: &[TestStep]) -> Result<(), String> {
    for step in steps {
        run_step(shared, step).map_err(|err| format!("{step:?}: {err}"))?;
        eprintln!("slint e2e: ok {step:?}");
    }
    Ok(())
}

fn run_step(shared: &SharedController, step: &TestStep) -> Result<(), String> {
    match step {
        TestStep::Login { username, password } => {
            with_controller(shared, |controller| {
                controller.login_username = username.clone();
                controller.login_password = password.clone();
                controller.login();
            })?;
            wait_logged_in(shared, username, Duration::from_secs(120))?;
            with_controller(shared, |controller| controller.refresh())?;
        }
        TestStep::Wait {
            connected,
            unlocked,
            signers_min,
            signers_present,
            notice,
            completed_transfers_min,
            timeout_secs,
        } => wait(
            shared,
            WaitSpec {
                connected: *connected,
                unlocked: *unlocked,
                signers_min: *signers_min,
                signers_present: signers_present.clone(),
                notice: notice.clone(),
                completed_transfers_min: *completed_transfers_min,
                pending: false,
                timeout: Duration::from_secs(timeout_secs.unwrap_or(120)),
            },
        )?,
        TestStep::Refresh => with_controller(shared, |controller| controller.refresh())?,
        TestStep::WaitGroup {
            status,
            members,
            members_with_keys,
            name,
            timeout_secs,
        } => wait_group(
            shared,
            GroupWait {
                status: status.clone(),
                members: *members,
                members_with_keys: *members_with_keys,
                name: name.clone(),
                timeout: Duration::from_secs(timeout_secs.unwrap_or(180)),
            },
        )?,
        TestStep::CreateGroup {
            name,
            threshold,
            members,
        } => {
            with_controller(shared, |controller| {
                controller.group_name = name.clone();
                controller.threshold = threshold.to_string();
                controller.picked_signers = members.iter().cloned().collect();
                controller.create_group();
            })?;
            wait_group(
                shared,
                GroupWait {
                    name: Some(name.clone()),
                    members: Some(members.len()),
                    timeout: Duration::from_secs(60),
                    ..Default::default()
                },
            )?;
        }
        TestStep::SelectGroup { name } => {
            let id = {
                let controller = shared.lock().map_err(|_| "controller lock".to_string())?;
                controller
                    .state
                    .groups
                    .iter()
                    .find(|group| group.name == *name)
                    .map(|group| group.id)
                    .ok_or_else(|| format!("группа {name} не найдена"))?
            };
            with_controller(shared, |controller| controller.select_group(id))?;
        }
        TestStep::AcceptParticipation => {
            with_controller(shared, |controller| controller.accept_participation())?;
            std::thread::sleep(Duration::from_millis(300));
        }
        TestStep::StartDkg => with_controller(shared, |controller| controller.start_dkg())?,
        TestStep::Reshare { add, remove } => {
            with_controller(shared, |controller| {
                controller.add_picked = add.iter().cloned().collect();
                controller.remove_picked = remove.iter().cloned().collect();
                controller.reshare();
            })?;
            wait_group(
                shared,
                GroupWait {
                    status: Some("active".into()),
                    timeout: Duration::from_secs(180),
                    ..Default::default()
                },
            )?;
        }
        TestStep::RequestSolana { recipient, lamports } => {
            with_controller(shared, |controller| {
                controller.solana_recipient = recipient.clone();
                controller.solana_lamports = lamports.to_string();
                controller.request_solana();
            })?;
        }
        TestStep::WaitPending => wait(
            shared,
            WaitSpec {
                timeout: Duration::from_secs(300),
                ..Default::default()
            }
            .with_pending(true),
        )?,
        TestStep::ApproveFirstPending => {
            let id = {
                let controller = shared.lock().map_err(|_| "controller lock".to_string())?;
                controller
                    .first_pending_request()
                    .map(|request| request.id)
                    .ok_or_else(|| "нет ожидающих запросов".to_string())?
            };
            with_controller(shared, |controller| controller.approve(id))?;
        }
        TestStep::Sleep { millis } => std::thread::sleep(Duration::from_millis(*millis)),
        TestStep::Done => {}
    }
    Ok(())
}
