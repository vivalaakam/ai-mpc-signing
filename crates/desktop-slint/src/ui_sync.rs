use std::sync::{Arc, Mutex};

use slint::{ComponentHandle, ModelRc, SharedString, TimerMode, VecModel};

use crate::controller::{
    build_group_detail, forming_panel_hint, forming_ready, group_status, needs_my_participation,
    request_action_hint, request_status, role_line, signer_group_hint, Controller,
};
use crate::log;

slint::include_modules!();

pub type SharedController = Arc<Mutex<Controller>>;

fn pull_wizard_fields(ui: &AppWindow, controller: &mut Controller) {
    controller.group_name = ui.get_group_name_input().to_string();
    controller.threshold = ui.get_threshold_input().to_string();
    controller.signer_search = ui.get_signer_search().to_string();
}

fn submit_login(
    ui: &AppWindow,
    shared: &SharedController,
    username: slint::SharedString,
    password: slint::SharedString,
) {
    let mut controller = shared.lock().expect("controller");
    controller.login_username = username.to_string();
    controller.login_password = password.to_string();
    let name = controller.login_username.trim();
    let prop_user = ui.get_login_username().to_string();
    let prop_pass_len = ui.get_login_password().len();
    tracing::info!(
        username = %name,
        password_len = controller.login_password.len(),
        prop_username = %prop_user,
        prop_password_len = prop_pass_len,
        "вход: отправка команды"
    );
    log::login_user_action(name, controller.login_password.len());
    if name.is_empty() || controller.login_password.is_empty() {
        tracing::warn!("вход: пустое имя или пароль");
    }
    controller.login();
    push_to_ui(ui, &controller);
}

pub fn wire_ui(ui: &AppWindow, shared: SharedController) {
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        let weak = weak.clone();
        ui.on_login_submit(move |username, password| {
            tracing::debug!("callback login-submit");
            if let Some(ui) = weak.upgrade() {
                submit_login(&ui, &shared, username, password);
            } else {
                tracing::warn!("login-submit: окно уже закрыто");
            }
        });
    }
    {
        let shared = shared.clone();
        let weak = weak.clone();
        ui.on_login_clicked(move || {
            tracing::debug!("callback login-clicked (устарело, используйте login-submit)");
            if let Some(ui) = weak.upgrade() {
                submit_login(
                    &ui,
                    &shared,
                    ui.get_login_username(),
                    ui.get_login_password(),
                );
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_logout_clicked(move || {
            let mut controller = shared.lock().expect("controller");
            controller.logout();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_refresh_clicked(move || {
            let mut controller = shared.lock().expect("controller");
            controller.refresh();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_create_group_clicked(move || {
            let mut controller = shared.lock().expect("controller");
            controller.open_create_wizard();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_create_wizard_cancel(move || {
            let mut controller = shared.lock().expect("controller");
            controller.wizard_cancel();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_create_wizard_next(move || {
            let mut controller = shared.lock().expect("controller");
            if let Some(ui) = weak.upgrade() {
                pull_wizard_fields(&ui, &mut controller);
            }
            controller.wizard_next();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_create_wizard_back(move || {
            let mut controller = shared.lock().expect("controller");
            if let Some(ui) = weak.upgrade() {
                pull_wizard_fields(&ui, &mut controller);
            }
            controller.wizard_back();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_create_wizard_create(move || {
            let mut controller = shared.lock().expect("controller");
            if let Some(ui) = weak.upgrade() {
                pull_wizard_fields(&ui, &mut controller);
            }
            controller.wizard_create();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_signer_search_changed(move |query| {
            let mut controller = shared.lock().expect("controller");
            controller.signer_search = query.to_string();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_toggle_signer(move |username| {
            let mut controller = shared.lock().expect("controller");
            if let Some(ui) = weak.upgrade() {
                pull_wizard_fields(&ui, &mut controller);
            }
            controller.toggle_signer(username.as_str());
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_select_group(move |id| {
            if let Ok(uuid) = uuid::Uuid::parse_str(id.as_str()) {
                let mut controller = shared.lock().expect("controller");
                controller.select_group(uuid);
                if let Some(ui) = weak.upgrade() {
                    push_to_ui(&ui, &controller);
                }
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_start_dkg_clicked(move || {
            let mut controller = shared.lock().expect("controller");
            controller.start_dkg();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_accept_participation_clicked(move || {
            let mut controller = shared.lock().expect("controller");
            controller.accept_participation();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_reshare_clicked(move || {
            let mut controller = shared.lock().expect("controller");
            controller.reshare();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_request_solana_clicked(move || {
            let mut controller = shared.lock().expect("controller");
            controller.request_solana();
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_approve_request(move |id| {
            if let Ok(uuid) = uuid::Uuid::parse_str(id.as_str()) {
                let mut controller = shared.lock().expect("controller");
                controller.approve(uuid);
                if let Some(ui) = weak.upgrade() {
                    push_to_ui(&ui, &controller);
                }
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_reject_request(move |id| {
            if let Ok(uuid) = uuid::Uuid::parse_str(id.as_str()) {
                let mut controller = shared.lock().expect("controller");
                controller.reject(uuid);
                if let Some(ui) = weak.upgrade() {
                    push_to_ui(&ui, &controller);
                }
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_toggle_remove_member(move |username| {
            let mut controller = shared.lock().expect("controller");
            controller.toggle_remove(username.as_str());
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
    let weak = ui.as_weak();
    {
        let shared = shared.clone();
        ui.on_toggle_add_member(move |username| {
            let mut controller = shared.lock().expect("controller");
            controller.toggle_add(username.as_str());
            if let Some(ui) = weak.upgrade() {
                push_to_ui(&ui, &controller);
            }
        });
    }
}

pub fn push_to_ui(ui: &AppWindow, controller: &Controller) {
    let state = &controller.state;
    ui.set_server_url(SharedString::from(state.server_url.as_str()));
    ui.set_unlocked(state.unlocked);
    ui.set_role_label(SharedString::from(role_line(state).as_str()));
    ui.set_connected(state.connected);
    ui.set_busy(controller.busy);
    ui.set_is_admin(state.role.as_deref() == Some("admin"));
    ui.set_group_name_input(SharedString::from(controller.group_name.as_str()));
    ui.set_threshold_input(SharedString::from(controller.threshold.as_str()));
    ui.set_show_create_wizard(controller.show_create_wizard);
    ui.set_create_wizard_step(controller.wizard_step as i32);
    ui.set_create_wizard_summary(SharedString::from(controller.wizard_summary().as_str()));
    ui.set_create_wizard_error(SharedString::from(
        controller.wizard_error.as_deref().unwrap_or(""),
    ));
    ui.set_signer_search(SharedString::from(controller.signer_search.as_str()));
    ui.set_solana_recipient(SharedString::from(
        controller.solana_recipient.as_str(),
    ));
    ui.set_solana_lamports(SharedString::from(controller.solana_lamports.as_str()));

    if !state.unlocked {
        ui.set_login_username(SharedString::from(controller.login_username.as_str()));
    }

    if let Some(error) = &state.error {
        ui.set_status_text(SharedString::from(error.as_str()));
        ui.set_status_is_error(true);
    } else if let Some(notice) = &state.notice {
        ui.set_status_text(SharedString::from(notice.as_str()));
        ui.set_status_is_error(false);
    } else {
        ui.set_status_text(SharedString::from(""));
        ui.set_status_is_error(false);
    }

    let groups: Vec<GroupRow> = state
        .groups
        .iter()
        .map(|group| GroupRow {
            id: group.id.to_string().into(),
            label: SharedString::from(format!(
                "{} · {} · {}-из-{}",
                group.name,
                group_status(&group.status),
                group.threshold,
                group.max_signers
            )),
            selected: controller.selected == Some(group.id),
        })
        .collect();
    ui.set_groups(ModelRc::new(VecModel::from(groups)));

    let search = controller.signer_search.trim().to_lowercase();
    let signer_pick: Vec<SignerRow> = state
        .signers
        .iter()
        .filter(|signer| {
            search.is_empty() || signer.username.to_lowercase().contains(&search)
        })
        .map(|signer| SignerRow {
            username: signer.username.clone().into(),
            picked: controller.picked_signers.contains(&signer.username),
        })
        .collect();
    ui.set_signer_pick(ModelRc::new(VecModel::from(signer_pick)));

    let is_admin = state.role.as_deref() == Some("admin");
    let pending_inbox = state
        .requests
        .iter()
        .filter(|r| r.status == "pending" && r.my_decision.is_none())
        .count();
    ui.set_inbox_tab_title(SharedString::from(if pending_inbox > 0 {
        format!("Сообщения ({pending_inbox})")
    } else {
        "Сообщения".into()
    }));

    if let Some(group) = controller.selected_group() {
        let has_share = state.shares.get(&group.id).copied().unwrap_or(false);
        let (title, body) = build_group_detail(group, &state.shares);
        ui.set_group_detail_title(SharedString::from(title.as_str()));
        ui.set_group_detail_body(SharedString::from(body.as_str()));
        ui.set_group_signer_hint(SharedString::from(
            signer_group_hint(group, has_share, is_admin).as_str(),
        ));
        if let Some(request) = state.requests.iter().find(|request| {
            request.group_id == group.id
                && request.status == "pending"
                && request.my_decision.is_none()
        }) {
            let can_approve = request.status == "pending"
                && request.my_decision.is_none()
                && has_share;
            let body = request
                .transaction
                .as_ref()
                .map(|tx| format!("Solana: {} lamports → {}", tx.lamports, tx.recipient))
                .unwrap_or_else(|| request.message_preview.clone());
            ui.set_show_group_sign_panel(true);
            ui.set_group_sign_title(SharedString::from(request.group_name.as_str()));
            ui.set_group_sign_body(SharedString::from(body.as_str()));
            ui.set_group_sign_status(SharedString::from(format!(
                "{} · {} из {}",
                request_status(&request.status),
                request.approvals,
                request.threshold
            )));
            ui.set_group_sign_request_id(SharedString::from(request.id.to_string()));
            ui.set_group_sign_can_approve(can_approve);
            ui.set_group_sign_hint(SharedString::from(
                request_action_hint(request, has_share, is_admin).as_str(),
            ));
        } else {
            ui.set_show_group_sign_panel(false);
            ui.set_group_sign_title(SharedString::from(""));
            ui.set_group_sign_body(SharedString::from(""));
            ui.set_group_sign_status(SharedString::from(""));
            ui.set_group_sign_request_id(SharedString::from(""));
            ui.set_group_sign_can_approve(false);
            ui.set_group_sign_hint(SharedString::from(""));
        }
        let forming = group.status == "forming"
            || (group.status == "resharing"
                && group
                    .members
                    .iter()
                    .any(|member| !member.participation_accepted));
        ui.set_show_forming_panel(forming);
        ui.set_show_start_dkg(false);
        if forming {
            ui.set_forming_panel_hint(SharedString::from(
                forming_panel_hint(group, is_admin && group.i_created).as_str(),
            ));
            let forming_members: Vec<FormingMemberRow> = group
                .members
                .iter()
                .map(|member| {
                    let ready = member.participation_accepted;
                    FormingMemberRow {
                        username: member.username.clone().into(),
                        status_line: SharedString::from(if ready {
                            "участие подтверждено"
                        } else {
                            "ожидает подтверждения"
                        }),
                        ready,
                    }
                })
                .collect();
            ui.set_forming_members(ModelRc::new(VecModel::from(forming_members)));
        } else {
            ui.set_forming_panel_hint(SharedString::from(""));
            ui.set_forming_members(ModelRc::new(VecModel::from(
                Vec::<FormingMemberRow>::new(),
            )));
        }
        let ready = forming_ready(group);
        ui.set_start_dkg_enabled(ready && forming && group.i_created);
        ui.set_show_accept_participation(needs_my_participation(group));
        ui.set_show_membership_editor(group.status == "active" && controller.membership_editable());
        ui.set_show_solana_actions(group.status == "active" && group.i_created);
        ui.set_group_ceremony_banner(SharedString::from(
            controller
                .ceremony_banner(group)
                .unwrap_or("")
        ));

        if group.status == "active" && group.i_created {
            let present: std::collections::HashSet<_> = group
                .members
                .iter()
                .map(|member| member.username.as_str())
                .collect();
            let remove: Vec<MemberRow> = group
                .members
                .iter()
                .map(|member| {
                    let mut detail = format!(
                        "убрать {} · участник {}",
                        member.username, member.identifier
                    );
                    if member.box_public_hex.is_none() {
                        detail.push_str(" · нет ключа устройства");
                    }
                    MemberRow {
                        username: member.username.clone().into(),
                        detail: detail.into(),
                        remove_picked: controller.remove_picked.contains(&member.username),
                    }
                })
                .collect();
            ui.set_member_remove_pick(ModelRc::new(VecModel::from(remove)));

            let add: Vec<MemberRow> = state
                .signers
                .iter()
                .filter(|signer| !present.contains(signer.username.as_str()))
                .map(|signer| MemberRow {
                    username: signer.username.clone().into(),
                    detail: SharedString::from(format!("добавить {}", signer.username)),
                    remove_picked: controller.add_picked.contains(&signer.username),
                })
                .collect();
            ui.set_member_add_pick(ModelRc::new(VecModel::from(add)));
        } else {
            ui.set_member_remove_pick(ModelRc::new(VecModel::from(Vec::<MemberRow>::new())));
            ui.set_member_add_pick(ModelRc::new(VecModel::from(Vec::<MemberRow>::new())));
        }
    } else {
        ui.set_group_detail_title(SharedString::from(""));
        ui.set_group_detail_body(SharedString::from(if state.role.as_deref() == Some("admin") {
            "Групп пока нет. Создайте группу и выберите подписантов."
        } else {
            "Групп пока нет. Администратор добавит вас в группу."
        }));
        ui.set_show_start_dkg(false);
        ui.set_start_dkg_enabled(false);
        ui.set_show_forming_panel(false);
        ui.set_forming_panel_hint(SharedString::from(""));
        ui.set_forming_members(ModelRc::new(VecModel::from(
            Vec::<FormingMemberRow>::new(),
        )));
        ui.set_show_accept_participation(false);
        ui.set_show_membership_editor(false);
        ui.set_show_solana_actions(false);
        ui.set_group_ceremony_banner(SharedString::from(""));
        ui.set_group_signer_hint(SharedString::from(""));
        ui.set_show_group_sign_panel(false);
        ui.set_member_remove_pick(ModelRc::new(VecModel::from(Vec::<MemberRow>::new())));
        ui.set_member_add_pick(ModelRc::new(VecModel::from(Vec::<MemberRow>::new())));
    }

    let requests: Vec<RequestRow> = state
        .requests
        .iter()
        .map(|request| {
            let has_share = state.shares.get(&request.group_id).copied().unwrap_or(false);
            let can_decide =
                request.status == "pending" && request.my_decision.is_none() && has_share;
            let body = request
                .transaction
                .as_ref()
                .map(|tx| format!("Solana: {} lamports → {}", tx.lamports, tx.recipient))
                .unwrap_or_else(|| request.message_preview.clone());
            RequestRow {
                id: request.id.to_string().into(),
                title: request.group_name.clone().into(),
                body: body.into(),
                can_approve: can_decide,
                status_line: SharedString::from(format!(
                    "{} · {} из {}",
                    request_status(&request.status),
                    request.approvals,
                    request.threshold
                )),
                action_hint: SharedString::from(
                    request_action_hint(request, has_share, is_admin).as_str(),
                ),
            }
        })
        .collect();
    ui.set_requests(ModelRc::new(VecModel::from(requests)));
}

/// Опрос канала состояния в потоке Slint (на macOS `invoke_from_event_loop` из фона ненадёжен).
pub fn attach_state_pump(
    ui: &AppWindow,
    shared: SharedController,
    events: async_channel::Receiver<ai_signing_client::UiState>,
) -> slint::Timer {
    let ui_weak = ui.as_weak();
    let timer = slint::Timer::default();
    timer.start(
        TimerMode::Repeated,
        std::time::Duration::from_millis(16),
        move || {
            while let Ok(state) = events.try_recv() {
                log::state_event(&state);
                if let Some(ui) = ui_weak.upgrade() {
                    let mut controller = shared.lock().expect("controller");
                    controller.apply(state);
                    push_to_ui(&ui, &controller);
                }
            }
        },
    );
    timer
}
