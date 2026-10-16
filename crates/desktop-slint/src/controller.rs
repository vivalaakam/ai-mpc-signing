use std::collections::{HashMap, HashSet};

use ai_signing_client::{
    membership_change, signing_in_progress, Cmd, GroupDto, SignRequestDto, UiState,
};
use async_channel::Sender;
use uuid::Uuid;

pub struct Controller {
    pub commands: Sender<Cmd>,
    pub state: UiState,
    pub busy: bool,
    pub selected: Option<Uuid>,
    pub picked_signers: HashSet<String>,
    pub remove_picked: HashSet<String>,
    pub add_picked: HashSet<String>,
    pub group_name: String,
    pub threshold: String,
    pub solana_recipient: String,
    pub solana_lamports: String,
    pub login_username: String,
    pub login_password: String,
    pub show_create_wizard: bool,
    pub wizard_step: u8,
    pub wizard_error: Option<String>,
    pub signer_search: String,
    /// Группа, для которой ждём DKG или reshare (UI заблокирован до active/failed).
    pub ceremony_group: Option<Uuid>,
    pub ceremony_awaiting_start: bool,
}

impl Controller {
    pub fn new(commands: Sender<Cmd>, initial: UiState) -> Self {
        let login_username = initial.username.clone().unwrap_or_default();
        Self {
            commands,
            state: initial,
            busy: false,
            selected: None,
            picked_signers: HashSet::new(),
            remove_picked: HashSet::new(),
            add_picked: HashSet::new(),
            group_name: String::new(),
            threshold: "2".into(),
            solana_recipient: String::new(),
            solana_lamports: String::new(),
            login_username,
            login_password: String::new(),
            show_create_wizard: false,
            wizard_step: 0,
            wizard_error: None,
            signer_search: String::new(),
            ceremony_group: None,
            ceremony_awaiting_start: false,
        }
    }

    pub fn membership_editable(&self) -> bool {
        let Some(group) = self.selected_group() else {
            return false;
        };
        group.status == "active"
            && group.i_created
            && !signing_in_progress(group.id, &self.state.requests)
            && self.ceremony_group.is_none()
    }

    fn sync_busy(&mut self) {
        if let Some(gid) = self.ceremony_group {
            let Some(group) = self.state.groups.iter().find(|g| g.id == gid) else {
                self.ceremony_group = None;
                self.ceremony_awaiting_start = false;
                self.busy = false;
                return;
            };
            match group.status.as_str() {
                "resharing" | "dkg" => {
                    self.ceremony_awaiting_start = false;
                    self.busy = true;
                }
                "active" => {
                    if self.ceremony_awaiting_start {
                        self.busy = true;
                        if self.state.error.is_some() {
                            self.ceremony_group = None;
                            self.ceremony_awaiting_start = false;
                            self.busy = false;
                        }
                    } else {
                        self.ceremony_group = None;
                        self.ceremony_awaiting_start = false;
                        self.busy = false;
                    }
                }
                "failed" => {
                    self.ceremony_group = None;
                    self.ceremony_awaiting_start = false;
                    self.busy = false;
                }
                _ => self.busy = true,
            }
        } else {
            self.busy = false;
        }
    }

    fn begin_ceremony(&mut self, group_id: Uuid) {
        self.ceremony_group = Some(group_id);
        self.ceremony_awaiting_start = true;
        self.busy = true;
    }

    pub fn apply(&mut self, state: UiState) {
        let previous = self.selected;
        let known: HashSet<Uuid> = self.state.groups.iter().map(|group| group.id).collect();
        let fresh = state
            .groups
            .iter()
            .find(|group| !known.contains(&group.id))
            .map(|group| group.id);
        let ids: Vec<Uuid> = state.groups.iter().map(|group| group.id).collect();
        if let Some(id) = fresh {
            self.selected = Some(id);
        } else if self.selected.is_some_and(|id| !ids.contains(&id)) || self.selected.is_none() {
            self.selected = ids.first().copied();
        }
        if state.notice.as_deref() == Some("Группа создана") {
            self.picked_signers.clear();
            self.show_create_wizard = false;
            self.wizard_step = 0;
            self.wizard_error = None;
        }
        if state.notice.as_deref() == Some("Доли пересчитаны")
            || state.notice.as_deref() == Some("Пересчёт долей запущен")
        {
            if state.notice.as_deref() == Some("Доли пересчитаны") {
                self.ceremony_group = None;
                self.ceremony_awaiting_start = false;
            }
        }
        if self.selected != previous
            || state.notice.as_deref() == Some("Пересчёт долей запущен")
            || !state.unlocked
        {
            self.remove_picked.clear();
            self.add_picked.clear();
        }
        if self.ceremony_group.is_some() && state.error.is_some() {
            self.ceremony_group = None;
            self.ceremony_awaiting_start = false;
        }
        self.state = state;
        self.sync_busy();
    }

    pub fn send(&mut self, cmd: Cmd) {
        self.state.error = None;
        self.state.notice = None;
        match &cmd {
            Cmd::Reshare { group_id, .. } | Cmd::StartDkg { group_id } => {
                self.begin_ceremony(*group_id);
            }
            _ => {
                self.busy = true;
            }
        }
        if self.commands.try_send(cmd).is_err() {
            self.ceremony_group = None;
            self.ceremony_awaiting_start = false;
            self.busy = false;
            self.state.error = Some("Фоновая служба остановилась".into());
            tracing::error!("не удалось отправить команду в фоновую службу");
        } else {
            tracing::debug!("команда отправлена в session");
        }
    }

    pub fn login(&mut self) {
        let name = self.login_username.trim().to_string();
        let pass = self.login_password.clone();
        if name.is_empty() || pass.is_empty() {
            tracing::warn!("login: отклонено — пустые поля");
            self.state.error = Some("Введите имя и пароль".into());
            self.busy = false;
            return;
        }
        tracing::info!(username = %name, "login: Cmd::Login");
        self.send(Cmd::Login {
            username: name,
            password: pass,
        });
    }

    pub fn logout(&mut self) {
        self.send(Cmd::Logout);
    }

    pub fn refresh(&mut self) {
        self.send(Cmd::Refresh);
    }

    pub fn open_create_wizard(&mut self) {
        self.show_create_wizard = true;
        self.wizard_step = 0;
        self.wizard_error = None;
        self.picked_signers.clear();
        self.group_name.clear();
        self.threshold = "2".into();
        self.signer_search.clear();
    }

    pub fn wizard_cancel(&mut self) {
        self.show_create_wizard = false;
        self.wizard_step = 0;
        self.wizard_error = None;
        self.signer_search.clear();
    }

    pub fn wizard_back(&mut self) {
        self.wizard_error = None;
        if self.wizard_step > 0 {
            self.wizard_step -= 1;
        }
    }

    pub fn wizard_next(&mut self) {
        self.wizard_error = None;
        match self.wizard_step {
            0 => match validate_wizard_settings(&self.group_name, &self.threshold) {
                Ok(()) => self.wizard_step = 1,
                Err(err) => self.wizard_error = Some(err),
            },
            1 => {
                let n = self.picked_signers.len();
                if n < 2 {
                    self.wizard_error = Some("Выберите минимум 2 подписантов".into());
                    return;
                }
                if n > 16 {
                    self.wizard_error = Some("Не больше 16 подписантов".into());
                    return;
                }
                if let Err(err) = parse_threshold(&self.threshold, n) {
                    self.wizard_error = Some(err);
                    return;
                }
                self.wizard_step = 2;
            }
            _ => {}
        }
    }

    pub fn wizard_create(&mut self) {
        self.create_group_internal(true);
    }

    pub fn create_group(&mut self) {
        self.create_group_internal(false);
    }

    fn create_group_internal(&mut self, from_wizard: bool) {
        self.wizard_error = None;
        let name = self.group_name.trim().to_string();
        if name.is_empty() {
            let err = "Укажите название группы".into();
            if from_wizard {
                self.wizard_error = Some(err);
            } else {
                self.state.error = Some(err);
            }
            self.busy = false;
            return;
        }
        let members: Vec<String> = self
            .state
            .signers
            .iter()
            .filter(|signer| self.picked_signers.contains(&signer.username))
            .map(|signer| signer.username.clone())
            .collect();
        match parse_threshold(&self.threshold, members.len()) {
            Ok(threshold) => {
                self.send(Cmd::CreateGroup {
                    name,
                    threshold,
                    members,
                });
                if from_wizard {
                    // закроем после успешного ответа в apply()
                }
            }
            Err(err) => {
                if from_wizard {
                    self.wizard_error = Some(err);
                } else {
                    self.state.error = Some(err);
                }
                self.busy = false;
            }
        }
    }

    pub fn wizard_summary(&self) -> String {
        let name = self.group_name.trim();
        let members: Vec<&str> = self
            .state
            .signers
            .iter()
            .filter(|s| self.picked_signers.contains(&s.username))
            .map(|s| s.username.as_str())
            .collect();
        let n = members.len();
        format!(
            "Название: {name}\nПорог: {} из {n}\nУчастники:\n  {}",
            self.threshold.trim(),
            members.join("\n  ")
        )
    }

    pub fn select_group(&mut self, id: Uuid) {
        if self.selected != Some(id) {
            self.remove_picked.clear();
            self.add_picked.clear();
        }
        self.selected = Some(id);
    }

    pub fn accept_participation(&mut self) {
        let Some(group_id) = self.selected else {
            self.state.error = Some("Выберите группу".into());
            return;
        };
        self.send(Cmd::AcceptGroupParticipation { group_id });
    }

    pub fn start_dkg(&mut self) {
        let Some(group_id) = self.selected else {
            self.state.error = Some("Выберите группу".into());
            return;
        };
        self.send(Cmd::StartDkg { group_id });
    }

    pub fn reshare(&mut self) {
        if !self.membership_editable() {
            self.state.error = Some(
                self.membership_block_reason()
                    .unwrap_or_else(|| "Сейчас нельзя менять состав".into()),
            );
            return;
        }
        let Some(group_id) = self.selected else {
            self.state.error = Some("Выберите группу".into());
            return;
        };
        let Some(group) = self.state.groups.iter().find(|g| g.id == group_id).cloned() else {
            self.state.error = Some("Группа не найдена".into());
            return;
        };
        let (add, remove) = self.chosen_membership(&group);
        match membership_change(&group, &self.state.requests, &add, &remove) {
            Ok((add, remove)) => self.send(Cmd::Reshare {
                group_id,
                add,
                remove,
            }),
            Err(err) => self.state.error = Some(err),
        }
    }

    fn membership_block_reason(&self) -> Option<String> {
        let group = self.selected_group()?;
        if self.ceremony_group.is_some() {
            return Some("Дождитесь завершения текущей операции с группой".into());
        }
        if signing_in_progress(group.id, &self.state.requests) {
            return Some("Дождитесь завершения текущей подписи".into());
        }
        match group.status.as_str() {
            "resharing" => Some("Дождитесь завершения текущего пересчёта долей".into()),
            "dkg" => Some("Дождитесь завершения генерации ключа".into()),
            "active" if group.i_created => None,
            "active" => Some("Пересчитывать доли может создатель группы".into()),
            _ => Some("Пересчёт долей доступен только активной группе".into()),
        }
    }

    pub fn request_solana(&mut self) {
        let Some(group_id) = self.selected else {
            self.state.error = Some("Выберите группу".into());
            return;
        };
        let recipient = self.solana_recipient.trim().to_string();
        let lamports = self.solana_lamports.trim().parse::<u64>();
        if recipient.is_empty() || !matches!(lamports, Ok(value) if value > 0) {
            self.state.error =
                Some("Введите адрес и положительную сумму в lamports".into());
            return;
        }
        self.send(Cmd::RequestSolanaTransfer {
            group_id,
            recipient,
            lamports: lamports.unwrap_or_default(),
        });
    }

    pub fn approve(&mut self, request_id: Uuid) {
        self.send(Cmd::Approve { request_id });
    }

    pub fn reject(&mut self, request_id: Uuid) {
        self.send(Cmd::Reject { request_id });
    }

    pub fn toggle_signer(&mut self, username: &str) {
        if !self.picked_signers.insert(username.to_string()) {
            self.picked_signers.remove(username);
        }
    }

    pub fn toggle_remove(&mut self, username: &str) {
        if !self.membership_editable() {
            return;
        }
        self.add_picked.remove(username);
        if !self.remove_picked.insert(username.to_string()) {
            self.remove_picked.remove(username);
        }
    }

    pub fn toggle_add(&mut self, username: &str) {
        if !self.membership_editable() {
            return;
        }
        self.remove_picked.remove(username);
        if !self.add_picked.insert(username.to_string()) {
            self.add_picked.remove(username);
        }
    }

    pub fn ceremony_banner(&self, group: &GroupDto) -> Option<&'static str> {
        if self.ceremony_group == Some(group.id) && self.ceremony_awaiting_start {
            return Some("Запуск операции…");
        }
        match group.status.as_str() {
            "resharing" => Some("Идёт пересчёт долей. Дождитесь завершения."),
            "dkg" => Some("Идёт генерация ключа. Дождитесь завершения."),
            _ => None,
        }
    }

    pub fn chosen_membership(&self, group: &GroupDto) -> (Vec<String>, Vec<String>) {
        let present: HashSet<&str> = group
            .members
            .iter()
            .map(|member| member.username.as_str())
            .collect();
        let remove = group
            .members
            .iter()
            .filter(|member| self.remove_picked.contains(&member.username))
            .map(|member| member.username.clone())
            .collect();
        let add = self
            .state
            .signers
            .iter()
            .filter(|signer| {
                self.add_picked.contains(&signer.username)
                    && !present.contains(signer.username.as_str())
            })
            .map(|signer| signer.username.clone())
            .collect();
        (add, remove)
    }

    pub fn selected_group(&self) -> Option<&GroupDto> {
        self.selected
            .and_then(|id| self.state.groups.iter().find(|group| group.id == id))
    }

    pub fn first_pending_request(&self) -> Option<&SignRequestDto> {
        self.state.requests.iter().find(|request| {
            request.status == "pending" && request.my_decision.is_none()
        })
    }

    pub fn completed_transfers(&self) -> usize {
        self.state
            .requests
            .iter()
            .filter(|request| {
                request.status == "completed" && request.transaction.is_some()
            })
            .count()
    }
}

fn validate_wizard_settings(name: &str, threshold: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("Укажите название группы".into());
    }
    let t: u16 = threshold
        .trim()
        .parse()
        .map_err(|_| "Порог t должен быть числом".to_string())?;
    if !(2..=16).contains(&t) {
        return Err("Порог t: от 2 до 16".into());
    }
    Ok(())
}

pub fn parse_threshold(threshold: &str, members: usize) -> Result<u16, String> {
    let threshold: u16 = threshold
        .trim()
        .parse()
        .map_err(|_| "Порог t должен быть числом".to_string())?;
    let members = u16::try_from(members).unwrap_or(u16::MAX);
    if members < 2 || members > 16 || !(2..=members).contains(&threshold) {
        return Err("Порог t и число подписантов: 2 ≤ t ≤ n ≤ 16".into());
    }
    Ok(threshold)
}

pub fn group_status(status: &str) -> &str {
    match status {
        "forming" => "набор",
        "dkg" => "генерация ключа",
        "active" => "активна",
        "failed" => "ошибка",
        "resharing" => "пересчёт долей",
        other => other,
    }
}

pub fn request_status(status: &str) -> &str {
    match status {
        "pending" => "ожидает",
        "signing" => "подпись",
        "completed" => "подписано",
        "failed" => "ошибка",
        other => other,
    }
}

pub fn role_line(state: &UiState) -> String {
    let user = state.username.clone().unwrap_or_default();
    let role = ai_signing_client::role_title(state.role.as_deref().unwrap_or(""));
    format!("{user} · {role}")
}

pub fn request_action_hint(
    request: &SignRequestDto,
    has_share: bool,
    is_admin: bool,
) -> String {
    if request.status != "pending" {
        return String::new();
    }
    if request.my_decision.is_some() {
        return "Вы уже ответили на этот запрос.".into();
    }
    if !has_share {
        return if is_admin {
            "Запрос ждёт решения подписантов.".into()
        } else {
            "На этом устройстве нет доли ключа — подписать нельзя. Откройте клиент с базой, где проходили DKG.".into()
        };
    }
    String::new()
}

pub fn forming_panel_hint(group: &GroupDto, is_admin: bool) -> String {
    let ready = group
        .members
        .iter()
        .filter(|m| m.participation_accepted)
        .count();
    let total = group.members.len();
    if is_admin && group.i_created {
        format!(
            "Администратор создал группу. Подписанты подтверждают участие ({ready}/{total}). Когда все подтвердят и будут в сети, генерация ключа начнётся автоматически."
        )
    } else {
        "Вас пригласили в группу. Нажмите «Подтвердить участие», если согласны.".into()
    }
}

pub fn needs_my_participation(group: &GroupDto) -> bool {
    group.status == "forming"
        && group.my_identifier.is_some_and(|id| {
            group
                .members
                .iter()
                .find(|member| member.identifier == id)
                .is_some_and(|member| !member.participation_accepted)
        })
}

pub fn forming_ready(group: &GroupDto) -> bool {
    group.members.len() == usize::from(group.max_signers)
        && group.members.iter().all(|member| {
            member.participation_accepted && member.box_public_hex.is_some()
        })
}

pub fn signer_group_hint(group: &GroupDto, has_share: bool, is_admin: bool) -> String {
    if is_admin || group.status == "forming" {
        return String::new();
    }
    match group.status.as_str() {
        "forming" => String::new(),
        "dkg" => "Идёт генерация ключа. Не закрывайте окно — клиент участвует автоматически.".into(),
        "active" if !has_share => "Группа активна, но на этом устройстве нет доли ключа. Подписывать переводы нельзя.".into(),
        _ => String::new(),
    }
}

pub fn build_group_detail(group: &GroupDto, shares: &HashMap<Uuid, bool>) -> (String, String) {
    let has_share = shares.get(&group.id).copied().unwrap_or(false);
    let share = if has_share {
        "Доля ключа хранится на этом устройстве."
    } else if group.status == "active" || group.status == "dkg" {
        "Доли ключа на этом устройстве нет."
    } else {
        "Доля появится после генерации ключа."
    };
    let title = group.name.clone();
    let body = format!(
        "{} · порог {} из {}\n{share}",
        group_status(&group.status),
        group.threshold,
        group.max_signers
    );
    (title, body)
}
