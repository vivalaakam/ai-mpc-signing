use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use ai_signing_client::{
    listen, message_text, recode_hex, role_title, start, Cmd, GroupDto, SignRequestDto, Store,
    UiState,
};
use async_channel::Sender;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use uuid::Uuid;

pub fn run(store: Store, server: String, database: &Path) -> Result<(), String> {
    let (listener, _unlink) = listen(database)?;
    let initial = UiState::from_store(&store, &server);
    let (commands, events) = start(store, server, listener);
    let mut terminal = ratatui::try_init().map_err(|err| format!("терминал: {err}"))?;
    let _guard = TerminalGuard;
    let mut app = App::new(initial);
    app.event_loop(&mut terminal, &commands, &events)
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

enum Screen {
    Login,
    Home,
    Create,
    Message,
}

struct LoginForm {
    username: String,
    password: String,
    field: u8,
}

struct CreateForm {
    name: String,
    threshold: String,
    field: u8,
    index: usize,
    picked: HashSet<String>,
}

struct MessageForm {
    group_id: Uuid,
    group_name: String,
    text: String,
}

struct App {
    state: UiState,
    screen: Screen,
    login: LoginForm,
    create: CreateForm,
    message: MessageForm,
    tab: u8,
    group_index: usize,
    request_index: usize,
    pending: bool,
    local_error: Option<String>,
    local_notice: Option<String>,
    copy_base64: bool,
    quit: bool,
}

impl App {
    fn new(state: UiState) -> Self {
        let screen = if state.unlocked {
            Screen::Home
        } else {
            Screen::Login
        };
        let username = state.username.clone().unwrap_or_default();
        Self {
            state,
            screen,
            login: LoginForm {
                username,
                password: String::new(),
                field: 0,
            },
            create: CreateForm {
                name: String::new(),
                threshold: "2".into(),
                field: 0,
                index: 0,
                picked: HashSet::new(),
            },
            message: MessageForm {
                group_id: Uuid::nil(),
                group_name: String::new(),
                text: String::new(),
            },
            tab: 0,
            group_index: 0,
            request_index: 0,
            pending: false,
            local_error: None,
            local_notice: None,
            copy_base64: false,
            quit: false,
        }
    }

    fn event_loop(
        &mut self,
        terminal: &mut ratatui::DefaultTerminal,
        commands: &Sender<Cmd>,
        events: &async_channel::Receiver<UiState>,
    ) -> Result<(), String> {
        while !self.quit {
            while let Ok(state) = events.try_recv() {
                self.apply(state);
            }
            terminal
                .draw(|frame| self.draw(frame))
                .map_err(|err| err.to_string())?;
            if !event::poll(Duration::from_millis(50)).map_err(|err| err.to_string())? {
                continue;
            }
            if let Event::Key(key) = event::read().map_err(|err| err.to_string())? {
                self.on_key(key, commands);
            }
        }
        Ok(())
    }

    fn apply(&mut self, state: UiState) {
        let created = state.notice.as_deref() == Some("Группа создана");
        let sent = state.notice.as_deref() == Some("Запрос отправлен на подпись");
        let unlocked = state.unlocked;
        self.state = state;
        self.pending = false;
        if !unlocked {
            if !matches!(self.screen, Screen::Login) {
                self.screen = Screen::Login;
                self.login.password.clear();
            }
            if self.login.username.is_empty() {
                if let Some(name) = &self.state.username {
                    self.login.username = name.clone();
                }
            }
        } else if matches!(self.screen, Screen::Login) {
            self.screen = Screen::Home;
            self.login.password.clear();
        } else if matches!(self.screen, Screen::Create) && created {
            self.screen = Screen::Home;
            self.create.picked.clear();
        } else if matches!(self.screen, Screen::Message) && sent {
            self.screen = Screen::Home;
            self.message.text.clear();
        }
        self.clamp();
    }

    fn clamp(&mut self) {
        self.group_index = clamp_index(self.group_index, self.state.groups.len());
        self.request_index = clamp_index(self.request_index, self.request_order().len());
        self.create.index = clamp_index(self.create.index, self.state.signers.len());
    }

    fn on_key(&mut self, key: KeyEvent, commands: &Sender<Cmd>) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        if is_ctrl(&key, 'c') || is_ctrl(&key, 'w') {
            self.quit = true;
            return;
        }
        if is_ctrl(&key, 'q') {
            self.logout(commands);
            return;
        }
        self.local_error = None;
        self.local_notice = None;
        match self.screen {
            Screen::Login => self.login_key(key, commands),
            Screen::Home => self.home_key(key, commands),
            Screen::Create => self.create_key(key, commands),
            Screen::Message => self.message_key(key, commands),
        }
    }

    fn login_key(&mut self, key: KeyEvent, commands: &Sender<Cmd>) {
        match key.code {
            KeyCode::Esc => self.quit = true,
            KeyCode::Tab | KeyCode::Down => self.login.field = 1,
            KeyCode::BackTab | KeyCode::Up => self.login.field = 0,
            KeyCode::Enter => {
                if self.login.field == 0 {
                    self.login.field = 1;
                } else {
                    self.submit_login(commands);
                }
            }
            KeyCode::Backspace => {
                if self.login.field == 0 {
                    self.login.username.pop();
                } else {
                    self.login.password.pop();
                }
            }
            KeyCode::Char(ch) if is_text(key.modifiers) => {
                if self.login.field == 0 && self.login.username.chars().count() < 32 {
                    self.login.username.push(ch);
                } else if self.login.field == 1 && self.login.password.chars().count() < 128 {
                    self.login.password.push(ch);
                }
            }
            _ => {}
        }
    }

    fn submit_login(&mut self, commands: &Sender<Cmd>) {
        let username = self.login.username.trim().to_string();
        if username.is_empty() || self.login.password.is_empty() {
            self.local_error = Some("Введите имя и пароль".into());
            return;
        }
        self.send(
            Cmd::Login {
                username,
                password: self.login.password.clone(),
            },
            commands,
        );
    }

    fn logout(&mut self, commands: &Sender<Cmd>) {
        if self.state.username.is_none() {
            return;
        }
        self.send(Cmd::Logout, commands);
    }

    fn home_key(&mut self, key: KeyEvent, commands: &Sender<Cmd>) {
        let copying = self.can_copy();
        match key.code {
            KeyCode::Char('w') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('q') => self.logout(commands),
            KeyCode::Char('u') => self.send(Cmd::Refresh, commands),
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                self.tab = if self.tab == 0 { 1 } else { 0 };
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('1') if copying => self.copy_selected(CopyPart::Key),
            KeyCode::Char('2') if copying => self.copy_selected(CopyPart::Signature),
            KeyCode::Char('3') if copying => self.copy_selected(CopyPart::Message),
            KeyCode::Char('f') if copying => {
                self.copy_base64 = !self.copy_base64;
                self.local_notice = Some(format_notice(self.copy_base64));
            }
            KeyCode::Char('n') => self.open_create(commands),
            KeyCode::Char('d') => {
                if self.tab != 0 {
                    self.tab = 0;
                } else {
                    self.start_dkg(commands);
                }
            }
            KeyCode::Char('s') => self.open_message(),
            KeyCode::Char('a') => self.decide(commands, true),
            KeyCode::Char('r') => self.decide(commands, false),
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.tab == 0 {
            self.group_index = shift(self.group_index, delta, self.state.groups.len());
        } else {
            self.request_index = shift(self.request_index, delta, self.request_order().len());
        }
    }

    fn open_create(&mut self, commands: &Sender<Cmd>) {
        if !self.is_admin() {
            self.local_error = Some("Группу создаёт администратор".into());
            return;
        }
        self.create.name.clear();
        self.create.threshold = "2".into();
        self.create.field = 0;
        self.create.index = 0;
        self.create.picked.clear();
        self.screen = Screen::Create;
        self.send(Cmd::ListSigners, commands);
    }

    fn start_dkg(&mut self, commands: &Sender<Cmd>) {
        if !self.is_admin() {
            self.local_error = Some("Генерацию ключа запускает администратор".into());
            return;
        }
        let Some(group) = self.selected_group().cloned() else {
            self.local_error = Some("Выберите группу".into());
            return;
        };
        if !group.i_created || group.status != "forming" {
            self.local_error = Some("Генерация доступна создателю, пока группа набирается".into());
            return;
        }
        self.send(Cmd::StartDkg { group_id: group.id }, commands);
    }

    fn open_message(&mut self) {
        if !self.is_admin() {
            self.local_error = Some("Запрос на подпись создаёт администратор".into());
            return;
        }
        if self.tab != 0 {
            self.tab = 0;
            return;
        }
        let Some((group_id, group_name, created, active)) = self.selected_group().map(|group| {
            (
                group.id,
                group.name.clone(),
                group.i_created,
                group.status == "active",
            )
        }) else {
            self.local_error = Some("Выберите группу".into());
            return;
        };
        if !created {
            self.local_error = Some("Отправлять на подпись может создатель группы".into());
            return;
        }
        if !active {
            self.local_error = Some("Группа ещё не готова подписывать".into());
            return;
        }
        self.message.group_id = group_id;
        self.message.group_name = group_name;
        self.message.text.clear();
        self.screen = Screen::Message;
    }

    fn message_key(&mut self, key: KeyEvent, commands: &Sender<Cmd>) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Home,
            KeyCode::Enter => self.submit_message(commands),
            KeyCode::Backspace => {
                self.message.text.pop();
            }
            KeyCode::Char(ch) if is_text(key.modifiers) => {
                self.message.text.push(ch);
            }
            _ => {}
        }
    }

    fn submit_message(&mut self, commands: &Sender<Cmd>) {
        let message = self.message.text.trim().to_string();
        if message.is_empty() {
            self.local_error = Some("Введите сообщение".into());
            return;
        }
        let group_id = self.message.group_id;
        self.send(Cmd::RequestSign { group_id, message }, commands);
    }

    fn decide(&mut self, commands: &Sender<Cmd>, approve: bool) {
        if self.tab != 1 {
            self.tab = 1;
            return;
        }
        let Some(request) = self.selected_request().cloned() else {
            self.local_error = Some("Нет запроса на подпись".into());
            return;
        };
        if request.status != "pending" || request.my_decision.is_some() {
            self.local_error = Some("Этот запрос уже не ждёт решения".into());
            return;
        }
        let has_share = self
            .state
            .shares
            .get(&request.group_id)
            .copied()
            .unwrap_or(false);
        if !has_share {
            self.local_error = Some("На этом устройстве нет доли ключа".into());
            return;
        }
        let request_id = request.id;
        self.send(
            if approve {
                Cmd::Approve { request_id }
            } else {
                Cmd::Reject { request_id }
            },
            commands,
        );
    }

    fn create_key(&mut self, key: KeyEvent, commands: &Sender<Cmd>) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Home,
            KeyCode::Tab => self.create.field = (self.create.field + 1) % 3,
            KeyCode::BackTab => self.create.field = (self.create.field + 2) % 3,
            KeyCode::Enter => self.submit_create(commands),
            KeyCode::Up | KeyCode::Char('k') if self.create.field == 2 => {
                self.create.index = shift(self.create.index, -1, self.state.signers.len());
            }
            KeyCode::Down | KeyCode::Char('j') if self.create.field == 2 => {
                self.create.index = shift(self.create.index, 1, self.state.signers.len());
            }
            KeyCode::Char(' ') if self.create.field == 2 => self.toggle_signer(),
            KeyCode::Backspace if self.create.field < 2 => self.edit_create('\0', true),
            KeyCode::Char(ch) if is_text(key.modifiers) && self.create.field < 2 => {
                self.edit_create(ch, false);
            }
            _ => {}
        }
    }

    fn edit_create(&mut self, ch: char, backspace: bool) {
        let field = if self.create.field == 0 {
            &mut self.create.name
        } else {
            &mut self.create.threshold
        };
        if backspace {
            field.pop();
            return;
        }
        if self.create.field == 1 {
            if ch.is_ascii_digit() && field.chars().count() < 2 {
                field.push(ch);
            }
            return;
        }
        if field.chars().count() < 80 {
            field.push(ch);
        }
    }

    fn toggle_signer(&mut self) {
        let Some(name) = self
            .state
            .signers
            .get(self.create.index)
            .map(|signer| signer.username.clone())
        else {
            return;
        };
        if !self.create.picked.insert(name.clone()) {
            self.create.picked.remove(&name);
        }
    }

    fn submit_create(&mut self, commands: &Sender<Cmd>) {
        let name = self.create.name.trim().to_string();
        if name.is_empty() {
            self.local_error = Some("Введите название группы".into());
            return;
        }
        let members: Vec<String> = self
            .state
            .signers
            .iter()
            .filter(|signer| self.create.picked.contains(&signer.username))
            .map(|signer| signer.username.clone())
            .collect();
        let Ok(threshold) = self.create.threshold.trim().parse::<u16>() else {
            self.local_error = Some("Порог t должен быть числом".into());
            return;
        };
        let count = u16::try_from(members.len()).unwrap_or(u16::MAX);
        if !(2..=count).contains(&threshold) || !(2..=16).contains(&count) {
            self.local_error = Some("Порог t и число подписантов: 2 ≤ t ≤ n ≤ 16".into());
            return;
        }
        self.send(
            Cmd::CreateGroup {
                name,
                threshold,
                members,
            },
            commands,
        );
    }

    fn send(&mut self, cmd: Cmd, commands: &Sender<Cmd>) {
        if self.pending {
            return;
        }
        self.pending = true;
        if commands.try_send(cmd).is_err() {
            self.pending = false;
            self.local_error = Some("Фоновая служба остановилась".into());
        }
    }

    fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        if area.width < 48 || area.height < 12 {
            frame.render_widget(Paragraph::new("Увеличьте окно терминала"), area);
            return;
        }
        match self.screen {
            Screen::Login => self.draw_login(frame),
            Screen::Home => self.draw_home(frame),
            Screen::Create => self.draw_create(frame),
            Screen::Message => self.draw_message(frame),
        }
    }

    fn draw_login(&self, frame: &mut Frame) {
        let lines = vec![
            Line::from("Пороговая подпись Ed25519. Доля ключа остаётся на этом устройстве."),
            Line::from("Пароль проверяется при каждом входе и открывает локальные ключи."),
            Line::from(format!("Сервер {}", self.state.server_url)),
            Line::from(""),
            field_line("Имя", &self.login.username, self.login.field == 0, false),
            field_line("Пароль", &self.login.password, self.login.field == 1, true),
            Line::from(""),
            Line::from("Enter войти    Ctrl+W закрыть    Esc закрыть    Tab поле"),
            Line::from(""),
            self.banner(),
        ];
        frame.render_widget(panel("Подпись MPC", lines), frame.area());
    }

    fn draw_home(&self, frame: &mut Frame) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(6),
                Constraint::Length(4),
            ])
            .split(frame.area());
        frame.render_widget(panel("Подпись MPC", self.header_lines()), rows[0]);
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(rows[1]);
        let list_title = if self.tab == 0 {
            "Группы"
        } else {
            "Сообщения"
        };
        let list_lines = if self.tab == 0 {
            self.group_lines()
        } else {
            self.request_lines()
        };
        frame.render_widget(panel(list_title, list_lines), columns[0]);
        let detail_title = if self.tab == 0 {
            "Группа"
        } else {
            "Сообщение"
        };
        let detail = if self.tab == 0 {
            self.group_detail()
        } else {
            self.request_detail()
        };
        frame.render_widget(panel(detail_title, detail), columns[1]);
        frame.render_widget(panel("Клавиши", self.footer_lines()), rows[2]);
    }

    fn header_lines(&self) -> Vec<Line<'static>> {
        let name = self.state.username.clone().unwrap_or_default();
        let role = role_title(self.state.role.as_deref().unwrap_or(""));
        let (link, color) = if self.state.connected {
            ("на связи", Color::Green)
        } else {
            ("нет связи", Color::Yellow)
        };
        vec![Line::from(vec![
            Span::raw(format!("{name} · {role} · ")),
            Span::styled(link, Style::default().fg(color)),
            Span::raw(format!("    {}", self.state.server_url)),
        ])]
    }

    fn footer_lines(&self) -> Vec<Line<'static>> {
        let mut keys =
            "Ctrl+Q выйти   Ctrl+W закрыть   u обновить   Tab вкладка   j/k выбор".to_string();
        if self.is_admin() {
            keys.push_str("   n группа   d генерация   s на подпись");
        }
        keys.push_str("   a подписать   r отклонить");
        let mut lines = vec![Line::from(keys)];
        if self.can_copy() {
            let format = if self.copy_base64 { "base64" } else { "hex" };
            lines.push(Line::from(format!(
                "1 ключ   2 подпись   3 сообщение   f формат {format}   проверка: ai-signing-cli verify"
            )));
        }
        lines.push(self.banner());
        lines
    }

    fn group_lines(&self) -> Vec<Line<'static>> {
        if self.state.groups.is_empty() {
            let text = if self.is_admin() {
                "Групп пока нет. Клавиша n создаёт группу."
            } else {
                "Групп пока нет. Администратор добавит вас в группу."
            };
            return vec![Line::from(text)];
        }
        self.state
            .groups
            .iter()
            .enumerate()
            .map(|(index, group)| {
                selected_line(
                    index == self.group_index,
                    format!(
                        "{} · {} · {}-из-{}",
                        group.name,
                        group_status(&group.status),
                        group.threshold,
                        group.max_signers
                    ),
                )
            })
            .collect()
    }

    fn request_order(&self) -> Vec<usize> {
        let mut waiting = Vec::new();
        let mut signed = Vec::new();
        for (index, request) in self.state.requests.iter().enumerate() {
            if self.is_admin() && request.status == "completed" {
                signed.push(index);
            } else {
                waiting.push(index);
            }
        }
        if self.is_admin() {
            waiting.extend(signed);
        }
        waiting
    }

    fn request_lines(&self) -> Vec<Line<'static>> {
        let order = self.request_order();
        if order.is_empty() {
            let text = if self.is_admin() {
                "Подписанных сообщений пока нет."
            } else {
                "Сообщений пока нет."
            };
            return vec![Line::from(text)];
        }
        if !self.is_admin() {
            return order
                .iter()
                .enumerate()
                .map(|(pos, &index)| self.request_line(pos, &self.state.requests[index]))
                .collect();
        }
        let mut lines = Vec::new();
        let waiting: Vec<(usize, usize)> = order
            .iter()
            .enumerate()
            .filter(|(_, &index)| self.state.requests[index].status != "completed")
            .map(|(pos, &index)| (pos, index))
            .collect();
        let signed: Vec<(usize, usize)> = order
            .iter()
            .enumerate()
            .filter(|(_, &index)| self.state.requests[index].status == "completed")
            .map(|(pos, &index)| (pos, index))
            .collect();
        if !waiting.is_empty() {
            lines.push(Line::from("Ждут подписи"));
            for (pos, index) in waiting {
                lines.push(self.request_line(pos, &self.state.requests[index]));
            }
            lines.push(Line::from(""));
        }
        lines.push(Line::from("Подписанные"));
        if signed.is_empty() {
            lines.push(Line::from("Пока нет."));
        } else {
            for (pos, index) in signed {
                lines.push(self.request_line(pos, &self.state.requests[index]));
            }
        }
        lines
    }

    fn request_line(&self, pos: usize, request: &SignRequestDto) -> Line<'static> {
        let message = message_label(request);
        let text = if self.is_admin() && request.status == "completed" {
            format!("{message} · {}", request.group_name)
        } else {
            format!(
                "{message} · {} · {}",
                request.group_name,
                request_status(&request.status)
            )
        };
        selected_line(pos == self.request_index, text)
    }

    fn group_detail(&self) -> Vec<Line<'static>> {
        let Some(group) = self.selected_group() else {
            return vec![Line::from("Выберите группу.")];
        };
        let mut lines = vec![
            Line::from(group.name.clone()),
            Line::from(format!(
                "{} · порог {} из {}",
                group_status(&group.status),
                group.threshold,
                group.max_signers
            )),
            Line::from(""),
            Line::from("Участники"),
        ];
        if group.members.is_empty() {
            lines.push(Line::from("Пока никого нет."));
        }
        for member in &group.members {
            let mut line = format!("{} · участник {}", member.username, member.identifier);
            if member.box_public_hex.is_none() {
                line.push_str(" · нет ключа устройства");
            }
            lines.push(Line::from(line));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(share_line(
            self.state.shares.get(&group.id).copied().unwrap_or(false),
            &group.status,
        )));
        if group.status == "forming" && group.i_created {
            lines.push(Line::from(
                "Перед запуском каждый подписант должен открыть клиент. Клавиша d.",
            ));
        } else if group.status == "dkg" {
            lines.push(Line::from(
                "Идёт распределённая генерация ключа. Это окно лучше не закрывать.",
            ));
        } else if group.status == "failed" {
            lines.push(Line::from(
                "Генерация ключа не удалась. Создайте новую группу.",
            ));
        }
        if let Some(key) = &group.verifying_key_hex {
            lines.push(Line::from(format!("Ключ проверки {key}")));
        }
        if let Some(token) = &group.api_token {
            lines.push(Line::from(format!("Токен API {token}")));
        }
        if group.status == "active" && group.i_created {
            lines.push(Line::from(
                "Клавиша s отправляет сообщение на подпись. Подписанты подтвердят его.",
            ));
        }
        lines
    }

    fn request_detail(&self) -> Vec<Line<'static>> {
        let Some(request) = self.selected_request() else {
            let text = if self.is_admin() {
                "Подписанных сообщений пока нет."
            } else {
                "Сообщений пока нет."
            };
            return vec![Line::from(text)];
        };
        let shown_message =
            message_text(&request.message_hex).unwrap_or_else(|_| message_label(request));
        let mut lines = vec![
            Line::from(request.group_name.clone()),
            Line::from(shown_message),
            Line::from(format!(
                "{} · {} из {}",
                request_status(&request.status),
                request.approvals,
                request.threshold
            )),
        ];
        if let Some(decision) = &request.my_decision {
            let text = if decision == "approved" {
                "Вы подтвердили подпись."
            } else {
                "Вы отклонили запрос."
            };
            lines.push(Line::from(text));
        } else if request.status == "pending" {
            let has_share = self
                .state
                .shares
                .get(&request.group_id)
                .copied()
                .unwrap_or(false);
            if has_share {
                lines.push(Line::from("a подписать    r отклонить"));
            } else if self.is_admin() {
                lines.push(Line::from("Запрос ждёт решения подписантов."));
            } else {
                lines.push(Line::from("На этом устройстве нет доли ключа."));
            }
        }
        if let Some(error) = &request.error {
            lines.push(Line::from(Span::styled(
                error.clone(),
                Style::default().fg(Color::Red),
            )));
        }
        if request.status == "completed" {
            if self.is_admin() {
                if request
                    .signature_hex
                    .as_deref()
                    .is_some_and(|signature| !signature.is_empty())
                {
                    self.push_admin_copy(&mut lines, request);
                }
            } else {
                lines.push(Line::from("Всё прошло."));
            }
        }
        lines
    }

    fn push_admin_copy(&self, lines: &mut Vec<Line<'static>>, request: &SignRequestDto) {
        let format = if self.copy_base64 { "base64" } else { "hex" };
        match copy_payload(&self.state, request, CopyPart::Key, self.copy_base64) {
            Ok(shown) => lines.push(Line::from(format!("Ключ {shown}"))),
            Err(err) => lines.push(red_line(err)),
        }
        match copy_payload(&self.state, request, CopyPart::Signature, self.copy_base64) {
            Ok(shown) => lines.push(Line::from(format!("Подпись {shown}"))),
            Err(err) => lines.push(red_line(err)),
        }
        if message_text(&request.message_hex).is_err() {
            if let Err(err) = copy_payload(&self.state, request, CopyPart::Message, false) {
                lines.push(red_line(err));
            }
        }
        lines.push(Line::from(format!(
            "1 ключ   2 подпись   3 сообщение   f формат {format}"
        )));
        lines.push(Line::from(
            "Проверка в отдельном окне: ai-signing-cli verify",
        ));
    }

    fn can_copy(&self) -> bool {
        if !self.is_admin() || self.tab != 1 {
            return false;
        }
        self.selected_request().is_some_and(|request| {
            request.status == "completed"
                && request
                    .signature_hex
                    .as_deref()
                    .is_some_and(|signature| !signature.is_empty())
        })
    }

    fn copy_selected(&mut self, part: CopyPart) {
        let Some(request) = self.selected_request().cloned() else {
            self.local_error = Some("Нет подписанного сообщения".into());
            return;
        };
        let text = match copy_payload(&self.state, &request, part, self.copy_base64) {
            Ok(text) => text,
            Err(err) => {
                self.local_error = Some(err);
                return;
            }
        };
        match copy_clipboard(&text) {
            Ok(()) => self.local_notice = Some(copied_notice(part)),
            Err(err) => self.local_error = Some(format!("Не удалось скопировать: {err}")),
        }
    }

    fn draw_create(&self, frame: &mut Frame) {
        let mut lines = vec![
            Line::from("Выберите активных подписантов. Активный подписант уже входил в клиент."),
            Line::from(""),
            field_line("Название", &self.create.name, self.create.field == 0, false),
            field_line(
                "Порог t",
                &self.create.threshold,
                self.create.field == 1,
                false,
            ),
            Line::from(""),
            Line::from(Span::styled(
                "Подписанты",
                if self.create.field == 2 {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            )),
        ];
        if self.state.signers.is_empty() {
            lines.push(Line::from(
                "Нет активных подписантов. Пусть подписант откроет клиент и войдёт.",
            ));
        }
        for (index, signer) in self.state.signers.iter().enumerate() {
            let mark = if self.create.picked.contains(&signer.username) {
                "[x]"
            } else {
                "[ ]"
            };
            lines.push(selected_line(
                self.create.field == 2 && index == self.create.index,
                format!("{mark} {}", signer.username),
            ));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "Выбрано {}. Пробел отмечает, Enter создаёт, Esc назад.",
            self.create.picked.len()
        )));
        lines.push(self.banner());
        frame.render_widget(panel("Новая группа", lines), frame.area());
    }

    fn draw_message(&self, frame: &mut Frame) {
        let lines = vec![
            Line::from(format!("Группа {}", self.message.group_name)),
            Line::from("Подписанты увидят этот текст и подтвердят подпись."),
            Line::from(""),
            field_line("Сообщение", &self.message.text, true, false),
            Line::from(""),
            Line::from("Enter отправить    Esc назад"),
            Line::from(""),
            self.banner(),
        ];
        frame.render_widget(panel("На подпись", lines), frame.area());
    }

    fn banner(&self) -> Line<'static> {
        if let Some(error) = &self.local_error {
            return red_line(error.clone());
        }
        if let Some(error) = &self.state.error {
            return red_line(error.clone());
        }
        if let Some(notice) = &self.local_notice {
            return green_line(notice.clone());
        }
        if let Some(notice) = &self.state.notice {
            return green_line(notice.clone());
        }
        Line::from("")
    }

    fn selected_group(&self) -> Option<&GroupDto> {
        self.state.groups.get(self.group_index)
    }

    fn selected_request(&self) -> Option<&SignRequestDto> {
        let index = *self.request_order().get(self.request_index)?;
        self.state.requests.get(index)
    }

    fn is_admin(&self) -> bool {
        self.state.role.as_deref() == Some("admin")
    }
}

fn is_ctrl(key: &KeyEvent, letter: char) -> bool {
    let letter = letter.to_ascii_lowercase();
    match key.code {
        KeyCode::Char(ch) if key.modifiers.contains(KeyModifiers::CONTROL) => {
            ch.eq_ignore_ascii_case(&letter)
        }
        KeyCode::Char(ch)
            if !key.modifiers.contains(KeyModifiers::ALT)
                && !key.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            ch as u32 == u32::from(letter as u8 & 0x1f)
        }
        _ => false,
    }
}

fn is_text(modifiers: KeyModifiers) -> bool {
    !modifiers.contains(KeyModifiers::CONTROL) && !modifiers.contains(KeyModifiers::ALT)
}

fn panel(title: &str, lines: Vec<Line<'static>>) -> Paragraph<'static> {
    Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} ")),
        )
        .wrap(Wrap { trim: false })
}

fn field_line(label: &str, value: &str, focused: bool, secret: bool) -> Line<'static> {
    let shown = if secret {
        "•".repeat(value.chars().count())
    } else {
        value.to_string()
    };
    let cursor = if focused { "▌" } else { "" };
    let style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    Line::from(Span::styled(format!("{label}: {shown}{cursor}"), style))
}

fn selected_line(selected: bool, text: String) -> Line<'static> {
    let style = if selected {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    let marker = if selected { ">" } else { " " };
    Line::from(Span::styled(format!("{marker} {text}"), style))
}

fn clamp_index(index: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        index.min(len - 1)
    }
}

fn shift(index: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let next = index as isize + delta;
    if next < 0 {
        0
    } else if next as usize >= len {
        len - 1
    } else {
        next as usize
    }
}

fn group_status(status: &str) -> &str {
    match status {
        "forming" => "набор",
        "dkg" => "генерация ключа",
        "active" => "активна",
        "failed" => "ошибка",
        other => other,
    }
}

fn message_label(request: &SignRequestDto) -> String {
    if !request.message_preview.is_empty() {
        return request.message_preview.clone();
    }
    let hex: String = request.message_hex.chars().take(16).collect();
    if hex.is_empty() {
        request.group_name.clone()
    } else {
        hex
    }
}

fn request_status(status: &str) -> &str {
    match status {
        "pending" => "ожидает",
        "signing" => "подпись",
        "completed" => "подписано",
        "failed" => "ошибка",
        other => other,
    }
}

#[derive(Clone, Copy)]
enum CopyPart {
    Key,
    Signature,
    Message,
}

fn copy_payload(
    state: &UiState,
    request: &SignRequestDto,
    part: CopyPart,
    as_base64: bool,
) -> Result<String, String> {
    match part {
        CopyPart::Key => {
            let Some(group) = state
                .groups
                .iter()
                .find(|group| group.id == request.group_id)
            else {
                return Err("Группа не найдена".into());
            };
            let Some(key) = group
                .verifying_key_hex
                .as_deref()
                .filter(|key| !key.is_empty())
            else {
                return Err("У группы нет публичного ключа".into());
            };
            recode_hex(key, as_base64).map_err(|err| err.to_string())
        }
        CopyPart::Signature => {
            let Some(signature) = request
                .signature_hex
                .as_deref()
                .filter(|signature| !signature.is_empty())
            else {
                return Err("Подписи нет".into());
            };
            recode_hex(signature, as_base64).map_err(|err| err.to_string())
        }
        CopyPart::Message => message_text(&request.message_hex).map_err(|err| err.to_string()),
    }
}

fn copied_notice(part: CopyPart) -> String {
    match part {
        CopyPart::Key => "Ключ скопирован".into(),
        CopyPart::Signature => "Подпись скопирована".into(),
        CopyPart::Message => "Сообщение скопировано".into(),
    }
}

fn format_notice(as_base64: bool) -> String {
    let name = if as_base64 { "base64" } else { "hex" };
    format!("Формат копирования: {name}")
}

fn copy_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|err| err.to_string())?;
    clipboard.set_text(text).map_err(|err| err.to_string())
}

fn red_line(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::Red)))
}

fn green_line(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::Green)))
}

fn share_line(has_share: bool, status: &str) -> String {
    if has_share {
        "Доля ключа хранится на этом устройстве.".into()
    } else if status == "active" || status == "dkg" {
        "Доли ключа на этом устройстве нет.".into()
    } else {
        "Доля появится после генерации ключа.".into()
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_payload, format_notice, is_ctrl, App, CopyPart};
    use ai_signing_client::{GroupDto, SignRequestDto, UiState};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use uuid::Uuid;

    #[test]
    fn ctrl_q_logs_out_and_ctrl_w_closes() {
        let ctrl_q = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);
        let ctrl_w = KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL);
        let raw_q = KeyEvent::new(KeyCode::Char('\u{11}'), KeyModifiers::NONE);
        let raw_w = KeyEvent::new(KeyCode::Char('\u{17}'), KeyModifiers::NONE);
        let plain_q = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        let plain_w = KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE);
        assert!(is_ctrl(&ctrl_q, 'q'));
        assert!(is_ctrl(&ctrl_w, 'w'));
        assert!(is_ctrl(&raw_q, 'q'));
        assert!(is_ctrl(&raw_w, 'w'));
        assert!(!is_ctrl(&plain_q, 'q'));
        assert!(!is_ctrl(&plain_w, 'w'));
        assert!(!is_ctrl(&ctrl_q, 'w'));
        assert!(!is_ctrl(&ctrl_w, 'q'));
    }

    #[test]
    fn admin_copies_key_signature_and_exact_message() {
        let group_id = Uuid::from_u128(1);
        let key_hex = "11".repeat(32);
        let signature_hex = "ab".repeat(64);
        let message_hex = "696e766f6963652d34320a";
        let mut state = empty_state();
        state.role = Some("admin".into());
        state.groups = vec![group(group_id, Some(key_hex.clone()))];
        let request = request(group_id, &message_hex, Some(signature_hex.clone()));
        state.requests = vec![request.clone()];

        let key = copy_payload(&state, &request, CopyPart::Key, false).unwrap();
        let key_b64 = copy_payload(&state, &request, CopyPart::Key, true).unwrap();
        let signature = copy_payload(&state, &request, CopyPart::Signature, false).unwrap();
        let signature_b64 = copy_payload(&state, &request, CopyPart::Signature, true).unwrap();
        let message = copy_payload(&state, &request, CopyPart::Message, false).unwrap();
        assert_eq!(key, key_hex);
        assert_ne!(key_b64, key_hex);
        assert_eq!(signature, signature_hex);
        assert_ne!(signature_b64, signature_hex);
        assert_eq!(message, "invoice-42\n");
        assert_eq!(format_notice(false), "Формат копирования: hex");
        assert_eq!(format_notice(true), "Формат копирования: base64");

        let mut app = App::new(state);
        app.tab = 1;
        assert!(app.can_copy());
        app.state.role = Some("signer".into());
        assert!(!app.can_copy());
        app.state.role = Some("admin".into());
        app.tab = 0;
        assert!(!app.can_copy());
        app.tab = 1;
        app.state.requests[0].status = "pending".into();
        assert!(!app.can_copy());
    }

    #[test]
    fn copy_reports_a_missing_group_and_a_missing_key() {
        let group_id = Uuid::from_u128(1);
        let request = request(group_id, "696e766f6963652d34320a", Some("ab".repeat(64)));
        let state = empty_state();
        let err = copy_payload(&state, &request, CopyPart::Key, false).unwrap_err();
        assert_eq!(err, "Группа не найдена");

        let mut state = empty_state();
        state.groups = vec![group(group_id, None)];
        let err = copy_payload(&state, &request, CopyPart::Key, false).unwrap_err();
        assert_eq!(err, "У группы нет публичного ключа");
    }

    fn empty_state() -> UiState {
        UiState {
            server_url: "http://127.0.0.1:8080".into(),
            username: Some("eve".into()),
            role: Some("admin".into()),
            connected: true,
            error: None,
            notice: None,
            groups: Vec::new(),
            requests: Vec::new(),
            signers: Vec::new(),
            shares: Default::default(),
            unlocked: true,
        }
    }

    fn group(id: Uuid, verifying_key_hex: Option<String>) -> GroupDto {
        GroupDto {
            id,
            name: "treasury".into(),
            threshold: 2,
            max_signers: 2,
            status: "active".into(),
            api_token: None,
            verifying_key_hex,
            solana_address: None,
            created_by: Uuid::from_u128(7),
            i_created: true,
            my_identifier: None,
            members: Vec::new(),
        }
    }

    fn request(group_id: Uuid, message_hex: &str, signature_hex: Option<String>) -> SignRequestDto {
        SignRequestDto {
            id: Uuid::from_u128(2),
            group_id,
            group_name: "treasury".into(),
            message_hex: message_hex.into(),
            message_preview: "invoice-42".into(),
            status: "completed".into(),
            signature_hex,
            error: None,
            approvals: 2,
            threshold: 2,
            my_decision: None,
            created_at: "2026-10-07".into(),
            transaction: None,
        }
    }
}
