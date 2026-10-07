use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use ai_signing_client::{listen, role_title, start, Cmd, GroupDto, SignRequestDto, Store, UiState};
use async_channel::Sender;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

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

struct App {
    state: UiState,
    screen: Screen,
    login: LoginForm,
    create: CreateForm,
    tab: u8,
    group_index: usize,
    request_index: usize,
    pending: bool,
    local_error: Option<String>,
    quit: bool,
}

impl App {
    fn new(state: UiState) -> Self {
        let screen = if state.username.is_none() {
            Screen::Login
        } else {
            Screen::Home
        };
        Self {
            state,
            screen,
            login: LoginForm {
                username: String::new(),
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
            tab: 0,
            group_index: 0,
            request_index: 0,
            pending: false,
            local_error: None,
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
        let logged_in = state.username.is_some();
        self.state = state;
        self.pending = false;
        if !logged_in {
            self.screen = Screen::Login;
            self.login.password.clear();
        } else if matches!(self.screen, Screen::Login) {
            self.screen = Screen::Home;
            self.login.password.clear();
        } else if matches!(self.screen, Screen::Create) && created {
            self.screen = Screen::Home;
            self.create.picked.clear();
        }
        self.clamp();
    }

    fn clamp(&mut self) {
        self.group_index = clamp_index(self.group_index, self.state.groups.len());
        self.request_index = clamp_index(self.request_index, self.state.requests.len());
        self.create.index = clamp_index(self.create.index, self.state.signers.len());
    }

    fn on_key(&mut self, key: KeyEvent, commands: &Sender<Cmd>) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            self.quit = true;
            return;
        }
        self.local_error = None;
        match self.screen {
            Screen::Login => self.login_key(key, commands),
            Screen::Home => self.home_key(key, commands),
            Screen::Create => self.create_key(key, commands),
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

    fn home_key(&mut self, key: KeyEvent, commands: &Sender<Cmd>) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('w') => self.send(Cmd::Logout, commands),
            KeyCode::Char('u') => self.send(Cmd::Refresh, commands),
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                self.tab = if self.tab == 0 { 1 } else { 0 };
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('n') => self.open_create(commands),
            KeyCode::Char('d') => {
                if self.tab != 0 {
                    self.tab = 0;
                } else {
                    self.start_dkg(commands);
                }
            }
            KeyCode::Char('a') => self.decide(commands, true),
            KeyCode::Char('r') => self.decide(commands, false),
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.tab == 0 {
            self.group_index = shift(self.group_index, delta, self.state.groups.len());
        } else {
            self.request_index = shift(self.request_index, delta, self.state.requests.len());
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
        }
    }

    fn draw_login(&self, frame: &mut Frame) {
        let lines = vec![
            Line::from("Пороговая подпись Ed25519. Доля ключа остаётся на этом устройстве."),
            Line::from(format!("Сервер {}", self.state.server_url)),
            Line::from(""),
            field_line("Имя", &self.login.username, self.login.field == 0, false),
            field_line("Пароль", &self.login.password, self.login.field == 1, true),
            Line::from(""),
            Line::from("Enter войти    Esc закрыть    Tab поле"),
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
            "На подпись"
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
            "Запрос"
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
        let mut keys = "q закрыть   w выйти   u обновить   Tab вкладка   j/k выбор".to_string();
        if self.is_admin() {
            keys.push_str("   n группа   d генерация");
        }
        keys.push_str("   a подписать   r отклонить");
        vec![Line::from(keys), self.banner()]
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

    fn request_lines(&self) -> Vec<Line<'static>> {
        if self.state.requests.is_empty() {
            return vec![Line::from("Запросов на подпись нет.")];
        }
        self.state
            .requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                selected_line(
                    index == self.request_index,
                    format!(
                        "{} · {} · {}/{}",
                        request.group_name,
                        request_status(&request.status),
                        request.approvals,
                        request.threshold
                    ),
                )
            })
            .collect()
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
        lines
    }

    fn request_detail(&self) -> Vec<Line<'static>> {
        let Some(request) = self.selected_request() else {
            return vec![Line::from("Запросов на подпись нет.")];
        };
        let mut lines = vec![
            Line::from(request.group_name.clone()),
            Line::from(request.message_preview.clone()),
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
            lines.push(Line::from("a подписать    r отклонить"));
        }
        if let Some(error) = &request.error {
            lines.push(Line::from(Span::styled(
                error.clone(),
                Style::default().fg(Color::Red),
            )));
        }
        if let Some(signature) = &request.signature_hex {
            lines.push(Line::from(format!("Подпись {signature}")));
        }
        lines
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

    fn banner(&self) -> Line<'static> {
        if let Some(error) = &self.local_error {
            return Line::from(Span::styled(error.clone(), Style::default().fg(Color::Red)));
        }
        if let Some(error) = &self.state.error {
            return Line::from(Span::styled(error.clone(), Style::default().fg(Color::Red)));
        }
        if let Some(notice) = &self.state.notice {
            return Line::from(Span::styled(
                notice.clone(),
                Style::default().fg(Color::Green),
            ));
        }
        Line::from("")
    }

    fn selected_group(&self) -> Option<&GroupDto> {
        self.state.groups.get(self.group_index)
    }

    fn selected_request(&self) -> Option<&SignRequestDto> {
        self.state.requests.get(self.request_index)
    }

    fn is_admin(&self) -> bool {
        self.state.role.as_deref() == Some("admin")
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

fn request_status(status: &str) -> &str {
    match status {
        "pending" => "ожидает",
        "signing" => "подпись",
        "completed" => "подписано",
        "failed" => "ошибка",
        other => other,
    }
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
