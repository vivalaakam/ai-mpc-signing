use std::io::stdout;
use std::time::Duration;

use ai_signing_protocol::{verify_ed25519, MAX_MESSAGE_LEN};
use ratatui::{
    crossterm::{
        event::{
            self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent,
            KeyEventKind, KeyModifiers,
        },
        execute,
    },
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

const TOKEN_CAP: usize = 512;

pub fn run(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("verify не принимает аргументы".into());
    }
    run_tui()
}

fn run_tui() -> Result<(), String> {
    let mut terminal = ratatui::try_init().map_err(|err| format!("терминал: {err}"))?;
    let _ = execute!(stdout(), EnableBracketedPaste);
    let _guard = TerminalGuard;
    let mut app = VerifyApp::default();
    loop_events(&mut terminal, &mut app)
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(stdout(), DisableBracketedPaste);
        ratatui::restore();
    }
}

fn loop_events(terminal: &mut ratatui::DefaultTerminal, app: &mut VerifyApp) -> Result<(), String> {
    while !app.quit {
        terminal
            .draw(|frame| app.draw(frame))
            .map_err(|err| err.to_string())?;
        if !event::poll(Duration::from_millis(50)).map_err(|err| err.to_string())? {
            continue;
        }
        match event::read().map_err(|err| err.to_string())? {
            Event::Key(key) => app.on_key(key),
            Event::Paste(text) => app.append(&text),
            _ => {}
        }
    }
    Ok(())
}

struct VerifyApp {
    key: String,
    signature: String,
    message: String,
    field: u8,
    notice: Option<String>,
    error: Option<String>,
    quit: bool,
}

impl Default for VerifyApp {
    fn default() -> Self {
        Self {
            key: String::new(),
            signature: String::new(),
            message: String::new(),
            field: 0,
            notice: None,
            error: None,
            quit: false,
        }
    }
}

impl VerifyApp {
    fn on_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        if is_ctrl(&key, 'c') || is_ctrl(&key, 'w') {
            self.quit = true;
            return;
        }
        match key.code {
            KeyCode::Esc => self.quit = true,
            KeyCode::Tab => self.field = (self.field + 1) % 3,
            KeyCode::BackTab => self.field = (self.field + 2) % 3,
            KeyCode::Enter => self.verify(),
            KeyCode::Backspace => {
                self.clear_result();
                match self.field {
                    0 => {
                        self.key.pop();
                    }
                    1 => {
                        self.signature.pop();
                    }
                    _ => {
                        self.message.pop();
                    }
                }
            }
            KeyCode::Char(ch) if is_text(key.modifiers) => self.append(&ch.to_string()),
            _ => {}
        }
    }

    fn verify(&mut self) {
        self.notice = None;
        self.error = None;
        match verify_ed25519(&self.key, self.message.as_bytes(), &self.signature) {
            Ok(()) => self.notice = Some("Подпись верна".into()),
            Err(err) => self.error = Some(err.to_string()),
        }
    }

    fn append(&mut self, extra: &str) {
        self.clear_result();
        if self.field == 2 {
            let room = MAX_MESSAGE_LEN.saturating_sub(self.message.len());
            let piece = prefix_bytes(extra, room);
            let truncated = piece.len() < extra.len();
            self.message.push_str(piece);
            if truncated {
                self.error = Some("Сообщение обрезано: максимум 64 КиБ".into());
            }
            return;
        }
        let current_len = if self.field == 0 {
            self.key.chars().count()
        } else {
            self.signature.chars().count()
        };
        let room = TOKEN_CAP.saturating_sub(current_len);
        let mut taken = String::new();
        for (index, ch) in extra.chars().enumerate() {
            if index == room {
                break;
            }
            taken.push(ch);
        }
        let truncated = extra.chars().count() > taken.chars().count();
        if self.field == 0 {
            self.key.push_str(&taken);
        } else {
            self.signature.push_str(&taken);
        }
        if truncated {
            self.error = Some("Поле обрезано: максимум 512 символов".into());
        }
    }

    fn clear_result(&mut self) {
        self.notice = None;
        self.error = None;
    }

    fn draw(&self, frame: &mut Frame) {
        let lines = vec![
            Line::from("Ключ и подпись — hex или base64. Сообщение сравнивается байт в байт."),
            Line::from(""),
            field_line("Ключ", &self.key, self.field == 0),
            field_line("Подпись", &self.signature, self.field == 1),
            field_line("Сообщение", &self.message, self.field == 2),
            Line::from(""),
            Line::from("Tab поле    Enter проверить    Esc закрыть"),
            Line::from(""),
            self.result_line(),
        ];
        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Проверка подписи "),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, frame.area());
    }

    fn result_line(&self) -> Line<'static> {
        if let Some(error) = &self.error {
            return Line::from(Span::styled(error.clone(), Style::default().fg(Color::Red)));
        }
        if let Some(notice) = &self.notice {
            return Line::from(Span::styled(
                notice.clone(),
                Style::default().fg(Color::Green),
            ));
        }
        Line::from("")
    }
}

fn field_line(label: &str, value: &str, focused: bool) -> Line<'static> {
    let shown = tail(value, 180);
    let cursor = if focused { "▌" } else { "" };
    let style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    Line::from(Span::styled(format!("{label}: {shown}{cursor}"), style))
}

fn tail(value: &str, limit: usize) -> String {
    let count = value.chars().count();
    if count <= limit {
        value.to_string()
    } else {
        let skip = count - limit;
        format!("…{}", value.chars().skip(skip).collect::<String>())
    }
}

fn prefix_bytes(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn is_text(modifiers: KeyModifiers) -> bool {
    !modifiers.contains(KeyModifiers::CONTROL) && !modifiers.contains(KeyModifiers::ALT)
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

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_arguments() {
        let err = super::run(&[String::from("лишнее")]).unwrap_err();
        assert_eq!(err, "verify не принимает аргументы");
    }
}
