use ai_signing_client::UiState;
use tracing_subscriber::EnvFilter;

pub fn init(verbose: bool) {
    let default = if verbose {
        "ai_signing_desktop_slint=trace,ai_signing_client=debug,reqwest=warn,warn"
    } else {
        "ai_signing_desktop_slint=info,ai_signing_client=info,warn"
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    match tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init()
    {
        Ok(()) => eprintln!(
            "ai-signing-gui-slint: логи в stderr (RUST_LOG переопределяет фильтр, --verbose = trace)"
        ),
        Err(_) => eprintln!("ai-signing-gui-slint: tracing уже инициализирован"),
    }
}

/// Всегда в stderr — видно даже при запуске двойным кликом без RUST_LOG.
pub fn login_user_action(username: &str, password_len: usize) {
    eprintln!(
        "[gui-slint] вход: user={username:?} password_len={password_len}"
    );
}

pub fn state_event(state: &UiState) {
    tracing::info!(
        username = ?state.username,
        role = ?state.role,
        unlocked = state.unlocked,
        connected = state.connected,
        error = ?state.error,
        notice = ?state.notice,
        groups = state.groups.len(),
        requests = state.requests.len(),
        "ui state"
    );
    if state.unlocked {
        eprintln!(
            "[gui-slint] вошли: user={:?} role={:?} connected={}",
            state.username, state.role, state.connected
        );
    }
    if let Some(err) = &state.error {
        tracing::warn!("{err}");
        eprintln!("[gui-slint] ошибка: {err}");
    }
}
