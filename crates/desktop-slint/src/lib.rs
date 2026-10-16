mod controller;
pub mod log;
mod ui_sync;

#[cfg(feature = "test-harness")]
pub mod test_harness;

use std::sync::{Arc, Mutex};

use ai_signing_client::{listen, parse_args, Config, Store, UiState};
use slint::ComponentHandle;
use ui_sync::{attach_state_pump, push_to_ui, wire_ui, AppWindow, SharedController};

pub fn run() {
    let launch = match parse_args(std::env::args().skip(1)) {
        Ok(launch) => launch,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    if launch.rest.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Подпись MPC (Slint)\n\n  ai-signing-gui-slint [--config ПУТЬ] [--database ПУТЬ] [--verbose]\n\nSlint-клиент для десктопа и будущих мобильных сборок.\nЛоги: stderr; RUST_LOG=debug или --verbose.\nHeadless UI e2e: бинарник ai-signing-gui-slint-e2e из пакета ai-signing-e2e."
        );
        return;
    }
    log::init(launch.verbose);
    if let Some(extra) = launch.rest.first() {
        eprintln!("неизвестный аргумент: {extra}");
        std::process::exit(1);
    }
    if launch.certificate_path.is_some() {
        eprintln!("сертификат читает ai-signing-auto. В окне вход по имени и паролю.");
        std::process::exit(1);
    }
    if launch.test_script_path.is_some() {
        eprintln!("--test-script только у ai-signing-gui-slint-e2e (пакет ai-signing-e2e).");
        std::process::exit(1);
    }

    let config = match Config::load(&launch.config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let store = match Store::open_path(&launch.database_path) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("не удалось открыть локальную базу: {err}");
            std::process::exit(1);
        }
    };
    let (listener, _socket) = match listen(&launch.database_path) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let server = config.server_url();
    let initial = UiState::from_store(&store, &server);
    let (commands, events) = ai_signing_client::start(store, server.clone(), listener);

    let shared: SharedController = Arc::new(Mutex::new(controller::Controller::new(
        commands.clone(),
        initial.clone(),
    )));

    let ui = AppWindow::new().expect("окно Slint");
    ui.window().on_close_requested(move || {
        slint::quit_event_loop().expect("выход из цикла Slint");
        slint::CloseRequestResponse::HideWindow
    });
    wire_ui(&ui, shared.clone());
    push_to_ui(&ui, &shared.lock().expect("controller"));
    let _state_pump = attach_state_pump(&ui, shared.clone(), events);
    tracing::info!(server = %server, database = %launch.database_path.display(), "Slint-клиент запущен");
    ui.run().expect("цикл Slint");
}
