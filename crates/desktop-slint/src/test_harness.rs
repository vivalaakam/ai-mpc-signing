//! Headless controller bootstrap for Slint UI e2e (no window).

use std::path::Path;
use std::sync::{Arc, Mutex};

use ai_signing_client::{listen, Config, Store, UiState};
use async_channel::Receiver;

pub use crate::controller::Controller;

pub type SharedController = Arc<Mutex<Controller>>;

pub fn bootstrap(
    config_path: &Path,
    database_path: &Path,
) -> Result<(SharedController, Receiver<UiState>, String), String> {
    let config = Config::load(config_path)?;
    let store = Store::open_path(database_path)
        .map_err(|err| format!("не удалось открыть локальную базу: {err}"))?;
    let (listener, _socket) = listen(database_path)?;
    let server = config.server_url();
    let initial = UiState::from_store(&store, &server);
    let (commands, events) = ai_signing_client::start(store, server.clone(), listener);
    let shared = Arc::new(Mutex::new(Controller::new(commands, initial)));
    Ok((shared, events, server))
}

pub fn spawn_state_pump(shared: SharedController, events: Receiver<UiState>) {
    std::thread::spawn(move || {
        while let Ok(state) = events.recv_blocking() {
            if let Ok(mut controller) = shared.lock() {
                controller.apply(state);
            }
        }
    });
}
