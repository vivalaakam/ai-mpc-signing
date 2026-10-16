mod plan;
mod runner;
mod wait;

pub use plan::load_plan;
pub use runner::run_plan;

use std::path::Path;
use std::time::Duration;

use ai_signing_client::parse_args;
use ai_signing_desktop_slint::test_harness;

pub fn run_from_cli() {
    let launch = match parse_args(std::env::args().skip(1)) {
        Ok(launch) => launch,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let Some(script) = launch.test_script_path else {
        eprintln!("ai-signing-gui-slint-e2e: нужен --test-script ПЛАН.json");
        std::process::exit(1);
    };
    if launch.certificate_path.is_some() {
        eprintln!("сертификат не поддерживается в e2e Slint-клиенте");
        std::process::exit(1);
    }
    ai_signing_desktop_slint::log::init(launch.verbose);
    run_script(&launch.config_path, &launch.database_path, &script);
}

fn run_script(config: &Path, database: &Path, script: &Path) {
    let (shared, events, server) =
        test_harness::bootstrap(config, database).unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        });
    test_harness::spawn_state_pump(shared.clone(), events);
    std::thread::sleep(Duration::from_millis(300));
    tracing::info!(%server, database = %database.display(), "Slint e2e headless");
    let plan = load_plan(script).unwrap_or_else(|err| {
        eprintln!("план e2e: {err}");
        std::process::exit(1);
    });
    if let Err(err) = run_plan(&shared, &plan.steps) {
        eprintln!("slint e2e: ошибка: {err}");
        std::process::exit(1);
    }
    eprintln!("slint e2e: готово");
}
