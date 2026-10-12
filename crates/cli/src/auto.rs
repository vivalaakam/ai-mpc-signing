use std::process::ExitCode;

use ai_signing_client::{auto, load_certificate, parse_args, socket_path_for, Config, Store};

const HELP: &str = "\
ai-signing-auto — подписывает запросы сам

Использование:
  ai-signing-auto [--config ПУТЬ] [--database ПУТЬ] --certificate ПУТЬ

Слушает тот же сокет, что окно и командная строка, и сразу подтверждает
каждый запрос на подпись. Вход по сертификату, который выпустил администратор:
имя и пароль не нужны. Сертификат открывает локальные ключи этой базы.
База задаётся флагом --database. Без флага используется каталог данных
или AI_SIGNING_HOME. Пока процесс запущен, команды с той же базой передаются ему.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let launch = parse_args(std::env::args().skip(1))?;
    if launch.rest.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{HELP}");
        return Ok(());
    }
    if !launch.rest.is_empty() {
        return Err(format!(
            "неизвестный аргумент: {}\n\n{HELP}",
            launch.rest[0]
        ));
    }
    let certificate_path = launch
        .certificate_path
        .as_deref()
        .ok_or_else(|| format!("укажите --certificate ПУТЬ\n\n{HELP}"))?;
    let certificate = load_certificate(certificate_path)?;
    let config = Config::load(&launch.config_path)?;
    let store = Store::open_path(&launch.database_path)?;
    let socket = socket_path_for(&launch.database_path)?;
    auto(store, config.server_url(), &socket, certificate)
}
