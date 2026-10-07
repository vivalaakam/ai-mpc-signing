use std::process::ExitCode;
use std::time::Duration;

use ai_signing_client::{parse_args, Config};

const HELP: &str = "\
ai-signing-admin — пользователи сервера

Использование:
  ai-signing-admin [--config ПУТЬ] КОМАНДА

Адрес сервера берётся из конфига, поле server.

Команды:
  create-user ИМЯ ПАРОЛЬ РОЛЬ   создать учётную запись
  users                         список пользователей
  delete-user ИМЯ               удалить учётную запись

Роль: подписант или админ.
Имя: 3–32 символа, латиница, цифры, _ и -.
Пароль: не короче 8 символов.
Группу создаёт администратор. Подписант входит в клиент и участвует в подписи.
После создания пользователь входит через клиент.
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
    if launch.rest.is_empty() || launch.rest.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{HELP}");
        if launch.rest.is_empty() {
            return Err("укажите команду".into());
        }
        return Ok(());
    }
    let command = launch.rest[0].as_str();
    let args = &launch.rest[1..];
    match command {
        "create-user" => {
            if args.len() != 3 {
                return Err("использование: create-user ИМЯ ПАРОЛЬ РОЛЬ".into());
            }
            let config = Config::load(&launch.config_path)?;
            let created = create_user(&config.server_url(), &args[0], &args[1], &args[2])?;
            println!("{created}");
            Ok(())
        }
        "users" => {
            if !args.is_empty() {
                return Err("использование: users".into());
            }
            let config = Config::load(&launch.config_path)?;
            let users = list_users(&config.server_url())?;
            println!("{users}");
            Ok(())
        }
        "delete-user" => {
            if args.len() != 1 {
                return Err("использование: delete-user ИМЯ".into());
            }
            let config = Config::load(&launch.config_path)?;
            let deleted = delete_user(&config.server_url(), &args[0])?;
            println!("{deleted}");
            Ok(())
        }
        other => Err(format!("неизвестная команда: {other}\n\n{HELP}")),
    }
}

fn create_user(server: &str, username: &str, password: &str, role: &str) -> Result<String, String> {
    let text = send(
        client()?
            .post(format!("{server}/api/users"))
            .json(&serde_json::json!({
                "username": username,
                "password": password,
                "role": role,
            })),
    )?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|err| format!("{err}: {text}"))?;
    serde_json::to_string(&user_value(&value, &text)?).map_err(|err| err.to_string())
}

fn delete_user(server: &str, username: &str) -> Result<String, String> {
    let text = send(client()?.delete(format!("{server}/api/users/{username}")))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|err| format!("{err}: {text}"))?;
    serde_json::to_string(&user_value(&value, &text)?).map_err(|err| err.to_string())
}

fn list_users(server: &str) -> Result<String, String> {
    let text = send(client()?.get(format!("{server}/api/users")))?;
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&text).map_err(|err| format!("{err}: {text}"))?;
    let mut users = Vec::with_capacity(rows.len());
    for row in &rows {
        users.push(user_value(row, &text)?);
    }
    serde_json::to_string(&users).map_err(|err| err.to_string())
}

fn client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|err| err.to_string())
}

fn send(request: reqwest::blocking::RequestBuilder) -> Result<String, String> {
    let response = request
        .send()
        .map_err(|err| format!("сервер недоступен: {err}"))?;
    let status = response.status();
    let text = response
        .text()
        .map_err(|err| format!("ответ сервера: {err}"))?;
    if !status.is_success() {
        return Err(api_message(&text, status));
    }
    Ok(text)
}

fn user_value(value: &serde_json::Value, text: &str) -> Result<serde_json::Value, String> {
    let user_id = value
        .get("user_id")
        .and_then(|item| item.as_str())
        .ok_or_else(|| format!("сервер не вернул пользователя: {text}"))?;
    let name = value
        .get("username")
        .and_then(|item| item.as_str())
        .ok_or_else(|| format!("сервер не вернул пользователя: {text}"))?;
    let role = value
        .get("role")
        .and_then(|item| item.as_str())
        .ok_or_else(|| format!("сервер не вернул пользователя: {text}"))?;
    Ok(serde_json::json!({
        "user_id": user_id,
        "username": name,
        "role": role,
    }))
}

fn api_message(text: &str, status: reqwest::StatusCode) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|item| item.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("{status}: {text}"))
}
