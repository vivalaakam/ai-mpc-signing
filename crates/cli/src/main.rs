mod tui;
mod verify;

use std::process::ExitCode;
use std::time::Duration;

use ai_signing_client::{
    execute, parse_args, socket_path_for, try_forward, watch, Cmd, Config, Launch, Reply,
    SettleWait, Store,
};
use uuid::Uuid;

const HELP: &str = "\
Подпись MPC

Использование:
  ai-signing-cli [--config ПУТЬ] [--database ПУТЬ]
  ai-signing-cli [--config ПУТЬ] [--database ПУТЬ] КОМАНДА

Без команды открывается текстовый интерфейс. Он держит связь с сервером
и участвует в протоколе. Вход каждый раз спрашивает пароль: им зашифрованы
личный ключ и доли ключей на этом устройстве. Адрес сервера берётся из конфига, поле server.
Если конфига ещё нет, он создаётся с адресом http://127.0.0.1:8080.
Переменная AI_SIGNING_HOME задаёт каталог конфига и базы, когда пути не переданы.

В интерфейсе: Ctrl+Q выйти из учётной записи, Ctrl+W закрыть, u обновить, Tab вкладка,
j/k выбор. Админ: n новая группа, d генерация ключа, s сообщение на подпись.
На подписанном сообщении: 1 копировать ключ, 2 подпись, 3 сообщение, f формат hex или base64.
Подписант: a подписать, r отклонить. В новой группе пробел отмечает подписанта,
Enter создаёт группу. На экране сообщения Enter отправляет текст.

Команды:
  login ИМЯ ПАРОЛЬ                 войти
  logout                           выйти
  whoami                           текущий пользователь и связь с сервером
  groups                           список групп
  group ID                         одна группа
  signers                          активные подписанты
  create-group НАЗВАНИЕ T ИМЯ...   создать группу, 2 ≤ t ≤ n ≤ 16
  add-member ID ИМЯ                добавить участника в недособранную группу
  start-dkg ID                     запустить генерацию ключа
  request-sign ID СООБЩЕНИЕ...     отправить текст на подпись в активную группу
  inbox                            запросы на подпись
  approve ID                       подтвердить подпись
  reject ID                        отклонить запрос
  watch ПАРОЛЬ                     держать связь: пароль открывает локальные ключи
  verify                           проверить подпись в отдельном окне, без входа

Группу создаёт администратор и сразу выбирает подписантов.
Активный подписант уже входил в клиент, у него есть ключ устройства.
Пока открыты интерфейс, окно или watch с той же базой, команды передаются им.
На время генерации ключа и подписи у каждого подписанта должен быть открыт клиент.
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
    if launch.rest.is_empty() {
        let (store, server) = open(&launch)?;
        return tui::run(store, server, &launch.database_path);
    }
    let command = launch.rest[0].as_str();
    let args = &launch.rest[1..];
    if command == "verify" {
        return verify::run(args);
    }
    let socket = socket_path_for(&launch.database_path)?;
    if command == "watch" {
        if args.len() != 1 || args[0].is_empty() {
            return Err("использование: watch ПАРОЛЬ".into());
        }
        let (store, server) = open(&launch)?;
        return watch(store, server, &socket, &args[0]);
    }
    let (cmd, kind) = parse_command(command, args)?;
    if let Some(reply) = try_forward(&socket, &cmd)? {
        return emit(kind, reply);
    }
    let (store, server) = open(&launch)?;
    let connect = matches!(kind, Kind::StartDkg);
    let wait = match kind {
        Kind::StartDkg => Some(SettleWait {
            group_id: group_id_of(&cmd)?,
            timeout: Duration::from_secs(90),
        }),
        _ => None,
    };
    let reply = execute(store, server, cmd, connect, wait)?;
    emit(kind, reply)
}

fn open(launch: &Launch) -> Result<(Store, String), String> {
    let config = Config::load(&launch.config_path)?;
    let store = Store::open_path(&launch.database_path)?;
    Ok((store, config.server_url()))
}

enum Kind {
    Auth,
    Logout,
    Whoami,
    Groups,
    Group(Uuid),
    MutateGroup,
    Inbox,
    Signers,
    Decide,
    StartDkg,
    RequestSign,
}

fn parse_command(command: &str, args: &[String]) -> Result<(Cmd, Kind), String> {
    let need = |n: usize, usage: &str| -> Result<(), String> {
        if args.len() == n {
            Ok(())
        } else {
            Err(format!("использование: {usage}"))
        }
    };
    match command {
        "login" => {
            need(2, "login ИМЯ ПАРОЛЬ")?;
            Ok((
                Cmd::Login {
                    username: args[0].clone(),
                    password: args[1].clone(),
                },
                Kind::Auth,
            ))
        }
        "logout" => {
            need(0, "logout")?;
            Ok((Cmd::Logout, Kind::Logout))
        }
        "whoami" => {
            need(0, "whoami")?;
            Ok((Cmd::Status, Kind::Whoami))
        }
        "groups" => {
            need(0, "groups")?;
            Ok((Cmd::Refresh, Kind::Groups))
        }
        "group" => {
            need(1, "group ID")?;
            Ok((Cmd::Refresh, Kind::Group(parse_id(&args[0], "группы")?)))
        }
        "signers" => {
            need(0, "signers")?;
            Ok((Cmd::ListSigners, Kind::Signers))
        }
        "create-group" => {
            if args.len() < 3 {
                return Err("использование: create-group НАЗВАНИЕ T ИМЯ...".into());
            }
            let (threshold, members) = parse_group(&args[1], &args[2..])?;
            Ok((
                Cmd::CreateGroup {
                    name: args[0].clone(),
                    threshold,
                    members,
                },
                Kind::MutateGroup,
            ))
        }
        "add-member" => {
            need(2, "add-member ID ИМЯ")?;
            Ok((
                Cmd::AddMember {
                    group_id: parse_id(&args[0], "группы")?,
                    username: args[1].clone(),
                },
                Kind::MutateGroup,
            ))
        }
        "start-dkg" => {
            need(1, "start-dkg ID")?;
            Ok((
                Cmd::StartDkg {
                    group_id: parse_id(&args[0], "группы")?,
                },
                Kind::StartDkg,
            ))
        }
        "request-sign" => {
            if args.len() < 2 {
                return Err("использование: request-sign ID СООБЩЕНИЕ...".into());
            }
            let message = args[1..].join(" ");
            let message = message.trim().to_string();
            if message.is_empty() {
                return Err("укажите сообщение".into());
            }
            Ok((
                Cmd::RequestSign {
                    group_id: parse_id(&args[0], "группы")?,
                    message,
                },
                Kind::RequestSign,
            ))
        }
        "inbox" => {
            need(0, "inbox")?;
            Ok((Cmd::Refresh, Kind::Inbox))
        }
        "approve" => {
            need(1, "approve ID")?;
            Ok((
                Cmd::Approve {
                    request_id: parse_id(&args[0], "запроса")?,
                },
                Kind::Decide,
            ))
        }
        "reject" => {
            need(1, "reject ID")?;
            Ok((
                Cmd::Reject {
                    request_id: parse_id(&args[0], "запроса")?,
                },
                Kind::Decide,
            ))
        }
        other => Err(format!("неизвестная команда: {other}\n\n{HELP}")),
    }
}

fn emit(kind: Kind, reply: Reply) -> Result<(), String> {
    if !reply.ok {
        return Err(reply.error.unwrap_or_else(|| "ошибка".into()));
    }
    match kind {
        Kind::Auth => print_json(&serde_json::json!({
            "username": reply.username,
            "role": reply.role,
            "server": reply.server,
            "connected": reply.connected,
        })),
        Kind::Logout => print_json(&serde_json::json!({ "ok": true })),
        Kind::Whoami => {
            let username = reply.username.ok_or_else(|| "вы не вошли".to_string())?;
            print_json(&serde_json::json!({
                "username": username,
                "role": reply.role,
                "server": reply.server,
                "connected": reply.connected,
            }))
        }
        Kind::Groups => print_json(&reply.groups),
        Kind::Group(id) => {
            let group = reply
                .groups
                .iter()
                .find(|group| group.id == id)
                .ok_or_else(|| "группа не найдена".to_string())?;
            print_json(group)
        }
        Kind::MutateGroup | Kind::StartDkg => {
            let group = reply
                .group
                .ok_or_else(|| "сервер не вернул группу".to_string())?;
            print_json(&group)
        }
        Kind::Inbox => print_json(&reply.requests),
        Kind::Signers => print_json(&reply.signers),
        Kind::Decide | Kind::RequestSign => {
            let request = reply
                .request
                .ok_or_else(|| "сервер не вернул запрос".to_string())?;
            print_json(&request)
        }
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|err| err.to_string())?;
    println!("{text}");
    Ok(())
}

fn group_id_of(cmd: &Cmd) -> Result<Uuid, String> {
    match cmd {
        Cmd::StartDkg { group_id } => Ok(*group_id),
        _ => Err("ожидалась команда генерации ключа".into()),
    }
}

fn parse_id(value: &str, what: &str) -> Result<Uuid, String> {
    value
        .parse()
        .map_err(|_| format!("не удалось прочитать идентификатор {what}"))
}

fn parse_group(threshold: &str, names: &[String]) -> Result<(u16, Vec<String>), String> {
    let threshold: u16 = threshold
        .trim()
        .parse()
        .map_err(|_| "порог t должен быть числом".to_string())?;
    let members: Vec<String> = names.iter().map(|name| name.trim().to_string()).collect();
    let max_signers = u16::try_from(members.len()).unwrap_or(u16::MAX);
    if !(2..=max_signers).contains(&threshold) || !(2..=16).contains(&max_signers) {
        return Err("порог t и размер n: 2 ≤ t ≤ n ≤ 16".into());
    }
    Ok((threshold, members))
}
