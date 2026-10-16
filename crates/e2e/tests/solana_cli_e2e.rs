//! Three CLI signers (`watch`), the admin CLI, the server and the docker-compose Solana validator.
//!
//! Unlike `solana_e2e`, these signers log in with a password and stay online through `watch`.
//! Each one approves the transfer with `approve`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ai_signing_protocol::{verify_ed25519, CertificateMaterial, GroupDto, SignRequestDto};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

const SOLANA_RPC: &str = "http://127.0.0.1:8899";
const LAMPORTS: u64 = 1_000_000;
const AIRDROP: u64 = 1_000_000_000;

fn progress(message: impl std::fmt::Display) {
    info!("solana_cli_e2e: {message}");
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Signer {
    name: String,
    db: PathBuf,
    log: PathBuf,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_cli_signers_send_a_solana_transfer() {
    std::env::set_var("SOLANA_RPC_URL", SOLANA_RPC);
    ai_signing_server::init_tracing();
    let http = reqwest::Client::new();
    wait_solana(&http).await;

    let state = ai_signing_server::bootstrap().await.expect("postgres");
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let names = [
        format!("cli_a_{suffix}"),
        format!("cli_b_{suffix}"),
        format!("cli_c_{suffix}"),
    ];
    let admin_name = format!("cli_e_{suffix}");
    for name in names.iter().chain(std::iter::once(&admin_name)) {
        let _ = ai_signing_server::delete_user(&state, name).await;
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        ai_signing_server::serve(listener, server_state)
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");

    // macOS sun_path вмещает 104 байта, а путь из temp_dir() длиннее.
    let root = PathBuf::from(format!("/tmp/scli-{suffix}"));
    std::fs::create_dir_all(&root).unwrap();
    let config = root.join("config.toml");
    std::fs::write(&config, format!("server = \"{base}\"\n")).unwrap();
    let admin_db = root.join(format!("data/admin_{suffix}.sqlite"));
    let signers: Vec<Signer> = names
        .iter()
        .enumerate()
        .map(|(index, name)| Signer {
            name: name.clone(),
            db: root.join(format!("data/{index}_{suffix}.sqlite")),
            log: root.join(format!("data/{index}_{suffix}.log")),
        })
        .collect();

    let password = "password1";
    for signer in &signers {
        progress(format!("создаю пользователя {} (подписант)", signer.name));
        admin(
            &config,
            &["create-user", &signer.name, password, "подписант"],
        );
        progress(format!("вхожу как {} (подписант)", signer.name));
        let logged_in: serde_json::Value =
            cli(&config, &signer.db, &["login", &signer.name, password]);
        assert_eq!(logged_in["username"], signer.name);
        assert_eq!(logged_in["role"], "signer");
    }
    progress(format!("создаю пользователя {admin_name} (админ)"));
    admin(&config, &["create-user", &admin_name, password, "админ"]);
    progress(format!("вхожу как {admin_name}"));
    let admin_login: serde_json::Value = cli(&config, &admin_db, &["login", &admin_name, password]);
    assert_eq!(admin_login["role"], "admin");

    let running: Vec<Proc> = signers
        .iter()
        .map(|signer| {
            progress(format!(
                "запускаю подписанта {} через cli watch, лог {}",
                signer.name,
                signer.log.display()
            ));
            Proc(spawn_watch(&config, &signer.db, &signer.log, password))
        })
        .collect();
    for signer in &signers {
        wait_socket(&socket_of(&signer.db), &signer.log);
        wait_connected(&config, &signer.db, &signer.log);
    }
    wait_signers(&config, &admin_db, &names);

    let mut create = vec!["create-group".to_string(), "treasury".into(), "3".into()];
    create.extend(names.iter().cloned());
    let create_refs: Vec<&str> = create.iter().map(String::as_str).collect();
    progress(format!(
        "создаю группу treasury, порог 3, участники {}",
        names.join(", ")
    ));
    let group: GroupDto = cli(&config, &admin_db, &create_refs);
    assert_eq!(group.members.len(), 3);
    assert_eq!(group.threshold, 3);
    let group_id = group.id.to_string();
    wait_group(
        &config,
        &signers[0].db,
        &group_id,
        &signers,
        "ключи участников группы",
        |group| {
            group.members.len() == 3
                && group
                    .members
                    .iter()
                    .all(|member| member.box_public_hex.is_some())
        },
    );
    progress(format!("запускаю DKG группы {group_id}"));
    let _: GroupDto = cli(&config, &admin_db, &["start-dkg", &group_id]);
    let active = wait_group(
        &config,
        &signers[0].db,
        &group_id,
        &signers,
        "группа стала active",
        |group| group.status == "active",
    );
    let verifying_key = active
        .verifying_key_hex
        .clone()
        .expect("у группы есть ключ");
    let payer = active
        .solana_address
        .clone()
        .expect("ключ группы является адресом Solana");
    assert_eq!(payer, bs58::encode(unhex(&verifying_key)).into_string());
    progress(format!("адрес группы (отправитель): {payer}"));

    let recipient = {
        let material = CertificateMaterial::generate("payee");
        bs58::encode(unhex(&material.public_key_hex)).into_string()
    };
    progress(format!("адрес получателя: {recipient}"));
    airdrop(&http, &payer, AIRDROP).await;
    let recipient_before = airdrop(&http, &recipient, AIRDROP).await;

    progress(format!(
        "создаю перевод {LAMPORTS} lamports с {payer} на {recipient}"
    ));
    let created: SignRequestDto = cli(
        &config,
        &admin_db,
        &[
            "request-solana",
            &group_id,
            &recipient,
            &LAMPORTS.to_string(),
        ],
    );
    assert_eq!(created.status, "pending");
    assert_eq!(
        created.transaction.as_ref().map(|tx| tx.lamports),
        Some(LAMPORTS)
    );
    assert_eq!(
        created.transaction.as_ref().map(|tx| tx.recipient.as_str()),
        Some(recipient.as_str())
    );
    let request_id = created.id.to_string();
    for signer in &signers {
        progress(format!(
            "подтверждаю перевод {request_id} от {}",
            signer.name
        ));
        let decision: SignRequestDto = cli(&config, &signer.db, &["approve", &request_id]);
        assert_eq!(decision.my_decision.as_deref(), Some("approved"));
        progress(format!(
            "{} подтвердил, голосов {}/{}",
            signer.name, decision.approvals, decision.threshold
        ));
    }

    let signed = wait_inbox(&config, &admin_db, &request_id, &signers);
    assert_eq!(signed.status, "completed");
    let signature_hex = signed.signature_hex.expect("админ видит подпись");
    let network = signed
        .transaction
        .expect("перевод Solana")
        .transaction_signature
        .expect("сервер отправил транзакцию");
    verify_ed25519(&verifying_key, &unhex(&signed.message_hex), &signature_hex)
        .expect("подпись FROST является подписью Ed25519");
    assert_eq!(network, bs58::encode(unhex(&signature_hex)).into_string());
    wait_landed(&http, &network).await;
    let payer_after = balance(&http, &payer).await;
    let recipient_after = balance(&http, &recipient).await;
    progress(format!(
        "после перевода {LAMPORTS} lamports отправитель {payer}: {payer_after} lamports"
    ));
    progress(format!(
        "после перевода {LAMPORTS} lamports получатель {recipient}: {recipient_after} lamports (было {recipient_before})"
    ));
    assert_eq!(recipient_after, recipient_before + LAMPORTS);

    drop(running);
    for name in names.iter().chain(std::iter::once(&admin_name)) {
        ai_signing_server::delete_user(&state, name).await.unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
}

async fn wait_solana(http: &reqwest::Client) {
    progress(format!(
        "цикл: проверяю, что Solana уже запущена ({SOLANA_RPC})"
    ));
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut last = String::new();
    while Instant::now() < deadline {
        match rpc(http, "getHealth", json!([])).await {
            Ok(value) if value["result"] == "ok" => {
                progress("Solana RPC отвечает");
                return;
            }
            Ok(value) => last = value.to_string(),
            Err(err) => last = err,
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("Solana RPC не ответил: {last}");
}

async fn airdrop(http: &reqwest::Client, address: &str, lamports: u64) -> u64 {
    progress(format!("airdrop {lamports} lamports на {address}"));
    let value = rpc(http, "requestAirdrop", json!([address, lamports]))
        .await
        .unwrap_or_else(|err| panic!("airdrop {address}: {err}"));
    let signature = value["result"]
        .as_str()
        .unwrap_or_else(|| panic!("airdrop {address}: {value}"))
        .to_string();
    wait_landed(http, &signature).await;
    let now = balance(http, address).await;
    progress(format!("баланс {address}: {now} lamports"));
    now
}

async fn balance(http: &reqwest::Client, address: &str) -> u64 {
    let value = rpc(
        http,
        "getBalance",
        json!([address, {"commitment": "confirmed"}]),
    )
    .await
    .unwrap_or_else(|err| panic!("баланс {address}: {err}"));
    value
        .pointer("/result/value")
        .and_then(|item| item.as_u64())
        .unwrap_or_else(|| panic!("баланс {address}: {value}"))
}

async fn wait_landed(http: &reqwest::Client, signature: &str) {
    progress(format!("цикл: жду подтверждение транзакции {signature}"));
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut last = String::new();
    while Instant::now() < deadline {
        match rpc(
            http,
            "getSignatureStatuses",
            json!([[signature], {"searchTransactionHistory": true}]),
        )
        .await
        {
            Ok(value) => {
                let status = value
                    .pointer("/result/value/0")
                    .cloned()
                    .unwrap_or(json!(null));
                if !status.is_null() {
                    if status.get("err").is_some_and(|err| !err.is_null()) {
                        panic!("Solana отклонила {signature}: {status}");
                    }
                    if matches!(
                        status
                            .get("confirmationStatus")
                            .and_then(|item| item.as_str()),
                        Some("confirmed" | "finalized")
                    ) {
                        progress(format!("транзакция подтверждена: {signature}"));
                        return;
                    }
                }
                last = status.to_string();
            }
            Err(err) => last = err,
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    panic!("транзакция не подтвердилась: {signature}\n{last}");
}

async fn rpc(
    http: &reqwest::Client,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let response = http
        .post(SOLANA_RPC)
        .timeout(Duration::from_secs(10))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let value: serde_json::Value = response.json().await.map_err(|err| err.to_string())?;
    if let Some(error) = value.get("error") {
        return Err(error.to_string());
    }
    Ok(value)
}

fn unhex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "нечётный hex: {value}");
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex"))
        .collect()
}

fn admin(config: &Path, args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-admin-e2e"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("ai-signing-admin");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "команда {args:?} завершилась с ошибкой\nstdout: {stdout}\nstderr: {stderr}"
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("ответ не json ({err})\nstdout: {stdout}\nstderr: {stderr}"))
}

fn cli<T: serde::de::DeserializeOwned>(config: &Path, database: &Path, args: &[&str]) -> T {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .args(args)
        .output()
        .expect("запуск cli");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "команда {args:?} завершилась с ошибкой\nstdout: {stdout}\nstderr: {stderr}"
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("ответ не json ({err})\nstdout: {stdout}\nstderr: {stderr}"))
}

fn spawn_watch(config: &Path, database: &Path, log: &Path, password: &str) -> Child {
    let file = std::fs::File::create(log).expect("лог подписанта");
    Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .args(["watch", password])
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .expect("watch")
}

fn socket_of(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(".sock");
    PathBuf::from(name)
}

fn wait_socket(path: &Path, log: &Path) {
    progress(format!("цикл: жду сокет {}", path.display()));
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            progress(format!("сокет готов: {}", path.display()));
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("сокет не поднялся: {}\n{}", path.display(), read_log(log));
}

fn wait_connected(config: &Path, database: &Path, log: &Path) {
    progress(format!(
        "цикл: жду связь с сервером, база {}",
        database.display()
    ));
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    while Instant::now() < deadline {
        let value: serde_json::Value = cli(config, database, &["whoami"]);
        last = value.to_string();
        if value["connected"] == true {
            progress(format!(
                "есть связь с сервером, база {}",
                database.display()
            ));
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("нет связи с сервером: {last}\n{}", read_log(log));
}

fn wait_signers(config: &Path, database: &Path, names: &[String]) {
    progress(format!("цикл: жду ключи подписантов {}", names.join(", ")));
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    while Instant::now() < deadline {
        let signers: Vec<serde_json::Value> = cli(config, database, &["signers"]);
        last = serde_json::to_string(&signers).unwrap_or_default();
        if names.iter().all(|name| {
            signers
                .iter()
                .any(|signer| signer["username"].as_str() == Some(name))
        }) {
            progress("все подписанты опубликовали ключ");
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("не все подписанты опубликовали ключ: {last}");
}

fn wait_group(
    config: &Path,
    database: &Path,
    group_id: &str,
    signers: &[Signer],
    what: &str,
    ready: impl Fn(&GroupDto) -> bool,
) -> GroupDto {
    progress(format!("цикл: {what}"));
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let group: GroupDto = cli(config, database, &["group", group_id]);
        if group.status == "failed" {
            panic!(
                "генерация ключа не удалась: {group:?}\n{}",
                signer_logs(signers)
            );
        }
        if ready(&group) {
            progress(format!("готово: {what}"));
            return group;
        }
        last = format!("{group:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "группа не перешла в нужный статус: {last}\n{}",
        signer_logs(signers)
    );
}

fn wait_inbox(
    config: &Path,
    database: &Path,
    request_id: &str,
    signers: &[Signer],
) -> SignRequestDto {
    progress(format!("цикл: жду подпись и отправку запроса {request_id}"));
    let deadline = Instant::now() + Duration::from_secs(60);
    let wanted: Uuid = request_id.parse().unwrap();
    let mut last = String::new();
    while Instant::now() < deadline {
        let requests: Vec<SignRequestDto> = cli(config, database, &["inbox"]);
        if let Some(request) = requests.into_iter().find(|request| request.id == wanted) {
            if request.status == "failed" {
                panic!("подпись не удалась: {request:?}\n{}", signer_logs(signers));
            }
            if request.status == "completed" {
                progress(format!("запрос {request_id} выполнен"));
                return request;
            }
            last = format!("{request:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("перевод не собрался: {last}\n{}", signer_logs(signers));
}

fn signer_logs(signers: &[Signer]) -> String {
    signers
        .iter()
        .map(|signer| {
            format!(
                "--- {} ({}) ---\n{}",
                signer.name,
                signer.log.display(),
                read_log(&signer.log)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
