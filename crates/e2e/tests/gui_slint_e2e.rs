//! Slint GUI: admin window + one signer window, остальные — автоподписанты.
//! Полный цикл: группа, DKG, три перевода Solana, reshare (remove + add).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ai_signing_protocol::{CertificateMaterial, GroupDto};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

const SOLANA_RPC: &str = "http://127.0.0.1:8899";
const LAMPORTS: u64 = 1_000_000;
const AIRDROP: u64 = 1_000_000_000;

fn progress(message: impl std::fmt::Display) {
    info!("gui_slint_e2e: {message}");
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct AutoSigner {
    name: String,
    db: PathBuf,
    cert: PathBuf,
    log: PathBuf,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn slint_admin_and_signer_full_cycle_with_reshare() {
    std::env::set_var("SOLANA_RPC_URL", SOLANA_RPC);
    ai_signing_server::init_tracing();
    let http = reqwest::Client::new();
    wait_solana(&http).await;

    let state = ai_signing_server::bootstrap().await.expect("postgres");
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let gui_signer = format!("gui_s_{suffix}");
    let autos = [
        format!("gui_a0_{suffix}"),
        format!("gui_a1_{suffix}"),
        format!("gui_a2_{suffix}"),
    ];
    let admin_name = format!("gui_e_{suffix}");
    for name in autos
        .iter()
        .chain(std::iter::once(&gui_signer))
        .chain(std::iter::once(&admin_name))
    {
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

    let root = PathBuf::from(format!("/tmp/slint-gui-{suffix}"));
    std::fs::create_dir_all(&root).unwrap();
    let config = root.join("config.toml");
    std::fs::write(&config, format!("server = \"{base}\"\n")).unwrap();
    let admin_db = root.join("admin.sqlite");
    let signer_db = root.join("signer.sqlite");
    let signer_log = root.join("signer.log");
    let admin_log = root.join("admin.log");
    let password = "password1";

    let auto_signers: Vec<AutoSigner> = autos
        .iter()
        .enumerate()
        .map(|(index, name)| AutoSigner {
            name: name.clone(),
            db: root.join(format!("auto{index}.sqlite")),
            cert: root.join(format!("auto{index}.cert.json")),
            log: root.join(format!("auto{index}.log")),
        })
        .collect();

    for auto in &auto_signers {
        progress(format!("создаю автоподписанта {}", auto.name));
        admin(
            &config,
            &["create-user", &auto.name, password, "подписант"],
        );
        admin(
            &config,
            &["issue-cert", &auto.name, &auto.cert.to_string_lossy()],
        );
    }
    progress(format!("создаю подписанта {gui_signer} (окно Slint)"));
    admin(
        &config,
        &["create-user", &gui_signer, password, "подписант"],
    );
    progress(format!("создаю админа {admin_name}"));
    admin(
        &config,
        &["create-user", &admin_name, password, "админ"],
    );

    let running_autos: Vec<Proc> = auto_signers
        .iter()
        .map(|auto| {
            progress(format!("запускаю автоподписанта {}", auto.name));
            Proc(spawn_auto(&config, &auto.db, &auto.cert, &auto.log))
        })
        .collect();
    for auto in &auto_signers {
        wait_socket(&socket_of(&auto.db), &auto.log);
        wait_connected_cli(&config, &auto.db, &auto.log);
    }

    let recipient = {
        let material = CertificateMaterial::generate("payee");
        bs58::encode(unhex(&material.public_key_hex)).into_string()
    };
    let recipient_before = airdrop(&http, &recipient, AIRDROP).await;

    let signer_plan = root.join("signer.plan.json");
    std::fs::write(
        &signer_plan,
        format!(
            r#"{{
  "steps": [
    {{ "step": "login", "username": "{gui_signer}", "password": "{password}" }},
    {{ "step": "wait_group", "name": "treasury", "status": "active", "timeout_secs": 480 }},
    {{ "step": "wait_pending" }},
    {{ "step": "approve_first_pending" }},
    {{ "step": "sleep", "millis": 45000 }},
    {{ "step": "wait_pending" }},
    {{ "step": "approve_first_pending" }},
    {{ "step": "sleep", "millis": 45000 }},
    {{ "step": "wait_pending" }},
    {{ "step": "approve_first_pending" }},
    {{ "step": "done" }}
  ]
}}"#
        ),
    )
    .unwrap();

    let member_names: Vec<&str> = std::iter::once(gui_signer.as_str())
        .chain(autos.iter().map(String::as_str))
        .collect();
    let members_json: String = member_names
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let admin_plan = root.join("admin.plan.json");
    std::fs::write(
        &admin_plan,
        format!(
            r#"{{
  "steps": [
    {{ "step": "login", "username": "{admin_name}", "password": "{password}" }},
    {{ "step": "create_group", "name": "treasury", "threshold": 3, "members": [{members_json}] }},
    {{ "step": "wait_group", "name": "treasury", "members_with_keys": 4, "timeout_secs": 480 }},
    {{ "step": "start_dkg" }},
    {{ "step": "wait_group", "name": "treasury", "status": "active", "timeout_secs": 480 }},
    {{ "step": "sleep", "millis": 15000 }},
    {{ "step": "request_solana", "recipient": "{recipient}", "lamports": {LAMPORTS} }},
    {{ "step": "sleep", "millis": 45000 }},
    {{ "step": "select_group", "name": "treasury" }},
    {{ "step": "reshare", "add": [], "remove": ["{}"] }},
    {{ "step": "wait_group", "name": "treasury", "status": "active", "members": 3, "timeout_secs": 240 }},
    {{ "step": "request_solana", "recipient": "{recipient}", "lamports": {LAMPORTS} }},
    {{ "step": "sleep", "millis": 45000 }},
    {{ "step": "sleep", "millis": 60000 }},
    {{ "step": "refresh" }},
    {{ "step": "reshare", "add": ["{}"], "remove": [] }},
    {{ "step": "wait_group", "name": "treasury", "status": "active", "members": 4, "timeout_secs": 240 }},
    {{ "step": "request_solana", "recipient": "{recipient}", "lamports": {LAMPORTS} }},
    {{ "step": "sleep", "millis": 45000 }},
    {{ "step": "done" }}
  ]
}}"#,
            autos[2], autos[2]
        ),
    )
    .unwrap();

    let airdrop_config = config.clone();
    let airdrop_admin_db = admin_db.clone();
    let airdrop_http = http.clone();
    let airdrop_task = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(720);
        while Instant::now() < deadline {
            let groups = tokio::task::spawn_blocking({
                let config = airdrop_config.clone();
                let admin_db = airdrop_admin_db.clone();
                move || try_groups(&config, &admin_db)
            })
            .await
            .expect("groups task");
            let Some(groups) = groups else {
                tokio::time::sleep(Duration::from_millis(400)).await;
                continue;
            };
            if let Some(group) = groups.iter().find(|group| group.name == "treasury") {
                if group.status == "active" {
                    if let Some(payer) = &group.solana_address {
                        airdrop(&airdrop_http, payer, AIRDROP).await;
                        progress(format!("airdrop на адрес группы {payer}"));
                        return;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        progress("airdrop: группа treasury так и не стала active");
    });

    let admin_handle = std::thread::spawn({
        let config = config.clone();
        let admin_db = admin_db.clone();
        let admin_plan = admin_plan.clone();
        let admin_log = admin_log.clone();
        move || spawn_gui(&config, &admin_db, &admin_plan, &admin_log)
    });

    let _ = airdrop_task;

    progress("жду active группы treasury перед запуском окна подписанта");
    let wait_active = Instant::now() + Duration::from_secs(480);
    while Instant::now() < wait_active {
        if let Some(groups) = try_groups(&config, &admin_db) {
            if groups.iter().any(|group| group.name == "treasury" && group.status == "active") {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(400));
    }

    let signer_handle = std::thread::spawn({
        let config = config.clone();
        let signer_db = signer_db.clone();
        let signer_plan = signer_plan.clone();
        let signer_log = signer_log.clone();
        move || spawn_gui(&config, &signer_db, &signer_plan, &signer_log)
    });

    let signer_status = signer_handle.join().expect("signer thread");
    let admin_status = admin_handle.join().expect("admin thread");
    assert!(
        signer_status.status.success(),
        "signer Slint завершился с ошибкой\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&signer_status.stdout),
        String::from_utf8_lossy(&signer_status.stderr)
    );
    assert!(
        admin_status.status.success(),
        "admin Slint завершился с ошибкой\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&admin_status.stdout),
        String::from_utf8_lossy(&admin_status.stderr)
    );

    let group: GroupDto = cli(
        &config,
        &admin_db,
        &["group", &group_id(&config, &admin_db, "treasury")],
    );
    let verifying_key = group.verifying_key_hex.expect("ключ группы");
    let payer = group.solana_address.clone().expect("адрес группы");
    let recipient_after = balance(&http, &recipient).await;
    assert_eq!(recipient_after, recipient_before + LAMPORTS * 3);
    progress(format!(
        "три перевода с {payer} на {recipient} подтверждены, vk {verifying_key}"
    ));

    drop(running_autos);
    for name in autos
        .iter()
        .chain(std::iter::once(&gui_signer))
        .chain(std::iter::once(&admin_name))
    {
        ai_signing_server::delete_user(&state, name).await.unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
}

fn group_id(config: &Path, admin_db: &Path, name: &str) -> String {
    let groups: Vec<GroupDto> = cli(config, admin_db, &["groups"]);
    groups
        .into_iter()
        .find(|group| group.name == name)
        .expect("группа")
        .id
        .to_string()
}

fn spawn_gui(
    config: &Path,
    database: &Path,
    plan: &Path,
    log: &Path,
) -> std::process::Output {
    let stderr = std::fs::File::create(log).expect("лог gui");
    Command::new(env!("CARGO_BIN_EXE_ai-signing-gui-slint-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .arg("--test-script")
        .arg(plan)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr))
        .output()
        .expect("ai-signing-gui-slint-e2e")
}

async fn wait_solana(http: &reqwest::Client) {
    progress(format!("жду Solana RPC {SOLANA_RPC}"));
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut last = String::new();
    while Instant::now() < deadline {
        match rpc(http, "getHealth", json!([])).await {
            Ok(value) if value["result"] == "ok" => return,
            Ok(value) => last = value.to_string(),
            Err(err) => last = err,
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("Solana RPC не ответил: {last}");
}

async fn airdrop(http: &reqwest::Client, address: &str, lamports: u64) -> u64 {
    let value = rpc(http, "requestAirdrop", json!([address, lamports]))
        .await
        .unwrap();
    let signature = value["result"].as_str().unwrap().to_string();
    wait_landed(http, &signature).await;
    balance(http, address).await
}

async fn wait_landed(http: &reqwest::Client, signature: &str) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        if let Ok(value) = rpc(
            http,
            "getSignatureStatuses",
            json!([[signature], {"searchTransactionHistory": true}]),
        )
        .await
        {
            let status = value.pointer("/result/value/0").cloned().unwrap_or(json!(null));
            if matches!(
                status.get("confirmationStatus").and_then(|v| v.as_str()),
                Some("confirmed" | "finalized")
            ) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    panic!("транзакция не подтвердилась: {signature}");
}

async fn balance(http: &reqwest::Client, address: &str) -> u64 {
    let value = rpc(
        http,
        "getBalance",
        json!([address, {"commitment": "confirmed"}]),
    )
    .await
    .unwrap();
    value["result"]["value"].as_u64().unwrap()
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
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn admin(config: &Path, args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-admin-e2e"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("admin");
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn try_groups(config: &Path, database: &Path) -> Option<Vec<GroupDto>> {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .arg("groups")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

fn cli<T: serde::de::DeserializeOwned>(config: &Path, database: &Path, args: &[&str]) -> T {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .args(args)
        .output()
        .expect("cli");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn spawn_auto(config: &Path, database: &Path, certificate: &Path, log: &Path) -> Child {
    let file = std::fs::File::create(log).expect("лог");
    Command::new(env!("CARGO_BIN_EXE_ai-signing-auto-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .arg("--certificate")
        .arg(certificate)
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .expect("auto")
}

fn socket_of(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(".sock");
    PathBuf::from(name)
}

fn wait_socket(path: &Path, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("сокет не появился, лог {}", log.display());
}

fn wait_connected_cli(config: &Path, database: &Path, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
            .arg("--config")
            .arg(config)
            .arg("--database")
            .arg(database)
            .arg("whoami")
            .output()
            .expect("whoami");
        if output.status.success() {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            if value["connected"] == true {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("нет связи, лог {}", log.display());
}
