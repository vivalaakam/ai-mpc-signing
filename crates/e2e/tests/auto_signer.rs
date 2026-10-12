use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ai_signing_protocol::{verify_ed25519, GroupDto, SignRequestDto};
use serde_json::json;
use uuid::Uuid;

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn cli_rejects_the_certificate_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .args(["--certificate", "/tmp/nope.json", "whoami"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        err.contains("ai-signing-auto"),
        "командная строка не должна принимать сертификат: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_signer_approves_without_a_password() {
    ai_signing_server::init_tracing();
    let state = ai_signing_server::bootstrap().await.expect("postgres");
    let suffix = &Uuid::new_v4().simple().to_string()[..20];
    let alice_name = format!("auto_a_{suffix}");
    let bob_name = format!("auto_b_{suffix}");
    let eve_name = format!("auto_e_{suffix}");
    let _ = ai_signing_server::delete_user(&state, &alice_name).await;
    let _ = ai_signing_server::delete_user(&state, &bob_name).await;
    let _ = ai_signing_server::delete_user(&state, &eve_name).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        ai_signing_server::serve(listener, server_state)
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");

    let root = std::env::temp_dir().join(format!("ai-signing-auto-{suffix}"));
    std::fs::create_dir_all(&root).unwrap();
    let alice_db = root.join("alice.sqlite");
    let bob_db = root.join("bob.sqlite");
    let eve_db = root.join("eve.sqlite");
    let alice_cfg = root.join("alice.toml");
    let bob_cfg = root.join("bob.toml");
    let cert_path = root.join("alice.cert.json");
    let config_body = format!("server = \"{base}\"\n");
    std::fs::write(&alice_cfg, &config_body).unwrap();
    std::fs::write(&bob_cfg, &config_body).unwrap();

    let password = "password1";
    admin(
        &alice_cfg,
        &["create-user", &alice_name, password, "подписант"],
    );
    admin(
        &alice_cfg,
        &["create-user", &bob_name, password, "подписант"],
    );
    admin(&alice_cfg, &["create-user", &eve_name, password, "админ"]);

    let missing = Command::new(env!("CARGO_BIN_EXE_ai-signing-admin-e2e"))
        .arg("--config")
        .arg(&alice_cfg)
        .args([
            "issue-cert",
            &format!("missing_{suffix}"),
            &cert_path.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(!missing.status.success(), "сертификат без пользователя");
    let missing_err = String::from_utf8_lossy(&missing.stderr);
    assert!(
        missing_err.contains("пользователь не найден"),
        "stderr: {missing_err}"
    );

    let issued = admin(
        &alice_cfg,
        &["issue-cert", &alice_name, &cert_path.to_string_lossy()],
    );
    assert_eq!(issued["username"], alice_name);
    assert_eq!(
        issued["path"].as_str(),
        Some(cert_path.to_str().expect("путь сертификата"))
    );
    let issued_text = issued.to_string();
    assert!(
        !issued_text.contains("secret_key_hex"),
        "вывод команды не должен содержать секрет: {issued_text}"
    );
    let cert_text = std::fs::read_to_string(&cert_path).unwrap();
    assert!(cert_text.contains("secret_key_hex"));
    assert!(cert_text.contains(&alice_name));

    let http = reqwest::Client::new();
    let password_login = http
        .post(format!("{base}/api/login"))
        .json(&json!({"username": alice_name, "password": password}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let password_body: serde_json::Value = password_login.json().await.unwrap();
    assert_eq!(password_body["username"], alice_name);
    assert!(password_body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));

    let material = ai_signing_client::load_certificate(&cert_path).unwrap();
    let proof = material.login_now().unwrap();
    let cert_login = http
        .post(format!("{base}/api/login/certificate"))
        .json(&proof)
        .send()
        .await
        .unwrap();
    assert!(cert_login.status().is_success(), "вход по сертификату");
    let cert_body: serde_json::Value = cert_login.json().await.unwrap();
    assert_eq!(cert_body["username"], alice_name);
    assert_eq!(cert_body["role"], "signer");

    let replay = http
        .post(format!("{base}/api/login/certificate"))
        .json(&proof)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
    let replay_text = replay.text().await.unwrap();
    assert!(
        replay_text.contains("уже использован"),
        "повтор входа: {replay_text}"
    );

    let _: serde_json::Value = cli(&bob_cfg, &bob_db, &["login", &bob_name, password]);
    let _: serde_json::Value = cli(&alice_cfg, &eve_db, &["login", &eve_name, password]);

    let alice_log = root.join("alice.auto.log");
    let bob_log = root.join("bob.watch.log");
    let alice_auto = Proc(spawn_auto(&alice_cfg, &alice_db, &cert_path, &alice_log));
    let bob_watch = Proc(spawn_watch(&bob_cfg, &bob_db, &bob_log, password));
    wait_socket(&socket_of(&alice_db), &alice_log);
    wait_socket(&socket_of(&bob_db), &bob_log);
    wait_connected(&alice_cfg, &alice_db, &alice_log);
    wait_connected(&bob_cfg, &bob_db, &bob_log);

    let who: serde_json::Value = cli(&alice_cfg, &alice_db, &["whoami"]);
    assert_eq!(who["username"], alice_name);
    assert_eq!(who["role"], "signer");

    let signers: Vec<serde_json::Value> = cli(&alice_cfg, &eve_db, &["signers"]);
    assert!(
        signers
            .iter()
            .any(|signer| signer["username"] == alice_name),
        "автоподписант публикует ключ устройства: {signers:?}"
    );
    assert!(
        signers.iter().any(|signer| signer["username"] == bob_name),
        "bob есть среди подписантов: {signers:?}"
    );

    let group: GroupDto = cli(
        &alice_cfg,
        &eve_db,
        &["create-group", "treasury", "2", &alice_name, &bob_name],
    );
    let group_id = group.id.to_string();
    wait_group(&alice_cfg, &alice_db, &group_id, &alice_log, |group| {
        group.members.len() == 2
            && group
                .members
                .iter()
                .all(|member| member.box_public_hex.is_some())
    });
    let _: GroupDto = cli(&alice_cfg, &eve_db, &["start-dkg", &group_id]);
    let active = wait_group(&alice_cfg, &alice_db, &group_id, &alice_log, |group| {
        group.status == "active"
    });
    let verifying_key = active
        .verifying_key_hex
        .clone()
        .expect("у активной группы есть ключ проверки");

    let created: SignRequestDto = cli(
        &alice_cfg,
        &eve_db,
        &["request-sign", &group_id, "invoice-auto"],
    );
    assert_eq!(created.status, "pending");
    wait_approval(&state.pool, created.id, &alice_name).await;
    let status: String = sqlx::query_scalar("SELECT status FROM signing_requests WHERE id = $1")
        .bind(created.id)
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(
        status, "pending",
        "одного подтверждения ещё мало для кворума"
    );

    let _: SignRequestDto = cli(&bob_cfg, &bob_db, &["approve", &created.id.to_string()]);
    let signed = wait_inbox(&alice_cfg, &eve_db, &created.id.to_string(), &bob_log);
    assert_eq!(signed.status, "completed");
    let signature = signed.signature_hex.expect("админ видит подпись");
    verify_ed25519(&verifying_key, b"invoice-auto", &signature).expect("подпись Ed25519");

    drop(alice_auto);
    drop(bob_watch);
    ai_signing_server::delete_user(&state, &eve_name)
        .await
        .unwrap();
    ai_signing_server::delete_user(&state, &alice_name)
        .await
        .unwrap();
    ai_signing_server::delete_user(&state, &bob_name)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

async fn wait_approval(pool: &sqlx::PgPool, request_id: Uuid, username: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = String::new();
    while Instant::now() < deadline {
        let decision: Option<String> = sqlx::query_scalar(
            "SELECT a.decision FROM signing_approvals a
             JOIN users u ON u.id = a.user_id
             WHERE a.request_id = $1 AND u.username = $2",
        )
        .bind(request_id)
        .bind(username)
        .fetch_optional(pool)
        .await
        .unwrap();
        if decision.as_deref() == Some("approved") {
            return;
        }
        last = decision.unwrap_or_else(|| "нет решения".into());
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("автоподписант не подтвердил запрос: {last}");
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

fn spawn_auto(config: &Path, database: &Path, certificate: &Path, log: &Path) -> Child {
    let file = std::fs::File::create(log).expect("лог автоподписанта");
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
        .expect("автоподписант")
}

fn spawn_watch(config: &Path, database: &Path, log: &Path, password: &str) -> Child {
    let file = std::fs::File::create(log).expect("лог watch");
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
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("сокет не поднялся: {}\n{}", path.display(), read_log(log));
}

fn wait_connected(config: &Path, database: &Path, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = String::new();
    while Instant::now() < deadline {
        let value: serde_json::Value = cli(config, database, &["whoami"]);
        last = value.to_string();
        if value["connected"] == true {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("нет связи с сервером: {last}\n{}", read_log(log));
}

fn wait_group(
    config: &Path,
    database: &Path,
    group_id: &str,
    log: &Path,
    ready: impl Fn(&GroupDto) -> bool,
) -> GroupDto {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut last = String::new();
    while Instant::now() < deadline {
        let group: GroupDto = cli(config, database, &["group", group_id]);
        if group.status == "failed" {
            panic!("генерация ключа не удалась: {group:?}\n{}", read_log(log));
        }
        if ready(&group) {
            return group;
        }
        last = format!("{group:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "группа не перешла в нужный статус: {last}\n{}",
        read_log(log)
    );
}

fn wait_inbox(config: &Path, database: &Path, request_id: &str, log: &Path) -> SignRequestDto {
    let deadline = Instant::now() + Duration::from_secs(45);
    let wanted: Uuid = request_id.parse().unwrap();
    let mut last = String::new();
    while Instant::now() < deadline {
        let requests: Vec<SignRequestDto> = cli(config, database, &["inbox"]);
        if let Some(request) = requests.into_iter().find(|request| request.id == wanted) {
            if request.status == "failed" {
                panic!("подпись не удалась: {request:?}\n{}", read_log(log));
            }
            if request.status == "completed" {
                return request;
            }
            last = format!("{request:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("подпись не собралась: {last}\n{}", read_log(log));
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
