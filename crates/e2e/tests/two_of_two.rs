use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ai_signing_protocol::{verify_ed25519, GroupDto, SignRequestDto};
use uuid::Uuid;

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_two_of_two_signs_an_ed25519_message() {
    ai_signing_server::init_tracing();
    let state = ai_signing_server::bootstrap().await.expect("postgres");
    let suffix = &Uuid::new_v4().simple().to_string()[..20];
    let alice_name = format!("cli_a_{suffix}");
    let bob_name = format!("cli_b_{suffix}");
    let eve_name = format!("cli_e_{suffix}");
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

    let root = std::env::temp_dir().join(format!("ai-signing-cli-{suffix}"));
    std::fs::create_dir_all(&root).unwrap();
    let alice_db = root.join("alice.sqlite");
    let bob_db = root.join("bob.sqlite");
    let eve_db = root.join("eve.sqlite");
    let alice_cfg = root.join("alice.toml");
    let bob_cfg = root.join("bob.toml");
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
    let _: serde_json::Value = cli(&alice_cfg, &alice_db, &["login", &alice_name, password]);
    let _: serde_json::Value = cli(&bob_cfg, &bob_db, &["login", &bob_name, password]);
    let _: serde_json::Value = cli(&alice_cfg, &eve_db, &["login", &eve_name, password]);
    let denied = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(&alice_cfg)
        .arg("--database")
        .arg(&alice_db)
        .args(["create-group", "nope", "2", &alice_name, &bob_name])
        .output()
        .expect("запрос подписанта");
    assert!(
        !denied.status.success(),
        "подписант не создаёт группу: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
    let denied_err = String::from_utf8_lossy(&denied.stderr);
    assert!(
        denied_err.contains("группу создаёт администратор"),
        "stderr: {denied_err}"
    );
    let signers: Vec<serde_json::Value> = cli(&alice_cfg, &eve_db, &["signers"]);
    assert!(
        signers
            .iter()
            .any(|signer| signer["username"] == alice_name),
        "alice есть среди активных подписантов: {signers:?}"
    );
    assert!(
        signers.iter().any(|signer| signer["username"] == bob_name),
        "bob есть среди активных подписантов: {signers:?}"
    );

    let alice_log = root.join("alice.watch.log");
    let bob_log = root.join("bob.watch.log");
    let alice_watch = Proc(spawn_watch(&alice_cfg, &alice_db, &alice_log, password));
    let bob_watch = Proc(spawn_watch(&bob_cfg, &bob_db, &bob_log, password));
    wait_socket(&socket_of(&alice_db), &alice_log);
    wait_socket(&socket_of(&bob_db), &bob_log);
    wait_connected(&alice_cfg, &alice_db, &alice_log);
    wait_connected(&bob_cfg, &bob_db, &bob_log);

    let group: GroupDto = cli(
        &alice_cfg,
        &eve_db,
        &["create-group", "treasury", "2", &alice_name, &bob_name],
    );
    let group_id = group.id.to_string();
    assert!(group.api_token.is_some(), "создатель видит токен API");
    assert_eq!(group.members.len(), 2);
    let early = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(&alice_cfg)
        .arg("--database")
        .arg(&eve_db)
        .args(["request-sign", &group_id, "too-soon"])
        .output()
        .expect("ранний запрос");
    assert!(
        !early.status.success(),
        "неготовая группа не принимает сообщение: {}",
        String::from_utf8_lossy(&early.stderr)
    );
    let early_err = String::from_utf8_lossy(&early.stderr);
    assert!(
        early_err.contains("группа ещё не готова подписывать"),
        "stderr: {early_err}"
    );
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

    let denied_sign = Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(&alice_cfg)
        .arg("--database")
        .arg(&alice_db)
        .args(["request-sign", &group_id, "invoice-42"])
        .output()
        .expect("запрос подписанта");
    assert!(
        !denied_sign.status.success(),
        "подписант не отправляет сообщение: {}",
        String::from_utf8_lossy(&denied_sign.stderr)
    );
    let denied_sign_err = String::from_utf8_lossy(&denied_sign.stderr);
    assert!(
        denied_sign_err.contains("запрос на подпись создаёт администратор"),
        "stderr: {denied_sign_err}"
    );

    let created: SignRequestDto = cli(
        &alice_cfg,
        &eve_db,
        &["request-sign", &group_id, "invoice-42"],
    );
    assert_eq!(created.status, "pending");
    assert_eq!(created.message_preview, "invoice-42");
    let request_id = created.id.to_string();
    let admin_inbox: Vec<SignRequestDto> = cli(&alice_cfg, &eve_db, &["inbox"]);
    assert!(
        admin_inbox.iter().any(|request| request.id == created.id),
        "админ видит свой запрос: {admin_inbox:?}"
    );

    let _: SignRequestDto = cli(&alice_cfg, &alice_db, &["approve", &request_id]);
    let _: SignRequestDto = cli(&bob_cfg, &bob_db, &["approve", &request_id]);

    let signed = wait_inbox(&alice_cfg, &alice_db, &request_id, &alice_log);
    assert_eq!(signed.status, "completed");
    assert_eq!(signed.message_preview, "invoice-42");
    assert!(
        signed.signature_hex.is_none(),
        "подписант не видит подпись: {signed:?}"
    );
    let bob_done: Vec<SignRequestDto> = cli(&bob_cfg, &bob_db, &["inbox"]);
    let bob_signed = bob_done
        .iter()
        .find(|request| request.id == created.id)
        .expect("подписант видит своё сообщение");
    assert!(bob_signed.signature_hex.is_none());
    let admin_done: Vec<SignRequestDto> = cli(&alice_cfg, &eve_db, &["inbox"]);
    let admin_signed = admin_done
        .iter()
        .find(|request| request.id == created.id)
        .expect("админ видит готовый запрос");
    let signature = admin_signed
        .signature_hex
        .clone()
        .expect("админ видит подпись");
    verify_ed25519(&verifying_key, b"invoice-42", &signature).expect("подпись Ed25519");

    drop(alice_watch);
    drop(bob_watch);
    ai_signing_server::delete_user(&state, &eve_name)
        .await
        .expect("удалить eve");
    ai_signing_server::delete_user(&state, &alice_name)
        .await
        .expect("удалить alice");
    ai_signing_server::delete_user(&state, &bob_name)
        .await
        .expect("удалить bob");
    let _ = std::fs::remove_dir_all(&root);
}

fn admin(config: &Path, args: &[&str]) {
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
