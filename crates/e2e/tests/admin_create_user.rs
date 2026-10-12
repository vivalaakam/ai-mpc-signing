use std::path::Path;
use std::process::Command;

use serde_json::json;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_creates_a_user_who_can_log_in() {
    ai_signing_server::init_tracing();
    let state = ai_signing_server::bootstrap().await.expect("postgres");
    let suffix = &Uuid::new_v4().simple().to_string()[..20];
    let name = format!("adm_{suffix}");
    let password = "password1";
    let _ = ai_signing_server::delete_user(&state, &name).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        ai_signing_server::serve(listener, server_state)
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");

    let root = std::env::temp_dir().join(format!("ai-signing-admin-{suffix}"));
    std::fs::create_dir_all(&root).unwrap();
    let config = root.join("config.toml");
    std::fs::write(&config, format!("server = \"{base}\"\n")).unwrap();

    let created = admin(&config, &["create-user", &name, password, "подписант"]);
    assert_eq!(created["username"], name);
    assert_eq!(created["role"], "signer");
    let user_id = created["user_id"].as_str().expect("user_id");
    let listed = admin(&config, &["users"]);
    let users = listed.as_array().expect("список пользователей");
    assert!(
        users.iter().any(|user| {
            user["username"] == name && user["user_id"] == user_id && user["role"] == "signer"
        }),
        "созданный пользователь отсутствует в списке: {listed}"
    );
    let sessions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1::uuid")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await
            .expect("сессии");
    assert_eq!(sessions, 0, "создание пользователя не открывает сессию");

    let http = reqwest::Client::new();
    let login = http
        .post(format!("{base}/api/login"))
        .json(&json!({"username": name, "password": password}))
        .send()
        .await
        .expect("login")
        .error_for_status()
        .expect("вход");
    let body: serde_json::Value = login.json().await.expect("ответ входа");
    assert_eq!(body["username"], name);
    assert_eq!(body["role"], "signer");
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));

    let duplicate = Command::new(env!("CARGO_BIN_EXE_ai-signing-admin-e2e"))
        .arg("--config")
        .arg(&config)
        .args(["create-user", &name, password, "подписант"])
        .output()
        .expect("повтор");
    assert!(!duplicate.status.success());
    let stderr = String::from_utf8_lossy(&duplicate.stderr);
    assert!(stderr.contains("такое имя уже занято"), "stderr: {stderr}");

    let keeper_name = format!("keep_{suffix}");
    let _ = ai_signing_server::delete_user(&state, &keeper_name).await;
    let keeper = admin(&config, &["create-user", &keeper_name, password, "админ"]);
    let keeper_id: Uuid = keeper["user_id"]
        .as_str()
        .expect("keeper id")
        .parse()
        .unwrap();
    let victim_id: Uuid = user_id.parse().unwrap();
    let group_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO groups (id, name, threshold, max_signers, status, api_token, created_by)
         VALUES ($1, 'shared', 2, 2, 'active', $2, $3)",
    )
    .bind(group_id)
    .bind(format!("tok-{suffix}"))
    .bind(keeper_id)
    .execute(&state.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO group_members (group_id, user_id, identifier) VALUES ($1, $2, 2)")
        .bind(group_id)
        .bind(victim_id)
        .execute(&state.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO signing_requests (id, group_id, message, status) VALUES ($1, $2, $3, 'pending')",
    )
    .bind(request_id)
    .bind(group_id)
    .bind(b"invoice".as_slice())
    .execute(&state.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO signing_approvals (request_id, user_id, decision) VALUES ($1, $2, 'approved')",
    )
    .bind(request_id)
    .bind(victim_id)
    .execute(&state.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sign_participants (request_id, user_id, identifier) VALUES ($1, $2, 2)",
    )
    .bind(request_id)
    .bind(victim_id)
    .execute(&state.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO dkg_round2 (group_id, from_identifier, to_user_id, ciphertext)
         VALUES ($1, 1, $2, 'sealed')",
    )
    .bind(group_id)
    .bind(victim_id)
    .execute(&state.pool)
    .await
    .unwrap();

    let deleted = admin(&config, &["delete-user", &name]);
    assert_eq!(deleted["username"], name);
    assert_eq!(deleted["user_id"], user_id);

    let listed = admin(&config, &["users"]);
    let users = listed.as_array().expect("список после удаления");
    assert!(
        users.iter().all(|user| user["username"] != name),
        "удалённый пользователь остался в списке: {listed}"
    );
    let groups_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE id = $1")
        .bind(group_id)
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(groups_left, 1, "чужая группа должна остаться");
    let ties: i64 = sqlx::query_scalar(
        "SELECT
            (SELECT COUNT(*) FROM group_members WHERE user_id = $1)
          + (SELECT COUNT(*) FROM signing_approvals WHERE user_id = $1)
          + (SELECT COUNT(*) FROM sign_participants WHERE user_id = $1)
          + (SELECT COUNT(*) FROM dkg_round2 WHERE to_user_id = $1)",
    )
    .bind(victim_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(ties, 0);

    let login_again = http
        .post(format!("{base}/api/login"))
        .json(&json!({"username": name, "password": password}))
        .send()
        .await
        .expect("повторный вход");
    assert_eq!(login_again.status(), reqwest::StatusCode::UNAUTHORIZED);

    let missing = Command::new(env!("CARGO_BIN_EXE_ai-signing-admin-e2e"))
        .arg("--config")
        .arg(&config)
        .args(["delete-user", &name])
        .output()
        .expect("повторное удаление");
    assert!(!missing.status.success());
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        stderr.contains("пользователь не найден"),
        "stderr: {stderr}"
    );

    ai_signing_server::delete_user(&state, &keeper_name)
        .await
        .expect("удалить оставшегося пользователя");
    let _ = std::fs::remove_dir_all(&root);
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
        "команда {args:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("ответ не json ({err})\nstdout: {stdout}\nstderr: {stderr}"))
}
