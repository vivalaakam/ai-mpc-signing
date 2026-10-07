use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use ai_signing_protocol::{
    verify_ed25519, AuthResponse, ClientMsg, DeviceKey, GroupDto, Participant, ServerMsg,
    SignStatusResponse,
};
use futures::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

#[tokio::test]
async fn two_of_two_group_signs_an_ed25519_message() {
    ai_signing_server::init_tracing();
    let state = ai_signing_server::bootstrap().await.expect("postgres");
    let suffix = &Uuid::new_v4().simple().to_string()[..20];
    let alice_name = format!("e2e_a_{suffix}");
    let bob_name = format!("e2e_b_{suffix}");
    let eve_name = format!("e2e_e_{suffix}");
    let _ = ai_signing_server::delete_user(&state, &alice_name).await;
    let _ = ai_signing_server::delete_user(&state, &bob_name).await;
    let _ = ai_signing_server::delete_user(&state, &eve_name).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        ai_signing_server::serve(listener, server_state)
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");
    let ws_base = format!("ws://{addr}");
    let http = reqwest::Client::new();

    let eve = register(&http, &base, &eve_name, "admin").await;
    let alice = register(&http, &base, &alice_name, "signer").await;
    let bob = register(&http, &base, &bob_name, "signer").await;
    assert_eq!(eve.role, "admin");
    assert_eq!(alice.role, "signer");
    let alice_device = DeviceKey::generate();
    let bob_device = DeviceKey::generate();
    put_device(&http, &base, &alice.token, &alice_device.public_hex()).await;
    put_device(&http, &base, &bob.token, &bob_device.public_hex()).await;

    let denied = http
        .post(format!("{base}/api/groups"))
        .bearer_auth(&alice.token)
        .json(&json!({
            "name": "treasury",
            "threshold": 2,
            "members": [&alice_name, &bob_name],
        }))
        .send()
        .await
        .expect("запрос подписанта");
    assert_eq!(denied.status(), 403, "подписант не создаёт группу");

    let signers: Vec<serde_json::Value> = send(
        &http,
        http.get(format!("{base}/api/signers"))
            .bearer_auth(&eve.token),
    )
    .await;
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

    let group: GroupDto = send(
        &http,
        http.post(format!("{base}/api/groups"))
            .bearer_auth(&eve.token)
            .json(&json!({
                "name": "treasury",
                "threshold": 2,
                "members": [&alice_name, &bob_name],
            })),
    )
    .await;
    let group_id = group.id;
    let api_token = group.api_token.clone().expect("создатель видит токен API");
    assert_eq!(group.members.len(), 2);
    put_group_device(
        &http,
        &base,
        &alice.token,
        group_id,
        &alice_device.public_hex(),
    )
    .await;
    put_group_device(&http, &base, &bob.token, group_id, &bob_device.public_hex()).await;

    let booted = Arc::new(AtomicUsize::new(0));
    let dkg_ready = Arc::new(AtomicUsize::new(0));
    let signature = Arc::new(Mutex::new(None));
    spawn_member(
        ws_base.clone(),
        alice.token.clone(),
        alice_device,
        group_id,
        booted.clone(),
        dkg_ready.clone(),
        signature.clone(),
    );
    spawn_member(
        ws_base,
        bob.token.clone(),
        bob_device,
        group_id,
        booted.clone(),
        dkg_ready.clone(),
        signature.clone(),
    );
    wait_flag(&booted, 2, "подключение участников").await;

    let _: GroupDto = send(
        &http,
        http.post(format!("{base}/api/groups/{group_id}/dkg"))
            .bearer_auth(&eve.token),
    )
    .await;
    wait_flag(&dkg_ready, 2, "DKG").await;

    let created: SignStatusResponse = send(
        &http,
        http.post(format!("{base}/api/v1/groups/{group_id}/requests"))
            .bearer_auth(&api_token)
            .json(&json!({"message_utf8": "invoice-42"})),
    )
    .await;
    assert_eq!(created.status, "pending");

    wait_signature(&signature).await;
    let final_status: SignStatusResponse = send(
        &http,
        http.get(format!(
            "{base}/api/v1/groups/{group_id}/requests/{}",
            created.request_id
        ))
        .bearer_auth(&api_token),
    )
    .await;
    assert_eq!(final_status.status, "completed");
    let signature_hex = final_status.signature_hex.expect("подпись");
    let group: GroupDto = send(
        &http,
        http.get(format!("{base}/api/groups/{group_id}"))
            .bearer_auth(&alice.token),
    )
    .await;
    verify_ed25519(
        group.verifying_key_hex.as_deref().expect("ключ группы"),
        b"invoice-42",
        &signature_hex,
    )
    .expect("подпись Ed25519");

    ai_signing_server::delete_user(&state, &eve_name)
        .await
        .unwrap();
    ai_signing_server::delete_user(&state, &alice_name)
        .await
        .unwrap();
    ai_signing_server::delete_user(&state, &bob_name)
        .await
        .unwrap();
}

fn spawn_member(
    ws_base: String,
    token: String,
    device: DeviceKey,
    group_id: Uuid,
    booted: Arc<AtomicUsize>,
    dkg_ready: Arc<AtomicUsize>,
    signature: Arc<Mutex<Option<String>>>,
) {
    tokio::spawn(async move {
        let (mut socket, _) = connect_async(format!("{ws_base}/ws?token={token}"))
            .await
            .expect("websocket");
        let mut party: Option<Participant> = None;
        let mut reported = false;
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(15), socket.next())
                .await
                .expect("таймаут сокета")
                .expect("сокет закрыт")
                .expect("кадр");
            let Message::Text(text) = frame else { continue };
            let msg: ServerMsg = serde_json::from_str(&text).expect("json сервера");
            let mut outgoing = Vec::new();
            match &msg {
                ServerMsg::Snapshot { groups, .. } => {
                    let group = groups
                        .iter()
                        .find(|group| group.id == group_id)
                        .expect("группа в снимке");
                    let mut created = Participant::new(device.clone(), group.clone());
                    outgoing.extend(created.set_group(group.clone()).unwrap());
                    party = Some(created);
                    booted.fetch_add(1, Ordering::SeqCst);
                }
                ServerMsg::GroupUpdated { group } if group.id == group_id => {
                    if let Some(party) = party.as_mut() {
                        outgoing.extend(party.set_group(group.clone()).unwrap());
                    }
                }
                ServerMsg::SignRequest { request }
                    if request.group_id == group_id
                        && request.status == "pending"
                        && request.my_decision.is_none() =>
                {
                    outgoing.push(ClientMsg::SignApprove {
                        request_id: request.id,
                    });
                }
                ServerMsg::DkgCompleted { .. } if !reported => {
                    reported = true;
                    dkg_ready.fetch_add(1, Ordering::SeqCst);
                }
                ServerMsg::SignCompleted { signature_hex, .. } => {
                    *signature.lock().expect("lock") = Some(signature_hex.clone());
                    break;
                }
                ServerMsg::DkgFailed { message, .. } => panic!("DKG: {message}"),
                ServerMsg::SignFailed { message, .. } => panic!("подпись: {message}"),
                ServerMsg::Error { message } => panic!("сервер: {message}"),
                _ => {}
            }
            if let Some(party) = party.as_mut() {
                outgoing.extend(
                    party
                        .handle(&msg)
                        .unwrap_or_else(|err| panic!("протокол: {err}")),
                );
            }
            for message in outgoing {
                let text = serde_json::to_string(&message).unwrap();
                socket
                    .send(Message::Text(text.into()))
                    .await
                    .expect("отправка");
            }
        }
    });
}

async fn wait_flag(flag: &AtomicUsize, expected: usize, label: &str) {
    for _ in 0..100 {
        if flag.load(Ordering::SeqCst) >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "{label}: готово {} из {expected}",
        flag.load(Ordering::SeqCst)
    );
}

async fn wait_signature(signature: &Mutex<Option<String>>) {
    for _ in 0..100 {
        if signature.lock().expect("lock").is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("подпись не собралась");
}

async fn register(http: &reqwest::Client, base: &str, username: &str, role: &str) -> AuthResponse {
    let _: serde_json::Value = send(
        http,
        http.post(format!("{base}/api/users")).json(&json!({
            "username": username,
            "password": "password123",
            "role": role,
        })),
    )
    .await;
    send(
        http,
        http.post(format!("{base}/api/login"))
            .json(&json!({"username": username, "password": "password123"})),
    )
    .await
}

async fn put_group_device(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    group_id: Uuid,
    public_key_hex: &str,
) {
    let response = http
        .put(format!("{base}/api/groups/{group_id}/device"))
        .bearer_auth(token)
        .json(&json!({"public_key_hex": public_key_hex}))
        .send()
        .await
        .expect("ключ участника");
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap_or_default()
    );
}

async fn put_device(http: &reqwest::Client, base: &str, token: &str, public_key_hex: &str) {
    let response = http
        .put(format!("{base}/api/me/device"))
        .bearer_auth(token)
        .json(&json!({"public_key_hex": public_key_hex}))
        .send()
        .await
        .expect("device");
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap_or_default()
    );
}

async fn send<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    request: reqwest::RequestBuilder,
) -> T {
    let _ = http;
    let response = request.send().await.expect("http");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(status.is_success(), "{status}: {body}");
    serde_json::from_str(&body).unwrap_or_else(|err| panic!("{err}: {body}"))
}
