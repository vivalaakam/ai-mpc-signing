//! Reshare keeps the same Solana address. The group secret never appears.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ai_signing_client::{load_certificate, ShareEpoch, Store, Vault};
use ai_signing_protocol::{
    verify_ed25519, GroupDto, GroupEventDto, ParticipantBlobDto, SignRequestDto,
};
use frost_ed25519::keys::{reconstruct, KeyPackage};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

const SOLANA_RPC: &str = "http://127.0.0.1:8899";
const LAMPORTS: u64 = 1_000_000;
const AIRDROP: u64 = 1_000_000_000;

fn progress(message: impl std::fmt::Display) {
    info!("reshare_e2e: {message}");
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
    cert: PathBuf,
    log: PathBuf,
}

struct Env {
    http: reqwest::Client,
    state: ai_signing_server::AppState,
    config: PathBuf,
    admin_db: PathBuf,
    admin_name: String,
    signers: Vec<Signer>,
    running: Vec<Proc>,
    root: PathBuf,
}

struct Held {
    epochs: Vec<ShareEpoch>,
    live: ParticipantBlobDto,
}

struct Watch {
    stop: Arc<AtomicBool>,
    leak: Arc<Mutex<Option<String>>>,
    server: tokio::task::JoinHandle<()>,
    files: Vec<JoinHandle<()>>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_member_then_transfer_from_the_same_address() {
    let env = Env::start("rm", 3).await;
    let group = env.activate("treasury", 2, 3).await;
    env.transfer(&group).await;
    let secret = env.group_secret(&group);
    let watch = env.watch(&group, &secret);
    env.reject_signer_reshare(&group);
    let removed = env.signers[2].name.clone();
    let group = env
        .reshare(&group, &[], std::slice::from_ref(&removed))
        .await;
    env.transfer(&group).await;
    env.prove(&group, &secret, Change::Removed).await;
    env.admin_sees_removal(&group, &removed);
    watch.finish();
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn add_member_then_transfer_from_the_same_address() {
    let env = Env::start("add", 3).await;
    let group = env.activate("treasury", 2, 2).await;
    env.transfer(&group).await;
    let secret = env.group_secret(&group);
    let watch = env.watch(&group, &secret);
    env.reject_signer_reshare(&group);
    let joiner = env.signers[2].name.clone();
    let group = env
        .reshare(&group, std::slice::from_ref(&joiner), &[])
        .await;
    env.transfer(&group).await;
    env.prove(&group, &secret, Change::Added).await;
    env.admin_sees_addition(&group, &joiner);
    watch.finish();
    env.shutdown().await;
}

enum Change {
    Removed,
    Added,
}

impl Env {
    async fn start(label: &str, signers: usize) -> Self {
        std::env::set_var("SOLANA_RPC_URL", SOLANA_RPC);
        let http = reqwest::Client::new();
        wait_solana(&http).await;
        ai_signing_server::init_tracing();
        let state = ai_signing_server::bootstrap().await.expect("postgres");
        let suffix = &Uuid::new_v4().simple().to_string()[..12];
        let names: Vec<String> = (0..signers)
            .map(|index| format!("e2e_{label}{index}_{suffix}"))
            .collect();
        let admin_name = format!("e2e_{label}e_{suffix}");
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
        let root = PathBuf::from(format!("/tmp/asr-{label}-{suffix}"));
        std::fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        std::fs::write(&config, format!("server = \"{base}\"\n")).unwrap();
        let admin_db = root.join("admin.sqlite");
        let signers: Vec<Signer> = names
            .iter()
            .enumerate()
            .map(|(index, name)| Signer {
                name: name.clone(),
                db: root.join(format!("{index}.sqlite")),
                cert: root.join(format!("{index}.cert.json")),
                log: root.join(format!("{index}.log")),
            })
            .collect();
        let password = "password1";
        for signer in &signers {
            progress(format!("создаю пользователя {} (подписант)", signer.name));
            admin(
                &config,
                &["create-user", &signer.name, password, "подписант"],
            );
            let issued = admin(
                &config,
                &["issue-cert", &signer.name, &signer.cert.to_string_lossy()],
            );
            assert_eq!(issued["username"], signer.name);
            assert!(!issued.to_string().contains("secret_key_hex"));
        }
        progress(format!("создаю пользователя {admin_name} (админ)"));
        admin(&config, &["create-user", &admin_name, password, "админ"]);
        let _: serde_json::Value = cli(&config, &admin_db, &["login", &admin_name, password]);
        let running: Vec<Proc> = signers
            .iter()
            .map(|signer| {
                progress(format!("запускаю автоподписанта {}", signer.name));
                Proc(spawn_auto(&config, &signer.db, &signer.cert, &signer.log))
            })
            .collect();
        for signer in &signers {
            wait_socket(&socket_of(&signer.db), &signer.log);
            wait_connected(&config, &signer.db, &signer.log);
        }
        wait_signers(&config, &admin_db, &names);
        Self {
            http,
            state,
            config,
            admin_db,
            admin_name,
            signers,
            running,
            root,
        }
    }

    async fn activate(&self, name: &str, threshold: u16, members: usize) -> GroupDto {
        let mut create = vec![
            "create-group".to_string(),
            name.into(),
            threshold.to_string(),
        ];
        create.extend(
            self.signers
                .iter()
                .take(members)
                .map(|signer| signer.name.clone()),
        );
        let refs: Vec<&str> = create.iter().map(String::as_str).collect();
        progress(format!("создаю группу {name}, порог {threshold}"));
        let group: GroupDto = cli(&self.config, &self.admin_db, &refs);
        assert_eq!(group.members.len(), members);
        assert_eq!(group.threshold, threshold);
        let group_id = group.id.to_string();
        wait_group(
            &self.config,
            &self.signers[0].db,
            &group_id,
            &self.signers[0].log,
            "ключи участников группы",
            |group| {
                group.members.len() == members
                    && group
                        .members
                        .iter()
                        .all(|member| member.box_public_hex.is_some())
            },
        );
        progress(format!("запускаю DKG группы {group_id}"));
        let _: GroupDto = cli(&self.config, &self.admin_db, &["start-dkg", &group_id]);
        let active = wait_group(
            &self.config,
            &self.signers[0].db,
            &group_id,
            &self.signers[0].log,
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
        progress(format!("адрес группы: {payer}"));
        airdrop(&self.http, &payer, AIRDROP).await;
        active
    }

    async fn transfer(&self, group: &GroupDto) {
        let verifying_key = group.verifying_key_hex.clone().expect("ключ группы");
        let payer = group.solana_address.clone().expect("адрес группы");
        let group_id = group.id.to_string();
        let recipient = {
            let material = ai_signing_protocol::CertificateMaterial::generate("payee");
            bs58::encode(unhex(&material.public_key_hex)).into_string()
        };
        progress(format!("перевод {LAMPORTS} lamports на {recipient}"));
        let recipient_before = airdrop(&self.http, &recipient, AIRDROP).await;
        let created: SignRequestDto = cli(
            &self.config,
            &self.admin_db,
            &[
                "request-solana",
                &group_id,
                &recipient,
                &LAMPORTS.to_string(),
            ],
        );
        let signed = wait_inbox(
            &self.config,
            &self.admin_db,
            &created.id.to_string(),
            &self.signers[0].log,
        );
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
        wait_landed(&self.http, &network).await;
        let recipient_after = balance(&self.http, &recipient).await;
        assert_eq!(recipient_after, recipient_before + LAMPORTS);
        let still = self.group_now(group.id);
        assert_eq!(still.solana_address.as_deref(), Some(payer.as_str()));
        assert_eq!(
            still.verifying_key_hex.as_deref(),
            Some(verifying_key.as_str())
        );
        progress(format!("перевод с {payer} подтверждён"));
    }

    fn group_secret(&self, group: &GroupDto) -> Vec<u8> {
        let held: Vec<Held> = self
            .signers
            .iter()
            .take(2)
            .map(|signer| hold(signer, group.id))
            .collect();
        for one in &held {
            assert_eq!(one.epochs.len(), 1, "после DKG у участника одна доля");
            assert!(one.live.reshare.is_none(), "после DKG нет сессии пересчёта");
        }
        let keys = [
            package(&held[0].epochs[0].key),
            package(&held[1].epochs[0].key),
        ];
        let secret = secret_bytes(&keys);
        for one in &held {
            deny_share(&package(&one.epochs[0].key), &secret);
            assert_material_clean("доля после DKG", &secret, &material(one));
        }
        self.assert_files_clean(&secret);
        secret
    }

    fn watch(&self, group: &GroupDto, secret: &[u8]) -> Watch {
        let stop = Arc::new(AtomicBool::new(false));
        let leak = Arc::new(Mutex::new(None));
        let flag = stop.clone();
        let found = leak.clone();
        let pool = self.state.pool.clone();
        let secret_server = secret.to_vec();
        let server = tokio::spawn(async move {
            while !flag.load(Ordering::Relaxed) {
                if let Some(place) = server_leak(&pool, &secret_server).await {
                    *found.lock().expect("наблюдение") = Some(place);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        });
        let mut files = Vec::new();
        for signer in &self.signers {
            let signer_db = signer.db.clone();
            let signer_cert = signer.cert.clone();
            let signer_log = signer.log.clone();
            let group_id = group.id;
            let secret = secret.to_vec();
            let flag = stop.clone();
            let found = leak.clone();
            files.push(std::thread::spawn(move || {
                let opened = open_local(&Signer {
                    name: String::new(),
                    db: signer_db.clone(),
                    cert: signer_cert.clone(),
                    log: signer_log.clone(),
                });
                while !flag.load(Ordering::Relaxed) {
                    if let Some(place) = local_leak(
                        &opened,
                        group_id,
                        &secret,
                        &signer_db,
                        &signer_log,
                        &signer_cert,
                    ) {
                        *found.lock().expect("наблюдение") = Some(place);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
            }));
        }
        Watch {
            stop,
            leak,
            server,
            files,
        }
    }

    fn reject_signer_reshare(&self, group: &GroupDto) {
        let group_id = group.id.to_string();
        let other = &self.signers[1].name;
        let reshare = cli_err(
            &self.config,
            &self.signers[0].db,
            &["reshare", &group_id, "remove", other],
        );
        assert!(
            reshare.contains("пересчёт долей запускает администратор"),
            "{reshare}"
        );
        let history = cli_err(&self.config, &self.signers[0].db, &["history", &group_id]);
        assert!(
            history.contains("историю группы видит администратор"),
            "{history}"
        );
    }

    async fn reshare(&self, group: &GroupDto, add: &[String], remove: &[String]) -> GroupDto {
        let group_id = group.id.to_string();
        let mut args = vec!["reshare".to_string(), group_id.clone()];
        for name in add {
            args.push("add".into());
            args.push(name.clone());
        }
        for name in remove {
            args.push("remove".into());
            args.push(name.clone());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        progress(format!("пересчёт долей группы {group_id}"));
        let _: GroupDto = cli(&self.config, &self.admin_db, &refs);
        let done = wait_group(
            &self.config,
            &self.admin_db,
            &group_id,
            &self.signers[0].log,
            "группа снова active",
            |current| current.status == "active",
        );
        assert_eq!(done.threshold, group.threshold);
        assert_eq!(done.verifying_key_hex, group.verifying_key_hex);
        assert_eq!(done.solana_address, group.solana_address);
        assert_eq!(
            done.max_signers as usize,
            group.members.len() + add.len() - remove.len()
        );
        for name in remove {
            assert!(done.members.iter().all(|member| &member.username != name));
        }
        for name in add {
            assert!(done.members.iter().any(|member| &member.username == name));
        }
        done
    }

    async fn prove(&self, group: &GroupDto, secret: &[u8], change: Change) {
        let stayers = [
            hold_when(&self.signers[0], group.id, 2),
            hold_when(&self.signers[1], group.id, 2),
        ];
        let third = hold_when(&self.signers[2], group.id, 1);
        for held in stayers.iter().chain(std::iter::once(&third)) {
            assert!(
                held.live.reshare.is_none(),
                "после пересчёта сессия не хранится"
            );
            let latest = held.epochs.last().expect("эпоха");
            if held.live.key.as_deref() != Some(latest.key.as_str()) {
                panic!("живая доля не совпала с последней эпохой");
            }
            for epoch in &held.epochs {
                deny_share(&package(&epoch.key), secret);
                assert_material_clean("эпоха доли", secret, &epoch.key);
                if let Some(pubkey) = &epoch.pubkey {
                    assert_material_clean("публичный пакет эпохи", secret, pubkey);
                }
            }
            assert_material_clean(
                "живая доля",
                secret,
                &serde_json::to_string(&held.live).unwrap(),
            );
        }
        let old = [
            package(&stayers[0].epochs[0].key),
            package(&stayers[1].epochs[0].key),
        ];
        let new = [
            package(&stayers[0].epochs[1].key),
            package(&stayers[1].epochs[1].key),
        ];
        if secret_bytes(&old) != secret || secret_bytes(&new) != secret {
            panic!("после пересчёта секрет группы изменился");
        }
        if reconstruct(&[
            package(&stayers[0].epochs[0].key),
            package(&stayers[0].epochs[1].key),
        ])
        .is_ok()
        {
            panic!("старая и новая доля одного участника сложились");
        }
        match change {
            Change::Removed => {
                let mixed = secret_bytes(&[
                    package(&third.epochs[0].key),
                    package(&stayers[0].epochs[1].key),
                ]);
                if mixed == secret {
                    panic!("старая доля ушедшего и новая доля оставшегося собрали секрет");
                }
            }
            Change::Added => {
                let with_new = secret_bytes(&[
                    package(&stayers[0].epochs[1].key),
                    package(&third.epochs[0].key),
                ]);
                if with_new != secret {
                    panic!("новый участник не держит секрет группы");
                }
            }
        }
        self.assert_files_clean(secret);
        if let Some(place) = server_leak(&self.state.pool, secret).await {
            panic!("секрет группы появился на сервере: {place}");
        }
    }

    fn admin_sees_removal(&self, group: &GroupDto, removed: &str) {
        let events = self.history(group.id);
        assert!(events.iter().any(|event| {
            event.kind == "member_removed"
                && event.subject == removed
                && event.actor == self.admin_name
        }));
        for signer in &self.signers {
            assert!(events.iter().any(|event| {
                event.kind == "member_added"
                    && event.subject == signer.name
                    && event.actor == self.admin_name
            }));
        }
        assert!(events
            .iter()
            .all(|event| event.created_at.chars().count() >= 19));
    }

    fn admin_sees_addition(&self, group: &GroupDto, joiner: &str) {
        let events = self.history(group.id);
        assert!(events.iter().any(|event| {
            event.kind == "member_added"
                && event.subject == joiner
                && event.actor == self.admin_name
        }));
        for signer in self.signers.iter().take(2) {
            assert!(events.iter().any(|event| {
                event.kind == "member_added"
                    && event.subject == signer.name
                    && event.actor == self.admin_name
            }));
        }
        assert!(events.iter().all(|event| event.kind != "member_removed"));
        assert!(events
            .iter()
            .all(|event| event.created_at.chars().count() >= 19));
    }

    fn history(&self, group_id: Uuid) -> Vec<GroupEventDto> {
        cli(
            &self.config,
            &self.admin_db,
            &["history", &group_id.to_string()],
        )
    }

    fn group_now(&self, group_id: Uuid) -> GroupDto {
        cli(
            &self.config,
            &self.admin_db,
            &["group", &group_id.to_string()],
        )
    }

    fn assert_files_clean(&self, secret: &[u8]) {
        for signer in &self.signers {
            assert_path_clean(&signer.db, secret);
            assert_path_clean(&signer.log, secret);
            assert_path_clean(&signer.cert, secret);
        }
        assert_path_clean(&self.admin_db, secret);
    }

    async fn shutdown(mut self) {
        self.running.clear();
        let names: Vec<String> = self
            .signers
            .iter()
            .map(|signer| signer.name.clone())
            .chain(std::iter::once(self.admin_name.clone()))
            .collect();
        for name in names {
            ai_signing_server::delete_user(&self.state, &name)
                .await
                .unwrap();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Watch {
    fn finish(self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server.abort();
        for handle in self.files {
            let _ = handle.join();
        }
        if let Some(place) = self.leak.lock().expect("наблюдение").clone() {
            panic!("секрет группы появился: {place}");
        }
    }
}

struct Opened {
    store: Store,
    vault: Vault,
    user_id: Uuid,
}

fn open_local(signer: &Signer) -> Opened {
    let cert = load_certificate(&signer.cert).expect("сертификат");
    let store = Store::open_path(&signer.db).expect("локальная база");
    let vault = Vault::unlock_or_create(&store, &cert.secret_key_hex).expect("хранилище");
    let user_id = store.session().expect("сессия автоподписанта").1;
    Opened {
        store,
        vault,
        user_id,
    }
}

fn hold(signer: &Signer, group_id: Uuid) -> Held {
    let opened = open_local(signer);
    read_held(&opened, group_id)
}

fn hold_when(signer: &Signer, group_id: Uuid, epochs: usize) -> Held {
    let opened = open_local(signer);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = 0;
    while Instant::now() < deadline {
        let held = read_held(&opened, group_id);
        last = held.epochs.len();
        if last == epochs {
            return held;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "у {} ожидалось {epochs} эпох, сейчас {last}\n{}",
        signer.name,
        read_log(&signer.log)
    );
}

fn read_held(opened: &Opened, group_id: Uuid) -> Held {
    let epochs = opened
        .store
        .load_epochs(opened.user_id, group_id, &opened.vault)
        .expect("эпохи");
    let live = opened
        .store
        .load_share(opened.user_id, group_id, &opened.vault)
        .expect("доля")
        .unwrap_or_else(|| panic!("нет сохранённой доли"));
    Held { epochs, live }
}

fn local_leak(
    opened: &Opened,
    group_id: Uuid,
    secret: &[u8],
    db: &Path,
    log: &Path,
    cert: &Path,
) -> Option<String> {
    if let Ok(Some(live)) = opened
        .store
        .load_share(opened.user_id, group_id, &opened.vault)
    {
        let json = serde_json::to_string(&live).unwrap_or_default();
        if contains_secret(secret, json.as_bytes()) {
            return Some("живая доля".into());
        }
    }
    if let Ok(epochs) = opened
        .store
        .load_epochs(opened.user_id, group_id, &opened.vault)
    {
        for epoch in epochs {
            if contains_secret(secret, epoch.key.as_bytes()) {
                return Some(format!("эпоха {}", epoch.epoch));
            }
        }
    }
    for path in [db, log, cert] {
        if path_contains(path, secret) {
            return Some(format!("файл {}", path.display()));
        }
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        let wal = PathBuf::from(wal);
        if wal.exists() && path_contains(&wal, secret) {
            return Some(format!("файл {}", wal.display()));
        }
    }
    None
}

fn material(held: &Held) -> String {
    let mut text = serde_json::to_string(&held.live).unwrap_or_default();
    for epoch in &held.epochs {
        text.push_str(&epoch.key);
        if let Some(pubkey) = &epoch.pubkey {
            text.push_str(pubkey);
        }
    }
    text
}

fn package(json: &str) -> KeyPackage {
    serde_json::from_str(json).expect("доля не читается")
}

fn secret_bytes(keys: &[KeyPackage]) -> Vec<u8> {
    reconstruct(keys).expect("реконструкция доли").serialize()
}

fn deny_share(package: &KeyPackage, secret: &[u8]) {
    if package.signing_share().serialize() == secret {
        panic!("доля участника совпала с секретом группы");
    }
}

fn assert_material_clean(label: &str, secret: &[u8], text: &str) {
    if contains_secret(secret, text.as_bytes()) {
        panic!("{label}: секрет группы найден в данных участника");
    }
}

fn assert_path_clean(path: &Path, secret: &[u8]) {
    if path_contains(path, secret) {
        panic!("секрет группы появился в {}", path.display());
    }
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let wal = PathBuf::from(wal);
    if wal.exists() && path_contains(&wal, secret) {
        panic!("секрет группы появился в {}", wal.display());
    }
}

fn path_contains(path: &Path, secret: &[u8]) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    contains_secret(secret, &bytes)
}

fn contains_secret(secret: &[u8], haystack: &[u8]) -> bool {
    if secret.is_empty() {
        return false;
    }
    if haystack
        .windows(secret.len())
        .any(|window| window == secret)
    {
        return true;
    }
    let hex = encode_hex(secret);
    let upper = hex.to_ascii_uppercase();
    contains_slice(haystack, hex.as_bytes()) || contains_slice(haystack, upper.as_bytes())
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

async fn server_leak(pool: &sqlx::PgPool, secret: &[u8]) -> Option<String> {
    let hex = encode_hex(secret);
    let upper = hex.to_ascii_uppercase();
    const TEXT: &[(&str, &str)] = &[
        ("groups", "public_key_package"),
        ("groups", "verifying_key_hex"),
        ("group_members", "box_public"),
        ("group_events", "kind"),
        ("group_events", "actor_username"),
        ("group_events", "subject_username"),
        ("users", "box_public"),
        ("dkg_round1", "package"),
        ("dkg_round2", "ciphertext"),
        ("dkg_publics", "package"),
        ("reshare_sessions", "phase"),
        ("reshare_sessions", "refresh_package"),
        ("reshare_round1", "package"),
        ("reshare_round2", "ciphertext"),
        ("reshare_refresh_public", "package"),
        ("reshare_deltas", "ciphertext"),
        ("reshare_sigmas", "ciphertext"),
        ("reshare_sigmas", "commitment"),
        ("reshare_verifyings", "verifying_share"),
        ("reshare_final_public", "package"),
        ("sign_commitments", "commitment"),
        ("sign_shares", "share"),
        ("signing_requests", "signature_hex"),
        ("signing_requests", "error"),
        ("signing_requests", "solana_recipient"),
        ("signing_requests", "transaction_signature"),
    ];
    for (table, column) in TEXT {
        for needle in [&hex, &upper] {
            let sql = format!(
                "SELECT EXISTS(SELECT 1 FROM {table} WHERE strpos(COALESCE({column}, ''), $1) > 0)"
            );
            let found: bool = sqlx::query_scalar(&sql)
                .bind(needle)
                .fetch_one(pool)
                .await
                .unwrap_or_else(|_| panic!("не удалось прочитать {table}.{column}"));
            if found {
                return Some(format!("{table}.{column}"));
            }
        }
    }
    let found: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM signing_requests WHERE position($1 in message) > 0)",
    )
    .bind(secret)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|_| panic!("не удалось прочитать signing_requests.message"));
    if found {
        return Some("signing_requests.message".into());
    }
    None
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
    assert!(value.len().is_multiple_of(2), "нечётный hex: {value}");
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
    let output = command(config, database, args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "команда {args:?} завершилась с ошибкой\nstdout: {stdout}\nstderr: {stderr}"
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("ответ не json ({err})\nstdout: {stdout}\nstderr: {stderr}"))
}

fn cli_err(config: &Path, database: &Path, args: &[&str]) -> String {
    let output = command(config, database, args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "команда {args:?} должна была завершиться с ошибкой\nstdout: {stdout}\nstderr: {stderr}"
    );
    format!("{stdout}\n{stderr}")
}

fn command(config: &Path, database: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ai-signing-cli-e2e"))
        .arg("--config")
        .arg(config)
        .arg("--database")
        .arg(database)
        .args(args)
        .output()
        .expect("запуск cli")
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
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("сокет не поднялся: {}\n{}", path.display(), read_log(log));
}

fn wait_connected(config: &Path, database: &Path, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
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

fn wait_signers(config: &Path, database: &Path, names: &[String]) {
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
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("не все автоподписанты опубликовали ключ: {last}");
}

fn wait_group(
    config: &Path,
    database: &Path,
    group_id: &str,
    log: &Path,
    what: &str,
    ready: impl Fn(&GroupDto) -> bool,
) -> GroupDto {
    progress(format!("цикл: {what}"));
    let deadline = Instant::now() + Duration::from_secs(90);
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
    progress(format!("цикл: жду подпись и отправку запроса {request_id}"));
    let deadline = Instant::now() + Duration::from_secs(60);
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
    panic!("перевод не собрался: {last}\n{}", read_log(log));
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
