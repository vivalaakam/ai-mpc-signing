use std::{
    collections::HashMap,
    path::Path,
    time::{Duration, Instant},
};

use ai_signing_protocol::{
    role_title, AuthResponse, CertificateMaterial, ClientMsg, GroupDto, GroupEventDto, Participant,
    ServerMsg, SignRequestDto, SignerDto, UserProfile, ROLE_ADMIN,
};
use async_channel::Sender;
use futures::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::os::unix::net::UnixListener as StdUnixListener;

use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

use crate::control;
use crate::store::Store;
use crate::vault::Vault;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Cmd {
    Login {
        username: String,
        password: String,
    },
    Logout,
    Refresh,
    Status,
    CreateGroup {
        name: String,
        threshold: u16,
        members: Vec<String>,
    },
    ListSigners,
    AddMember {
        group_id: Uuid,
        username: String,
    },
    StartDkg {
        group_id: Uuid,
    },
    RequestSign {
        group_id: Uuid,
        message: String,
    },
    RequestSolanaTransfer {
        group_id: Uuid,
        recipient: String,
        lamports: u64,
    },
    Approve {
        request_id: Uuid,
    },
    Reject {
        request_id: Uuid,
    },
    Reshare {
        group_id: Uuid,
        add: Vec<String>,
        remove: Vec<String>,
    },
    History {
        group_id: Uuid,
    },
    AcceptGroupParticipation {
        group_id: Uuid,
    },
}

#[derive(Clone, Debug)]
pub struct SettleWait {
    pub group_id: Uuid,
    pub timeout: Duration,
    pub timeout_message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub username: Option<String>,
    pub role: Option<String>,
    pub connected: bool,
    pub server: String,
    pub groups: Vec<GroupDto>,
    pub requests: Vec<SignRequestDto>,
    pub signers: Vec<SignerDto>,
    pub group: Option<GroupDto>,
    pub request: Option<SignRequestDto>,
    #[serde(default)]
    pub events: Vec<GroupEventDto>,
}

impl Reply {
    pub(crate) fn fatal(server: &str, error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
            notice: None,
            username: None,
            role: None,
            connected: false,
            server: server.to_string(),
            groups: Vec::new(),
            requests: Vec::new(),
            signers: Vec::new(),
            group: None,
            request: None,
            events: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UiState {
    pub server_url: String,
    pub username: Option<String>,
    pub role: Option<String>,
    pub connected: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub groups: Vec<GroupDto>,
    pub requests: Vec<SignRequestDto>,
    pub signers: Vec<SignerDto>,
    pub shares: HashMap<Uuid, bool>,
    pub history: HashMap<Uuid, Vec<GroupEventDto>>,
    pub unlocked: bool,
}

impl UiState {
    pub fn from_store(store: &Store, server_url: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            username: store.session().map(|(_, _, username)| username),
            role: store.role(),
            connected: false,
            error: None,
            notice: None,
            groups: Vec::new(),
            requests: Vec::new(),
            signers: Vec::new(),
            shares: HashMap::new(),
            history: HashMap::new(),
            unlocked: false,
        }
    }
}

pub(crate) struct Job {
    pub cmd: Cmd,
    pub reply: Option<tokio::sync::oneshot::Sender<Reply>>,
    pub wait: Option<SettleWait>,
}

struct Settle {
    group_id: Uuid,
    deadline: Instant,
    reply: tokio::sync::oneshot::Sender<Reply>,
    timeout_message: String,
}

/// Opens the window session. The socket makes this the only ceremony on `listener`'s path.
pub fn start(
    store: Store,
    server_url: String,
    listener: StdUnixListener,
) -> (Sender<Cmd>, async_channel::Receiver<UiState>) {
    let (cmd_tx, cmd_rx) = async_channel::unbounded();
    let (event_tx, event_rx) = async_channel::unbounded();
    std::thread::Builder::new()
        .name("ai-signing-net".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio");
            runtime.block_on(async move {
                let listener = control::into_tokio(listener).expect("сокет управления");
                let (job_tx, job_rx) = async_channel::unbounded();
                let accept_tx = job_tx.clone();
                let bridge = async move {
                    while let Ok(cmd) = cmd_rx.recv().await {
                        if job_tx
                            .send(Job {
                                cmd,
                                reply: None,
                                wait: None,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                };
                let accept = control::accept(listener, accept_tx);
                let session = run(store, server_url, true, Boot::idle(), job_rx, event_tx);
                tokio::join!(bridge, accept, session);
            });
        })
        .expect("поток сети");
    (cmd_tx, event_rx)
}

enum Unlock {
    Password(String),
    Certificate(CertificateMaterial),
}

struct Boot {
    unlock: Option<Unlock>,
    resume_session: bool,
    auto_approve: bool,
}

impl Boot {
    fn idle() -> Self {
        Self {
            unlock: None,
            resume_session: false,
            auto_approve: false,
        }
    }

    fn resume() -> Self {
        Self {
            unlock: None,
            resume_session: true,
            auto_approve: false,
        }
    }

    fn password(password: String) -> Self {
        Self {
            unlock: Some(Unlock::Password(password)),
            resume_session: false,
            auto_approve: false,
        }
    }

    fn certificate(certificate: CertificateMaterial) -> Self {
        Self {
            unlock: Some(Unlock::Certificate(certificate)),
            resume_session: false,
            auto_approve: true,
        }
    }
}

/// Keeps the ceremony running and answers CLI commands on the database socket.
pub fn watch(
    store: Store,
    server_url: String,
    socket: &Path,
    password: &str,
) -> Result<(), String> {
    let listener = control::bind(socket)?;
    let _unlink = control::Unlink(socket.to_path_buf());
    eprintln!("клиент слушает {}, сервер {server_url}", socket.display());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let listener = control::into_tokio(listener)?;
        let (job_tx, job_rx) = async_channel::unbounded();
        let (event_tx, _event_rx) = async_channel::unbounded();
        let accept = control::accept(listener, job_tx);
        let session = run(
            store,
            server_url,
            true,
            Boot::password(password.to_string()),
            job_rx,
            event_tx,
        );
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|err| err.to_string())?;
        tokio::select! {
            _ = accept => {}
            _ = session => {}
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
        Ok(())
    })
}

/// Listens on the database socket, logs in with a certificate, and approves every
/// pending request this user can sign.
pub fn auto(
    store: Store,
    server_url: String,
    socket: &Path,
    certificate: CertificateMaterial,
) -> Result<(), String> {
    let listener = control::bind(socket)?;
    let _unlink = control::Unlink(socket.to_path_buf());
    eprintln!(
        "автоподписант слушает {}, сервер {server_url}",
        socket.display()
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let listener = control::into_tokio(listener)?;
        let (job_tx, job_rx) = async_channel::unbounded();
        let (event_tx, event_rx) = async_channel::unbounded();
        let accept = control::accept(listener, job_tx);
        let session = run(
            store,
            server_url,
            true,
            Boot::certificate(certificate),
            job_rx,
            event_tx,
        );
        tokio::pin!(session);
        tokio::pin!(accept);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|err| err.to_string())?;
        let mut ready = false;
        loop {
            tokio::select! {
                _ = &mut session => break,
                _ = &mut accept => break,
                state = event_rx.recv() => {
                    match state {
                        Ok(state) if !ready => {
                            ready = true;
                            if let Some(err) = state.error {
                                return Err(err);
                            }
                            if !state.unlocked || state.username.is_none() {
                                return Err("сертификат не открыл локальные ключи".into());
                            }
                            eprintln!(
                                "вошёл как {}",
                                state.username.unwrap_or_default()
                            );
                        }
                        Ok(state) => {
                            if let Some(err) = state.error.as_deref() {
                                eprintln!("{err}");
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = tokio::signal::ctrl_c() => break,
                _ = terminate.recv() => break,
            }
        }
        Ok(())
    })
}

/// Runs one command in this process. `connect` joins the relay; use it only when
/// no other process is already the ceremony for this database.
pub fn execute(
    store: Store,
    server_url: String,
    cmd: Cmd,
    connect: bool,
    wait: Option<SettleWait>,
) -> Result<Reply, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let (job_tx, job_rx) = async_channel::unbounded();
        let (event_tx, _event_rx) = async_channel::unbounded();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        job_tx
            .send(Job {
                cmd,
                reply: Some(reply_tx),
                wait,
            })
            .await
            .map_err(|_| "сессия не запустилась".to_string())?;
        let session = run(store, server_url, connect, Boot::resume(), job_rx, event_tx);
        tokio::pin!(session);
        tokio::select! {
            reply = reply_rx => reply.map_err(|_| "сессия не ответила".to_string()),
            _ = &mut session => Err("сессия остановилась".to_string()),
        }
    })
}

struct Conn {
    outgoing: Sender<ClientMsg>,
    task: JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Session {
    store: Store,
    http: reqwest::Client,
    vault: Option<Vault>,
    events: Sender<UiState>,
    server_url: String,
    token: Option<String>,
    user_id: Option<Uuid>,
    username: Option<String>,
    connected: bool,
    error: Option<String>,
    notice: Option<String>,
    role: Option<String>,
    groups: Vec<GroupDto>,
    requests: Vec<SignRequestDto>,
    signers: Vec<SignerDto>,
    parties: HashMap<Uuid, Participant>,
    focus_group: Option<GroupDto>,
    focus_request: Option<SignRequestDto>,
    focus_events: Vec<GroupEventDto>,
    history: HashMap<Uuid, Vec<GroupEventDto>>,
    preserve_error: bool,
    auto_approve: bool,
}

async fn run(
    store: Store,
    server_url: String,
    connect: bool,
    boot: Boot,
    cmd_rx: async_channel::Receiver<Job>,
    events: Sender<UiState>,
) {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("http");
    let auto_approve = boot.auto_approve;
    let resume_session = boot.resume_session;
    let role = store.role();
    let remembered = store.session().map(|(_, _, username)| username);
    let mut session = Session {
        server_url: server_url.clone(),
        token: None,
        user_id: None,
        username: remembered.clone(),
        connected: false,
        error: None,
        notice: None,
        role,
        groups: Vec::new(),
        requests: Vec::new(),
        signers: Vec::new(),
        parties: HashMap::new(),
        focus_group: None,
        focus_request: None,
        focus_events: Vec::new(),
        history: HashMap::new(),
        preserve_error: false,
        auto_approve,
        store,
        http,
        vault: None,
        events,
    };
    if let Some(unlock) = boot.unlock {
        match unlock {
            Unlock::Password(password) => match remembered {
                Some(username) => {
                    if let Err(err) = session.auth("/api/login", &username, &password).await {
                        session.error = Some(err.text());
                    }
                }
                None => {
                    session.error = Some("сначала войдите: login ИМЯ ПАРОЛЬ".into());
                }
            },
            Unlock::Certificate(certificate) => {
                if let Err(err) = session.auth_certificate(&certificate).await {
                    session.error = Some(err.text());
                }
            }
        }
    } else if resume_session {
        if let Some((token, user_id, username)) = session.store.session() {
            session.token = Some(token);
            session.user_id = Some(user_id);
            session.username = Some(username);
            session.restore().await;
        }
    }
    session.emit();

    let mut conn: Option<Conn> = None;
    let mut incoming: Option<async_channel::Receiver<ServerMsg>> = None;
    let mut reconnect_at = Instant::now();
    let mut settle: Option<Settle> = None;

    loop {
        if connect && conn.is_none() && session.token.is_some() && Instant::now() >= reconnect_at {
            match connect_ws(&session.ws_url()).await {
                Ok((outgoing, receiver, task)) => {
                    conn = Some(Conn { outgoing, task });
                    incoming = Some(receiver);
                    session.connected = true;
                    session.emit();
                }
                Err(err) => {
                    session.connected = false;
                    session.error = Some(err);
                    session.emit();
                    reconnect_at = Instant::now() + Duration::from_secs(2);
                }
            }
        }

        let mut delay = if connect && conn.is_none() && session.token.is_some() {
            reconnect_at.saturating_duration_since(Instant::now())
        } else {
            Duration::from_secs(3600)
        };
        if let Some(pending) = &settle {
            delay = delay.min(pending.deadline.saturating_duration_since(Instant::now()));
        }

        let wake = tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Ok(cmd) => Wake::Command(cmd),
                Err(_) => break,
            },
            msg = recv_server(&mut incoming) => Wake::Server(msg),
            _ = tokio::time::sleep(delay) => Wake::Tick,
        };

        match wake {
            Wake::Tick => {}
            Wake::Command(job) => {
                let drop_socket = session.handle_cmd(job.cmd).await;
                if let Some(reply) = job.reply {
                    let waiting = match job.wait {
                        Some(wait) if session.error.is_none() => Some(wait),
                        _ => None,
                    };
                    if let Some(wait) = waiting {
                        settle = Some(Settle {
                            group_id: wait.group_id,
                            deadline: Instant::now() + wait.timeout,
                            reply,
                            timeout_message: wait.timeout_message,
                        });
                    } else {
                        let _ = reply.send(session.reply());
                    }
                }
                if drop_socket {
                    conn = None;
                    incoming = None;
                    session.connected = false;
                    reconnect_at = Instant::now();
                }
            }
            Wake::Server(Ok(message)) => {
                if let Some(conn) = conn.as_ref() {
                    if let Err(err) = session.on_server(message, &conn.outgoing).await {
                        session.error = Some(err);
                        session.emit();
                    }
                }
            }
            Wake::Server(Err(())) => {
                conn = None;
                incoming = None;
                session.connected = false;
                session.emit();
                reconnect_at = Instant::now() + Duration::from_secs(2);
            }
        }
        pump_settle(&mut session, &mut settle);
    }
}

fn pump_settle(session: &mut Session, settle: &mut Option<Settle>) {
    let Some(pending) = settle.take() else {
        return;
    };
    let status = session
        .groups
        .iter()
        .find(|group| group.id == pending.group_id)
        .map(|group| group.status.as_str());
    let done = matches!(status, Some("active" | "failed"));
    let timed_out = Instant::now() >= pending.deadline;
    if done || timed_out {
        if timed_out && !done {
            session.error = Some(pending.timeout_message);
        } else if status == Some("active") && !session.preserve_error {
            session.error = None;
        }
        session.preserve_error = false;
        if session.focus_group.is_none() {
            session.focus_group = session
                .groups
                .iter()
                .find(|group| group.id == pending.group_id)
                .cloned();
        }
        let _ = pending.reply.send(session.reply());
    } else {
        *settle = Some(pending);
    }
}

enum Wake {
    Command(Job),
    Server(Result<ServerMsg, ()>),
    Tick,
}

async fn recv_server(
    incoming: &mut Option<async_channel::Receiver<ServerMsg>>,
) -> Result<ServerMsg, ()> {
    match incoming {
        Some(receiver) => receiver.recv().await.map_err(|_| ()),
        None => std::future::pending().await,
    }
}

async fn connect_ws(
    url: &str,
) -> Result<
    (
        Sender<ClientMsg>,
        async_channel::Receiver<ServerMsg>,
        JoinHandle<()>,
    ),
    String,
> {
    let (socket, _) = connect_async(url)
        .await
        .map_err(|err| format!("нет связи с сервером: {err}"))?;
    let (mut sink, mut stream) = socket.split();
    let (in_tx, in_rx) = async_channel::unbounded();
    let (out_tx, out_rx) = async_channel::unbounded::<ClientMsg>();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                incoming = stream.next() => {
                    match incoming {
                        Some(Ok(Message::Text(text))) => {
                            let message = serde_json::from_str::<ServerMsg>(&text).unwrap_or_else(|err| {
                                ServerMsg::Error { message: format!("непонятное сообщение: {err}") }
                            });
                            if in_tx.send(message).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            if sink.send(Message::Pong(payload)).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(_)) => {}
                        _ => break,
                    }
                }
                outgoing = out_rx.recv() => {
                    let Ok(message) = outgoing else { break };
                    let Ok(text) = serde_json::to_string(&message) else { continue };
                    if sink.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    Ok((out_tx, in_rx, task))
}

impl Session {
    fn ws_url(&self) -> String {
        let token = self.token.clone().unwrap_or_default();
        let base = self.server_url.trim_end_matches('/');
        let ws = if let Some(rest) = base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            format!("ws://{base}")
        };
        format!("{ws}/ws?token={token}")
    }

    fn emit(&self) {
        let shares = self
            .parties
            .iter()
            .map(|(id, party)| (*id, party.has_share()))
            .collect();
        let _ = self.events.try_send(UiState {
            server_url: self.server_url.clone(),
            username: self.username.clone(),
            role: self.role.clone(),
            connected: self.connected,
            error: self.error.clone(),
            notice: self.notice.clone(),
            groups: self.groups.clone(),
            requests: self.requests.clone(),
            signers: self.signers.clone(),
            shares,
            history: self.history.clone(),
            unlocked: self.vault.is_some(),
        });
    }

    fn reply(&self) -> Reply {
        Reply {
            ok: self.error.is_none(),
            error: self.error.clone(),
            notice: self.notice.clone(),
            username: self.username.clone(),
            role: self.role.clone(),
            connected: self.connected,
            server: self.server_url.clone(),
            groups: self.groups.clone(),
            requests: self.requests.clone(),
            signers: self.signers.clone(),
            group: self.focus_group.clone(),
            request: self.focus_request.clone(),
            events: self.focus_events.clone(),
        }
    }

    async fn restore(&mut self) {
        match self.load_profile().await {
            Ok(()) => {}
            Err(CallError::Unauthorized) => {
                self.clear_login();
                return;
            }
            Err(CallError::Message(message)) => {
                self.error = Some(message);
                return;
            }
        }
        if self.vault.is_some() {
            if let Err(err) = self.upload_account_key().await {
                self.error = Some(err.text());
            }
        }
        match self.fetch_lists().await {
            Ok(()) => {}
            Err(CallError::Unauthorized) => self.clear_login(),
            Err(CallError::Message(message)) => self.error = Some(message),
        }
    }

    fn clear_login(&mut self) {
        self.token = None;
        self.user_id = None;
        self.username = None;
        self.role = None;
        self.groups.clear();
        self.requests.clear();
        self.signers.clear();
        self.parties.clear();
        self.connected = false;
        let _ = self.store.clear_session();
    }

    async fn handle_cmd(&mut self, cmd: Cmd) -> bool {
        self.notice = None;
        self.focus_group = None;
        self.focus_request = None;
        self.focus_events.clear();
        let outcome = match cmd {
            Cmd::Login { username, password } => {
                tracing::info!(username = %username, "session: login");
                match self.auth("/api/login", &username, &password).await {
                    Ok(()) => {
                        tracing::info!(
                            role = ?self.role,
                            username = ?self.username,
                            "session: login ok"
                        );
                        Ok(())
                    }
                    Err(err) => {
                        tracing::warn!(?err, "session: login failed");
                        Err(err)
                    }
                }
            }
            Cmd::Logout => {
                self.vault = None;
                self.parties.clear();
                self.clear_login();
                self.error = None;
                self.emit();
                return true;
            }
            Cmd::Status => Ok(()),
            Cmd::Refresh => self.fetch_lists().await,
            Cmd::CreateGroup {
                name,
                threshold,
                members,
            } => {
                let group: Result<GroupDto, CallError> = self
                    .post(
                        "/api/groups",
                        &serde_json::json!({
                            "name": name,
                            "threshold": threshold,
                            "members": members,
                        }),
                    )
                    .await;
                match group {
                    Ok(group) => {
                        self.focus_group = Some(group.clone());
                        self.upsert_group(group);
                        self.notice = Some("Группа создана".into());
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Cmd::AddMember { group_id, username } => {
                let group: Result<GroupDto, CallError> = self
                    .post(
                        &format!("/api/groups/{group_id}/members"),
                        &serde_json::json!({ "username": username }),
                    )
                    .await;
                match group {
                    Ok(group) => {
                        self.focus_group = Some(group.clone());
                        self.upsert_group(group);
                        self.notice = Some("Участник добавлен".into());
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Cmd::AcceptGroupParticipation { group_id } => {
                let Some(group) = self.groups.iter().find(|g| g.id == group_id).cloned() else {
                    self.error = Some("Группа не найдена".into());
                    self.emit();
                    return true;
                };
                if group.status != "forming" && group.status != "resharing" {
                    self.error = Some("Группа уже не принимает подтверждения".into());
                    self.emit();
                    return true;
                }
                if group.status == "resharing" {
                    let accepted = group
                        .members
                        .iter()
                        .find(|member| member.user_id == self.user_id.unwrap_or_default())
                        .is_some_and(|member| member.participation_accepted);
                    if accepted {
                        self.error = Some("Участие уже подтверждено".into());
                        self.emit();
                        return true;
                    }
                }
                let public_key = match self.group_public(group_id) {
                    Ok(key) => key,
                    Err(err) => {
                        self.error = Some(err);
                        self.emit();
                        return true;
                    }
                };
                let updated: Result<GroupDto, CallError> = self
                    .post(
                        &format!("/api/groups/{group_id}/accept"),
                        &serde_json::json!({ "public_key_hex": public_key }),
                    )
                    .await;
                match updated {
                    Ok(group) => {
                        self.adopt_group(group);
                        self.notice = Some("Участие в группе подтверждено".into());
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Cmd::StartDkg { group_id } => {
                let group: Result<GroupDto, CallError> = self
                    .post(
                        &format!("/api/groups/{group_id}/dkg"),
                        &serde_json::json!({}),
                    )
                    .await;
                match group {
                    Ok(group) => {
                        self.focus_group = Some(group.clone());
                        self.adopt_group(group);
                        self.notice = Some("Генерация ключа запущена".into());
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Cmd::RequestSign { group_id, message } => {
                let request: Result<SignRequestDto, CallError> = self
                    .post(
                        &format!("/api/groups/{group_id}/requests"),
                        &serde_json::json!({ "message_utf8": message }),
                    )
                    .await;
                match request {
                    Ok(request) => {
                        self.focus_request = Some(request.clone());
                        self.upsert_request(request);
                        self.notice = Some("Запрос отправлен на подпись".into());
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Cmd::RequestSolanaTransfer {
                group_id,
                recipient,
                lamports,
            } => {
                let request: Result<SignRequestDto, CallError> = self
                    .post(
                        &format!("/api/groups/{group_id}/solana-transfers"),
                        &serde_json::json!({ "recipient": recipient, "lamports": lamports }),
                    )
                    .await;
                match request {
                    Ok(request) => {
                        self.focus_request = Some(request.clone());
                        self.upsert_request(request);
                        self.notice = Some("Перевод Solana отправлен на подтверждение".into());
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Cmd::Approve { request_id } => self.decide(request_id, true).await,
            Cmd::Reject { request_id } => self.decide(request_id, false).await,
            Cmd::Reshare {
                group_id,
                add,
                remove,
            } => {
                self.preserve_error = false;
                let Some(group) = self.groups.iter().find(|g| g.id == group_id).cloned() else {
                    self.error = Some("Группа не найдена".into());
                    self.emit();
                    return true;
                };
                if let Err(message) =
                    crate::membership::membership_change(&group, &self.requests, &add, &remove)
                {
                    self.error = Some(message);
                    self.emit();
                    return true;
                }
                let group: Result<GroupDto, CallError> = self
                    .post(
                        &format!("/api/groups/{group_id}/reshare"),
                        &serde_json::json!({ "add": add, "remove": remove }),
                    )
                    .await;
                match group {
                    Ok(group) => {
                        self.focus_group = Some(group.clone());
                        self.adopt_group(group);
                        self.notice = Some(
                            "Состав группы обновлён. Новые участники должны подтвердить участие — пересчёт стартует автоматически.".into(),
                        );
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Cmd::History { group_id } => {
                let events: Result<Vec<GroupEventDto>, CallError> =
                    self.get(&format!("/api/groups/{group_id}/history")).await;
                match events {
                    Ok(events) => {
                        self.history.insert(group_id, events.clone());
                        self.focus_events = events;
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Cmd::ListSigners => {
                let signers: Result<Vec<SignerDto>, CallError> = self.get("/api/signers").await;
                match signers {
                    Ok(signers) => {
                        self.signers = signers;
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
        };
        match outcome {
            Ok(()) => self.error = None,
            Err(CallError::Unauthorized) => {
                self.clear_login();
                self.error = Some("Сессия закончилась, войдите снова".into());
                self.emit();
                return true;
            }
            Err(CallError::Message(message)) => self.error = Some(message),
        }
        self.emit();
        false
    }

    async fn auth(&mut self, path: &str, username: &str, password: &str) -> Result<(), CallError> {
        tracing::debug!(path, username, server = %self.server_url, "session: POST auth");
        let auth: AuthResponse = self
            .send(
                self.http
                    .post(self.url(path))
                    .json(&serde_json::json!({ "username": username, "password": password })),
            )
            .await?;
        self.finish_auth(auth, password, false).await
    }

    async fn auth_certificate(
        &mut self,
        certificate: &CertificateMaterial,
    ) -> Result<(), CallError> {
        let proof = certificate
            .login_now()
            .map_err(|err| CallError::Message(err.to_string()))?;
        let auth: AuthResponse = self
            .send(
                self.http
                    .post(self.url("/api/login/certificate"))
                    .json(&proof),
            )
            .await?;
        self.finish_auth(auth, &certificate.secret_key_hex, true)
            .await
    }

    async fn finish_auth(
        &mut self,
        auth: AuthResponse,
        vault_secret: &str,
        from_certificate: bool,
    ) -> Result<(), CallError> {
        self.store
            .save_session(&auth.token, auth.user_id, &auth.username, &auth.role)
            .map_err(CallError::Message)?;
        self.token = Some(auth.token);
        self.user_id = Some(auth.user_id);
        self.username = Some(auth.username);
        self.role = Some(auth.role);
        self.parties.clear();
        self.groups.clear();
        self.requests.clear();
        match Vault::unlock_or_create(&self.store, vault_secret) {
            Ok(vault) => self.vault = Some(vault),
            Err(err) => {
                let err = if from_certificate && err == "пароль не открывает локальные ключи"
                {
                    "сертификат не открывает локальные ключи этой базы".to_string()
                } else {
                    err
                };
                return Err(CallError::Message(err));
            }
        }
        self.upload_account_key().await?;
        self.fetch_lists().await?;
        self.publish_group_keys().await?;
        self.fetch_lists().await?;
        let title = role_title(self.role.as_deref().unwrap_or(""));
        self.notice = Some(format!(
            "Вы вошли как {} · {title}",
            self.username.clone().unwrap_or_default()
        ));
        Ok(())
    }

    async fn load_profile(&mut self) -> Result<(), CallError> {
        let profile: UserProfile = self.get("/api/me").await?;
        let token = self.token.clone().unwrap_or_default();
        self.store
            .save_session(&token, profile.user_id, &profile.username, &profile.role)
            .map_err(CallError::Message)?;
        self.user_id = Some(profile.user_id);
        self.username = Some(profile.username);
        self.role = Some(profile.role);
        Ok(())
    }

    async fn decide(&mut self, request_id: Uuid, approve: bool) -> Result<(), CallError> {
        let path = if approve {
            format!("/api/signing-requests/{request_id}/approve")
        } else {
            format!("/api/signing-requests/{request_id}/reject")
        };
        let request: SignRequestDto = self.post(&path, &serde_json::json!({})).await?;
        self.focus_request = Some(request.clone());
        self.upsert_request(request);
        self.notice = Some(if approve {
            "Подпись подтверждена".into()
        } else {
            "Запрос отклонён".into()
        });
        Ok(())
    }

    fn can_sign(&self, request: &SignRequestDto) -> bool {
        request.status == "pending"
            && request.my_decision.is_none()
            && self
                .groups
                .iter()
                .any(|group| group.id == request.group_id && group.my_identifier.is_some())
    }

    async fn approve_pending(&mut self) -> Result<(), CallError> {
        if !self.auto_approve || !self.connected || self.vault.is_none() {
            return Ok(());
        }
        let ids: Vec<Uuid> = self
            .requests
            .iter()
            .filter(|request| self.can_sign(request))
            .map(|request| request.id)
            .collect();
        let mut failed = None;
        for id in ids {
            if let Err(err) = self.decide(id, true).await {
                if matches!(err, CallError::Unauthorized) {
                    return Err(err);
                }
                failed = Some(err);
            }
        }
        if let Some(err) = failed {
            return Err(err);
        }
        Ok(())
    }

    fn group_public(&self, group_id: Uuid) -> Result<String, String> {
        let vault = self
            .vault
            .as_ref()
            .ok_or("локальные ключи закрыты: войдите с паролем")?;
        Ok(vault.identity().group_key(group_id).public_hex())
    }

    async fn upload_account_key(&self) -> Result<(), CallError> {
        let Some(vault) = &self.vault else {
            return Err(CallError::Message(
                "локальные ключи закрыты: войдите с паролем".into(),
            ));
        };
        let public_key_hex = vault.identity().account_key().public_hex();
        self.put_public("/api/me/device", &public_key_hex).await
    }

    async fn publish_group_keys(&mut self) -> Result<(), CallError> {
        let groups = self.groups.clone();
        for group in &groups {
            self.ensure_group_key(group).await?;
        }
        Ok(())
    }

    async fn ensure_group_key(&mut self, group: &GroupDto) -> Result<(), CallError> {
        if group.my_identifier.is_none() || self.vault.is_none() {
            return Ok(());
        }
        if group.status == "forming" || group.status == "resharing" {
            let Some(user_id) = self.user_id else {
                return Ok(());
            };
            let accepted = group
                .members
                .iter()
                .find(|member| member.user_id == user_id)
                .is_some_and(|member| member.participation_accepted);
            if !accepted {
                return Ok(());
            }
        }
        let Some(user_id) = self.user_id else {
            return Ok(());
        };
        let public_key = self.group_public(group.id).map_err(CallError::Message)?;
        let current = group
            .members
            .iter()
            .find(|member| member.user_id == user_id)
            .and_then(|member| member.box_public_hex.clone());
        if current.as_deref() == Some(public_key.as_str()) {
            return Ok(());
        }
        if group.status != "forming" && current.is_some() {
            return Err(CallError::Message("ключ участника уже зафиксирован".into()));
        }
        self.put_public(&format!("/api/groups/{}/device", group.id), &public_key)
            .await
    }

    async fn put_public(&self, path: &str, public_key_hex: &str) -> Result<(), CallError> {
        let response = self
            .http
            .put(self.url(path))
            .bearer_auth(self.token.clone().unwrap_or_default())
            .json(&serde_json::json!({ "public_key_hex": public_key_hex }))
            .send()
            .await
            .map_err(|err| CallError::Message(format!("сервер недоступен: {err}")))?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(error_from(response).await)
    }

    async fn fetch_lists(&mut self) -> Result<(), CallError> {
        let groups: Vec<GroupDto> = self.get("/api/groups").await?;
        let requests: Vec<SignRequestDto> = self.get("/api/inbox").await?;
        self.groups = groups;
        self.requests = requests;
        if self.vault.is_some() {
            self.publish_group_keys().await?;
        }
        if self.role.as_deref() == Some(ROLE_ADMIN) {
            self.signers = self.get("/api/signers").await?;
        } else {
            self.signers.clear();
        }
        self.parties
            .retain(|id, _| self.groups.iter().any(|group| group.id == *id));
        let groups = self.groups.clone();
        for group in groups {
            self.adopt_group(group);
        }
        self.load_histories().await;
        self.approve_pending().await?;
        Ok(())
    }

    async fn load_histories(&mut self) {
        if self.role.as_deref() != Some(ROLE_ADMIN) {
            return;
        }
        let ids: Vec<Uuid> = self
            .groups
            .iter()
            .filter(|group| group.i_created)
            .map(|group| group.id)
            .collect();
        for id in ids {
            self.load_history(id).await;
        }
    }

    async fn load_history(&mut self, group_id: Uuid) {
        let path = format!("/api/groups/{group_id}/history");
        if let Ok(events) = self.get::<Vec<GroupEventDto>>(&path).await {
            self.history.insert(group_id, events);
        }
    }

    fn adopt_group(&mut self, group: GroupDto) {
        self.upsert_group(group.clone());
        if self.vault.is_none() {
            return;
        }
        if let Err(err) = self.with_party(&group, |party| {
            party
                .set_group(group.clone())
                .map_err(|err| err.to_string())
        }) {
            self.error = Some(err);
        }
    }

    async fn on_server(
        &mut self,
        message: ServerMsg,
        outgoing: &Sender<ClientMsg>,
    ) -> Result<(), String> {
        let mut produced = Vec::new();
        match &message {
            ServerMsg::Hello { username, .. } => {
                self.connected = true;
                self.username = Some(username.clone());
            }
            ServerMsg::Error { message } => self.error = Some(message.clone()),
            ServerMsg::Snapshot { groups, requests } => {
                self.groups = groups.clone();
                self.requests = requests.clone();
                self.parties
                    .retain(|id, _| self.groups.iter().any(|group| group.id == *id));
                let groups = self.groups.clone();
                for group in &groups {
                    self.ensure_group_key(group)
                        .await
                        .map_err(|err| err.text())?;
                }
                for group in groups {
                    if self.vault.is_none() {
                        break;
                    }
                    produced.extend(self.with_party(&group, |party| {
                        party
                            .set_group(group.clone())
                            .map_err(|err| err.to_string())
                    })?);
                }
                self.load_histories().await;
            }
            ServerMsg::GroupUpdated { group } => {
                let group = group.clone();
                self.upsert_group(group.clone());
                if self.vault.is_some() {
                    if let Err(err) = self.ensure_group_key(&group).await {
                        tracing::warn!(group_id = %group.id, ?err, "не удалось зарегистрировать ключ устройства в группе");
                        if self.error.is_none() {
                            self.error = Some(err.text());
                        }
                    }
                    produced.extend(self.with_party(&group, |party| {
                        party
                            .set_group(group.clone())
                            .map_err(|err| err.to_string())
                    })?);
                }
                if group.i_created {
                    self.load_history(group.id).await;
                }
            }
            ServerMsg::SignRequest { request } => self.upsert_request(request.clone()),
            ServerMsg::DkgCompleted {
                group_id,
                verifying_key_hex,
            } => {
                let group_id = *group_id;
                let verifying_key_hex = verifying_key_hex.clone();
                if let Some(group) = self.groups.iter_mut().find(|group| group.id == group_id) {
                    group.status = "active".into();
                    group.verifying_key_hex = Some(verifying_key_hex);
                }
                self.notice = Some("Ключ группы собран".into());
            }
            ServerMsg::DkgFailed { group_id, message } => {
                let group_id = *group_id;
                if let Some(group) = self.groups.iter_mut().find(|group| group.id == group_id) {
                    group.status = "failed".into();
                }
                self.error = Some(message.clone());
            }
            ServerMsg::SignCompleted {
                request_id,
                signature_hex,
            } => {
                let request_id = *request_id;
                let signature_hex = signature_hex.clone();
                let admin = self.role.as_deref() == Some(ROLE_ADMIN);
                if let Some(request) = self
                    .requests
                    .iter_mut()
                    .find(|request| request.id == request_id)
                {
                    request.status = "completed".into();
                    if admin && !signature_hex.is_empty() {
                        request.signature_hex = Some(signature_hex);
                    }
                }
                self.notice = Some(if admin {
                    "Подпись готова".into()
                } else {
                    "Всё прошло".into()
                });
            }
            ServerMsg::SignFailed {
                request_id,
                message,
            } => {
                let request_id = *request_id;
                let message = message.clone();
                if let Some(request) = self
                    .requests
                    .iter_mut()
                    .find(|request| request.id == request_id)
                {
                    request.status = "failed".into();
                    request.error = Some(message.clone());
                }
                self.error = Some(message);
            }
            ServerMsg::DkgStarted { group_id }
            | ServerMsg::DkgRound1 { group_id, .. }
            | ServerMsg::DkgRound2 { group_id, .. }
            | ServerMsg::SignStarted { group_id, .. } => {
                produced.extend(self.drive(*group_id, &message)?);
            }
            ServerMsg::SignCommitment { request_id, .. } => {
                let group_id = self
                    .requests
                    .iter()
                    .find(|request| request.id == *request_id)
                    .map(|request| request.group_id);
                if let Some(group_id) = group_id {
                    produced.extend(self.drive(group_id, &message)?);
                }
            }
            ServerMsg::ReshareCompleted {
                group_id,
                verifying_key_hex,
            } => {
                let group_id = *group_id;
                let verifying_key_hex = verifying_key_hex.clone();
                self.preserve_error = false;
                if let Some(group) = self.groups.iter_mut().find(|group| group.id == group_id) {
                    if group.verifying_key_hex.as_deref() != Some(verifying_key_hex.as_str())
                        && group.verifying_key_hex.is_some()
                    {
                        self.preserve_error = true;
                        self.error = Some("пересчёт изменил ключ группы".into());
                    }
                }
                produced.extend(self.drive(group_id, &message)?);
                if self.error.is_none() {
                    self.notice = Some("Доли пересчитаны".into());
                }
            }
            ServerMsg::ReshareFailed {
                group_id,
                message: reason,
            } => {
                let group_id = *group_id;
                self.preserve_error = true;
                self.error = Some(reason.clone());
                produced.extend(self.drive(group_id, &message)?);
            }
            ServerMsg::ReshareStarted { group_id, .. }
            | ServerMsg::ReshareRound1 { group_id, .. }
            | ServerMsg::ReshareRound2 { group_id, .. }
            | ServerMsg::ReshareRepair { group_id, .. }
            | ServerMsg::ReshareDelta { group_id, .. }
            | ServerMsg::ReshareSigma { group_id, .. }
            | ServerMsg::ReshareSigmaCommit { group_id, .. }
            | ServerMsg::ReshareVerifying { group_id, .. } => {
                produced.extend(self.drive(*group_id, &message)?);
            }
        }
        self.send_client(outgoing, produced);
        if matches!(
            &message,
            ServerMsg::Snapshot { .. } | ServerMsg::SignRequest { .. }
        ) {
            self.approve_pending().await.map_err(|err| err.text())?;
        }
        self.emit();
        Ok(())
    }

    fn drive(&mut self, group_id: Uuid, message: &ServerMsg) -> Result<Vec<ClientMsg>, String> {
        let Some(group) = self
            .groups
            .iter()
            .find(|group| group.id == group_id)
            .cloned()
        else {
            return Ok(Vec::new());
        };
        let reshare = matches!(
            message,
            ServerMsg::ReshareStarted { .. }
                | ServerMsg::ReshareRound1 { .. }
                | ServerMsg::ReshareRound2 { .. }
                | ServerMsg::ReshareRepair { .. }
                | ServerMsg::ReshareDelta { .. }
                | ServerMsg::ReshareSigma { .. }
                | ServerMsg::ReshareSigmaCommit { .. }
                | ServerMsg::ReshareVerifying { .. }
                | ServerMsg::ReshareCompleted { .. }
                | ServerMsg::ReshareFailed { .. }
        );
        self.with_party(&group, |party| match party.handle(message) {
            Ok(messages) => Ok(messages),
            Err(err) if reshare => Ok(vec![ClientMsg::ReshareAbort {
                group_id,
                reason: err.to_string(),
            }]),
            Err(err) => Err(err.to_string()),
        })
    }

    fn send_client(&mut self, outgoing: &Sender<ClientMsg>, messages: Vec<ClientMsg>) {
        if messages.is_empty() {
            return;
        }
        for message in messages {
            if outgoing.try_send(message).is_err() {
                self.error = Some("Не удалось отправить сообщение церемонии".into());
                break;
            }
        }
    }

    fn with_party(
        &mut self,
        group: &GroupDto,
        body: impl FnOnce(&mut Participant) -> Result<Vec<ClientMsg>, String>,
    ) -> Result<Vec<ClientMsg>, String> {
        if group.my_identifier.is_none() {
            return Ok(Vec::new());
        }
        self.ensure(group)?;
        let messages = body(self.parties.get_mut(&group.id).expect("участник группы"))?;
        self.save_party(group.id)?;
        Ok(messages)
    }

    fn ensure(&mut self, group: &GroupDto) -> Result<(), String> {
        if self.parties.contains_key(&group.id) {
            return Ok(());
        }
        let Some(vault) = self.vault.as_ref() else {
            return Err("локальные ключи закрыты: войдите с паролем".into());
        };
        let device = vault.identity().group_key(group.id);
        let mut party = Participant::new(device, group.clone());
        if let Some(user_id) = self.user_id {
            if let Some(blob) = self.store.load_share(user_id, group.id, vault)? {
                party.import_state(&blob).map_err(|err| err.to_string())?;
            }
        }
        self.parties.insert(group.id, party);
        Ok(())
    }

    fn save_party(&self, group_id: Uuid) -> Result<(), String> {
        let Some(user_id) = self.user_id else {
            return Ok(());
        };
        let Some(party) = self.parties.get(&group_id) else {
            return Ok(());
        };
        let Some(vault) = &self.vault else {
            return Err("локальные ключи закрыты: войдите с паролем".into());
        };
        let blob = party.export().map_err(|err| err.to_string())?;
        self.store.save_share(user_id, group_id, &blob, vault)
    }

    fn upsert_group(&mut self, group: GroupDto) {
        if let Some(slot) = self.groups.iter_mut().find(|item| item.id == group.id) {
            *slot = group;
        } else {
            self.groups.insert(0, group);
        }
    }

    fn upsert_request(&mut self, request: SignRequestDto) {
        if let Some(slot) = self.requests.iter_mut().find(|item| item.id == request.id) {
            *slot = request;
        } else {
            self.requests.insert(0, request);
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server_url.trim_end_matches('/'))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CallError> {
        self.send(
            self.http
                .get(self.url(path))
                .bearer_auth(self.token.clone().unwrap_or_default()),
        )
        .await
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, CallError> {
        self.send(
            self.http
                .post(self.url(path))
                .bearer_auth(self.token.clone().unwrap_or_default())
                .json(body),
        )
        .await
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, CallError> {
        let response = request
            .send()
            .await
            .map_err(|err| CallError::Message(format!("сервер недоступен: {err}")))?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(CallError::Unauthorized);
        }
        let text = response
            .text()
            .await
            .map_err(|err| CallError::Message(err.to_string()))?;
        if !status.is_success() {
            return Err(CallError::Message(api_message(&text, status)));
        }
        serde_json::from_str(&text).map_err(|err| CallError::Message(format!("{err}: {text}")))
    }
}

#[derive(Debug)]
enum CallError {
    Unauthorized,
    Message(String),
}

impl CallError {
    fn text(self) -> String {
        match self {
            Self::Unauthorized => "сессия не найдена".into(),
            Self::Message(message) => message,
        }
    }
}

async fn error_from(response: reqwest::Response) -> CallError {
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return CallError::Unauthorized;
    }
    let text = response.text().await.unwrap_or_default();
    CallError::Message(api_message(&text, status))
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
