use std::collections::HashSet;

use ai_signing_protocol::{
    canonical_public_key, canonical_role, decode_sign_message, verify_certificate_login,
    AddMemberRequest, AuthResponse, CertificateLogin, CreateGroupRequest, CreateSignBody,
    CreateSolanaTransferBody, DeviceKeyRequest, GroupDto, GroupEventDto, ReshareRequest,
    SignRequestDto, SignStatusResponse, SignerDto, UserProfile, ROLE_ADMIN, ROLE_SIGNER,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::{FromRequestParts, Path, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ceremony::{self, publish_group},
    db::{self, random_token},
    error::{bad, ApiError},
    ws, AppState,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{username}", delete(delete_user))
        .route(
            "/api/users/{username}/certificates",
            post(issue_certificate),
        )
        .route("/api/login", post(login))
        .route("/api/login/certificate", post(login_certificate))
        .route("/api/me", get(me))
        .route("/api/signers", get(list_signers))
        .route("/api/me/device", put(set_device))
        .route("/api/groups", get(list_groups).post(create_group))
        .route("/api/groups/{id}", get(get_group))
        .route("/api/groups/{id}/device", put(set_group_device))
        .route("/api/groups/{id}/accept", post(accept_group_participation))
        .route("/api/groups/{id}/members", post(add_member))
        .route("/api/groups/{id}/dkg", post(start_dkg))
        .route("/api/groups/{id}/reshare", post(start_reshare))
        .route("/api/groups/{id}/history", get(group_history))
        .route("/api/groups/{id}/requests", post(create_sign_request))
        .route(
            "/api/groups/{id}/solana-transfers",
            post(create_solana_transfer),
        )
        .route("/api/inbox", get(inbox))
        .route("/api/signing-requests/{id}/approve", post(approve))
        .route("/api/signing-requests/{id}/reject", post(reject))
        .route("/api/v1/groups/{id}/requests", post(external_create))
        .route(
            "/api/v1/groups/{id}/requests/{request_id}",
            get(external_get),
        )
        .route("/ws", get(ws::upgrade))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

struct CurrentUser {
    id: Uuid,
    username: String,
    role: String,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(&parts.headers)?;
        let user = db::user_by_token(&state.pool, &token)
            .await
            .map_err(ApiError::db)?;
        let Some((id, username, role)) = user else {
            return Err(ApiError::new(StatusCode::UNAUTHORIZED, "сессия не найдена"));
        };
        Ok(Self { id, username, role })
    }
}

fn bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "нужен заголовок Authorization"))?;
    value
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "нужен Bearer-токен"))
}

fn valid_username(username: &str) -> bool {
    let len = username.chars().count();
    (3..=32).contains(&len)
        && username
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "не удалось захэшировать пароль",
            )
        })
}

fn password_ok(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded)
        .ok()
        .and_then(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .ok()
        })
        .is_some()
}

async fn issue_session(
    state: &AppState,
    user_id: Uuid,
    username: String,
    role: String,
) -> Result<Json<AuthResponse>, ApiError> {
    let token = random_token();
    sqlx::query("INSERT INTO sessions (token, user_id) VALUES ($1, $2)")
        .bind(&token)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::db)?;
    Ok(Json(AuthResponse {
        token,
        user_id,
        username,
        role,
    }))
}

#[derive(Serialize)]
struct UserCreated {
    user_id: Uuid,
    username: String,
    role: String,
}

async fn list_users(State(state): State<AppState>) -> Result<Json<Vec<UserCreated>>, ApiError> {
    let rows: Vec<(Uuid, String, String)> =
        sqlx::query_as("SELECT id, username, role FROM users ORDER BY username")
            .fetch_all(&state.pool)
            .await
            .map_err(ApiError::db)?;
    Ok(Json(
        rows.into_iter()
            .map(|(user_id, username, role)| UserCreated {
                user_id,
                username,
                role,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
    password: String,
    role: String,
}

async fn create_user(
    State(state): State<AppState>,
    Json(body): Json<NewUser>,
) -> Result<(StatusCode, Json<UserCreated>), ApiError> {
    let role = canonical_role(&body.role)
        .ok_or_else(|| bad("роль: подписант или админ"))?
        .to_string();
    let id = insert_user(&state, &body.username, &body.password, &role).await?;
    Ok((
        StatusCode::CREATED,
        Json(UserCreated {
            user_id: id,
            username: body.username,
            role,
        }),
    ))
}

async fn delete_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<UserCreated>, ApiError> {
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, role FROM users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::db)?;
    let Some((id, role)) = row else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "пользователь не найден",
        ));
    };
    crate::delete_user(&state, &username)
        .await
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "ошибка базы данных"))?;
    Ok(Json(UserCreated {
        user_id: id,
        username,
        role,
    }))
}

async fn insert_user(
    state: &AppState,
    username: &str,
    password: &str,
    role: &str,
) -> Result<Uuid, ApiError> {
    if !valid_username(username) {
        return Err(bad("имя: 3–32 символа, латиница, цифры, _ и -"));
    }
    if password.chars().count() < 8 {
        return Err(bad("пароль должен быть не короче 8 символов"));
    }
    let id = Uuid::new_v4();
    let hash = hash_password(password)?;
    let inserted = sqlx::query(
        "INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(username)
    .bind(&hash)
    .bind(role)
    .execute(&state.pool)
    .await;
    if let Err(err) = inserted {
        if let sqlx::Error::Database(db) = &err {
            if db.code().as_deref() == Some("23505") {
                return Err(ApiError::new(StatusCode::CONFLICT, "такое имя уже занято"));
            }
        }
        return Err(ApiError::db(err));
    }
    Ok(id)
}

#[derive(Deserialize)]
struct NewCertificate {
    public_key_hex: String,
}

#[derive(Serialize)]
struct CertificateCreated {
    certificate_id: Uuid,
    username: String,
    public_key_hex: String,
}

async fn issue_certificate(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Json(body): Json<NewCertificate>,
) -> Result<(StatusCode, Json<CertificateCreated>), ApiError> {
    let public_key =
        canonical_public_key(&body.public_key_hex).map_err(|err| bad(err.to_string()))?;
    let user: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, username FROM users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::db)?;
    let Some((user_id, username)) = user else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "пользователь не найден",
        ));
    };
    let certificate_id = Uuid::new_v4();
    let inserted =
        sqlx::query("INSERT INTO user_certificates (id, user_id, public_key) VALUES ($1, $2, $3)")
            .bind(certificate_id)
            .bind(user_id)
            .bind(&public_key)
            .execute(&state.pool)
            .await;
    if let Err(err) = inserted {
        if is_unique(&err) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "такой сертификат уже выпущен",
            ));
        }
        return Err(ApiError::db(err));
    }
    Ok((
        StatusCode::CREATED,
        Json(CertificateCreated {
            certificate_id,
            username,
            public_key_hex: public_key,
        }),
    ))
}

async fn login_certificate(
    State(state): State<AppState>,
    Json(body): Json<CertificateLogin>,
) -> Result<Json<AuthResponse>, ApiError> {
    verify_certificate_login(&body)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "сертификат не принят"))?;
    let now = chrono::Utc::now().timestamp();
    if now.abs_diff(body.signed_at) > 120 {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "срок подписи сертификата истёк",
        ));
    }
    if !canonical_nonce(&body.nonce) {
        return Err(bad("сертификат указан неверно"));
    }
    let public_key = canonical_public_key(&body.public_key_hex)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "сертификат не принят"))?;
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT u.id, u.username, u.role
         FROM user_certificates c
         JOIN users u ON u.id = c.user_id
         WHERE c.public_key = $1",
    )
    .bind(&public_key)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let Some((id, username, role)) = row else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "сертификат не принят",
        ));
    };
    if username != body.username || public_key != body.public_key_hex {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "сертификат не принят",
        ));
    }
    let mut tx = state.pool.begin().await.map_err(ApiError::db)?;
    sqlx::query("DELETE FROM certificate_nonces WHERE expires_at < now()")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    let inserted = sqlx::query(
        "INSERT INTO certificate_nonces (nonce, expires_at) VALUES ($1, now() + interval '5 minutes')",
    )
    .bind(&body.nonce)
    .execute(&mut *tx)
    .await;
    if let Err(err) = inserted {
        tx.rollback().await.ok();
        if is_unique(&err) {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "этот вход сертификатом уже использован",
            ));
        }
        return Err(ApiError::db(err));
    }
    tx.commit().await.map_err(ApiError::db)?;
    issue_session(&state, id, username, role).await
}

fn canonical_nonce(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
}

fn is_unique(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<Credentials>,
) -> Result<Json<AuthResponse>, ApiError> {
    let row: Option<(Uuid, String, String, String)> =
        sqlx::query_as("SELECT id, username, password_hash, role FROM users WHERE username = $1")
            .bind(&body.username)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::db)?;
    let Some((id, username, hash, role)) = row else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "неверное имя или пароль",
        ));
    };
    if !password_ok(&body.password, &hash) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "неверное имя или пароль",
        ));
    }
    issue_session(&state, id, username, role).await
}

async fn me(user: CurrentUser) -> Json<UserProfile> {
    Json(UserProfile {
        user_id: user.id,
        username: user.username,
        role: user.role,
    })
}

async fn list_signers(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<SignerDto>>, ApiError> {
    if user.role != ROLE_ADMIN {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "список подписантов доступен администратору",
        ));
    }
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, username FROM users
         WHERE role = 'signer' AND box_public IS NOT NULL
         ORDER BY username",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(Json(
        rows.into_iter()
            .map(|(user_id, username)| SignerDto { user_id, username })
            .collect(),
    ))
}

async fn set_device(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(body): Json<DeviceKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let bytes = hex::decode(body.public_key_hex.trim())
        .map_err(|_| bad("публичный ключ не является hex"))?;
    if bytes.len() != 32 {
        return Err(bad("публичный ключ устройства должен быть 32 байта"));
    }
    let public_hex = hex::encode(bytes);
    let current: Option<String> = sqlx::query_scalar("SELECT box_public FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await
        .map_err(ApiError::db)?;
    if current.as_deref() == Some(public_hex.as_str()) {
        return Ok(StatusCode::NO_CONTENT);
    }
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM group_members m
            JOIN groups g ON g.id = m.group_id
            WHERE m.user_id = $1 AND g.status = 'dkg'
         )",
    )
    .bind(user.id)
    .fetch_one(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if busy {
        return Err(bad(
            "нельзя сменить ключ устройства, пока идёт генерация ключа группы",
        ));
    }
    sqlx::query("UPDATE users SET box_public = $2 WHERE id = $1")
        .bind(user.id)
        .bind(&public_hex)
        .execute(&state.pool)
        .await
        .map_err(ApiError::db)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_group_device(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(group_id): Path<Uuid>,
    Json(body): Json<DeviceKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let bytes = hex::decode(body.public_key_hex.trim())
        .map_err(|_| bad("публичный ключ не является hex"))?;
    if bytes.len() != 32 {
        return Err(bad("публичный ключ участника должен быть 32 байта"));
    }
    let public_hex = hex::encode(bytes);
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT g.status, gm.box_public
         FROM group_members gm
         JOIN groups g ON g.id = gm.group_id
         WHERE gm.group_id = $1 AND gm.user_id = $2",
    )
    .bind(group_id)
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let Some((status, current)) = row else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "вы не участник этой группы",
        ));
    };
    if current.as_deref() == Some(public_hex.as_str()) {
        if status == "resharing" {
            crate::reshare::note_device(&state, group_id).await?;
        }
        return Ok(StatusCode::NO_CONTENT);
    }
    let joining = status == "resharing" && current.is_none();
    if status == "forming" || joining {
        let accepted: bool = sqlx::query_scalar(
            "SELECT accepted_at IS NOT NULL FROM group_members WHERE group_id = $1 AND user_id = $2",
        )
        .bind(group_id)
        .bind(user.id)
        .fetch_one(&state.pool)
        .await
        .map_err(ApiError::db)?;
        if !accepted {
            return Err(bad(
                "сначала подтвердите участие в группе (кнопка в клиенте)",
            ));
        }
    } else if status != "forming" && !joining {
        return Err(bad("ключ участника уже зафиксирован"));
    }
    sqlx::query("UPDATE group_members SET box_public = $3 WHERE group_id = $1 AND user_id = $2")
        .bind(group_id)
        .bind(user.id)
        .bind(&public_hex)
        .execute(&state.pool)
        .await
        .map_err(ApiError::db)?;
    publish_group(&state, group_id).await?;
    if joining {
        crate::reshare::note_device(&state, group_id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn accept_group_participation(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(group_id): Path<Uuid>,
    Json(body): Json<DeviceKeyRequest>,
) -> Result<Json<GroupDto>, ApiError> {
    ceremony::accept_participation(&state, user.id, group_id, &body.public_key_hex).await?;
    Ok(Json(
        db::load_group(&state.pool, group_id, user.id)
            .await
            .map_err(ApiError::db)?,
    ))
}

async fn list_groups(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<GroupDto>>, ApiError> {
    let ids = db::list_group_ids(&state.pool, user.id)
        .await
        .map_err(ApiError::db)?;
    let mut groups = Vec::with_capacity(ids.len());
    for id in ids {
        groups.push(
            db::load_group(&state.pool, id, user.id)
                .await
                .map_err(ApiError::db)?,
        );
    }
    Ok(Json(groups))
}

async fn create_group(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(body): Json<CreateGroupRequest>,
) -> Result<Json<GroupDto>, ApiError> {
    if user.role != ROLE_ADMIN {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "группу создаёт администратор",
        ));
    }
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(bad("название группы: от 1 до 80 символов"));
    }
    let members = member_names(&body.members)?;
    let max_signers = u16::try_from(members.len()).unwrap_or(u16::MAX);
    if !(2..=max_signers).contains(&body.threshold) || !(2..=16).contains(&max_signers) {
        return Err(bad("порог t и размер n: 2 ≤ t ≤ n ≤ 16"));
    }
    let id = Uuid::new_v4();
    let api_token = random_token();
    let mut tx = state.pool.begin().await.map_err(ApiError::db)?;
    sqlx::query(
        "INSERT INTO groups (id, name, threshold, max_signers, status, api_token, created_by)
         VALUES ($1, $2, $3, $4, 'forming', $5, $6)",
    )
    .bind(id)
    .bind(name)
    .bind(i32::from(body.threshold))
    .bind(i32::from(max_signers))
    .bind(&api_token)
    .bind(user.id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    for (index, username) in members.iter().enumerate() {
        let signer = signer_user(&mut *tx, username).await?;
        let identifier = i32::try_from(index + 1).unwrap_or(i32::MAX);
        sqlx::query(
            "INSERT INTO group_members (group_id, user_id, identifier) VALUES ($1, $2, $3)",
        )
        .bind(id)
        .bind(signer)
        .bind(identifier)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::db)?;
        db::insert_group_event(&mut *tx, id, "member_added", &user.username, username)
            .await
            .map_err(ApiError::db)?;
    }
    tx.commit().await.map_err(ApiError::db)?;
    publish_group(&state, id).await?;
    Ok(Json(
        db::load_group(&state.pool, id, user.id)
            .await
            .map_err(ApiError::db)?,
    ))
}

fn member_names(names: &[String]) -> Result<Vec<String>, ApiError> {
    let mut seen = HashSet::new();
    let mut members = Vec::with_capacity(names.len());
    for name in names {
        let name = name.trim();
        if name.is_empty() {
            return Err(bad("укажите имя подписанта"));
        }
        if !seen.insert(name.to_string()) {
            return Err(bad(format!("подписант {name} указан дважды")));
        }
        members.push(name.to_string());
    }
    Ok(members)
}

async fn signer_user(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    username: &str,
) -> Result<Uuid, ApiError> {
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, role FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(executor)
            .await
            .map_err(ApiError::db)?;
    let Some((id, role)) = row else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("пользователь {username} не найден"),
        ));
    };
    if role != ROLE_SIGNER {
        return Err(bad(format!("{username} не подписант")));
    }
    Ok(id)
}

async fn active_signer(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    username: &str,
) -> Result<Uuid, ApiError> {
    let row: Option<(Uuid, String, Option<String>)> =
        sqlx::query_as("SELECT id, role, box_public FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(executor)
            .await
            .map_err(ApiError::db)?;
    let Some((id, role, box_public)) = row else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("пользователь {username} не найден"),
        ));
    };
    if role != ROLE_SIGNER {
        return Err(bad(format!("{username} не подписант")));
    }
    if box_public.is_none() {
        return Err(bad(format!(
            "у {username} ещё нет ключа устройства: пусть этот пользователь откроет клиент"
        )));
    }
    Ok(id)
}

async fn get_group(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Json<GroupDto>, ApiError> {
    let group = db::load_group(&state.pool, id, user.id)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => ApiError::new(StatusCode::NOT_FOUND, "группа не найдена"),
            other => ApiError::db(other),
        })?;
    if !group.i_created && group.my_identifier.is_none() {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "нет доступа к группе"));
    }
    Ok(Json(group))
}

async fn add_member(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    Json(body): Json<AddMemberRequest>,
) -> Result<Json<GroupDto>, ApiError> {
    if user.role != ROLE_ADMIN {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "группу создаёт администратор",
        ));
    }
    let group = db::load_group(&state.pool, id, user.id)
        .await
        .map_err(ApiError::db)?;
    if !group.i_created {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "добавлять участников может создатель",
        ));
    }
    if group.status != "forming" {
        return Err(bad("состав группы уже зафиксирован"));
    }
    if group.members.len() >= usize::from(group.max_signers) {
        return Err(bad("в группе уже достаточно участников"));
    }
    let username = body.username.trim();
    let member = active_signer(&state.pool, username).await?;
    if group
        .members
        .iter()
        .any(|existing| existing.user_id == member)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "пользователь уже в группе",
        ));
    }
    let identifier = group.members.len() as i32 + 1;
    let mut tx = state.pool.begin().await.map_err(ApiError::db)?;
    sqlx::query("INSERT INTO group_members (group_id, user_id, identifier) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(member)
        .bind(identifier)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    db::insert_group_event(&mut *tx, id, "member_added", &user.username, username)
        .await
        .map_err(ApiError::db)?;
    tx.commit().await.map_err(ApiError::db)?;
    publish_group(&state, id).await?;
    Ok(Json(
        db::load_group(&state.pool, id, user.id)
            .await
            .map_err(ApiError::db)?,
    ))
}

async fn start_dkg(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Json<GroupDto>, ApiError> {
    if user.role != ROLE_ADMIN {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "генерацию ключа запускает администратор",
        ));
    }
    ceremony::start_dkg(&state, user.id, id).await?;
    Ok(Json(
        db::load_group(&state.pool, id, user.id)
            .await
            .map_err(ApiError::db)?,
    ))
}

async fn start_reshare(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    Json(body): Json<ReshareRequest>,
) -> Result<Json<GroupDto>, ApiError> {
    if user.role != ROLE_ADMIN {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "пересчёт долей запускает администратор",
        ));
    }
    crate::reshare::start(&state, user.id, id, body.add, body.remove).await?;
    Ok(Json(
        db::load_group(&state.pool, id, user.id)
            .await
            .map_err(ApiError::db)?,
    ))
}

async fn group_history(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<GroupEventDto>>, ApiError> {
    if user.role != ROLE_ADMIN {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "историю группы видит администратор",
        ));
    }
    let group = db::load_group(&state.pool, id, user.id)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => ApiError::new(StatusCode::NOT_FOUND, "группа не найдена"),
            other => ApiError::db(other),
        })?;
    if !group.i_created {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "историю группы видит её создатель",
        ));
    }
    Ok(Json(
        db::list_group_events(&state.pool, id)
            .await
            .map_err(ApiError::db)?,
    ))
}

async fn create_sign_request(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateSignBody>,
) -> Result<(StatusCode, Json<SignRequestDto>), ApiError> {
    if user.role != ROLE_ADMIN {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "запрос на подпись создаёт администратор",
        ));
    }
    let group = db::load_group(&state.pool, id, user.id)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => ApiError::new(StatusCode::NOT_FOUND, "группа не найдена"),
            other => ApiError::db(other),
        })?;
    if !group.i_created {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "отправлять на подпись может создатель группы",
        ));
    }
    let message = decode_sign_message(&body).map_err(|err| bad(err.to_string()))?;
    let request = ceremony::create_request(&state, id, message).await?;
    Ok((StatusCode::CREATED, Json(request)))
}

async fn create_solana_transfer(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateSolanaTransferBody>,
) -> Result<(StatusCode, Json<SignRequestDto>), ApiError> {
    if user.role != ROLE_ADMIN {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "перевод создаёт администратор",
        ));
    }
    let group = db::load_group(&state.pool, id, user.id)
        .await
        .map_err(ApiError::db)?;
    if !group.i_created {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "отправлять перевод может создатель группы",
        ));
    }
    let request =
        ceremony::create_solana_transfer(&state, id, body.recipient, body.lamports).await?;
    Ok((StatusCode::CREATED, Json(request)))
}

async fn inbox(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<SignRequestDto>>, ApiError> {
    Ok(Json(
        db::list_requests(&state.pool, user.id)
            .await
            .map_err(ApiError::db)?,
    ))
}

async fn approve(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Json<SignRequestDto>, ApiError> {
    ceremony::decide(&state, user.id, id, true).await?;
    Ok(Json(
        db::load_request(&state.pool, id, user.id, false)
            .await
            .map_err(ApiError::db)?,
    ))
}

async fn reject(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Json<SignRequestDto>, ApiError> {
    ceremony::decide(&state, user.id, id, false).await?;
    Ok(Json(
        db::load_request(&state.pool, id, user.id, false)
            .await
            .map_err(ApiError::db)?,
    ))
}

async fn authorize_group(
    state: &AppState,
    headers: &HeaderMap,
    group_id: Uuid,
) -> Result<(), ApiError> {
    let token = bearer(headers)?;
    let ok = db::group_by_api_token(&state.pool, group_id, &token)
        .await
        .map_err(ApiError::db)?;
    if ok {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "неверный токен группы",
        ))
    }
}

fn status_of(request: &SignRequestDto) -> SignStatusResponse {
    SignStatusResponse {
        request_id: request.id,
        status: request.status.clone(),
        signature_hex: request.signature_hex.clone(),
        error: request.error.clone(),
    }
}

async fn external_create(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<CreateSignBody>,
) -> Result<(StatusCode, Json<SignStatusResponse>), ApiError> {
    authorize_group(&state, &headers, id).await?;
    let message = decode_sign_message(&body).map_err(|err| bad(err.to_string()))?;
    let request = ceremony::create_request(&state, id, message).await?;
    Ok((StatusCode::CREATED, Json(status_of(&request))))
}

async fn external_get(
    State(state): State<AppState>,
    Path((id, request_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<SignStatusResponse>, ApiError> {
    authorize_group(&state, &headers, id).await?;
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT group_id FROM signing_requests WHERE id = $1")
            .bind(request_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::db)?;
    if owner != Some(id) {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "запрос не найден"));
    }
    let request = db::load_request(&state.pool, request_id, Uuid::nil(), true)
        .await
        .map_err(ApiError::db)?;
    Ok(Json(status_of(&request)))
}
