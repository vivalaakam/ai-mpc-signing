use ai_signing_protocol::{message_preview, GroupDto, MemberDto, SignRequestDto};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiError;

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)")
        .execute(pool)
        .await?;
    apply(pool, "001", include_str!("../migrations/001_init.sql")).await?;
    apply(pool, "002", include_str!("../migrations/002_roles.sql")).await?;
    Ok(())
}

async fn apply(pool: &PgPool, version: &str, sql: &str) -> anyhow::Result<()> {
    let applied: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)")
            .bind(version)
            .fetch_one(pool)
            .await?;
    if applied {
        return Ok(());
    }
    for statement in sql.split(';') {
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        sqlx::query(statement).execute(pool).await?;
    }
    sqlx::query("INSERT INTO schema_migrations (version) VALUES ($1)")
        .bind(version)
        .execute(pool)
        .await?;
    Ok(())
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    hex::encode(bytes)
}

#[derive(sqlx::FromRow)]
struct GroupRow {
    id: Uuid,
    name: String,
    threshold: i32,
    max_signers: i32,
    status: String,
    api_token: String,
    verifying_key_hex: Option<String>,
    created_by: Uuid,
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    user_id: Uuid,
    username: String,
    identifier: i32,
    box_public: Option<String>,
}

pub async fn load_group(
    pool: &PgPool,
    group_id: Uuid,
    viewer: Uuid,
) -> Result<GroupDto, sqlx::Error> {
    let group = sqlx::query_as::<_, GroupRow>(
        "SELECT id, name, threshold, max_signers, status, api_token, verifying_key_hex, created_by
         FROM groups WHERE id = $1",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await?;
    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT gm.user_id, u.username, gm.identifier, u.box_public
         FROM group_members gm
         JOIN users u ON u.id = gm.user_id
         WHERE gm.group_id = $1
         ORDER BY gm.identifier",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    let my_identifier = members
        .iter()
        .find(|member| member.user_id == viewer)
        .map(|member| member.identifier as u16);
    let i_created = group.created_by == viewer;
    Ok(GroupDto {
        id: group.id,
        name: group.name,
        threshold: group.threshold as u16,
        max_signers: group.max_signers as u16,
        status: group.status,
        api_token: i_created.then_some(group.api_token),
        verifying_key_hex: group.verifying_key_hex,
        created_by: group.created_by,
        i_created,
        my_identifier,
        members: members
            .into_iter()
            .map(|member| MemberDto {
                user_id: member.user_id,
                username: member.username,
                identifier: member.identifier as u16,
                box_public_hex: member.box_public,
            })
            .collect(),
    })
}

pub async fn list_group_ids(pool: &PgPool, user: Uuid) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT g.id FROM groups g
         WHERE g.created_by = $1
            OR EXISTS (SELECT 1 FROM group_members m WHERE m.group_id = g.id AND m.user_id = $1)
         ORDER BY g.created_at DESC",
    )
    .bind(user)
    .fetch_all(pool)
    .await
}

pub async fn audience(pool: &PgPool, group_id: Uuid) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT user_id FROM group_members WHERE group_id = $1
         UNION
         SELECT created_by FROM groups WHERE id = $1",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
}

pub async fn member_ids(pool: &PgPool, group_id: Uuid) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT user_id FROM group_members WHERE group_id = $1 ORDER BY identifier")
        .bind(group_id)
        .fetch_all(pool)
        .await
}

#[derive(sqlx::FromRow)]
struct RequestRow {
    id: Uuid,
    group_id: Uuid,
    group_name: String,
    message: Vec<u8>,
    status: String,
    signature_hex: Option<String>,
    error: Option<String>,
    approvals: i64,
    threshold: i32,
    my_decision: Option<String>,
    created_at: DateTime<Utc>,
}

fn request_dto(row: RequestRow) -> SignRequestDto {
    SignRequestDto {
        id: row.id,
        group_id: row.group_id,
        group_name: row.group_name,
        message_hex: hex::encode(&row.message),
        message_preview: message_preview(&row.message),
        status: row.status,
        signature_hex: row.signature_hex,
        error: row.error,
        approvals: row.approvals as u16,
        threshold: row.threshold as u16,
        my_decision: row.my_decision,
        created_at: row.created_at.to_rfc3339(),
    }
}

const REQUEST_SQL: &str = "
    SELECT r.id, r.group_id, g.name AS group_name, r.message, r.status, r.signature_hex, r.error,
           (SELECT count(*) FROM signing_approvals a WHERE a.request_id = r.id AND a.decision = 'approved') AS approvals,
           g.threshold,
           (SELECT decision FROM signing_approvals a WHERE a.request_id = r.id AND a.user_id = $1) AS my_decision,
           r.created_at
    FROM signing_requests r
    JOIN groups g ON g.id = r.group_id
";

pub async fn load_request(
    pool: &PgPool,
    request_id: Uuid,
    viewer: Uuid,
) -> Result<SignRequestDto, sqlx::Error> {
    let row = sqlx::query_as::<_, RequestRow>(&format!("{REQUEST_SQL} WHERE r.id = $2"))
        .bind(viewer)
        .bind(request_id)
        .fetch_one(pool)
        .await?;
    Ok(request_dto(row))
}

pub async fn list_requests(pool: &PgPool, user: Uuid) -> Result<Vec<SignRequestDto>, sqlx::Error> {
    let rows = sqlx::query_as::<_, RequestRow>(&format!(
        "{REQUEST_SQL}
         WHERE EXISTS (SELECT 1 FROM group_members m WHERE m.group_id = r.group_id AND m.user_id = $1)
         ORDER BY r.created_at DESC
         LIMIT 50"
    ))
    .bind(user)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(request_dto).collect())
}

pub async fn require_member(pool: &PgPool, group_id: Uuid, user: Uuid) -> Result<u16, ApiError> {
    let identifier: Option<i32> = sqlx::query_scalar(
        "SELECT identifier FROM group_members WHERE group_id = $1 AND user_id = $2",
    )
    .bind(group_id)
    .bind(user)
    .fetch_optional(pool)
    .await
    .map_err(ApiError::db)?;
    identifier
        .map(|value| value as u16)
        .ok_or_else(|| ApiError::new(axum::http::StatusCode::FORBIDDEN, "вы не участник группы"))
}

pub fn check_package(value: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.len() > 256 * 1024 {
        return Err(crate::error::bad("пакет недопустимого размера"));
    }
    Ok(())
}

pub async fn user_by_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<(Uuid, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await
}

pub async fn group_by_api_token(
    pool: &PgPool,
    group_id: Uuid,
    token: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1 AND api_token = $2)")
        .bind(group_id)
        .bind(token)
        .fetch_one(pool)
        .await
}
