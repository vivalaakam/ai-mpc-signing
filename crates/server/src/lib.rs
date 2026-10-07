//! Coordination server for FROST signing groups.
//!
//! The server stores accounts, groups and ceremony transcripts. It never stores
//! key shares. DKG round 2 is forwarded as a sealed box that only the receiving
//! device can open. Signature shares are aggregated here because that step is
//! public.

mod ceremony;
mod db;
mod error;
mod hub;
mod routes;
mod ws;

use std::net::SocketAddr;

use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;

pub use error::ApiError;
pub use hub::Hub;

use crate::db::migrate;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub hub: Hub,
}

pub fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/ai-signing".to_string())
}

pub async fn bootstrap() -> anyhow::Result<AppState> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url())
        .await?;
    migrate(&pool).await?;
    Ok(AppState {
        pool,
        hub: Hub::default(),
    })
}

pub fn router(state: AppState) -> axum::Router {
    routes::router(state)
}

pub async fn serve(listener: tokio::net::TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

pub async fn delete_user(state: &AppState, username: &str) -> anyhow::Result<()> {
    let id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(&state.pool)
        .await?;
    let Some(id) = id else {
        return Ok(());
    };
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM groups WHERE created_by = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM signing_approvals WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sign_participants WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM dkg_round2 WHERE to_user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM group_members WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn run() -> anyhow::Result<()> {
    init_tracing();
    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let addr: SocketAddr = bind.parse()?;
    let state = bootstrap().await?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "сервер подписи слушает");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
