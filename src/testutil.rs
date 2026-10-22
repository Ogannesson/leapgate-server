//! Test helpers for HTTP contract tests (`tower::ServiceExt::oneshot`) and database tests.

use crate::{config::Config, state::AppState};
use axum::{
    body::{Body, Bytes},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
};
use sqlx::SqlitePool;
use std::net::SocketAddr;
use tempfile::TempDir;
use tower::ServiceExt as _;

/// Keep `dir` alive for as long as the pool/state is used.
pub(crate) struct TestApp {
    pub dir: TempDir,
    pub state: AppState,
    /// All API routes, the same as served on `api.listen`.
    pub app: axum::Router,
}

/// A migrated SQLite database in a temporary directory.
pub(crate) async fn pool() -> (TempDir, SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite3");
    let pool = crate::database::open(path.to_str().unwrap()).await.unwrap();
    (dir, pool)
}

/// Full `AppState` (skeleton-level Router/ConnTracker, default `Config`, temporary secret key) and the router.
pub(crate) async fn app() -> TestApp {
    let (dir, db) = pool().await;
    let state = AppState::new(db, Config::default(), &dir.path().join(crate::crypto::SECRET_KEY_FILE)).unwrap();
    let app = crate::api::router(state.clone());
    TestApp { dir, state, app }
}

/// Inserts an enabled user (argon2id password; `""` = no password login) and a token for it.
/// Returns `(user_id, bearer_token)`.
pub(crate) async fn create_user(db: &SqlitePool, name: &str, password: &str, is_admin: bool) -> (i64, String) {
    let now = crate::common::now() as i64;
    let hash = if password.is_empty() {
        String::new()
    } else {
        crate::auth::hash_password(password).unwrap()
    };
    let id: i64 = sqlx::query_scalar(
        "insert into user(name, password_hash, is_admin, created_at, updated_at) values(?, ?, ?, ?, ?)
         returning id",
    )
    .bind(name)
    .bind(hash)
    .bind(is_admin)
    .bind(now)
    .bind(now)
    .fetch_one(db)
    .await
    .unwrap();
    let token = crate::auth::new_token();
    sqlx::query("insert into token(token_hash, user_id, created_at, last_used_at) values(?, ?, ?, ?)")
        .bind(crate::auth::token_hash(&token))
        .bind(id)
        .bind(now)
        .bind(now)
        .execute(db)
        .await
        .unwrap();
    (id, token)
}

/// Sends one request like the client does (`Content-Type: application/json`, optional Bearer token;
/// `body` is sent verbatim, `""` = empty), from TCP peer `127.0.0.1:50000` (`ClientIp`).
/// Returns `(status, Content-Type, body)`.
pub(crate) async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, String, Bytes) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let mut req = req.body(Body::from(body.to_owned())).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50000))));
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, ct, body)
}
