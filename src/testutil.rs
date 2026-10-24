//! Test helpers for HTTP contract tests (`tower::ServiceExt::oneshot`) and database tests.

use crate::{config::Config, state::AppState};
use axum::{
    body::{Body, Bytes},
    extract::ConnectInfo,
    http::{header, HeaderMap, Request, StatusCode},
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
    let pool = crate::database::open(path.to_str().unwrap(), true).await.unwrap();
    (dir, pool)
}

/// Full `AppState` (skeleton-level Router/ConnTracker, default `Config`, a fresh rendezvous private
/// key, temporary secret key) and the router.
pub(crate) async fn app() -> TestApp {
    let (dir, db) = pool().await;
    let (_, sk) = sodiumoxide::crypto::sign::gen_keypair();
    let key_file = dir.path().join(crate::crypto::SECRET_KEY_FILE);
    let state = AppState::new(db, Config::default(), Some(sk), &key_file).await.unwrap();
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

/// A Leapgate device: its id and signing key pair.
pub(crate) struct Device {
    pub id: String,
    pub pk: sodiumoxide::crypto::sign::PublicKey,
    pub sk: sodiumoxide::crypto::sign::SecretKey,
}

/// A signed Leapgate answer and the signature of the request it answers.
pub(crate) struct LeapgateResp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub sig: [u8; 64],
}

impl LeapgateResp {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

impl Device {
    /// A fresh key pair, not registered anywhere.
    pub fn new(id: &str) -> Self {
        let (pk, sk) = sodiumoxide::crypto::sign::gen_keypair();
        Self { id: id.to_owned(), pk, sk }
    }

    /// The `Leapgate-Device-Auth` header value and the signature, for `POST /api/leapgate/v1/<endpoint>`.
    pub fn auth(&self, endpoint: &str, t: i64, body: &[u8]) -> (String, [u8; 64]) {
        use crate::api::devauth::{b64url, request_message};
        let message = request_message("POST", endpoint, &self.id, t, body);
        let sig = sodiumoxide::crypto::sign::sign_detached(&message, &self.sk).to_bytes();
        (format!("v1 id={}, t={t}, s={}", b64url(self.id.as_bytes()), b64url(&sig)), sig)
    }

    /// Signs (now) and posts `body` to `/api/leapgate/v1/<endpoint>`.
    pub async fn post(&self, app: &axum::Router, endpoint: &str, body: &[u8]) -> LeapgateResp {
        let (auth, sig) = self.auth(endpoint, crate::common::now() as i64, body);
        let (status, headers, body) = send_leapgate(app, &format!("/api/leapgate/v1/{endpoint}"), Some(&auth), body).await;
        LeapgateResp { status, headers, body, sig }
    }
}

/// A device registered with hbbs (a `peer` row with its public key and `uuid`).
pub(crate) async fn leapgate_device(state: &AppState, id: &str, uuid: &[u8]) -> Device {
    let dev = Device::new(id);
    crate::database::Database::new(state.db.clone())
        .insert_peer(id, uuid, &dev.pk.0, "{}")
        .await
        .unwrap();
    dev
}

/// Posts like the Leapgate client (`Content-Type: application/json`, optional `Leapgate-Device-Auth`),
/// from TCP peer `127.0.0.1:50000`. Returns `(status, headers, body)`.
pub(crate) async fn send_leapgate(
    app: &axum::Router,
    uri: &str,
    auth: Option<&str>,
    body: &[u8],
) -> (StatusCode, HeaderMap, Bytes) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(auth) = auth {
        req = req.header("Leapgate-Device-Auth", auth);
    }
    let mut req = req.body(Body::from(body.to_vec())).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50000))));
    let resp = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, body)
}

/// Whether `headers` carry a `Leapgate-Server-Sig` over `body` for the request signed `req_sig`, by
/// the state's rendezvous key.
pub(crate) fn verify_server_sig(state: &AppState, req_sig: &[u8; 64], headers: &HeaderMap, body: &[u8]) -> bool {
    use sodiumoxide::crypto::sign;
    let Some(sig) = headers.get(crate::api::devauth::SIG_HEADER) else {
        return false;
    };
    let sig = base64::decode_config(sig.to_str().unwrap(), base64::URL_SAFE_NO_PAD).unwrap();
    let pk = state.sk.as_ref().unwrap().public_key();
    let message = crate::api::devauth::response_message(req_sig, body);
    sign::verify_detached(&sign::Signature::from_bytes(&sig).unwrap(), &message, &pk)
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

/// Bytes of a hex string, for vectors shared with the client's tests.
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "{s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
