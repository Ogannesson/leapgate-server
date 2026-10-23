//! Native HTTP API (LEAPGATE.md §9): route table and the shared plumbing every handler uses.
//!
//! Rules every handler follows (§9.1): never answer 5xx; read bodies as `Bytes` and parse with
//! [`parse_json`] (axum's `Json` extractor answers 415/422 in plain text); JSON responses carry
//! `charset=utf-8`; invalid token or disabled account → 401.

pub(crate) mod ab;
pub(crate) mod account;
pub(crate) mod audit;
pub(crate) mod devauth;
pub(crate) mod device;
pub(crate) mod group;
mod listen;

use crate::state::AppState;
use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Request, State},
    http::{header, request::Parts, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use hbb_common::{
    futures::FutureExt as _,
    log,
    tokio::{self, net::TcpListener},
};
use serde::{de::DeserializeOwned, Serialize};
use serde_derive::Deserialize;
use std::{
    convert::Infallible,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    panic::AssertUnwindSafe,
};

const JSON: &str = "application/json; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";
const HTML: &str = "text/html; charset=utf-8";

// Request body limits (review C-9/C-14; over one → 413, `json_rejections`). Real bodies are small;
// the 2 MB default of `Bytes` let any request make a handler hold and parse 2 MB.
/// Every route not listed below: login, logout, currentUser, sysinfo (over 8 KB is a 403 anyway,
/// §9.3), heartbeat, single-tag writes, and the routes that ignore their body. Real ones are under 2 KB.
const BODY_LIMIT: usize = 16 * 1024;
/// Audit reports: real ones are under 4 KB, but over-long fields (a session note can be any length)
/// are truncated and stored (§9.3), so allow a few times the 4 KB field caps.
const AUDIT_BODY_LIMIT: usize = 64 * 1024;
/// `peer/add` and `peer/update`, one peer each (ab_model.dart sends them one by one): the largest
/// valid one is ~18 KB (data 8 KB + 64 tags of 64 bytes, quotes escaped + hash 1 KB + id).
const AB_PEER_BODY_LIMIT: usize = 64 * 1024;
/// `DELETE /api/ab/tag`: the selected names in one array, up to a book's 1000 tags of 64 bytes
/// (~131 KB if every byte is an escaped quote).
const AB_TAG_DELETE_BODY_LIMIT: usize = 256 * 1024;
/// `DELETE /api/ab/peer`: ab_model.dart puts every id to delete in one array, up to a book's 5000
/// ids of 253 bytes (~1.3 MB).
const AB_PEER_DELETE_BODY_LIMIT: usize = 2 * 1024 * 1024;
/// `POST /api/leapgate/v1/heartbeat`: sysinfo (8 KB at most) plus the relay probes (block 02: up to 32
/// relays × about 270 bytes).
const LEAPGATE_HEARTBEAT_BODY_LIMIT: usize = 32 * 1024;

pub(crate) fn router(state: AppState) -> axum::Router {
    let limit = DefaultBodyLimit::max;
    axum::Router::new()
        .route("/", get(index))
        // Account (account.rs)
        .route("/api/login-options", get(account::login_options))
        .route("/api/login", post(account::login))
        .route("/api/currentUser", post(account::current_user))
        .route("/api/logout", post(account::logout))
        // Group panel (group.rs)
        .route("/api/users", get(group::users))
        .route("/api/peers", get(group::peers))
        .route("/api/device-group/accessible", get(group::device_groups))
        // Device reports (device.rs, audit.rs)
        .route("/api/sysinfo", post(device::sysinfo))
        .route("/api/heartbeat", post(device::heartbeat))
        .route("/api/audit/conn", post(audit::conn).layer(limit(AUDIT_BODY_LIMIT)))
        .route("/api/audit/file", post(audit::file).layer(limit(AUDIT_BODY_LIMIT)))
        .route("/api/audit/alarm", post(audit::alarm).layer(limit(AUDIT_BODY_LIMIT)))
        // Leapgate clients' signed reports (devauth.rs)
        .route("/api/leapgate/v1/heartbeat", post(device::leapgate_heartbeat).layer(limit(LEAPGATE_HEARTBEAT_BODY_LIMIT)))
        .route("/api/leapgate/v1/audit/conn", post(audit::leapgate_conn).layer(limit(AUDIT_BODY_LIMIT)))
        .route("/api/leapgate/v1/audit/file", post(audit::leapgate_file).layer(limit(AUDIT_BODY_LIMIT)))
        .route("/api/leapgate/v1/audit/alarm", post(audit::leapgate_alarm).layer(limit(AUDIT_BODY_LIMIT)))
        // Address book (ab.rs)
        .route("/api/ab/personal", post(ab::personal))
        .route("/api/ab/settings", post(ab::settings))
        .route("/api/ab/shared/profiles", post(ab::shared_profiles))
        .route("/api/ab/peers", post(ab::peers))
        .route("/api/ab/tags/{guid}", post(ab::tags))
        .route("/api/ab/peer/add/{guid}", post(ab::peer_add).layer(limit(AB_PEER_BODY_LIMIT)))
        .route("/api/ab/peer/update/{guid}", put(ab::peer_update).layer(limit(AB_PEER_BODY_LIMIT)))
        .route("/api/ab/peer/{guid}", delete(ab::peer_delete).layer(limit(AB_PEER_DELETE_BODY_LIMIT)))
        .route("/api/ab/tag/add/{guid}", post(ab::tag_add))
        .route("/api/ab/tag/rename/{guid}", put(ab::tag_rename))
        .route("/api/ab/tag/update/{guid}", put(ab::tag_update))
        .route("/api/ab/tag/{guid}", delete(ab::tag_delete).layer(limit(AB_TAG_DELETE_BODY_LIMIT)))
        .fallback(not_found)
        // Outside the per-route layers above, so theirs is set last and wins.
        .layer(limit(BODY_LIMIT))
        .layer(middleware::from_fn(json_rejections))
        .layer(middleware::from_fn(catch_panic))
        .layer(middleware::from_fn(request_timeout))
        .with_state(state)
}

/// Serves the API with connection caps and timeouts (`listen`); spawned by `start_with_bind`.
pub(crate) async fn serve(listener: TcpListener, state: AppState) {
    listen::serve(listener, router(state)).await;
}

// ---- Responses ----

/// JSON with `charset=utf-8`.
pub(crate) fn json<T: Serialize + ?Sized>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => (status, [(header::CONTENT_TYPE, JSON)], body).into_response(),
        Err(err) => error(StatusCode::BAD_REQUEST, &format!("Failed to encode response: {err}")),
    }
}

/// 200 + JSON.
pub(crate) fn ok_json<T: Serialize + ?Sized>(value: &T) -> Response {
    json(StatusCode::OK, value)
}

/// 200 + empty body (address book writes, audit success).
pub(crate) fn ok_empty() -> Response {
    StatusCode::OK.into_response()
}

/// 200 + plain text, byte for byte (`SYSINFO_UPDATED`).
pub(crate) fn text(body: &'static str) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, TEXT)], body).into_response()
}

/// `{"error": msg}` with the given (non-5xx) status.
pub(crate) fn error(status: StatusCode, msg: &str) -> Response {
    json(status, &serde_json::json!({ "error": msg }))
}

/// 200 + `{"error": …}`: internal errors of the audit endpoints (the client retries, note 03 §5.1)
/// and of `/api/currentUser` (a 400 would make the client drop its token).
pub(crate) fn ok_error(msg: &str) -> Response {
    error(StatusCode::OK, msg)
}

/// Logs an internal failure and answers [`ok_error`].
pub(crate) fn ok_internal(err: impl Display) -> Response {
    log::error!("API internal error: {err}");
    ok_error("Server error")
}

/// Error side of [`ApiResult`]. `?` on `sqlx::Error` / `anyhow::Error` becomes 400 + `{"error"}`
/// (logged); audit handlers and `currentUser` answer [`ok_internal`] instead.
pub(crate) struct ApiError(pub Response);

pub(crate) type ApiResult = Result<Response, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, msg: &str) -> Self {
        Self(error(status, msg))
    }

    pub fn bad_request(msg: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }

    pub fn forbidden(msg: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }

    /// 401: the client drops its login state.
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Unauthorized")
    }

    /// Logged; 400 + `{"error"}`.
    pub fn internal(err: impl Display) -> Self {
        log::error!("API internal error: {err}");
        Self::bad_request("Server error")
    }

    /// Logged; 200 + `{"error"}` ([`ok_internal`]).
    pub fn ok_internal(err: impl Display) -> Self {
        Self(ok_internal(err))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.0
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        Self::internal(err)
    }
}

impl From<hbb_common::anyhow::Error> for ApiError {
    fn from(err: hbb_common::anyhow::Error) -> Self {
        Self::internal(format!("{err:#}"))
    }
}

// ---- Requests ----

/// Parses a `Bytes` body; failure → 400 + `{"error"}`.
pub(crate) fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|err| ApiError::bad_request(&format!("Invalid request body: {err}")))
}

/// Largest page: one `/api/ab/peers` page is read and its response built in memory whole (about
/// 18 MB for 1000 of the largest rows, LEAPGATE.md §12.1). The client always asks for 100 (`pageSize =
/// 100` in flutter/lib/models/ab_model.dart and group_model.dart, note 04 §1.1) and pages with its
/// own value (`while (current * pageSize < total)`): a cap below what any client asks would make it
/// stop early and silently drop entries, so this stays well above 100.
const MAX_PAGE_SIZE: i64 = 1000;

/// `current`, `pageSize`, `status` (the group panel's user filter) and `ab` (`/api/ab/peers`);
/// unknown parameters (`accessible`) are ignored.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct PageQuery {
    pub current: Option<String>,
    #[serde(rename = "pageSize")]
    pub page_size: Option<String>,
    pub status: Option<String>,
    pub ab: Option<String>,
}

impl PageQuery {
    /// `status` as a number; missing or not a number = no filter.
    pub fn status(&self) -> Option<i64> {
        self.status.as_deref().and_then(|s| s.trim().parse().ok())
    }

    /// `(offset, limit)` for SQL; `current` starts at 1, `pageSize` defaults to 100 and is capped at
    /// `MAX_PAGE_SIZE` (never below what the client asks: it always sends 100). Callers report the
    /// full `total`, and the client keeps paging by it.
    pub fn offset_limit(&self) -> (i64, i64) {
        let parse = |v: &Option<String>, default: i64| {
            v.as_deref()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .filter(|n| *n >= 1)
                .unwrap_or(default)
        };
        let current = parse(&self.current, 1);
        let size = parse(&self.page_size, 100).min(MAX_PAGE_SIZE);
        (current.saturating_sub(1).saturating_mul(size), size)
    }
}

/// The logged-in user behind `Authorization: Bearer <token>`. Missing/unknown token or disabled
/// account → 401. Each use updates `token.last_used_at`. A database error answers 200 + `{"error"}`:
/// every caller treats that as a plain failure, and `currentUser` must not log the user out on it.
#[derive(Debug, Clone)]
pub(crate) struct CurrentUser {
    pub id: i64,
    pub name: String,
    pub is_admin: bool,
    /// `token.token_hash` of the token used (logout deletes it, plus the user's other tokens with
    /// the same non-empty `device_id`).
    pub token_hash: String,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .unwrap_or_default();
        if token.is_empty() {
            return Err(ApiError::unauthorized());
        }
        let token_hash = crate::auth::token_hash(token);
        let row = sqlx::query_as::<_, (i64, String, bool, i64)>(
            "select u.id, u.name, u.is_admin, u.status from token t join user u on u.id = t.user_id
             where t.token_hash = ?",
        )
        .bind(&token_hash)
        .fetch_optional(&state.db)
        .await
        .map_err(ApiError::ok_internal)?;
        let Some((id, name, is_admin, status)) = row else {
            return Err(ApiError::unauthorized());
        };
        if status != 1 {
            return Err(ApiError::unauthorized());
        }
        sqlx::query("update token set last_used_at = ? where token_hash = ?")
            .bind(crate::common::now() as i64)
            .bind(&token_hash)
            .execute(&state.db)
            .await
            .map_err(ApiError::ok_internal)?;
        Ok(Self {
            id,
            name,
            is_admin,
            token_hash,
        })
    }
}

/// Client address (LEAPGATE.md §10): when the TCP peer is loopback (a reverse proxy on this machine),
/// `X-Real-IP`, else the last `X-Forwarded-For` entry; otherwise the TCP peer itself. Canonical
/// (`::ffff:a.b.c.d` → IPv4). `0.0.0.0` when the connection info is missing (only in tests).
pub(crate) struct ClientIp(pub IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(peer) = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_canonical())
        else {
            return Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        };
        if !peer.is_loopback() {
            return Ok(Self(peer));
        }
        let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
        let ip = header("x-real-ip")
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
            .or_else(|| {
                header("x-forwarded-for")
                    .and_then(|v| v.rsplit(',').next())
                    .and_then(|v| v.trim().parse::<IpAddr>().ok())
            })
            .unwrap_or(peer);
        Ok(Self(ip.to_canonical()))
    }
}

// ---- Fixed routes ----

/// `GET /`: the client's "manage in web console" menu opens this page (§9.4).
async fn index(State(st): State<AppState>) -> Response {
    let url = &st.cfg.api.source_url;
    let source = if url.is_empty() {
        "not configured (set <code>[api] source_url</code> in leapgate.toml)".to_owned()
    } else {
        let url = url.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        format!(r#"<a href="{url}">{url}</a>"#)
    };
    let body = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Leapgate</title></head>
<body style="font-family:system-ui,sans-serif;max-width:40em;margin:3em auto;padding:0 1em;line-height:1.6">
<h1>Leapgate</h1>
<p>This is a Leapgate server. There is no web console; manage it with the <code>leapgate-server</code> command line.</p>
<p>Source code (AGPL-3.0): {source}</p>
<p><a href="https://db-ip.com">IP Geolocation by DB-IP</a></p>
</body></html>
"#
    );
    (StatusCode::OK, [(header::CONTENT_TYPE, HTML)], body).into_response()
}

async fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "Not Found")
}

/// axum's own 405 (wrong method) and 413 (body over the route's limit, `BODY_LIMIT` and the
/// others) are plain text; §9.1 wants JSON errors. No handler of ours answers either status. The
/// audit endpoints keep the 413 too: the client gives up on a 4xx at once and retries a 200 with
/// an error, and resending the same body cannot help.
/// On the Leapgate endpoints the body is the Leapgate error shape (`devauth::leapgate_error`).
async fn json_rejections(req: Request<Body>, next: Next) -> Response {
    let leapgate = is_leapgate(req.uri().path());
    let resp = next.run(req).await;
    let (code, msg) = match resp.status() {
        StatusCode::METHOD_NOT_ALLOWED => ("method_not_allowed", "Method Not Allowed"),
        StatusCode::PAYLOAD_TOO_LARGE => ("too_large", "Request body too large"),
        _ => return resp,
    };
    let mut json = if leapgate { devauth::leapgate_error(resp.status(), code, msg) } else { error(resp.status(), msg) };
    if let Some(allow) = resp.headers().get(header::ALLOW) {
        json.headers_mut().insert(header::ALLOW, allow.clone());
    }
    json
}

/// Whether an internal error on `path` answers 200 + `{"error"}` (§9.1 item 1): the audit
/// endpoints (the client retries) and `/api/currentUser` (a 400 would log the user out); the
/// others answer 400 + `{"error"}`.
fn internal_error_is_200(path: &str) -> bool {
    path.starts_with("/api/audit/") || path == "/api/currentUser"
}

/// The Leapgate clients' signed endpoints (`devauth`), which may answer 5xx.
fn is_leapgate(path: &str) -> bool {
    path.starts_with(devauth::PREFIX)
}

/// The device reports, which the client sends only from its Rust side (12-second HTTP timeout):
/// they get `listen::REPORT_TIMEOUT` instead of `listen::REQUEST_TIMEOUT`. The Leapgate reports too.
fn is_report(path: &str) -> bool {
    matches!(path, "/api/heartbeat" | "/api/sysinfo" | "/api/sysinfo_ver")
        || path.starts_with("/api/audit/")
        || is_leapgate(path)
}

/// A request not answered within its timeout (`is_report`; receiving its body included) gets an
/// internal-error answer (`timeout_response`).
async fn request_timeout(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let limit = if is_report(&path) { listen::REPORT_TIMEOUT } else { listen::REQUEST_TIMEOUT };
    match tokio::time::timeout(limit, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => timeout_response(&path),
    }
}

/// 503 on the Leapgate endpoints, else 200 or 400 + `{"error"}` (`internal_error_is_200`).
fn timeout_response(path: &str) -> Response {
    if is_leapgate(path) {
        // Not logged, as on the other endpoints.
        devauth::leapgate_error(StatusCode::SERVICE_UNAVAILABLE, "internal", "Request timeout")
    } else if internal_error_is_200(path) {
        ok_error("Request timeout")
    } else {
        error(StatusCode::BAD_REQUEST, "Request timeout")
    }
}

/// A panicking handler answers like any other internal error (`internal_error_is_200`; 503 on the
/// Leapgate endpoints) instead of dropping the connection (needs `panic = "unwind"`, the default; the
/// release profile no longer aborts).
async fn catch_panic(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    match AssertUnwindSafe(next.run(req)).catch_unwind().await {
        Ok(resp) => resp,
        // `leapgate_internal`: logged at most once a minute.
        Err(_) if is_leapgate(&path) => devauth::leapgate_internal("handler panicked"),
        Err(_) if internal_error_is_200(&path) => ok_internal("handler panicked"),
        Err(_) => ApiError::internal("handler panicked").0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{self, send};
    use hbb_common::tokio;

    #[tokio::test]
    async fn index_and_not_found() {
        let t = testutil::app().await;
        let (status, ct, body) = send(&t.app, "GET", "/", None, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, HTML);
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Leapgate") && body.contains("https://db-ip.com") && body.contains("source_url"));

        let (status, ct, body) = send(&t.app, "GET", "/nope", None, "").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(ct, JSON);
        assert_eq!(&body[..], br#"{"error":"Not Found"}"#);
    }

    #[tokio::test]
    async fn wrong_method_and_big_body_are_json() {
        let t = testutil::app().await;
        let req = axum::http::Request::builder().method("GET").uri("/api/login").body(Body::empty()).unwrap();
        let resp = tower::ServiceExt::oneshot(t.app.clone(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], JSON);
        assert!(resp.headers().contains_key(header::ALLOW));
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"Method Not Allowed"}"#);

        let big = "x".repeat(3 << 20);
        for path in ["/api/login", "/api/heartbeat", "/api/audit/conn"] {
            let (status, ct, body) = send(&t.app, "POST", path, None, &big).await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
            assert_eq!(ct, JSON, "{path}");
            assert_eq!(&body[..], br#"{"error":"Request body too large"}"#, "{path}");
        }
        // Still within the limit: the handler's own answer.
        let (status, ct, _) = send(&t.app, "POST", "/api/login", None, &"x".repeat(BODY_LIMIT)).await;
        assert_eq!((status, ct.as_str()), (StatusCode::BAD_REQUEST, JSON));
    }

    #[tokio::test]
    async fn body_limits_per_route() {
        let t = testutil::app().await;
        let (_, token) = testutil::create_user(&t.state.db, "u", "pw", false).await;
        let guid = String::from_utf8(send(&t.app, "POST", "/api/ab/personal", Some(&token), "").await.2.to_vec())
            .unwrap();
        let guid = serde_json::from_str::<serde_json::Value>(&guid).unwrap()["guid"].as_str().unwrap().to_owned();
        let routes: &[(&str, String, usize)] = &[
            ("POST", "/api/login".into(), BODY_LIMIT),
            ("POST", "/api/currentUser".into(), BODY_LIMIT),
            ("POST", "/api/sysinfo".into(), BODY_LIMIT),
            ("POST", "/api/heartbeat".into(), BODY_LIMIT),
            ("POST", "/api/audit/conn".into(), AUDIT_BODY_LIMIT),
            ("POST", "/api/audit/file".into(), AUDIT_BODY_LIMIT),
            ("POST", "/api/audit/alarm".into(), AUDIT_BODY_LIMIT),
            ("POST", format!("/api/ab/peer/add/{guid}"), AB_PEER_BODY_LIMIT),
            ("PUT", format!("/api/ab/peer/update/{guid}"), AB_PEER_BODY_LIMIT),
            ("DELETE", format!("/api/ab/peer/{guid}"), AB_PEER_DELETE_BODY_LIMIT),
            ("POST", format!("/api/ab/tag/add/{guid}"), BODY_LIMIT),
            ("PUT", format!("/api/ab/tag/rename/{guid}"), BODY_LIMIT),
            ("PUT", format!("/api/ab/tag/update/{guid}"), BODY_LIMIT),
            ("DELETE", format!("/api/ab/tag/{guid}"), AB_TAG_DELETE_BODY_LIMIT),
            // Last: at the limit it logs the token out.
            ("POST", "/api/logout".into(), BODY_LIMIT),
        ];
        // A real batch delete of a full book's longest ids fits.
        let ids: Vec<String> = (0..5000).map(|i| format!("{i:0>253}")).collect();
        let (status, _, body) =
            send(&t.app, "DELETE", &format!("/api/ab/peer/{guid}"), Some(&token), &serde_json::to_string(&ids).unwrap())
                .await;
        assert_eq!((status, &body[..]), (StatusCode::OK, &b""[..]));
        for (method, path, max) in routes {
            let (status, ct, body) = send(&t.app, method, path, Some(&token), &" ".repeat(max + 1)).await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{method} {path} over {max}");
            assert_eq!(ct, JSON, "{method} {path}");
            assert_eq!(&body[..], br#"{"error":"Request body too large"}"#, "{method} {path}");
            // At the limit: whatever the handler says about the bad JSON, never 413.
            let (status, _, _) = send(&t.app, method, path, Some(&token), &" ".repeat(*max)).await;
            assert_ne!(status, StatusCode::PAYLOAD_TOO_LARGE, "{method} {path} at {max}");
        }
    }

    #[tokio::test]
    async fn current_user_extractor() {
        let t = testutil::app().await;
        let app = axum::Router::new()
            .route("/me", get(|u: CurrentUser| async move { ok_json(&(u.id, u.name, u.is_admin)) }))
            .with_state(t.state.clone());
        let (uid, token) = testutil::create_user(&t.state.db, "12345", "pw", true).await;

        let (status, ct, body) = send(&app, "GET", "/me", Some(&token), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, JSON);
        // Numeric-looking names stay strings.
        assert_eq!(body, serde_json::to_vec(&(uid, "12345", true)).unwrap());
        let used: i64 = sqlx::query_scalar("select last_used_at from token where user_id = ?")
            .bind(uid)
            .fetch_one(&t.state.db)
            .await
            .unwrap();
        assert!(used > 0);

        for bad in [None, Some(""), Some("wrong")] {
            let (status, ct, body) = send(&app, "GET", "/me", bad, "").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(ct, JSON);
            assert_eq!(&body[..], br#"{"error":"Unauthorized"}"#);
        }

        sqlx::query("update user set status = 0 where id = ?")
            .bind(uid)
            .execute(&t.state.db)
            .await
            .unwrap();
        let (status, _, _) = send(&app, "GET", "/me", Some(&token), "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn panics_do_not_become_5xx() {
        async fn boom() -> Response {
            panic!("boom")
        }
        let app = axum::Router::new()
            .route("/x", get(boom))
            .route("/api/audit/x", get(boom))
            .route("/api/currentUser", post(boom))
            .layer(middleware::from_fn(catch_panic));
        let (status, ct, body) = send(&app, "GET", "/x", None, "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(ct, JSON);
        assert_eq!(&body[..], br#"{"error":"Server error"}"#);
        // A 400 from currentUser would log the user out (§9.1 item 1).
        for (method, path) in [("GET", "/api/audit/x"), ("POST", "/api/currentUser")] {
            let (status, ct, body) = send(&app, method, path, None, "").await;
            assert_eq!((status, ct.as_str()), (StatusCode::OK, JSON), "{path}");
            assert_eq!(&body[..], br#"{"error":"Server error"}"#, "{path}");
        }
    }

    /// Phase 3 contract 01 §3.9: on the Leapgate endpoints axum's 413 and 405 carry the Leapgate error
    /// shape, a timeout or panic is a 503, an unknown path a 404; the compatibility answers are as
    /// before (`wrong_method_and_big_body_are_json`, `panics_do_not_become_5xx`).
    #[tokio::test]
    async fn leapgate_endpoints_errors() {
        let t = testutil::app().await;
        let dev = testutil::Device::new("unknown1");
        let leapgate_json = |body: &[u8]| serde_json::from_slice::<serde_json::Value>(body).unwrap();

        // Over the heartbeat's 32 KB (the header must parse for the body to be read at all).
        let big = vec![b' '; LEAPGATE_HEARTBEAT_BODY_LIMIT + 1];
        let (auth, _) = dev.auth("heartbeat", crate::common::now() as i64, &big);
        let (status, headers, body) = testutil::send_leapgate(&t.app, "/api/leapgate/v1/heartbeat", Some(&auth), &big).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(headers[header::CONTENT_TYPE], JSON);
        assert_eq!(leapgate_json(&body)["error"], "too_large");
        assert!(leapgate_json(&body)["message"].is_string());
        // Within it: read, and the device is unknown.
        let fits = vec![b' '; LEAPGATE_HEARTBEAT_BODY_LIMIT];
        let (auth, _) = dev.auth("heartbeat", crate::common::now() as i64, &fits);
        let (status, _, body) = testutil::send_leapgate(&t.app, "/api/leapgate/v1/heartbeat", Some(&auth), &fits).await;
        assert_eq!((status, &leapgate_json(&body)["error"]), (StatusCode::UNAUTHORIZED, &serde_json::json!("unknown_device")));
        // The audits keep 64 KB.
        let big = vec![b' '; AUDIT_BODY_LIMIT + 1];
        let (auth, _) = dev.auth("audit/conn", crate::common::now() as i64, &big);
        let (status, _, body) = testutil::send_leapgate(&t.app, "/api/leapgate/v1/audit/conn", Some(&auth), &big).await;
        assert_eq!((status, &leapgate_json(&body)["error"]), (StatusCode::PAYLOAD_TOO_LARGE, &serde_json::json!("too_large")));

        let req = axum::http::Request::builder().method("GET").uri("/api/leapgate/v1/heartbeat").body(Body::empty()).unwrap();
        let resp = tower::ServiceExt::oneshot(t.app.clone(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(resp.headers().contains_key(header::ALLOW));
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"method_not_allowed","message":"Method Not Allowed"}"#);

        let (status, _, _) = testutil::send_leapgate(&t.app, "/api/leapgate/v1/nope", None, b"{}").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        async fn boom() -> Response {
            panic!("boom")
        }
        let app = axum::Router::new().route("/api/leapgate/v1/x", get(boom)).layer(middleware::from_fn(catch_panic));
        let (status, ct, body) = send(&app, "GET", "/api/leapgate/v1/x", None, "").await;
        assert_eq!((status, ct.as_str()), (StatusCode::SERVICE_UNAVAILABLE, JSON));
        assert_eq!(&body[..], br#"{"error":"internal","message":"Server error"}"#);

        // Timeouts: 503 on the Leapgate endpoints (which get the reports' 10 s), as before elsewhere.
        assert!(is_report("/api/leapgate/v1/heartbeat") && is_report("/api/leapgate/v1/audit/file"));
        let cases = [
            ("/api/leapgate/v1/heartbeat", StatusCode::SERVICE_UNAVAILABLE, &br#"{"error":"internal","message":"Request timeout"}"#[..]),
            ("/api/audit/conn", StatusCode::OK, br#"{"error":"Request timeout"}"#),
            ("/api/currentUser", StatusCode::OK, br#"{"error":"Request timeout"}"#),
            ("/api/heartbeat", StatusCode::BAD_REQUEST, br#"{"error":"Request timeout"}"#),
        ];
        for (path, status, want) in cases {
            let resp = timeout_response(path);
            assert_eq!(resp.status(), status, "{path}");
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            assert_eq!(&body[..], want, "{path}");
        }
    }

    #[test]
    fn page_query() {
        let q = |c: Option<&str>, s: Option<&str>| PageQuery {
            current: c.map(Into::into),
            page_size: s.map(Into::into),
            status: None,
            ab: None,
        };
        assert_eq!(q(None, None).offset_limit(), (0, 100));
        assert_eq!(q(Some("3"), Some("100")).offset_limit(), (200, 100));
        assert_eq!(q(Some("0"), Some("x")).offset_limit(), (0, 100));
        assert_eq!(q(Some("2"), Some("500")).offset_limit(), (500, 500));
        assert_eq!(q(Some("1"), Some("1000")).offset_limit(), (0, 1000));
        assert_eq!(q(Some("3"), Some("1001")).offset_limit(), (2000, 1000));
        assert_eq!(q(None, Some("99999999999")).offset_limit(), (0, 1000));
    }

    #[test]
    fn client_ip() {
        let ip = |headers: &[(&str, &str)], peer: Option<&str>| {
            let mut req = axum::http::Request::builder().uri("/");
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let mut req = req.body(()).unwrap();
            if let Some(p) = peer {
                req.extensions_mut().insert(ConnectInfo(p.parse::<SocketAddr>().unwrap()));
            }
            let (mut parts, _) = req.into_parts();
            let fut = ClientIp::from_request_parts(&mut parts, &());
            let Ok(ClientIp(ip)) = hbb_common::futures::executor::block_on(fut);
            ip.to_string()
        };
        // Behind a local reverse proxy.
        assert_eq!(ip(&[("x-real-ip", "1.2.3.4")], Some("[::1]:5")), "1.2.3.4");
        assert_eq!(ip(&[("x-forwarded-for", "10.0.0.1, 5.6.7.8")], Some("127.0.0.1:5")), "5.6.7.8");
        assert_eq!(ip(&[("x-real-ip", "::ffff:1.2.3.4")], Some("[::ffff:127.0.0.1]:5")), "1.2.3.4");
        assert_eq!(ip(&[], Some("127.0.0.1:5")), "127.0.0.1");
        // Direct connections ignore the headers.
        assert_eq!(ip(&[("x-real-ip", "1.2.3.4")], Some("[::ffff:9.9.9.9]:1")), "9.9.9.9");
        assert_eq!(ip(&[], None), "0.0.0.0");
    }
}
