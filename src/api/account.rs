//! Account endpoints (PORTA.md §9.2, §11; note 03 §2).

use super::{device::uuid_matches, ok_json, parse_json, ApiError, ApiResult, CurrentUser};
use crate::{
    auth::{self, PasswordCheck},
    state::AppState,
};
use axum::{body::Bytes, extract::State, http::StatusCode};
use hbb_common::{log, tokio};
use serde_derive::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Failed logins per user name: 5 within 15 minutes lock the name for 15 minutes (§11).
const FAIL_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_FAILS: usize = 5;

#[derive(Default)]
struct FailState {
    /// Failures within the last `FAIL_WINDOW`.
    fails: Vec<Instant>,
    locked_until: Option<Instant>,
}

lazy_static::lazy_static! {
    static ref LOGIN_FAILS: Mutex<HashMap<String, FailState>> = Default::default();
}

fn is_locked(name: &str) -> bool {
    let map = LOGIN_FAILS.lock().unwrap();
    map.get(name)
        .and_then(|s| s.locked_until)
        .is_some_and(|t| t > Instant::now())
}

fn record_failure(name: &str) {
    let now = Instant::now();
    let mut map = LOGIN_FAILS.lock().unwrap();
    // Forget names that neither are locked nor failed recently, so random names do not pile up.
    map.retain(|_, s| {
        s.locked_until.is_some_and(|t| t > now) || s.fails.last().is_some_and(|t| now - *t < FAIL_WINDOW)
    });
    let s = map.entry(name.to_owned()).or_default();
    s.fails.retain(|t| now - *t < FAIL_WINDOW);
    s.fails.push(now);
    if s.fails.len() >= MAX_FAILS {
        s.fails.clear();
        s.locked_until = Some(now + FAIL_WINDOW);
    }
}

fn clear_failures(name: &str) {
    LOGIN_FAILS.lock().unwrap().remove(name);
}

/// The user object of login, currentUser and `/api/users` (note 03 §2.5): `name` non-empty,
/// `status`/`is_admin`/`info` never null.
#[derive(Debug, Serialize)]
pub(crate) struct UserPayload {
    pub name: String,
    pub display_name: String,
    pub avatar: &'static str,
    pub email: String,
    pub note: String,
    pub status: i64,
    pub is_admin: bool,
    /// Serializes as `{}`; the client's Rust side requires an object.
    pub info: EmptyObject,
}

#[derive(Debug, Serialize)]
pub(crate) struct EmptyObject {}

/// Columns of `user` that make up a [`UserPayload`], in the order [`UserPayload::from_row`] expects.
pub(crate) const USER_COLUMNS: &str = "name, display_name, email, note, status, is_admin";

pub(crate) type UserRow = (String, String, String, String, i64, bool);

impl UserPayload {
    pub fn from_row((name, display_name, email, note, status, is_admin): UserRow) -> Self {
        Self {
            name,
            display_name,
            avatar: "",
            email,
            note,
            status,
            is_admin,
            info: EmptyObject {},
        }
    }
}

async fn load_user(db: &SqlitePool, id: i64) -> sqlx::Result<Option<UserPayload>> {
    let row = sqlx::query_as::<_, UserRow>(&format!("select {USER_COLUMNS} from user where id = ?"))
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(UserPayload::from_row))
}

/// `GET /api/login-options` (also answers HEAD): `[]`.
pub(crate) async fn login_options() -> ApiResult {
    Ok(ok_json::<[&str]>(&[]))
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    uuid: String,
    #[serde(rename = "type")]
    typ: Option<String>,
}

#[derive(Serialize)]
struct LoginResponse {
    #[serde(rename = "type")]
    typ: &'static str,
    access_token: String,
    user: UserPayload,
}

/// `POST /api/login`, `type=account` only.
pub(crate) async fn login(State(state): State<AppState>, body: Bytes) -> ApiResult {
    let req: LoginRequest = parse_json(&body)?;
    if req.typ.as_deref().is_some_and(|t| t != "account") {
        return Err(ApiError::bad_request("Unsupported login type"));
    }
    if is_locked(&req.username) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed attempts, try again later",
        ));
    }
    let row = sqlx::query_as::<_, (i64, String, i64)>(
        "select id, password_hash, status from user where name = ?",
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await?;
    let (uid, stored, status) = row.unwrap_or_default();
    // argon2 takes tens of milliseconds of CPU: keep it off the async workers.
    let password = req.password.clone();
    let (check, upgraded) = tokio::task::spawn_blocking(move || {
        let check = auth::verify_password(&password, &stored);
        let upgraded = (check == PasswordCheck::OkNeedsUpgrade).then(|| auth::hash_password(&password));
        (check, upgraded)
    })
    .await
    .map_err(ApiError::internal)?;
    if check == PasswordCheck::Mismatch {
        record_failure(&req.username);
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Wrong credentials"));
    }
    clear_failures(&req.username);
    if status != 1 {
        return Err(ApiError::forbidden("Account disabled"));
    }
    let now = crate::common::now() as i64;
    if let Some(hash) = upgraded {
        sqlx::query("update user set password_hash = ?, updated_at = ? where id = ?")
            .bind(hash?)
            .bind(now)
            .bind(uid)
            .execute(&state.db)
            .await?;
        log::info!("Upgraded the password hash of user {} to argon2id", req.username);
    }

    let token = auth::new_token();
    sqlx::query(
        "insert into token(token_hash, user_id, device_id, device_uuid, created_at, last_used_at)
         values(?, ?, ?, ?, ?, ?)",
    )
    .bind(auth::token_hash(&token))
    .bind(uid)
    .bind(&req.id)
    .bind(&req.uuid)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    if !req.id.is_empty() && uuid_matches(&state.db, &req.id, Some(&req.uuid)).await? {
        sqlx::query(
            "insert into device(id, uuid, user_id, first_seen_at, last_seen_at) values(?, ?, ?, ?, ?)
             on conflict(id) do update set user_id = excluded.user_id",
        )
        .bind(&req.id)
        .bind(&req.uuid)
        .bind(uid)
        .bind(now)
        .bind(now)
        .execute(&state.db)
        .await?;
    }

    let Some(user) = load_user(&state.db, uid).await? else {
        return Err(ApiError::unauthorized());
    };
    Ok(ok_json(&LoginResponse {
        typ: "access_token",
        access_token: token,
        user,
    }))
}

/// `POST /api/currentUser`: ignores the body; internal errors answer 200 + `{"error"}` (`ApiError::ok_internal`).
pub(crate) async fn current_user(
    State(state): State<AppState>,
    user: CurrentUser,
    _body: Bytes,
) -> ApiResult {
    match load_user(&state.db, user.id).await {
        Ok(Some(payload)) => Ok(ok_json(&payload)),
        Ok(None) => Err(ApiError::unauthorized()),
        Err(err) => Err(ApiError::ok_internal(err)),
    }
}

/// `POST /api/logout`: deletes only the token used.
pub(crate) async fn logout(
    State(state): State<AppState>,
    user: CurrentUser,
    _body: Bytes,
) -> ApiResult {
    let device_id: Option<String> =
        sqlx::query_scalar("delete from token where token_hash = ? returning device_id")
            .bind(&user.token_hash)
            .fetch_optional(&state.db)
            .await?;
    if let Some(device_id) = device_id.filter(|d| !d.is_empty()) {
        sqlx::query("update device set user_id = null where id = ? and user_id = ?")
            .bind(device_id)
            .bind(user.id)
            .execute(&state.db)
            .await?;
    }
    Ok(ok_json(&serde_json::json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{self, send};
    use md5::{Digest as _, Md5};
    use serde_json::{json, Value};

    const JSON: &str = "application/json; charset=utf-8";

    fn login_body(name: &str, password: &str, id: &str, uuid: &str) -> String {
        json!({
            "username": name, "password": password, "id": id, "uuid": uuid, "autoLogin": true,
            "type": "account", "deviceInfo": {"os": "linux", "type": "client", "name": "host"}
        })
        .to_string()
    }

    async fn login_as(app: &axum::Router, name: &str, password: &str, id: &str, uuid: &str) -> (StatusCode, Value) {
        let (status, ct, body) = send(app, "POST", "/api/login", None, &login_body(name, password, id, uuid)).await;
        assert_eq!(ct, JSON);
        (status, serde_json::from_slice(&body).unwrap())
    }

    async fn device_owner(db: &SqlitePool, id: &str) -> Option<i64> {
        sqlx::query_scalar("select user_id from device where id = ?")
            .bind(id)
            .fetch_optional(db)
            .await
            .unwrap()
            .flatten()
    }

    fn assert_user_payload(v: &Value, name: &str, is_admin: bool) {
        assert_eq!(
            v,
            &json!({"name": name, "display_name": "", "avatar": "", "email": "", "note": "",
                    "status": 1, "is_admin": is_admin, "info": {}})
        );
    }

    #[tokio::test]
    async fn login_options_empty() {
        let t = testutil::app().await;
        let (status, ct, body) = send(&t.app, "GET", "/api/login-options", None, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, JSON);
        assert_eq!(&body[..], b"[]");
        let (status, _, _) = send(&t.app, "HEAD", "/api/login-options", None, "").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn login_success_records_token_and_device() {
        let t = testutil::app().await;
        let db = &t.state.db;
        // A numeric-looking name must come back as a string.
        let (uid, _) = testutil::create_user(db, "10086", "pw", true).await;
        let (status, v) = login_as(&t.app, "10086", "pw", "123456789", "dXVpZA==").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["type"], "access_token");
        let token = v["access_token"].as_str().unwrap().to_owned();
        assert!(!token.is_empty());
        assert_user_payload(&v["user"], "10086", true);

        let row: (i64, String, String) =
            sqlx::query_as("select user_id, device_id, device_uuid from token where token_hash = ?")
                .bind(auth::token_hash(&token))
                .fetch_one(db)
                .await
                .unwrap();
        assert_eq!(row, (uid, "123456789".to_owned(), "dXVpZA==".to_owned()));
        // Not in hbbs' peer table: the device is bound.
        assert_eq!(device_owner(db, "123456789").await, Some(uid));

        let (status, _, body) = send(&t.app, "POST", "/api/currentUser", Some(&token), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_user_payload(&serde_json::from_slice(&body).unwrap(), "10086", true);
    }

    #[tokio::test]
    async fn login_failures() {
        let t = testutil::app().await;
        let db = &t.state.db;
        testutil::create_user(db, "lf-bob", "pw", false).await;
        testutil::create_user(db, "lf-nopw", "", false).await;
        for (name, pw) in [("lf-bob", "wrong"), ("lf-nobody", "pw"), ("lf-nopw", ""), ("LF-BOB", "pw")] {
            let (status, v) = login_as(&t.app, name, pw, "1", "").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}");
            assert_eq!(v, json!({"error": "Wrong credentials"}));
        }
        for body in ["", "not json", r#"{"username":1}"#] {
            let (status, ct, body) = send(&t.app, "POST", "/api/login", None, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(ct, JSON);
            assert!(serde_json::from_slice::<Value>(&body).unwrap()["error"].is_string());
        }
        let body = json!({"username": "lf-bob", "password": "pw", "type": "email_code"}).to_string();
        let (status, _, _) = send(&t.app, "POST", "/api/login", None, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Only the two tokens `create_user` made.
        let n: i64 = sqlx::query_scalar("select count(*) from token").fetch_one(db).await.unwrap();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn login_disabled_account() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, token) = testutil::create_user(db, "ld-carol", "pw", false).await;
        sqlx::query("update user set status = 0 where id = ?").bind(uid).execute(db).await.unwrap();
        let (status, v) = login_as(&t.app, "ld-carol", "pw", "1", "").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(v["error"].is_string());
        for path in ["/api/currentUser", "/api/logout"] {
            let (status, _, body) = send(&t.app, "POST", path, Some(&token), "{}").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(&body[..], br#"{"error":"Unauthorized"}"#);
        }
    }

    #[tokio::test]
    async fn login_rate_limited_per_name() {
        let t = testutil::app().await;
        testutil::create_user(&t.state.db, "rl-dave", "pw", false).await;
        testutil::create_user(&t.state.db, "rl-erin", "pw", false).await;
        for _ in 0..MAX_FAILS {
            let (status, _) = login_as(&t.app, "rl-dave", "bad", "", "").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        // Locked now, even with the right password.
        let (status, v) = login_as(&t.app, "rl-dave", "pw", "", "").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(v["error"].is_string());
        // Other names are not affected.
        let (status, _) = login_as(&t.app, "rl-erin", "pw", "", "").await;
        assert_eq!(status, StatusCode::OK);
        // A success clears the count.
        for _ in 0..MAX_FAILS - 1 {
            login_as(&t.app, "rl-erin", "bad", "", "").await;
        }
        let (status, _) = login_as(&t.app, "rl-erin", "pw", "", "").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = login_as(&t.app, "rl-erin", "bad", "", "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = login_as(&t.app, "rl-erin", "pw", "", "").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn legacy_hashes_upgraded() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let md5 = Md5::digest(b"pw2rustdesk-api").iter().map(|b| format!("{b:02x}")).collect::<String>();
        for (name, hash) in [
            ("lh-bcrypt", bcrypt::hash("pw2", 4).unwrap()),
            ("lh-md5", format!("md5:{md5}")),
        ] {
            let (uid, _) = testutil::create_user(db, name, "", false).await;
            sqlx::query("update user set password_hash = ? where id = ?")
                .bind(&hash)
                .bind(uid)
                .execute(db)
                .await
                .unwrap();
            let (status, _) = login_as(&t.app, name, "pw2", "", "").await;
            assert_eq!(status, StatusCode::OK, "{name}");
            let stored: String = sqlx::query_scalar("select password_hash from user where id = ?")
                .bind(uid)
                .fetch_one(db)
                .await
                .unwrap();
            assert!(stored.starts_with("$argon2id$"), "{name}");
            assert_eq!(auth::verify_password("pw2", &stored), PasswordCheck::Ok);
            let (status, _) = login_as(&t.app, name, "pw2", "", "").await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn weak_check_guards_device_binding() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, _) = testutil::create_user(db, "wc-frank", "pw", false).await;
        t.state.pm.db.insert_peer("111", b"real-uuid", b"pk", "{}").await.unwrap();
        let good = base64::encode(b"real-uuid");
        // Wrong or missing uuid: login works, the device stays unbound.
        for uuid in [base64::encode(b"other"), String::new(), "%%%".to_owned()] {
            let (status, _) = login_as(&t.app, "wc-frank", "pw", "111", &uuid).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(device_owner(db, "111").await, None);
        }
        // Someone else's binding is not taken over by a mismatching login either.
        let (gid, _) = testutil::create_user(db, "wc-grace", "pw", false).await;
        let (status, _) = login_as(&t.app, "wc-grace", "pw", "111", &good).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(device_owner(db, "111").await, Some(gid));
        login_as(&t.app, "wc-frank", "pw", "111", "bad").await;
        assert_eq!(device_owner(db, "111").await, Some(gid));
        let (status, _) = login_as(&t.app, "wc-frank", "pw", "111", &good).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(device_owner(db, "111").await, Some(uid));
    }

    #[tokio::test]
    async fn current_user_ignores_body() {
        let t = testutil::app().await;
        let (_, token) = testutil::create_user(&t.state.db, "cu-heidi", "pw", false).await;
        for body in ["", "garbage", r#"{"id":1}"#, r#"{"id":"1","uuid":"x"}"#] {
            let (status, ct, resp) = send(&t.app, "POST", "/api/currentUser", Some(&token), body).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(ct, JSON);
            assert_user_payload(&serde_json::from_slice(&resp).unwrap(), "cu-heidi", false);
        }
        for bad in [None, Some("nope")] {
            let (status, _, _) = send(&t.app, "POST", "/api/currentUser", bad, "").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn current_user_internal_error_is_200() {
        let t = testutil::app().await;
        let (_, token) = testutil::create_user(&t.state.db, "cu-ivan", "pw", false).await;
        t.state.db.close().await;
        let (status, ct, body) = send(&t.app, "POST", "/api/currentUser", Some(&token), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, JSON);
        assert_eq!(&body[..], br#"{"error":"Server error"}"#);
    }

    #[tokio::test]
    async fn logout_deletes_only_this_token_and_unbinds() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, other_token) = testutil::create_user(db, "lo-judy", "pw", false).await;
        let (_, v) = login_as(&t.app, "lo-judy", "pw", "222", "").await;
        let token = v["access_token"].as_str().unwrap().to_owned();
        assert_eq!(device_owner(db, "222").await, Some(uid));

        let (status, ct, body) = send(&t.app, "POST", "/api/logout", Some(&token), r#"{"id":"222"}"#).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, JSON);
        assert_eq!(&body[..], b"{}");
        assert_eq!(device_owner(db, "222").await, None);
        let (status, _, _) = send(&t.app, "POST", "/api/currentUser", Some(&token), "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = send(&t.app, "POST", "/api/currentUser", Some(&other_token), "").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = send(&t.app, "POST", "/api/logout", Some(&token), "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Logging out does not clear a device that now belongs to someone else.
        let (_, v) = login_as(&t.app, "lo-judy", "pw", "333", "").await;
        let token = v["access_token"].as_str().unwrap().to_owned();
        let (kid, _) = testutil::create_user(db, "lo-ken", "pw", false).await;
        login_as(&t.app, "lo-ken", "pw", "333", "").await;
        send(&t.app, "POST", "/api/logout", Some(&token), "").await;
        assert_eq!(device_owner(db, "333").await, Some(kid));
    }
}
