//! Account endpoints (PORTA.md §9.2, §11; note 03 §2).

use super::{
    device::{uuid_matches, MAX_UUID_LEN},
    ok_json, parse_json, ApiError, ApiResult, CurrentUser,
};
use crate::{
    auth::{self, PasswordCheck},
    peer::MAX_PEER_ID_LEN,
    state::AppState,
};
use axum::{body::Bytes, extract::State, http::StatusCode};
use hbb_common::{log, tokio};
use serde_derive::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

/// Failed logins per user name: 5 within 15 minutes lock the name for 15 minutes (§11).
const FAIL_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_FAILS: usize = 5;
/// Longer names are refused before the lookup, so request bodies cannot make big keys.
pub(crate) const MAX_NAME_LEN: usize = 128;
/// Password checks that may wait per argon2 slot. A burst of real logins then waits at most a few
/// check times (tens of milliseconds each); beyond it, unauthenticated requests (unknown names are
/// not rate limited, §11) would only queue up ahead of real logins, each holding its password.
const QUEUE_PER_SLOT: usize = 4;
/// Tokens kept per user; each login evicts the least recently used beyond this (§11).
const MAX_TOKENS: i64 = 50;

#[derive(Default)]
struct FailState {
    /// Failures within the last `FAIL_WINDOW`.
    fails: Vec<Instant>,
    /// Attempts past the limit check whose password check has not finished.
    in_flight: usize,
    locked_until: Option<Instant>,
}

lazy_static::lazy_static! {
    /// Only names of existing users, so at most one entry per user; a name's stale failures are
    /// dropped when it is next used, never by scanning the whole map.
    static ref LOGIN_FAILS: Mutex<HashMap<String, FailState>> = Default::default();
    static ref ARGON2: Argon2Slots =
        Argon2Slots::new(std::thread::available_parallelism().map_or(1, |n| n.get()));
}

/// Password checks running at once: each argon2 check takes ~19 MiB and a core for tens of
/// milliseconds, so more than one per core only adds memory. The rest wait their turn, up to
/// `QUEUE_PER_SLOT` per slot; past that new checks are refused with 429.
struct Argon2Slots {
    slots: Arc<Semaphore>,
    waiting: AtomicUsize,
    max_waiting: usize,
}

impl Argon2Slots {
    fn new(slots: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(slots)),
            waiting: AtomicUsize::new(0),
            max_waiting: QUEUE_PER_SLOT * slots,
        }
    }

    /// Runs `f` on the blocking pool once a slot is free. The permit moves into the task, so a
    /// client that goes away does not free it early; one that goes away while waiting leaves the queue.
    async fn run<T: Send + 'static>(&self, f: impl FnOnce() -> T + Send + 'static) -> Result<T, ApiError> {
        let max = self.max_waiting;
        if self
            .waiting
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < max).then_some(n + 1))
            .is_err()
        {
            return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "Too many login attempts, try again later"));
        }
        let waiting = Waiting(&self.waiting);
        let permit = self.slots.clone().acquire_owned().await.map_err(ApiError::internal)?;
        drop(waiting);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        })
        .await
        .map_err(ApiError::internal)
    }
}

/// One place in [`Argon2Slots`]' queue, given back when dropped.
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A login attempt on an existing user, counted from the limit check on, so concurrent attempts
/// cannot all pass the check before the first failure is recorded. Dropped without `finish` (an
/// error, or the client went away) it only gives its place back.
struct Attempt {
    name: String,
    matched: Option<bool>,
}

impl Attempt {
    /// `None`: the name is locked, or its failures plus attempts in flight reached `MAX_FAILS`.
    fn begin(name: &str) -> Option<Self> {
        let now = Instant::now();
        let mut map = LOGIN_FAILS.lock().unwrap_or_else(|e| e.into_inner());
        let s = map.entry(name.to_owned()).or_default();
        s.fails.retain(|t| now - *t < FAIL_WINDOW);
        if s.locked_until.is_some_and(|t| t > now) || s.fails.len() + s.in_flight >= MAX_FAILS {
            return None;
        }
        s.in_flight += 1;
        Some(Self { name: name.to_owned(), matched: None })
    }

    /// Records the result when dropped: a failure counts, a success forgets the earlier failures.
    fn finish(mut self, matched: bool) {
        self.matched = Some(matched);
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        let now = Instant::now();
        let mut map = LOGIN_FAILS.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = map.get_mut(&self.name) else {
            return;
        };
        s.in_flight -= 1;
        match self.matched {
            Some(true) => s.fails.clear(),
            Some(false) => {
                s.fails.push(now);
                if s.fails.len() >= MAX_FAILS {
                    s.fails.clear();
                    s.locked_until = Some(now + FAIL_WINDOW);
                }
            }
            None => {}
        }
        if s.in_flight == 0 && s.fails.is_empty() && !s.locked_until.is_some_and(|t| t > now) {
            map.remove(&self.name);
        }
    }
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
    let mut req: LoginRequest = parse_json(&body)?;
    // Waiting for a password check holds only what the login still needs (`QUEUE_PER_SLOT`).
    drop(body);
    if req.typ.as_deref().is_some_and(|t| t != "account") {
        return Err(ApiError::bad_request("Unsupported login type"));
    }
    if req.username.len() > MAX_NAME_LEN {
        return Err(ApiError::bad_request("User name too long"));
    }
    // Both go into the token row, and the device id from there into every `conn_attempt` row of
    // this token's connections (§8): refused up front, like the device reports would (§9.3).
    if req.id.len() > MAX_PEER_ID_LEN || req.uuid.len() > MAX_UUID_LEN {
        return Err(ApiError::bad_request("Device id or uuid too long"));
    }
    let row = sqlx::query_as::<_, (i64, String, i64)>(
        "select id, password_hash, status from user where name = ?",
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await?;
    let attempt = match row {
        Some(_) => Some(Attempt::begin(&req.username).ok_or_else(|| {
            ApiError::new(StatusCode::TOO_MANY_REQUESTS, "Too many failed attempts, try again later")
        })?),
        None => {
            // An unknown name never gets past the check: its device fields are not needed.
            (req.id, req.uuid) = Default::default();
            None
        }
    };
    let (uid, stored, status) = row.unwrap_or_default();
    // argon2 takes tens of milliseconds of CPU: keep it off the async workers, a few at a time.
    let password = std::mem::take(&mut req.password);
    let checked = stored.clone();
    let (check, upgraded, password) = ARGON2
        .run(move || {
            let check = auth::verify_password(&password, &checked);
            let upgraded = (check == PasswordCheck::OkNeedsUpgrade).then(|| auth::hash_password(&password));
            (check, upgraded, password)
        })
        .await?;
    let matched = check != PasswordCheck::Mismatch;
    if let Some(attempt) = attempt {
        attempt.finish(matched);
    }
    if !matched {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Wrong credentials"));
    }
    if status != 1 {
        return Err(ApiError::forbidden("Account disabled"));
    }
    let now = crate::common::now() as i64;
    // Both writes below only apply while the hash is still the one just checked: a `user passwd`
    // in between has already signed out every token, so neither may undo it.
    let current = match upgraded {
        Some(hash) => {
            let hash = hash?;
            let res = sqlx::query(
                "update user set password_hash = ?, updated_at = ? where id = ? and password_hash = ?",
            )
            .bind(&hash)
            .bind(now)
            .bind(uid)
            .bind(&stored)
            .execute(&state.db)
            .await?;
            if res.rows_affected() == 1 {
                log::info!("Upgraded the password hash of user {} to argon2id", req.username);
                hash
            } else {
                // Another login with the same legacy hash may have upgraded it first: its argon2
                // hash is as good as ours. Anything else (a `user passwd`) refuses this login.
                let now_stored: Option<String> = sqlx::query_scalar("select password_hash from user where id = ?")
                    .bind(uid)
                    .fetch_optional(&state.db)
                    .await?;
                let Some(now_stored) = now_stored.filter(|h| h.starts_with("$argon2id$")) else {
                    return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Wrong credentials"));
                };
                let (check, now_stored) = ARGON2
                    .run(move || (auth::verify_password(&password, &now_stored), now_stored))
                    .await?;
                if check != PasswordCheck::Ok {
                    return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Wrong credentials"));
                }
                now_stored
            }
        }
        None => stored,
    };

    let token = auth::new_token();
    let mut tx = state.db.begin().await?;
    let issued = sqlx::query(
        "insert into token(token_hash, user_id, device_id, device_uuid, created_at, last_used_at)
         select ?, id, ?, ?, ?, ? from user where id = ? and password_hash = ? and status = 1",
    )
    .bind(auth::token_hash(&token))
    .bind(&req.id)
    .bind(&req.uuid)
    .bind(now)
    .bind(now)
    .bind(uid)
    .bind(&current)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if issued == 0 {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Wrong credentials"));
    }
    // Tokens never expire (§11): keep only the user's MAX_TOKENS most recently used, the new one
    // included, so logging in again and again cannot pile up rows.
    sqlx::query(
        "delete from token where user_id = ?1 and rowid not in
         (select rowid from token where user_id = ?1 order by last_used_at desc, rowid desc limit ?2)",
    )
    .bind(uid)
    .bind(MAX_TOKENS)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // Only a device registered with hbbs, with a matching uuid, is bound: someone else's device is
    // not taken over, and made-up ids add no device rows (§11).
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

/// `POST /api/logout`: deletes the token used and the user's older tokens from the same device.
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
        // The client holds only its latest token, so earlier ones from this device are dead; left
        // in place, the next heartbeat would bind the device right back to this user (§11).
        sqlx::query("delete from token where user_id = ? and device_id = ?")
            .bind(user.id)
            .bind(&device_id)
            .execute(&state.db)
            .await?;
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
        // Not in hbbs' peer table: no device row is made, nothing is bound.
        let n: i64 = sqlx::query_scalar("select count(*) from device").fetch_one(db).await.unwrap();
        assert_eq!(n, 0);
        // Registered with a matching uuid: the device row is made and bound.
        t.state.pm.db.insert_peer("123456789", b"uuid", b"pk", "{}").await.unwrap();
        let (status, _) = login_as(&t.app, "10086", "pw", "123456789", "dXVpZA==").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(device_owner(db, "123456789").await, Some(uid));

        let (status, _, body) = send(&t.app, "POST", "/api/currentUser", Some(&token), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_user_payload(&serde_json::from_slice(&body).unwrap(), "10086", true);
    }

    #[tokio::test]
    async fn login_keeps_the_most_recently_used_tokens() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, first) = testutil::create_user(db, "alice", "pw", false).await;
        let (_, other_user) = testutil::create_user(db, "bob", "", false).await;
        // 49 more, inserted in order but used longer ago the later they were made: eviction goes
        // by last use, not by creation.
        let now = crate::common::now() as i64;
        let mut old = Vec::new();
        for i in 0..MAX_TOKENS - 1 {
            let token = auth::new_token();
            sqlx::query("insert into token(token_hash, user_id, created_at, last_used_at) values(?, ?, ?, ?)")
                .bind(auth::token_hash(&token))
                .bind(uid)
                .bind(now - 5000)
                .bind(now - 1000 - i)
                .execute(db)
                .await
                .unwrap();
            old.push(token);
        }
        let works = |token: String| {
            let app = t.app.clone();
            async move { send(&app, "POST", "/api/currentUser", Some(&token), "").await.0 }
        };
        let count = || async {
            let n: i64 = sqlx::query_scalar("select count(*) from token where user_id = ?")
                .bind(uid)
                .fetch_one(db)
                .await
                .unwrap();
            n
        };
        assert_eq!(count().await, MAX_TOKENS);

        // The 51st token evicts the least recently used one; the 52nd the next.
        let (status, v) = login_as(&t.app, "alice", "pw", "", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(count().await, MAX_TOKENS);
        assert_eq!(works(old[48].clone()).await, StatusCode::UNAUTHORIZED);
        assert_eq!(works(old[47].clone()).await, StatusCode::OK);
        let (status, _) = login_as(&t.app, "alice", "pw", "", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(count().await, MAX_TOKENS);
        // old[47] was just used, so old[46] goes.
        assert_eq!(works(old[46].clone()).await, StatusCode::UNAUTHORIZED);
        for token in [first, old[0].clone(), old[47].clone(), v["access_token"].as_str().unwrap().to_owned()] {
            assert_eq!(works(token).await, StatusCode::OK);
        }
        // Other users' tokens are not touched.
        assert_eq!(works(other_user).await, StatusCode::OK);
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
    async fn concurrent_attempts_count_against_the_limit() {
        let t = testutil::app().await;
        testutil::create_user(&t.state.db, "cc-zoe", "pw", false).await;
        let tasks: Vec<_> = (0..3 * MAX_FAILS)
            .map(|_| {
                let app = t.app.clone();
                tokio::spawn(async move { login_as(&app, "cc-zoe", "bad", "", "").await.0 })
            })
            .collect();
        let mut statuses = Vec::new();
        for task in tasks {
            statuses.push(task.await.unwrap());
        }
        // Only MAX_FAILS of the burst get a password check; the rest are refused up front.
        let checked = statuses.iter().filter(|s| **s == StatusCode::UNAUTHORIZED).count();
        let refused = statuses.iter().filter(|s| **s == StatusCode::TOO_MANY_REQUESTS).count();
        assert_eq!((checked, refused), (MAX_FAILS, 2 * MAX_FAILS), "{statuses:?}");
        let (status, _) = login_as(&t.app, "cc-zoe", "pw", "", "").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn abandoned_attempt_gives_its_place_back() {
        let name = "ab-quinn";
        let mut attempts: Vec<_> = (0..MAX_FAILS).map(|_| Attempt::begin(name).unwrap()).collect();
        assert!(Attempt::begin(name).is_none());
        // E.g. the client went away during the password check: no failure is recorded.
        attempts.pop();
        attempts.push(Attempt::begin(name).unwrap());
        drop(attempts);
        assert!(!LOGIN_FAILS.lock().unwrap().contains_key(name));
    }

    #[tokio::test]
    async fn password_checks_wait_for_a_slot() {
        let t = testutil::app().await;
        testutil::create_user(&t.state.db, "ps-paul", "pw", false).await;
        let slots = std::thread::available_parallelism().map_or(1, |n| n.get()) as u32;
        let all = ARGON2.slots.clone().acquire_many_owned(slots).await.unwrap();
        let app = t.app.clone();
        let mut login = tokio::spawn(async move { login_as(&app, "ps-paul", "pw", "", "").await.0 });
        let waited = tokio::time::timeout(Duration::from_millis(300), &mut login).await;
        assert!(waited.is_err(), "login finished while every slot was taken");
        drop(all);
        assert_eq!(login.await.unwrap(), StatusCode::OK);
    }

    /// A pool of its own: filling the global queue would refuse the other tests' logins.
    #[tokio::test]
    async fn password_check_queue_is_bounded() {
        let pool = Arc::new(Argon2Slots::new(1));
        let held = pool.slots.clone().acquire_owned().await.unwrap();
        let waiters: Vec<_> = (0..QUEUE_PER_SLOT)
            .map(|i| {
                let pool = pool.clone();
                tokio::spawn(async move { pool.run(move || i).await.ok() })
            })
            .collect();
        while pool.waiting.load(Ordering::SeqCst) < QUEUE_PER_SLOT {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let Err(ApiError(resp)) = pool.run(|| ()).await else {
            panic!("a full queue took another check");
        };
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"Too many login attempts, try again later"}"#);

        // A waiter whose client went away gives its place back.
        let mut waiters = waiters.into_iter();
        let gone = waiters.next().unwrap();
        gone.abort();
        assert!(gone.await.is_err());
        assert_eq!(pool.waiting.load(Ordering::SeqCst), QUEUE_PER_SLOT - 1);
        let late = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.run(|| QUEUE_PER_SLOT).await.ok() })
        };

        drop(held);
        for (i, w) in waiters.enumerate() {
            assert_eq!(w.await.unwrap(), Some(i + 1));
        }
        assert_eq!(late.await.unwrap(), Some(QUEUE_PER_SLOT));
        assert_eq!(pool.waiting.load(Ordering::SeqCst), 0);
    }

    /// `user passwd` lands while a login with the old password is past the lookup: the login gets
    /// no token, and a legacy hash upgrade does not write the old password back.
    #[tokio::test]
    async fn password_change_during_login_wins() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let slots = std::thread::available_parallelism().map_or(1, |n| n.get()) as u32;
        let (aid, _) = testutil::create_user(db, "pc-rita", "old", false).await;
        let (bid, _) = testutil::create_user(db, "pc-sam", "", false).await;
        sqlx::query("update user set password_hash = ? where id = ?")
            .bind(bcrypt::hash("old", 4).unwrap())
            .bind(bid)
            .execute(db)
            .await
            .unwrap();
        for (uid, name) in [(aid, "pc-rita"), (bid, "pc-sam")] {
            // Hold the login between reading the stored hash and checking it.
            let all = ARGON2.slots.clone().acquire_many_owned(slots).await.unwrap();
            let app = t.app.clone();
            let mut login = tokio::spawn(async move { login_as(&app, name, "old", "", "").await.0 });
            assert!(tokio::time::timeout(Duration::from_millis(300), &mut login).await.is_err());
            let new_hash = auth::hash_password("new").unwrap();
            sqlx::query("update user set password_hash = ? where id = ?")
                .bind(&new_hash)
                .bind(uid)
                .execute(db)
                .await
                .unwrap();
            sqlx::query("delete from token where user_id = ?").bind(uid).execute(db).await.unwrap();
            drop(all);

            assert_eq!(login.await.unwrap(), StatusCode::UNAUTHORIZED, "{name}");
            let tokens: i64 = sqlx::query_scalar("select count(*) from token where user_id = ?")
                .bind(uid)
                .fetch_one(db)
                .await
                .unwrap();
            assert_eq!(tokens, 0, "{name}");
            let stored: String = sqlx::query_scalar("select password_hash from user where id = ?")
                .bind(uid)
                .fetch_one(db)
                .await
                .unwrap();
            assert_eq!(stored, new_hash, "{name}");
            let (status, _) = login_as(&t.app, name, "new", "", "").await;
            assert_eq!(status, StatusCode::OK, "{name}");
        }
    }

    /// Two first logins of an imported user: the one that finishes second finds the hash already
    /// upgraded by the other, and still gets its token.
    #[tokio::test]
    async fn concurrent_legacy_upgrade_both_log_in() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let slots = std::thread::available_parallelism().map_or(1, |n| n.get()) as u32;
        let (uid, _) = testutil::create_user(db, "cu-tina", "", false).await;
        sqlx::query("update user set password_hash = ? where id = ?")
            .bind(bcrypt::hash("pw", 4).unwrap())
            .bind(uid)
            .execute(db)
            .await
            .unwrap();
        // Hold this login between reading the bcrypt hash and checking it.
        let all = ARGON2.slots.clone().acquire_many_owned(slots).await.unwrap();
        let app = t.app.clone();
        let mut login = tokio::spawn(async move { login_as(&app, "cu-tina", "pw", "", "").await });
        assert!(tokio::time::timeout(Duration::from_millis(300), &mut login).await.is_err());
        // The other login's upgrade lands meanwhile.
        let other = auth::hash_password("pw").unwrap();
        sqlx::query("update user set password_hash = ? where id = ?")
            .bind(&other)
            .bind(uid)
            .execute(db)
            .await
            .unwrap();
        drop(all);

        let (status, v) = login.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{v}");
        let token = v["access_token"].as_str().unwrap();
        let (status, _, _) = send(&t.app, "POST", "/api/currentUser", Some(token), "").await;
        assert_eq!(status, StatusCode::OK);
        let stored: String = sqlx::query_scalar("select password_hash from user where id = ?")
            .bind(uid)
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(stored, other);
    }

    #[tokio::test]
    async fn failure_table_only_holds_existing_users() {
        let t = testutil::app().await;
        testutil::create_user(&t.state.db, "ft-olga", "pw", false).await;
        let fails = |name: &str| LOGIN_FAILS.lock().unwrap().get(name).map(|s| s.fails.len());

        // Unknown names, however many failures, leave nothing behind.
        for _ in 0..MAX_FAILS + 1 {
            let (status, _) = login_as(&t.app, "ft-nobody", "pw", "", "").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(fails("ft-nobody"), None);

        // Over-long names are refused up front; 128 bytes is still a normal (unknown) name.
        let long = "n".repeat(MAX_NAME_LEN + 1);
        let (status, v) = login_as(&t.app, &long, "pw", "", "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(v["error"].is_string());
        assert_eq!(fails(&long), None);
        let (status, _) = login_as(&t.app, &long[1..], "pw", "", "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // An existing user's failures older than the window are dropped when the name is next used.
        let old = Instant::now().checked_sub(FAIL_WINDOW).unwrap();
        LOGIN_FAILS.lock().unwrap().insert(
            "ft-olga".to_owned(),
            FailState { fails: vec![old; MAX_FAILS - 1], ..Default::default() },
        );
        let (status, _) = login_as(&t.app, "ft-olga", "bad", "", "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(fails("ft-olga"), Some(1));
        let (status, _) = login_as(&t.app, "ft-olga", "pw", "", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fails("ft-olga"), None);
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
    async fn login_refuses_overlong_device_fields() {
        let t = testutil::app().await;
        let db = &t.state.db;
        testutil::create_user(db, "ol-mia", "pw", false).await;
        let tokens = || async { sqlx::query_scalar::<_, i64>("select count(*) from token").fetch_one(db).await.unwrap() };
        let before = tokens().await;
        let (id, uuid) = ("i".repeat(MAX_PEER_ID_LEN), "u".repeat(MAX_UUID_LEN));
        for (id, uuid) in [(format!("{id}i"), uuid.clone()), (id.clone(), format!("{uuid}u"))] {
            let (status, v) = login_as(&t.app, "ol-mia", "pw", &id, &uuid).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(v, json!({"error": "Device id or uuid too long"}));
        }
        assert_eq!(tokens().await, before);
        // At the limits: a normal login, recorded in the token row.
        let (status, v) = login_as(&t.app, "ol-mia", "pw", &id, &uuid).await;
        assert_eq!(status, StatusCode::OK);
        let row: (String, String) = sqlx::query_as("select device_id, device_uuid from token where token_hash = ?")
            .bind(auth::token_hash(v["access_token"].as_str().unwrap()))
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(row, (id, uuid));
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
    async fn logout_keeps_tokens_of_other_devices_and_unbinds() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, other_token) = testutil::create_user(db, "lo-judy", "pw", false).await;
        for id in ["222", "333"] {
            t.state.pm.db.insert_peer(id, b"uuid", b"pk", "{}").await.unwrap();
        }
        let (_, v) = login_as(&t.app, "lo-judy", "pw", "222", "dXVpZA==").await;
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
        let (_, v) = login_as(&t.app, "lo-judy", "pw", "333", "dXVpZA==").await;
        let token = v["access_token"].as_str().unwrap().to_owned();
        let (kid, _) = testutil::create_user(db, "lo-ken", "pw", false).await;
        login_as(&t.app, "lo-ken", "pw", "333", "dXVpZA==").await;
        send(&t.app, "POST", "/api/logout", Some(&token), "").await;
        assert_eq!(device_owner(db, "333").await, Some(kid));
    }
}
