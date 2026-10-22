//! Audit reports (PORTA.md §9.3; note 03 §5).
//! Success: 200 + empty body (`ok_empty`); internal error: 200 + `{"error"}` (`ok_internal`, the
//! client retries); bad body: 400. Handlers return `Response` so `?` cannot produce a plain 400.

use super::{device::uuid_matches, ok_empty, ok_internal, parse_json};
use crate::{conn_tracker::clip, peer::MAX_PEER_ID_LEN, state::AppState};
use axum::{body::Bytes, extract::State, response::Response};
use once_cell::sync::Lazy;
use serde::de::{DeserializeOwned, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde_derive::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    collections::HashSet,
    fmt,
    future::Future,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Retries carry the same nonce for up to 120 s (note 03 §5.1); remember them for 5 minutes.
const NONCE_TTL: Duration = Duration::from_secs(300);
/// Real clients send a uuid v4 (36 bytes); longer nonces are treated as absent.
const MAX_NONCE_LEN: usize = 64;
/// Nonces held at most; once full, new ones are not registered and their reports just lose dedupe.
const MAX_NONCES: usize = 100_000;

// What a report can make us store (review A-9). Longer values are clipped at a char boundary and
// stored: the audits answer 200 whatever comes (§9.1.8). `device_id` is the checked id (at most
// `MAX_PEER_ID_LEN`); `peer_id` is clipped to the same.
/// `audit_conn.ip`: an IPv6 text is at most 45 bytes.
const MAX_IP_LEN: usize = 64;
/// `audit_conn.peer_name`, the controller's name.
const MAX_PEER_NAME_LEN: usize = 256;
/// `audit_conn.auth` (serialized; see `auth_json`) and `.note` (the client's note field takes 256
/// characters, at most 1 KB), `audit_file.path` and `.info` (the top 10 files with their sizes),
/// `audit_alarm.info`.
const MAX_TEXT_LEN: usize = 4096;

/// The audit tables, each kept to `MAX_ROWS` rows (`make_room`) and `RETENTION_SECS` (`purge`).
pub(crate) const TABLES: [&str; 3] = ["audit_conn", "audit_file", "audit_alarm"];
/// Rows per audit table. Worst-case rows (every text column at its limit, measured on SQLite with
/// 4 KB pages, indexes included): audit_conn ≈ 9.5 KB (253 + 253 + 256 + 64 + 4096 + 4096 bytes of
/// text, mostly in overflow pages), audit_file ≈ 8.8 KB (253 + 253 + 4096 + 4096), audit_alarm ≈
/// 4.6 KB (253 + 4096). 20,000 × (9.5 + 8.8 + 4.6) KB ≈ 0.46 GB for the three together; freed pages
/// are reused, so the file stays there. Real rows are a few hundred bytes (20,000 ≈ 6 MB a table).
const MAX_ROWS: i64 = 20_000;
/// Rows created longer ago than this are deleted by the hourly purge.
const RETENTION_SECS: i64 = 180 * 24 * 3600;

/// Nonces of records already written, in two generations of `NONCE_TTL`: each is kept for 5 to 10
/// minutes, and old ones go a whole generation at a time instead of by scanning.
struct Nonces {
    current: HashSet<String>,
    previous: HashSet<String>,
    since: Instant,
}

impl Nonces {
    fn new() -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            since: Instant::now(),
        }
    }

    fn rotate(&mut self) {
        let age = self.since.elapsed();
        if age < NONCE_TTL {
            return;
        }
        if age >= 2 * NONCE_TTL {
            self.current.clear();
        }
        self.previous = std::mem::take(&mut self.current);
        self.since = Instant::now();
    }

    fn seen(&mut self, nonce: &str) -> bool {
        self.rotate();
        self.current.contains(nonce) || self.previous.contains(nonce)
    }

    fn remember(&mut self, nonce: &str) {
        self.rotate();
        if self.current.len() + self.previous.len() < MAX_NONCES {
            self.current.insert(nonce.to_owned());
        }
    }
}

static NONCES: Lazy<Mutex<Nonces>> = Lazy::new(|| Mutex::new(Nonces::new()));

fn nonce_seen(nonce: &str) -> bool {
    NONCES.lock().unwrap_or_else(|e| e.into_inner()).seen(nonce)
}

fn remember_nonce(nonce: &str) {
    NONCES.lock().unwrap_or_else(|e| e.into_inner()).remember(nonce);
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, Response> {
    parse_json(body).map_err(|e| e.0)
}

/// Makes room for one more row in `table` (one of `TABLES`): deletes the rows `MAX_ROWS - 1` ids or
/// more below the newest, so with the insert that follows at most `MAX_ROWS` are left. Ids only grow
/// (a new rowid is the largest + 1), so this is a range on the primary key that deletes nothing or
/// one row. Done on every insert, not by the hourly purge: the reports are not rate limited, so an
/// hour of them is not bounded. Runs before the insert, so a failure leaves nothing that the
/// client's retry would duplicate.
async fn make_room(db: &SqlitePool, table: &str) -> Result<(), sqlx::Error> {
    sqlx::query(&format!("delete from {table} where id <= (select max(id) from {table}) - ?"))
        .bind(MAX_ROWS - 1)
        .execute(db)
        .await?;
    Ok(())
}

/// Hourly, from `conn_tracker`'s purge: deletes the rows of `table` (one of `TABLES`) created more
/// than `RETENTION_SECS` before `now` (unix seconds). A scan of at most `MAX_ROWS` rows.
pub(crate) async fn purge(db: &SqlitePool, table: &str, now: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(&format!("delete from {table} where created_at < ?"))
        .bind(now - RETENTION_SECS)
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}

/// `audit_conn.auth`: the authed report's own keys (`Auth`) as JSON, the text clipped to `MAX_TEXT_LEN`.
fn auth_json(req: &ConnReq) -> String {
    let auth = Auth {
        conn_audit_ref: req.conn_audit_ref.as_deref(),
        primary_auth: req.primary_auth,
        two_factor: req.two_factor,
    };
    let mut auth = serde_json::to_string(&auth).unwrap_or_default();
    clip(&mut auth, MAX_TEXT_LEN);
    auth
}

/// What `audit_conn.auth` keeps: the keys known clients send with the authed report (note 03 §5.2),
/// absent ones omitted. Declared in key order, as the map it replaces serialized them.
#[derive(Serialize)]
struct Auth<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    conn_audit_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    primary_auth: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    two_factor: Option<i64>,
}

/// The first two strings of a JSON array; later elements are skipped without being built. A
/// `Vec<String>` would turn a 2 MB array of `""` into ~700,000 strings (~17 MB).
#[derive(Default)]
struct FirstTwo(Vec<String>);

impl<'de> serde::Deserialize<'de> for FirstTwo {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct FirstTwoVisitor;
        impl<'de> Visitor<'de> for FirstTwoVisitor {
            type Value = FirstTwo;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array of strings")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<FirstTwo, A::Error> {
                let mut kept = Vec::with_capacity(2);
                while kept.len() < 2 {
                    match seq.next_element::<String>()? {
                        Some(s) => kept.push(s),
                        None => return Ok(FirstTwo(kept)),
                    }
                }
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(FirstTwo(kept))
            }
        }
        de.deserialize_seq(FirstTwoVisitor)
    }
}

/// Shared by the device-side audits: a repeated nonce is a success without writing; a failed
/// `uuid_matches` (unregistered id or wrong uuid) answers success without writing; the nonce is registered only after `write` succeeded, so
/// the client's retry of a failed write gets stored. No nonce (1.4.x), `""` or one longer than
/// `MAX_NONCE_LEN`: no dedupe.
async fn report(
    db: &SqlitePool,
    id: &str,
    uuid: Option<&str>,
    nonce: Option<&str>,
    write: impl Future<Output = Result<(), sqlx::Error>>,
) -> Response {
    let nonce = nonce.filter(|n| !n.is_empty() && n.len() <= MAX_NONCE_LEN);
    if nonce.is_some_and(nonce_seen) {
        return ok_empty();
    }
    match uuid_matches(db, id, uuid).await {
        Ok(true) => {}
        Ok(false) => return ok_empty(),
        Err(err) => return ok_internal(err),
    }
    if let Err(err) = write.await {
        return ok_internal(err);
    }
    if let Some(nonce) = nonce {
        remember_nonce(nonce);
    }
    ok_empty()
}

/// `/api/audit/conn` body (note 03 §5.2): new / authed (no `action`) / close from the controlled
/// side, or the controller's session note (`note` and no `uuid`). Only the fields below are built;
/// serde skips any other key without keeping it (review C-9: a flattened catch-all map turned a
/// 2 MB body into ~80 MB of `Value`s, before any identity check).
#[derive(Deserialize)]
struct ConnReq {
    id: String,
    uuid: Option<String>,
    nonce: Option<String>,
    action: Option<String>,
    note: Option<String>,
    #[serde(default)]
    conn_id: i64,
    /// Random u64, about half of them above i64::MAX; stored as a decimal string.
    #[serde(default)]
    session_id: u64,
    #[serde(default)]
    ip: String,
    /// `[controller id, controller name]`.
    #[serde(default)]
    peer: FirstTwo,
    #[serde(rename = "type")]
    conn_type: Option<i64>,
    // The authed report's keys kept as `audit_conn.auth` (`Auth`).
    conn_audit_ref: Option<String>,
    primary_auth: Option<i64>,
    two_factor: Option<i64>,
}

/// `POST /api/audit/conn`: new / authed / close, and the controller's session note (no uuid, no nonce).
pub(crate) async fn conn(State(state): State<AppState>, body: Bytes) -> Response {
    let mut req: ConnReq = match parse(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    if let Some(note) = &mut req.note {
        clip(note, MAX_TEXT_LEN);
    }
    clip(&mut req.ip, MAX_IP_LEN);
    for (field, max) in req.peer.0.iter_mut().zip([MAX_PEER_ID_LEN, MAX_PEER_NAME_LEN]) {
        clip(field, max);
    }
    let db = &state.db;
    if let (Some(note), None) = (&req.note, &req.uuid) {
        // Session note: no identity to check; updates every record of the session (remote desktop
        // and file transfer share one session id), none matching is ignored. Never inserts, so it
        // cannot add rows.
        return match sqlx::query("update audit_conn set note = ? where device_id = ? and session_id = ?")
            .bind(note)
            .bind(&req.id)
            .bind(req.session_id.to_string())
            .execute(db)
            .await
        {
            Ok(_) => ok_empty(),
            Err(err) => ok_internal(err),
        };
    }
    report(db, &req.id, req.uuid.as_deref(), req.nonce.as_deref(), write_conn(db, &req)).await
}

async fn write_conn(db: &SqlitePool, req: &ConnReq) -> Result<(), sqlx::Error> {
    let now = crate::common::now() as i64;
    // The latest record of this connection still open (`conn_id` restarts with the client process).
    const OPEN: &str =
        "(select max(id) from audit_conn where device_id = ? and conn_id = ? and closed_at is null)";
    match req.action.as_deref() {
        Some("new") => {
            make_room(db, "audit_conn").await?;
            sqlx::query("insert into audit_conn(device_id, conn_id, ip, created_at) values(?, ?, ?, ?)")
                .bind(&req.id)
                .bind(req.conn_id)
                .bind(&req.ip)
                .bind(now)
                .execute(db)
                .await?;
        }
        Some("close") => {
            sqlx::query(&format!("update audit_conn set closed_at = ? where id = {OPEN}"))
                .bind(now)
                .bind(&req.id)
                .bind(req.conn_id)
                .execute(db)
                .await?;
        }
        None => {
            let peer_id = req.peer.0.first().map(String::as_str).unwrap_or_default();
            let peer_name = req.peer.0.get(1).map(String::as_str).unwrap_or_default();
            let session_id = req.session_id.to_string();
            let auth = auth_json(req);
            let updated = sqlx::query(&format!(
                "update audit_conn set peer_id = ?, peer_name = ?, conn_type = ?, session_id = ?, auth = ?,
                   authed_at = ?
                 where id = {OPEN}"
            ))
            .bind(peer_id)
            .bind(peer_name)
            .bind(req.conn_type)
            .bind(&session_id)
            .bind(&auth)
            .bind(now)
            .bind(&req.id)
            .bind(req.conn_id)
            .execute(db)
            .await?
            .rows_affected();
            if updated == 0 {
                // The `new` report was lost.
                make_room(db, "audit_conn").await?;
                sqlx::query(
                    "insert into audit_conn(device_id, conn_id, session_id, peer_id, peer_name, conn_type,
                                            auth, created_at, authed_at)
                     values(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&req.id)
                .bind(req.conn_id)
                .bind(&session_id)
                .bind(peer_id)
                .bind(peer_name)
                .bind(req.conn_type)
                .bind(&auth)
                .bind(now)
                .bind(now)
                .execute(db)
                .await?;
            }
        }
        // Not sent by any known client; accepted and dropped.
        Some(_) => {}
    }
    Ok(())
}

/// `/api/audit/file` body (note 03 §5.3); `info` is a JSON string, stored as is.
#[derive(Deserialize)]
struct FileReq {
    id: String,
    uuid: Option<String>,
    nonce: Option<String>,
    #[serde(default)]
    conn_id: i64,
    #[serde(default)]
    peer_id: String,
    #[serde(default, rename = "type")]
    typ: i64,
    #[serde(default)]
    path: String,
    #[serde(default)]
    is_file: bool,
    #[serde(default)]
    info: String,
}

/// `POST /api/audit/file`.
pub(crate) async fn file(State(state): State<AppState>, body: Bytes) -> Response {
    let mut req: FileReq = match parse(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    clip(&mut req.peer_id, MAX_PEER_ID_LEN);
    clip(&mut req.path, MAX_TEXT_LEN);
    clip(&mut req.info, MAX_TEXT_LEN);
    let write = async {
        make_room(&state.db, "audit_file").await?;
        sqlx::query(
            "insert into audit_file(device_id, conn_id, peer_id, type, path, is_file, info, created_at)
             values(?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&req.id)
        .bind(req.conn_id)
        .bind(&req.peer_id)
        .bind(req.typ)
        .bind(&req.path)
        .bind(req.is_file)
        .bind(&req.info)
        .bind(crate::common::now() as i64)
        .execute(&state.db)
        .await
        .map(|_| ())
    };
    report(&state.db, &req.id, req.uuid.as_deref(), req.nonce.as_deref(), write).await
}

/// `/api/audit/alarm` body (note 03 §5.4): the field is `typ` here; unknown values are kept.
#[derive(Deserialize)]
struct AlarmReq {
    id: String,
    uuid: Option<String>,
    nonce: Option<String>,
    conn_id: Option<i64>,
    typ: i64,
    #[serde(default)]
    info: String,
}

/// `POST /api/audit/alarm`.
pub(crate) async fn alarm(State(state): State<AppState>, body: Bytes) -> Response {
    let mut req: AlarmReq = match parse(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    clip(&mut req.info, MAX_TEXT_LEN);
    let write = async {
        make_room(&state.db, "audit_alarm").await?;
        sqlx::query("insert into audit_alarm(device_id, conn_id, typ, info, created_at) values(?, ?, ?, ?, ?)")
            .bind(&req.id)
            .bind(req.conn_id)
            .bind(req.typ)
            .bind(&req.info)
            .bind(crate::common::now() as i64)
            .execute(&state.db)
            .await
            .map(|_| ())
    };
    report(&state.db, &req.id, req.uuid.as_deref(), req.nonce.as_deref(), write).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{self, send};
    use axum::http::StatusCode;
    use hbb_common::tokio;
    use serde_json::{json, Value};

    const UUID: &[u8] = b"8f2c1d4e-1111-2222-3333-444455556666";

    fn nonce() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Posts and asserts the success shape: 200 + empty body.
    async fn ok(app: &axum::Router, path: &str, body: Value) {
        let (status, _, resp) = send(app, "POST", path, None, &body.to_string()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(resp.is_empty(), "{}", String::from_utf8_lossy(&resp));
    }

    async fn count(db: &SqlitePool, table: &str) -> i64 {
        sqlx::query_scalar(&format!("select count(*) from {table}"))
            .fetch_one(db)
            .await
            .unwrap()
    }

    async fn add_peer(db: &SqlitePool, id: &str) {
        crate::database::Database::new(db.clone())
            .insert_peer(id, UUID, b"pk", "{}")
            .await
            .unwrap();
    }

    fn file_body(id: &str, uuid: Option<&[u8]>, nonce: Option<&str>) -> Value {
        let mut v = json!({
            "id": id, "peer_id": "999", "conn_id": 1234, "type": 1, "path": "C:\\x", "is_file": false,
            "info": "{\"ip\":\"203.0.113.5\",\"name\":\"bob\",\"num\":1,\"files\":[[\"a.txt\",123]]}",
        });
        if let Some(u) = uuid {
            v["uuid"] = json!(base64::encode(u));
        }
        if let Some(n) = nonce {
            v["nonce"] = json!(n);
        }
        v
    }

    #[tokio::test]
    async fn weak_check() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111").await;

        // Known id: wrong or missing uuid → success shape, nothing stored.
        ok(&t.app, "/api/audit/file", file_body("111", Some(b"other"), Some(&nonce()))).await;
        ok(&t.app, "/api/audit/file", file_body("111", None, Some(&nonce()))).await;
        ok(&t.app, "/api/audit/alarm", json!({"id": "111", "typ": 0, "info": "{}", "conn_id": 1})).await;
        ok(&t.app, "/api/audit/conn", json!({"id": "111", "action": "new", "conn_id": 1, "session_id": 0})).await;
        assert_eq!(count(db, "audit_file").await, 0);
        assert_eq!(count(db, "audit_alarm").await, 0);
        assert_eq!(count(db, "audit_conn").await, 0);

        // An id hbbs does not know, with or without uuid: success shape, nothing stored.
        ok(&t.app, "/api/audit/file", file_body("222", None, Some(&nonce()))).await;
        ok(&t.app, "/api/audit/file", file_body("222", Some(UUID), Some(&nonce()))).await;
        ok(&t.app, "/api/audit/alarm", json!({"id": "222", "uuid": base64::encode(UUID), "typ": 0, "info": "{}"})).await;
        ok(&t.app, "/api/audit/conn", json!({"id": "222", "uuid": base64::encode(UUID), "action": "new", "conn_id": 1})).await;
        assert_eq!(count(db, "audit_file").await, 0);
        assert_eq!(count(db, "audit_alarm").await, 0);
        assert_eq!(count(db, "audit_conn").await, 0);

        // Matching uuid: stored.
        ok(&t.app, "/api/audit/file", file_body("111", Some(UUID), Some(&nonce()))).await;
        let row: (String, i64, String, i64, String, bool, String) = sqlx::query_as(
            "select device_id, conn_id, peer_id, type, path, is_file, info from audit_file order by id limit 1",
        )
        .fetch_one(db)
        .await
        .unwrap();
        assert_eq!(row.0, "111");
        assert_eq!((row.1, row.2.as_str(), row.3, row.4.as_str(), row.5), (1234, "999", 1, "C:\\x", false));
        assert!(row.6.starts_with("{\"ip\""));
        assert_eq!(count(db, "audit_file").await, 1);

        // Alarm with an unknown typ and without conn_id.
        ok(&t.app, "/api/audit/alarm", json!({"id": "111", "uuid": base64::encode(UUID), "typ": 42, "info": "{\"ip\":\"x\"}"})).await;
        let row: (Option<i64>, i64, String) = sqlx::query_as("select conn_id, typ, info from audit_alarm")
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(row, (None, 42, "{\"ip\":\"x\"}".into()));

        // A broken body is a 400 (the client does not retry it).
        let (status, ct, _) = send(&t.app, "POST", "/api/audit/file", None, "{").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(ct, "application/json; charset=utf-8");
    }

    #[tokio::test]
    async fn nonce_dedupe() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "1").await;

        // Same nonce twice: stored once, both answered with an empty body.
        let n = nonce();
        ok(&t.app, "/api/audit/file", file_body("1", Some(UUID), Some(&n))).await;
        ok(&t.app, "/api/audit/file", file_body("1", Some(UUID), Some(&n))).await;
        assert_eq!(count(db, "audit_file").await, 1);

        // No nonce (1.4.x) or an empty one: never deduplicated.
        ok(&t.app, "/api/audit/file", file_body("1", Some(UUID), None)).await;
        ok(&t.app, "/api/audit/file", file_body("1", Some(UUID), None)).await;
        ok(&t.app, "/api/audit/file", file_body("1", Some(UUID), Some(""))).await;
        ok(&t.app, "/api/audit/file", file_body("1", Some(UUID), Some(""))).await;
        assert_eq!(count(db, "audit_file").await, 5);

        // A failed write answers 200 + {"error"} and does not register the nonce, so the retry is stored.
        sqlx::query("alter table audit_file rename to audit_file_away").execute(db).await.unwrap();
        let n = nonce();
        let (status, ct, body) = send(&t.app, "POST", "/api/audit/file", None, &file_body("1", Some(UUID), Some(&n)).to_string()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json; charset=utf-8");
        assert_eq!(&body[..], br#"{"error":"Server error"}"#);
        sqlx::query("alter table audit_file_away rename to audit_file").execute(db).await.unwrap();
        ok(&t.app, "/api/audit/file", file_body("1", Some(UUID), Some(&n))).await;
        assert_eq!(count(db, "audit_file").await, 6);
    }

    #[tokio::test]
    async fn long_nonce_is_no_nonce() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "1").await;
        // 64 bytes still deduplicates; 65 is treated as absent: stored every time, never registered.
        let (fits, long) = ("n".repeat(MAX_NONCE_LEN), "l".repeat(MAX_NONCE_LEN + 1));
        for _ in 0..2 {
            ok(&t.app, "/api/audit/file", file_body("1", Some(UUID), Some(&fits))).await;
            ok(&t.app, "/api/audit/file", file_body("1", Some(UUID), Some(&long))).await;
        }
        assert_eq!(count(db, "audit_file").await, 3);
        assert!(!nonce_seen(&long));
    }

    /// Driven by moving `since` back, on a private table so other tests' nonces are not affected.
    #[test]
    fn nonce_generations() {
        let age = |nonces: &mut Nonces| nonces.since = nonces.since.checked_sub(NONCE_TTL).unwrap();
        let mut nonces = Nonces::new();
        let n = nonce();
        nonces.remember(&n);
        assert!(nonces.seen(&n));
        // One generation later it is still known; after the next one it is gone.
        age(&mut nonces);
        assert!(nonces.seen(&n));
        assert!(nonces.previous.contains(&n) && nonces.current.is_empty());
        age(&mut nonces);
        assert!(!nonces.seen(&n));
        assert!(nonces.previous.is_empty());

        // Idle for two generations or more: both go at once.
        nonces.remember(&n);
        age(&mut nonces);
        age(&mut nonces);
        assert!(!nonces.seen(&n));

        // Full: new nonces are not registered, the ones held still are.
        for i in 0..MAX_NONCES {
            nonces.remember(&i.to_string());
        }
        nonces.remember(&n);
        assert!(!nonces.seen(&n));
        assert!(nonces.seen("0"));
    }

    #[tokio::test]
    async fn fields_are_clipped() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111").await;
        let uuid = base64::encode(UUID);
        // 2-byte chars: an odd limit cuts at the char boundary below it.
        let wide = |bytes: usize| "é".repeat(bytes / 2 + 1);
        let long = |bytes: usize| "x".repeat(bytes + 1);

        ok(&t.app, "/api/audit/conn", json!({"id": "111", "uuid": uuid, "action": "new", "conn_id": 1, "ip": wide(MAX_IP_LEN)})).await;
        let auth = json!({"id": "111", "uuid": uuid, "conn_id": 1, "session_id": 7, "type": 0, "primary_auth": 2,
                          "two_factor": 1, "peer": [wide(MAX_PEER_ID_LEN), long(MAX_PEER_NAME_LEN)],
                          "junk": long(MAX_TEXT_LEN)});
        ok(&t.app, "/api/audit/conn", auth).await;
        ok(&t.app, "/api/audit/conn", json!({"id": "111", "session_id": 7, "note": wide(MAX_TEXT_LEN)})).await;
        let row: (String, String, String, String, String) =
            sqlx::query_as("select ip, peer_id, peer_name, auth, note from audit_conn").fetch_one(db).await.unwrap();
        assert_eq!(row.0, "é".repeat(MAX_IP_LEN / 2));
        assert_eq!(row.1, "é".repeat(MAX_PEER_ID_LEN / 2));
        assert_eq!(row.2, "x".repeat(MAX_PEER_NAME_LEN));
        // Only the known keys are kept; the unknown one is never stored.
        assert_eq!(serde_json::from_str::<Value>(&row.3).unwrap(), json!({"primary_auth": 2, "two_factor": 1}));
        assert_eq!(row.4, "é".repeat(MAX_TEXT_LEN / 2));

        // A known key over the limit: clipped text. Exactly at the limit: kept whole.
        let huge = json!({"id": "111", "uuid": uuid, "conn_id": 2, "session_id": 8, "conn_audit_ref": long(MAX_TEXT_LEN), "x": 1});
        ok(&t.app, "/api/audit/conn", huge).await;
        // `{"conn_audit_ref":"…"}`: exactly MAX_TEXT_LEN bytes.
        let fits = json!({"id": "111", "uuid": uuid, "conn_id": 3, "session_id": 9, "conn_audit_ref": "y".repeat(MAX_TEXT_LEN - 21)});
        ok(&t.app, "/api/audit/conn", fits).await;
        let auths: Vec<String> = sqlx::query_scalar("select auth from audit_conn where conn_id in (2, 3) order by conn_id")
            .fetch_all(db)
            .await
            .unwrap();
        assert_eq!(auths[0].len(), MAX_TEXT_LEN);
        assert!(auths[0].starts_with(r#"{"conn_audit_ref":"xxx"#));
        assert_eq!(auths[1].len(), MAX_TEXT_LEN);
        let fits: Value = serde_json::from_str(&auths[1]).unwrap();
        assert_eq!(fits["conn_audit_ref"].as_str().unwrap().len(), MAX_TEXT_LEN - 21);

        let file = json!({"id": "111", "uuid": uuid, "conn_id": 1, "peer_id": long(MAX_PEER_ID_LEN), "type": 0,
                          "path": wide(MAX_TEXT_LEN), "is_file": true, "info": long(MAX_TEXT_LEN)});
        ok(&t.app, "/api/audit/file", file).await;
        let row: (String, String, String) =
            sqlx::query_as("select peer_id, path, info from audit_file").fetch_one(db).await.unwrap();
        assert_eq!(row, ("x".repeat(MAX_PEER_ID_LEN), "é".repeat(MAX_TEXT_LEN / 2), "x".repeat(MAX_TEXT_LEN)));
        ok(&t.app, "/api/audit/alarm", json!({"id": "111", "uuid": uuid, "typ": 0, "info": wide(MAX_TEXT_LEN)})).await;
        let info: String = sqlx::query_scalar("select info from audit_alarm").fetch_one(db).await.unwrap();
        assert_eq!(info, "é".repeat(MAX_TEXT_LEN / 2));
    }

    /// Review C-9: a body near the 2 MB limit, made of an unknown key's big array and a long `peer`,
    /// parses into the known fields only: nothing holds the skipped elements (the RSS side is
    /// `audit_conn_big_body_is_not_amplified` in tests/bb_api.rs).
    #[test]
    fn big_conn_body_builds_only_known_fields() {
        let body = format!(
            r#"{{"id":"1","junk":[{}0],"peer":["a","b"{},1,{{"x":[]}}],"primary_auth":2,"note":null}}"#,
            "0,".repeat(400_000),
            ",\"\"".repeat(200_000)
        );
        assert!(body.len() > 1_400_000 && body.len() < 2 * 1024 * 1024, "{}", body.len());
        let req: ConnReq = serde_json::from_slice(body.as_bytes()).unwrap();
        assert_eq!(req.peer.0, ["a", "b"]);
        assert_eq!(req.peer.0.capacity(), 2);
        assert_eq!(auth_json(&req), r#"{"primary_auth":2}"#);
        // Short arrays are taken as they are.
        for (peer, kept) in [("[]", vec![]), (r#"["a"]"#, vec!["a"])] {
            let req: ConnReq = serde_json::from_str(&format!(r#"{{"id":"1","peer":{peer}}}"#)).unwrap();
            assert_eq!(req.peer.0, kept);
        }
    }

    /// Driven by placing rows at chosen ids: `MAX_ROWS` real inserts are not needed.
    #[tokio::test]
    async fn every_insert_keeps_the_newest_rows() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111").await;
        let uuid = base64::encode(UUID);
        let reports = [
            ("audit_conn", "/api/audit/conn", json!({"id": "111", "uuid": uuid, "action": "new", "conn_id": 1})),
            // Authed without an open record: the other insert of audit_conn.
            ("audit_conn", "/api/audit/conn", json!({"id": "111", "uuid": uuid, "conn_id": 2, "session_id": 1})),
            ("audit_file", "/api/audit/file", file_body("111", Some(UUID), None)),
            ("audit_alarm", "/api/audit/alarm", json!({"id": "111", "uuid": uuid, "typ": 0})),
        ];
        for (table, path, body) in reports {
            sqlx::query(&format!("delete from {table}")).execute(db).await.unwrap();
            for id in [2, 3, MAX_ROWS + 1] {
                // Every audit table has these columns (`conn_id` and `typ` are only required in some).
                let cols = match table {
                    "audit_alarm" => "id, device_id, typ, created_at",
                    _ => "id, device_id, conn_id, created_at",
                };
                sqlx::query(&format!("insert into {table}({cols}) values(?, 'x', 0, 0)"))
                    .bind(id)
                    .execute(db)
                    .await
                    .unwrap();
            }
            ok(&t.app, path, body).await;
            // The new row gets MAX_ROWS + 2: ids 3 ..= MAX_ROWS + 2 are the newest MAX_ROWS.
            let ids: Vec<i64> = sqlx::query_scalar(&format!("select id from {table} order by id"))
                .fetch_all(db)
                .await
                .unwrap();
            assert_eq!(ids, [3, MAX_ROWS + 1, MAX_ROWS + 2], "{table} via {path}");
        }
    }

    #[tokio::test]
    async fn old_rows_are_purged() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let now = 1_800_000_000;
        for table in TABLES {
            // Created 180 days + 1 s before `now`, exactly 180 days before, and recently.
            for created_at in [now - RETENTION_SECS - 1, now - RETENTION_SECS, now - 1] {
                let cols = match table {
                    "audit_alarm" => "device_id, typ, created_at",
                    _ => "device_id, conn_id, created_at",
                };
                sqlx::query(&format!("insert into {table}({cols}) values('x', 0, ?)"))
                    .bind(created_at)
                    .execute(db)
                    .await
                    .unwrap();
            }
            assert_eq!(purge(db, table, now).await.unwrap(), 1, "{table}");
            let left: Vec<i64> = sqlx::query_scalar(&format!("select created_at from {table} order by id"))
                .fetch_all(db)
                .await
                .unwrap();
            assert_eq!(left, [now - RETENTION_SECS, now - 1], "{table}");
            assert_eq!(purge(db, table, now).await.unwrap(), 0, "{table}");
        }
    }

    #[tokio::test]
    async fn conn_lifecycle_and_note() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111").await;
        let uuid = base64::encode(UUID);
        let big: u64 = 12345678901234567890; // > i64::MAX
        let conn = |extra: Value| {
            let mut v = json!({"id": "111", "uuid": uuid, "conn_id": 1234, "nonce": nonce()});
            v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            v
        };
        type Row = (i64, String, String, String, String, Option<i64>, String, String, Option<i64>, Option<i64>);
        let rows = || async {
            sqlx::query_as::<_, Row>(
                "select conn_id, session_id, peer_id, peer_name, ip, conn_type, auth, note, authed_at, closed_at
                 from audit_conn order by id",
            )
            .fetch_all(db)
            .await
            .unwrap()
        };

        // An earlier connection with the same conn_id (before a client restart), already closed.
        ok(&t.app, "/api/audit/conn", conn(json!({"action": "new", "ip": "198.51.100.1", "session_id": 0}))).await;
        ok(&t.app, "/api/audit/conn", conn(json!({"action": "close", "session_id": 0}))).await;

        // new → authed → close.
        ok(&t.app, "/api/audit/conn", conn(json!({"action": "new", "ip": "203.0.113.5", "session_id": 0}))).await;
        let r = rows().await;
        assert_eq!(r.len(), 2);
        assert!(r[0].9.is_some());
        assert_eq!((r[1].1.as_str(), r[1].4.as_str(), r[1].8, r[1].9), ("", "203.0.113.5", None, None));

        ok(
            &t.app,
            "/api/audit/conn",
            conn(json!({"peer": ["999", "bob"], "type": 0, "primary_auth": 2, "two_factor": 1, "session_id": big})),
        )
        .await;
        let r = rows().await;
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].1, ""); // the closed one is untouched
        assert_eq!(
            (r[1].1.as_str(), r[1].2.as_str(), r[1].3.as_str(), r[1].5),
            ("12345678901234567890", "999", "bob", Some(0))
        );
        let auth: Value = serde_json::from_str(&r[1].6).unwrap();
        assert_eq!(auth, json!({"primary_auth": 2, "two_factor": 1}));
        assert!(r[1].8.is_some());

        // A file-transfer connection of the same session, whose `new` was lost: inserted on auth.
        let mut ft = conn(json!({"peer": ["999", "bob"], "type": 1, "primary_auth": 3, "session_id": big}));
        ft["conn_id"] = json!(1235);
        ok(&t.app, "/api/audit/conn", ft).await;
        let r = rows().await;
        assert_eq!(r.len(), 3);
        assert_eq!((r[2].0, r[2].1.as_str(), r[2].5, r[2].4.as_str()), (1235, "12345678901234567890", Some(1), ""));
        assert!(r[2].8.is_some());

        ok(&t.app, "/api/audit/conn", conn(json!({"action": "close", "session_id": big}))).await;
        assert!(rows().await[1].9.is_some());
        // Closing again (nothing open) is ignored.
        ok(&t.app, "/api/audit/conn", conn(json!({"action": "close", "session_id": big}))).await;
        assert_eq!(rows().await.len(), 3);

        // The controller's note: no uuid, conn_id or nonce; skips the weak check; updates both records.
        ok(&t.app, "/api/audit/conn", json!({"id": "111", "session_id": big, "note": "fixed the printer"})).await;
        let r = rows().await;
        assert_eq!((r[0].7.as_str(), r[1].7.as_str(), r[2].7.as_str()), ("", "fixed the printer", "fixed the printer"));
        // Unknown session: ignored.
        ok(&t.app, "/api/audit/conn", json!({"id": "111", "session_id": 1, "note": "x"})).await;
        assert_eq!(rows().await.len(), 3);

        // A note with a uuid is a normal report and goes through the weak check (here: authed, mismatched).
        ok(&t.app, "/api/audit/conn", json!({"id": "111", "uuid": base64::encode(b"x"), "conn_id": 9, "session_id": 5, "note": "y"})).await;
        assert_eq!(rows().await.len(), 3);
    }
}
