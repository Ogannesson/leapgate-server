//! Audit reports (PORTA.md §9.3; note 03 §5).
//! Success: 200 + empty body (`ok_empty`); internal error: 200 + `{"error"}` (`ok_internal`, the
//! client retries); bad body: 400. Handlers return `Response` so `?` cannot produce a plain 400.

use super::{device::uuid_matches, ok_empty, ok_internal, parse_json};
use crate::state::AppState;
use axum::{body::Bytes, extract::State, response::Response};
use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;
use serde_derive::Deserialize;
use serde_json::{Map, Value};
use sqlx::SqlitePool;
use std::{
    collections::HashSet,
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

/// Shared by the device-side audits: a repeated nonce is a success without writing; a failed weak
/// check answers success without writing; the nonce is registered only after `write` succeeded, so
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
/// side, or the controller's session note (`note` and no `uuid`).
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
    peer: Vec<String>,
    #[serde(rename = "type")]
    conn_type: Option<i64>,
    /// The rest (`primary_auth`, `two_factor`, `conn_audit_ref`, …), kept as `audit_conn.auth`.
    #[serde(flatten)]
    rest: Map<String, Value>,
}

/// `POST /api/audit/conn`: new / authed / close, and the controller's session note (no uuid, no nonce).
pub(crate) async fn conn(State(state): State<AppState>, body: Bytes) -> Response {
    let req: ConnReq = match parse(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    let db = &state.db;
    if let (Some(note), None) = (&req.note, &req.uuid) {
        // Session note: no identity to check; updates every record of the session (remote desktop
        // and file transfer share one session id), none matching is ignored.
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
            let peer_id = req.peer.first().map(String::as_str).unwrap_or_default();
            let peer_name = req.peer.get(1).map(String::as_str).unwrap_or_default();
            let session_id = req.session_id.to_string();
            let auth = Value::Object(req.rest.clone()).to_string();
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
    let req: FileReq = match parse(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    let write = async {
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
    let req: AlarmReq = match parse(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    let write = async {
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
    use serde_json::json;

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

        // Matching uuid, and an id hbbs does not know: stored.
        ok(&t.app, "/api/audit/file", file_body("111", Some(UUID), Some(&nonce()))).await;
        ok(&t.app, "/api/audit/file", file_body("222", None, Some(&nonce()))).await;
        let row: (String, i64, String, i64, String, bool, String) = sqlx::query_as(
            "select device_id, conn_id, peer_id, type, path, is_file, info from audit_file order by id limit 1",
        )
        .fetch_one(db)
        .await
        .unwrap();
        assert_eq!(row.0, "111");
        assert_eq!((row.1, row.2.as_str(), row.3, row.4.as_str(), row.5), (1234, "999", 1, "C:\\x", false));
        assert!(row.6.starts_with("{\"ip\""));
        assert_eq!(count(db, "audit_file").await, 2);

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

        // Same nonce twice: stored once, both answered with an empty body.
        let n = nonce();
        ok(&t.app, "/api/audit/file", file_body("1", None, Some(&n))).await;
        ok(&t.app, "/api/audit/file", file_body("1", None, Some(&n))).await;
        assert_eq!(count(db, "audit_file").await, 1);

        // No nonce (1.4.x) or an empty one: never deduplicated.
        ok(&t.app, "/api/audit/file", file_body("1", None, None)).await;
        ok(&t.app, "/api/audit/file", file_body("1", None, None)).await;
        ok(&t.app, "/api/audit/file", file_body("1", None, Some(""))).await;
        ok(&t.app, "/api/audit/file", file_body("1", None, Some(""))).await;
        assert_eq!(count(db, "audit_file").await, 5);

        // A failed write answers 200 + {"error"} and does not register the nonce, so the retry is stored.
        sqlx::query("alter table audit_file rename to audit_file_away").execute(db).await.unwrap();
        let n = nonce();
        let (status, ct, body) = send(&t.app, "POST", "/api/audit/file", None, &file_body("1", None, Some(&n)).to_string()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json; charset=utf-8");
        assert_eq!(&body[..], br#"{"error":"Server error"}"#);
        sqlx::query("alter table audit_file_away rename to audit_file").execute(db).await.unwrap();
        ok(&t.app, "/api/audit/file", file_body("1", None, Some(&n))).await;
        assert_eq!(count(db, "audit_file").await, 6);
    }

    #[tokio::test]
    async fn long_nonce_is_no_nonce() {
        let t = testutil::app().await;
        let db = &t.state.db;
        // 64 bytes still deduplicates; 65 is treated as absent: stored every time, never registered.
        let (fits, long) = ("n".repeat(MAX_NONCE_LEN), "l".repeat(MAX_NONCE_LEN + 1));
        for _ in 0..2 {
            ok(&t.app, "/api/audit/file", file_body("1", None, Some(&fits))).await;
            ok(&t.app, "/api/audit/file", file_body("1", None, Some(&long))).await;
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
