//! Audit reports (PORTA.md §9.3; note 03 §5).
//! Success: 200 + empty body (`ok_empty`); internal error or over the source's report budget: 200 +
//! `{"error"}` (`ok_internal`, `admit`; the client retries); bad body: 400. Handlers return
//! `Response` so `?` cannot produce a plain 400.
//! The Porta clients' signed audits (`porta_*`, phase 3 contract 01 §3.7) write the same way:
//! signed 200 + `{"api":1}`, 503 on a failed write.

use super::{
    devauth::{parse_body, porta_internal, signed_json, SignedBody},
    device::{report_allowed, uuid_matches, UuidCheck},
    ok_empty, ok_error, ok_internal, parse_json, ClientIp,
};
use crate::{conn_tracker::clip, peer::MAX_PEER_ID_LEN, state::AppState};
use axum::{body::Bytes, extract::State, http::StatusCode, response::Response};
use once_cell::sync::Lazy;
use serde::de::{DeserializeOwned, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde_derive::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    collections::HashSet,
    fmt,
    future::Future,
    net::IpAddr,
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
/// Records of a session the controller's note updates for each connection type (`NOTE_TYPES`), the
/// newest first. One session id is shared by the remote desktop connection and those opened from its
/// toolbar (file transfer, camera, TCP tunnel, terminal: rustdesk@bd92623:src/client.rs `ConnToken`),
/// each again after a reconnect; and a TCP tunnel without multiplexing (1.4.x, or either side
/// without it) connects and logs in again for every local connection it accepts
/// (rustdesk@bd92623:src/port_forward.rs `listen`, `Claim::Legacy`), a record each, so a browser
/// through it soon has tens. Counted per type, so these never crowd out the remote desktop's record
/// (review E-5); within a type, more than this many records (reconnects, or the local connections
/// of such a tunnel) leaves the oldest of that type without the note. 4, not 8: one note rewrites up to 6 × this many rows (each taking the 4 KB note) in the
/// write lock, 24 rows (~1 ms, see `note_updates_only_the_newest_records`), three times the 8 it was
/// before the split rather than six.
const NOTE_ROWS: i64 = 4;
/// The connection types the note picks records of (`NOTE_ROWS` each): what the controlled side
/// reports as `type` (rustdesk@bd92623:src/server/connection.rs `AuthConnType`: 0 remote desktop,
/// 1 file transfer, 2 port forward, 3 camera, 4 terminal), and no type (an authed report that left
/// it out; upstream always sends it). A record whose authed report was lost keeps session_id '' and
/// is never noted either way. Other values, which no client sends, never get a note.
const NOTE_TYPES: [&str; 6] = ["= 0", "= 1", "= 2", "= 3", "= 4", "is null"];
/// The note's update, `?1` note, `?2` device, `?3` session, `?4` `NOTE_ROWS`: one arm per type in
/// `NOTE_TYPES`, each an exact range on `audit_conn_session_dev(session_id, device_id, conn_type)`
/// read backwards that stops after `NOTE_ROWS` (migration 0003). One statement, so a single write.
/// Not `group by conn_type` or `conn_type is not 2`: those read every record of the session, which
/// anyone can make 20,000 of.
static NOTE_SQL: Lazy<String> = Lazy::new(|| {
    let arms: Vec<String> = NOTE_TYPES
        .iter()
        .map(|t| {
            format!(
                "select id from (select id from audit_conn
                   where session_id = ?3 and device_id = ?2 and conn_type {t} order by id desc limit ?4)"
            )
        })
        .collect();
    format!("update audit_conn set note = ?1 where id in ({})", arms.join(" union all "))
});
/// Rows created longer ago than this are deleted by the hourly purge.
const RETENTION_SECS: i64 = 180 * 24 * 3600;
/// Rows the retention purge deletes per statement: each statement holds the write lock (shared
/// with hbbs's registrations and every API write) for one short batch, not for the whole backlog.
const PURGE_BATCH: i64 = 1_000;
/// Pause between two batches of the purge, and before each table's (`conn_tracker`'s hourly
/// purge). Waiting writers retry on SQLite's busy handler (sleeps of 1, 2, 5, … 100 ms) and do not
/// queue, so they almost never hit the microseconds between two statements: without a pause the
/// write lock stayed taken for the whole backlog and hbbs's writes (200 ms `busy_timeout`) failed
/// (review D-10, measured: with 20 ms every probe write got in, waiting 79 ms at most).
pub(crate) const PURGE_PAUSE: Duration = Duration::from_millis(20);

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

/// The source's report budget (`report_allowed`), then the body. Over the budget: 200 + `{"error"}`,
/// nothing parsed or written; the client retries it like an internal error (10 s and 30 s later).
fn admit<T: DeserializeOwned>(ip: IpAddr, body: &[u8]) -> Result<T, Response> {
    if !report_allowed(ip) {
        return Err(ok_error("Too many requests"));
    }
    parse_json(body).map_err(|e| e.0)
}

/// Makes room for one more row in `table` (one of `TABLES`): deletes the rows `MAX_ROWS - 1` ids or
/// more below the newest, so with the insert that follows at most `MAX_ROWS` are left. Ids only grow
/// (a new rowid is the largest + 1), so this is a range on the primary key that deletes nothing or
/// one row. Done on every insert, not by the hourly purge: the reports are only rate limited per
/// source (`report_allowed`), so an hour of them is not bounded. Runs before the insert, so a
/// failure leaves nothing that the client's retry would duplicate.
async fn make_room(db: &SqlitePool, table: &str) -> Result<(), sqlx::Error> {
    sqlx::query(&format!("delete from {table} where id <= (select max(id) from {table}) - ?"))
        .bind(MAX_ROWS - 1)
        .execute(db)
        .await?;
    Ok(())
}

/// Hourly, from `conn_tracker`'s purge: deletes the rows of `table` (one of `TABLES`) created more
/// than `RETENTION_SECS` before `now` (unix seconds), `PURGE_BATCH` rows per statement, with
/// `PURGE_PAUSE` between two so other writers get the write lock in between. A range on
/// the `created_at` index (migration 0002; review C-16: `created_at` sits after the 4 KB text
/// columns, so without it every purge read the whole table's overflow pages in the write lock).
pub(crate) async fn purge(db: &SqlitePool, table: &str, now: i64) -> Result<u64, sqlx::Error> {
    let sql = format!("delete from {table} where id in (select id from {table} where created_at < ? limit ?)");
    let mut deleted = 0;
    loop {
        let n = sqlx::query(&sql)
            .bind(now - RETENTION_SECS)
            .bind(PURGE_BATCH)
            .execute(db)
            .await?
            .rows_affected();
        deleted += n;
        if n < PURGE_BATCH as u64 {
            return Ok(deleted);
        }
        hbb_common::tokio::time::sleep(PURGE_PAUSE).await;
    }
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

/// Who sent a device-side audit.
enum Identity<'a> {
    /// A compatibility report: passes on `uuid_matches` giving `Match` only (an unregistered id, a
    /// wrong uuid, or a device whose key is pinned is skipped).
    Compat { uuid: Option<&'a str> },
    /// A Porta report whose signature verified (`SignedBody`): nothing more to check.
    Verified,
}

enum ReportOutcome {
    Written,
    /// A repeated nonce, or the compatibility identity check failed: nothing written.
    Skipped,
    /// Nothing written and the nonce not registered, so the client's retry gets stored.
    Failed(sqlx::Error),
}

/// Shared by the device-side audits of both paths, which share the nonce table too (a record that
/// arrives on both is stored once): a repeated nonce is skipped; then the identity; the nonce is
/// registered only after `write` succeeded. No nonce (1.4.x), `""` or one longer than
/// `MAX_NONCE_LEN`: no dedupe.
async fn report(
    db: &SqlitePool,
    id: &str,
    identity: Identity<'_>,
    nonce: Option<&str>,
    write: impl Future<Output = Result<(), sqlx::Error>>,
) -> ReportOutcome {
    let nonce = nonce.filter(|n| !n.is_empty() && n.len() <= MAX_NONCE_LEN);
    if nonce.is_some_and(nonce_seen) {
        return ReportOutcome::Skipped;
    }
    if let Identity::Compat { uuid } = identity {
        match uuid_matches(db, id, uuid).await {
            Ok(UuidCheck::Match) => {}
            Ok(_) => return ReportOutcome::Skipped,
            Err(err) => return ReportOutcome::Failed(err),
        }
    }
    if let Err(err) = write.await {
        return ReportOutcome::Failed(err);
    }
    if let Some(nonce) = nonce {
        remember_nonce(nonce);
    }
    ReportOutcome::Written
}

/// A compatibility audit's answer: 200 + empty body, or 200 + `{"error"}` (the client retries).
fn compat_answer(outcome: ReportOutcome) -> Response {
    match outcome {
        ReportOutcome::Written | ReportOutcome::Skipped => ok_empty(),
        ReportOutcome::Failed(err) => ok_internal(err),
    }
}

/// A Porta audit's answer: signed 200 + `{"api":1}`, or 503 (the client retries).
fn porta_answer(state: &AppState, signed: &SignedBody, outcome: ReportOutcome) -> Response {
    match outcome {
        ReportOutcome::Written | ReportOutcome::Skipped => {
            signed_json(state, &signed.sig, StatusCode::OK, &serde_json::json!({ "api": 1 }))
        }
        ReportOutcome::Failed(err) => porta_internal(err),
    }
}

/// `/api/audit/conn` body (note 03 §5.2): new / authed (no `action`) / close from the controlled
/// side, or the controller's session note (`note` and no `uuid`). Only the fields below are built;
/// serde skips any other key without keeping it (review C-9: a flattened catch-all map turned a
/// 2 MB body into ~80 MB of `Value`s, before any identity check).
#[derive(Deserialize)]
struct ConnReq {
    /// Missing: `""`, which no registered device has. On the Porta path the signed id replaces it.
    #[serde(default)]
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
pub(crate) async fn conn(State(state): State<AppState>, ClientIp(ip): ClientIp, body: Bytes) -> Response {
    let mut req: ConnReq = match admit(ip, &body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    clip_conn(&mut req);
    let db = &state.db;
    if let (Some(note), None) = (&req.note, &req.uuid) {
        // Session note: no identity to check; updates the newest `NOTE_ROWS` records of the session
        // of each connection type, none matching is ignored. Never inserts, so it cannot add rows;
        // the limit bounds what one request rewrites (review D-5: anyone can make up 20,000 rows of
        // one session).
        return match sqlx::query(&NOTE_SQL)
            .bind(note)
            .bind(&req.id)
            .bind(req.session_id.to_string())
            .bind(NOTE_ROWS)
            .execute(db)
            .await
        {
            Ok(_) => ok_empty(),
            Err(err) => ok_internal(err),
        };
    }
    let identity = Identity::Compat { uuid: req.uuid.as_deref() };
    compat_answer(conn_inner(db, &req, identity).await)
}

/// `POST /api/porta/v1/audit/conn`: new / authed / close of a signed device; no note branch (a `note`
/// key is ignored).
pub(crate) async fn porta_conn(State(state): State<AppState>, signed: SignedBody) -> Response {
    let mut req: ConnReq = match parse_body(&signed.body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    req.id.clone_from(&signed.id);
    clip_conn(&mut req);
    let outcome = conn_inner(&state.db, &req, Identity::Verified).await;
    porta_answer(&state, &signed, outcome)
}

fn clip_conn(req: &mut ConnReq) {
    if let Some(note) = &mut req.note {
        clip(note, MAX_TEXT_LEN);
    }
    clip(&mut req.ip, MAX_IP_LEN);
    for (field, max) in req.peer.0.iter_mut().zip([MAX_PEER_ID_LEN, MAX_PEER_NAME_LEN]) {
        clip(field, max);
    }
}

async fn conn_inner(db: &SqlitePool, req: &ConnReq, identity: Identity<'_>) -> ReportOutcome {
    report(db, &req.id, identity, req.nonce.as_deref(), write_conn(db, req)).await
}

/// The latest record of a connection still open, `?` device and `?` conn_id (`conn_id` restarts with
/// the client process); the authed and close reports update it. On the partial index
/// `audit_conn_open` (migration 0003), which holds the open records only: closed ones, which anyone
/// can pile up 20,000 of under one conn_id, are never read (review E-6).
const OPEN: &str = "(select max(id) from audit_conn where device_id = ? and conn_id = ? and closed_at is null)";

async fn write_conn(db: &SqlitePool, req: &ConnReq) -> Result<(), sqlx::Error> {
    let now = crate::common::now() as i64;
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
    #[serde(default)]
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
pub(crate) async fn file(State(state): State<AppState>, ClientIp(ip): ClientIp, body: Bytes) -> Response {
    let req: FileReq = match admit(ip, &body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    let uuid = req.uuid.clone();
    compat_answer(file_inner(&state.db, req, Identity::Compat { uuid: uuid.as_deref() }).await)
}

/// `POST /api/porta/v1/audit/file`.
pub(crate) async fn porta_file(State(state): State<AppState>, signed: SignedBody) -> Response {
    let mut req: FileReq = match parse_body(&signed.body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    req.id.clone_from(&signed.id);
    let outcome = file_inner(&state.db, req, Identity::Verified).await;
    porta_answer(&state, &signed, outcome)
}

async fn file_inner(db: &SqlitePool, mut req: FileReq, identity: Identity<'_>) -> ReportOutcome {
    clip(&mut req.peer_id, MAX_PEER_ID_LEN);
    clip(&mut req.path, MAX_TEXT_LEN);
    clip(&mut req.info, MAX_TEXT_LEN);
    let write = async {
        make_room(db, "audit_file").await?;
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
        .execute(db)
        .await
        .map(|_| ())
    };
    report(db, &req.id, identity, req.nonce.as_deref(), write).await
}

/// `/api/audit/alarm` body (note 03 §5.4): the field is `typ` here; unknown values are kept.
#[derive(Deserialize)]
struct AlarmReq {
    #[serde(default)]
    id: String,
    uuid: Option<String>,
    nonce: Option<String>,
    conn_id: Option<i64>,
    typ: i64,
    #[serde(default)]
    info: String,
}

/// `POST /api/audit/alarm`.
pub(crate) async fn alarm(State(state): State<AppState>, ClientIp(ip): ClientIp, body: Bytes) -> Response {
    let req: AlarmReq = match admit(ip, &body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    let uuid = req.uuid.clone();
    compat_answer(alarm_inner(&state.db, req, Identity::Compat { uuid: uuid.as_deref() }).await)
}

/// `POST /api/porta/v1/audit/alarm`.
pub(crate) async fn porta_alarm(State(state): State<AppState>, signed: SignedBody) -> Response {
    let mut req: AlarmReq = match parse_body(&signed.body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    req.id.clone_from(&signed.id);
    let outcome = alarm_inner(&state.db, req, Identity::Verified).await;
    porta_answer(&state, &signed, outcome)
}

async fn alarm_inner(db: &SqlitePool, mut req: AlarmReq, identity: Identity<'_>) -> ReportOutcome {
    clip(&mut req.info, MAX_TEXT_LEN);
    let write = async {
        make_room(db, "audit_alarm").await?;
        sqlx::query("insert into audit_alarm(device_id, conn_id, typ, info, created_at) values(?, ?, ?, ?, ?)")
            .bind(&req.id)
            .bind(req.conn_id)
            .bind(req.typ)
            .bind(&req.info)
            .bind(crate::common::now() as i64)
            .execute(db)
            .await
            .map(|_| ())
    };
    report(db, &req.id, identity, req.nonce.as_deref(), write).await
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

    /// Review C-9: a big body, made of an unknown key's big array and a long `peer`, parses into the
    /// known fields only: nothing holds the skipped elements. Parsed directly, so it may be well over
    /// the route's 64 KB limit; the RSS side, within the limit, is `audit_conn_big_body_is_not_amplified`
    /// in tests/bb_api.rs.
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

            // A backlog over several batches goes in one purge; the recent rows stay.
            let backlog = 2 * PURGE_BATCH + 5;
            sqlx::query(&format!(
                "with recursive n(i) as (select 1 union all select i + 1 from n where i < ?)
                 insert into {table}({cols}) select 'x', 0, ? from n",
                cols = if table == "audit_alarm" { "device_id, typ, created_at" } else { "device_id, conn_id, created_at" },
            ))
            .bind(backlog)
            .bind(now - RETENTION_SECS - 1)
            .execute(db)
            .await
            .unwrap();
            assert_eq!(purge(db, table, now).await.unwrap(), backlog as u64, "{table}");
            assert_eq!(count(db, table).await, 2, "{table}");
        }
    }

    /// Review C-16: the retention purge is a range on the `created_at` index (migration 0002), not a
    /// scan of the table and its overflow pages.
    #[tokio::test]
    async fn purge_uses_the_created_at_index() {
        let t = testutil::app().await;
        for table in TABLES {
            let sql = format!("delete from {table} where id in (select id from {table} where created_at < 1 limit 1000)");
            let plan = crate::api::device::query_plan(&t.state.db, &sql).await;
            eprintln!("{table} purge: {plan:?}");
            assert!(plan.iter().any(|l| l == &format!("SEARCH {table} USING COVERING INDEX {table}_created (created_at<?)")), "{plan:?}");
            assert!(!plan.iter().any(|l| l.starts_with("SCAN")), "{plan:?}");
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

    /// The note's plan: each arm of `NOTE_SQL` is an exact range on `audit_conn_session_dev`, no scan
    /// of the table and no sort.
    async fn assert_note_plan(db: &SqlitePool) {
        let sql = NOTE_SQL.replace("?1", "'x'").replace("?2", "'1'").replace("?3", "'7'").replace("?4", "4");
        let plan = crate::api::device::query_plan(db, &sql).await;
        eprintln!("note: {plan:#?}");
        let index = "SEARCH audit_conn USING COVERING INDEX audit_conn_session_dev (session_id=? AND device_id=? AND conn_type=?)";
        assert_eq!(plan.iter().filter(|l| *l == index).count(), NOTE_TYPES.len(), "{plan:#?}");
        assert!(!plan.iter().any(|l| l.starts_with("SCAN audit_conn") || l.contains("TEMP B-TREE")), "{plan:#?}");
    }

    /// The ids of `device`'s records of session '7' the note should update: the newest `NOTE_ROWS` of
    /// each type in `NOTE_TYPES`, newest first.
    async fn newest_of_each_type(db: &SqlitePool, device: &str) -> Vec<i64> {
        let mut ids = Vec::new();
        for typ in [Some(0), Some(1), Some(2), Some(3), Some(4), None::<i64>] {
            let of_type: Vec<i64> = sqlx::query_scalar(
                "select id from audit_conn where device_id = ? and session_id = '7' and conn_type is ? order by id desc limit ?",
            )
            .bind(device)
            .bind(typ)
            .bind(NOTE_ROWS)
            .fetch_all(db)
            .await
            .unwrap();
            ids.extend(of_type);
        }
        ids.sort_unstable_by(|a, b| b.cmp(a));
        ids
    }

    /// Review D-5: the unauthenticated note rewrites at most `NOTE_ROWS` records of each type, the
    /// newest, however many a made-up device piled up in one session; picking them is a range on an
    /// index.
    #[tokio::test]
    async fn note_updates_only_the_newest_records() {
        let t = testutil::app().await;
        let db = &t.state.db;
        // MAX_ROWS records of one session with a 4 KB auth each (rewriting them all took ~1 s), of
        // every type the note picks, an unknown one (9) among them; and as many of the same session
        // id under another device.
        let auth = "a".repeat(MAX_TEXT_LEN);
        for device in ["111", "999"] {
            sqlx::query(
                "with recursive n(i) as (select 1 union all select i + 1 from n where i < ?)
                 insert into audit_conn(device_id, conn_id, session_id, conn_type, auth, created_at)
                 select ?, i, '7', case i % 7 when 5 then null when 6 then 9 else i % 7 end, ?, 0 from n",
            )
            .bind(MAX_ROWS)
            .bind(device)
            .bind(&auth)
            .execute(db)
            .await
            .unwrap();
        }
        let newest = newest_of_each_type(db, "111").await;
        assert_eq!(newest.len(), NOTE_TYPES.len() * NOTE_ROWS as usize);
        // A device of the session, then one that has none of its records.
        for id in ["111", "222"] {
            let start = Instant::now();
            ok(&t.app, "/api/audit/conn", json!({"id": id, "session_id": 7, "note": "n".repeat(MAX_TEXT_LEN)})).await;
            let took = start.elapsed();
            eprintln!("note for {id}: {took:?}");
            let noted: Vec<i64> = sqlx::query_scalar("select id from audit_conn where note != '' order by id desc")
                .fetch_all(db)
                .await
                .unwrap();
            assert_eq!(noted, newest, "{id}");
            assert!(took < Duration::from_millis(200), "note for {id} took {took:?}");
        }
        assert_note_plan(db).await;
    }

    /// Review E-5: a 1.4.x TCP tunnel opened from the remote desktop's toolbar logs in again for
    /// every local connection, each a record of the same session; the remote desktop's record,
    /// older than all of them, still gets the note.
    #[tokio::test]
    async fn note_reaches_the_remote_desktop_behind_many_tunnel_records() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111").await;
        let uuid = base64::encode(UUID);
        let authed = |conn_id: i64, typ: i64| {
            json!({"id": "111", "uuid": uuid, "conn_id": conn_id, "session_id": 7, "type": typ, "peer": ["999", "bob"]})
        };
        ok(&t.app, "/api/audit/conn", authed(1, 0)).await;
        ok(&t.app, "/api/audit/conn", authed(2, 1)).await;
        for conn_id in 3..18 {
            ok(&t.app, "/api/audit/conn", authed(conn_id, 2)).await;
        }
        ok(&t.app, "/api/audit/conn", json!({"id": "111", "session_id": 7, "note": "fixed the printer"})).await;
        let rows: Vec<(i64, i64, String)> = sqlx::query_as("select conn_id, conn_type, note from audit_conn order by id")
            .fetch_all(db)
            .await
            .unwrap();
        assert_eq!(rows.len(), 17);
        let noted: Vec<i64> = rows.iter().filter(|r| r.2 == "fixed the printer").map(|r| r.0).collect();
        // The remote desktop, the file transfer, and the newest NOTE_ROWS tunnel connections.
        let mut want = vec![1, 2];
        want.extend(18 - NOTE_ROWS..18);
        assert_eq!(noted, want);
        assert_note_plan(db).await;
    }

    /// Review E-6: the authed and close reports find the open record on the partial index
    /// `audit_conn_open`, so closed records piled up under the same conn_id (20,000 with a 4 KB auth
    /// each: ~20 ms in the write lock per report on `(device_id, conn_id)`) are never read.
    #[tokio::test]
    async fn open_record_is_found_on_the_partial_index() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111").await;
        let uuid = base64::encode(UUID);
        // As the close report runs it. Not a covering index (SQLite still reads `closed_at` in the
        // table), but `max(id)` reads the newest entry of the range, an open record, and stops.
        let sql = format!("update audit_conn set closed_at = 1 where id = {}", OPEN.replacen('?', "'1'", 1).replacen('?', "7", 1));
        let plan = crate::api::device::query_plan(db, &sql).await;
        eprintln!("open: {plan:?}");
        assert!(
            plan.iter().any(|l| l == "SEARCH audit_conn USING INDEX audit_conn_open (device_id=? AND conn_id=?)"),
            "{plan:?}"
        );
        assert!(!plan.iter().any(|l| l.starts_with("SCAN audit_conn")), "{plan:?}");

        sqlx::query(
            "with recursive n(i) as (select 1 union all select i + 1 from n where i < ?)
             insert into audit_conn(device_id, conn_id, auth, created_at, closed_at) select '111', 7, ?, 0, 0 from n",
        )
        .bind(MAX_ROWS)
        .bind("a".repeat(MAX_TEXT_LEN))
        .execute(db)
        .await
        .unwrap();
        let close = json!({"id": "111", "uuid": uuid, "conn_id": 7, "action": "close"});
        // Nothing open: the attack's case, which updates nothing.
        let start = Instant::now();
        ok(&t.app, "/api/audit/conn", close.clone()).await;
        let took = start.elapsed();
        eprintln!("close with nothing open behind {MAX_ROWS} closed records: {took:?}");
        assert!(took < Duration::from_millis(200), "{took:?}");
        // An open record behind them is still found, authed and closed.
        ok(&t.app, "/api/audit/conn", json!({"id": "111", "uuid": uuid, "conn_id": 7, "action": "new"})).await;
        ok(&t.app, "/api/audit/conn", json!({"id": "111", "uuid": uuid, "conn_id": 7, "session_id": 5, "type": 0})).await;
        let start = Instant::now();
        ok(&t.app, "/api/audit/conn", close).await;
        eprintln!("close of the open record: {:?}", start.elapsed());
        let newest: (String, Option<i64>) =
            sqlx::query_as("select session_id, closed_at from audit_conn order by id desc limit 1").fetch_one(db).await.unwrap();
        assert_eq!(newest.0, "5");
        assert!(newest.1.is_some_and(|c| c > 0));
        assert_eq!(count(db, "audit_conn").await, MAX_ROWS);
    }

    // ---- Phase 3 contract 01 §3.5, §3.7 ----

    /// A device whose key is pinned: its unsigned audits are answered like a mismatch, not stored.
    #[tokio::test]
    async fn pinned_device_unsigned_audits_dropped() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111").await;
        sqlx::query("update peer set pk_pinned_at = 1 where id = '111'").execute(db).await.unwrap();
        let uuid = base64::encode(UUID);
        ok(&t.app, "/api/audit/file", file_body("111", Some(UUID), Some(&nonce()))).await;
        ok(&t.app, "/api/audit/alarm", json!({"id": "111", "uuid": uuid, "typ": 0, "info": "{}"})).await;
        ok(&t.app, "/api/audit/conn", json!({"id": "111", "uuid": uuid, "action": "new", "conn_id": 1})).await;
        for table in TABLES {
            assert_eq!(count(db, table).await, 0, "{table}");
        }
        // A body without `id` is no longer a 400: an id no device has, success shape, nothing stored.
        ok(&t.app, "/api/audit/alarm", json!({"uuid": uuid, "typ": 0})).await;
        assert_eq!(count(db, "audit_alarm").await, 0);
    }

    /// Signed 200 + `{"api":1}`.
    fn assert_porta_ok(t: &testutil::TestApp, r: &testutil::PortaResp) {
        assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(&r.body[..], br#"{"api":1}"#);
        assert!(testutil::verify_server_sig(&t.state, &r.sig, &r.headers, &r.body));
    }

    #[tokio::test]
    async fn porta_audits() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let dev = testutil::porta_device(&t.state, "pa0001", UUID).await;

        // A nonce first seen on the compatibility path (before the key is pinned) is not stored again.
        let n = nonce();
        ok(&t.app, "/api/audit/file", file_body("pa0001", Some(UUID), Some(&n))).await;
        let r = dev.post(&t.app, "audit/file", file_body("pa0001", None, Some(&n)).to_string().as_bytes()).await;
        assert_porta_ok(&t, &r);
        assert_eq!(count(db, "audit_file").await, 1);

        // The id in the body is ignored: stored under the signed one.
        let r = dev.post(&t.app, "audit/file", file_body("someone", None, Some(&nonce())).to_string().as_bytes()).await;
        assert_porta_ok(&t, &r);
        let ids: Vec<String> = sqlx::query_scalar("select device_id from audit_file").fetch_all(db).await.unwrap();
        assert_eq!(ids, ["pa0001", "pa0001"]);
        let r = dev.post(&t.app, "audit/alarm", br#"{"typ":3,"info":"x","conn_id":2}"#).await;
        assert_porta_ok(&t, &r);
        let alarm: (String, i64) = sqlx::query_as("select device_id, typ from audit_alarm").fetch_one(db).await.unwrap();
        assert_eq!(alarm, ("pa0001".into(), 3));

        // A failed write: 503, unsigned, and the nonce not registered, so the retry is stored.
        sqlx::query("alter table audit_file rename to audit_file_away").execute(db).await.unwrap();
        let n = nonce();
        let body = file_body("pa0001", None, Some(&n)).to_string();
        let r = dev.post(&t.app, "audit/file", body.as_bytes()).await;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.json()["error"], "internal");
        assert!(!r.headers.contains_key(crate::api::devauth::SIG_HEADER));
        sqlx::query("alter table audit_file_away rename to audit_file").execute(db).await.unwrap();
        // Signed a second later than the first try, as the client's retry is (the same signature
        // within one second would be a replay).
        let (auth, sig) = dev.auth("audit/file", crate::common::now() as i64 + 1, body.as_bytes());
        let (status, headers, resp) = testutil::send_porta(&t.app, "/api/porta/v1/audit/file", Some(&auth), body.as_bytes()).await;
        assert_porta_ok(&t, &testutil::PortaResp { status, headers, body: resp, sig });
        assert_eq!(count(db, "audit_file").await, 3);

        // conn: new / authed / close as on the compatibility path, and no note branch: a body with a
        // note and no uuid is an authed report like any other, and notes nothing.
        for body in [
            json!({"action": "new", "conn_id": 1, "ip": "203.0.113.5"}),
            json!({"conn_id": 1, "session_id": 77, "peer": ["999", "bob"], "type": 0}),
            json!({"note": "hi", "session_id": 77, "conn_id": 2}),
        ] {
            assert_porta_ok(&t, &dev.post(&t.app, "audit/conn", body.to_string().as_bytes()).await);
        }
        let rows: Vec<(String, i64, String, String, String)> =
            sqlx::query_as("select device_id, conn_id, session_id, peer_id, note from audit_conn order by id")
                .fetch_all(db)
                .await
                .unwrap();
        assert_eq!(
            rows,
            [
                ("pa0001".into(), 1, "77".into(), "999".into(), String::new()),
                ("pa0001".into(), 2, "77".into(), String::new(), String::new()),
            ]
        );
        // A bad body: 400, unsigned.
        let r = dev.post(&t.app, "audit/alarm", b"{").await;
        assert_eq!((r.status, &r.json()["error"]), (StatusCode::BAD_REQUEST, &json!("bad_request")));
    }
}
