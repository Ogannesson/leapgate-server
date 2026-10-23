//! Address book, the 12 endpoints of the new protocol (LEAPGATE.md §12; note 04).
//! Writes succeed with 200 + empty body only; `personal`, `settings`, `shared/profiles` never 404.

use super::{ok_empty, ok_json, parse_json, ApiError, ApiResult, CurrentUser, PageQuery, JSON};
use crate::{peer::MAX_PEER_ID_LEN, state::AppState};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
};
use hbb_common::tokio::sync::{OwnedSemaphorePermit, Semaphore};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde_derive::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::{SqliteConnection, SqlitePool};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt,
    io::Write as _,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

/// The client recognizes the personal book by this name (note 04 §6).
const PERSONAL_NAME: &str = "My address book";

/// Effective rule of user `?1` on book `a` (§12.1): 3 for the owner; otherwise the highest rule
/// granted to the user or to any of their groups (personal books have no rules); NULL = no access.
const RULE_SQL: &str = "case when a.owner_id = ?1 then 3 when a.personal = 0 then (
        select max(r.rule) from ab_rule r where r.ab_guid = a.guid
        and (r.user_id = ?1 or r.group_id in (select group_id from group_member where user_id = ?1))) end";

const READ: i64 = 1;
/// Rules 2 and 3 both allow every write of the 12 endpoints (§12.1).
const WRITE: i64 = 2;

// Write limits (§12.1): any logged-in user can write their own personal book, so without them one
// account fills the disk. Over a limit → 400 + `{"error"}`, which the client shows as a failure.
/// Peers per book. Also sent as `max_peer_one_ab`: the client stops adding at this count itself
/// (`Ab.isFull`, note 04 §3.2). The client asks for the online state of a whole tab in one
/// `OnlineRequest` on 21115, whose frames are capped at 128 KB (§6 item 8): 5000 ids of 16
/// characters are about 90 KB, so a full book still gets its online state.
pub(crate) const MAX_PEERS: i64 = 5000;
/// Tags per book (`ab_tag` rows).
const MAX_TAGS: i64 = 1000;
/// A tag name, in bytes (`tag/add`, `tag/rename`, a peer's `tags`). Control characters are refused
/// too: serde_json writes each as a 6-byte `\u00XX`, which would make the tags `cascade_tags` reads
/// in one go (up to MAX_PEERS rows) six times their byte length.
const MAX_TAG_LEN: usize = 64;
/// Tags on one peer.
pub(crate) const MAX_PEER_TAGS: usize = 64;
/// A peer's `data` column as stored (serialized JSON, after `peer/update` merges into it).
const MAX_DATA_LEN: usize = 8 << 10;
/// JSON nodes in a peer's `data` (every key and every value, nested arrays and objects counted
/// through). Parsed into `serde_json::Value`s a row takes about ten times its bytes for tiny keys
/// and values; `/api/ab/peers` parses one row at a time, but `peer/update` merges into a parsed row.
/// The client's own peer (`Peer.toJson`, flutter/lib/models/peer_model.dart) has 11 data keys,
/// i.e. 22 nodes.
const MAX_DATA_NODES: usize = 64;
/// The `hash`/`password` the client uploads, before encryption. Control characters are refused,
/// as in tag names: each would be written back as a 6-byte `\u00XX`.
const MAX_SECRET_LEN: usize = 1 << 10;

/// Must be strings when given (§12.1); `same_server` must be a bool.
const STRING_FIELDS: [&str; 10] = [
    "alias",
    "note",
    "username",
    "hostname",
    "platform",
    "rdpPort",
    "rdpUsername",
    "loginName",
    "device_group_name",
    "forceAlwaysRelay",
];

/// Checks that `user` has at least rule `need` on book `guid`; returns whether it is a personal book.
/// Unknown book or no access → 403.
async fn check(db: &SqlitePool, user: &CurrentUser, guid: &str, need: i64) -> Result<bool, ApiError> {
    let row = sqlx::query_as::<_, (bool, Option<i64>)>(&format!(
        "select a.personal, {RULE_SQL} from ab a where a.guid = ?2"
    ))
    .bind(user.id)
    .bind(guid)
    .fetch_optional(db)
    .await?;
    match row {
        Some((personal, Some(rule))) if rule >= need => Ok(personal),
        Some((_, Some(_))) => Err(ApiError::forbidden("Read-only address book")),
        _ => Err(ApiError::forbidden("No permission to access this address book")),
    }
}

fn not_found(msg: &str) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, msg)
}

/// `POST /api/ab/personal`: `{"guid": …}`, creating the personal book on first use.
pub(crate) async fn personal(State(state): State<AppState>, user: CurrentUser) -> ApiResult {
    let select = || {
        sqlx::query_scalar::<_, String>("select guid from ab where owner_id = ? and personal = 1")
            .bind(user.id)
            .fetch_optional(&state.db)
    };
    let guid = match select().await? {
        Some(guid) => guid,
        None => {
            let now = crate::common::now() as i64;
            // A concurrent first call may have created it: keep that one.
            sqlx::query(
                "insert into ab(guid, name, owner_id, personal, created_at, updated_at) values(?, ?, ?, 1, ?, ?)
                 on conflict do nothing",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(PERSONAL_NAME)
            .bind(user.id)
            .bind(now)
            .bind(now)
            .execute(&state.db)
            .await?;
            select().await?.ok_or_else(|| ApiError::internal("personal address book missing after insert"))?
        }
    };
    Ok(ok_json(&serde_json::json!({ "guid": guid })))
}

/// `POST /api/ab/settings`: `{"max_peer_one_ab": MAX_PEERS}`.
pub(crate) async fn settings(State(_state): State<AppState>, _user: CurrentUser) -> ApiResult {
    Ok(ok_json(&serde_json::json!({ "max_peer_one_ab": MAX_PEERS })))
}

#[derive(Serialize)]
struct Profile {
    guid: String,
    name: String,
    /// Owner's user name.
    owner: String,
    note: String,
    /// Effective rule of the current user.
    rule: i64,
    info: Value,
}

/// `POST /api/ab/shared/profiles?current=&pageSize=`.
pub(crate) async fn shared_profiles(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(page): Query<PageQuery>,
) -> ApiResult {
    let rows = sqlx::query_as::<_, (String, String, String, String, i64)>(&format!(
        "select * from (select a.guid, a.name, u.name, a.note, {RULE_SQL} as rule
         from ab a join user u on u.id = a.owner_id where a.personal = 0)
         where rule is not null order by 2"
    ))
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    let total = rows.len();
    let (offset, limit) = page.offset_limit();
    let data: Vec<Profile> = rows
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|(guid, name, owner, note, rule)| Profile {
            guid,
            name,
            owner,
            note,
            rule,
            info: Value::Object(Map::new()),
        })
        .collect();
    Ok(ok_json(&serde_json::json!({ "total": total, "data": data })))
}

/// `POST /api/ab/peers?current=&pageSize=&ab=<guid>`.
pub(crate) async fn peers(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(page): Query<PageQuery>,
) -> ApiResult {
    let guid = page.ab.as_deref().unwrap_or_default();
    let personal = check(&state.db, &user, guid, READ).await?;
    // Waits in line; the request timeout (20 s, §9.4) bounds the wait.
    let slots = state.ab_pages.acquire(user.id).await?;
    let total: i64 = sqlx::query_scalar("select count(*) from ab_peer where ab_guid = ?")
        .bind(guid)
        .fetch_one(&state.db)
        .await?;
    let (offset, limit) = page.offset_limit();
    let rows = sqlx::query_as::<_, (String, String, String, String)>(
        "select id, data, tags, case when ? then hash_enc else password_enc end from ab_peer
         where ab_guid = ? order by id limit ? offset ?",
    )
    .bind(personal)
    .bind(guid)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    // Personal books carry the password hash, shared books the plain password.
    let secret_key = if personal { "hash" } else { "password" };
    // One row parsed at a time and serialized straight into the response, never a page of `Value`s
    // (review C-14). The stored columns are about the output's size (the secret is smaller decrypted
    // than encrypted), so this capacity is not outgrown.
    let capacity = rows.iter().map(|(i, d, t, s)| i.len() + d.len() + t.len() + s.len() + 32).sum::<usize>() + 64;
    let mut out = Vec::with_capacity(capacity);
    write!(out, r#"{{"total":{total},"data":["#).map_err(ApiError::internal)?;
    for (n, (id, fields, tags, secret)) in rows.into_iter().enumerate() {
        let mut peer: Map<String, Value> = serde_json::from_str(&fields).map_err(ApiError::internal)?;
        peer.insert("id".to_owned(), Value::String(id.clone()));
        peer.insert("tags".to_owned(), serde_json::from_str(&tags).map_err(ApiError::internal)?);
        // A value that does not decrypt (lost or replaced leapgate_secret.key, corrupt row) only loses
        // that password: the key is omitted ("no saved password") and the rest of the book still lists.
        match state.secret.decrypt(&secret) {
            Ok(plain) if !plain.is_empty() => {
                peer.insert(secret_key.to_owned(), Value::String(plain));
            }
            Ok(_) => {}
            Err(err) => {
                hbb_common::log::warn!("Address book {guid}, peer {id}: {secret_key} omitted: {err}")
            }
        }
        if n > 0 {
            out.push(b',');
        }
        serde_json::to_writer(&mut out, &peer).map_err(ApiError::internal)?;
    }
    out.extend_from_slice(b"]}");
    let body = PageBody {
        rest: Bytes::from_owner(PageBuf { buf: out, _slots: slots }),
    };
    Ok(([(header::CONTENT_TYPE, JSON)], axum::body::Body::new(body)).into_response())
}

/// `/api/ab/peers` pages built or being sent at once, from all users (review C-14); more wait in
/// line. A page of 1000 of the largest rows peaks at ~36 MB while built (rows read + response) and
/// holds ~18 MB until sent, so at most ~8 × 36 MB; the client asks for 100 rows, a tenth of that.
/// The slots go with the page's bytes (`PageBuf`): a client that reads slowly or not at all keeps
/// them until the socket's write floor or no-progress timeout drops the connection (§9.4,
/// `listen.rs`), so a per-handler limit would not bound this memory.
pub(crate) const MAX_PAGES: usize = 8;
/// Of those, pages one user has built or being sent at once (review D-4): a user reading slowly
/// holds up only their own requests, not everyone's. Their next request waits in line, within the
/// request timeout. The client fetches one page at a time.
const MAX_USER_PAGES: usize = 2;
/// A page goes to hyper in frames of this size: it asks for the next one when the previous is
/// written out, so the page is not copied into hyper's write queue whole.
const PAGE_FRAME: usize = 64 * 1024;

/// The `/api/ab/peers` slots (`AppState::ab_pages`): `MAX_PAGES` in all, `MAX_USER_PAGES` per user.
pub(crate) struct PageSlots {
    all: Arc<Semaphore>,
    /// Per user with a page built, being sent or waiting: their slots and how many requests hold
    /// or wait for one. A user's key goes with the last, so this holds only users with pages.
    users: Mutex<HashMap<i64, (Arc<Semaphore>, usize)>>,
}

impl PageSlots {
    pub(crate) fn new() -> Self {
        Self {
            all: Arc::new(Semaphore::new(MAX_PAGES)),
            users: Default::default(),
        }
    }

    /// One of `user`'s slots, then one of all; both wait in line (the request timeout bounds it).
    async fn acquire(self: &Arc<Self>, user: i64) -> Result<(UserSlot, OwnedSemaphorePermit), ApiError> {
        let sem = {
            let mut users = self.users.lock().unwrap();
            let entry = users.entry(user).or_insert_with(|| (Arc::new(Semaphore::new(MAX_USER_PAGES)), 0));
            entry.1 += 1;
            entry.0.clone()
        };
        // Counted before waiting, so a request dropped while it waits (request timeout) still
        // takes its count back.
        let mut slot = UserSlot {
            slots: self.clone(),
            user,
            sem,
            held: false,
        };
        slot.sem.acquire().await.map_err(ApiError::internal)?.forget();
        slot.held = true;
        let all = self.all.clone().acquire_owned().await.map_err(ApiError::internal)?;
        Ok((slot, all))
    }

    /// (Free slots of `MAX_PAGES`, users with a page in flight.)
    #[cfg(test)]
    pub(crate) fn free(&self) -> (usize, usize) {
        (self.all.available_permits(), self.users.lock().unwrap().len())
    }
}

/// A request's place among one user's `MAX_USER_PAGES`, waiting or (`held`) holding a slot.
struct UserSlot {
    slots: Arc<PageSlots>,
    user: i64,
    sem: Arc<Semaphore>,
    held: bool,
}

impl Drop for UserSlot {
    fn drop(&mut self) {
        if self.held {
            self.sem.add_permits(1);
        }
        let mut users = self.slots.users.lock().unwrap();
        if let Some(entry) = users.get_mut(&self.user) {
            entry.1 -= 1;
            if entry.1 == 0 {
                users.remove(&self.user);
            }
        }
    }
}

/// A page's bytes with its slots. Every frame cut from it shares this allocation, so the slots go
/// back with the memory: when the last frame is written out or the connection drops (review D-3:
/// hyper drops the body as soon as it takes the last frame, up to ~80 KB of the page still queued).
struct PageBuf {
    buf: Vec<u8>,
    _slots: (UserSlot, OwnedSemaphorePermit),
}

impl AsRef<[u8]> for PageBuf {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

/// A page's response body, cut into `PAGE_FRAME` frames.
struct PageBody {
    rest: Bytes,
}

impl HttpBody for PageBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let rest = &mut self.get_mut().rest;
        if rest.is_empty() {
            return Poll::Ready(None);
        }
        let frame = rest.split_to(rest.len().min(PAGE_FRAME));
        Poll::Ready(Some(Ok(Frame::data(frame))))
    }

    fn is_end_stream(&self) -> bool {
        self.rest.is_empty()
    }

    /// Exact, so the response carries a `Content-Length` as before.
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.rest.len() as u64)
    }
}

#[derive(Serialize, Deserialize)]
struct Tag {
    name: String,
    color: i64,
}

/// `POST /api/ab/tags/<guid>`: JSON array.
pub(crate) async fn tags(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(guid): Path<String>,
) -> ApiResult {
    check(&state.db, &user, &guid, READ).await?;
    let tags: Vec<Tag> = sqlx::query_as::<_, (String, i64)>(
        "select name, color from ab_tag where ab_guid = ? order by name",
    )
    .bind(&guid)
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .map(|(name, color)| Tag { name, color })
    .collect();
    Ok(ok_json(&tags))
}

/// A peer body split into its columns (§12.1).
struct PeerFields {
    id: String,
    /// Everything except id/tags/hash/password; null values dropped.
    data: Map<String, Value>,
    tags: Option<Vec<String>>,
    /// `hash` in a personal book, `password` in a shared one; the other key is ignored.
    secret: Option<String>,
}

fn split_peer(body: &[u8], personal: bool) -> Result<PeerFields, ApiError> {
    let body: Map<String, Value> = parse_json(body)?;
    let secret_key = if personal { "hash" } else { "password" };
    let mut id = None;
    let mut fields = PeerFields {
        id: String::new(),
        data: Map::new(),
        tags: None,
        secret: None,
    };
    for (key, value) in body {
        if value.is_null() {
            continue;
        }
        let bad = || ApiError::bad_request(&format!("Invalid type of field '{key}'"));
        match key.as_str() {
            "id" => id = Some(value.as_str().ok_or_else(bad)?.to_owned()),
            "tags" => {
                let tags: Vec<String> = serde_json::from_value(value).map_err(|_| bad())?;
                if tags.len() > MAX_PEER_TAGS {
                    return Err(ApiError::bad_request("Too many tags on one peer"));
                }
                for tag in &tags {
                    check_tag(tag).map_err(ApiError::bad_request)?;
                }
                fields.tags = Some(tags);
            }
            "hash" | "password" => {
                if key == secret_key {
                    let secret = value.as_str().ok_or_else(bad)?;
                    if secret.len() > MAX_SECRET_LEN {
                        return Err(ApiError::bad_request(&format!("Field '{key}' too long")));
                    }
                    if secret.chars().any(char::is_control) {
                        return Err(ApiError::bad_request(&format!("Field '{key}' contains control characters")));
                    }
                    fields.secret = Some(secret.to_owned());
                }
            }
            _ => {
                if (STRING_FIELDS.contains(&key.as_str()) && !value.is_string())
                    || (key == "same_server" && !value.is_boolean())
                {
                    return Err(bad());
                }
                fields.data.insert(key, value);
            }
        }
    }
    fields.id = id.filter(|id| !id.is_empty()).ok_or_else(|| ApiError::bad_request("Missing id"))?;
    if fields.id.len() > MAX_PEER_ID_LEN {
        return Err(ApiError::bad_request("Peer id too long"));
    }
    Ok(fields)
}

/// The error is the 400 message (`.map_err(ApiError::bad_request)`). Also used by the import's
/// report (§15).
pub(crate) fn check_tag(name: &str) -> Result<(), &'static str> {
    if name.len() > MAX_TAG_LEN {
        return Err("Tag name too long");
    }
    if name.chars().any(char::is_control) {
        return Err("Tag name contains control characters");
    }
    Ok(())
}

/// JSON nodes under `v`, `v` itself not counted: each element, or each key and value.
fn child_nodes(v: &Value) -> usize {
    match v {
        Value::Array(a) => a.iter().map(|v| 1 + child_nodes(v)).sum(),
        Value::Object(m) => m.values().map(|v| 2 + child_nodes(v)).sum(),
        _ => 0,
    }
}

/// The `data` column as stored, refused over `MAX_DATA_NODES` or `MAX_DATA_LEN`; the error is the
/// 400 message.
fn encode_data(data: &Map<String, Value>) -> Result<String, &'static str> {
    if data.values().map(|v| 2 + child_nodes(v)).sum::<usize>() > MAX_DATA_NODES {
        return Err("Peer data has too many fields");
    }
    let data = serde_json::to_string(data).map_err(|_| "Peer data cannot be encoded")?;
    if data.len() > MAX_DATA_LEN {
        return Err("Peer data too large");
    }
    Ok(data)
}

/// `POST /api/ab/peer/add/<guid>`: an id already in the book is left untouched (§12.1: a client
/// that has not pulled the book sends duplicates with emptied fields).
pub(crate) async fn peer_add(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult {
    let personal = check(&state.db, &user, &guid, WRITE).await?;
    let fields = split_peer(&body, personal)?;
    let data = encode_data(&fields.data).map_err(ApiError::bad_request)?;
    let secret = state.secret.encrypt(fields.secret.as_deref().unwrap_or_default());
    let (hash, password) = if personal { (secret, String::new()) } else { (String::new(), secret) };
    // The count and the insert in one statement, so concurrent adds cannot overshoot MAX_PEERS.
    let inserted = sqlx::query(
        "insert into ab_peer(ab_guid, id, data, tags, hash_enc, password_enc, created_at, updated_at)
         select ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7 where (select count(*) from ab_peer where ab_guid = ?1) < ?8
         on conflict do nothing",
    )
    .bind(&guid)
    .bind(&fields.id)
    .bind(data)
    .bind(serde_json::json!(fields.tags.unwrap_or_default()).to_string())
    .bind(hash)
    .bind(password)
    .bind(crate::common::now() as i64)
    .bind(MAX_PEERS)
    .execute(&state.db)
    .await?
    .rows_affected();
    // Nothing inserted: either the id is already there (success, §12.1) or the book is full.
    if inserted == 0 {
        let exists: bool = sqlx::query_scalar("select exists(select 1 from ab_peer where ab_guid = ? and id = ?)")
            .bind(&guid)
            .bind(&fields.id)
            .fetch_one(&state.db)
            .await?;
        if !exists {
            return Err(ApiError::bad_request("Address book is full"));
        }
    }
    Ok(ok_empty())
}

/// `PUT /api/ab/peer/update/<guid>`: merges only the fields present.
pub(crate) async fn peer_update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult {
    let personal = check(&state.db, &user, &guid, WRITE).await?;
    let fields = split_peer(&body, personal)?;
    drop(body);
    // The request's own data over a limit fails before it is carried into the transaction (where
    // it may wait for the write lock); the merged row is checked again below.
    encode_data(&fields.data).map_err(ApiError::bad_request)?;
    let mut tx = state.db.begin().await?;
    // Write first so the transaction holds the write lock before it reads (in WAL mode a
    // read-then-write transaction fails with SQLITE_BUSY instead of waiting).
    let found = sqlx::query("update ab_peer set updated_at = ? where ab_guid = ? and id = ?")
        .bind(crate::common::now() as i64)
        .bind(&guid)
        .bind(&fields.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if found == 0 {
        return Err(not_found("Peer not found in this address book"));
    }
    let stored: String = sqlx::query_scalar("select data from ab_peer where ab_guid = ? and id = ?")
        .bind(&guid)
        .bind(&fields.id)
        .fetch_one(&mut *tx)
        .await?;
    let mut data: Map<String, Value> = serde_json::from_str(&stored).map_err(ApiError::internal)?;
    data.extend(fields.data);
    // Checked after merging: each update may add keys to the same row. Dropping `tx` rolls back.
    let data = encode_data(&data).map_err(ApiError::bad_request)?;
    let secret = fields.secret.map(|s| state.secret.encrypt(&s));
    let (hash, password) = if personal { (secret, None) } else { (None, secret) };
    sqlx::query(
        "update ab_peer set data = ?, tags = coalesce(?, tags), hash_enc = coalesce(?, hash_enc),
         password_enc = coalesce(?, password_enc) where ab_guid = ? and id = ?",
    )
    .bind(data)
    .bind(fields.tags.map(|t| serde_json::json!(t).to_string()))
    .bind(hash)
    .bind(password)
    .bind(&guid)
    .bind(&fields.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ok_empty())
}

/// `DELETE /api/ab/peer/<guid>`: body is a JSON array of ids; unknown ids are ignored.
pub(crate) async fn peer_delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult {
    check(&state.db, &user, &guid, WRITE).await?;
    check_peer_ids(&body)?;
    // Checked above to be a JSON array of strings: SQLite reads the ids out of the body itself.
    let ids = std::str::from_utf8(&body).map_err(|_| ApiError::bad_request("Invalid request body"))?;
    // One statement, so all of them go in one transaction.
    sqlx::query("delete from ab_peer where ab_guid = ? and id in (select value from json_each(?))")
        .bind(&guid)
        .bind(ids)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

/// Checks a `DELETE /api/ab/peer` body: a JSON array of at most `MAX_PEERS` strings; else 400.
/// Counts as it reads and keeps nothing (review D-16): the 2 MB the route allows holds ~700,000
/// `""`, about 50 MB as a `Vec<String>` re-encoded, held while the statement waits for the
/// database. The count bounds what `json_each` goes through in the write lock. An id's length is
/// not checked (review E-4): the import does not check it (§15), and an entry whose id is over
/// `MAX_PEER_ID_LEN`, which `peer/update` refuses, can then at least be deleted; what a long id
/// costs is bounded by the body limit.
fn check_peer_ids(body: &[u8]) -> Result<(), ApiError> {
    struct Ids;
    impl<'de> Visitor<'de> for Ids {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an array of peer ids")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
            let mut n = 0;
            while let Some(Id) = seq.next_element()? {
                n += 1;
                if n > MAX_PEERS {
                    return Err(de::Error::custom("too many peer ids"));
                }
            }
            Ok(())
        }
    }
    /// A string, not kept (escaped ones are not even allocated).
    struct Id;
    impl<'de> de::Deserialize<'de> for Id {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Str;
            impl Visitor<'_> for Str {
                type Value = Id;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("a peer id")
                }
                fn visit_str<E>(self, _: &str) -> Result<Id, E> {
                    Ok(Id)
                }
            }
            d.deserialize_str(Str)
        }
    }
    let mut parser = serde_json::Deserializer::from_slice(body);
    parser
        .deserialize_seq(Ids)
        .and_then(|()| parser.end())
        .map_err(|err| ApiError::bad_request(&format!("Invalid request body: {err}")))
}

/// `POST /api/ab/tag/add/<guid>`: an existing name keeps its color.
pub(crate) async fn tag_add(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult {
    check(&state.db, &user, &guid, WRITE).await?;
    let tag: Tag = parse_json(&body)?;
    check_tag(&tag.name).map_err(ApiError::bad_request)?;
    // Same pattern as `peer_add`: count and insert in one statement; nothing inserted and the name
    // not there means the book has MAX_TAGS tags.
    let inserted = sqlx::query(
        "insert into ab_tag(ab_guid, name, color)
         select ?1, ?2, ?3 where (select count(*) from ab_tag where ab_guid = ?1) < ?4 on conflict do nothing",
    )
    .bind(&guid)
    .bind(&tag.name)
    .bind(tag.color)
    .bind(MAX_TAGS)
    .execute(&state.db)
    .await?
    .rows_affected();
    if inserted == 0 {
        let exists: bool = sqlx::query_scalar("select exists(select 1 from ab_tag where ab_guid = ? and name = ?)")
            .bind(&guid)
            .bind(&tag.name)
            .fetch_one(&state.db)
            .await?;
        if !exists {
            return Err(ApiError::bad_request("Too many tags in this address book"));
        }
    }
    Ok(ok_empty())
}

#[derive(Deserialize)]
struct Rename {
    old: String,
    new: String,
}

/// `PUT /api/ab/tag/rename/<guid>`: cascades into the peers' `tags`.
pub(crate) async fn tag_rename(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult {
    check(&state.db, &user, &guid, WRITE).await?;
    let Rename { old, new } = parse_json(&body)?;
    check_tag(&new).map_err(ApiError::bad_request)?;
    let mut tx = state.db.begin().await?;
    let renamed = sqlx::query("update ab_tag set name = ? where ab_guid = ? and name = ?")
        .bind(&new)
        .bind(&guid)
        .bind(&old)
        .execute(&mut *tx)
        .await;
    match renamed {
        Ok(r) if r.rows_affected() == 0 => return Err(not_found("Tag not found")),
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::new(StatusCode::CONFLICT, "Tag already exists"))
        }
        Err(e) => return Err(e.into()),
    }
    let names = serde_json::json!([&old]).to_string();
    cascade_tags(&mut tx, &guid, &names, |t| Some(if t == old { new.clone() } else { t })).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

/// `PUT /api/ab/tag/update/<guid>`: color.
pub(crate) async fn tag_update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult {
    check(&state.db, &user, &guid, WRITE).await?;
    let tag: Tag = parse_json(&body)?;
    let updated = sqlx::query("update ab_tag set color = ? where ab_guid = ? and name = ?")
        .bind(tag.color)
        .bind(&guid)
        .bind(&tag.name)
        .execute(&state.db)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(not_found("Tag not found"));
    }
    Ok(ok_empty())
}

/// `DELETE /api/ab/tag/<guid>`: body is a JSON array of names; cascades into the peers' `tags`.
pub(crate) async fn tag_delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(guid): Path<String>,
    body: Bytes,
) -> ApiResult {
    check(&state.db, &user, &guid, WRITE).await?;
    let names: Vec<String> = parse_json(&body)?;
    // Deduplicated and counted before the transaction (review D-14): the cascade looks up every tag
    // of every affected peer, under the write lock, and 256 KB holds ~65,000 names. The client
    // sends the selected tags of the book, at most MAX_TAGS. The names are not checked against the
    // tag limits: an imported tag over them (§15) can still be deleted, and a lookup's cost does
    // not depend on the name's length.
    let mut set = HashSet::new();
    for name in names {
        set.insert(name);
        if set.len() > MAX_TAGS as usize {
            return Err(ApiError::bad_request("Too many tag names"));
        }
    }
    let names = serde_json::to_string(&set).map_err(ApiError::internal)?;
    let mut tx = state.db.begin().await?;
    sqlx::query("delete from ab_tag where ab_guid = ? and name in (select value from json_each(?))")
        .bind(&guid)
        .bind(&names)
        .execute(&mut *tx)
        .await?;
    cascade_tags(&mut tx, &guid, &names, |t| (!set.contains(&t)).then_some(t)).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

/// Rewrites the `tags` of every peer in the book that carries one of `names` (a JSON array):
/// `map` gives each tag's replacement (None = drop it); duplicates are removed, keeping the first
/// occurrence. Runs inside the caller's transaction, after its first write.
async fn cascade_tags(
    conn: &mut SqliteConnection,
    guid: &str,
    names: &str,
    map: impl Fn(String) -> Option<String>,
) -> Result<(), ApiError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "select id, tags from ab_peer where ab_guid = ?
         and exists (select 1 from json_each(tags) where value in (select value from json_each(?)))",
    )
    .bind(guid)
    .bind(names)
    .fetch_all(&mut *conn)
    .await?;
    let now = crate::common::now() as i64;
    for (id, tags) in rows {
        let tags: Vec<String> = serde_json::from_str(&tags).map_err(ApiError::internal)?;
        let mut out: Vec<String> = Vec::with_capacity(tags.len());
        for tag in tags.into_iter().filter_map(&map) {
            if !out.contains(&tag) {
                out.push(tag);
            }
        }
        sqlx::query("update ab_peer set tags = ?, updated_at = ? where ab_guid = ? and id = ?")
            .bind(serde_json::json!(out).to_string())
            .bind(now)
            .bind(guid)
            .bind(&id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::JSON;
    use crate::testutil::{self, send};
    use hbb_common::tokio;

    fn js(body: &Bytes) -> Value {
        serde_json::from_slice(body).unwrap()
    }

    async fn shared_book(db: &SqlitePool, name: &str, owner: i64) -> String {
        let guid = uuid::Uuid::new_v4().to_string();
        sqlx::query("insert into ab(guid, name, owner_id, personal, created_at, updated_at) values(?, ?, ?, 0, 1, 1)")
            .bind(&guid)
            .bind(name)
            .bind(owner)
            .execute(db)
            .await
            .unwrap();
        guid
    }

    async fn grant_user(db: &SqlitePool, guid: &str, user: i64, rule: i64) {
        sqlx::query("insert into ab_rule(ab_guid, user_id, rule) values(?, ?, ?)")
            .bind(guid)
            .bind(user)
            .bind(rule)
            .execute(db)
            .await
            .unwrap();
    }

    async fn grant_group(db: &SqlitePool, guid: &str, group: i64, rule: i64) {
        sqlx::query("insert into ab_rule(ab_guid, group_id, rule) values(?, ?, ?)")
            .bind(guid)
            .bind(group)
            .bind(rule)
            .execute(db)
            .await
            .unwrap();
    }

    async fn group(db: &SqlitePool, name: &str) -> i64 {
        sqlx::query_scalar("insert into user_group(name, created_at) values(?, 1) returning id")
            .bind(name)
            .fetch_one(db)
            .await
            .unwrap()
    }

    async fn member(db: &SqlitePool, group: i64, user: i64, add: bool) {
        let sql = if add {
            "insert into group_member(group_id, user_id) values(?, ?)"
        } else {
            "delete from group_member where group_id = ? and user_id = ?"
        };
        sqlx::query(sql).bind(group).bind(user).execute(db).await.unwrap();
    }

    async fn personal_guid(app: &axum::Router, token: &str) -> String {
        let (status, _, body) = send(app, "POST", "/api/ab/personal", Some(token), "").await;
        assert_eq!(status, StatusCode::OK);
        js(&body)["guid"].as_str().unwrap().to_owned()
    }

    /// Asserts 200 + empty body (the only success the client accepts for writes).
    async fn write_ok(app: &axum::Router, method: &str, uri: &str, token: &str, body: &str) {
        let (status, _, resp) = send(app, method, uri, Some(token), body).await;
        assert_eq!((status, &resp[..]), (StatusCode::OK, &b""[..]), "{method} {uri} {body}");
    }

    /// Asserts a JSON `{"error"}` with this status.
    async fn write_err(app: &axum::Router, method: &str, uri: &str, token: &str, body: &str, want: StatusCode) {
        let (status, ct, resp) = send(app, method, uri, Some(token), body).await;
        assert_eq!(status, want, "{method} {uri} {body}");
        assert_eq!(ct, JSON);
        assert!(js(&resp)["error"].is_string());
    }

    async fn list_peers(app: &axum::Router, token: &str, guid: &str) -> Vec<Value> {
        let (status, ct, body) = send(app, "POST", &format!("/api/ab/peers?ab={guid}"), Some(token), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, JSON);
        js(&body)["data"].as_array().unwrap().clone()
    }

    async fn stored(db: &SqlitePool, guid: &str, id: &str) -> (Value, Vec<String>, String, String) {
        let (data, tags, hash, password) = sqlx::query_as::<_, (String, String, String, String)>(
            "select data, tags, hash_enc, password_enc from ab_peer where ab_guid = ? and id = ?",
        )
        .bind(guid)
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap();
        (serde_json::from_str(&data).unwrap(), serde_json::from_str(&tags).unwrap(), hash, password)
    }

    #[tokio::test]
    async fn personal_and_settings() {
        let t = testutil::app().await;
        let (uid, token) = testutil::create_user(&t.state.db, "alice", "", false).await;

        for uri in ["/api/ab/personal", "/api/ab/settings", "/api/ab/shared/profiles"] {
            let (status, _, _) = send(&t.app, "POST", uri, None, "").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }

        let (status, ct, body) = send(&t.app, "POST", "/api/ab/personal", Some(&token), "").await;
        assert_eq!((status, ct.as_str()), (StatusCode::OK, JSON));
        let guid = js(&body)["guid"].as_str().unwrap().to_owned();
        assert!(!guid.is_empty());
        assert_eq!(personal_guid(&t.app, &token).await, guid, "stable");
        let (name, owner, personal): (String, i64, bool) =
            sqlx::query_as("select name, owner_id, personal from ab where guid = ?")
                .bind(&guid)
                .fetch_one(&t.state.db)
                .await
                .unwrap();
        assert_eq!((name.as_str(), owner, personal), (PERSONAL_NAME, uid, true));

        let (status, ct, body) = send(&t.app, "POST", "/api/ab/settings", Some(&token), "").await;
        assert_eq!((status, ct.as_str()), (StatusCode::OK, JSON));
        assert_eq!(&body[..], br#"{"max_peer_one_ab":5000}"#);
    }

    #[tokio::test]
    async fn write_size_limits() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, token) = testutil::create_user(db, "alice", "", false).await;
        let personal = personal_guid(&t.app, &token).await;
        let shared = shared_book(db, "S", uid).await;
        let add = format!("/api/ab/peer/add/{personal}");
        let update = format!("/api/ab/peer/update/{personal}");
        let tag = "t".repeat(MAX_TAG_LEN);
        let secret = "s".repeat(MAX_SECRET_LEN);
        // `{"note":"…"}` serialized is the note plus 11 bytes.
        let note = |extra: usize| "n".repeat(MAX_DATA_LEN - 11 + extra);

        // At each limit: accepted.
        let id = "i".repeat(MAX_PEER_ID_LEN);
        let tags = vec![tag.clone(); MAX_PEER_TAGS];
        let body = serde_json::json!({"id": id, "tags": tags, "hash": secret, "note": note(0)}).to_string();
        write_ok(&t.app, "POST", &add, &token, &body).await;
        let (data, stored_tags, hash, _) = stored(db, &personal, &id).await;
        assert_eq!((data.to_string().len(), stored_tags.len()), (MAX_DATA_LEN, MAX_PEER_TAGS));
        assert_eq!(t.state.secret.decrypt(&hash).unwrap(), secret);
        let body = serde_json::json!({"id": "1", "password": secret}).to_string();
        write_ok(&t.app, "POST", &format!("/api/ab/peer/add/{shared}"), &token, &body).await;

        // One over: 400 + error, nothing stored or changed (updates go to the peer just added).
        let long_id = serde_json::json!({"id": "i".repeat(MAX_PEER_ID_LEN + 1)}).to_string();
        write_err(&t.app, "POST", &add, &token, &long_id, StatusCode::BAD_REQUEST).await;
        write_err(&t.app, "PUT", &update, &token, &long_id, StatusCode::BAD_REQUEST).await;
        let before = stored(db, &personal, &id).await;
        for bad in [
            serde_json::json!({"id": "2", "tags": vec!["t"; MAX_PEER_TAGS + 1]}),
            serde_json::json!({"id": "2", "tags": ["a", format!("{tag}x")]}),
            serde_json::json!({"id": "2", "hash": format!("{secret}x")}),
            serde_json::json!({"id": "2", "hash": "a\u{1}b"}),
            serde_json::json!({"id": "2", "hash": "\n"}),
            serde_json::json!({"id": "2", "note": note(1)}),
        ] {
            write_err(&t.app, "POST", &add, &token, &bad.to_string(), StatusCode::BAD_REQUEST).await;
            let mut bad = bad;
            bad["id"] = Value::String(id.clone());
            write_err(&t.app, "PUT", &update, &token, &bad.to_string(), StatusCode::BAD_REQUEST).await;
        }
        assert_eq!(stored(db, &personal, &id).await, before);
        let body = serde_json::json!({"id": "2", "password": format!("{secret}x")}).to_string();
        write_err(&t.app, "POST", &format!("/api/ab/peer/add/{shared}"), &token, &body, StatusCode::BAD_REQUEST).await;
        let body = serde_json::json!({"id": "2", "password": "pw\u{7f}"}).to_string();
        write_err(&t.app, "POST", &format!("/api/ab/peer/add/{shared}"), &token, &body, StatusCode::BAD_REQUEST).await;
        // The request's own data is checked before looking the peer up: over the limit is a 400
        // even for an id not in the book (which is otherwise a 404).
        let body = serde_json::json!({"id": "nope", "note": note(1)}).to_string();
        write_err(&t.app, "PUT", &update, &token, &body, StatusCode::BAD_REQUEST).await;
        write_err(&t.app, "PUT", &update, &token, r#"{"id":"nope"}"#, StatusCode::NOT_FOUND).await;
        // The other book's secret key is ignored, so not limited either.
        let body = serde_json::json!({"id": "2", "password": format!("{secret}x")}).to_string();
        write_ok(&t.app, "POST", &add, &token, &body).await;
        let count: i64 = sqlx::query_scalar("select count(*) from ab_peer").fetch_one(db).await.unwrap();
        assert_eq!(count, 3);

        // peer/update checks the merged row: each half fits, together they do not.
        write_ok(&t.app, "POST", &add, &token, r#"{"id":"m"}"#).await;
        let half = "a".repeat(MAX_DATA_LEN / 2);
        write_ok(&t.app, "PUT", &update, &token, &serde_json::json!({"id": "m", "alias": half}).to_string()).await;
        let body = serde_json::json!({"id": "m", "note": half}).to_string();
        write_err(&t.app, "PUT", &update, &token, &body, StatusCode::BAD_REQUEST).await;
        assert_eq!(stored(db, &personal, "m").await.0, serde_json::json!({"alias": half}), "rolled back");
        // Replacing a value with a shorter one is fine.
        write_ok(&t.app, "PUT", &update, &token, r#"{"id":"m","alias":"short","note":"n"}"#).await;

        // Tag names.
        let tag_add = format!("/api/ab/tag/add/{personal}");
        let rename = format!("/api/ab/tag/rename/{personal}");
        write_ok(&t.app, "POST", &tag_add, &token, &serde_json::json!({"name": tag, "color": 1}).to_string()).await;
        let body = serde_json::json!({"name": format!("{tag}x"), "color": 1}).to_string();
        write_err(&t.app, "POST", &tag_add, &token, &body, StatusCode::BAD_REQUEST).await;
        write_ok(&t.app, "POST", &tag_add, &token, r#"{"name":"a","color":1}"#).await;
        let body = serde_json::json!({"old": "a", "new": format!("{tag}y")}).to_string();
        write_err(&t.app, "PUT", &rename, &token, &body, StatusCode::BAD_REQUEST).await;
        let body = serde_json::json!({"old": "a", "new": "b".repeat(MAX_TAG_LEN)}).to_string();
        write_ok(&t.app, "PUT", &rename, &token, &body).await;
        let names: Vec<String> = sqlx::query_scalar("select name from ab_tag order by name").fetch_all(db).await.unwrap();
        assert_eq!(names, ["b".repeat(MAX_TAG_LEN), tag.clone()]);

        // Control characters in a tag name, wherever it comes from.
        for name in ["a\u{0}", "a\nb", "\u{7f}", "x\u{9f}"] {
            let body = serde_json::json!({"id": "c", "tags": ["ok", name]}).to_string();
            write_err(&t.app, "POST", &add, &token, &body, StatusCode::BAD_REQUEST).await;
            let body = serde_json::json!({"id": "m", "tags": [name]}).to_string();
            write_err(&t.app, "PUT", &update, &token, &body, StatusCode::BAD_REQUEST).await;
            let body = serde_json::json!({"name": name, "color": 1}).to_string();
            write_err(&t.app, "POST", &tag_add, &token, &body, StatusCode::BAD_REQUEST).await;
            let body = serde_json::json!({"old": tag, "new": name}).to_string();
            write_err(&t.app, "PUT", &rename, &token, &body, StatusCode::BAD_REQUEST).await;
        }
        // Not control characters: quotes, backslash, spaces, CJK, emoji.
        let fine = "\"\\ 标签 \u{1f600}";
        write_ok(&t.app, "POST", &tag_add, &token, &serde_json::json!({"name": fine, "color": 1}).to_string()).await;
        write_ok(&t.app, "PUT", &update, &token, &serde_json::json!({"id": "m", "tags": [fine]}).to_string()).await;
        assert_eq!(stored(db, &personal, "m").await.1, [fine]);
        let found: bool = sqlx::query_scalar("select exists(select 1 from ab_tag where name = ?)")
            .bind(fine)
            .fetch_one(db)
            .await
            .unwrap();
        let refused: i64 = sqlx::query_scalar("select count(*) from ab_peer where id = 'c'").fetch_one(db).await.unwrap();
        assert_eq!((found, refused), (true, 0));
        assert_eq!(stored(db, &personal, &id).await, before);
    }

    #[test]
    fn data_node_count() {
        let n = |v: Value| child_nodes(&v);
        assert_eq!(n(serde_json::json!({})), 0);
        assert_eq!(n(serde_json::json!({"a": 1, "b": "x", "c": null, "d": true})), 8);
        assert_eq!(n(serde_json::json!({"a": [1, 2]})), 4);
        assert_eq!(n(serde_json::json!({"a": {"b": {"c": []}}})), 6);
        assert_eq!(n(serde_json::json!({"a": [[], {}, [{"x": 1}]]})), 8);
    }

    #[tokio::test]
    async fn data_node_limit() {
        let t = testutil::app().await;
        let (_, token) = testutil::create_user(&t.state.db, "alice", "", false).await;
        let book = personal_guid(&t.app, &token).await;
        let add = format!("/api/ab/peer/add/{book}");
        let update = format!("/api/ab/peer/update/{book}");
        // `keys` string keys = 2 × keys nodes.
        let flat = |id: &str, keys: usize, prefix: &str| {
            let mut m = Map::new();
            m.insert("id".into(), id.into());
            for i in 0..keys {
                m.insert(format!("{prefix}{i}"), "v".into());
            }
            m
        };

        // The client's own peer is well under the limit.
        let client = r#"{"id":"c","hash":"","password":"","username":"u","hostname":"h","platform":"Windows",
            "alias":"a","tags":["t"],"forceAlwaysRelay":"false","rdpPort":"","rdpUsername":"","loginName":"",
            "device_group_name":"","note":"","same_server":false}"#;
        write_ok(&t.app, "POST", &add, &token, client).await;

        write_ok(&t.app, "POST", &add, &token, &Value::Object(flat("64", MAX_DATA_NODES / 2, "k")).to_string()).await;
        let mut over = flat("65", MAX_DATA_NODES / 2 - 1, "k");
        over.insert("nested".into(), serde_json::json!([1]));
        write_err(&t.app, "POST", &add, &token, &Value::Object(over).to_string(), StatusCode::BAD_REQUEST).await;
        // Nesting counts through: one key holding 70 nested arrays.
        let mut deep = serde_json::json!(1);
        for _ in 0..70 {
            deep = serde_json::json!([deep]);
        }
        let deep = serde_json::json!({"id": "deep", "a": deep});
        write_err(&t.app, "POST", &add, &token, &deep.to_string(), StatusCode::BAD_REQUEST).await;

        // peer/update counts the merged row: 32 + 1 new keys are 66 nodes.
        let body = Value::Object(flat("64", 1, "new")).to_string();
        write_err(&t.app, "PUT", &update, &token, &body, StatusCode::BAD_REQUEST).await;
        // Overwriting existing keys keeps the count.
        let body = Value::Object(flat("64", MAX_DATA_NODES / 2, "k")).to_string();
        write_ok(&t.app, "PUT", &update, &token, &body).await;
        let ids: Vec<String> = sqlx::query_scalar("select id from ab_peer order by id").fetch_all(&t.state.db).await.unwrap();
        assert_eq!(ids, ["64", "c"]);
    }

    /// Fills a book with `n` peers (ids `f0`, `f1`, …) or tags straight in the database.
    async fn fill(db: &SqlitePool, guid: &str, table: &str, n: i64) {
        let sql = match table {
            "ab_peer" => "with recursive c(i) as (select 0 union all select i + 1 from c where i + 1 < ?2)
                 insert into ab_peer(ab_guid, id, created_at, updated_at) select ?1, 'f' || i, 1, 1 from c",
            _ => "with recursive c(i) as (select 0 union all select i + 1 from c where i + 1 < ?2)
                 insert into ab_tag(ab_guid, name, color) select ?1, 'f' || i, 1 from c",
        };
        sqlx::query(sql).bind(guid).bind(n).execute(db).await.unwrap();
    }

    #[tokio::test]
    async fn book_peer_and_tag_count_limits() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, token) = testutil::create_user(db, "alice", "", false).await;
        let book = personal_guid(&t.app, &token).await;
        let other = shared_book(db, "S", uid).await;
        let add = format!("/api/ab/peer/add/{book}");
        let tag_add = format!("/api/ab/tag/add/{book}");

        fill(db, &book, "ab_peer", MAX_PEERS - 1).await;
        fill(db, &book, "ab_tag", MAX_TAGS - 1).await;
        // The last one fits.
        write_ok(&t.app, "POST", &add, &token, r#"{"id":"last"}"#).await;
        write_ok(&t.app, "POST", &tag_add, &token, r#"{"name":"last","color":1}"#).await;
        // Full: a new one is refused; an existing one still succeeds without changes (§12.1).
        write_err(&t.app, "POST", &add, &token, r#"{"id":"new"}"#, StatusCode::BAD_REQUEST).await;
        write_ok(&t.app, "POST", &add, &token, r#"{"id":"last","alias":"x"}"#).await;
        write_err(&t.app, "POST", &tag_add, &token, r#"{"name":"new","color":1}"#, StatusCode::BAD_REQUEST).await;
        write_ok(&t.app, "POST", &tag_add, &token, r#"{"name":"last","color":2}"#).await;
        let peers: i64 = sqlx::query_scalar("select count(*) from ab_peer where ab_guid = ?")
            .bind(&book)
            .fetch_one(db)
            .await
            .unwrap();
        let tags: Vec<(String, i64)> = sqlx::query_as("select name, color from ab_tag where ab_guid = ? and name = 'last'")
            .bind(&book)
            .fetch_all(db)
            .await
            .unwrap();
        assert_eq!((peers, tags), (MAX_PEERS, vec![("last".to_owned(), 1)]));
        assert_eq!(stored(db, &book, "last").await.0, serde_json::json!({}));
        // Other books are counted on their own.
        write_ok(&t.app, "POST", &format!("/api/ab/peer/add/{other}"), &token, r#"{"id":"new"}"#).await;
        write_ok(&t.app, "POST", &format!("/api/ab/tag/add/{other}"), &token, r#"{"name":"new","color":1}"#).await;
        // Room again after a delete.
        write_ok(&t.app, "DELETE", &format!("/api/ab/peer/{book}"), &token, r#"["f0"]"#).await;
        write_ok(&t.app, "POST", &add, &token, r#"{"id":"new"}"#).await;
        write_ok(&t.app, "DELETE", &format!("/api/ab/tag/{book}"), &token, r#"["f0"]"#).await;
        write_ok(&t.app, "POST", &tag_add, &token, r#"{"name":"new","color":1}"#).await;

        // A page never holds more than 1000 peers; total stays the full count.
        let (status, _, body) =
            send(&t.app, "POST", &format!("/api/ab/peers?current=2&pageSize=5000&ab={book}"), Some(&token), "").await;
        assert_eq!(status, StatusCode::OK);
        let v = js(&body);
        assert_eq!((v["total"].as_i64(), v["data"].as_array().unwrap().len()), (Some(MAX_PEERS), 1000));
        let id_1000: String = sqlx::query_scalar("select id from ab_peer where ab_guid = ? order by id limit 1 offset 1000")
            .bind(&book)
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(v["data"][0]["id"], id_1000, "page 2 starts at offset 1000");
    }

    #[tokio::test]
    async fn shared_profiles_effective_rule() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (owner, owner_token) = testutil::create_user(db, "1001", "", false).await;
        let (alice, alice_token) = testutil::create_user(db, "alice", "", false).await;
        let (bob, bob_token) = testutil::create_user(db, "bob", "", false).await;
        personal_guid(&t.app, &owner_token).await;
        let alice_personal = personal_guid(&t.app, &alice_token).await;
        let g = group(db, "team").await;
        member(db, g, alice, true).await;

        let b = shared_book(db, "B", owner).await;
        grant_user(db, &b, alice, 1).await;
        let a = shared_book(db, "A", owner).await;
        grant_user(db, &a, alice, 1).await;
        grant_group(db, &a, g, 2).await;
        let c = shared_book(db, "C", owner).await;
        grant_user(db, &c, bob, 3).await;

        let profiles = |token: String, query: &'static str| {
            let app = t.app.clone();
            async move {
                let (status, ct, body) =
                    send(&app, "POST", &format!("/api/ab/shared/profiles{query}"), Some(&token), "").await;
                assert_eq!((status, ct.as_str()), (StatusCode::OK, JSON));
                js(&body)
            }
        };

        // max(direct 1, group 2) = 2; owner as a string even when it looks numeric; info {}.
        let v = profiles(alice_token.clone(), "?current=1&pageSize=100").await;
        assert_eq!(
            v,
            serde_json::json!({"total": 2, "data": [
                {"guid": a, "name": "A", "owner": "1001", "note": "", "rule": 2, "info": {}},
                {"guid": b, "name": "B", "owner": "1001", "note": "", "rule": 1, "info": {}},
            ]})
        );
        assert!(!v.to_string().contains(&alice_personal), "personal books are not listed");

        // The owner sees every own shared book with rule 3, never the personal one.
        let v = profiles(owner_token.clone(), "").await;
        assert_eq!(v["total"], 3);
        assert!(v["data"].as_array().unwrap().iter().all(|p| p["rule"] == 3 && p["owner"] == "1001"));
        let v = profiles(owner_token.clone(), "?current=2&pageSize=2").await;
        assert_eq!(v["total"], 3);
        assert_eq!(v["data"].as_array().unwrap().len(), 1);
        assert_eq!(v["data"][0]["name"], "C");

        let v = profiles(bob_token.clone(), "").await;
        assert_eq!(v["total"], 1);
        assert_eq!(v["data"][0]["rule"], 3);

        // Someone else's personal book is not accessible, even to read.
        let (status, _, _) =
            send(&t.app, "POST", &format!("/api/ab/peers?ab={alice_personal}"), Some(&bob_token), "").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn group_rule_follows_membership() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (owner, _) = testutil::create_user(db, "owner", "", false).await;
        let (alice, token) = testutil::create_user(db, "alice", "", false).await;
        let book = shared_book(db, "team book", owner).await;
        let g = group(db, "team").await;
        grant_group(db, &book, g, 2).await;
        let peers_uri = format!("/api/ab/peers?ab={book}");
        let add_uri = format!("/api/ab/peer/add/{book}");

        write_err(&t.app, "POST", &peers_uri, &token, "", StatusCode::FORBIDDEN).await;
        write_err(&t.app, "POST", &add_uri, &token, r#"{"id":"1"}"#, StatusCode::FORBIDDEN).await;

        member(db, g, alice, true).await;
        write_ok(&t.app, "POST", &add_uri, &token, r#"{"id":"1"}"#).await;
        assert_eq!(list_peers(&t.app, &token, &book).await.len(), 1);
        let (_, _, body) = send(&t.app, "POST", "/api/ab/shared/profiles", Some(&token), "").await;
        assert_eq!(js(&body)["data"][0]["rule"], 2);

        member(db, g, alice, false).await;
        write_err(&t.app, "POST", &peers_uri, &token, "", StatusCode::FORBIDDEN).await;
        let (_, _, body) = send(&t.app, "POST", "/api/ab/shared/profiles", Some(&token), "").await;
        assert_eq!(js(&body), serde_json::json!({"total": 0, "data": []}));
    }

    #[tokio::test]
    async fn read_only_and_no_access() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (owner, owner_token) = testutil::create_user(db, "owner", "", false).await;
        let (alice, token) = testutil::create_user(db, "alice", "", false).await;
        let (_, bob_token) = testutil::create_user(db, "bob", "", false).await;
        let book = shared_book(db, "ro", owner).await;
        grant_user(db, &book, alice, 1).await;
        write_ok(&t.app, "POST", &format!("/api/ab/peer/add/{book}"), &owner_token, r#"{"id":"1","tags":["x"]}"#)
            .await;
        write_ok(&t.app, "POST", &format!("/api/ab/tag/add/{book}"), &owner_token, r#"{"name":"x","color":1}"#)
            .await;

        // Reads work for rule 1.
        assert_eq!(list_peers(&t.app, &token, &book).await.len(), 1);
        let (status, _, body) = send(&t.app, "POST", &format!("/api/ab/tags/{book}"), Some(&token), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(js(&body), serde_json::json!([{"name": "x", "color": 1}]));

        let writes = [
            ("POST", "peer/add", r#"{"id":"2"}"#),
            ("PUT", "peer/update", r#"{"id":"1","alias":"a"}"#),
            ("DELETE", "peer", r#"["1"]"#),
            ("POST", "tag/add", r#"{"name":"y","color":1}"#),
            ("PUT", "tag/rename", r#"{"old":"x","new":"z"}"#),
            ("PUT", "tag/update", r#"{"name":"x","color":2}"#),
            ("DELETE", "tag", r#"["x"]"#),
        ];
        for (method, path, body) in writes {
            let uri = format!("/api/ab/{path}/{book}");
            write_err(&t.app, method, &uri, &token, body, StatusCode::FORBIDDEN).await;
            // No rule at all, and an unknown book: 403 too.
            write_err(&t.app, method, &uri, &bob_token, body, StatusCode::FORBIDDEN).await;
            let uri = format!("/api/ab/{path}/no-such-book");
            write_err(&t.app, method, &uri, &owner_token, body, StatusCode::FORBIDDEN).await;
        }
        let (data, tags, _, _) = stored(db, &book, "1").await;
        assert_eq!((data, tags), (serde_json::json!({}), vec!["x".to_owned()]));
        let count: i64 = sqlx::query_scalar("select count(*) from ab_peer").fetch_one(db).await.unwrap();
        assert_eq!(count, 1);
        let color: i64 = sqlx::query_scalar("select color from ab_tag").fetch_one(db).await.unwrap();
        assert_eq!(color, 1);

        for uri in [format!("/api/ab/peers?ab={book}"), format!("/api/ab/tags/{book}"), "/api/ab/peers".to_owned()] {
            write_err(&t.app, "POST", &uri, &bob_token, "", StatusCode::FORBIDDEN).await;
        }

        // Rule 2 may delete (2 and 3 are the same for these endpoints).
        sqlx::query("update ab_rule set rule = 2").execute(db).await.unwrap();
        write_ok(&t.app, "DELETE", &format!("/api/ab/peer/{book}"), &token, r#"["1"]"#).await;
        write_ok(&t.app, "DELETE", &format!("/api/ab/tag/{book}"), &token, r#"["x"]"#).await;
    }

    #[tokio::test]
    async fn peer_add_personal_and_shared() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, token) = testutil::create_user(db, "alice", "", false).await;
        let personal = personal_guid(&t.app, &token).await;
        let add = format!("/api/ab/peer/add/{personal}");

        let (status, ct, body) = send(
            &t.app,
            "POST",
            &add,
            Some(&token),
            r#"{"id":"123","alias":"pc","tags":["t1"],"note":null,"hash":"aGFzaA==","password":"ignored",
                "same_server":true,"forceAlwaysRelay":"false","extra":{"k":[1]},"username":"u"}"#,
        )
        .await;
        assert_eq!((status, ct.as_str(), &body[..]), (StatusCode::OK, "", &b""[..]));
        let (data, tags, hash, password) = stored(db, &personal, "123").await;
        assert_eq!(
            data,
            serde_json::json!({"alias": "pc", "same_server": true, "forceAlwaysRelay": "false",
                "extra": {"k": [1]}, "username": "u"})
        );
        assert_eq!(tags, vec!["t1".to_owned()]);
        assert!(hash.starts_with("sb1:") && !hash.contains("aGFzaA=="), "stored encrypted");
        assert_eq!(password, "", "personal books ignore password");
        let peers = list_peers(&t.app, &token, &personal).await;
        assert_eq!(
            peers,
            vec![serde_json::json!({"id": "123", "alias": "pc", "tags": ["t1"], "hash": "aGFzaA==",
                "same_server": true, "forceAlwaysRelay": "false", "extra": {"k": [1]}, "username": "u"})]
        );

        // A duplicate id changes nothing.
        write_ok(&t.app, "POST", &add, &token, r#"{"id":"123","alias":"","tags":[],"note":"","hash":""}"#).await;
        assert_eq!(list_peers(&t.app, &token, &personal).await, peers);

        // Type checks.
        for bad in [
            r#"{"id":"9","alias":1}"#,
            r#"{"id":"9","note":true}"#,
            r#"{"id":"9","rdpPort":3389}"#,
            r#"{"id":"9","forceAlwaysRelay":true}"#,
            r#"{"id":"9","same_server":"true"}"#,
            r#"{"id":"9","same_server":1}"#,
            r#"{"id":"9","tags":"t1"}"#,
            r#"{"id":"9","tags":[1]}"#,
            r#"{"id":"9","hash":1}"#,
            r#"{"id":9}"#,
            r#"{"id":""}"#,
            r#"{"alias":"x"}"#,
            r#"["9"]"#,
            "",
        ] {
            write_err(&t.app, "POST", &add, &token, bad, StatusCode::BAD_REQUEST).await;
        }
        let count: i64 = sqlx::query_scalar("select count(*) from ab_peer").fetch_one(db).await.unwrap();
        assert_eq!(count, 1);

        // Shared book: the plain password is stored encrypted, hash is ignored.
        let shared = shared_book(db, "S", uid).await;
        let add = format!("/api/ab/peer/add/{shared}");
        write_ok(&t.app, "POST", &add, &token, r#"{"id":"1","password":"秘密","hash":"h"}"#).await;
        write_ok(&t.app, "POST", &add, &token, r#"{"id":"2","password":""}"#).await;
        let (data, tags, hash, password) = stored(db, &shared, "1").await;
        assert_eq!((data, tags, hash.as_str()), (serde_json::json!({}), vec![], ""));
        assert!(password.starts_with("sb1:") && !password.contains("秘密"));
        assert_eq!(stored(db, &shared, "2").await.3, "");
        assert_eq!(
            list_peers(&t.app, &token, &shared).await,
            vec![
                serde_json::json!({"id": "1", "tags": [], "password": "秘密"}),
                serde_json::json!({"id": "2", "tags": []}),
            ]
        );
    }

    #[tokio::test]
    async fn peer_update_and_delete() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (_, token) = testutil::create_user(db, "alice", "", false).await;
        let book = personal_guid(&t.app, &token).await;
        let update = format!("/api/ab/peer/update/{book}");
        write_ok(
            &t.app,
            "POST",
            &format!("/api/ab/peer/add/{book}"),
            &token,
            r#"{"id":"1","alias":"a","note":"n","username":"u","tags":["t"],"hash":"h"}"#,
        )
        .await;

        write_err(&t.app, "PUT", &update, &token, r#"{"id":"2","alias":"x"}"#, StatusCode::NOT_FOUND).await;
        write_err(&t.app, "PUT", &update, &token, r#"{"id":"1","alias":5}"#, StatusCode::BAD_REQUEST).await;
        write_err(&t.app, "PUT", &update, &token, r#"{"alias":"x"}"#, StatusCode::BAD_REQUEST).await;
        let count: i64 = sqlx::query_scalar("select count(*) from ab_peer").fetch_one(db).await.unwrap();
        assert_eq!(count, 1, "update never creates");

        // Only the fields present change; null means "not given".
        write_ok(&t.app, "PUT", &update, &token, r#"{"id":"1","alias":"b","note":null,"hostname":"h1"}"#).await;
        let (data, tags, hash, _) = stored(db, &book, "1").await;
        assert_eq!(data, serde_json::json!({"alias": "b", "note": "n", "username": "u", "hostname": "h1"}));
        assert_eq!(tags, vec!["t".to_owned()]);
        assert_eq!(t.state.secret.decrypt(&hash).unwrap(), "h");

        write_ok(&t.app, "PUT", &update, &token, r#"{"id":"1","tags":[]}"#).await;
        assert!(stored(db, &book, "1").await.1.is_empty());
        write_ok(&t.app, "PUT", &update, &token, r#"{"id":"1","hash":"aGFzaDI="}"#).await;
        let hash = stored(db, &book, "1").await.2;
        assert!(hash.starts_with("sb1:"));
        assert_eq!(list_peers(&t.app, &token, &book).await[0]["hash"], "aGFzaDI=");
        // Forget password: stored as '' and the key is omitted.
        write_ok(&t.app, "PUT", &update, &token, r#"{"id":"1","hash":""}"#).await;
        assert_eq!(stored(db, &book, "1").await.2, "");
        assert!(list_peers(&t.app, &token, &book).await[0].get("hash").is_none());

        write_ok(&t.app, "POST", &format!("/api/ab/peer/add/{book}"), &token, r#"{"id":"2"}"#).await;
        let delete = format!("/api/ab/peer/{book}");
        write_err(&t.app, "DELETE", &delete, &token, r#"{"id":"1"}"#, StatusCode::BAD_REQUEST).await;
        write_ok(&t.app, "DELETE", &delete, &token, r#"["1","missing"]"#).await;
        let peers = list_peers(&t.app, &token, &book).await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["id"], "2");
    }

    #[tokio::test]
    async fn undecryptable_secret_only_drops_that_key() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, token) = testutil::create_user(db, "alice", "", false).await;
        let personal = personal_guid(&t.app, &token).await;
        let shared = shared_book(db, "S", uid).await;
        for (book, body) in [
            (&personal, r#"{"id":"1","alias":"a","hash":"h1"}"#),
            (&personal, r#"{"id":"2","alias":"b","hash":"h2"}"#),
            (&shared, r#"{"id":"1","password":"p1"}"#),
            (&shared, r#"{"id":"2","password":"p2"}"#),
        ] {
            write_ok(&t.app, "POST", &format!("/api/ab/peer/add/{book}"), &token, body).await;
        }
        // Peer 2 of each book: encrypted with another key (a replaced leapgate_secret.key), or corrupt.
        let other = crate::crypto::SecretBox::load_or_create(&t.dir.path().join("other.key")).unwrap();
        sqlx::query("update ab_peer set hash_enc = ? where ab_guid = ? and id = '2'")
            .bind(other.encrypt("h2"))
            .bind(&personal)
            .execute(db)
            .await
            .unwrap();
        sqlx::query("update ab_peer set password_enc = 'sb1:AAAA' where ab_guid = ? and id = '2'")
            .bind(&shared)
            .execute(db)
            .await
            .unwrap();

        assert_eq!(
            list_peers(&t.app, &token, &personal).await,
            vec![
                serde_json::json!({"id": "1", "tags": [], "alias": "a", "hash": "h1"}),
                serde_json::json!({"id": "2", "tags": [], "alias": "b"}),
            ]
        );
        assert_eq!(
            list_peers(&t.app, &token, &shared).await,
            vec![
                serde_json::json!({"id": "1", "tags": [], "password": "p1"}),
                serde_json::json!({"id": "2", "tags": []}),
            ]
        );
    }

    #[tokio::test]
    async fn peers_pagination() {
        let t = testutil::app().await;
        let (_, token) = testutil::create_user(&t.state.db, "alice", "", false).await;
        let book = personal_guid(&t.app, &token).await;
        for i in 0..5 {
            write_ok(&t.app, "POST", &format!("/api/ab/peer/add/{book}"), &token, &format!(r#"{{"id":"p{i}"}}"#))
                .await;
        }
        let page = |query: String| {
            let (app, token) = (t.app.clone(), token.clone());
            async move {
                let (status, _, body) =
                    send(&app, "POST", &format!("/api/ab/peers?{query}"), Some(&token), "").await;
                assert_eq!(status, StatusCode::OK);
                let v = js(&body);
                assert!(v["total"].is_i64(), "total is an integer");
                let ids: Vec<String> =
                    v["data"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap().to_owned()).collect();
                (v["total"].as_i64().unwrap(), ids)
            }
        };
        assert_eq!(page(format!("current=1&pageSize=2&ab={book}")).await, (5, vec!["p0".into(), "p1".into()]));
        assert_eq!(page(format!("current=3&pageSize=2&ab={book}")).await, (5, vec!["p4".into()]));
        assert_eq!(page(format!("current=1&pageSize=100&ab={book}")).await.1.len(), 5);
        assert_eq!(page(format!("ab={book}")).await.1.len(), 5);
        // Past the end, and exactly what the page is made of.
        assert_eq!(page(format!("current=4&pageSize=2&ab={book}")).await, (5, vec![]));
        let (status, ct, body) =
            send(&t.app, "POST", &format!("/api/ab/peers?current=4&pageSize=2&ab={book}"), Some(&token), "").await;
        assert_eq!((status, ct.as_str(), &body[..]), (StatusCode::OK, JSON, &br#"{"total":5,"data":[]}"#[..]));
        let (_, _, body) =
            send(&t.app, "POST", &format!("/api/ab/peers?current=2&pageSize=2&ab={book}"), Some(&token), "").await;
        assert_eq!(&body[..], br#"{"total":5,"data":[{"id":"p2","tags":[]},{"id":"p3","tags":[]}]}"#);
    }

    /// A user's personal book with `n` peers of about `note` bytes each, written straight into the
    /// database; returns (token, guid).
    async fn big_book(t: &testutil::TestApp, name: &str, n: i64, note: usize) -> (String, String) {
        let (_, token) = testutil::create_user(&t.state.db, name, "", false).await;
        let book = personal_guid(&t.app, &token).await;
        sqlx::query(
            "with recursive n(i) as (select 1 union all select i + 1 from n where i < ?)
             insert into ab_peer(ab_guid, id, data, tags, created_at, updated_at)
             select ?, 'p' || i, json_object('note', hex(randomblob(?))), '[]', 0, 0 from n",
        )
        .bind(n)
        .bind(&book)
        .bind((note / 2) as i64)
        .execute(&t.state.db)
        .await
        .unwrap();
        (token, book)
    }

    fn page_request(token: &str, book: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/ab/peers?current=1&pageSize=1000&ab={book}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    /// The next frame of a response body, `None` at its end.
    async fn next_frame(body: &mut axum::body::Body) -> Option<Bytes> {
        let frame = std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await?;
        Some(frame.unwrap().into_data().unwrap())
    }

    /// At most `MAX_PAGES` pages at once, counted until their response bodies are gone: the next
    /// request waits for one to be read out or dropped (a client that stops reading).
    #[tokio::test]
    async fn pages_in_flight_are_capped() {
        use tower::ServiceExt as _;
        let t = testutil::app().await;
        let all = &t.state.ab_pages.all;
        // `MAX_USER_PAGES` each, so the users together fill every slot.
        let mut users = Vec::new();
        for i in 0..=MAX_PAGES / MAX_USER_PAGES {
            users.push(big_book(&t, &format!("u{i}"), 1, 10).await);
        }
        // Answered, bodies not read: every slot held.
        let mut held = Vec::new();
        for (token, book) in &users[1..] {
            for _ in 0..MAX_USER_PAGES {
                let resp = t.app.clone().oneshot(page_request(token, book)).await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                held.push(resp);
            }
        }
        assert_eq!(all.available_permits(), 0);
        let (token, book) = &users[0];
        let ninth = tokio::spawn(t.app.clone().oneshot(page_request(token, book)));
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(!ninth.is_finished(), "the ninth page waits for a slot");
        // One body read to the end gives its slot back, and the ninth goes ahead.
        // (The collected bytes are the page's own: the slot goes back when they are dropped too.)
        let body = axum::body::to_bytes(held.pop().unwrap().into_body(), usize::MAX).await.unwrap();
        assert_eq!(js(&body)["total"], 1);
        let len = body.len() as u64;
        drop(body);
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), ninth).await.unwrap().unwrap().unwrap();
        // An exact length, so hyper sends a Content-Length (not chunked) as before.
        assert_eq!(resp.body().size_hint().exact(), Some(len));
        // Bodies dropped unread (the connection gone) give theirs back too, and no user is left.
        drop((resp, held));
        assert_eq!(all.available_permits(), MAX_PAGES);
        assert_eq!(t.state.ab_pages.free().1, 0);
    }

    /// A user's third page waits for one of their first two, while other users go ahead (review
    /// D-4); waiting counts toward the request timeout, and a request dropped while it waits
    /// leaves nothing behind.
    #[tokio::test]
    async fn a_users_pages_wait_beyond_their_share() {
        use tower::ServiceExt as _;
        let t = testutil::app().await;
        let (alice, alice_book) = big_book(&t, "alice", 1, 10).await;
        let (bob, bob_book) = big_book(&t, "bob", 1, 10).await;
        let mut held = Vec::new();
        for _ in 0..MAX_USER_PAGES {
            held.push(t.app.clone().oneshot(page_request(&alice, &alice_book)).await.unwrap());
        }
        let third = tokio::spawn(t.app.clone().oneshot(page_request(&alice, &alice_book)));
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            t.app.clone().oneshot(page_request(&bob, &bob_book)),
        )
        .await
        .expect("another user's page does not wait")
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        drop(resp);
        assert!(!third.is_finished(), "the user's third page waits");
        assert_eq!(t.state.ab_pages.all.available_permits(), MAX_PAGES - MAX_USER_PAGES);
        // A waiting request dropped (as by the request timeout) takes its place back: two held,
        // the third waiting.
        let fourth = tokio::spawn(t.app.clone().oneshot(page_request(&alice, &alice_book)));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        fourth.abort();
        let _ = fourth.await;
        let counts: Vec<usize> = t.state.ab_pages.users.lock().unwrap().values().map(|(_, n)| *n).collect();
        assert_eq!(counts, [MAX_USER_PAGES + 1]);
        // One of the first two read out: the third goes ahead.
        let body = axum::body::to_bytes(held.pop().unwrap().into_body(), usize::MAX).await.unwrap();
        assert_eq!(js(&body)["total"], 1);
        drop(body);
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), third).await.unwrap().unwrap().unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        drop((resp, held));
        assert_eq!(t.state.ab_pages.all.available_permits(), MAX_PAGES);
        assert_eq!(t.state.ab_pages.free().1, 0);
    }

    /// The slots go back with the page's memory (review D-3): not when the body is dropped after
    /// its last frame, but when that last frame is gone too (hyper may still have it queued).
    #[tokio::test]
    async fn page_slots_go_back_with_the_last_frame() {
        use tower::ServiceExt as _;
        let t = testutil::app().await;
        // About 200 KB: several frames.
        let (token, book) = big_book(&t, "alice", 20, 10_000).await;
        let resp = t.app.clone().oneshot(page_request(&token, &book)).await.unwrap();
        let mut body = resp.into_body();
        let mut frames = Vec::new();
        while let Some(frame) = next_frame(&mut body).await {
            frames.push(frame);
        }
        assert!(frames.len() > 2, "{} frames", frames.len());
        assert_eq!(js(&frames.concat().into())["total"], 20);
        // Body gone, frames still queued: the page's memory and its slots are still held.
        drop(body);
        let last = frames.pop().unwrap();
        drop(frames);
        assert_eq!(t.state.ab_pages.all.available_permits(), MAX_PAGES - 1);
        assert_eq!(t.state.ab_pages.free().1, 1);
        drop(last);
        assert_eq!(t.state.ab_pages.all.available_permits(), MAX_PAGES);
        assert_eq!(t.state.ab_pages.free().1, 0);
    }

    #[tokio::test]
    async fn tags_add_update_list() {
        let t = testutil::app().await;
        let (_, token) = testutil::create_user(&t.state.db, "alice", "", false).await;
        let book = personal_guid(&t.app, &token).await;
        let list = || {
            let (app, token, book) = (t.app.clone(), token.clone(), book.clone());
            async move {
                let (status, ct, body) = send(&app, "POST", &format!("/api/ab/tags/{book}"), Some(&token), "").await;
                assert_eq!((status, ct.as_str()), (StatusCode::OK, JSON));
                body
            }
        };
        assert_eq!(&list().await[..], b"[]");

        let add = format!("/api/ab/tag/add/{book}");
        write_ok(&t.app, "POST", &add, &token, r#"{"name":"b","color":4294967295}"#).await;
        write_ok(&t.app, "POST", &add, &token, r#"{"name":"a","color":4278190080}"#).await;
        // Same name: success, color unchanged.
        write_ok(&t.app, "POST", &add, &token, r#"{"name":"b","color":1}"#).await;
        write_err(&t.app, "POST", &add, &token, r#"{"name":"c","color":"1"}"#, StatusCode::BAD_REQUEST).await;
        write_err(&t.app, "POST", &add, &token, r#"{"name":"c"}"#, StatusCode::BAD_REQUEST).await;
        assert_eq!(
            js(&list().await),
            serde_json::json!([{"name": "a", "color": 4278190080u32}, {"name": "b", "color": 4294967295u32}])
        );

        let update = format!("/api/ab/tag/update/{book}");
        write_ok(&t.app, "PUT", &update, &token, r#"{"name":"a","color":4278255360}"#).await;
        write_err(&t.app, "PUT", &update, &token, r#"{"name":"zz","color":1}"#, StatusCode::NOT_FOUND).await;
        assert_eq!(js(&list().await)[0], serde_json::json!({"name": "a", "color": 4278255360u32}));
    }

    #[tokio::test]
    async fn tag_rename_and_delete_cascade() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (_, token) = testutil::create_user(db, "alice", "", false).await;
        let book = personal_guid(&t.app, &token).await;
        let other = shared_book(db, "other", testutil::create_user(db, "bob", "", false).await.0).await;
        for name in ["t1", "t2", "t3"] {
            write_ok(&t.app, "POST", &format!("/api/ab/tag/add/{book}"), &token, &format!(r#"{{"name":"{name}","color":1}}"#))
                .await;
        }
        // p2 carries an orphan tag "t5" (not in ab_tag).
        for (id, tags) in [("p1", r#"["t1","t2"]"#), ("p2", r#"["t2","t5"]"#), ("p3", r#"["t3","t1"]"#)] {
            write_ok(&t.app, "POST", &format!("/api/ab/peer/add/{book}"), &token, &format!(r#"{{"id":"{id}","tags":{tags}}}"#))
                .await;
        }
        // Another book's peer with the same tag is not touched.
        sqlx::query("insert into ab_peer(ab_guid, id, tags, created_at, updated_at) values(?, 'q', '[\"t1\"]', 1, 1)")
            .bind(&other)
            .execute(db)
            .await
            .unwrap();
        let tags_of = |id: &'static str| {
            let book = book.clone();
            async move { stored(db, &book, id).await.1 }
        };
        let names = || {
            let book = book.clone();
            async move {
                sqlx::query_scalar::<_, String>("select name from ab_tag where ab_guid = ? order by name")
                    .bind(book)
                    .fetch_all(db)
                    .await
                    .unwrap()
            }
        };

        let rename = format!("/api/ab/tag/rename/{book}");
        write_err(&t.app, "PUT", &rename, &token, r#"{"old":"nope","new":"x"}"#, StatusCode::NOT_FOUND).await;
        write_err(&t.app, "PUT", &rename, &token, r#"{"old":"t1","new":"t2"}"#, StatusCode::CONFLICT).await;
        assert_eq!(tags_of("p1").await, ["t1", "t2"]);

        write_ok(&t.app, "PUT", &rename, &token, r#"{"old":"t1","new":"t4"}"#).await;
        assert_eq!(names().await, ["t2", "t3", "t4"]);
        assert_eq!(tags_of("p1").await, ["t4", "t2"]);
        assert_eq!(tags_of("p3").await, ["t3", "t4"]);
        assert_eq!(stored(db, &other, "q").await.1, ["t1"]);
        // Renaming onto a name some peer already carries removes the duplicate.
        write_ok(&t.app, "PUT", &rename, &token, r#"{"old":"t2","new":"t5"}"#).await;
        assert_eq!(tags_of("p2").await, ["t5"]);
        assert_eq!(tags_of("p1").await, ["t4", "t5"]);

        let delete = format!("/api/ab/tag/{book}");
        write_ok(&t.app, "DELETE", &delete, &token, r#"["t4","missing"]"#).await;
        assert_eq!(names().await, ["t3", "t5"]);
        assert_eq!(tags_of("p1").await, ["t5"]);
        assert_eq!(tags_of("p3").await, ["t3"]);
        assert_eq!(tags_of("p2").await, ["t5"]);
        write_err(&t.app, "DELETE", &delete, &token, r#""t3""#, StatusCode::BAD_REQUEST).await;
    }

    /// `DELETE /api/ab/tag` names are deduplicated and counted before the transaction (review
    /// D-14): over `MAX_TAGS` distinct names is a 400 that touches nothing; names over the tag
    /// limits (imported ones, §15) are deleted like any other; a full book of 5000 peers with 64
    /// tags each cascades well within the request timeout.
    #[tokio::test]
    async fn tag_delete_names_are_capped() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (_, token) = testutil::create_user(db, "alice", "", false).await;
        let book = personal_guid(&t.app, &token).await;
        // Every peer carries "m" and 63 two-byte tags.
        let tags: Vec<String> = std::iter::once("m".to_owned()).chain((0..63).map(|i| format!("{i:02}"))).collect();
        sqlx::query(
            "with recursive n(i) as (select 1 union all select i + 1 from n where i < ?)
             insert into ab_peer(ab_guid, id, tags, created_at, updated_at) select ?, 'p' || i, ?, 0, 0 from n",
        )
        .bind(MAX_PEERS)
        .bind(&book)
        .bind(serde_json::to_string(&tags).unwrap())
        .execute(db)
        .await
        .unwrap();
        let carrying_m = || {
            let book = book.clone();
            async move {
                sqlx::query_scalar::<_, i64>(
                    "select count(*) from ab_peer where ab_guid = ? and exists (select 1 from json_each(tags) where value = 'm')",
                )
                .bind(book)
                .fetch_one(db)
                .await
                .unwrap()
            }
        };
        let delete = format!("/api/ab/tag/{book}");
        let over: Vec<String> = std::iter::once("m".to_owned()).chain((0..MAX_TAGS).map(|i| format!("x{i}"))).collect();
        write_err(&t.app, "DELETE", &delete, &token, &serde_json::to_string(&over).unwrap(), StatusCode::BAD_REQUEST)
            .await;
        assert_eq!(carrying_m().await, MAX_PEERS);
        // Names over the tag limits (as an import leaves them, §15) are matched and deleted.
        let long = "y".repeat(MAX_TAG_LEN + 1);
        let ctrl = "a\u{1}".to_owned();
        for name in [&long, &ctrl] {
            sqlx::query("insert into ab_tag(ab_guid, name, color) values(?, ?, 1)")
                .bind(&book)
                .bind(name)
                .execute(db)
                .await
                .unwrap();
        }
        let odd = serde_json::json!(["00", &long, &ctrl]).to_string();
        sqlx::query("update ab_peer set tags = ? where ab_guid = ? and id = 'p2'")
            .bind(&odd)
            .bind(&book)
            .execute(db)
            .await
            .unwrap();
        write_ok(&t.app, "DELETE", &delete, &token, &serde_json::json!([&long, &ctrl]).to_string()).await;
        assert_eq!(stored(db, &book, "p2").await.1, ["00"]);
        let left: i64 = sqlx::query_scalar("select count(*) from ab_tag where ab_guid = ?")
            .bind(&book)
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(left, 0);
        // ~60,000 entries are fine when they are few distinct names: "m", 998 others and "z".
        let mut names: Vec<String> = std::iter::once("m".to_owned()).chain((0..998).map(|i| format!("x{i}"))).collect();
        names.extend(std::iter::repeat("z".to_owned()).take(60_000));
        let body = serde_json::to_string(&names).unwrap();
        assert!(body.len() <= super::super::AB_TAG_DELETE_BODY_LIMIT, "{}", body.len());
        let start = std::time::Instant::now();
        write_ok(&t.app, "DELETE", &delete, &token, &body).await;
        assert!(start.elapsed() < std::time::Duration::from_secs(10), "took {:?}", start.elapsed());
        assert_eq!(carrying_m().await, 0);
        assert_eq!(stored(db, &book, "p1").await.1, tags[1..]);
    }

    /// `DELETE /api/ab/peer` checks its array as it reads it (review D-16): over `MAX_PEERS` ids or
    /// anything but an array of strings is a 400 that deletes nothing; SQLite reads the ids out of
    /// the checked body, escapes included. An id over `MAX_PEER_ID_LEN`, as the import can bring
    /// in, is deleted like any other (review E-4).
    #[tokio::test]
    async fn peer_delete_checks_the_ids() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (_, token) = testutil::create_user(db, "alice", "", false).await;
        let book = personal_guid(&t.app, &token).await;
        let imported = "x".repeat(MAX_PEER_ID_LEN + 1);
        for id in ["p1", "a\"b", "é", &imported] {
            sqlx::query("insert into ab_peer(ab_guid, id, created_at, updated_at) values(?, ?, 0, 0)")
                .bind(&book)
                .bind(id)
                .execute(db)
                .await
                .unwrap();
        }
        let delete = format!("/api/ab/peer/{book}");
        let too_many = serde_json::to_string(&vec!["p1"; MAX_PEERS as usize + 1]).unwrap();
        // The 2 MB the route allows, as short elements: refused at element 5001.
        let mut huge = "[".to_owned() + &r#""","#.repeat((2 << 20) / 3 - 2);
        huge.push_str(r#""p1"]"#);
        assert!(huge.len() <= super::super::AB_PEER_DELETE_BODY_LIMIT);
        for (body, want) in [
            (too_many.as_str(), "too many peer ids"),
            (huge.as_str(), "too many peer ids"),
            (r#"["p1",1]"#, "invalid type"),
            (r#"{"id":"p1"}"#, "invalid type"),
            (r#"["p1"] x"#, "trailing characters"),
            (r#"["p1""#, "EOF"),
        ] {
            let (status, _, resp) = send(&t.app, "DELETE", &delete, Some(&token), body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{}", &body[..body.len().min(40)]);
            let msg = js(&resp)["error"].as_str().unwrap().to_owned();
            assert!(msg.starts_with("Invalid request body: ") && msg.contains(want), "{msg}");
        }
        assert_eq!(list_peers(&t.app, &token, &book).await.len(), 4);
        let body = serde_json::json!(["a\"b", "é", "nope", imported, "y".repeat(10_000)]).to_string();
        write_ok(&t.app, "DELETE", &delete, &token, &body).await;
        let left: Vec<Value> = list_peers(&t.app, &token, &book).await.iter().map(|p| p["id"].clone()).collect();
        assert_eq!(left, ["p1"]);
        write_ok(&t.app, "DELETE", &delete, &token, "[]").await;
    }
}
