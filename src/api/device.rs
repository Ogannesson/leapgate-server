//! Device reports: sysinfo and heartbeat / strategy push (LEAPGATE.md §9.3, §10; notes 01, 03 §4).
//! No authentication (compatibility debt); only devices registered with hbbs, checked by `uuid`.
//! Leapgate clients' signed heartbeat (`leapgate_heartbeat`, phase 3 contract 01 §3.6) shares the row
//! writes (`touch`, `store_sysinfo`).

use super::{
    devauth::{parse_body, leapgate_error, leapgate_internal, signed_json, SignedBody},
    ok_json, parse_json, text, ApiResult, ClientIp,
};
use crate::{
    conn_tracker::{clip, has_room, now_ms, source_key, IP_WINDOW_MS},
    peer::{LeapgateHb, MAX_PEER_ID_LEN},
    state::AppState,
};
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use hbb_common::throttled_log;
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};
use sqlx::{SqliteConnection, SqlitePool};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Longest `uuid` (base64 text) the device reports and the login accept. Real ones are the base64
/// of a machine id, well under this.
pub(crate) const MAX_UUID_LEN: usize = 128;
/// Largest sysinfo body accepted; it is stored whole as `device.sysinfo`. A real one is a few
/// hundred bytes; without this every registered device could keep 2 MB (the body limit) there.
const MAX_SYSINFO_LEN: usize = 8 * 1024;
/// `hostname`, `username`, `os` and `version` are stored again in their own columns, clipped to this.
const MAX_SYSINFO_FIELD_LEN: usize = 253;
/// Device rows at most. Registering with hbbs is not authenticated, so made-up devices that pass
/// `uuid_matches` can still add rows (review A-10). Kept when a report creates a row (`make_room`),
/// not by a periodic purge: between two purges every id ever registered could come back (review
/// C-10/C-18/C-26). A row is at most about 10.5 KB on disk (8 KB of sysinfo, 4 × 253 bytes of split
/// fields, the id and uuid; measured with 4 KB pages, the primary key index included): 10,000 rows ≈
/// 0.1 GB. Rows `make_room` may not evict are kept even past this, and reports and logins then
/// create no rows; imports add rows without this check.
const MAX_DEVICES: i64 = 10_000;
/// Rows one `make_room` deletes at most when the table is past `MAX_DEVICES` (review D-7: deleting
/// the whole excess in one write transaction held the write lock for seconds, and past the request
/// timeout it was rolled back and started over by every next new row). 64 rows of 10.5 KB read cold
/// are tens of milliseconds.
const EVICT_BATCH: i64 = 64;
/// A heartbeat that changes nothing else writes `last_seen_at` only once the stored one is this many
/// seconds old: heartbeats come every 15 s (every 3 s while the device is in a session), and every
/// write takes the database's write lock, which hbbs's registrations also wait on (§4.1).
const LAST_SEEN_STEP: i64 = 60;
/// Reports (heartbeat, sysinfo, audits) per source per minute (`report_allowed`). A NAT with 50
/// devices, all in sessions: 50 × 20 heartbeats (one every 3 s; idle devices send 4 a minute) =
/// 1,000; sysinfo and audits, a few per session, fit in what devices not in a session leave. Without
/// a budget one source could keep the write lock busy with reports that create rows (`make_room`, a
/// write transaction each) and, through `busy_timeout`, stall hbbs's registrations.
const REPORTS_PER_MIN: u32 = 1_000;
/// Sources with a budget at most (about 50 bytes each, ~3 MB). When full and no window has ended, a
/// new source goes without a budget, as with hbbs's `IP_BLOCKER`: whoever holds that many sources
/// gets that many budgets anyway.
const MAX_REPORT_SOURCES: usize = 65_536;

/// Per-source report budgets, counted per `source_key` (an IPv4 address or an IPv6 /64) in fixed
/// one-minute windows, the same way as `conn_tracker`'s new-row limit.
#[derive(Default)]
struct ReportBudgets {
    /// `source_key` → (start of its current minute, reports in it), unix ms.
    sources: HashMap<IpAddr, (i64, u32)>,
    /// When the ended windows were last dropped: at most once a window, so a full map does not
    /// cost a scan per request.
    pruned_at: i64,
}

impl ReportBudgets {
    fn allow(&mut self, ip: IpAddr, now: i64) -> bool {
        let key = source_key(ip);
        if !self.sources.contains_key(&key) && self.sources.len() >= MAX_REPORT_SOURCES {
            if now - self.pruned_at >= IP_WINDOW_MS {
                self.sources.retain(|_, (start, _)| now - *start < IP_WINDOW_MS);
                self.pruned_at = now;
            }
            if self.sources.len() >= MAX_REPORT_SOURCES {
                throttled_log!(
                    Duration::from_secs(60),
                    warn,
                    "Device report budgets are full ({MAX_REPORT_SOURCES} sources): {key} goes without one"
                );
                return true;
            }
        }
        let window = self.sources.entry(key).or_insert((now, 0));
        if !has_room(window, now, REPORTS_PER_MIN) {
            return false;
        }
        window.1 += 1;
        true
    }
}

static REPORT_BUDGETS: Lazy<Mutex<ReportBudgets>> = Lazy::new(Default::default);

/// Counts a device report (heartbeat, sysinfo, audit) from `ip` (`ClientIp`) against its source's
/// `REPORTS_PER_MIN`; false when over it. Behind a reverse proxy on this machine the source is the
/// proxy's `X-Real-IP` (§10).
pub(crate) fn report_allowed(ip: IpAddr) -> bool {
    REPORT_BUDGETS.lock().unwrap_or_else(|e| e.into_inner()).allow(ip, now_ms())
}

/// Result of `uuid_matches`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum UuidCheck {
    Mismatch,
    Match,
    /// Matches, and a signed Leapgate report pinned the device's key: the unsigned reports of the id are
    /// refused from then on (phase 3 contract 01 §3.5: they are what a downgrade would fall back to),
    /// the login's binding is not.
    MatchPinned,
}

/// Identity check of the unauthenticated device reports and of the login's device binding (§9.3):
/// hbbs' `peer` table must know `id` (real clients register before they report), and `uuid` must be
/// present and decode (standard base64) to `peer.uuid` byte for byte. An id over `MAX_PEER_ID_LEN`
/// or a uuid over `MAX_UUID_LEN` bytes fails without a query. The reports pass on `Match` only.
pub(crate) async fn uuid_matches(db: &SqlitePool, id: &str, uuid: Option<&str>) -> Result<UuidCheck, sqlx::Error> {
    let Some(uuid) = uuid.filter(|u| u.len() <= MAX_UUID_LEN) else {
        return Ok(UuidCheck::Mismatch);
    };
    if id.len() > MAX_PEER_ID_LEN {
        return Ok(UuidCheck::Mismatch);
    }
    let known: Option<(Vec<u8>, bool)> =
        sqlx::query_as("select uuid, pk_pinned_at is not null from peer where id = ?")
            .bind(id)
            .fetch_optional(db)
            .await?;
    Ok(match known {
        Some((known, pinned)) if base64::decode(uuid).is_ok_and(|u| u == known) => {
            if pinned {
                UuidCheck::MatchPinned
            } else {
                UuidCheck::Match
            }
        }
        _ => UuidCheck::Mismatch,
    })
}

/// Late binding (§11) of a device that passed `uuid_matches` and has no owner, written as
/// `user_id = coalesce(user_id, OWNER_FROM_TOKEN)` by the statement that writes the device row, with
/// the device's id as `?1` and the reported uuid as `?2`: a login on it made before it was
/// registered with hbbs (the login binds only registered devices) left a token row with its id and
/// uuid. The newest such token (`last_used_at`) of an enabled account gives the owner. As safe as
/// the login's binding: the token's uuid is the one just checked against hbbs. Reading the token
/// and writing the owner in one statement keeps a logout from deleting the token in between and
/// being undone (review C-24). A device whose key is pinned takes only a token issued before it was
/// pinned (same second included, phase 4 A1): after pinning, its owner's login binds it directly,
/// so a later token left to bind it is a login that found it owned, and must not take it over
/// once the owner logs out.
const OWNER_FROM_TOKEN: &str = "(select t.user_id from token t join user u on u.id = t.user_id
     where t.device_id = ?1 and t.device_uuid = ?2 and u.status = 1
       and not exists (select 1 from peer p where p.id = ?1 and p.pk_pinned_at < t.created_at)
     order by t.last_used_at desc limit 1)";

/// The `?1` oldest (`last_seen_at`) rows a report may delete to make room: unowned ones, and owned
/// ones whose owner has no token left on the device (review C-19: a login binds any registered id,
/// but a user keeps at most `MAX_TOKENS` = 50 tokens, so the owned rows kept are at most 50 per user,
/// and a binding made up with a login goes once its token does). Never a row with a `device_policy`
/// or device-scoped `strategy_option` row (neither table references `device`, so nothing goes with
/// the row). Neither arm reads the table's `last_seen_at`, which sits after the 8 KB sysinfo in
/// overflow pages (review C-16), and both stop once they have `?1` rows: the unowned arm reads
/// `device_user_seen(user_id, last_seen_at)` (migration 0002) in order; the owned arm reads the
/// partial index `device_owned_seen(last_seen_at, user_id, id)` (migration 0003), which covers its
/// token check, looked up on `token_user_device(user_id, device_id)` (review D-6: on
/// `device_user_seen` it sorted every owned row, reading each one's id in the table and its owner's
/// up to 50 tokens, ~100 ms in the write lock with 10,000 owned rows). So it reads past only the
/// owned rows that still have a token, at most 50 per user. Pinned with `indexed by`: with only
/// 0002's index the planner took a full scan for `user_id is not null`.
const EVICTABLE: &str = "
    select id, last_seen_at from (
      select id, last_seen_at from device d where user_id is null
        and not exists (select 1 from device_policy p where p.device_id = d.id)
        and not exists (select 1 from strategy_option s where s.scope = d.id)
      order by last_seen_at limit ?1)
    union all
    select id, last_seen_at from (
      select id, last_seen_at from device d indexed by device_owned_seen where user_id is not null
        and not exists (select 1 from token t where t.user_id = d.user_id and t.device_id = d.id)
        and not exists (select 1 from device_policy p where p.device_id = d.id)
        and not exists (select 1 from strategy_option s where s.scope = d.id)
      order by last_seen_at limit ?1)
    order by last_seen_at limit ?1";

/// Before a report or a login (`account.rs`) writes the row of `id` that did not exist, in `tx`
/// (`begin immediate`): true when the row exists by now (a concurrent first report) or there is
/// room for it, after deleting the oldest evictable rows (`EVICTABLE`) if the table is at
/// `MAX_DEVICES`: normally one; past the limit (an import adds rows without this check) the excess,
/// at most `EVICT_BATCH`, and one deleted is enough for the insert, so the table never grows and
/// comes back to the limit over the next new rows. False when none may be evicted, and then the
/// caller writes nothing and drops `tx`. An evicted device that comes back gets a new row, and its
/// heartbeat asks for its sysinfo again (`sysinfo` key, §10). Real devices report every 15 s, so
/// the oldest rows are normally ones that stopped; a reporter can keep its own rows the newest.
pub(crate) async fn make_room(tx: &mut SqliteConnection, id: &str) -> Result<bool, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("select exists(select 1 from device where id = ?)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if exists {
        return Ok(true);
    }
    let rows: i64 = sqlx::query_scalar("select count(*) from device").fetch_one(&mut *tx).await?;
    if rows < MAX_DEVICES {
        return Ok(true);
    }
    let want = (rows - MAX_DEVICES + 1).min(EVICT_BATCH);
    let deleted = sqlx::query(&format!("delete from device where id in (select id from ({EVICTABLE}))"))
        .bind(want)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    Ok(deleted >= 1)
}

/// A write transaction that takes the write lock up front: one that reads first and writes later
/// fails with `SQLITE_BUSY_SNAPSHOT` when another connection wrote in between, which `busy_timeout`
/// does not retry.
pub(crate) const BEGIN_WRITE: &str = "begin immediate";

/// sysinfo body (note 01 §5.2): every value is a string; the rest of the keys are kept in the raw text.
#[derive(Deserialize)]
struct SysinfoReq {
    id: String,
    uuid: Option<String>,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    version: String,
}

/// `POST /api/sysinfo`: plain text `SYSINFO_UPDATED` on success, never `ID_NOT_FOUND`; a refusal
/// (over the source's budget, too long, not a registered device or one whose key is pinned, no room
/// in the device table) is 403 with an empty body, which the client retries after 120 s.
pub(crate) async fn sysinfo(State(state): State<AppState>, ClientIp(ip): ClientIp, body: Bytes) -> ApiResult {
    let refused = || Ok(StatusCode::FORBIDDEN.into_response());
    if !report_allowed(ip) || body.len() > MAX_SYSINFO_LEN {
        return refused();
    }
    let req: SysinfoReq = parse_json(&body)?;
    if uuid_matches(&state.db, &req.id, req.uuid.as_deref()).await? != UuidCheck::Match {
        return refused();
    }
    let fields = SysinfoFields {
        hostname: req.hostname,
        username: req.username,
        os: req.os,
        version: req.version,
    };
    let uuid = req.uuid.as_deref().unwrap_or_default();
    if !store_sysinfo(&state.db, &req.id, uuid, &String::from_utf8_lossy(&body), fields, CLIENT_RUSTDESK).await? {
        return refused();
    }
    Ok(text("SYSINFO_UPDATED"))
}

/// `device.client_type`: the path the device reported on last (`touch`, `store_sysinfo`).
const CLIENT_RUSTDESK: &str = "rustdesk";
const CLIENT_LEAPGATE: &str = "leapgate";

/// The sysinfo values stored again in their own columns (clipped to `MAX_SYSINFO_FIELD_LEN`).
#[derive(Default, Deserialize)]
pub(crate) struct SysinfoFields {
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    version: String,
}

/// Stores the sysinfo text `raw` of `id` (already checked) and its split `f`, with the reported
/// `uuid` for the late binding (§11) and the path it came on: in a `make_room` transaction, so it
/// creates the row if needed within the device table's limit. False when there was no room (nothing
/// written). Rare (a device sends it when it starts or its sysinfo changes), so it always writes.
pub(crate) async fn store_sysinfo(
    db: &SqlitePool,
    id: &str,
    uuid: &str,
    raw: &str,
    mut f: SysinfoFields,
    client_type: &str,
) -> Result<bool, sqlx::Error> {
    for field in [&mut f.hostname, &mut f.username, &mut f.os, &mut f.version] {
        clip(field, MAX_SYSINFO_FIELD_LEN);
    }
    let mut tx = db.begin_with(BEGIN_WRITE).await?;
    if !make_room(&mut tx, id).await? {
        return Ok(false);
    }
    const SET: &str = "uuid = ?2, hostname = ?3, username = ?4, os = ?5, version = ?6,
         client_type = ?9, sysinfo = ?7, last_seen_at = ?8";
    sqlx::query(&format!(
        "insert into device(id, uuid, hostname, username, os, version, client_type, sysinfo,
                            first_seen_at, last_seen_at, user_id)
         values(?1, ?2, ?3, ?4, ?5, ?6, ?9, ?7, ?8, ?8, {OWNER_FROM_TOKEN})
         on conflict(id) do update set {SET}, user_id = coalesce(user_id, excluded.user_id)"
    ))
    .bind(id)
    .bind(uuid)
    .bind(&f.hostname)
    .bind(&f.username)
    .bind(&f.os)
    .bind(&f.version)
    .bind(raw)
    .bind(crate::common::now() as i64)
    .bind(client_type)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Heartbeat body (note 01 §1.4). `conns` is not used (no `disconnect` in phase 1).
#[derive(Deserialize)]
struct HeartbeatReq {
    id: String,
    uuid: Option<String>,
    #[serde(default)]
    ver: i64,
    #[serde(default)]
    modified_at: i64,
}

/// The client only checks whether a key is present, so absent values are omitted, never null/false.
#[derive(Default, Serialize)]
struct HeartbeatResp {
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strategy: Option<Strategy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sysinfo: Option<bool>,
}

#[derive(Serialize)]
struct Strategy {
    config_options: BTreeMap<String, String>,
}

/// `POST /api/heartbeat`: always a JSON object (at least `{}`); strategy only when `modified_at != rev`.
/// Over the source's budget, not a registered device or one whose key is pinned (it reports signed
/// on `/api/leapgate/v1/`): `{}`. The client has no branch for either
/// (rustdesk@bd92623:src/hbbs_http/sync.rs `start_hbbs_sync_async` only looks for keys) and sends
/// the next one 15 s later. No room for a new row (`make_room`): served without the row, so without
/// the `sysinfo` key.
pub(crate) async fn heartbeat(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    body: Bytes,
) -> ApiResult {
    if !report_allowed(ip) {
        return Ok(ok_json(&HeartbeatResp::default()));
    }
    let req: HeartbeatReq = parse_json(&body)?;
    if uuid_matches(&state.db, &req.id, req.uuid.as_deref()).await? != UuidCheck::Match {
        return Ok(ok_json(&HeartbeatResp::default()));
    }
    let uuid = req.uuid.as_deref().unwrap_or_default();
    let stored = touch(&state.db, &req.id, uuid, req.ver, &ip.to_string(), CLIENT_RUSTDESK).await?;
    let mut resp = HeartbeatResp {
        sysinfo: stored.is_some_and(|s| s.is_empty()).then_some(true),
        ..Default::default()
    };
    let (rev, options) = crate::strategy::effective(&state.db, &req.id).await?;
    if req.modified_at != rev {
        resp.modified_at = Some(rev);
        resp.strategy = Some(Strategy {
            config_options: options,
        });
    }
    Ok(ok_json(&resp))
}

/// A heartbeat's write of the device row of `id` (already checked): `ver`, `last_ip` and the path it
/// came on (`client_type`) are written when one changed, `last_seen_at` also once the stored one is
/// `LAST_SEEN_STEP` old, else nothing is written; a missing row is created within the table's limit
/// (`make_room`). Rows written with no owner get the late binding (`OWNER_FROM_TOKEN`, with the
/// reported `uuid`). Returns the stored sysinfo text (`''`: none yet); `None` when there is no row
/// (no room for it, or evicted meanwhile: served without it, the next heartbeat makes a new one).
pub(crate) async fn touch(
    db: &SqlitePool,
    id: &str,
    uuid: &str,
    ver: i64,
    ip: &str,
    client_type: &str,
) -> Result<Option<String>, sqlx::Error> {
    let now = crate::common::now() as i64;
    let seen: Option<(i64, i64, String, String, String)> =
        sqlx::query_as("select ver, last_seen_at, last_ip, client_type, sysinfo from device where id = ?")
            .bind(id)
            .fetch_optional(db)
            .await?;
    match seen {
        Some((old_ver, last_seen, last_ip, old_type, sysinfo))
            if old_ver == ver && last_ip == ip && old_type == client_type && now - last_seen < LAST_SEEN_STEP =>
        {
            Ok(Some(sysinfo))
        }
        // Changed, or `last_seen_at` due.
        Some(_) => {
            sqlx::query_scalar(&format!(
                "update device set ver = ?3, last_seen_at = ?4, last_ip = ?5, client_type = ?6,
                   user_id = coalesce(user_id, {OWNER_FROM_TOKEN})
                 where id = ?1 returning sysinfo"
            ))
            .bind(id)
            .bind(uuid)
            .bind(ver)
            .bind(now)
            .bind(ip)
            .bind(client_type)
            .fetch_optional(db)
            .await
        }
        None => {
            let mut tx = db.begin_with(BEGIN_WRITE).await?;
            if !make_room(&mut tx, id).await? {
                return Ok(None);
            }
            // `on conflict`: another first heartbeat of the same device may have made the row.
            let sysinfo = sqlx::query_scalar(&format!(
                "insert into device(id, uuid, ver, first_seen_at, last_seen_at, last_ip, client_type, user_id)
                 values(?1, ?2, ?3, ?4, ?4, ?5, ?6, {OWNER_FROM_TOKEN})
                 on conflict(id) do update set ver = ?3, last_seen_at = ?4, last_ip = ?5, client_type = ?6,
                   user_id = coalesce(user_id, excluded.user_id)
                 returning sysinfo"
            ))
            .bind(id)
            .bind(uuid)
            .bind(ver)
            .bind(now)
            .bind(ip)
            .bind(client_type)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(Some(sysinfo))
        }
    }
}

/// Features of this server the Leapgate client may use (response `features`); block 05 (self-built
/// ICE) adds `"ice"`, announced with or without the rendezvous private key (contract 05 §2.12).
/// `"exit"` (phase 4): this server has the exit directory `/api/leapgate/user/v1/exits`.
const LEAPGATE_FEATURES: &[&str] = &["ice", "exit"];

/// `POST /api/leapgate/v1/heartbeat` body (contract 01 §2.3, 02 §2.2); absent keys are absent values.
/// The id comes from the signature (`SignedBody`). `conns` is not used.
#[derive(Deserialize)]
struct LeapgateHeartbeatReq {
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    ver: i64,
    /// The client's `libs/leapgate` version (`LeapgateHb::leapgate_ver`), not stored.
    #[serde(default)]
    leapgate: String,
    #[serde(default)]
    strategy_rev: i64,
    /// Standard base64 of the sha256 of the client's `sysinfo` bytes.
    #[serde(default)]
    sysinfo_hash: String,
    /// Kept byte for byte: the hash is over these bytes.
    sysinfo: Option<Box<RawValue>>,
    /// Rev of the relay list the client holds (0: none yet).
    #[serde(default)]
    routing_rev: i64,
    /// The client's latest round of relay measurements; any JSON here, a bad one only drops the
    /// round (`Router::record_probes`), never the heartbeat.
    probes: Option<serde_json::Value>,
    /// Phase 4: the device accepts exit logins now (`LeapgateHb::exit`); absent = false.
    #[serde(default)]
    exit: bool,
}

#[derive(Serialize)]
struct LeapgateHeartbeatResp {
    api: u32,
    features: &'static [&'static str],
    time: i64,
    /// Only `true`, only when wanted.
    #[serde(skip_serializing_if = "Option::is_none")]
    need_sysinfo: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strategy: Option<LeapgateStrategy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    routing: Option<LeapgateRouting>,
}

/// The relays to measure (routing level two), sent when the client's `routing_rev` is not `rev`.
#[derive(Serialize)]
struct LeapgateRouting {
    rev: i64,
    probe_interval_secs: u64,
    relays: Vec<String>,
}

/// Every effective option (values are strings, `''` deletes the key) and their `rev`.
#[derive(Serialize)]
struct LeapgateStrategy {
    rev: i64,
    options: BTreeMap<String, String>,
}

/// `POST /api/leapgate/v1/heartbeat` (contract 01 §3.6, 02 §3.4): a signed heartbeat. Records it in
/// memory (`Peer::leapgate_hb`) along with its relay measurements (routing level two; none in the
/// heartbeat drops the device's last round), stores a
/// sysinfo that came with it, writes the device row (`touch`, as `leapgate`), and answers signed:
/// `need_sysinfo` when the stored sysinfo is missing or its hash is not the reported one, the
/// effective options when their rev is not the reported one, the relays to measure when their rev
/// is not the reported one. Bad body 400, sysinfo over `MAX_SYSINFO_LEN` 413, database error 503
/// (all unsigned).
pub(crate) async fn leapgate_heartbeat(State(state): State<AppState>, signed: SignedBody) -> Response {
    let req: LeapgateHeartbeatReq = match parse_body(&signed.body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };
    if req.uuid.len() > MAX_UUID_LEN {
        return leapgate_error(StatusCode::BAD_REQUEST, "bad_request", "uuid too long");
    }
    let sysinfo = match &req.sysinfo {
        Some(raw) if raw.get().len() > MAX_SYSINFO_LEN => {
            return leapgate_error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "sysinfo too large")
        }
        Some(raw) => match parse_body::<SysinfoFields>(raw.get().as_bytes()) {
            Ok(fields) => Some((raw.get(), fields)),
            Err(resp) => return resp,
        },
        None => None,
    };
    let leapgate_ver = hbb_common::get_version_number(&req.leapgate).clamp(0, u32::MAX as i64) as u32;
    signed.peer.write().await.leapgate_hb = Some(LeapgateHb {
        at: Instant::now(),
        leapgate_ver,
        exit: req.exit,
    });
    // Under the verified id: nobody can report measurements for another device.
    match &req.probes {
        Some(probes) => state.router.record_probes(&signed.id, probes),
        None => state.router.forget_probes(&signed.id),
    }
    let db = &state.db;
    if let Some((raw, fields)) = sysinfo {
        if let Err(err) = store_sysinfo(db, &signed.id, &req.uuid, raw, fields, CLIENT_LEAPGATE).await {
            return leapgate_internal(err);
        }
    }
    let stored = match touch(db, &signed.id, &req.uuid, req.ver, &signed.ip.to_string(), CLIENT_LEAPGATE).await {
        Ok(stored) => stored,
        Err(err) => return leapgate_internal(err),
    };
    let need_sysinfo = stored
        .is_some_and(|s| s.is_empty() || base64::encode(Sha256::digest(s.as_bytes())) != req.sysinfo_hash)
        .then_some(true);
    let (rev, options) = match crate::strategy::effective(db, &signed.id).await {
        Ok(v) => v,
        Err(err) => return leapgate_internal(format!("{err:#}")),
    };
    let (routing_rev, relays) = state.router.routing();
    let resp = LeapgateHeartbeatResp {
        api: 1,
        features: LEAPGATE_FEATURES,
        time: crate::common::now() as i64,
        need_sysinfo,
        strategy: (req.strategy_rev != rev).then_some(LeapgateStrategy { rev, options }),
        routing: (req.routing_rev != routing_rev).then_some(LeapgateRouting {
            rev: routing_rev,
            probe_interval_secs: crate::router::PROBE_INTERVAL_SECS,
            relays,
        }),
    };
    signed_json(&state, &signed.sig, StatusCode::OK, &resp)
}

/// `explain query plan` of `sql` (parameters written as literals): the `detail` of every step.
#[cfg(test)]
pub(crate) async fn query_plan(db: &SqlitePool, sql: &str) -> Vec<String> {
    let rows: Vec<(i64, i64, i64, String)> =
        sqlx::query_as(&format!("explain query plan {sql}")).fetch_all(db).await.unwrap();
    rows.into_iter().map(|r| r.3).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        query_plan, ReportBudgets, EVICTABLE, EVICT_BATCH, LAST_SEEN_STEP, MAX_DEVICES, MAX_PEER_ID_LEN, MAX_REPORT_SOURCES,
        MAX_SYSINFO_FIELD_LEN, MAX_SYSINFO_LEN, MAX_UUID_LEN, REPORTS_PER_MIN,
    };
    use crate::testutil::{self, send};
    use axum::http::StatusCode;
    use hbb_common::tokio;
    use serde_json::{json, Value};
    use sqlx::SqlitePool;
    use std::net::IpAddr;

    const UUID: &[u8] = b"8f2c1d4e-1111-2222-3333-444455556666";

    fn b64(raw: &[u8]) -> String {
        base64::encode(raw)
    }

    async fn add_peer(db: &SqlitePool, id: &str, uuid: &[u8]) {
        crate::database::Database::new(db.clone())
            .insert_peer(id, uuid, b"pk", "{}")
            .await
            .unwrap();
    }

    async fn set_option(db: &SqlitePool, scope: &str, key: &str, value: &str) {
        sqlx::query("insert or replace into strategy_option(scope, key, value) values(?, ?, ?)")
            .bind(scope)
            .bind(key)
            .bind(value)
            .execute(db)
            .await
            .unwrap();
    }

    async fn bump_epoch(db: &SqlitePool, device_id: &str) {
        sqlx::query(
            "insert into device_policy(device_id, strategy_epoch) values(?, 1)
             on conflict(device_id) do update set strategy_epoch = strategy_epoch + 1",
        )
        .bind(device_id)
        .execute(db)
        .await
        .unwrap();
    }

    async fn heartbeat(app: &axum::Router, body: Value) -> Value {
        let (status, ct, body) = send(app, "POST", "/api/heartbeat", None, &body.to_string()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json; charset=utf-8");
        serde_json::from_slice(&body).unwrap()
    }

    fn sysinfo_body(id: &str, uuid: Option<&str>, hostname: &str) -> String {
        let mut v = json!({
            "cpu": "Intel, 3.6GHz, 8/4 cores", "memory": "16GB", "os": "windows / Windows 11 Pro - 10.0.26100",
            "hostname": hostname, "username": "alice", "version": "1.5.1", "id": id,
            "preset-address-book-name": "x",
        });
        if let Some(u) = uuid {
            v["uuid"] = json!(u);
        }
        v.to_string()
    }

    #[tokio::test]
    async fn sysinfo_weak_check_and_storage() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111", UUID).await;

        // Unknown to hbbs: refused like a mismatch, with or without uuid, and no device row.
        for uuid in [None, Some(b64(UUID))] {
            let (status, _, body) =
                send(&t.app, "POST", "/api/sysinfo", None, &sysinfo_body("222", uuid.as_deref(), "h2")).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert!(body.is_empty());
        }
        let n: i64 = sqlx::query_scalar("select count(*) from device").fetch_one(db).await.unwrap();
        assert_eq!(n, 0);

        // Known id, matching uuid: stored with the raw text and split fields.
        let raw = sysinfo_body("111", Some(&b64(UUID)), "h1");
        let (status, ct, body) = send(&t.app, "POST", "/api/sysinfo", None, &raw).await;
        assert_eq!((status, ct.as_str(), &body[..]), (StatusCode::OK, "text/plain; charset=utf-8", &b"SYSINFO_UPDATED"[..]));
        let row: (String, String, String, String, String, String, String) = sqlx::query_as(
            "select uuid, hostname, username, os, version, client_type, sysinfo from device where id = '111'",
        )
        .fetch_one(db)
        .await
        .unwrap();
        assert_eq!(
            row,
            (
                b64(UUID),
                "h1".into(),
                "alice".into(),
                "windows / Windows 11 Pro - 10.0.26100".into(),
                "1.5.1".into(),
                "rustdesk".into(),
                raw
            )
        );

        // Known id, wrong or missing uuid: 403 with an empty body, nothing changes.
        for uuid in [Some(b64(b"other")), Some("not base64!".to_owned()), None] {
            let (status, _, body) =
                send(&t.app, "POST", "/api/sysinfo", None, &sysinfo_body("111", uuid.as_deref(), "evil")).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert!(body.is_empty());
        }
        let host: String = sqlx::query_scalar("select hostname from device where id = '111'")
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(host, "h1");

        // A broken body is a 400 with a JSON error, never ID_NOT_FOUND.
        let (status, ct, _) = send(&t.app, "POST", "/api/sysinfo", None, "nope").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(ct, "application/json; charset=utf-8");
    }

    #[tokio::test]
    async fn heartbeat_weak_check() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111", UUID).await;

        // Mismatch or missing uuid: `{}`, no device row.
        for uuid in [json!(b64(b"other")), Value::Null] {
            let mut body = json!({"id": "111", "ver": 1005010, "modified_at": 0});
            if !uuid.is_null() {
                body["uuid"] = uuid;
            }
            assert_eq!(heartbeat(&t.app, body).await, json!({}));
        }
        // An id hbbs does not know: `{}` too (a first heartbeat racing the registration gets served
        // 15 s later), no device row.
        assert_eq!(heartbeat(&t.app, json!({"id": "333", "uuid": b64(b"x"), "ver": 1004020, "modified_at": 0})).await, json!({}));
        let n: i64 = sqlx::query_scalar("select count(*) from device").fetch_one(db).await.unwrap();
        assert_eq!(n, 0);

        // Matching uuid: served, the device row is created.
        let r = heartbeat(&t.app, json!({"id": "111", "uuid": b64(UUID), "ver": 1004020, "modified_at": 0})).await;
        assert!(r["modified_at"].is_i64());
        let row: (i64, String, String) = sqlx::query_as("select ver, last_ip, uuid from device where id = '111'")
            .fetch_one(db)
            .await
            .unwrap();
        // `send` comes from 127.0.0.1 without proxy headers.
        assert_eq!(row, (1004020, "127.0.0.1".into(), b64(UUID)));
    }

    #[tokio::test]
    async fn uuid_matches_limits() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let matches = |id: String, uuid: Option<String>| async move {
            super::uuid_matches(db, &id, uuid.as_deref()).await.unwrap() == super::UuidCheck::Match
        };
        add_peer(db, "111", UUID).await;
        assert!(matches("111".into(), Some(b64(UUID))).await);
        assert!(!matches("111".into(), None).await);
        assert!(!matches("222".into(), Some(b64(UUID))).await);

        // Ids up to MAX_PEER_ID_LEN bytes are looked up; longer ones fail even when hbbs has them.
        let (fits, long) = ("i".repeat(MAX_PEER_ID_LEN), "l".repeat(MAX_PEER_ID_LEN + 1));
        add_peer(db, &fits, UUID).await;
        add_peer(db, &long, UUID).await;
        assert!(matches(fits, Some(b64(UUID))).await);
        assert!(!matches(long, Some(b64(UUID))).await);

        // 96 raw bytes are 128 base64 bytes (MAX_UUID_LEN); 99 are 132.
        let (fits, long) = (vec![7u8; 96], vec![7u8; 99]);
        assert_eq!((b64(&fits).len(), b64(&long).len()), (MAX_UUID_LEN, MAX_UUID_LEN + 4));
        add_peer(db, "333", &fits).await;
        add_peer(db, "444", &long).await;
        assert!(matches("333".into(), Some(b64(&fits))).await);
        assert!(!matches("444".into(), Some(b64(&long))).await);
    }

    #[tokio::test]
    async fn sysinfo_size_limit() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111", UUID).await;
        // Padded to exactly `len` bytes with an extra key, which the raw text keeps.
        let padded = |len: usize| {
            let mut v: Value = serde_json::from_str(&sysinfo_body("111", Some(&b64(UUID)), "h")).unwrap();
            v["pad"] = json!("");
            let pad = len - v.to_string().len();
            v["pad"] = json!("p".repeat(pad));
            let body = v.to_string();
            assert_eq!(body.len(), len);
            body
        };
        let (status, _, body) = send(&t.app, "POST", "/api/sysinfo", None, &padded(MAX_SYSINFO_LEN + 1)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.is_empty());
        let n: i64 = sqlx::query_scalar("select count(*) from device").fetch_one(db).await.unwrap();
        assert_eq!(n, 0);
        let raw = padded(MAX_SYSINFO_LEN);
        let (status, _, body) = send(&t.app, "POST", "/api/sysinfo", None, &raw).await;
        assert_eq!((status, &body[..]), (StatusCode::OK, &b"SYSINFO_UPDATED"[..]));
        let stored: String = sqlx::query_scalar("select sysinfo from device where id = '111'")
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(stored, raw);
    }

    #[tokio::test]
    async fn sysinfo_split_fields_are_clipped() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111", UUID).await;
        let mut v: Value = serde_json::from_str(&sysinfo_body("111", Some(&b64(UUID)), "")).unwrap();
        // 2-byte chars cut at the char boundary below the limit; the raw text keeps everything.
        v["hostname"] = json!("é".repeat(MAX_SYSINFO_FIELD_LEN));
        for key in ["username", "os", "version"] {
            v[key] = json!("x".repeat(MAX_SYSINFO_FIELD_LEN + 1));
        }
        let raw = v.to_string();
        let (status, _, _) = send(&t.app, "POST", "/api/sysinfo", None, &raw).await;
        assert_eq!(status, StatusCode::OK);
        let row: (String, String, String, String, String) =
            sqlx::query_as("select hostname, username, os, version, sysinfo from device where id = '111'")
                .fetch_one(db)
                .await
                .unwrap();
        let x = "x".repeat(MAX_SYSINFO_FIELD_LEN);
        assert_eq!(row, ("é".repeat(MAX_SYSINFO_FIELD_LEN / 2), x.clone(), x.clone(), x, raw));
    }

    async fn count(db: &SqlitePool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(db).await.unwrap()
    }

    async fn has_row(db: &SqlitePool, id: &str) -> bool {
        count(db, &format!("select count(*) from device where id = '{id}'")).await == 1
    }

    /// Review C-10/C-18/C-26/C-19: a report that creates a row first evicts the oldest evictable one
    /// when the table is at `MAX_DEVICES`; with none evictable it creates nothing.
    #[tokio::test]
    async fn new_rows_keep_the_table_capped() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let uuid = b64(UUID);
        let insert = |id: &'static str, last_seen: i64| async move {
            sqlx::query("insert into device(id, first_seen_at, last_seen_at) values(?, 0, ?)")
                .bind(id)
                .bind(last_seen)
                .execute(db)
                .await
                .unwrap();
        };
        // MAX_DEVICES - 5 recent rows, seen at 1001, 1002, …
        sqlx::query(
            "with recursive n(i) as (select 1 union all select i + 1 from n where i < ?)
             insert into device(id, first_seen_at, last_seen_at) select 'bulk' || i, 0, 1000 + i from n",
        )
        .bind(MAX_DEVICES - 5)
        .execute(db)
        .await
        .unwrap();
        // The oldest rows: owned with the owner's token on it, a pinned relay, a device option (all
        // kept); owned with no token of the owner on it, and unowned (both evictable).
        let (amy, _) = testutil::create_user(db, "ev-amy", "pw", false).await;
        for (id, seen) in [("owned", 1), ("pinned", 2), ("optioned", 3), ("orphaned", 4), ("old", 5)] {
            insert(id, seen).await;
        }
        sqlx::query("update device set user_id = ? where id in ('owned', 'orphaned')").bind(amy).execute(db).await.unwrap();
        sqlx::query("insert into token(token_hash, user_id, device_id, created_at, last_used_at) values('h', ?, 'owned', 0, 0)")
            .bind(amy)
            .execute(db)
            .await
            .unwrap();
        sqlx::query("insert into device_policy(device_id, relay_pin) values('pinned', 'r:21117')")
            .execute(db)
            .await
            .unwrap();
        set_option(db, "optioned", "allow-auto-disconnect", "Y").await;
        assert_eq!(count(db, "select count(*) from device").await, MAX_DEVICES);

        // Each new device takes the place of the oldest evictable row.
        for (new, gone) in [("n1", "orphaned"), ("n2", "old"), ("n3", "bulk1")] {
            add_peer(db, new, UUID).await;
            let r = heartbeat(&t.app, json!({"id": new, "uuid": uuid, "ver": 1005010, "modified_at": 0})).await;
            assert_eq!(r["sysinfo"], json!(true), "{new}");
            assert!(has_row(db, new).await && !has_row(db, gone).await, "{new} replaces {gone}");
            assert_eq!(count(db, "select count(*) from device").await, MAX_DEVICES);
        }
        for id in ["owned", "pinned", "optioned", "bulk2"] {
            assert!(has_row(db, id).await, "{id}");
        }
        // A device with a row evicts nothing; sysinfo creates rows the same way.
        heartbeat(&t.app, json!({"id": "n1", "uuid": uuid, "ver": 1005011, "modified_at": 0})).await;
        assert!(has_row(db, "bulk2").await);
        add_peer(db, "n4", UUID).await;
        let (status, _, _) = send(&t.app, "POST", "/api/sysinfo", None, &sysinfo_body("n4", Some(&uuid), "h")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(has_row(db, "n4").await && !has_row(db, "bulk2").await);
        // Past the limit (rows added without the check, e.g. by an import) by less than a batch: back
        // to it in one go.
        insert("x1", 99_999).await;
        insert("x2", 99_999).await;
        add_peer(db, "n5", UUID).await;
        heartbeat(&t.app, json!({"id": "n5", "uuid": uuid, "ver": 1005010, "modified_at": 0})).await;
        assert_eq!(count(db, "select count(*) from device").await, MAX_DEVICES);
        assert!(has_row(db, "n5").await && !has_row(db, "bulk3").await && !has_row(db, "bulk5").await);

        // Nothing evictable: served without a row (strategy, no `sysinfo` key), sysinfo refused.
        sqlx::query("insert or ignore into device_policy(device_id) select id from device").execute(db).await.unwrap();
        add_peer(db, "n6", UUID).await;
        let r = heartbeat(&t.app, json!({"id": "n6", "uuid": uuid, "ver": 1005010, "modified_at": 0})).await;
        assert!(r["modified_at"].is_i64() && r.get("sysinfo").is_none(), "{r}");
        let (status, _, body) = send(&t.app, "POST", "/api/sysinfo", None, &sysinfo_body("n6", Some(&uuid), "h")).await;
        assert_eq!((status, body.is_empty()), (StatusCode::FORBIDDEN, true));
        assert!(!has_row(db, "n6").await);
        assert_eq!(count(db, "select count(*) from device").await, MAX_DEVICES);
        // Devices with a row are still served and updated.
        let r = heartbeat(&t.app, json!({"id": "n1", "uuid": uuid, "ver": 1005012, "modified_at": 0})).await;
        assert!(r["modified_at"].is_i64());
        assert_eq!(count(db, "select ver from device where id = 'n1'").await, 1005012);
    }

    /// Reviews C-16, D-6: picking the rows to evict reads indexes in `last_seen_at` order (no scan of
    /// the table, whose `last_seen_at` sits after the 8 KB sysinfo, and no sort of the owned rows).
    #[tokio::test]
    async fn eviction_uses_the_owner_and_last_seen_index() {
        let t = testutil::app().await;
        let sql = format!("delete from device where id in (select id from ({}))", EVICTABLE.replace("?1", "1"));
        let plan = query_plan(&t.state.db, &sql).await;
        eprintln!("device eviction: {plan:#?}");
        for step in [
            "SEARCH d USING INDEX device_user_seen (user_id=?)",
            "SCAN d USING COVERING INDEX device_owned_seen",
            "SEARCH t USING COVERING INDEX token_user_device (user_id=? AND device_id=?)",
        ] {
            assert!(plan.iter().any(|l| l == step), "{step}: {plan:?}");
        }
        assert!(!plan.iter().any(|l| l.starts_with("SCAN d") && !l.contains("device_owned_seen")), "{plan:?}");
        // The only sorts are of each arm's at most `?1` rows, for the merge of the two.
        for (i, l) in plan.iter().enumerate() {
            if l.contains("TEMP B-TREE") {
                assert!(i > 0 && plan[i - 1].starts_with("SCAN (subquery"), "{plan:?}");
            }
        }
    }

    /// Review D-7: past the limit a new row deletes at most `EVICT_BATCH` rows, and one deleted is
    /// enough for it; the table comes back to `MAX_DEVICES` over the next new rows. A login keeps to
    /// the limit too: with nothing evictable it succeeds without a row.
    #[tokio::test]
    async fn eviction_past_the_limit_is_batched() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let uuid = b64(UUID);
        let rows = || count(db, "select count(*) from device");
        let excess = 5_000;
        sqlx::query(
            "with recursive n(i) as (select 1 union all select i + 1 from n where i < ?)
             insert into device(id, first_seen_at, last_seen_at) select 'bulk' || i, 0, i from n",
        )
        .bind(MAX_DEVICES + excess)
        .execute(db)
        .await
        .unwrap();
        let mut left = MAX_DEVICES + excess;
        let mut new = 0;
        while left > MAX_DEVICES {
            new += 1;
            let id = format!("n{new}");
            add_peer(db, &id, UUID).await;
            let r = heartbeat(&t.app, json!({"id": id, "uuid": uuid, "ver": 1005010, "modified_at": 0})).await;
            assert_eq!(r["sysinfo"], json!(true), "{id}");
            let want = (left - MAX_DEVICES + 1).min(EVICT_BATCH);
            assert_eq!(rows().await, left - want + 1, "{id}");
            left -= want - 1;
        }
        // Every new row deleted up to EVICT_BATCH - 1 more than it added.
        assert_eq!(new, (excess + EVICT_BATCH - 2) / (EVICT_BATCH - 1));

        // Past the limit with fewer evictable rows than the excess: those go and the row is made.
        let oldest: Vec<String> = sqlx::query_scalar("select id from device order by last_seen_at limit 3")
            .fetch_all(db)
            .await
            .unwrap();
        sqlx::query("insert into device(id, first_seen_at, last_seen_at) values('x1', 0, 99999), ('x2', 0, 99999)")
            .execute(db)
            .await
            .unwrap();
        sqlx::query("insert into device_policy(device_id) select id from device where id not in (?, ?)")
            .bind(&oldest[0])
            .bind(&oldest[1])
            .execute(db)
            .await
            .unwrap();
        add_peer(db, "few", UUID).await;
        heartbeat(&t.app, json!({"id": "few", "uuid": uuid, "ver": 1005010, "modified_at": 0})).await;
        assert!(has_row(db, "few").await && !has_row(db, &oldest[0]).await && !has_row(db, &oldest[1]).await);
        assert_eq!(rows().await, MAX_DEVICES + 1);

        // Nothing evictable: a login on a new device succeeds without a row; one on a device with a
        // row binds it.
        sqlx::query("insert into device_policy(device_id) values('few')").execute(db).await.unwrap();
        let (amy, _) = testutil::create_user(db, "ev-amy", "pw", false).await;
        add_peer(db, "full", UUID).await;
        login(&t.app, "ev-amy", "full", &uuid).await;
        assert!(!has_row(db, "full").await);
        login(&t.app, "ev-amy", "n1", &uuid).await;
        assert_eq!(owner(db, "n1").await, Some(amy));
        assert_eq!(rows().await, MAX_DEVICES + 1);
        // With room again (a policy gone), the login makes the row in the evicted one's place.
        sqlx::query("delete from device_policy where device_id = ?").bind(&oldest[2]).execute(db).await.unwrap();
        login(&t.app, "ev-amy", "full", &uuid).await;
        assert_eq!(owner(db, "full").await, Some(amy));
        assert!(!has_row(db, &oldest[2]).await);
        assert_eq!(rows().await, MAX_DEVICES + 1);
    }

    /// A heartbeat that changes nothing writes `last_seen_at` once it is `LAST_SEEN_STEP` old.
    #[tokio::test]
    async fn heartbeat_writes_last_seen_once_a_step() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "111", UUID).await;
        let hb = |ver: i64| json!({"id": "111", "uuid": b64(UUID), "ver": ver, "modified_at": 0});
        heartbeat(&t.app, hb(1005010)).await;
        let now = crate::common::now() as i64;
        let set_seen = |seen: i64| async move {
            sqlx::query("update device set last_seen_at = ? where id = '111'").bind(seen).execute(db).await.unwrap();
        };
        let seen = || count(db, "select last_seen_at from device where id = '111'");

        set_seen(now - LAST_SEEN_STEP + 5).await;
        heartbeat(&t.app, hb(1005010)).await;
        assert_eq!(seen().await, now - LAST_SEEN_STEP + 5, "not written yet");
        set_seen(now - LAST_SEEN_STEP).await;
        heartbeat(&t.app, hb(1005010)).await;
        assert!(seen().await >= now, "written once due");
        // Another field changed: written at once.
        set_seen(now - 1).await;
        heartbeat(&t.app, hb(1005011)).await;
        assert!(seen().await >= now);
        assert_eq!(count(db, "select ver from device where id = '111'").await, 1005011);
    }

    /// Driven on a private set of budgets with chosen times.
    #[test]
    fn report_budgets_per_source() {
        let mut b = ReportBudgets::default();
        let t0 = 1_000_000;
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for _ in 0..REPORTS_PER_MIN {
            assert!(b.allow(ip("198.51.100.7"), t0));
        }
        assert!(!b.allow(ip("198.51.100.7"), t0 + 59_999));
        // Another address has its own budget; an IPv6 /64 is one source.
        assert!(b.allow(ip("198.51.100.8"), t0));
        for _ in 0..REPORTS_PER_MIN {
            assert!(b.allow(ip("2001:db8:1:2::1"), t0));
        }
        assert!(!b.allow(ip("2001:db8:1:2:ffff::9"), t0));
        assert!(b.allow(ip("2001:db8:1:3::1"), t0));
        // The next minute is a new window.
        assert!(b.allow(ip("198.51.100.7"), t0 + 60_000));

        // Full: a new source goes without a budget until a window has ended and the map is pruned.
        let mut b = ReportBudgets::default();
        for i in 0..MAX_REPORT_SOURCES as u32 {
            b.sources.insert(IpAddr::from(i.to_be_bytes()), (t0, 0));
        }
        b.pruned_at = t0;
        for _ in 0..=REPORTS_PER_MIN {
            assert!(b.allow(ip("203.0.113.1"), t0 + 1));
        }
        assert!(!b.sources.contains_key(&ip("203.0.113.1")));
        assert!(b.allow(ip("203.0.113.1"), t0 + 60_000));
        assert_eq!(b.sources.len(), 1);
    }

    async fn login(app: &axum::Router, name: &str, id: &str, uuid: &str) -> String {
        let body = json!({"username": name, "password": "pw", "id": id, "uuid": uuid, "type": "account"});
        let (status, _, body) = send(app, "POST", "/api/login", None, &body.to_string()).await;
        assert_eq!(status, StatusCode::OK);
        serde_json::from_slice::<Value>(&body).unwrap()["access_token"].as_str().unwrap().to_owned()
    }

    async fn owner(db: &SqlitePool, id: &str) -> Option<i64> {
        sqlx::query_scalar("select user_id from device where id = ?")
            .bind(id)
            .fetch_optional(db)
            .await
            .unwrap()
            .flatten()
    }

    #[tokio::test]
    async fn late_binding_from_login_tokens() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let uuid = b64(UUID);
        let hb = |id: &str| json!({"id": id, "uuid": uuid, "ver": 1005010, "modified_at": 0});
        let (amy, _) = testutil::create_user(db, "lb-amy", "pw", false).await;
        testutil::create_user(db, "lb-bob", "pw", false).await;
        let (cat, _) = testutil::create_user(db, "lb-cat", "pw", false).await;

        // Logged in before registering with hbbs: not bound then, bound by the first heartbeat after.
        login(&t.app, "lb-amy", "111", &uuid).await;
        assert_eq!(owner(db, "111").await, None);
        add_peer(db, "111", UUID).await;
        heartbeat(&t.app, hb("111")).await;
        assert_eq!(owner(db, "111").await, Some(amy));
        // A newer login token of someone else does not take over an owned device.
        login(&t.app, "lb-bob", "111", &b64(b"stale")).await;
        sqlx::query("update token set device_uuid = ? where device_id = '111'").bind(&uuid).execute(db).await.unwrap();
        heartbeat(&t.app, hb("111")).await;
        assert_eq!(owner(db, "111").await, Some(amy));

        // Token with another uuid, or of a disabled account: no binding.
        login(&t.app, "lb-bob", "222", &b64(b"other")).await;
        login(&t.app, "lb-cat", "222", &uuid).await;
        sqlx::query("update user set status = 0 where id = ?").bind(cat).execute(db).await.unwrap();
        add_peer(db, "222", UUID).await;
        heartbeat(&t.app, hb("222")).await;
        assert_eq!(owner(db, "222").await, None);

        // Several candidates: the token used last wins; sysinfo binds too.
        login(&t.app, "lb-amy", "333", &uuid).await;
        login(&t.app, "lb-bob", "333", &uuid).await;
        sqlx::query("update token set last_used_at = last_used_at + 100 where user_id = ? and device_id = '333'")
            .bind(amy)
            .execute(db)
            .await
            .unwrap();
        add_peer(db, "333", UUID).await;
        let (status, _, _) = send(&t.app, "POST", "/api/sysinfo", None, &sysinfo_body("333", Some(&uuid), "h")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(owner(db, "333").await, Some(amy));

        // The token is read by the statement that writes the owner (review C-24): one gone before
        // it binds nothing.
        login(&t.app, "lb-amy", "444", &uuid).await;
        add_peer(db, "444", UUID).await;
        sqlx::query("delete from token where device_id = '444'").execute(db).await.unwrap();
        heartbeat(&t.app, hb("444")).await;
        assert_eq!(owner(db, "444").await, None);
    }

    #[tokio::test]
    async fn logout_is_not_undone_by_late_binding() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let uuid = b64(UUID);
        let hb = json!({"id": "111", "uuid": uuid, "ver": 1005010, "modified_at": 0});
        let (amy, _) = testutil::create_user(db, "lo-amy", "pw", false).await;
        add_peer(db, "111", UUID).await;
        // Two logins on this device (the first token is dead on the client) and one elsewhere.
        login(&t.app, "lo-amy", "111", &uuid).await;
        let latest = login(&t.app, "lo-amy", "111", &uuid).await;
        let elsewhere = login(&t.app, "lo-amy", "999", &uuid).await;
        assert_eq!(owner(db, "111").await, Some(amy));

        let (status, _, _) = send(&t.app, "POST", "/api/logout", Some(&latest), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(owner(db, "111").await, None);
        heartbeat(&t.app, hb).await;
        assert_eq!(owner(db, "111").await, None);
        let left: Vec<String> = sqlx::query_scalar("select device_id from token where user_id = ?")
            .bind(amy)
            .fetch_all(db)
            .await
            .unwrap();
        // `create_user`'s token (no device) and the one from the other device are kept.
        assert_eq!(left.iter().filter(|d| d.as_str() == "111").count(), 0);
        assert_eq!(left.len(), 2);
        let (status, _, _) = send(&t.app, "POST", "/api/currentUser", Some(&elsewhere), "").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Reviews C-5, C-20: logout spares the user's tokens from the same device that were issued after
    /// the one used (a new login while the logout was on its way) or used since it was issued
    /// (another system account of the same machine); the others go.
    #[tokio::test]
    async fn logout_spares_tokens_issued_or_used_after_it() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let uuid = b64(UUID);
        let (amy, _) = testutil::create_user(db, "ls-amy", "pw", false).await;
        add_peer(db, "111", UUID).await;
        let latest = login(&t.app, "ls-amy", "111", &uuid).await;
        let issued: i64 = count(db, "select max(created_at) from token where device_id = '111'").await;
        for (hash, created, used) in [
            ("stale", issued - 100, issued - 100),
            ("same-second", issued, issued),
            ("sibling", issued - 100, issued + 50),
            ("newer", issued + 100, issued + 100),
        ] {
            sqlx::query(
                "insert into token(token_hash, user_id, device_id, device_uuid, created_at, last_used_at)
                 values(?, ?, '111', ?, ?, ?)",
            )
            .bind(hash)
            .bind(amy)
            .bind(&uuid)
            .bind(created)
            .bind(used)
            .execute(db)
            .await
            .unwrap();
        }
        let (status, _, _) = send(&t.app, "POST", "/api/logout", Some(&latest), "").await;
        assert_eq!(status, StatusCode::OK);
        let left: Vec<String> = sqlx::query_scalar("select token_hash from token where device_id = '111' order by token_hash")
            .fetch_all(db)
            .await
            .unwrap();
        assert_eq!(left, ["newer", "sibling"]);
        // Unbound by the logout; the spared tokens bind the device back on its next written heartbeat.
        assert_eq!(owner(db, "111").await, None);
        heartbeat(&t.app, json!({"id": "111", "uuid": uuid, "ver": 1005010, "modified_at": 0})).await;
        assert_eq!(owner(db, "111").await, Some(amy));
    }

    // ---- Phase 4 A1: owners of pinned devices ----

    /// A login binds a pinned device only while it has no owner; the owner's logout frees it.
    #[tokio::test]
    async fn login_does_not_take_over_a_pinned_device() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let uuid = b64(UUID);
        let (amy, _) = testutil::create_user(db, "pl-amy", "pw", false).await;
        let (bob, _) = testutil::create_user(db, "pl-bob", "pw", false).await;
        add_peer(db, "111", UUID).await;
        pin(db, "111").await;
        let amy_t = login(&t.app, "pl-amy", "111", &uuid).await;
        assert_eq!(owner(db, "111").await, Some(amy));
        login(&t.app, "pl-bob", "111", &uuid).await;
        assert_eq!(owner(db, "111").await, Some(amy));
        let (status, _, _) = send(&t.app, "POST", "/api/logout", Some(&amy_t), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(owner(db, "111").await, None);
        login(&t.app, "pl-bob", "111", &uuid).await;
        assert_eq!(owner(db, "111").await, Some(bob));
    }

    /// The late binding of a pinned device takes only a token issued before (or in the same second
    /// as) the pin, on each statement that writes the row.
    #[tokio::test]
    async fn late_binding_of_pinned_devices() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let uuid = b64(UUID);
        let (bob, _) = testutil::create_user(db, "lp-bob", "pw", false).await;
        const PINNED_AT: i64 = 1_700_000_000;
        let token = |id: &'static str, created: i64| {
            let uuid = uuid.clone();
            async move {
                sqlx::query("delete from token where device_id = ?").bind(id).execute(db).await.unwrap();
                sqlx::query(
                    "insert into token(token_hash, user_id, device_id, device_uuid, created_at, last_used_at)
                     values(?, ?, ?, ?, ?, ?)",
                )
                .bind(format!("{id}-{created}"))
                .bind(bob)
                .bind(id)
                .bind(uuid)
                .bind(created)
                .bind(created)
                .execute(db)
                .await
                .unwrap();
            }
        };
        let reset = |id: &'static str| async move {
            sqlx::query("delete from device where id = ?").bind(id).execute(db).await.unwrap();
        };
        for id in ["upd", "ins", "sys"] {
            add_peer(db, id, UUID).await;
            sqlx::query("update peer set pk_pinned_at = ? where id = ?").bind(PINNED_AT).bind(id).execute(db).await.unwrap();
        }
        // `touch`'s update: the row is there (written on a changed `ver`).
        for (created, want) in [(PINNED_AT + 1, None), (PINNED_AT, Some(bob))] {
            token("upd", created).await;
            reset("upd").await;
            sqlx::query("insert into device(id, first_seen_at, last_seen_at) values('upd', 0, 0)").execute(db).await.unwrap();
            super::touch(db, "upd", &uuid, created, "1.2.3.4", "leapgate").await.unwrap();
            assert_eq!(owner(db, "upd").await, want, "update, token at {created}");
        }
        // `touch`'s insert.
        for (created, want) in [(PINNED_AT + 1, None), (PINNED_AT, Some(bob))] {
            token("ins", created).await;
            reset("ins").await;
            super::touch(db, "ins", &uuid, 1, "1.2.3.4", "leapgate").await.unwrap();
            assert_eq!(owner(db, "ins").await, want, "insert, token at {created}");
        }
        // `store_sysinfo`.
        for (created, want) in [(PINNED_AT + 1, None), (PINNED_AT, Some(bob))] {
            token("sys", created).await;
            reset("sys").await;
            assert!(super::store_sysinfo(db, "sys", &uuid, "{}", Default::default(), "leapgate").await.unwrap());
            assert_eq!(owner(db, "sys").await, want, "sysinfo, token at {created}");
        }
        // Unpinned: any token, as before.
        sqlx::query("update peer set pk_pinned_at = null where id = 'ins'").execute(db).await.unwrap();
        token("ins", PINNED_AT + 1).await;
        reset("ins").await;
        super::touch(db, "ins", &uuid, 1, "1.2.3.4", "leapgate").await.unwrap();
        assert_eq!(owner(db, "ins").await, Some(bob));
    }

    /// Logged in before registering: the first signed heartbeat pins the key and binds the owner.
    #[tokio::test]
    async fn first_signed_heartbeat_pins_and_binds() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let uuid = b64(UUID);
        let (amy, _) = testutil::create_user(db, "fs-amy", "pw", false).await;
        login(&t.app, "fs-amy", "fresh1", &uuid).await;
        assert_eq!(owner(db, "fresh1").await, None);
        let dev = testutil::leapgate_device(&t.state, "fresh1", UUID).await;
        let r = dev.post(&t.app, "heartbeat", json!({"uuid": uuid, "ver": 1}).to_string().as_bytes()).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(count(db, "select count(*) from peer where id = 'fresh1' and pk_pinned_at is not null").await, 1);
        assert_eq!(owner(db, "fresh1").await, Some(amy));
    }

    #[tokio::test]
    async fn heartbeat_strategy_push() {
        let t = testutil::app().await;
        let db = &t.state.db;
        add_peer(db, "dev1", UUID).await;
        let hb = |modified_at: i64| json!({"id": "dev1", "uuid": b64(UUID), "ver": 1005010, "modified_at": modified_at, "conns": [1001]});

        // First contact: the global relay-server tombstone, `modified_at` as a JSON number, and sysinfo asked for.
        let r = heartbeat(&t.app, hb(0)).await;
        let rev = r["modified_at"].as_i64().unwrap();
        assert!(rev > 0 && r["modified_at"].is_number());
        assert_eq!(r["strategy"], json!({"config_options": {"relay-server": ""}}));
        assert_eq!(r["sysinfo"], json!(true));
        assert_eq!(r.as_object().unwrap().len(), 3);

        // Echoing the rev back: nothing to push (only sysinfo, still missing).
        assert_eq!(heartbeat(&t.app, hb(rev)).await, json!({"sysinfo": true}));
        // Any other value (e.g. a timestamp from another server) gets the strategy again.
        assert_eq!(heartbeat(&t.app, hb(rev + 1)).await["modified_at"], json!(rev));

        // After sysinfo the key disappears completely.
        let (status, _, _) = send(&t.app, "POST", "/api/sysinfo", None, &sysinfo_body("dev1", Some(&b64(UUID)), "h")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(heartbeat(&t.app, hb(rev)).await, json!({}));

        // Changing a global option pushes again, with every effective option.
        set_option(db, "*", "allow-auto-disconnect", "Y").await;
        let r = heartbeat(&t.app, hb(rev)).await;
        let rev2 = r["modified_at"].as_i64().unwrap();
        assert_ne!(rev2, rev);
        assert_eq!(
            r,
            json!({"modified_at": rev2, "strategy": {"config_options": {"allow-auto-disconnect": "Y", "relay-server": ""}}})
        );
        assert_eq!(heartbeat(&t.app, hb(rev2)).await, json!({}));

        // A device override (here a tombstone) wins over the global value.
        set_option(db, "dev1", "allow-auto-disconnect", "").await;
        let r = heartbeat(&t.app, hb(rev2)).await;
        let rev3 = r["modified_at"].as_i64().unwrap();
        assert_ne!(rev3, rev2);
        assert_eq!(r["strategy"]["config_options"], json!({"allow-auto-disconnect": "", "relay-server": ""}));
        assert_eq!(heartbeat(&t.app, hb(rev3)).await, json!({}));

        // Epoch bumps (device, then global) force a re-push of the same options.
        bump_epoch(db, "dev1").await;
        let r = heartbeat(&t.app, hb(rev3)).await;
        let rev4 = r["modified_at"].as_i64().unwrap();
        assert_ne!(rev4, rev3);
        assert_eq!(r["strategy"]["config_options"], json!({"allow-auto-disconnect": "", "relay-server": ""}));
        bump_epoch(db, "*").await;
        let rev5 = heartbeat(&t.app, hb(rev4)).await["modified_at"].as_i64().unwrap();
        assert_ne!(rev5, rev4);
        assert_eq!(heartbeat(&t.app, hb(rev5)).await, json!({}));

        // The pushed rev is the one strategy::effective computes.
        let (rev, _) = crate::strategy::effective(db, "dev1").await.unwrap();
        assert_eq!(rev, rev5);
    }

    // ---- Phase 3 contract 01: pinned devices on the compatibility path, the Leapgate heartbeat ----

    async fn pin(db: &SqlitePool, id: &str) {
        sqlx::query("update peer set pk_pinned_at = 1 where id = ?").bind(id).execute(db).await.unwrap();
    }

    /// §3.5: once the key is pinned, the unsigned heartbeat and sysinfo of the id are refused like a
    /// mismatch; the login still binds; other ids are served as before.
    #[tokio::test]
    async fn pinned_devices_refuse_unsigned_reports() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let uuid = b64(UUID);
        add_peer(db, "pinned", UUID).await;
        add_peer(db, "free11", UUID).await;
        pin(db, "pinned").await;
        assert_eq!(
            super::uuid_matches(db, "pinned", Some(&uuid)).await.unwrap(),
            super::UuidCheck::MatchPinned
        );
        assert_eq!(heartbeat(&t.app, json!({"id": "pinned", "uuid": uuid, "ver": 1, "modified_at": 0})).await, json!({}));
        let (status, _, body) = send(&t.app, "POST", "/api/sysinfo", None, &sysinfo_body("pinned", Some(&uuid), "h")).await;
        assert_eq!((status, body.is_empty()), (StatusCode::FORBIDDEN, true));
        assert!(!has_row(db, "pinned").await);
        let (amy, _) = testutil::create_user(db, "pin-amy", "pw", false).await;
        login(&t.app, "pin-amy", "pinned", &uuid).await;
        assert_eq!(owner(db, "pinned").await, Some(amy));

        let r = heartbeat(&t.app, json!({"id": "free11", "uuid": uuid, "ver": 1, "modified_at": 0})).await;
        assert!(r["modified_at"].is_i64());
        assert!(has_row(db, "free11").await);
    }

    fn sysinfo_obj(hostname: &str) -> Value {
        json!({"cpu": "Intel, 3.6GHz, 8/4 cores", "memory": "16GB", "os": "windows / Windows 11 Pro - 10.0.26100",
               "hostname": hostname, "username": "alice", "version": "1.5.1"})
    }

    fn sha256_b64(raw: &str) -> String {
        base64::encode(<sha2::Sha256 as sha2::Digest>::digest(raw.as_bytes()))
    }

    /// The body the client sends: one compact serialization, so the sysinfo bytes inside it are the
    /// ones its hash is over. `hash` overrides the hash sent; returns the body and the own hash.
    /// Carries a key nobody reads (`conns`) and bad `probes`; `routing_rev` is the server's (`rr`),
    /// so no `routing` comes back.
    fn leapgate_body(rev: i64, rr: i64, sysinfo: Option<&Value>, hash: Option<&str>) -> (String, String) {
        let mut v = json!({"uuid": b64(UUID), "ver": 1005010, "leapgate": "0.3.0", "strategy_rev": rev,
                           "conns": [3], "routing_rev": rr, "probes": "not an object"});
        let raw = sysinfo.map(|s| serde_json::to_string(s).unwrap()).unwrap_or_default();
        let own_hash = sha256_b64(&raw);
        if let Some(s) = sysinfo {
            v["sysinfo"] = s.clone();
        }
        v["sysinfo_hash"] = json!(hash.unwrap_or(&own_hash));
        let body = serde_json::to_string(&v).unwrap();
        assert!(body.contains(&raw));
        (body, own_hash)
    }

    async fn device_row(db: &SqlitePool, id: &str) -> (String, String, String, i64) {
        sqlx::query_as("select sysinfo, hostname, client_type, ver from device where id = ?")
            .bind(id)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn leapgate_heartbeat_sysinfo_and_strategy() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let dev = testutil::leapgate_device(&t.state, "leapgate1", UUID).await;
        let hb = |body: String| {
            let (dev, app) = (&dev, &t.app);
            async move { dev.post(app, "heartbeat", body.as_bytes()).await }
        };

        let rr = t.state.router.routing().0;
        // No row yet: sysinfo wanted, every option pushed; signed, `features` ICE, `time` now.
        let r = hb(leapgate_body(0, rr, None, Some("")).0).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.headers["content-type"], "application/json; charset=utf-8");
        assert!(testutil::verify_server_sig(&t.state, &r.sig, &r.headers, &r.body));
        let v = r.json();
        let rev = v["strategy"]["rev"].as_i64().unwrap();
        assert_eq!(rev, crate::strategy::effective(db, "leapgate1").await.unwrap().0);
        assert_eq!(v["strategy"]["options"], json!({"relay-server": ""}));
        assert_eq!((&v["api"], &v["features"], &v["need_sysinfo"]), (&json!(1), &json!(["ice", "exit"]), &json!(true)));
        assert!((v["time"].as_i64().unwrap() - crate::common::now() as i64).abs() <= 2);
        assert_eq!(device_row(db, "leapgate1").await, (String::new(), String::new(), "leapgate".into(), 1005010));

        // The rev echoed back: no strategy; the row has no sysinfo yet, so it is still wanted.
        let v = hb(leapgate_body(rev, rr, None, Some("")).0).await.json();
        assert_eq!(v.get("strategy"), None);
        assert_eq!(v["need_sysinfo"], json!(true));

        // With the sysinfo: stored byte for byte (the hash the client computed is the stored text's),
        // not wanted any more; the answer is just api, features, time.
        let s = sysinfo_obj("h1");
        let (body, hash) = leapgate_body(rev, rr, Some(&s), None);
        let v = hb(body).await.json();
        assert_eq!(v.as_object().unwrap().keys().collect::<Vec<_>>(), ["api", "features", "time"]);
        let (stored, host, client, _) = device_row(db, "leapgate1").await;
        assert_eq!(
            (stored.as_str(), host.as_str(), client.as_str()),
            (serde_json::to_string(&s).unwrap().as_str(), "h1", "leapgate")
        );
        assert_eq!(sha256_b64(&stored), hash);
        // Without the sysinfo: the same hash wants nothing, another one wants it again.
        assert_eq!(hb(leapgate_body(rev, rr, None, Some(&hash)).0).await.json().get("need_sysinfo"), None);
        assert_eq!(hb(leapgate_body(rev, rr, None, Some("other")).0).await.json()["need_sysinfo"], json!(true));

        // An option changed: pushed again, with every effective option. (Not the body sent just
        // above, which within the same second would be a replay.)
        set_option(db, "leapgate1", "allow-auto-disconnect", "Y").await;
        let v = hb(leapgate_body(rev, rr, None, None).0).await.json();
        let rev2 = v["strategy"]["rev"].as_i64().unwrap();
        assert_ne!(rev2, rev);
        assert_eq!(v["strategy"]["options"], json!({"allow-auto-disconnect": "Y", "relay-server": ""}));

        // The path the device reported on last: a compatibility heartbeat (key unpinned for it)
        // makes it `rustdesk` again.
        sqlx::query("update peer set pk_pinned_at = null where id = 'leapgate1'").execute(db).await.unwrap();
        heartbeat(&t.app, json!({"id": "leapgate1", "uuid": b64(UUID), "ver": 1005010, "modified_at": 0})).await;
        assert_eq!(device_row(db, "leapgate1").await.2, "rustdesk");
    }

    #[tokio::test]
    async fn leapgate_heartbeat_bad_bodies() {
        let t = testutil::app().await;
        let dev = testutil::leapgate_device(&t.state, "leapgate2", UUID).await;
        let bad = [
            ("nope".to_owned(), StatusCode::BAD_REQUEST, "bad_request"),
            (json!({"uuid": "u".repeat(MAX_UUID_LEN + 1)}).to_string(), StatusCode::BAD_REQUEST, "bad_request"),
            (json!({"ver": "x"}).to_string(), StatusCode::BAD_REQUEST, "bad_request"),
            (json!({"sysinfo": {"hostname": 5}}).to_string(), StatusCode::BAD_REQUEST, "bad_request"),
            (json!({"sysinfo": 5}).to_string(), StatusCode::BAD_REQUEST, "bad_request"),
            (json!({"sysinfo": {"pad": "p".repeat(MAX_SYSINFO_LEN)}}).to_string(), StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
        ];
        for (body, want, code) in bad {
            let r = dev.post(&t.app, "heartbeat", body.as_bytes()).await;
            assert_eq!(r.status, want, "{body:.80}");
            assert_eq!(r.json()["error"], code, "{body:.80}");
            assert!(!r.headers.contains_key(crate::api::devauth::SIG_HEADER));
        }
        // None of them recorded a heartbeat or made a row.
        assert!(t.state.pm.get_in_memory("leapgate2").await.unwrap().read().await.leapgate_hb.is_none());
        assert!(!has_row(&t.state.db, "leapgate2").await);
        // A sysinfo at the limit is stored.
        let mut s = json!({"pad": ""});
        s["pad"] = json!("p".repeat(MAX_SYSINFO_LEN - s.to_string().len()));
        let r = dev.post(&t.app, "heartbeat", json!({"sysinfo": s}).to_string().as_bytes()).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(device_row(&t.state.db, "leapgate2").await.0, s.to_string());
    }

    /// The in-memory record of the last signed heartbeat (for block 04): written by the heartbeat
    /// only, not by a refused one or by a Leapgate audit.
    #[tokio::test]
    async fn leapgate_heartbeat_is_recorded_in_memory() {
        let t = testutil::app().await;
        let dev = testutil::leapgate_device(&t.state, "leapgate3", UUID).await;
        let audit = dev.post(&t.app, "audit/alarm", br#"{"typ":1}"#).await;
        assert_eq!(audit.status, StatusCode::OK);
        let peer = t.state.pm.get_in_memory("leapgate3").await.unwrap();
        assert!(peer.read().await.leapgate_hb.is_none());
        let r = dev.post(&t.app, "heartbeat", json!({"leapgate": "0.3.1", "ver": 1}).to_string().as_bytes()).await;
        assert_eq!(r.status, StatusCode::OK);
        {
            let p = peer.read().await;
            let hb = p.leapgate_hb.as_ref().unwrap();
            assert!(hb.at.elapsed() < std::time::Duration::from_secs(5));
            assert_eq!(hb.leapgate_ver, hbb_common::get_version_number("0.3.1") as u32);
        }
        // An unreadable version is 0.
        dev.post(&t.app, "heartbeat", json!({"leapgate": "x", "ver": 2}).to_string().as_bytes()).await;
        assert_eq!(peer.read().await.leapgate_hb.as_ref().unwrap().leapgate_ver, 0);
    }

    /// Phase 4 contract 01 §2.1: `exit` absent is false; each heartbeat replaces the record; a
    /// non-boolean one is a 400 that leaves the record alone.
    #[tokio::test]
    async fn leapgate_heartbeat_exit() {
        let t = testutil::app().await;
        let dev = testutil::leapgate_device(&t.state, "leapgate5", UUID).await;
        let exit = || async {
            let p = t.state.pm.get_in_memory("leapgate5").await.unwrap();
            let p = p.read().await;
            p.leapgate_hb.as_ref().unwrap().exit
        };
        for (body, want) in [
            (json!({"ver": 1}), false),
            (json!({"ver": 2, "exit": true}), true),
            (json!({"ver": 3, "exit": false}), false),
            (json!({"ver": 4, "exit": true}), true),
            (json!({"ver": 5}), false),
            (json!({"ver": 6, "exit": true}), true),
        ] {
            let r = dev.post(&t.app, "heartbeat", body.to_string().as_bytes()).await;
            assert_eq!(r.status, StatusCode::OK, "{body}");
            assert_eq!(exit().await, want, "{body}");
        }
        for bad in [json!({"ver": 7, "exit": "yes"}), json!({"ver": 8, "exit": 1}), json!({"ver": 9, "exit": null})] {
            let r = dev.post(&t.app, "heartbeat", bad.to_string().as_bytes()).await;
            assert_eq!((r.status, &r.json()["error"]), (StatusCode::BAD_REQUEST, &json!("bad_request")), "{bad}");
            assert!(exit().await, "{bad}");
        }
    }

    /// Contract 02 §3.4: `routing` when the client's `routing_rev` is not the server's; `probes` are
    /// kept under the verified id, and bad ones never fail the heartbeat.
    #[tokio::test]
    async fn leapgate_heartbeat_routing_and_probes() {
        let t = testutil::app().await;
        let router = &t.state.router;
        router.set_configured(vec!["r1.example:21117".to_owned(), "r2.example".to_owned()]);
        let (rev, _) = router.routing();
        let dev = testutil::leapgate_device(&t.state, "leapgate4", UUID).await;

        let r = dev.post(&t.app, "heartbeat", json!({"routing_rev": 0}).to_string().as_bytes()).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(testutil::verify_server_sig(&t.state, &r.sig, &r.headers, &r.body));
        assert_eq!(
            r.json()["routing"],
            json!({"rev": rev, "probe_interval_secs": 300, "relays": ["r1.example:21117", "r2.example"]})
        );
        assert!(r.json()["routing"]["rev"].is_i64());
        let r = dev.post(&t.app, "heartbeat", json!({"routing_rev": rev}).to_string().as_bytes()).await;
        assert_eq!(r.json().get("routing"), None);

        // Bad probes: the heartbeat is answered as usual and nothing is recorded.
        for (i, probes) in [json!("x"), json!(5), json!({"routing_rev": rev}), json!({"routing_rev": "x", "age_s": 0})]
            .into_iter()
            .enumerate()
        {
            let body = json!({"routing_rev": rev, "ver": i, "probes": probes}).to_string();
            let r = dev.post(&t.app, "heartbeat", body.as_bytes()).await;
            assert_eq!(r.status, StatusCode::OK, "{body}");
            assert_eq!(r.json()["api"], json!(1));
        }
        assert!(router.status_text().ends_with("measurements: 0 devices, 0 fresh\n"));

        // Good probes are kept under the signed id, whatever id the body names.
        let probes = json!({"routing_rev": rev, "age_s": 5, "rtt": {"r1.example:21117": 23}, "down": ["r2.example"]});
        let body = json!({"id": "other", "routing_rev": rev, "probes": probes}).to_string();
        assert_eq!(dev.post(&t.app, "heartbeat", body.as_bytes()).await.status, StatusCode::OK);
        assert!(router.status_text().ends_with("measurements: 1 devices, 1 fresh\n"));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mine = router.test(ip, ip, "leapgate4", "").await;
        assert!(mine.contains("(rtt_a)") && mine.contains("[A rtt 23ms, B est ?]"), "{mine}");
        let other = router.test(ip, ip, "other", "").await;
        assert!(other.contains("(rr)"), "{other}");

        // Probes that are dropped (for another list) leave the last round alone.
        let stale = json!({"routing_rev": rev + 1, "age_s": 0, "rtt": {"r1.example:21117": 40}});
        let body = json!({"routing_rev": rev, "ver": 99, "probes": stale}).to_string();
        assert_eq!(dev.post(&t.app, "heartbeat", body.as_bytes()).await.status, StatusCode::OK);
        assert!(router.status_text().ends_with("measurements: 1 devices, 1 fresh\n"));

        // No `probes` (the client dropped its round, e.g. one taken through a TUN): the last round
        // goes at once, not after `MEASURE_TTL`. (`ver` only keeps the body apart from the earlier
        // one, which a replay of the same signature would hit.)
        let body = json!({"routing_rev": rev, "ver": 100}).to_string();
        let r = dev.post(&t.app, "heartbeat", body.as_bytes()).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(router.status_text().ends_with("measurements: 0 devices, 0 fresh\n"));
        let mine = router.test(ip, ip, "leapgate4", "").await;
        assert!(mine.contains("(rr)"), "{mine}");
    }
}
