//! Device reports: sysinfo and heartbeat / strategy push (PORTA.md §9.3, §10; notes 01, 03 §4).
//! No authentication (compatibility debt); only devices registered with hbbs, checked by `uuid`.

use super::{ok_json, parse_json, text, ApiResult, ClientIp};
use crate::{conn_tracker::clip, peer::MAX_PEER_ID_LEN, state::AppState};
use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use serde_derive::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::BTreeMap;

/// Longest `uuid` (base64 text) the device reports and the login accept. Real ones are the base64
/// of a machine id, well under this.
pub(crate) const MAX_UUID_LEN: usize = 128;
/// Largest sysinfo body accepted; it is stored whole as `device.sysinfo`. A real one is a few
/// hundred bytes; without this every registered device could keep 2 MB (the body limit) there.
const MAX_SYSINFO_LEN: usize = 8 * 1024;
/// `hostname`, `username`, `os` and `version` are stored again in their own columns, clipped to this.
const MAX_SYSINFO_FIELD_LEN: usize = 253;
/// Device rows kept by the hourly purge (`evict`). Registering with hbbs is not authenticated, so
/// made-up devices that pass `uuid_matches` can still add rows (review A-10). A row is at most about
/// 10.5 KB on disk (8 KB of sysinfo, 4 × 253 bytes of split fields, the id and uuid; measured with
/// 4 KB pages, the primary key index included): 10,000 rows ≈ 0.1 GB, plus an hour of registrations.
const MAX_DEVICES: i64 = 10_000;

/// Identity check of the unauthenticated device reports and of the login's device binding (§9.3):
/// hbbs' `peer` table must know `id` (real clients register before they report), and `uuid` must be
/// present and decode (standard base64) to `peer.uuid` byte for byte. An id over `MAX_PEER_ID_LEN`
/// or a uuid over `MAX_UUID_LEN` bytes fails without a query.
pub(crate) async fn uuid_matches(db: &SqlitePool, id: &str, uuid: Option<&str>) -> Result<bool, sqlx::Error> {
    let Some(uuid) = uuid.filter(|u| u.len() <= MAX_UUID_LEN) else {
        return Ok(false);
    };
    if id.len() > MAX_PEER_ID_LEN {
        return Ok(false);
    }
    let known: Option<Vec<u8>> = sqlx::query_scalar("select uuid from peer where id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(known.is_some_and(|known| base64::decode(uuid).is_ok_and(|u| u == known)))
}

/// Late binding (§11) of a device that passed `uuid_matches` and has no owner: a login on it made
/// before it was registered with hbbs (the login binds only registered devices) left a token row
/// with its id and uuid. The newest such token (`last_used_at`) of an enabled account gives the
/// owner. As safe as the login's binding: the token's uuid is the one just checked against hbbs.
async fn bind_owner(db: &SqlitePool, id: &str, uuid: &str) -> Result<(), sqlx::Error> {
    let owner: Option<i64> = sqlx::query_scalar(
        "select t.user_id from token t join user u on u.id = t.user_id
         where t.device_id = ? and t.device_uuid = ? and u.status = 1
         order by t.last_used_at desc limit 1",
    )
    .bind(id)
    .bind(uuid)
    .fetch_optional(db)
    .await?;
    if let Some(owner) = owner {
        sqlx::query("update device set user_id = ? where id = ? and user_id is null")
            .bind(owner)
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(())
}

/// Hourly, from `conn_tracker`'s purge: over `MAX_DEVICES` rows, deletes the excess, oldest
/// `last_seen_at` first, among the rows with no owner and no `device_policy` / device-scoped
/// `strategy_option` rows (neither table references `device`, so nothing else goes with them). Rows
/// that do not qualify are kept even over the limit. An evicted device that comes back gets a new row
/// on its next heartbeat, which asks for its sysinfo again (`sysinfo` key, §10).
pub(crate) async fn evict(db: &SqlitePool) -> Result<u64, sqlx::Error> {
    let rows: i64 = sqlx::query_scalar("select count(*) from device").fetch_one(db).await?;
    if rows <= MAX_DEVICES {
        return Ok(0);
    }
    let res = sqlx::query(
        "delete from device where id in (
           select id from device d where user_id is null
             and not exists (select 1 from device_policy p where p.device_id = d.id)
             and not exists (select 1 from strategy_option s where s.scope = d.id)
           order by last_seen_at limit ?)",
    )
    .bind(rows - MAX_DEVICES)
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

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

/// `POST /api/sysinfo`: plain text `SYSINFO_UPDATED` on success, never `ID_NOT_FOUND`.
pub(crate) async fn sysinfo(State(state): State<AppState>, body: Bytes) -> ApiResult {
    let mut req: SysinfoReq = parse_json(&body)?;
    if body.len() > MAX_SYSINFO_LEN || !uuid_matches(&state.db, &req.id, req.uuid.as_deref()).await? {
        // The client retries after 120 s.
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    for field in [&mut req.hostname, &mut req.username, &mut req.os, &mut req.version] {
        clip(field, MAX_SYSINFO_FIELD_LEN);
    }
    let uuid = req.uuid.as_deref().unwrap_or_default();
    let now = crate::common::now() as i64;
    let owner: Option<i64> = sqlx::query_scalar(
        "insert into device(id, uuid, hostname, username, os, version, client_type, sysinfo,
                            first_seen_at, last_seen_at)
         values(?, ?, ?, ?, ?, ?, 'rustdesk', ?, ?, ?)
         on conflict(id) do update set uuid = excluded.uuid, hostname = excluded.hostname,
           username = excluded.username, os = excluded.os, version = excluded.version,
           client_type = excluded.client_type, sysinfo = excluded.sysinfo,
           last_seen_at = excluded.last_seen_at
         returning user_id",
    )
    .bind(&req.id)
    .bind(uuid)
    .bind(&req.hostname)
    .bind(&req.username)
    .bind(&req.os)
    .bind(&req.version)
    .bind(String::from_utf8_lossy(&body))
    .bind(now)
    .bind(now)
    .fetch_one(&state.db)
    .await?;
    if owner.is_none() {
        bind_owner(&state.db, &req.id, uuid).await?;
    }
    Ok(text("SYSINFO_UPDATED"))
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
pub(crate) async fn heartbeat(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    body: Bytes,
) -> ApiResult {
    let req: HeartbeatReq = parse_json(&body)?;
    if !uuid_matches(&state.db, &req.id, req.uuid.as_deref()).await? {
        return Ok(ok_json(&HeartbeatResp::default()));
    }
    let uuid = req.uuid.as_deref().unwrap_or_default();
    let now = crate::common::now() as i64;
    let (sysinfo, owner): (String, Option<i64>) = sqlx::query_as(
        "insert into device(id, uuid, ver, first_seen_at, last_seen_at, last_ip) values(?, ?, ?, ?, ?, ?)
         on conflict(id) do update set ver = excluded.ver, last_seen_at = excluded.last_seen_at,
           last_ip = excluded.last_ip
         returning sysinfo, user_id",
    )
    .bind(&req.id)
    .bind(uuid)
    .bind(req.ver)
    .bind(now)
    .bind(now)
    .bind(ip.to_string())
    .fetch_one(&state.db)
    .await?;
    if owner.is_none() {
        bind_owner(&state.db, &req.id, uuid).await?;
    }
    let mut resp = HeartbeatResp {
        sysinfo: sysinfo.is_empty().then_some(true),
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

#[cfg(test)]
mod tests {
    use super::{MAX_DEVICES, MAX_PEER_ID_LEN, MAX_SYSINFO_FIELD_LEN, MAX_SYSINFO_LEN, MAX_UUID_LEN};
    use crate::testutil::{self, send};
    use axum::http::StatusCode;
    use hbb_common::tokio;
    use serde_json::{json, Value};
    use sqlx::SqlitePool;

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
            super::uuid_matches(db, &id, uuid.as_deref()).await.unwrap()
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

    #[tokio::test]
    async fn evict_only_unowned_unconfigured_oldest() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let insert = |id: &'static str, last_seen: i64| async move {
            sqlx::query("insert into device(id, first_seen_at, last_seen_at) values(?, 0, ?)")
                .bind(id)
                .bind(last_seen)
                .execute(db)
                .await
                .unwrap();
        };
        // MAX_DEVICES - 3 recent rows, seen at 1001, 1002, …
        sqlx::query(
            "with recursive n(i) as (select 1 union all select i + 1 from n where i < ?)
             insert into device(id, first_seen_at, last_seen_at) select 'bulk' || i, 0, 1000 + i from n",
        )
        .bind(MAX_DEVICES - 3)
        .execute(db)
        .await
        .unwrap();
        // The oldest rows: one owned, one with a pinned relay, one with a device option.
        let (uid, _) = testutil::create_user(db, "ev-amy", "", false).await;
        insert("owned", 1).await;
        sqlx::query("update device set user_id = ? where id = 'owned'").bind(uid).execute(db).await.unwrap();
        insert("pinned", 2).await;
        sqlx::query("insert into device_policy(device_id, relay_pin) values('pinned', 'r:21117')")
            .execute(db)
            .await
            .unwrap();
        insert("optioned", 3).await;
        set_option(db, "optioned", "allow-auto-disconnect", "Y").await;
        assert_eq!(super::evict(db).await.unwrap(), 0, "at the limit");

        // Three over the limit: the three oldest rows that qualify go, the older ones that do not stay.
        insert("old-a", 4).await;
        insert("old-b", 5).await;
        insert("old-c", 6).await;
        assert_eq!(super::evict(db).await.unwrap(), 3);
        let n: i64 = sqlx::query_scalar("select count(*) from device").fetch_one(db).await.unwrap();
        assert_eq!(n, MAX_DEVICES);
        let gone: i64 = sqlx::query_scalar("select count(*) from device where id like 'old-%'")
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(gone, 0);
        for id in ["owned", "pinned", "optioned", "bulk1"] {
            let kept: i64 = sqlx::query_scalar("select count(*) from device where id = ?")
                .bind(id)
                .fetch_one(db)
                .await
                .unwrap();
            assert_eq!(kept, 1, "{id}");
        }
        // One over again: the oldest bulk row is the oldest that qualifies.
        insert("new", 99_999).await;
        assert_eq!(super::evict(db).await.unwrap(), 1);
        let bulk1: i64 = sqlx::query_scalar("select count(*) from device where id = 'bulk1'")
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(bulk1, 0);
        // The configuration of the kept rows is untouched.
        let (rows,): (i64,) = sqlx::query_as(
            "select (select count(*) from device_policy where device_id = 'pinned')
                  + (select count(*) from strategy_option where scope = 'optioned')",
        )
        .fetch_one(db)
        .await
        .unwrap();
        assert_eq!(rows, 2);
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
}
