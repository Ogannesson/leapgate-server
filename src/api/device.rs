//! Device reports: sysinfo and heartbeat / strategy push (PORTA.md §9.3, §10; notes 01, 03 §4).
//! No authentication (compatibility debt); only devices registered with hbbs, checked by `uuid`.

use super::{ok_json, parse_json, text, ApiResult, ClientIp};
use crate::{peer::MAX_PEER_ID_LEN, state::AppState};
use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use serde_derive::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::BTreeMap;

/// Longest `uuid` (base64 text) the device reports and the login accept. Real ones are the base64
/// of a machine id, well under this.
pub(crate) const MAX_UUID_LEN: usize = 128;
/// Largest sysinfo body accepted; it is stored whole as `device.sysinfo`. A real one is a few
/// hundred bytes; without this every registered device could keep 2 MB (the body limit) there.
const MAX_SYSINFO_LEN: usize = 64 * 1024;

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
    let req: SysinfoReq = parse_json(&body)?;
    if body.len() > MAX_SYSINFO_LEN || !uuid_matches(&state.db, &req.id, req.uuid.as_deref()).await? {
        // The client retries after 120 s.
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let now = crate::common::now() as i64;
    sqlx::query(
        "insert into device(id, uuid, hostname, username, os, version, client_type, sysinfo,
                            first_seen_at, last_seen_at)
         values(?, ?, ?, ?, ?, ?, 'rustdesk', ?, ?, ?)
         on conflict(id) do update set uuid = excluded.uuid, hostname = excluded.hostname,
           username = excluded.username, os = excluded.os, version = excluded.version,
           client_type = excluded.client_type, sysinfo = excluded.sysinfo,
           last_seen_at = excluded.last_seen_at",
    )
    .bind(&req.id)
    .bind(req.uuid.as_deref().unwrap_or_default())
    .bind(&req.hostname)
    .bind(&req.username)
    .bind(&req.os)
    .bind(&req.version)
    .bind(String::from_utf8_lossy(&body))
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;
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
    let now = crate::common::now() as i64;
    let sysinfo: String = sqlx::query_scalar(
        "insert into device(id, uuid, ver, first_seen_at, last_seen_at, last_ip) values(?, ?, ?, ?, ?, ?)
         on conflict(id) do update set ver = excluded.ver, last_seen_at = excluded.last_seen_at,
           last_ip = excluded.last_ip
         returning sysinfo",
    )
    .bind(&req.id)
    .bind(req.uuid.as_deref().unwrap_or_default())
    .bind(req.ver)
    .bind(now)
    .bind(now)
    .bind(ip.to_string())
    .fetch_one(&state.db)
    .await?;
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
    use super::{MAX_PEER_ID_LEN, MAX_SYSINFO_LEN, MAX_UUID_LEN};
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
