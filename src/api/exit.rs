//! Exit directory (phase 4 contract 01, LEAPGATE.md §12.4): the exits a user may use right now.

use super::{group::ONLINE_TIMEOUT, ok_json, ApiResult, CurrentUser};
use crate::{
    peer::{Peer, LEAPGATE_HB_FRESH},
    state::AppState,
};
use axum::extract::State;
use serde_derive::Serialize;

/// Devices the user (`?1`) may see as exits: owned by them, or granted to them or to a group they
/// are in. Owned ones first.
const CANDIDATES: &str = "
    with ids(id) as (
      select id from device where user_id = ?1
      union
      select device_id from exit_grant
       where user_id = ?1 or group_id in (select group_id from group_member where user_id = ?1))
    select ids.id, coalesce(d.hostname, ''), coalesce(u.name, ''), coalesce(d.user_id = ?1, 0)
      from ids left join device d on d.id = ids.id left join user u on u.id = d.user_id
     order by 4 desc, ids.id";

#[derive(Serialize)]
struct Exit {
    id: String,
    hostname: String,
    owner: String,
    own: bool,
}

#[derive(Serialize)]
struct Exits {
    exits: Vec<Exit>,
}

/// Registered over UDP within `ONLINE_TIMEOUT`, and its last signed Leapgate heartbeat is within
/// `LEAPGATE_HB_FRESH` and said `exit` (contract 01 §2.4).
pub(crate) fn available(p: &Peer) -> bool {
    p.last_reg_time.elapsed() < ONLINE_TIMEOUT
        && p.leapgate_hb.as_ref().is_some_and(|hb| hb.exit && hb.at.elapsed() < LEAPGATE_HB_FRESH)
}

/// `GET /api/leapgate/user/v1/exits`. Online state from memory only, like the group panel: a device
/// not in memory has not registered within `ONLINE_TIMEOUT`.
pub(crate) async fn exits(State(state): State<AppState>, user: CurrentUser) -> ApiResult {
    let rows: Vec<(String, String, String, bool)> =
        sqlx::query_as(CANDIDATES).bind(user.id).fetch_all(&state.db).await?;
    let mut exits = Vec::new();
    for (id, hostname, owner, own) in rows {
        let Some(peer) = state.pm.get_in_memory(&id).await else {
            continue;
        };
        if available(&*peer.read().await) {
            exits.push(Exit { id, hostname, owner, own });
        }
    }
    Ok(ok_json(&Exits { exits }))
}

#[cfg(test)]
mod tests {
    use super::available;
    use crate::{
        peer::{LeapgateHb, Peer},
        testutil::{self, send},
    };
    use axum::http::StatusCode;
    use hbb_common::tokio;
    use serde_json::{json, Value};
    use sqlx::SqlitePool;
    use std::time::{Duration, Instant};

    const URI: &str = "/api/leapgate/user/v1/exits";

    fn ago(secs: u64) -> Instant {
        Instant::now().checked_sub(Duration::from_secs(secs)).unwrap()
    }

    /// A peer registered `reg` seconds ago whose last signed heartbeat, `hb` seconds ago, said `exit`.
    fn peer(reg: u64, hb: Option<(u64, bool)>) -> Peer {
        Peer {
            last_reg_time: ago(reg),
            leapgate_hb: hb.map(|(age, exit)| LeapgateHb {
                at: ago(age),
                leapgate_ver: 4000,
                exit,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn available_needs_all_three() {
        assert!(available(&peer(29, Some((179, true)))));
        assert!(!available(&peer(31, Some((179, true)))));
        assert!(!available(&peer(29, Some((181, true)))));
        assert!(!available(&peer(29, Some((179, false)))));
        assert!(!available(&peer(29, None)));
    }

    /// `id` in memory as `peer(reg, hb)` would be.
    async fn online(t: &testutil::TestApp, id: &str, reg: u64, hb: Option<(u64, bool)>) {
        let p = t.state.pm.get_or(id).await;
        let mut w = p.write().await;
        let want = peer(reg, hb);
        w.last_reg_time = want.last_reg_time;
        w.leapgate_hb = want.leapgate_hb;
    }

    async fn device(db: &SqlitePool, id: &str, owner: Option<i64>, hostname: &str) {
        sqlx::query("insert into device(id, user_id, hostname, first_seen_at, last_seen_at) values(?, ?, ?, 0, 0)")
            .bind(id)
            .bind(owner)
            .bind(hostname)
            .execute(db)
            .await
            .unwrap();
    }

    async fn grant(db: &SqlitePool, id: &str, user: Option<i64>, group: Option<i64>) {
        sqlx::query("insert into exit_grant(device_id, user_id, group_id) values(?, ?, ?)")
            .bind(id)
            .bind(user)
            .bind(group)
            .execute(db)
            .await
            .unwrap();
    }

    async fn group(db: &SqlitePool, name: &str, members: &[i64]) -> i64 {
        let gid: i64 = sqlx::query_scalar("insert into user_group(name, created_at) values(?, 0) returning id")
            .bind(name)
            .fetch_one(db)
            .await
            .unwrap();
        for uid in members {
            sqlx::query("insert into group_member(group_id, user_id) values(?, ?)")
                .bind(gid)
                .bind(uid)
                .execute(db)
                .await
                .unwrap();
        }
        gid
    }

    async fn exits(t: &testutil::TestApp, token: &str) -> Value {
        let (status, ct, body) = send(&t.app, "GET", URI, Some(token), "").await;
        assert_eq!((status, ct.as_str()), (StatusCode::OK, "application/json; charset=utf-8"));
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 1, "{v}");
        v
    }

    /// The ids listed.
    async fn ids(t: &testutil::TestApp, token: &str) -> Vec<String> {
        exits(t, token).await["exits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn unauthorized_and_errors() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, token) = testutil::create_user(db, "ex-off", "pw", false).await;
        for bad in [None, Some("nope")] {
            let (status, _, body) = send(&t.app, "GET", URI, bad, "").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({"error": "Unauthorized"}));
        }
        // Wrong method: the general error shape, not the signed reports' one.
        let (status, _, body) = send(&t.app, "POST", URI, Some(&token), "").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({"error": "Method Not Allowed"}));
        // Nothing to list.
        assert_eq!(exits(&t, &token).await, json!({"exits": []}));
        sqlx::query("update user set status = 0 where id = ?").bind(uid).execute(db).await.unwrap();
        let (status, _, _) = send(&t.app, "GET", URI, Some(&token), "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Database gone: no 5xx.
        let (_, token2) = testutil::create_user(db, "ex-on", "pw", false).await;
        db.close().await;
        let (status, _, body) = send(&t.app, "GET", URI, Some(&token2), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({"error": "Server error"}));
    }

    #[tokio::test]
    async fn owners_see_their_available_devices() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (amy, amy_t) = testutil::create_user(db, "ex-amy", "pw", false).await;
        let (_, bob_t) = testutil::create_user(db, "ex-bob", "pw", false).await;
        for (id, reg, hb) in [
            ("a-on", 1, Some((1, true))),
            ("a-off", 1, Some((1, false))),
            ("a-stale-hb", 1, Some((181, true))),
            ("a-stale-reg", 31, Some((1, true))),
            ("a-no-hb", 1, None),
        ] {
            device(db, id, Some(amy), "pc").await;
            online(&t, id, reg, hb).await;
        }
        device(db, "a-not-in-memory", Some(amy), "pc").await;
        let v = exits(&t, &amy_t).await;
        assert_eq!(v, json!({"exits": [{"id": "a-on", "hostname": "pc", "owner": "ex-amy", "own": true}]}));
        // Exactly the four keys: no IP, system user name or OS.
        assert_eq!(v["exits"][0].as_object().unwrap().len(), 4);
        assert!(ids(&t, &bob_t).await.is_empty());
    }

    /// A real signed heartbeat with `exit`, then without it.
    #[tokio::test]
    async fn listed_after_a_signed_heartbeat_with_exit() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (amy, token) = testutil::create_user(db, "ex-hb", "pw", false).await;
        let dev = testutil::leapgate_device(&t.state, "hb-exit", b"uuid").await;
        let r = dev.post(&t.app, "heartbeat", br#"{"ver":1,"exit":true}"#).await;
        assert_eq!(r.status, StatusCode::OK);
        sqlx::query("update device set user_id = ? where id = 'hb-exit'").bind(amy).execute(db).await.unwrap();
        // Signed in over HTTP, not registered over UDP yet.
        assert!(ids(&t, &token).await.is_empty());
        t.state.pm.get_in_memory("hb-exit").await.unwrap().write().await.last_reg_time = Instant::now();
        assert_eq!(ids(&t, &token).await, ["hb-exit"]);
        dev.post(&t.app, "heartbeat", br#"{"ver":2}"#).await;
        assert!(ids(&t, &token).await.is_empty());
    }

    #[tokio::test]
    async fn grants_to_users_and_groups() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (amy, amy_t) = testutil::create_user(db, "gr-amy", "pw", false).await;
        let (bob, bob_t) = testutil::create_user(db, "gr-bob", "pw", false).await;
        let (cat, cat_t) = testutil::create_user(db, "gr-cat", "pw", false).await;
        let (_, root_t) = testutil::create_user(db, "gr-root", "pw", true).await;
        for id in ["d-amy", "d-bob"] {
            online(&t, id, 1, Some((1, true))).await;
        }
        device(db, "d-amy", Some(amy), "amy-pc").await;
        device(db, "d-bob", Some(bob), "bob-pc").await;

        // To a user: listed for them with the owner; not for anybody else, admins included.
        grant(db, "d-amy", Some(bob), None).await;
        let v = exits(&t, &bob_t).await;
        assert_eq!(
            v["exits"],
            json!([{"id": "d-bob", "hostname": "bob-pc", "owner": "gr-bob", "own": true},
                   {"id": "d-amy", "hostname": "amy-pc", "owner": "gr-amy", "own": false}])
        );
        assert!(ids(&t, &cat_t).await.is_empty());
        assert!(ids(&t, &root_t).await.is_empty());

        // To a group: its members; membership read at each query; the grant goes with the group.
        let ops = group(db, "gr-ops", &[cat]).await;
        grant(db, "d-bob", None, Some(ops)).await;
        assert_eq!(ids(&t, &cat_t).await, ["d-bob"]);
        sqlx::query("delete from group_member where user_id = ?").bind(cat).execute(db).await.unwrap();
        assert!(ids(&t, &cat_t).await.is_empty());
        sqlx::query("insert into group_member(group_id, user_id) values(?, ?)").bind(ops).bind(cat).execute(db).await.unwrap();
        assert_eq!(ids(&t, &cat_t).await, ["d-bob"]);
        sqlx::query("delete from user_group where id = ?").bind(ops).execute(db).await.unwrap();
        assert!(ids(&t, &cat_t).await.is_empty());

        // Owned and granted to the owner too: once, as own.
        grant(db, "d-amy", Some(amy), None).await;
        let ops2 = group(db, "gr-ops2", &[amy]).await;
        grant(db, "d-amy", None, Some(ops2)).await;
        assert_eq!(exits(&t, &amy_t).await["exits"], json!([{"id": "d-amy", "hostname": "amy-pc", "owner": "gr-amy", "own": true}]));

        // A grant on an id with no device row (online): listed with empty hostname and owner; sorted
        // owned first, then by id.
        online(&t, "a-rowless", 1, Some((1, true))).await;
        online(&t, "z-rowless", 1, Some((1, true))).await;
        grant(db, "z-rowless", Some(bob), None).await;
        grant(db, "a-rowless", Some(bob), None).await;
        let v = exits(&t, &bob_t).await;
        assert_eq!(
            v["exits"],
            json!([{"id": "d-bob", "hostname": "bob-pc", "owner": "gr-bob", "own": true},
                   {"id": "a-rowless", "hostname": "", "owner": "", "own": false},
                   {"id": "d-amy", "hostname": "amy-pc", "owner": "gr-amy", "own": false},
                   {"id": "z-rowless", "hostname": "", "owner": "", "own": false}])
        );
        // The admin's own device and grants only.
        let root: i64 = sqlx::query_scalar("select id from user where name = 'gr-root'").fetch_one(db).await.unwrap();
        grant(db, "z-rowless", Some(root), None).await;
        assert_eq!(ids(&t, &root_t).await, ["z-rowless"]);
    }

    /// Migration 0007: exactly one of user and group; one grant per pair; gone with the user or the
    /// group, not with the device row.
    #[tokio::test]
    async fn exit_grant_table() {
        let (_dir, db) = testutil::pool().await;
        let db = &db;
        let (amy, _) = testutil::create_user(db, "tb-amy", "pw", false).await;
        let ops = group(db, "tb-ops", &[]).await;
        let insert = |user: Option<i64>, group: Option<i64>| {
            sqlx::query("insert into exit_grant(device_id, user_id, group_id) values('d1', ?, ?)")
                .bind(user)
                .bind(group)
                .execute(db)
        };
        assert!(insert(None, None).await.is_err());
        assert!(insert(Some(amy), Some(ops)).await.is_err());
        insert(Some(amy), None).await.unwrap();
        insert(None, Some(ops)).await.unwrap();
        assert!(insert(Some(amy), None).await.is_err());
        assert!(insert(None, Some(ops)).await.is_err());
        let count = || async { sqlx::query_scalar::<_, i64>("select count(*) from exit_grant").fetch_one(db).await.unwrap() };
        device(db, "d1", Some(amy), "").await;
        sqlx::query("delete from device where id = 'd1'").execute(db).await.unwrap();
        assert_eq!(count().await, 2);
        sqlx::query("delete from user where id = ?").bind(amy).execute(db).await.unwrap();
        assert_eq!(count().await, 1);
        sqlx::query("delete from user_group where id = ?").bind(ops).execute(db).await.unwrap();
        assert_eq!(count().await, 0);
    }
}
