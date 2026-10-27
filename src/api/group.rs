//! Group panel (LEAPGATE.md §12.3; note 03 §3).
//!
//! Visibility: an admin sees every user and every device; anyone else sees themselves plus the
//! users sharing any `share_devices=1` group with them, and the devices owned (`device.user_id`)
//! by those users. A `status` parameter keeps only the users with that `user.status`, and drops the
//! devices of the users it leaves out (unowned devices stay).

use super::{
    account::{UserPayload, UserRow, USER_COLUMNS},
    ok_json, ApiResult, CurrentUser, PageQuery,
};
use crate::state::AppState;
use axum::extract::{Query, State};
use serde_derive::Serialize;
use std::time::Duration;

/// Same as hbbs' `REG_TIMEOUT`: online = registered within the last 30 seconds (note 02 §2.5).
pub(crate) const ONLINE_TIMEOUT: Duration = Duration::from_secs(30);

/// Ids of the users a non-admin sees; binds the current user's id twice.
const VISIBLE_USERS: &str = "select ? union select m2.user_id from group_member m1
     join user_group g on g.id = m1.group_id and g.share_devices = 1
     join group_member m2 on m2.group_id = m1.group_id
     where m1.user_id = ?";

#[derive(Serialize)]
struct Page<T> {
    total: i64,
    data: Vec<T>,
}

fn page<T: serde::Serialize>(total: i64, data: Vec<T>) -> ApiResult {
    Ok(ok_json(&Page { total, data }))
}

/// `where` condition restricting `col` (a user id) to what `user` sees, and the ids to bind for it.
fn visible(user: &CurrentUser, col: &str) -> (String, Vec<i64>) {
    if user.is_admin {
        ("1".to_owned(), vec![])
    } else {
        (format!("{col} in ({VISIBLE_USERS})"), vec![user.id, user.id])
    }
}

/// `GET /api/users?current=&pageSize=&accessible=&status=1`.
pub(crate) async fn users(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(page_query): Query<PageQuery>,
) -> ApiResult {
    let (offset, limit) = page_query.offset_limit();
    let (mut cond, mut ids) = visible(&user, "id");
    if let Some(status) = page_query.status() {
        cond.push_str(" and status = ?");
        ids.push(status);
    }
    let sql = format!("select count(*) from user where {cond}");
    let mut total = sqlx::query_scalar::<_, i64>(&sql);
    for id in &ids {
        total = total.bind(id);
    }
    let total = total.fetch_one(&state.db).await?;
    let sql = format!("select {USER_COLUMNS} from user where {cond} order by id limit ? offset ?");
    let mut rows = sqlx::query_as::<_, UserRow>(&sql);
    for id in &ids {
        rows = rows.bind(id);
    }
    let rows = rows.bind(limit).bind(offset).fetch_all(&state.db).await?;
    page(total, rows.into_iter().map(UserPayload::from_row).collect())
}

/// One device of `/api/peers` (note 03 §3.4); every string field is a string, never null.
#[derive(Serialize)]
struct PeerPayload {
    id: String,
    info: PeerInfo,
    /// 1 online, 0 offline (the client takes online state from hbbs, not from here).
    status: i64,
    user: String,
    user_name: String,
    device_group_name: &'static str,
    note: &'static str,
}

#[derive(Serialize)]
struct PeerInfo {
    username: String,
    os: String,
    device_name: String,
}

/// `GET /api/peers?current=&pageSize=&accessible=&status=1`.
pub(crate) async fn peers(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(page_query): Query<PageQuery>,
) -> ApiResult {
    let (offset, limit) = page_query.offset_limit();
    let (mut cond, mut ids) = visible(&user, "d.user_id");
    if let Some(status) = page_query.status() {
        // Devices have no status of their own: drop the ones owned by users `/api/users` leaves out.
        cond.push_str(" and (u.id is null or u.status = ?)");
        ids.push(status);
    }
    let sql = format!("select count(*) from device d left join user u on u.id = d.user_id where {cond}");
    let mut total = sqlx::query_scalar::<_, i64>(&sql);
    for id in &ids {
        total = total.bind(id);
    }
    let total = total.fetch_one(&state.db).await?;
    let sql = format!(
        "select d.id, d.username, d.os, d.hostname, coalesce(u.name, '') from device d
         left join user u on u.id = d.user_id where {cond} order by d.id limit ? offset ?"
    );
    let mut rows = sqlx::query_as::<_, (String, String, String, String, String)>(&sql);
    for id in &ids {
        rows = rows.bind(id);
    }
    let rows = rows.bind(limit).bind(offset).fetch_all(&state.db).await?;
    let mut data = Vec::with_capacity(rows.len());
    for (id, username, os, device_name, owner) in rows {
        let online = match state.pm.get_in_memory(&id).await {
            Some(peer) => peer.read().await.last_reg_time.elapsed() < ONLINE_TIMEOUT,
            None => false,
        };
        data.push(PeerPayload {
            id,
            info: PeerInfo {
                username,
                os,
                device_name,
            },
            status: online as i64,
            user: owner.clone(),
            user_name: owner,
            device_group_name: "",
            note: "",
        });
    }
    page(total, data)
}

/// `GET /api/device-group/accessible`: `{"total":0,"data":[]}`.
pub(crate) async fn device_groups(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Query(_page): Query<PageQuery>,
) -> ApiResult {
    page::<()>(0, vec![])
}

#[cfg(test)]
mod tests {
    use crate::testutil::{self, send};
    use axum::http::StatusCode;
    use hbb_common::tokio;
    use serde_json::{json, Value};
    use sqlx::SqlitePool;
    use std::time::Instant;

    async fn get(app: &axum::Router, uri: &str, token: &str) -> Value {
        let (status, ct, body) = send(app, "GET", uri, Some(token), "").await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(ct, "application/json; charset=utf-8");
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert!(v["total"].is_i64(), "{uri}: total must be an integer");
        assert!(v["data"].is_array());
        v
    }

    fn names(v: &Value) -> Vec<&str> {
        v["data"].as_array().unwrap().iter().map(|u| u["name"].as_str().unwrap()).collect()
    }

    fn ids(v: &Value) -> Vec<&str> {
        v["data"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap()).collect()
    }

    async fn group(db: &SqlitePool, name: &str, share: bool, members: &[i64]) {
        let gid: i64 = sqlx::query_scalar(
            "insert into user_group(name, share_devices, created_at) values(?, ?, 0) returning id",
        )
        .bind(name)
        .bind(share)
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
    }

    async fn device(db: &SqlitePool, id: &str, owner: Option<i64>) {
        sqlx::query(
            "insert into device(id, user_id, hostname, username, os, first_seen_at, last_seen_at)
             values(?, ?, ?, ?, 'windows / Windows 11 Pro - 10.0.26100', 0, 0)",
        )
        .bind(id)
        .bind(owner)
        .bind(format!("host-{id}"))
        .bind(format!("user-{id}"))
        .execute(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn visibility() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (admin, admin_t) = testutil::create_user(db, "admin", "pw", true).await;
        let (a, a_t) = testutil::create_user(db, "a", "pw", false).await;
        let (b, b_t) = testutil::create_user(db, "b", "pw", false).await;
        let (c, c_t) = testutil::create_user(db, "c", "pw", false).await;
        let (d, d_t) = testutil::create_user(db, "d", "pw", false).await;
        let (_e, e_t) = testutil::create_user(db, "e", "pw", false).await;
        // a, b, c share devices; c and d are in a group that does not; a is in both.
        group(db, "share", true, &[a, b, c]).await;
        group(db, "plain", false, &[c, d]).await;
        group(db, "share2", true, &[a, d]).await;
        for (id, owner) in [("1", Some(a)), ("2", Some(b)), ("3", Some(c)), ("4", Some(d)), ("5", None), ("6", Some(admin))] {
            device(db, id, owner).await;
        }

        let users = |tok: String| {
            let app = t.app.clone();
            async move { get(&app, "/api/users?current=1&pageSize=100&accessible=&status=1", &tok).await }
        };
        let peers = |tok: String| {
            let app = t.app.clone();
            async move { get(&app, "/api/peers?current=1&pageSize=100&accessible=&status=1", &tok).await }
        };

        let v = users(admin_t.clone()).await;
        assert_eq!(v["total"], 6);
        assert_eq!(names(&v), ["admin", "a", "b", "c", "d", "e"]);
        let v = peers(admin_t).await;
        assert_eq!(v["total"], 6);
        assert_eq!(ids(&v), ["1", "2", "3", "4", "5", "6"]);

        assert_eq!(names(&users(a_t.clone()).await), ["a", "b", "c", "d"]);
        assert_eq!(ids(&peers(a_t).await), ["1", "2", "3", "4"]);
        assert_eq!(names(&users(b_t.clone()).await), ["a", "b", "c"]);
        assert_eq!(ids(&peers(b_t).await), ["1", "2", "3"]);
        // c shares with d only through a non-sharing group.
        assert_eq!(names(&users(c_t.clone()).await), ["a", "b", "c"]);
        assert_eq!(names(&users(d_t.clone()).await), ["a", "d"]);
        assert_eq!(ids(&peers(d_t).await), ["1", "4"]);
        // No groups: only oneself, even without devices.
        let v = users(e_t.clone()).await;
        assert_eq!((v["total"].as_i64(), names(&v)), (Some(1), vec!["e"]));
        let v = peers(e_t).await;
        assert_eq!(v, json!({"total": 0, "data": []}));
    }

    #[tokio::test]
    async fn status_filter() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (admin, admin_t) = testutil::create_user(db, "admin", "pw", true).await;
        let (a, a_t) = testutil::create_user(db, "a", "pw", false).await;
        let (b, _) = testutil::create_user(db, "b", "pw", false).await;
        group(db, "share", true, &[a, b]).await;
        sqlx::query("update user set status = 0 where id = ?")
            .bind(b)
            .execute(db)
            .await
            .unwrap();
        for (id, owner) in [("1", Some(a)), ("2", Some(b)), ("3", None), ("4", Some(admin))] {
            device(db, id, owner).await;
        }

        let q = "?current=1&pageSize=100&accessible=";
        let v = get(&t.app, &format!("/api/users{q}&status=1"), &admin_t).await;
        assert_eq!((v["total"].as_i64(), names(&v)), (Some(2), vec!["admin", "a"]));
        let v = get(&t.app, &format!("/api/peers{q}&status=1"), &admin_t).await;
        assert_eq!((v["total"].as_i64(), ids(&v)), (Some(3), vec!["1", "3", "4"]), "unowned devices stay");
        assert_eq!(names(&get(&t.app, &format!("/api/users{q}&status=0"), &admin_t).await), ["b"]);
        assert_eq!(ids(&get(&t.app, &format!("/api/peers{q}&status=0"), &admin_t).await), ["2", "3"]);
        // No parameter: no filter.
        assert_eq!(names(&get(&t.app, &format!("/api/users{q}"), &admin_t).await), ["admin", "a", "b"]);
        assert_eq!(ids(&get(&t.app, &format!("/api/peers{q}"), &admin_t).await), ["1", "2", "3", "4"]);

        assert_eq!(names(&get(&t.app, &format!("/api/users{q}&status=1"), &a_t).await), ["a"]);
        assert_eq!(ids(&get(&t.app, &format!("/api/peers{q}&status=1"), &a_t).await), ["1"]);
        assert_eq!(names(&get(&t.app, &format!("/api/users{q}"), &a_t).await), ["a", "b"]);
        assert_eq!(ids(&get(&t.app, &format!("/api/peers{q}"), &a_t).await), ["1", "2"]);
    }

    #[tokio::test]
    async fn payload_fields() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (uid, token) = testutil::create_user(db, "007", "pw", false).await;
        sqlx::query("update user set display_name = 'Bond', email = 'j@b', note = 'n' where id = ?")
            .bind(uid)
            .execute(db)
            .await
            .unwrap();
        device(db, "100", Some(uid)).await;
        device(db, "200", Some(uid)).await;
        // "100" registered just now, "200" is in memory but stale.
        t.state.pm.get_or("100").await.write().await.last_reg_time = Instant::now();
        t.state.pm.get_or("200").await;

        let v = get(&t.app, "/api/users?current=1&pageSize=100", &token).await;
        assert_eq!(
            v,
            json!({"total": 1, "data": [{"name": "007", "display_name": "Bond", "avatar": "", "email": "j@b",
                   "note": "n", "status": 1, "is_admin": false, "info": {}}]})
        );
        let v = get(&t.app, "/api/peers?current=1&pageSize=100", &token).await;
        let peer = |id: &str, status: i64| {
            json!({"id": id, "info": {"username": format!("user-{id}"),
                   "os": "windows / Windows 11 Pro - 10.0.26100", "device_name": format!("host-{id}")},
                   "status": status, "user": "007", "user_name": "007", "device_group_name": "", "note": ""})
        };
        assert_eq!(v, json!({"total": 2, "data": [peer("100", 1), peer("200", 0)]}));

        // Unowned devices (admin view) still give strings.
        let (_, admin_t) = testutil::create_user(db, "root", "pw", true).await;
        device(db, "300", None).await;
        let v = get(&t.app, "/api/peers", &admin_t).await;
        let p = &v["data"][2];
        assert_eq!((p["id"].as_str(), p["user"].as_str(), p["user_name"].as_str()), (Some("300"), Some(""), Some("")));
    }

    #[tokio::test]
    async fn paging() {
        let t = testutil::app().await;
        let db = &t.state.db;
        let (_, token) = testutil::create_user(db, "pager", "pw", true).await;
        for i in 0..149 {
            testutil::create_user(db, &format!("u{i:03}"), "", false).await;
            device(db, &format!("{i:03}"), None).await;
        }
        for path in ["/api/users", "/api/peers"] {
            let p1 = get(&t.app, &format!("{path}?current=1&pageSize=100"), &token).await;
            let p2 = get(&t.app, &format!("{path}?current=2&pageSize=100"), &token).await;
            let total = if path == "/api/users" { 150 } else { 149 };
            assert_eq!(p1["total"], total);
            assert_eq!(p2["total"], total);
            assert_eq!(p1["data"].as_array().unwrap().len(), 100);
            assert_eq!(p2["data"].as_array().unwrap().len(), total - 100);
            let p3 = get(&t.app, &format!("{path}?current=3&pageSize=100"), &token).await;
            assert_eq!(p3["data"], json!([]));
        }
        let first = get(&t.app, "/api/peers?current=1&pageSize=100", &token).await;
        let second = get(&t.app, "/api/peers?current=2&pageSize=100", &token).await;
        assert_eq!(ids(&first)[99], "099");
        assert_eq!(ids(&second)[0], "100");
    }

    #[tokio::test]
    async fn device_groups_empty_and_auth() {
        let t = testutil::app().await;
        let (uid, token) = testutil::create_user(&t.state.db, "dg", "pw", false).await;
        let (status, ct, body) =
            send(&t.app, "GET", "/api/device-group/accessible?current=1&pageSize=100", Some(&token), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json; charset=utf-8");
        assert_eq!(&body[..], br#"{"total":0,"data":[]}"#);

        for path in ["/api/users", "/api/peers", "/api/device-group/accessible"] {
            for bad in [None, Some("nope")] {
                let (status, _, body) = send(&t.app, "GET", path, bad, "").await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
                assert_eq!(&body[..], br#"{"error":"Unauthorized"}"#);
            }
        }
        sqlx::query("update user set status = 0 where id = ?")
            .bind(uid)
            .execute(&t.state.db)
            .await
            .unwrap();
        for path in ["/api/users", "/api/peers", "/api/device-group/accessible"] {
            let (status, _, _) = send(&t.app, "GET", path, Some(&token), "").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        }
    }
}
