//! Address book, the 12 endpoints of the new protocol (PORTA.md §12; note 04).
//! Writes succeed with 200 + empty body only; `personal`, `settings`, `shared/profiles` never 404.

use super::{ok_empty, ok_json, parse_json, ApiError, ApiResult, CurrentUser, PageQuery};
use crate::state::AppState;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde_derive::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::{SqliteConnection, SqlitePool};

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

/// `POST /api/ab/settings`: `{"max_peer_one_ab": 0}`.
pub(crate) async fn settings(State(_state): State<AppState>, _user: CurrentUser) -> ApiResult {
    Ok(ok_json(&serde_json::json!({ "max_peer_one_ab": 0 })))
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
    let mut data = Vec::with_capacity(rows.len());
    for (id, fields, tags, secret) in rows {
        let mut peer: Map<String, Value> = serde_json::from_str(&fields).map_err(ApiError::internal)?;
        peer.insert("id".to_owned(), Value::String(id));
        peer.insert("tags".to_owned(), serde_json::from_str(&tags).map_err(ApiError::internal)?);
        if !secret.is_empty() {
            peer.insert(secret_key.to_owned(), Value::String(state.secret.decrypt(&secret)?));
        }
        data.push(Value::Object(peer));
    }
    Ok(ok_json(&serde_json::json!({ "total": total, "data": data })))
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
            "tags" => fields.tags = Some(serde_json::from_value(value).map_err(|_| bad())?),
            "hash" | "password" => {
                if key == secret_key {
                    fields.secret = Some(value.as_str().ok_or_else(bad)?.to_owned());
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
    Ok(fields)
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
    let secret = state.secret.encrypt(fields.secret.as_deref().unwrap_or_default());
    let (hash, password) = if personal { (secret, String::new()) } else { (String::new(), secret) };
    let now = crate::common::now() as i64;
    sqlx::query(
        "insert into ab_peer(ab_guid, id, data, tags, hash_enc, password_enc, created_at, updated_at)
         values(?, ?, ?, ?, ?, ?, ?, ?) on conflict do nothing",
    )
    .bind(&guid)
    .bind(&fields.id)
    .bind(Value::Object(fields.data).to_string())
    .bind(serde_json::json!(fields.tags.unwrap_or_default()).to_string())
    .bind(hash)
    .bind(password)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;
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
    let secret = fields.secret.map(|s| state.secret.encrypt(&s));
    let (hash, password) = if personal { (secret, None) } else { (None, secret) };
    sqlx::query(
        "update ab_peer set data = ?, tags = coalesce(?, tags), hash_enc = coalesce(?, hash_enc),
         password_enc = coalesce(?, password_enc) where ab_guid = ? and id = ?",
    )
    .bind(Value::Object(data).to_string())
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
    let ids: Vec<String> = parse_json(&body)?;
    // One statement, so all of them go in one transaction.
    sqlx::query("delete from ab_peer where ab_guid = ? and id in (select value from json_each(?))")
        .bind(&guid)
        .bind(serde_json::json!(ids).to_string())
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
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
    sqlx::query("insert into ab_tag(ab_guid, name, color) values(?, ?, ?) on conflict do nothing")
        .bind(&guid)
        .bind(&tag.name)
        .bind(tag.color)
        .execute(&state.db)
        .await?;
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
    cascade_tags(&mut tx, &guid, &[old.clone()], |t| Some(if t == old { new.clone() } else { t })).await?;
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
    let mut tx = state.db.begin().await?;
    sqlx::query("delete from ab_tag where ab_guid = ? and name in (select value from json_each(?))")
        .bind(&guid)
        .bind(serde_json::json!(names).to_string())
        .execute(&mut *tx)
        .await?;
    cascade_tags(&mut tx, &guid, &names, |t| (!names.contains(&t)).then_some(t)).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

/// Rewrites the `tags` of every peer in the book that carries one of `names`: `map` gives each
/// tag's replacement (None = drop it); duplicates are removed, keeping the first occurrence.
/// Runs inside the caller's transaction, after its first write.
async fn cascade_tags(
    conn: &mut SqliteConnection,
    guid: &str,
    names: &[String],
    map: impl Fn(String) -> Option<String>,
) -> Result<(), ApiError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "select id, tags from ab_peer where ab_guid = ?
         and exists (select 1 from json_each(tags) where value in (select value from json_each(?)))",
    )
    .bind(guid)
    .bind(serde_json::json!(names).to_string())
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
        assert_eq!(&body[..], br#"{"max_peer_one_ab":0}"#);
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
}
