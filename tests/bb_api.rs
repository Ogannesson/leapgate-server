//! 黑盒测试：账号、组面板、设备上报、审计（PORTA.md §9.1~§9.3、§10、§11、§12.3；笔记 01、03）。
//! 每个测试起一个真实的 porta-server 进程（见 `bb_api_support`），只看 HTTP 响应和数据库，不看实现。

mod bb_api_support;

use bb_api_support::*;
use hbb_common::tokio;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// 组面板三个接口客户端发的 query（笔记 03 §3.3、§3.4）。
const USERS_Q: &str = "/api/users?current=1&pageSize=100&accessible=&status=1";
const PEERS_Q: &str = "/api/peers?current=1&pageSize=100&accessible=&status=1";
const DG_Q: &str = "/api/device-group/accessible?current=1&pageSize=100";

/// 列表接口：`total` 必须是 JSON 整数、`data` 是数组（§9.1.6，笔记 03 §3.1）。返回 (total, data)。
fn list_of(r: &Resp) -> (i64, Vec<Value>) {
    assert_eq!(r.status, 200, "list: {:?}", r.text());
    r.assert_json_ct();
    let v = r.json();
    assert_no_null(&v, "list");
    let total = v.get("total").unwrap_or_else(|| panic!("list without total: {v}"));
    assert!(total.is_i64() || total.is_u64(), "total must be a JSON integer: {v}");
    let data = v.get("data").and_then(Value::as_array).unwrap_or_else(|| panic!("data must be an array: {v}"));
    (total.as_i64().unwrap(), data.clone())
}

/// 按客户端的分页循环把一个列表拉全（笔记 03 §3.1：total 只取第一页，`while current*pageSize < total`）。
async fn pull_all(s: &Server, path: &str, token: &str) -> Vec<Value> {
    let mut all = Vec::new();
    let mut total = 0;
    let mut current = 0;
    loop {
        current += 1;
        let r = s.get(&format!("{path}?current={current}&pageSize=100&accessible=&status=1"), Some(token)).await;
        let (t, data) = list_of(&r);
        if total == 0 {
            total = t;
        }
        all.extend(data);
        if current * 100 >= total {
            break;
        }
    }
    all
}

fn names(users: &[Value]) -> BTreeSet<String> {
    users.iter().map(|u| u["name"].as_str().unwrap_or_else(|| panic!("name not string: {u}")).to_owned()).collect()
}

fn ids(peers: &[Value]) -> BTreeSet<String> {
    peers.iter().map(|p| p["id"].as_str().unwrap_or_else(|| panic!("id not string: {p}")).to_owned()).collect()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn opts(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// 下发的 `strategy.config_options`；值必须全是字符串（笔记 01 §2.1 第 4 条，否则客户端整个丢弃）。
fn config_options(v: &Value) -> BTreeMap<String, String> {
    let co = v
        .get("strategy")
        .and_then(|s| s.get("config_options"))
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("no strategy.config_options in {v}"));
    co.iter()
        .map(|(k, x)| (k.clone(), x.as_str().unwrap_or_else(|| panic!("config_options.{k} is not a string: {v}")).to_owned()))
        .collect()
}

/// 下发的 `modified_at`：必须是 JSON 整数（§10 编码），且 ≥1（笔记 01 §2.2）。
fn modified_at(v: &Value) -> i64 {
    let m = v.get("modified_at").unwrap_or_else(|| panic!("no modified_at in {v}"));
    assert!(m.is_i64(), "modified_at must be a JSON integer: {v}");
    let m = m.as_i64().unwrap();
    assert!(m >= 1, "modified_at must be >= 1: {v}");
    m
}

/// 心跳响应：200、JSON、没有 null；返回解析后的对象。
fn hb_json(r: &Resp) -> Value {
    r.assert_not_5xx("heartbeat");
    r.assert_json_ct();
    let v = r.json();
    assert!(v.is_object(), "heartbeat must answer a JSON object: {v}");
    assert_no_null(&v, "heartbeat");
    v
}

/// 审计成功：200 + 空 body（§9.1.8，笔记 03 §5.1）。
fn assert_audit_ok(r: &Resp, what: &str) {
    assert_eq!(r.status, 200, "{what}: {:?}", r.text());
    assert!(r.body.is_empty(), "{what}: audit success must have an empty body, got {:?}", r.text());
}

// ===================== 进程管理与请求发送的自检 =====================

/// 自检（§9.4、§5）：API 监听在 P-2；`GET /` 回 HTML 说明页，含服务名 Porta 和 DB-IP 署名链接。
/// 这条不依赖任何并行模块，用来证明进程管理和请求发送本身是对的。
#[tokio::test]
async fn harness_index_page() {
    let s = Server::start().await;
    assert!(s.api.ends_with(&format!(":{}", s.port - 2)));
    let r = s.get("/", None).await;
    assert_eq!(r.status, 200);
    assert!(norm_ct(&r.ct).starts_with("text/html"), "ct {}", r.ct);
    let body = r.text();
    assert!(body.contains("Porta") && body.contains("https://db-ip.com"), "{body}");
    // 库已迁移：迁移种下的全局 relay-server 墓碑在（§4.2）；顺带验证读库辅助函数。
    let rows = s.rows("select scope, key, value, 7 as n, null as z from strategy_option").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(get_str(&rows[0], "key"), "relay-server");
    assert_eq!(get_str(&rows[0], "value"), "");
    assert_eq!(get_i64(&rows[0], "n"), 7);
    assert!(rows[0]["z"].is_null());
    // 造内部错误用的"运行中改表名再改回"不影响服务继续工作。
    s.exec("alter table audit_conn rename to audit_conn_hidden").await;
    s.exec("alter table audit_conn_hidden rename to audit_conn").await;
    assert_eq!(s.get("/", None).await.status, 200);
    // 造数据的辅助函数能写进服务的库。
    let uid = s.create_user("alice", "pw", false).await;
    let token = s.issue_token(uid).await;
    assert_eq!(s.scalar_i64(&format!("select count(*) from token where token_hash = '{}'", sha256_hex(&token))).await, 1);
}

/// 自检：经 UDP 发 `RegisterPk`（上游 hbbs 的注册路径）后，peer 表里有这台设备、uuid 是原始字节。
/// 组面板在线状态的测试依赖这一步。
#[tokio::test]
async fn harness_udp_register() {
    let s = Server::start().await;
    let raw = random_uuid_bytes();
    s.register_online("900000001", &raw).await;
    let stored: Vec<u8> = sqlx::query_scalar("select uuid from peer where id = '900000001'").fetch_one(&s.db).await.unwrap();
    assert_eq!(stored, raw);
}

/// 自检（§9.4）：未知路径回 404，带 JSON 错误体，不是 5xx。
#[tokio::test]
async fn harness_unknown_path_404() {
    let s = Server::start().await;
    let r = s.get("/api/nope", None).await;
    assert_eq!(r.status, 404);
    r.assert_error_body();
    // 经本机非回环地址也连得上（心跳测试用它验证"TCP 对端不是回环时不信转发头"）。
    if let Some(ip) = non_loopback_ip() {
        let base = format!("http://{}", std::net::SocketAddr::new(ip, s.port - 2));
        assert_eq!(s.request_to(&base, "GET", "/api/nope", None, None, &[]).await.status, 404);
    }
}

// ===================== §9.1 通则 =====================

/// §9.1.4：`/api/login-options` 回 `[]`（JSON 数组，不是 `["common-oidc/null"]`），带 charset=utf-8。
/// 笔记 03 §1.7：Rust 侧会发 HEAD 做 TLS 探测，只要能连上、不回 5xx。
#[tokio::test]
async fn login_options_is_empty_array() {
    let s = Server::start().await;
    // Dart 通路默认带 Content-Type: application/json，无 body。
    let r = s.request("GET", "/api/login-options", None, None, &[("Content-Type", "application/json")]).await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    r.assert_json_ct();
    assert_eq!(r.json(), json!([]));
    let r = s.request("HEAD", "/api/login-options", None, None, &[]).await;
    r.assert_not_5xx("HEAD /api/login-options");
}

/// §9.1.1、§9.1.2、§9.1.10：所有本组接口收到坏 body / 类型错的字段 / 坏 query 都不回 5xx；
/// 回 JSON 的必须带 charset=utf-8 且能解析；回 4xx 时是 `{"error": 字符串}`（axum Json 提取器的纯文本错误不行）。
#[tokio::test]
async fn no_5xx_on_bad_input() {
    let s = Server::start().await;
    let uid = s.create_user("alice", "pw", false).await;
    let token = s.issue_token(uid).await;
    let bad_bodies = [
        "",
        "not json",
        "null",
        "[]",
        "{}",
        r#"{"id":123,"uuid":5,"conn_id":"x","session_id":-1,"modified_at":"7","ver":"x","username":1,"password":[]}"#,
        r#"{"id":"123456789","uuid":"!!!not base64!!!","conn_id":1,"session_id":1e30,"note":7}"#,
    ];
    let posts = [
        "/api/login",
        "/api/currentUser",
        "/api/logout",
        "/api/sysinfo",
        "/api/heartbeat",
        "/api/audit/conn",
        "/api/audit/file",
        "/api/audit/alarm",
    ];
    for path in posts {
        for body in bad_bodies {
            // logout 会吊销令牌，每次换一个新的。
            let t = s.issue_token(uid).await;
            let r = s.post(path, Some(&t), body).await;
            r.assert_not_5xx(&format!("POST {path} {body:?}"));
            // §9.1.2：sysinfo 的 403 是空 body（uuid 不符），其余 4xx 都要 `{"error"}`。
            let sysinfo_403 = path == "/api/sysinfo" && r.status == 403 && r.body.is_empty();
            if (400..500).contains(&r.status) && !sysinfo_403 {
                r.assert_error_body();
            }
            if !r.body.is_empty() && norm_ct(&r.ct).starts_with("application/json") {
                r.assert_json_ct();
                assert_no_null(&r.json(), path);
            }
        }
    }
    for path in ["/api/users", "/api/peers", "/api/device-group/accessible", "/api/login-options"] {
        for q in ["", "?current=abc&pageSize=-5", "?current=0&pageSize=0", "?current=99999999999999999999&pageSize=1"] {
            let r = s.get(&format!("{path}{q}"), Some(&token)).await;
            r.assert_not_5xx(&format!("GET {path}{q}"));
            if r.status == 200 && path != "/api/login-options" {
                list_of(&r);
            }
        }
    }
}

/// §9.1.3、§11：令牌缺失、无效、账号禁用 → 401 + JSON 错误体（客户端据此清登录态，笔记 03 §1.5）。
/// logout 按笔记 03 §2.4 令牌无效时 200 或 401 都行。
#[tokio::test]
async fn invalid_token_is_401() {
    let s = Server::start().await;
    let uid = s.create_user("alice", "pw", false).await;
    let disabled_token = s.issue_token(uid).await;
    s.exec(&format!("update user set status = 0 where id = {uid}")).await;
    let bad: [Option<&str>; 3] = [None, Some("definitely-not-a-token"), Some(&disabled_token)];
    for token in bad {
        let r = s.post("/api/currentUser", token, r#"{"id":"123456789","uuid":"dXVpZA=="}"#).await;
        assert_eq!(r.status, 401, "currentUser {token:?}: {:?}", r.text());
        r.assert_error_body();
        for path in [USERS_Q, PEERS_Q, DG_Q] {
            let r = s.get(path, token).await;
            assert_eq!(r.status, 401, "{path} {token:?}: {:?}", r.text());
            r.assert_error_body();
        }
        let r = s.post("/api/logout", token, r#"{"id":"123456789","uuid":"dXVpZA=="}"#).await;
        assert!(r.status == 200 || r.status == 401, "logout {token:?}: {} {:?}", r.status, r.text());
    }
    // 令牌被删掉（登出、改密码）之后同样是 401。
    let uid2 = s.create_user("bob", "pw", false).await;
    let t2 = s.issue_token(uid2).await;
    s.exec(&format!("delete from token where user_id = {uid2}")).await;
    let r = s.post("/api/currentUser", Some(&t2), "{}").await;
    assert_eq!(r.status, 401);
}

// ===================== §9.2 / §11 账号 =====================

/// §9.1.5、§11、笔记 03 §2.2：登录成功回 `{"type":"access_token","access_token":…,"user":UserPayload}`；
/// 令牌是 32 字节随机数的 base64url（43 字符），库里只存 sha256 hex，并记下请求里的设备 id/uuid。
#[tokio::test]
async fn login_success_shape_and_token_row() {
    let s = Server::start().await;
    s.create_user("alice", "s3cret", false).await;
    s.create_user("root", "rootpw", true).await;
    let uuid = b64(&random_uuid_bytes());
    let r = s.login("alice", "s3cret", "123456789", &uuid).await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    r.assert_json_ct();
    let v = r.json();
    assert_no_null(&v, "login");
    assert_eq!(v["type"], "access_token");
    let token = v["access_token"].as_str().expect("access_token string");
    assert_eq!(token.len(), 43, "token: {token}");
    assert!(token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "token: {token}");
    check_user_payload(&v["user"], "alice", false);

    let rows = s
        .rows(&format!(
            "select t.device_id, t.device_uuid, u.name from token t join user u on u.id = t.user_id where t.token_hash = '{}'",
            sha256_hex(token)
        ))
        .await;
    assert_eq!(rows.len(), 1, "token row by sha256(token)");
    assert_eq!(get_str(&rows[0], "device_id"), "123456789");
    assert_eq!(get_str(&rows[0], "device_uuid"), uuid);
    assert_eq!(get_str(&rows[0], "name"), "alice");
    // 明文令牌不进库。
    assert_eq!(s.scalar_i64(&format!("select count(*) from token where token_hash = '{token}'")).await, 0);

    // 拿到的令牌能用。
    let r = s.post("/api/currentUser", Some(token), &json!({"id": "123456789", "uuid": uuid}).to_string()).await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    check_user_payload(&r.json(), "alice", false);

    // 管理员的 is_admin 为 true。
    let r = s.login("root", "rootpw", "222222222", &uuid).await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    check_user_payload(&r.json()["user"], "root", true);
}

/// §4.2（name 一律按字符串绑定和读取）、§9.1.10：纯数字的用户名在 login / currentUser / users 里都是 JSON 字符串。
#[tokio::test]
async fn numeric_user_name_stays_string() {
    let s = Server::start().await;
    s.create_user("10086", "pw", false).await;
    let token = s.login_ok("10086", "pw", "123456789", &b64(b"u")).await;
    let r = s.post("/api/currentUser", Some(&token), "{}").await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    check_user_payload(&r.json(), "10086", false);
    let (_, data) = list_of(&s.get(USERS_Q, Some(&token)).await);
    assert_eq!(data.len(), 1);
    check_user_payload(&data[0], "10086", false);
}

/// §11、笔记 03 §2.2：用户名或密码错、账号禁用（status≠1）、`password_hash=''` 的账号都登录失败：
/// 不回 5xx，回 `{"error": 字符串}`，不发令牌、不写令牌行。
#[tokio::test]
async fn login_failures() {
    let s = Server::start().await;
    s.create_user("alice", "right", false).await;
    s.create_user_hash("disabled", &argon2_hash("pw"), false, 0).await;
    s.create_user("nopass", "", false).await;
    let uuid = b64(b"some-uuid");
    for (user, pw) in [("alice", "wrong"), ("ghost", "whatever"), ("disabled", "pw"), ("nopass", ""), ("nopass", "x")] {
        let r = s.login(user, pw, "123456789", &uuid).await;
        r.assert_not_5xx(&format!("login {user}"));
        r.assert_error_body();
        assert!(r.json().get("access_token").is_none(), "login {user}/{pw} must not issue a token: {:?}", r.text());
    }
    assert_eq!(s.count("token").await, 0);
}

/// §11：rustdesk-api 导入的 bcrypt（`$2a$/$2b$/$2y$`）和 `md5:<hex>`（md5(明文+"rustdesk-api")）能登录，
/// 校验通过后当场改存 argon2id；错误密码不改存。
#[tokio::test]
async fn login_upgrades_legacy_hashes() {
    use md5::{Digest as _, Md5};
    let s = Server::start().await;
    let bc = bcrypt::hash("pw-b", 4).unwrap();
    let bc_2a = format!("$2a${}", &bc[4..]);
    let md5_hex: String = Md5::digest(b"pw-mrustdesk-api").iter().map(|b| format!("{b:02x}")).collect();
    let b_id = s.create_user_hash("legacy-b", &bc, false, 1).await;
    let a_id = s.create_user_hash("legacy-2a", &bc_2a, false, 1).await;
    let m_id = s.create_user_hash("legacy-m", &format!("md5:{md5_hex}"), false, 1).await;
    let hash_of = |id: i64| format!("select password_hash as h from user where id = {id}");

    // 错误密码：失败、不改存。
    let r = s.login("legacy-m", "nope", "123456789", &b64(b"u")).await;
    r.assert_error_body();
    assert_eq!(get_str(&s.rows(&hash_of(m_id)).await[0], "h"), format!("md5:{md5_hex}"));

    for (name, pw, id) in [("legacy-b", "pw-b", b_id), ("legacy-2a", "pw-b", a_id), ("legacy-m", "pw-m", m_id)] {
        let r = s.login(name, pw, "123456789", &b64(b"u")).await;
        assert_eq!(r.status, 200, "{name}: {:?}", r.text());
        check_user_payload(&r.json()["user"], name, false);
        let h = get_str(&s.rows(&hash_of(id)).await[0], "h").to_owned();
        assert!(h.starts_with("$argon2id$"), "{name} not upgraded: {h}");
        // 改存后还能用同一个密码登录。
        s.login_ok(name, pw, "123456789", &b64(b"u")).await;
    }
}

/// §11：登录失败只按用户名限流：15 分钟内失败 5 次后，第 6 次即使密码正确也直接拒绝（`{"error"}`、不发令牌）；
/// 别的用户名不受影响（不按来源 IP 限）。
#[tokio::test]
async fn login_rate_limit_by_username() {
    let s = Server::start().await;
    s.create_user("alice", "right", false).await;
    s.create_user("bob", "right", false).await;
    let uuid = b64(b"u");
    for i in 0..5 {
        let r = s.login("alice", "wrong", "123456789", &uuid).await;
        r.assert_not_5xx("login wrong");
        r.assert_error_body();
        assert!(r.json().get("access_token").is_none(), "attempt {i}");
    }
    let r = s.login("alice", "right", "123456789", &uuid).await;
    r.assert_not_5xx("login locked");
    r.assert_error_body();
    assert!(r.json().get("access_token").is_none(), "locked account must not log in: {:?}", r.text());
    // 同一来源 IP 的其他用户名照常。
    s.login_ok("bob", "right", "123456789", &uuid).await;
}

/// §11 设备归属（弱校验同 §9.3）：peer 表里没有这个 id → device.user_id 设成登录用户（设备行不存在就建）；
/// peer 表里有且 uuid 相符 → 同样设上；uuid 不符 → 登录照常成功，但不改 device.user_id。
#[tokio::test]
async fn login_binds_device_with_weak_check() {
    let s = Server::start().await;
    let alice = s.create_user("alice", "pw", false).await;
    let bob = s.create_user("bob", "pw", false).await;
    let raw = random_uuid_bytes();

    // peer 表里没有：建设备行并归给 alice。
    s.login_ok("alice", "pw", "100000001", &b64(&raw)).await;
    assert_eq!(s.device_user("100000001").await, Some(Some(alice)));

    // peer 表里有、uuid 相符。
    s.insert_peer("100000002", &raw).await;
    s.login_ok("alice", "pw", "100000002", &b64(&raw)).await;
    assert_eq!(s.device_user("100000002").await, Some(Some(alice)));

    // peer 表里有、uuid 不符：登录成功，但设备仍归 bob；令牌行照样记下请求里的 id/uuid。
    s.insert_peer("100000003", &raw).await;
    s.insert_device("100000003", Some(bob), "bob-pc", "bob", "windows").await;
    let forged = b64(b"someone-else");
    let token = s.login_ok("alice", "pw", "100000003", &forged).await;
    assert_eq!(s.device_user("100000003").await, Some(Some(bob)));
    let row = &s.rows(&format!("select device_id, device_uuid from token where token_hash = '{}'", sha256_hex(&token))).await[0];
    assert_eq!(get_str(row, "device_id"), "100000003");
    assert_eq!(get_str(row, "device_uuid"), forged);

    // peer 表里有、uuid 不符、设备行不存在：不建出归 alice 的设备。
    s.insert_peer("100000004", &raw).await;
    s.login_ok("alice", "pw", "100000004", &forged).await;
    assert_ne!(s.device_user("100000004").await, Some(Some(alice)));
}

/// §9.2、§11：currentUser 忽略请求体（缺字段、解析失败、空 body 都回 200 + UserPayload），每次使用更新 last_used_at。
#[tokio::test]
async fn current_user_ignores_body_and_touches_token() {
    let s = Server::start().await;
    let uid = s.create_user("alice", "pw", false).await;
    let token = s.issue_token(uid).await;
    s.exec("update token set last_used_at = 0").await;
    for body in ["", "garbage", "{}", "[]", r#"{"id":1}"#, r#"{"id":"123456789","uuid":"dXVpZA=="}"#] {
        let r = s.post("/api/currentUser", Some(&token), body).await;
        assert_eq!(r.status, 200, "body {body:?}: {:?}", r.text());
        r.assert_json_ct();
        check_user_payload(&r.json(), "alice", false);
    }
    assert!(s.scalar_i64("select last_used_at from token").await > 0, "last_used_at not updated");
}

/// §9.1.1、§9.2：currentUser 的内部错误回 200 + `{"error"}`（400 会让客户端清令牌、401 会全部重置）。
/// 造法：运行中把 token 表改名让查库失败，再改回来；改回后同一个令牌照常可用（没有因为临时错误被吊销）。
#[tokio::test]
async fn current_user_internal_error_is_200_error() {
    let s = Server::start().await;
    let uid = s.create_user("alice", "pw", false).await;
    let token = s.issue_token(uid).await;
    s.exec("alter table token rename to token_hidden").await;
    let r = s.post("/api/currentUser", Some(&token), "{}").await;
    s.exec("alter table token_hidden rename to token").await;
    assert_eq!(r.status, 200, "internal error must be 200: {:?}", r.text());
    r.assert_error_body();
    let r = s.post("/api/currentUser", Some(&token), "{}").await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    check_user_payload(&r.json(), "alice", false);
}

/// §11、笔记 03 §2.4：logout 只删当前这个令牌（同一用户的其他令牌照常可用）；
/// 若 device.user_id 是本人则清空，是别人则不动。
#[tokio::test]
async fn logout_revokes_only_current_token_and_unbinds_device() {
    let s = Server::start().await;
    let alice = s.create_user("alice", "pw", false).await;
    let bob = s.create_user("bob", "pw", false).await;
    let uuid = b64(&random_uuid_bytes());
    let body = json!({"id": "200000001", "uuid": uuid}).to_string();

    let t1 = s.login_ok("alice", "pw", "200000001", &uuid).await;
    let t2 = s.login_ok("alice", "pw", "200000001", &uuid).await;
    assert_eq!(s.device_user("200000001").await, Some(Some(alice)));

    let r = s.post("/api/logout", Some(&t1), &body).await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    assert_eq!(s.scalar_i64(&format!("select count(*) from token where token_hash = '{}'", sha256_hex(&t1))).await, 0);
    assert_eq!(s.post("/api/currentUser", Some(&t1), &body).await.status, 401);
    let r = s.post("/api/currentUser", Some(&t2), &body).await;
    assert_eq!(r.status, 200, "other token must survive: {:?}", r.text());
    assert_eq!(s.device_user("200000001").await, Some(None), "device bound to alice must be cleared on logout");

    // 设备已经归 bob：alice 登出不动它。
    let t3 = s.login_ok("alice", "pw", "200000002", &uuid).await;
    s.exec(&format!("update device set user_id = {bob} where id = '200000002'")).await;
    let r = s.post("/api/logout", Some(&t3), &json!({"id": "200000002", "uuid": uuid}).to_string()).await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    assert_eq!(s.device_user("200000002").await, Some(Some(bob)));
}

// ===================== §12.3 组面板 =====================

/// §12.3：普通用户看到自己 + 和自己同在任一 share_devices=1 组里的用户（不传递）；share_devices=0 的组不算；
/// 管理员看到全部用户。列表 total 是整数，每项是合法 UserPayload；当前用户总在列表里（笔记 03 §3.3）。
#[tokio::test]
async fn group_panel_users_visibility() {
    let s = Server::start().await;
    let root = s.create_user("root", "pw", true).await;
    let alice = s.create_user("alice", "pw", false).await;
    let bob = s.create_user("bob", "pw", false).await;
    let carol = s.create_user("carol", "pw", false).await;
    let dave = s.create_user("dave", "pw", false).await;
    let g1 = s.create_group("g1-share", true).await;
    let g2 = s.create_group("g2-noshare", false).await;
    let g3 = s.create_group("g3-share", true).await;
    for (g, u) in [(g1, alice), (g1, bob), (g2, alice), (g2, carol), (g3, bob), (g3, dave)] {
        s.add_member(g, u).await;
    }
    let cases = [
        (root, set(&["root", "alice", "bob", "carol", "dave"])),
        (alice, set(&["alice", "bob"])),
        (bob, set(&["alice", "bob", "dave"])),
        (carol, set(&["carol"])),
        (dave, set(&["bob", "dave"])),
    ];
    for (uid, expect) in cases.iter() {
        let token = s.issue_token(*uid).await;
        let r = s.get(USERS_Q, Some(&token)).await;
        let (total, data) = list_of(&r);
        assert_eq!(names(&data), *expect, "users visible to user {uid}");
        assert_eq!(total, expect.len() as i64);
        for u in &data {
            let name = u["name"].as_str().unwrap();
            check_user_payload(u, name, name == "root");
        }
    }
    // 成员变动立即生效（§12.2）。
    s.exec(&format!("delete from group_member where group_id = {g1} and user_id = {bob}")).await;
    let token = s.issue_token(alice).await;
    assert_eq!(names(&list_of(&s.get(USERS_Q, Some(&token)).await).1), set(&["alice"]));
}

/// §12.3、笔记 03 §3.4：设备是可见用户名下（device.user_id）的；管理员看到全部设备（含无主设备）。
/// 每项字段：`id` 字符串、`info.{username,os,device_name}` 来自 sysinfo 拆出的字段、`user_name` 是属主 name；
/// 纯数字的主机名、系统用户名、属主名都保持字符串。
#[tokio::test]
async fn group_panel_peers_visibility_and_fields() {
    let s = Server::start().await;
    let root = s.create_user("root", "pw", true).await;
    let alice = s.create_user("alice", "pw", false).await;
    let bob = s.create_user("12345", "pw", false).await;
    let carol = s.create_user("carol", "pw", false).await;
    let g = s.create_group("friends", true).await;
    s.add_member(g, alice).await;
    s.add_member(g, bob).await;
    s.insert_device("300000001", Some(alice), "alice-pc", "alice", "windows / Windows 11 Pro - 10.0.26100").await;
    s.insert_device("300000002", Some(bob), "10086", "007", "linux / Ubuntu 24.04").await;
    s.insert_device("300000003", Some(carol), "carol-pc", "carol", "macos / 14.0").await;
    s.insert_device("300000004", None, "orphan", "x", "windows / 10").await;

    let ta = s.issue_token(alice).await;
    let (total, data) = list_of(&s.get(PEERS_Q, Some(&ta)).await);
    assert_eq!(ids(&data), set(&["300000001", "300000002"]));
    assert_eq!(total, 2);
    for p in &data {
        let info = p.get("info").and_then(Value::as_object).unwrap_or_else(|| panic!("info must be an object: {p}"));
        let (host, user, os, owner) = match p["id"].as_str().unwrap() {
            "300000001" => ("alice-pc", "alice", "windows / Windows 11 Pro - 10.0.26100", "alice"),
            _ => ("10086", "007", "linux / Ubuntu 24.04", "12345"),
        };
        assert_eq!(info.get("device_name").and_then(Value::as_str), Some(host), "{p}");
        assert_eq!(info.get("username").and_then(Value::as_str), Some(user), "{p}");
        assert_eq!(info.get("os").and_then(Value::as_str), Some(os), "{p}");
        assert_eq!(p.get("user_name").and_then(Value::as_str), Some(owner), "{p}");
        for k in ["user", "note", "device_group_name"] {
            if let Some(x) = p.get(k) {
                assert!(x.is_string(), "{k} must be a string: {p}");
            }
        }
        if let Some(st) = p.get("status") {
            assert!(st.is_i64(), "status must be an integer: {p}");
        }
    }

    let tc = s.issue_token(carol).await;
    assert_eq!(ids(&list_of(&s.get(PEERS_Q, Some(&tc)).await).1), set(&["300000003"]));

    let tr = s.issue_token(root).await;
    let (total, data) = list_of(&s.get(PEERS_Q, Some(&tr)).await);
    assert_eq!(ids(&data), set(&["300000001", "300000002", "300000003", "300000004"]));
    assert_eq!(total, 4);
}

/// §12.3：`status`（在线）按 PeerMap 的内存在线判定：经 UDP 注册过的设备为 1，没注册的为 0；字段是整数。
#[tokio::test]
async fn group_panel_peer_online_status() {
    let s = Server::start().await;
    let alice = s.create_user("alice", "pw", false).await;
    let raw = random_uuid_bytes();
    s.register_online("400000001", &raw).await;
    s.insert_device("400000001", Some(alice), "on-pc", "alice", "windows / 11").await;
    s.insert_device("400000002", Some(alice), "off-pc", "alice", "windows / 11").await;
    let t = s.issue_token(alice).await;
    let (_, data) = list_of(&s.get(PEERS_Q, Some(&t)).await);
    let status: BTreeMap<String, Value> =
        data.iter().map(|p| (p["id"].as_str().unwrap().to_owned(), p.get("status").cloned().unwrap_or(Value::Null))).collect();
    assert_eq!(status.get("400000001"), Some(&json!(1)), "{data:?}");
    assert_eq!(status.get("400000002"), Some(&json!(0)), "{data:?}");
}

/// §12.3：`/api/device-group/accessible` 回 `{"total":0,"data":[]}`。
#[tokio::test]
async fn device_group_accessible_is_empty() {
    let s = Server::start().await;
    let uid = s.create_user("alice", "pw", false).await;
    let t = s.issue_token(uid).await;
    let r = s.get(DG_Q, Some(&t)).await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    r.assert_json_ct();
    assert_eq!(r.json(), json!({"total": 0, "data": []}));
}

/// §9.1.6：分页参数 `current`、`pageSize`，不能把每页压到客户端要的条数以下；`total` 是总数（客户端只取第一页的
/// total 决定翻几页，笔记 03 §3.1）。按客户端的循环拉全，结果不重不漏。
#[tokio::test]
async fn group_panel_pagination() {
    let s = Server::start().await;
    let root = s.create_user("root", "pw", true).await;
    let mut tx = s.db.begin().await.unwrap();
    let now = now();
    for i in 0..150 {
        sqlx::query("insert into user(name, created_at, updated_at) values(?, ?, ?)")
            .bind(format!("user{i:03}"))
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    for i in 0..130 {
        sqlx::query("insert into device(id, hostname, first_seen_at, last_seen_at) values(?, ?, ?, ?)")
            .bind(format!("5{i:08}"))
            .bind(format!("host{i}"))
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let t = s.issue_token(root).await;

    let (total, page1) = list_of(&s.get(USERS_Q, Some(&t)).await);
    assert_eq!(total, 151);
    assert_eq!(page1.len(), 100, "page 1 must hold pageSize items");
    let (total2, page2) = list_of(&s.get("/api/users?current=2&pageSize=100&accessible=&status=1", Some(&t)).await);
    assert_eq!(total2, 151);
    assert_eq!(page2.len(), 51);
    let all = pull_all(&s, "/api/users", &t).await;
    assert_eq!(all.len(), 151);
    assert_eq!(names(&all).len(), 151, "users must not repeat across pages");

    let (total, page1) = list_of(&s.get(PEERS_Q, Some(&t)).await);
    assert_eq!(total, 130);
    assert_eq!(page1.len(), 100);
    let all = pull_all(&s, "/api/peers", &t).await;
    assert_eq!(all.len(), 130);
    assert_eq!(ids(&all).len(), 130, "peers must not repeat across pages");
}

// ===================== §9.3 / §10 sysinfo =====================

/// §9.1.7、§10：sysinfo 成功回纯文本 `SYSINFO_UPDATED`（逐字节，无换行无引号）、`text/plain; charset=utf-8`；
/// peer 表里没有这个 id 也照常接受（不回 ID_NOT_FOUND）；存原文，拆出 hostname/username/os/version，
/// uuid 存上报里的 base64，client_type 一律 rustdesk；未知字段（preset-*、以后 Porta 的键）照收。
#[tokio::test]
async fn sysinfo_stores_and_answers_exactly() {
    let s = Server::start().await;
    let uuid = b64(&random_uuid_bytes());
    let mut body = sysinfo_body("600000001", &uuid);
    body["preset-address-book-name"] = json!("team");
    body["porta"] = json!({"ver": "0.1.0", "proto": 1});
    let r = s.post_json("/api/sysinfo", None, &body).await;
    assert_eq!(r.status, 200, "{:?}", r.text());
    assert_eq!(r.body, b"SYSINFO_UPDATED".to_vec(), "body must be exactly SYSINFO_UPDATED, got {:?}", r.text());
    assert_eq!(norm_ct(&r.ct), "text/plain;charset=utf-8");

    let rows = s.rows("select * from device where id = '600000001'").await;
    assert_eq!(rows.len(), 1, "device row must be created");
    let d = &rows[0];
    assert_eq!(get_str(d, "hostname"), "desk-01");
    assert_eq!(get_str(d, "username"), "alice");
    assert_eq!(get_str(d, "os"), "windows / Windows 11 Pro - 10.0.26100");
    assert_eq!(get_str(d, "version"), "1.4.3");
    assert_eq!(get_str(d, "uuid"), uuid);
    assert_eq!(get_str(d, "client_type"), "rustdesk");
    let stored: Value = serde_json::from_str(get_str(d, "sysinfo")).expect("device.sysinfo must hold the original JSON");
    assert_eq!(stored, body);

    // 再传一次（比如用户名变了、缺 username 键）：照样 SYSINFO_UPDATED，字段跟着更新。
    let mut body2 = sysinfo_body("600000001", &uuid);
    body2["hostname"] = json!("desk-02");
    body2.as_object_mut().unwrap().remove("username");
    let r = s.post_json("/api/sysinfo", None, &body2).await;
    assert_eq!(r.body, b"SYSINFO_UPDATED".to_vec(), "{:?}", r.text());
    let d = &s.rows("select * from device where id = '600000001'").await[0];
    assert_eq!(get_str(d, "hostname"), "desk-02");
    assert_eq!(serde_json::from_str::<Value>(get_str(d, "sysinfo")).unwrap(), body2);
}

/// §9.3：peer 表里有这个 id 时，sysinfo 必须带 uuid 且 base64 解码后与 peer.uuid 逐字节相等；
/// 不符或缺 uuid → 403 + 空 body（客户端 120 秒后重试），不写 device；相符 → SYSINFO_UPDATED。
#[tokio::test]
async fn sysinfo_uuid_weak_check() {
    let s = Server::start().await;
    let raw = random_uuid_bytes();
    s.insert_peer("600000002", &raw).await;

    let r = s.sysinfo("600000002", &b64(b"forged-uuid")).await;
    assert_eq!(r.status, 403, "{:?}", r.text());
    assert!(r.body.is_empty(), "403 must have an empty body: {:?}", r.text());
    let mut no_uuid = sysinfo_body("600000002", "");
    no_uuid.as_object_mut().unwrap().remove("uuid");
    let r = s.post_json("/api/sysinfo", None, &no_uuid).await;
    assert_eq!(r.status, 403, "{:?}", r.text());
    assert!(r.body.is_empty(), "{:?}", r.text());
    assert_eq!(s.count("device").await, 0, "rejected sysinfo must not create a device");

    let r = s.sysinfo("600000002", &b64(&raw)).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"SYSINFO_UPDATED".to_vec(), "{:?}", r.text());
    assert_eq!(s.count("device").await, 1);
}

// ===================== §10 心跳与策略 =====================

/// §10 完整时序（笔记 01 §2.2）：
/// 1. 首次心跳（modified_at=0）：同时带 `modified_at`（JSON 整数 ≥1）和 `strategy.config_options`（全部生效选项，
///    默认就是迁移种下的 `relay-server: ""`）；设备还没 sysinfo，带 `sysinfo: true`；设备行被建出来。
/// 2. 复带 rev：两者都不带；sysinfo 还没传，仍带 `sysinfo: true`。
/// 3. 上传 sysinfo 后：`sysinfo` 键完全省略（不是 false/null）。
/// 4. 改全局选项：rev 变，下发全部生效选项。
/// 5. 用 `!=` 比较：客户端带一个比服务端还大的值也要推。
#[tokio::test]
async fn heartbeat_strategy_sequence() {
    let s = Server::start().await;
    let uuid = b64(&random_uuid_bytes());
    let id = "700000001";

    let v = hb_json(&s.heartbeat(id, &uuid, 0).await);
    let rev1 = modified_at(&v);
    assert_eq!(config_options(&v), opts(&[("relay-server", "")]));
    assert_eq!(v.get("sysinfo"), Some(&json!(true)), "device without sysinfo must get sysinfo:true: {v}");
    assert!(s.device_user(id).await.is_some(), "heartbeat must create the device row");

    let v = hb_json(&s.heartbeat(id, &uuid, rev1).await);
    assert!(v.get("modified_at").is_none() && v.get("strategy").is_none(), "same rev must not resend: {v}");
    assert_eq!(v.get("sysinfo"), Some(&json!(true)), "{v}");

    let r = s.sysinfo(id, &uuid).await;
    assert_eq!(r.body, b"SYSINFO_UPDATED".to_vec(), "{:?}", r.text());
    let v = hb_json(&s.heartbeat(id, &uuid, rev1).await);
    assert_eq!(v, json!({}), "after sysinfo and with the current rev the answer is empty: {v}");

    s.set_option("*", "approve-mode", "click").await;
    let v = hb_json(&s.heartbeat(id, &uuid, rev1).await);
    let rev2 = modified_at(&v);
    assert_ne!(rev2, rev1);
    assert_eq!(config_options(&v), opts(&[("approve-mode", "click"), ("relay-server", "")]));
    assert!(v.get("sysinfo").is_none(), "{v}");
    let v = hb_json(&s.heartbeat(id, &uuid, rev2).await);
    assert_eq!(v, json!({}));

    // 客户端的值比服务端大（换过服务器、连过 Pro）：`!=` 而不是 `<`。
    let v = hb_json(&s.heartbeat(id, &uuid, rev2.checked_add(123456789).unwrap_or(rev2 - 123456789)).await);
    assert_eq!(modified_at(&v), rev2);
    assert_eq!(config_options(&v), opts(&[("approve-mode", "click"), ("relay-server", "")]));
}

/// §10：设备级覆盖全局（同键）、设备级 `''` 墓碑照样覆盖（让这台设备删键）、删掉设备级行回到全局值；
/// rev 只由（生效选项、全局 epoch、设备 epoch）决定，不是自增计数器：生效选项和 epoch 相同的两台设备 rev 相同。
/// epoch：全局 epoch 递增 → 所有设备换 rev、选项不变；设备 epoch 递增 → 只有这台换。
#[tokio::test]
async fn heartbeat_override_tombstone_epoch() {
    let s = Server::start().await;
    let (a, b) = ("700000011", "700000012");
    let (ua, ub) = (b64(&random_uuid_bytes()), b64(&random_uuid_bytes()));
    s.set_option("*", "whitelist", "1.2.3.4").await;

    let va = hb_json(&s.heartbeat(a, &ua, 0).await);
    let vb = hb_json(&s.heartbeat(b, &ub, 0).await);
    let base = modified_at(&va);
    assert_eq!(modified_at(&vb), base, "same effective options and epochs must give the same rev");
    assert_eq!(config_options(&va), opts(&[("relay-server", ""), ("whitelist", "1.2.3.4")]));

    // 设备级覆盖。
    s.set_option(a, "whitelist", "5.6.7.8").await;
    let va = hb_json(&s.heartbeat(a, &ua, base).await);
    let rev_override = modified_at(&va);
    assert_ne!(rev_override, base);
    assert_eq!(config_options(&va), opts(&[("relay-server", ""), ("whitelist", "5.6.7.8")]));
    let vb = hb_json(&s.heartbeat(b, &ub, base).await);
    assert_eq!(vb.get("strategy"), None, "other devices are unaffected: {vb}");

    // 设备级墓碑：值 '' 照样覆盖全局，下发时带着这个键（客户端删掉它）。
    s.set_option(a, "whitelist", "").await;
    let va = hb_json(&s.heartbeat(a, &ua, rev_override).await);
    let rev_tomb = modified_at(&va);
    assert_ne!(rev_tomb, rev_override);
    assert_eq!(config_options(&va), opts(&[("relay-server", ""), ("whitelist", "")]));

    // 删掉设备级行：回到全局值，rev 回到和 b 一样。
    s.forget_option(a, "whitelist").await;
    let va = hb_json(&s.heartbeat(a, &ua, rev_tomb).await);
    assert_eq!(modified_at(&va), base);
    assert_eq!(config_options(&va), opts(&[("relay-server", ""), ("whitelist", "1.2.3.4")]));

    // 设备 epoch：只有 a 换 rev，选项不变。
    s.bump_epoch(a).await;
    let va = hb_json(&s.heartbeat(a, &ua, base).await);
    let rev_dev_epoch = modified_at(&va);
    assert_ne!(rev_dev_epoch, base);
    assert_eq!(config_options(&va), opts(&[("relay-server", ""), ("whitelist", "1.2.3.4")]));
    assert_eq!(hb_json(&s.heartbeat(b, &ub, base).await).get("strategy"), None);

    // 全局 epoch：两台都换。
    s.bump_epoch("*").await;
    let va = hb_json(&s.heartbeat(a, &ua, rev_dev_epoch).await);
    let vb = hb_json(&s.heartbeat(b, &ub, base).await);
    assert_ne!(modified_at(&va), rev_dev_epoch);
    let rev_b = modified_at(&vb);
    assert_ne!(rev_b, base);
    assert_eq!(config_options(&vb), opts(&[("relay-server", ""), ("whitelist", "1.2.3.4")]));

    // 全局墓碑：把推过的键"撤销"成 ''，所有设备都收到这个空值。
    s.set_option("*", "whitelist", "").await;
    let vb = hb_json(&s.heartbeat(b, &ub, rev_b).await);
    assert_eq!(config_options(&vb), opts(&[("relay-server", ""), ("whitelist", "")]));
}

/// §10：rev 的算法和骨架共享的 `strategy::rev` 一致（设备模块和命令行 `strategy show` 用同一个版本号）：
/// sha256(规范 JSON `[按键排序的生效选项, 全局 epoch, 设备 epoch]`) 前 8 字节 → i64 & i64::MAX，0 取 1。
#[tokio::test]
async fn heartbeat_rev_matches_formula() {
    let s = Server::start().await;
    let (id, uuid) = ("700000021", b64(&random_uuid_bytes()));
    let v = hb_json(&s.heartbeat(id, &uuid, 0).await);
    assert_eq!(modified_at(&v), expected_rev(&opts(&[("relay-server", "")]), 0, 0));

    s.set_option(id, "b-key", "2").await;
    s.set_option("*", "a-key", "1").await;
    s.bump_epoch("*").await;
    s.bump_epoch("*").await;
    s.bump_epoch(id).await;
    let v = hb_json(&s.heartbeat(id, &uuid, 0).await);
    assert_eq!(
        modified_at(&v),
        expected_rev(&opts(&[("a-key", "1"), ("b-key", "2"), ("relay-server", "")]), 2, 1)
    );
}

/// §10：每次心跳更新 device.last_seen_at、ver、last_ip。客户端 IP：TCP 对端是回环时取 X-Real-IP，没有就取
/// X-Forwarded-For 的最后一个；都没有用对端地址；规范化 `::ffff:a.b.c.d` → IPv4。TCP 对端不是回环时不信这两个头。
#[tokio::test]
async fn heartbeat_updates_device_and_client_ip() {
    let s = Server::start().await;
    let (id, uuid) = ("700000031", b64(&random_uuid_bytes()));
    let body = json!({"id": id, "uuid": uuid, "ver": 1004030, "conns": [1234, 1235], "modified_at": 0}).to_string();
    async fn last_ip(s: &Server) -> Vec<serde_json::Map<String, Value>> {
        let rows = s.rows("select last_ip, ver, last_seen_at from device where id = '700000031'").await;
        assert_eq!(rows.len(), 1, "heartbeat must create/keep the device row");
        rows
    }

    let r = s.request("POST", "/api/heartbeat", None, Some(&body), &[]).await;
    hb_json(&r);
    let d = &last_ip(&s).await[0];
    assert_eq!(get_str(d, "last_ip"), "127.0.0.1");
    assert_eq!(get_i64(d, "ver"), 1004030);
    assert!(get_i64(d, "last_seen_at") > 0);

    let cases: [(&[(&str, &str)], &str); 4] = [
        (&[("X-Real-IP", "203.0.113.7")], "203.0.113.7"),
        (&[("X-Forwarded-For", "10.0.0.1, 198.51.100.9")], "198.51.100.9"),
        (&[("X-Real-IP", "::ffff:203.0.113.8")], "203.0.113.8"),
        (&[("X-Real-IP", "2001:db8::5"), ("X-Forwarded-For", "198.51.100.10")], "2001:db8::5"),
    ];
    for (headers, want) in cases {
        s.exec(&format!("update device set last_seen_at = 0 where id = '{id}'")).await;
        let r = s.request("POST", "/api/heartbeat", None, Some(&body), headers).await;
        hb_json(&r);
        let d = &last_ip(&s).await[0];
        assert_eq!(get_str(d, "last_ip"), want, "headers {headers:?}");
        assert!(get_i64(d, "last_seen_at") > 0, "last_seen_at must be refreshed");
    }

    // 经本机的非回环地址连过来：X-Real-IP 不可信，用 TCP 对端地址。
    if let Some(ip) = non_loopback_ip() {
        let base = format!("http://{}", std::net::SocketAddr::new(ip, s.port - 2));
        let r = s.request_to(&base, "POST", "/api/heartbeat", None, Some(&body), &[("X-Real-IP", "203.0.113.99")]).await;
        hb_json(&r);
        assert_eq!(get_str(&last_ip(&s).await[0], "last_ip"), ip.to_string());
    } else {
        eprintln!("skip: no non-loopback address on this machine");
    }
}

/// §9.3：peer 表里有这个 id 时心跳必须带相符的 uuid；不符或缺 uuid → 回 `{}`（不下发策略、不要 sysinfo），不建设备行；
/// 相符 → 正常下发。peer 表里没有这个 id → 照常接受。
#[tokio::test]
async fn heartbeat_uuid_weak_check() {
    let s = Server::start().await;
    let raw = random_uuid_bytes();
    s.insert_peer("700000041", &raw).await;

    let v = hb_json(&s.heartbeat("700000041", &b64(b"forged"), 0).await);
    assert_eq!(v, json!({}), "uuid mismatch must answer {{}}");
    let r = s
        .post_json("/api/heartbeat", None, &json!({"id": "700000041", "ver": 1005010, "modified_at": 0}))
        .await;
    assert_eq!(hb_json(&r), json!({}), "missing uuid counts as mismatch");
    assert_eq!(s.device_user("700000041").await, None, "rejected heartbeat must not create the device");

    let v = hb_json(&s.heartbeat("700000041", &b64(&raw), 0).await);
    modified_at(&v);
    config_options(&v);
    assert!(s.device_user("700000041").await.is_some());

    // peer 表里没有：照常。
    let v = hb_json(&s.heartbeat("700000042", &b64(b"anything"), 0).await);
    modified_at(&v);
}

// ===================== §9.3 审计 =====================

fn conn_new(id: &str, uuid: &str, conn_id: i32, nonce: Option<&str>) -> Value {
    let mut v = json!({"ip": "203.0.113.5", "action": "new", "id": id, "uuid": uuid, "conn_id": conn_id, "session_id": 0});
    if let Some(n) = nonce {
        v["nonce"] = json!(n);
    }
    v
}

fn conn_auth(id: &str, uuid: &str, conn_id: i32, session_id: u64, typ: i64) -> Value {
    json!({"peer": ["987654321", "Bob-PC"], "type": typ, "primary_auth": 2, "two_factor": 1,
           "id": id, "uuid": uuid, "conn_id": conn_id, "session_id": session_id, "nonce": nonce()})
}

fn conn_close(id: &str, uuid: &str, conn_id: i32, session_id: u64) -> Value {
    json!({"action": "close", "id": id, "uuid": uuid, "conn_id": conn_id, "session_id": session_id, "nonce": nonce()})
}

/// 关联查询：一行 audit_conn。
async fn audit_rows(s: &Server, dev: &str) -> Vec<serde_json::Map<String, Value>> {
    s.rows(&format!("select * from audit_conn where device_id = '{dev}' order by id")).await
}

/// §9.3 audit_conn 关联规则（笔记 03 §5.2、§5.5）：
/// - new：插一行，session_id 存 ''；
/// - 认证成功（无 action）：更新 (device_id, conn_id, 未关闭) 里 id 最大的一条：peer_id、peer_name、conn_type、
///   session_id（u64 十进制字符串，可超过 i64）、auth（其余字段原样 JSON）、authed_at；
/// - close：同样条件写 closed_at；
/// - 被控端重启后 conn_id 复用：已关闭的旧行不再被匹配。
#[tokio::test]
async fn audit_conn_lifecycle() {
    let s = Server::start().await;
    let (dev, uuid) = ("800000001", b64(&random_uuid_bytes()));
    let big: u64 = 12345678901234567890;

    let r = s.post_json("/api/audit/conn", None, &conn_new(dev, &uuid, 1234, Some(&nonce()))).await;
    assert_audit_ok(&r, "new");
    let rows = audit_rows(&s, dev).await;
    assert_eq!(rows.len(), 1);
    let r1 = &rows[0];
    assert_eq!(get_i64(r1, "conn_id"), 1234);
    assert_eq!(get_str(r1, "session_id"), "");
    assert_eq!(get_str(r1, "ip"), "203.0.113.5");
    assert!(get_i64(r1, "created_at") > 0);
    assert!(r1["authed_at"].is_null() && r1["closed_at"].is_null());

    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_auth(dev, &uuid, 1234, big, 0)).await, "auth");
    let rows = audit_rows(&s, dev).await;
    assert_eq!(rows.len(), 1, "auth must update the new row, not insert");
    let r1 = &rows[0];
    assert_eq!(get_str(r1, "peer_id"), "987654321");
    assert_eq!(get_str(r1, "peer_name"), "Bob-PC");
    assert_eq!(get_i64(r1, "conn_type"), 0);
    assert_eq!(get_str(r1, "session_id"), "12345678901234567890");
    assert!(get_i64(r1, "authed_at") > 0);
    let auth: Value = serde_json::from_str(get_str(r1, "auth")).expect("auth must be JSON");
    assert_eq!(auth.get("primary_auth"), Some(&json!(2)), "auth: {auth}");
    assert_eq!(auth.get("two_factor"), Some(&json!(1)), "auth: {auth}");

    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_close(dev, &uuid, 1234, big)).await, "close");
    let rows = audit_rows(&s, dev).await;
    assert!(get_i64(&rows[0], "closed_at") > 0);

    // 重启后同一个 conn_id：新行；认证只更新新行。
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_new(dev, &uuid, 1234, Some(&nonce()))).await, "new 2");
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_auth(dev, &uuid, 1234, 42, 1)).await, "auth 2");
    let rows = audit_rows(&s, dev).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(get_str(&rows[0], "session_id"), "12345678901234567890", "closed row must not be touched");
    assert_eq!(get_str(&rows[1], "session_id"), "42");
    assert_eq!(get_i64(&rows[1], "conn_type"), 1);
}

/// §9.3：同一 (device_id, conn_id) 有两条未关闭的行时，认证和 close 都选 id 最大的那条；
/// 认证找不到未关闭的行就新插一条（created_at = authed_at = now）；close 找不到就忽略。
#[tokio::test]
async fn audit_conn_matching_edge_cases() {
    let s = Server::start().await;
    let (dev, uuid) = ("800000002", b64(&random_uuid_bytes()));
    for _ in 0..2 {
        assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_new(dev, &uuid, 1500, Some(&nonce()))).await, "new");
    }
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_auth(dev, &uuid, 1500, 7, 0)).await, "auth");
    let rows = audit_rows(&s, dev).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(get_str(&rows[0], "session_id"), "", "older row untouched");
    assert_eq!(get_str(&rows[1], "session_id"), "7", "newest unclosed row updated");

    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_close(dev, &uuid, 1500, 7)).await, "close");
    let rows = audit_rows(&s, dev).await;
    assert!(rows[0]["closed_at"].is_null() && !rows[1]["closed_at"].is_null());
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_close(dev, &uuid, 1500, 0)).await, "close 2");
    assert!(!audit_rows(&s, dev).await[0]["closed_at"].is_null(), "second close hits the remaining unclosed row");

    // 认证时没有未关闭的行（new 丢了）：新插一条。
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_auth(dev, &uuid, 1600, 99, 0)).await, "auth w/o new");
    let rows = s.rows(&format!("select * from audit_conn where device_id = '{dev}' and conn_id = 1600")).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(get_str(&rows[0], "session_id"), "99");
    assert_eq!(get_str(&rows[0], "peer_id"), "987654321");
    assert_eq!(get_i64(&rows[0], "created_at"), get_i64(&rows[0], "authed_at"));

    // close 找不到：忽略（不插行）。
    let before = s.count("audit_conn").await;
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_close(dev, &uuid, 1999, 5)).await, "close unmatched");
    assert_eq!(s.count("audit_conn").await, before);
}

/// §9.3：控制端会话备注 `{"id","session_id","note"}`（有 note 键、没有 uuid 键）免 uuid 校验，
/// 按 (device_id, session_id) 更新所有匹配记录的 note（远程桌面和文件传输两条）；一条都匹配不到就忽略；回 200 空 body。
#[tokio::test]
async fn audit_conn_note() {
    let s = Server::start().await;
    let raw = random_uuid_bytes();
    let (dev, uuid) = ("800000003", b64(&raw));
    // peer 表里有这台设备：备注请求不带 uuid 也必须被接受（唯一免校验的请求）。
    s.insert_peer(dev, &raw).await;
    let session: u64 = 18000000000000000001;
    for (conn_id, typ) in [(1700, 0), (1701, 1)] {
        assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_new(dev, &uuid, conn_id, Some(&nonce()))).await, "new");
        assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_auth(dev, &uuid, conn_id, session, typ)).await, "auth");
    }
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_new(dev, &uuid, 1702, Some(&nonce()))).await, "new other");
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_auth(dev, &uuid, 1702, 5, 0)).await, "auth other");

    let r = s.post_json("/api/audit/conn", None, &json!({"id": dev, "session_id": session, "note": "修打印机"})).await;
    assert_audit_ok(&r, "note");
    let rows = audit_rows(&s, dev).await;
    let notes: Vec<(i64, String)> = rows.iter().map(|r| (get_i64(r, "conn_id"), get_str(r, "note").to_owned())).collect();
    assert_eq!(
        notes,
        vec![(1700, "修打印机".to_owned()), (1701, "修打印机".to_owned()), (1702, String::new())],
        "note must hit every row of the session and nothing else"
    );

    let before = s.count("audit_conn").await;
    let r = s.post_json("/api/audit/conn", None, &json!({"id": dev, "session_id": 1u64, "note": "nobody"})).await;
    assert_audit_ok(&r, "note unmatched");
    assert_eq!(s.count("audit_conn").await, before, "unmatched note must not insert");
    assert_eq!(s.scalar_i64("select count(*) from audit_conn where note = 'nobody'").await, 0);
}

/// §9.1.8：nonce 可选。带 nonce 的按 nonce 去重 5 分钟（重复的也回 200 空 body，不重复入库）；
/// 不带 nonce 的（1.4.x）直接入库、不去重；`nonce: ""` 不能当去重键。conn / file / alarm 都一样。
#[tokio::test]
async fn audit_nonce_dedup_and_optional() {
    let s = Server::start().await;
    let (dev, uuid) = ("800000004", b64(&random_uuid_bytes()));
    let n = nonce();

    for _ in 0..3 {
        assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_new(dev, &uuid, 1100, Some(&n))).await, "dup new");
    }
    assert_eq!(s.count("audit_conn").await, 1, "same nonce must be stored once");

    for _ in 0..2 {
        assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_new(dev, &uuid, 1101, None)).await, "no nonce");
    }
    assert_eq!(s.scalar_i64("select count(*) from audit_conn where conn_id = 1101").await, 2, "no nonce: no dedup");
    for _ in 0..2 {
        assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_new(dev, &uuid, 1102, Some(""))).await, "empty nonce");
    }
    assert_eq!(s.scalar_i64("select count(*) from audit_conn where conn_id = 1102").await, 2, "'' is not a dedup key");

    let file = |nonce: Option<&str>| {
        let mut v = json!({"id": dev, "uuid": uuid, "peer_id": "987654321", "conn_id": 1100, "type": 0, "path": "C:\\x",
                           "is_file": false, "info": "{\"ip\":\"203.0.113.5\",\"name\":\"Bob\",\"num\":1,\"files\":[[\"a.txt\",1]]}"});
        if let Some(n) = nonce {
            v["nonce"] = json!(n);
        }
        v
    };
    let fnonce = nonce();
    for _ in 0..2 {
        assert_audit_ok(&s.post_json("/api/audit/file", None, &file(Some(&fnonce))).await, "dup file");
    }
    assert_eq!(s.count("audit_file").await, 1);
    for _ in 0..2 {
        assert_audit_ok(&s.post_json("/api/audit/file", None, &file(None)).await, "file no nonce");
    }
    assert_eq!(s.count("audit_file").await, 3);

    let alarm = |nonce: Option<&str>| {
        let mut v = json!({"id": dev, "uuid": uuid, "typ": 2, "info": "{\"ip\":\"203.0.113.5\",\"id\":\"1\",\"name\":\"x\"}", "conn_id": 1100});
        if let Some(n) = nonce {
            v["nonce"] = json!(n);
        }
        v
    };
    let anonce = nonce();
    for _ in 0..2 {
        assert_audit_ok(&s.post_json("/api/audit/alarm", None, &alarm(Some(&anonce))).await, "dup alarm");
    }
    assert_eq!(s.count("audit_alarm").await, 1);
    for _ in 0..2 {
        assert_audit_ok(&s.post_json("/api/audit/alarm", None, &alarm(None)).await, "alarm no nonce");
    }
    assert_eq!(s.count("audit_alarm").await, 3);
}

/// §9.1.1、§9.1.8：审计写库失败回 200 + `{"error"}`（客户端会重试），nonce 只在写库成功后才登记，
/// 所以同一 nonce 的重试能入库。造法：运行中把 audit_conn 改名让插入失败，再改回来重发同一条。
#[tokio::test]
async fn audit_write_failure_does_not_burn_nonce() {
    let s = Server::start().await;
    let (dev, uuid) = ("800000005", b64(&random_uuid_bytes()));
    let n = nonce();
    let body = conn_new(dev, &uuid, 1300, Some(&n));
    s.exec("alter table audit_conn rename to audit_conn_hidden").await;
    let r = s.post_json("/api/audit/conn", None, &body).await;
    s.exec("alter table audit_conn_hidden rename to audit_conn").await;
    assert_eq!(r.status, 200, "audit internal error must be 200: {:?}", r.text());
    r.assert_error_body();
    assert_eq!(s.count("audit_conn").await, 0);

    assert_audit_ok(&s.post_json("/api/audit/conn", None, &body).await, "retry");
    assert_eq!(s.count("audit_conn").await, 1, "retry with the same nonce must be stored");
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &body).await, "dup after success");
    assert_eq!(s.count("audit_conn").await, 1);
}

/// §9.3、笔记 03 §5.3、§5.4：file 存 device_id、conn_id、peer_id、type、path、is_file（布尔 → 0/1）、info（JSON 字符串原样）；
/// alarm 存 typ（字段名是 typ）、info 原样、conn_id；未知 typ 照收。
#[tokio::test]
async fn audit_file_and_alarm_rows() {
    let s = Server::start().await;
    let (dev, uuid) = ("800000006", b64(&random_uuid_bytes()));
    let info = "{\"ip\":\"203.0.113.5\",\"name\":\"Bob\",\"num\":3,\"files\":[[\"a.txt\",123],[\"b\",45]]}";
    let r = s
        .post_json(
            "/api/audit/file",
            None,
            &json!({"id": dev, "uuid": uuid, "peer_id": "987654321", "conn_id": 1234, "type": 0, "path": "C:\\x",
                    "is_file": false, "info": info, "nonce": nonce()}),
        )
        .await;
    assert_audit_ok(&r, "file");
    let r = s
        .post_json(
            "/api/audit/file",
            None,
            &json!({"id": dev, "uuid": uuid, "peer_id": "987654321", "conn_id": 1234, "type": 1, "path": "/tmp/f.bin",
                    "is_file": true, "info": "{}", "nonce": nonce()}),
        )
        .await;
    assert_audit_ok(&r, "file 2");
    let rows = s.rows(&format!("select * from audit_file where device_id = '{dev}' order by id")).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(get_i64(&rows[0], "conn_id"), 1234);
    assert_eq!(get_str(&rows[0], "peer_id"), "987654321");
    assert_eq!(get_i64(&rows[0], "type"), 0);
    assert_eq!(get_str(&rows[0], "path"), "C:\\x");
    assert_eq!(get_i64(&rows[0], "is_file"), 0);
    assert_eq!(get_str(&rows[0], "info"), info);
    assert!(get_i64(&rows[0], "created_at") > 0);
    assert_eq!(get_i64(&rows[1], "type"), 1);
    assert_eq!(get_i64(&rows[1], "is_file"), 1);
    assert_eq!(get_str(&rows[1], "path"), "/tmp/f.bin");

    let ainfo = "{\"ip\":\"203.0.113.5\"}";
    for typ in [0, 42] {
        let r = s
            .post_json(
                "/api/audit/alarm",
                None,
                &json!({"id": dev, "uuid": uuid, "typ": typ, "info": ainfo, "conn_id": 1234, "nonce": nonce()}),
            )
            .await;
        assert_audit_ok(&r, "alarm");
    }
    let rows = s.rows(&format!("select * from audit_alarm where device_id = '{dev}' order by id")).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(get_i64(&rows[0], "typ"), 0);
    assert_eq!(get_i64(&rows[1], "typ"), 42);
    assert_eq!(get_str(&rows[0], "info"), ainfo);
    assert_eq!(get_i64(&rows[0], "conn_id"), 1234);
    assert!(get_i64(&rows[0], "created_at") > 0);
}

/// §9.3：peer 表里有这个 id 时，被控端审计必须带相符的 uuid；不符或缺 uuid（且不是备注请求）→ 200 空 body 但不入库。
/// 相符 → 入库。conn / file / alarm 都一样。
#[tokio::test]
async fn audit_uuid_weak_check() {
    let s = Server::start().await;
    let raw = random_uuid_bytes();
    let dev = "800000007";
    s.insert_peer(dev, &raw).await;
    let forged = b64(b"forged");

    let mut no_uuid = conn_new(dev, "", 1400, Some(&nonce()));
    no_uuid.as_object_mut().unwrap().remove("uuid");
    for body in [conn_new(dev, &forged, 1400, Some(&nonce())), no_uuid, conn_auth(dev, &forged, 1400, 3, 0)] {
        assert_audit_ok(&s.post_json("/api/audit/conn", None, &body).await, "conn mismatch");
    }
    let file = |u: &str| {
        json!({"id": dev, "uuid": u, "peer_id": "1", "conn_id": 1400, "type": 0, "path": "", "is_file": false, "info": "{}", "nonce": nonce()})
    };
    let alarm = |u: &str| json!({"id": dev, "uuid": u, "typ": 0, "info": "{}", "conn_id": 1400, "nonce": nonce()});
    assert_audit_ok(&s.post_json("/api/audit/file", None, &file(&forged)).await, "file mismatch");
    assert_audit_ok(&s.post_json("/api/audit/alarm", None, &alarm(&forged)).await, "alarm mismatch");
    assert_eq!(s.count("audit_conn").await, 0);
    assert_eq!(s.count("audit_file").await, 0);
    assert_eq!(s.count("audit_alarm").await, 0);

    let good = b64(&raw);
    assert_audit_ok(&s.post_json("/api/audit/conn", None, &conn_new(dev, &good, 1400, Some(&nonce()))).await, "conn ok");
    assert_audit_ok(&s.post_json("/api/audit/file", None, &file(&good)).await, "file ok");
    assert_audit_ok(&s.post_json("/api/audit/alarm", None, &alarm(&good)).await, "alarm ok");
    assert_eq!(s.count("audit_conn").await, 1);
    assert_eq!(s.count("audit_file").await, 1);
    assert_eq!(s.count("audit_alarm").await, 1);
}
