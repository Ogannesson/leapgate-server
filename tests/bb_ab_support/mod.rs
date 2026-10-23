//! 地址簿黑盒测试（tests/bb_ab.rs）的辅助代码：起真实的 leapgate-server 进程，直接写它的 SQLite 造数据，
//! 照原版客户端的方式发请求，按笔记 04 §1.2 的三种解析器判定回包。
//! 只依据 LEAPGATE.md、migrations/0001_init.sql 和笔记 04，不依赖任何模块的实现。
#![allow(dead_code)]

use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use sodiumoxide::crypto::secretbox;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use std::{
    fs::File,
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// 本进程里已经分出去的会合端口 P，避免并行的测试互相撞端口。
static RESERVED: Mutex<Vec<u16>> = Mutex::new(Vec::new());

/// 个人簿的固定名字（LEAPGATE.md §12.1，客户端按名字认个人簿）。
pub const PERSONAL_NAME: &str = "My address book";

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn tcp_free(port: u16) -> bool {
    TcpListener::bind(("0.0.0.0", port)).is_ok()
}

/// 随机高端口 P，要求 P-2（API）、P-1（NAT 测试和控制台）、P（TCP/UDP 会合）、P+2（WebSocket）都空闲。
fn pick_port() -> u16 {
    let mut reserved = RESERVED.lock().unwrap();
    loop {
        // 20000~32699：避开 Linux 的临时端口段（32768~60999）。测试发起的连接从那里取本地端口，
        // 可能在这里检查完、服务端还没绑定之间占掉其中一个。
        let p = (uuid::Uuid::new_v4().as_u128() % 12_700) as u16 + 20_000;
        if reserved.iter().any(|r| r.abs_diff(p) <= 5) {
            continue;
        }
        if [p - 2, p - 1, p, p + 2].into_iter().all(tcp_free) && UdpSocket::bind(("0.0.0.0", p)).is_ok() {
            reserved.push(p);
            return p;
        }
    }
}

/// 一次 HTTP 响应。
#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("响应不是 JSON（{e}）：HTTP {} {:?}", self.status, self.text()))
    }
}

/// 库里的一个 ab_peer 行。
#[derive(Debug, Clone, PartialEq)]
pub struct PeerRow {
    pub data: Value,
    pub tags: Value,
    pub hash_enc: String,
    pub password_enc: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct User {
    pub id: i64,
    pub name: String,
    pub token: String,
}

/// 一个真实的 leapgate-server 进程（临时工作目录、随机端口、TEST_HBBS=no、geo 不自动更新），
/// 以及连到它的 SQLite 的连接池。Drop 时杀掉进程。
pub struct Server {
    child: Child,
    pub dir: tempfile::TempDir,
    /// 会合端口 P；API 在 P-2。
    pub port: u16,
    pub db: SqlitePool,
    http: reqwest::Client,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 等 API 端口能连上；进程提前退出（端口被别的进程抢走等）返回 false。
fn wait_ready(child: &mut Child, api_port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return false;
        }
        if TcpStream::connect(("127.0.0.1", api_port)).is_ok() {
            // 连上的若是别的进程，本进程会在绑定 API 端口时报错退出：稍等再确认它还活着。
            std::thread::sleep(Duration::from_millis(300));
            return child.try_wait().unwrap().is_none();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

impl Server {
    pub async fn start() -> Self {
        sodiumoxide::init().unwrap();
        let mut last_log = String::new();
        for _ in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("leapgate.toml"), "[geo]\nauto_update = false\n").unwrap();
            let port = pick_port();
            let db_path = dir.path().join("db.sqlite3");
            let log = File::create(dir.path().join("server.log")).unwrap();
            let mut child = Command::new(env!("CARGO_BIN_EXE_leapgate-server"))
                .arg("-p")
                .arg(port.to_string())
                .current_dir(dir.path())
                .env("TEST_HBBS", "no")
                .env("DB_URL", &db_path)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap();
            if wait_ready(&mut child, port - 2) {
                let opts = SqliteConnectOptions::new()
                    .filename(&db_path)
                    .journal_mode(SqliteJournalMode::Wal)
                    .busy_timeout(Duration::from_secs(5))
                    .foreign_keys(true);
                let db = SqlitePoolOptions::new()
                    .max_connections(2)
                    .connect_with(opts)
                    .await
                    .unwrap();
                let http = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(20))
                    .build()
                    .unwrap();
                return Self {
                    child,
                    dir,
                    port,
                    db,
                    http,
                };
            }
            let _ = child.kill();
            let _ = child.wait();
            last_log = std::fs::read_to_string(dir.path().join("server.log")).unwrap_or_default();
        }
        panic!("leapgate-server 起不来，最后一次的日志：\n{last_log}");
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port - 2, path)
    }

    async fn finish(resp: reqwest::Response) -> Resp {
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        let body = resp.bytes().await.unwrap().to_vec();
        Resp {
            status,
            content_type,
            body,
        }
    }

    pub async fn get(&self, path: &str) -> Resp {
        Self::finish(self.http.get(self.url(path)).send().await.unwrap()).await
    }

    /// 照客户端发：`Authorization: Bearer <token>`（token 为空时就是 `Bearer `，笔记 04 §1.1）、
    /// `Content-Type: application/json`；body 为空时显式 `Content-Length: 0`（读接口，ab_model `_setEmptyBody`）。
    pub async fn call(&self, method: &str, path: &str, token: &str, body: &str) -> Resp {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut req = self
            .http
            .request(method, self.url(path))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json");
        if body.is_empty() {
            req = req.header("Content-Length", "0");
        }
        Self::finish(req.body(body.to_owned()).send().await.unwrap()).await
    }

    /// 读接口：POST、空 body。
    pub async fn read(&self, path: &str, token: &str) -> Resp {
        self.call("POST", path, token, "").await
    }

    pub async fn personal_guid(&self, token: &str) -> String {
        let r = self.read("/api/ab/personal", token).await;
        let obj = assert_object(&r, "personal");
        obj.get("guid")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("personal 没有字符串 guid：{obj:?}"))
            .to_owned()
    }

    /// 照客户端的分页循环拉完一个列表（笔记 04 §1.6）：current 从 1 起、pageSize=100，
    /// total 在第一次非 0 时锁定，按 `key` 去重（后来者覆盖），`current*100 < total` 时继续。
    /// 返回（去重后的条目，锁定的 total，每页条数）。每页都按对象型解析器判定。
    pub async fn pull_pages(&self, token: &str, path: &str, extra: &str, key: &str) -> (Vec<Map<String, Value>>, i64, Vec<usize>) {
        let mut items: Vec<Map<String, Value>> = Vec::new();
        let mut total = 0i64;
        let mut lens = Vec::new();
        let mut current = 0i64;
        loop {
            current += 1;
            assert!(current <= 100, "分页循环停不下来");
            let r = self
                .read(&format!("{path}?current={current}&pageSize=100{extra}"), token)
                .await;
            let obj = assert_object(&r, path);
            let t = obj
                .get("total")
                .unwrap_or_else(|| panic!("{path} 第 {current} 页没有 total（客户端会忽略整页）：{obj:?}"));
            assert!(is_int(t), "{path} 的 total 必须是 JSON 整数：{t}");
            if total == 0 {
                total = t.as_i64().unwrap();
            }
            let data = obj
                .get("data")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("{path} 第 {current} 页 data 不是数组：{obj:?}"));
            lens.push(data.len());
            for item in data {
                let item = item
                    .as_object()
                    .unwrap_or_else(|| panic!("{path} 的元素不是对象：{item}"))
                    .clone();
                let k = item
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{path} 的元素没有字符串 {key}：{item:?}"))
                    .to_owned();
                match items.iter_mut().find(|m| m.get(key).and_then(Value::as_str) == Some(k.as_str())) {
                    Some(m) => *m = item,
                    None => items.push(item),
                }
            }
            if current * 100 >= total {
                break;
            }
        }
        (items, total, lens)
    }

    /// 客户端拉一本簿的全部设备，按 id 索引。
    pub async fn peers(&self, token: &str, guid: &str) -> std::collections::BTreeMap<String, Value> {
        let (items, _, _) = self
            .pull_pages(token, "/api/ab/peers", &format!("&ab={guid}"), "id")
            .await;
        items
            .into_iter()
            .map(|m| (m["id"].as_str().unwrap().to_owned(), Value::Object(m)))
            .collect()
    }

    /// 客户端拉 shared/profiles，按 name 索引。
    pub async fn profiles(&self, token: &str) -> std::collections::BTreeMap<String, Map<String, Value>> {
        let (items, _, _) = self
            .pull_pages(token, "/api/ab/shared/profiles", "", "name")
            .await;
        items
            .into_iter()
            .map(|m| (m["name"].as_str().unwrap().to_owned(), m))
            .collect()
    }

    // ---- 直接写库造数据（表结构见 migrations/0001_init.sql） ----

    /// 建一个启用的用户和一个令牌（库里只存 sha256 hex，LEAPGATE.md §11）。
    pub async fn user(&self, name: &str, is_admin: bool) -> User {
        let id: i64 = sqlx::query_scalar(
            "insert into user(name, is_admin, created_at, updated_at) values(?, ?, ?, ?) returning id",
        )
        .bind(name)
        .bind(is_admin as i64)
        .bind(now())
        .bind(now())
        .fetch_one(&self.db)
        .await
        .unwrap();
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let hash: String = Sha256::digest(token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        sqlx::query("insert into token(token_hash, user_id, created_at, last_used_at) values(?, ?, ?, ?)")
            .bind(hash)
            .bind(id)
            .bind(now())
            .bind(now())
            .execute(&self.db)
            .await
            .unwrap();
        User {
            id,
            name: name.to_owned(),
            token,
        }
    }

    pub async fn disable(&self, uid: i64) {
        self.exec_i("update user set status = 0 where id = ?", uid).await;
    }

    async fn exec_i(&self, sql: &str, v: i64) {
        sqlx::query(sql).bind(v).execute(&self.db).await.unwrap();
    }

    pub async fn group(&self, name: &str) -> i64 {
        sqlx::query_scalar("insert into user_group(name, created_at) values(?, ?) returning id")
            .bind(name)
            .bind(now())
            .fetch_one(&self.db)
            .await
            .unwrap()
    }

    pub async fn delete_group(&self, gid: i64) {
        self.exec_i("delete from user_group where id = ?", gid).await;
    }

    pub async fn join(&self, gid: i64, uid: i64) {
        sqlx::query("insert into group_member(group_id, user_id) values(?, ?)")
            .bind(gid)
            .bind(uid)
            .execute(&self.db)
            .await
            .unwrap();
    }

    pub async fn leave(&self, gid: i64, uid: i64) {
        sqlx::query("delete from group_member where group_id = ? and user_id = ?")
            .bind(gid)
            .bind(uid)
            .execute(&self.db)
            .await
            .unwrap();
    }

    /// 建一本簿（命令行 / 导入的做法），返回 guid（UUIDv4 字符串）。
    pub async fn book(&self, name: &str, owner: i64, personal: bool) -> String {
        let guid = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "insert into ab(guid, name, owner_id, personal, created_at, updated_at) values(?, ?, ?, ?, ?, ?)",
        )
        .bind(&guid)
        .bind(name)
        .bind(owner)
        .bind(personal as i64)
        .bind(now())
        .bind(now())
        .execute(&self.db)
        .await
        .unwrap();
        guid
    }

    pub async fn personal_book(&self, owner: i64) -> String {
        self.book(PERSONAL_NAME, owner, true).await
    }

    pub async fn grant_user(&self, guid: &str, uid: i64, rule: i64) {
        sqlx::query("insert into ab_rule(ab_guid, user_id, rule) values(?, ?, ?)")
            .bind(guid)
            .bind(uid)
            .bind(rule)
            .execute(&self.db)
            .await
            .unwrap();
    }

    pub async fn grant_group(&self, guid: &str, gid: i64, rule: i64) {
        sqlx::query("insert into ab_rule(ab_guid, group_id, rule) values(?, ?, ?)")
            .bind(guid)
            .bind(gid)
            .bind(rule)
            .execute(&self.db)
            .await
            .unwrap();
    }

    pub async fn set_group_rule(&self, guid: &str, gid: i64, rule: i64) {
        sqlx::query("update ab_rule set rule = ? where ab_guid = ? and group_id = ?")
            .bind(rule)
            .bind(guid)
            .bind(gid)
            .execute(&self.db)
            .await
            .unwrap();
    }

    /// 直接插一个 ab_peer 行；`hash_enc`/`password_enc` 传库里的原样值（'' 或 `encrypt` 的结果）。
    pub async fn insert_peer(&self, guid: &str, id: &str, data: Value, tags: Value, hash_enc: &str, password_enc: &str) {
        sqlx::query(
            "insert into ab_peer(ab_guid, id, data, tags, hash_enc, password_enc, created_at, updated_at)
             values(?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(guid)
        .bind(id)
        .bind(data.to_string())
        .bind(tags.to_string())
        .bind(hash_enc)
        .bind(password_enc)
        .bind(now() - 1000)
        .bind(now() - 1000)
        .execute(&self.db)
        .await
        .unwrap();
    }

    pub async fn insert_tag(&self, guid: &str, name: &str, color: i64) {
        sqlx::query("insert into ab_tag(ab_guid, name, color) values(?, ?, ?)")
            .bind(guid)
            .bind(name)
            .bind(color)
            .execute(&self.db)
            .await
            .unwrap();
    }

    pub async fn peer_row(&self, guid: &str, id: &str) -> Option<PeerRow> {
        let row = sqlx::query_as::<_, (String, String, String, String, i64, i64)>(
            "select data, tags, hash_enc, password_enc, created_at, updated_at from ab_peer
             where ab_guid = ? and id = ?",
        )
        .bind(guid)
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .unwrap()?;
        let parse = |s: &str| -> Value {
            serde_json::from_str(s).unwrap_or_else(|e| panic!("ab_peer 列不是 JSON（{e}）：{s:?}"))
        };
        Some(PeerRow {
            data: parse(&row.0),
            tags: parse(&row.1),
            hash_enc: row.2,
            password_enc: row.3,
            created_at: row.4,
            updated_at: row.5,
        })
    }

    pub async fn peer_ids(&self, guid: &str) -> Vec<String> {
        sqlx::query_scalar("select id from ab_peer where ab_guid = ? order by id")
            .bind(guid)
            .fetch_all(&self.db)
            .await
            .unwrap()
    }

    /// ab_tag 行，按 name 排序。
    pub async fn tag_rows(&self, guid: &str) -> Vec<(String, i64)> {
        sqlx::query_as("select name, color from ab_tag where ab_guid = ? order by name")
            .bind(guid)
            .fetch_all(&self.db)
            .await
            .unwrap()
    }

    // ---- 密码字段加密（LEAPGATE.md §13：工作目录下的 leapgate_secret.key，secretbox，`sb1:` + base64(nonce ‖ 密文)） ----

    fn key(&self) -> secretbox::Key {
        let text = std::fs::read_to_string(self.dir.path().join("leapgate_secret.key")).unwrap();
        secretbox::Key::from_slice(&base64::decode(text.trim()).unwrap()).unwrap()
    }

    pub fn encrypt(&self, plain: &str) -> String {
        let nonce = secretbox::gen_nonce();
        let mut data = nonce.as_ref().to_vec();
        data.extend(secretbox::seal(plain.as_bytes(), &nonce, &self.key()));
        format!("sb1:{}", base64::encode(data))
    }

    pub fn decrypt(&self, stored: &str) -> String {
        let b64 = stored
            .strip_prefix("sb1:")
            .unwrap_or_else(|| panic!("落盘值不是 sb1: 密文：{stored:?}"));
        let data = base64::decode(b64).unwrap();
        let (nonce, cipher) = data.split_at(secretbox::NONCEBYTES);
        let plain = secretbox::open(cipher, &secretbox::Nonce::from_slice(nonce).unwrap(), &self.key()).unwrap();
        String::from_utf8(plain).unwrap()
    }
}

// ---- 回包判定 ----

pub fn is_int(v: &Value) -> bool {
    v.is_i64() || v.is_u64()
}

/// §9.1 第 10 条：JSON 里不给 null。
pub fn assert_no_null(v: &Value, ctx: &str) {
    match v {
        Value::Null => panic!("{ctx}：回包里出现了 null"),
        Value::Array(a) => a.iter().for_each(|x| assert_no_null(x, ctx)),
        Value::Object(m) => m.values().for_each(|x| assert_no_null(x, ctx)),
        _ => {}
    }
}

/// §9.1 第 2 条：JSON 响应带 `application/json; charset=utf-8`。
pub fn assert_json_ct(r: &Resp, ctx: &str) {
    assert_eq!(
        r.content_type.replace(' ', "").to_ascii_lowercase(),
        "application/json;charset=utf-8",
        "{ctx}：Content-Type 不对，body={:?}",
        r.text()
    );
}

/// 动作型解析器（笔记 04 §1.2C）的成功：只认 200 + 空 body。
pub fn assert_action_ok(r: &Resp, ctx: &str) {
    assert!(
        r.status == 200 && r.body.is_empty(),
        "{ctx}：写接口成功必须是 200 + 空 body，实际 HTTP {} {:?}",
        r.status,
        r.text()
    );
}

/// 失败：给定状态码 + `{"error": "<非空字符串>"}`（§9.1 第 1 条、笔记 04 §0 第 2 条）。
pub fn assert_error(r: &Resp, status: u16, ctx: &str) {
    assert_error_in(r, &[status], ctx);
}

pub fn assert_error_in(r: &Resp, statuses: &[u16], ctx: &str) {
    assert!(
        statuses.contains(&r.status),
        "{ctx}：状态码应为 {statuses:?}，实际 HTTP {} {:?}",
        r.status,
        r.text()
    );
    assert_json_ct(r, ctx);
    let v = r.json();
    let msg = v.get("error").and_then(Value::as_str).unwrap_or_default();
    assert!(!msg.is_empty(), "{ctx}：错误体必须是 {{\"error\": 非空字符串}}，实际 {v}");
}

/// 对象型解析器（笔记 04 §1.2A）的成功：200、JSON 对象、没有 error 键；顺带查 Content-Type 和 null。
pub fn assert_object(r: &Resp, ctx: &str) -> Map<String, Value> {
    assert_eq!(r.status, 200, "{ctx}：HTTP {} {:?}", r.status, r.text());
    assert_json_ct(r, ctx);
    let v = r.json();
    assert_no_null(&v, ctx);
    let Value::Object(m) = v else {
        panic!("{ctx}：回包必须是 JSON 对象，实际 {}", r.text());
    };
    assert!(!m.contains_key("error"), "{ctx}：200 + error 键客户端也判失败：{m:?}");
    m
}

/// 数组型解析器（笔记 04 §1.2B，只用于 tags）的成功：200、顶层 JSON 数组。
pub fn assert_array(r: &Resp, ctx: &str) -> Vec<Value> {
    assert_eq!(r.status, 200, "{ctx}：HTTP {} {:?}", r.status, r.text());
    assert_json_ct(r, ctx);
    let v = r.json();
    assert_no_null(&v, ctx);
    let Value::Array(a) = v else {
        panic!("{ctx}：回包必须是顶层 JSON 数组，实际 {}", r.text());
    };
    a
}
