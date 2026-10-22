//! bb_api 黑盒测试的辅助代码：起真实的 porta-server 进程，直接读写它的 SQLite，按客户端的样子发 HTTP/UDP。
//! 只依据 PORTA.md 契约、笔记 01/03 和上游客户端代码，不依赖任何模块的实现。

#![allow(dead_code)]

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use hbb_common::{
    bytes::Bytes,
    protobuf::Message as _,
    rand::{self, Rng as _, RngCore as _},
    rendezvous_proto::{register_pk_response, rendezvous_message, RegisterPk, RendezvousMessage},
    tokio,
    udp::FramedSocket,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
    Row as _,
};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

/// 本进程里已经分给别的测试的端口 P，避免并行测试在"探测空闲"和"服务真正绑定"之间撞车。
static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);

/// 选一个 P：P-2（API）、P-1（NAT 测试 / 控制台）、P（会合 TCP+UDP）、P+2（WebSocket）都要空闲。
fn pick_port() -> u16 {
    let mut rng = rand::thread_rng();
    for _ in 0..500 {
        let p: u16 = rng.gen_range(20000..60000);
        let mut taken = TAKEN.lock().unwrap();
        let set = taken.get_or_insert_with(HashSet::new);
        if [p - 2, p - 1, p, p + 2].iter().any(|q| set.contains(q)) {
            continue;
        }
        let tcp_free = [p - 2, p - 1, p, p + 2]
            .iter()
            .all(|q| TcpListener::bind((Ipv4Addr::UNSPECIFIED, *q)).is_ok());
        let udp_free = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, p)).is_ok();
        if tcp_free && udp_free {
            for q in [p - 2, p - 1, p, p + 2] {
                set.insert(q);
            }
            return p;
        }
    }
    panic!("no free port quadruple found");
}

/// HTTP 响应：状态码、Content-Type 原文（没有时为空串）、body 原始字节。
#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub ct: String,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// body 解析成 JSON；解析失败直接让测试失败并带上原文。
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("body is not JSON ({e}): status {} body {:?}", self.status, self.text()))
    }

    /// §9.1.2：JSON 响应带 `Content-Type: application/json; charset=utf-8`（大小写、空格不计）。
    pub fn assert_json_ct(&self) {
        assert_eq!(
            norm_ct(&self.ct),
            "application/json;charset=utf-8",
            "JSON response must carry charset=utf-8 (status {}, body {:?})",
            self.status,
            self.text()
        );
    }

    /// §9.1.1：任何接口都不回 5xx。
    pub fn assert_not_5xx(&self, what: &str) {
        assert!(self.status < 500, "{what}: got {} {:?}", self.status, self.text());
    }

    /// 带 `error` 字符串的 JSON 错误体（§9.1.1）。
    pub fn assert_error_body(&self) {
        self.assert_json_ct();
        let v = self.json();
        let err = v.get("error").and_then(Value::as_str);
        assert!(
            err.is_some_and(|s| !s.is_empty()),
            "expected {{\"error\": <non-empty string>}}, got {} {:?}",
            self.status,
            self.text()
        );
    }
}

pub fn norm_ct(ct: &str) -> String {
    ct.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase()
}

/// §9.1.10：JSON 里不给 null。
pub fn assert_no_null(v: &Value, path: &str) {
    match v {
        Value::Null => panic!("null at {path}"),
        Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| assert_no_null(x, &format!("{path}[{i}]"))),
        Value::Object(o) => o.iter().for_each(|(k, x)| assert_no_null(x, &format!("{path}.{k}"))),
        _ => {}
    }
}

/// §9.1.5 / 笔记 03 §2.5：UserPayload。`name` 非空字符串且等于用户名；`info` 是对象；`is_admin` 是布尔；
/// `status` 是整数（启用的账号为 1，Rust 侧只认 0/1/-1）；`display_name`/`avatar`/`email`/`note` 出现时必须是字符串；不能有 null。
pub fn check_user_payload(v: &Value, name: &str, is_admin: bool) {
    assert!(v.is_object(), "UserPayload must be an object: {v}");
    assert_eq!(v.get("name").and_then(Value::as_str), Some(name), "UserPayload.name: {v}");
    assert!(v.get("info").is_some_and(Value::is_object), "UserPayload.info must be an object: {v}");
    assert_eq!(v.get("is_admin").and_then(Value::as_bool), Some(is_admin), "UserPayload.is_admin: {v}");
    assert_eq!(v.get("status").and_then(Value::as_i64), Some(1), "UserPayload.status: {v}");
    for k in ["display_name", "avatar", "email", "note"] {
        if let Some(x) = v.get(k) {
            assert!(x.is_string(), "UserPayload.{k} must be a string: {v}");
        }
    }
    assert_no_null(v, "UserPayload");
}

/// 客户端的 uuid 字段：原始字节的标准 base64（带填充，笔记 03 §1.6）。
pub fn b64(raw: &[u8]) -> String {
    base64::encode(raw)
}

/// 形如 Windows MachineGuid 的 36 字节 uuid（笔记 01 §7.1）。
pub fn random_uuid_bytes() -> Vec<u8> {
    uuid::Uuid::new_v4().to_string().into_bytes()
}

pub fn nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// §11：令牌库里只存 sha256 hex。
pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// §11 的 argon2id（argon2 crate 默认参数）。骨架的 `auth::hash_password` 不是 pub，这里直接用同一个 crate。
pub fn argon2_hash(plain: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(plain.as_bytes(), &salt).unwrap().to_string()
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// §10 的 rev：对（按键排序的生效选项、全局 epoch、设备 epoch）的规范 JSON 做 sha256，取前 8 字节（大端，
/// 与骨架共享的 `strategy::rev` 一致）转 i64 后与 i64::MAX 按位与，0 取 1。
pub fn expected_rev(options: &BTreeMap<String, String>, global_epoch: i64, device_epoch: i64) -> i64 {
    let canonical = serde_json::json!([options, global_epoch, device_epoch]).to_string();
    let digest = Sha256::digest(canonical.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    match i64::from_be_bytes(first) & i64::MAX {
        0 => 1,
        v => v,
    }
}

/// 在 `dir` 里起 porta-server：`-p port`、`TEST_HBBS=no`、库是 `dir/db_v2.sqlite3`，输出追加到 `dir/server.log`。
fn spawn(dir: &tempfile::TempDir, port: u16) -> Child {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.path().join("server.log"))
        .unwrap();
    Command::new(env!("CARGO_BIN_EXE_porta-server"))
        .arg("-p")
        .arg(port.to_string())
        .current_dir(dir.path())
        .env("TEST_HBBS", "no")
        .env("DB_URL", dir.path().join("db_v2.sqlite3"))
        .env_remove("ALWAYS_USE_RELAY")
        .env_remove("RELAY")
        .env_remove("KEY")
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap()
}

/// 一个真实的 porta-server 进程：临时工作目录、`-p P`、`TEST_HBBS=no`、`porta.toml` 里 `[geo] auto_update = false`。
pub struct Server {
    pub dir: tempfile::TempDir,
    child: Child,
    /// `-p` 的值；API 在 P-2。
    pub port: u16,
    pub api: String,
    pub db: SqlitePool,
    http: reqwest::Client,
}

impl Server {
    pub async fn start() -> Self {
        Self::start_with("").await
    }

    /// `extra_toml` 追加到 `porta.toml`（`[geo]` 段已经写好）。
    pub async fn start_with(extra_toml: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port = pick_port();
        std::fs::write(
            dir.path().join("porta.toml"),
            format!("[geo]\nauto_update = false\n\n{extra_toml}\n"),
        )
        .unwrap();
        let db_path = dir.path().join("db_v2.sqlite3");
        let child = spawn(&dir, port);
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let mut server = Self {
            api: format!("http://127.0.0.1:{}", port - 2),
            db: SqlitePoolOptions::new()
                .max_connections(2)
                .connect_lazy_with(
                    SqliteConnectOptions::new()
                        .filename(&db_path)
                        .busy_timeout(Duration::from_secs(5))
                        .foreign_keys(true),
                ),
            dir,
            child,
            port,
            http,
        };
        server.wait_ready().await;
        server
    }

    /// 停掉进程，在同一个工作目录、同一个端口上重新启动（库、密钥文件都保留）；日志接着追加。
    pub async fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.child = spawn(&self.dir, self.port);
        self.wait_ready().await;
    }

    /// API 端口在迁移完成之后才绑定（`start_with_bind`），所以能连上 P-2 就说明库已就绪。
    async fn wait_ready(&mut self) {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port - 2));
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("porta-server exited early ({status}):\n{}", self.log());
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                return;
            }
            if Instant::now() > deadline {
                panic!("porta-server API did not come up on {addr}:\n{}", self.log());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("server.log")).unwrap_or_default()
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    // ---- HTTP ----

    /// 发一个请求。`json_ct`：像客户端那样带 `Content-Type: application/json`（POST 都带，组面板的 GET 不带）。
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Resp {
        self.request_to(&self.api, method, path, token, body, headers).await
    }

    pub async fn request_to(
        &self,
        base: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Resp {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut req = self.http.request(method, format!("{base}{path}"));
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        if let Some(b) = body {
            req = req.header("Content-Type", "application/json").body(b.to_owned());
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = req.send().await.unwrap_or_else(|e| panic!("request {path} failed: {e}\n{}", self.log()));
        let status = resp.status().as_u16();
        let ct = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or_default().to_owned())
            .unwrap_or_default();
        let body = resp.bytes().await.unwrap().to_vec();
        Resp { status, ct, body }
    }

    pub async fn get(&self, path: &str, token: Option<&str>) -> Resp {
        self.request("GET", path, token, None, &[]).await
    }

    pub async fn post(&self, path: &str, token: Option<&str>, body: &str) -> Resp {
        self.request("POST", path, token, Some(body), &[]).await
    }

    pub async fn post_json(&self, path: &str, token: Option<&str>, body: &Value) -> Resp {
        self.post(path, token, &body.to_string()).await
    }

    /// 客户端的登录请求（笔记 03 §2.2）。
    pub async fn login(&self, username: &str, password: &str, id: &str, uuid: &str) -> Resp {
        self.post_json(
            "/api/login",
            None,
            &serde_json::json!({
                "username": username,
                "password": password,
                "id": id,
                "uuid": uuid,
                "autoLogin": true,
                "type": "account",
                "deviceInfo": {"os": "linux", "type": "client", "name": "test-host"},
            }),
        )
        .await
    }

    /// 登录成功并返回令牌。
    pub async fn login_ok(&self, username: &str, password: &str, id: &str, uuid: &str) -> String {
        let r = self.login(username, password, id, uuid).await;
        assert_eq!(r.status, 200, "login {username}: {:?}", r.text());
        r.json()["access_token"]
            .as_str()
            .unwrap_or_else(|| panic!("login {username}: no access_token in {:?}", r.text()))
            .to_owned()
    }

    /// 客户端的心跳请求（笔记 01 §1.4）。
    pub async fn heartbeat(&self, id: &str, uuid: &str, modified_at: i64) -> Resp {
        self.post_json(
            "/api/heartbeat",
            None,
            &serde_json::json!({"id": id, "uuid": uuid, "ver": 1005010, "modified_at": modified_at}),
        )
        .await
    }

    /// 客户端的 sysinfo 请求（笔记 01 §5.2）。
    pub async fn sysinfo(&self, id: &str, uuid: &str) -> Resp {
        self.post_json("/api/sysinfo", None, &sysinfo_body(id, uuid)).await
    }

    // ---- 直接写库（表结构见 migrations/0001_init.sql）----

    pub async fn exec(&self, sql: &str) {
        sqlx::query(sql).execute(&self.db).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    pub async fn scalar_i64(&self, sql: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(sql).fetch_one(&self.db).await.unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    pub async fn count(&self, table: &str) -> i64 {
        self.scalar_i64(&format!("select count(*) from {table}")).await
    }

    /// 建账号：`hash` 原样写进 `password_hash`。
    pub async fn create_user_hash(&self, name: &str, hash: &str, is_admin: bool, status: i64) -> i64 {
        let now = now();
        sqlx::query_scalar(
            "insert into user(name, display_name, email, password_hash, is_admin, status, created_at, updated_at)
             values(?, ?, ?, ?, ?, ?, ?, ?) returning id",
        )
        .bind(name)
        .bind(format!("{name} display"))
        .bind(format!("{name}@example.com"))
        .bind(hash)
        .bind(is_admin as i64)
        .bind(status)
        .bind(now)
        .bind(now)
        .fetch_one(&self.db)
        .await
        .unwrap()
    }

    /// 建启用的账号，密码 argon2id（`""` = 不能用密码登录）。
    pub async fn create_user(&self, name: &str, password: &str, is_admin: bool) -> i64 {
        let hash = if password.is_empty() { String::new() } else { argon2_hash(password) };
        self.create_user_hash(name, &hash, is_admin, 1).await
    }

    /// 直接发一个令牌（32 字节随机数的 base64url，库里存 sha256 hex，§11）。
    pub async fn issue_token(&self, user_id: i64) -> String {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        let token = base64::encode_config(buf, base64::URL_SAFE_NO_PAD);
        let now = now();
        sqlx::query("insert into token(token_hash, user_id, created_at, last_used_at) values(?, ?, ?, ?)")
            .bind(sha256_hex(&token))
            .bind(user_id)
            .bind(now)
            .bind(now)
            .execute(&self.db)
            .await
            .unwrap();
        token
    }

    pub async fn user_id(&self, name: &str) -> i64 {
        sqlx::query_scalar("select id from user where name = ?").bind(name).fetch_one(&self.db).await.unwrap()
    }

    /// hbbs 的 peer 表里登记一台设备（uuid 是原始字节，和 `RegisterPk.uuid` 一样）。
    pub async fn insert_peer(&self, id: &str, uuid: &[u8]) {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        let mut pk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut pk);
        sqlx::query("insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)")
            .bind(guid)
            .bind(id)
            .bind(uuid)
            .bind(pk.to_vec())
            .bind(r#"{"ip":"127.0.0.1"}"#)
            .execute(&self.db)
            .await
            .unwrap();
    }

    /// device 表里放一行（像是已经上报过 sysinfo）。
    pub async fn insert_device(&self, id: &str, user_id: Option<i64>, hostname: &str, username: &str, os: &str) {
        let now = now();
        let sysinfo = serde_json::json!({"id": id, "hostname": hostname, "username": username, "os": os, "version": "1.4.3"});
        sqlx::query(
            "insert into device(id, user_id, hostname, username, os, version, sysinfo, first_seen_at, last_seen_at)
             values(?, ?, ?, ?, ?, '1.4.3', ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(hostname)
        .bind(username)
        .bind(os)
        .bind(sysinfo.to_string())
        .bind(now)
        .bind(now)
        .execute(&self.db)
        .await
        .unwrap();
    }

    pub async fn device_user(&self, id: &str) -> Option<Option<i64>> {
        sqlx::query_scalar::<_, Option<i64>>("select user_id from device where id = ?")
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .unwrap()
    }

    pub async fn create_group(&self, name: &str, share_devices: bool) -> i64 {
        sqlx::query_scalar("insert into user_group(name, share_devices, created_at) values(?, ?, ?) returning id")
            .bind(name)
            .bind(share_devices as i64)
            .bind(now())
            .fetch_one(&self.db)
            .await
            .unwrap()
    }

    pub async fn add_member(&self, group_id: i64, user_id: i64) {
        sqlx::query("insert into group_member(group_id, user_id) values(?, ?)")
            .bind(group_id)
            .bind(user_id)
            .execute(&self.db)
            .await
            .unwrap();
    }

    pub async fn set_option(&self, scope: &str, key: &str, value: &str) {
        sqlx::query("insert or replace into strategy_option(scope, key, value) values(?, ?, ?)")
            .bind(scope)
            .bind(key)
            .bind(value)
            .execute(&self.db)
            .await
            .unwrap();
    }

    pub async fn forget_option(&self, scope: &str, key: &str) {
        sqlx::query("delete from strategy_option where scope = ? and key = ?")
            .bind(scope)
            .bind(key)
            .execute(&self.db)
            .await
            .unwrap();
    }

    /// `strategy repush`：递增 epoch（`device_policy.device_id = '*'` 是全局 epoch）。
    pub async fn bump_epoch(&self, device_id: &str) {
        sqlx::query(
            "insert into device_policy(device_id, strategy_epoch) values(?, 1)
             on conflict(device_id) do update set strategy_epoch = strategy_epoch + 1",
        )
        .bind(device_id)
        .execute(&self.db)
        .await
        .unwrap();
    }

    /// 一行的全部列转成 JSON（列名 → 值；blob 不会出现在这里查的表里）。
    pub async fn rows(&self, sql: &str) -> Vec<serde_json::Map<String, Value>> {
        let rows = sqlx::query(sql).fetch_all(&self.db).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
        rows.iter()
            .map(|row| {
                use sqlx::{Column as _, TypeInfo as _, ValueRef as _};
                let mut m = serde_json::Map::new();
                for (i, col) in row.columns().iter().enumerate() {
                    let raw = row.try_get_raw(i).unwrap();
                    let v = if raw.is_null() {
                        Value::Null
                    } else {
                        match raw.type_info().name() {
                            "INTEGER" => Value::from(row.get::<i64, _>(i)),
                            "REAL" => Value::from(row.get::<f64, _>(i)),
                            _ => Value::from(row.get::<String, _>(i)),
                        }
                    };
                    m.insert(col.name().to_owned(), v);
                }
                m
            })
            .collect()
    }

    // ---- 会合协议 ----

    /// 像被控端那样经 UDP 发 `RegisterPk`（上游 hbbs 的注册路径：写 peer 表并把这台设备标为在线）。
    pub async fn register_online(&self, id: &str, uuid: &[u8]) {
        let mut socket = FramedSocket::new(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port);
        let mut pk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut pk);
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: Bytes::from(uuid.to_vec()),
            pk: Bytes::from(pk.to_vec()),
            ..Default::default()
        });
        socket.send(&msg, target).await.unwrap();
        let Some(Ok((data, _))) = socket.next_timeout(5000).await else {
            panic!("no RegisterPkResponse for {id}:\n{}", self.log());
        };
        let resp = RendezvousMessage::parse_from_bytes(&data).unwrap();
        match resp.union {
            Some(rendezvous_message::Union::RegisterPkResponse(r)) => {
                assert_eq!(r.result.enum_value(), Ok(register_pk_response::Result::OK), "RegisterPk {id}")
            }
            other => panic!("unexpected reply to RegisterPk: {other:?}"),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            let log = self.log();
            let tail: Vec<&str> = log.lines().rev().take(40).collect();
            eprintln!("---- porta-server log (last 40 lines, port {}) ----", self.port);
            for line in tail.iter().rev() {
                eprintln!("{line}");
            }
        }
        if let Ok(mut taken) = TAKEN.lock() {
            if let Some(set) = taken.as_mut() {
                for q in [self.port - 2, self.port - 1, self.port, self.port + 2] {
                    set.remove(&q);
                }
            }
        }
    }
}

/// 客户端 sysinfo 的 body（笔记 01 §5.2、笔记 03 §4.1）。
pub fn sysinfo_body(id: &str, uuid: &str) -> Value {
    serde_json::json!({
        "cpu": "Intel(R) Core(TM) i7, 3.6GHz, 8/4 cores",
        "memory": "15.86GB",
        "os": "windows / Windows 11 Pro - 10.0.26100",
        "hostname": "desk-01",
        "username": "alice",
        "version": "1.4.3",
        "id": id,
        "uuid": uuid,
    })
}

/// 本机一个非回环地址（经它连 API 时，TCP 对端就不是回环）。没有就返回 None。
pub fn non_loopback_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

pub fn get_str<'a>(m: &'a serde_json::Map<String, Value>, k: &str) -> &'a str {
    m.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("column {k} is not text: {m:?}"))
}

pub fn get_i64(m: &serde_json::Map<String, Value>, k: &str) -> i64 {
    m.get(k).and_then(Value::as_i64).unwrap_or_else(|| panic!("column {k} is not integer: {m:?}"))
}
