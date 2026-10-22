//! Helpers for the black-box command line / import tests (`tests/bb_cli.rs`).
//! Everything here talks to a real `porta-server` process (command line mode or server mode) and to
//! its SQLite file; nothing calls into the crate's implementation.

#![allow(dead_code)]

use hbb_common::rand::{Rng as _, RngCore as _};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    SqlitePool,
};
use std::{
    collections::BTreeMap,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use tempfile::TempDir;

pub const SECRET_KEY_FILE: &str = "porta_secret.key";

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_porta-server")
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A temporary working directory with the Porta database inside (`DB_URL` points at it).
pub struct Work {
    pub dir: TempDir,
}

impl Work {
    pub fn new() -> Self {
        Self { dir: tempfile::tempdir().unwrap() }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.path().join("porta.sqlite3")
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.path().join(SECRET_KEY_FILE)
    }

    /// Stands in for "the server was started once here" (PORTA.md §13): base64 of 32 random bytes,
    /// the format `porta_secret.key` uses.
    pub fn write_secret_key(&self) {
        let mut key = [0u8; 32];
        hbb_common::rand::thread_rng().fill_bytes(&mut key);
        std::fs::write(self.key_path(), base64::encode(key)).unwrap();
    }

    /// The migrated Porta database (same migration files the binary embeds, so the command line's own
    /// migration run is a no-op afterwards).
    pub async fn pool(&self) -> SqlitePool {
        let opt = SqliteConnectOptions::new()
            .filename(self.db_path())
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(opt)
            .await
            .unwrap();
        sqlx::migrate::Migrator::new(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")))
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
        pool
    }

    /// `porta-server <args…>` in command line mode, cwd = this directory, `stdin` written then closed.
    pub fn cli(&self, args: &[&str], stdin: &str) -> CliOutput {
        let mut child = Command::new(bin())
            .args(args)
            .current_dir(self.path())
            .env("DB_URL", self.db_path())
            .env("TEST_HBBS", "no")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(mut input) = child.stdin.take() {
            // The command may not read stdin at all; a broken pipe is fine.
            let _ = input.write_all(stdin.as_bytes());
        }
        let out = child.wait_with_output().unwrap();
        CliOutput {
            args: args.iter().map(|s| s.to_string()).collect(),
            status: out.status,
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }
}

pub struct CliOutput {
    pub args: Vec<String>,
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl CliOutput {
    /// stdout + stderr (the logger writes to stdout, error messages may go either way).
    pub fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }

    fn describe(&self) -> String {
        format!(
            "porta-server {:?}: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.args, self.status, self.stdout, self.stderr
        )
    }

    #[track_caller]
    pub fn ok(&self) -> &Self {
        assert!(self.status.success(), "expected success\n{}", self.describe());
        self
    }

    /// "报错退出": a non-zero exit code from an orderly error, not a panic (101) or a signal.
    #[track_caller]
    pub fn refused(&self) -> &Self {
        let code = self.status.code();
        assert!(
            code.is_some() && code != Some(0) && code != Some(101),
            "expected an orderly error exit\n{}",
            self.describe()
        );
        self
    }
}

// ---- Database helpers ----

pub async fn count(db: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sql).fetch_one(db).await.unwrap()
}

/// Inserts an enabled user directly (`password_hash` given verbatim). Returns its id.
pub async fn insert_user(db: &SqlitePool, name: &str, password_hash: &str) -> i64 {
    let t = now();
    sqlx::query_scalar(
        "insert into user(name, password_hash, created_at, updated_at) values(?, ?, ?, ?) returning id",
    )
    .bind(name)
    .bind(password_hash)
    .bind(t)
    .bind(t)
    .fetch_one(db)
    .await
    .unwrap()
}

pub async fn insert_token(db: &SqlitePool, user_id: i64, token_hash: &str) {
    let t = now();
    sqlx::query("insert into token(token_hash, user_id, created_at, last_used_at) values(?, ?, ?, ?)")
        .bind(token_hash)
        .bind(user_id)
        .bind(t)
        .bind(t)
        .execute(db)
        .await
        .unwrap();
}

pub async fn user_id(db: &SqlitePool, name: &str) -> Option<i64> {
    sqlx::query_scalar("select id from user where name = ?")
        .bind(name)
        .fetch_optional(db)
        .await
        .unwrap()
}

pub async fn group_id(db: &SqlitePool, name: &str) -> Option<i64> {
    sqlx::query_scalar("select id from user_group where name = ?")
        .bind(name)
        .fetch_optional(db)
        .await
        .unwrap()
}

pub async fn shared_ab_guid(db: &SqlitePool, name: &str) -> Option<String> {
    sqlx::query_scalar("select guid from ab where personal = 0 and name = ?")
        .bind(name)
        .fetch_optional(db)
        .await
        .unwrap()
}

/// `password_hash` is argon2id and matches `plain`.
pub fn is_argon2id_of(hash: &str, plain: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier as _};
    hash.starts_with("$argon2id$")
        && PasswordHash::new(hash)
            .map(|h| argon2::Argon2::default().verify_password(plain.as_bytes(), &h).is_ok())
            .unwrap_or(false)
}

/// Opens an `sb1:` value with the key file (PORTA.md §13 format: `sb1:` + base64(nonce ‖ ciphertext)).
pub fn decrypt(key_file: &Path, stored: &str) -> String {
    use sodiumoxide::crypto::secretbox;
    let key = base64::decode(std::fs::read_to_string(key_file).unwrap().trim()).unwrap();
    let key = secretbox::Key::from_slice(&key).unwrap();
    let data = base64::decode(stored.strip_prefix("sb1:").expect("value must start with sb1:")).unwrap();
    let (nonce, cipher) = data.split_at(secretbox::NONCEBYTES);
    let nonce = secretbox::Nonce::from_slice(nonce).unwrap();
    String::from_utf8(secretbox::open(cipher, &nonce, &key).expect("decrypts with porta_secret.key"))
        .unwrap()
}

/// PORTA.md §10 `rev`, recomputed from the database rows: sha256 over the canonical JSON of
/// `[effective options sorted by key, global epoch, device epoch]`, first 8 bytes big-endian & i64::MAX, 0 → 1.
pub async fn expected_rev(db: &SqlitePool, device: &str) -> i64 {
    use sha2::{Digest as _, Sha256};
    let mut options = BTreeMap::new();
    for scope in ["*", device] {
        let rows: Vec<(String, String)> =
            sqlx::query_as("select key, value from strategy_option where scope = ?")
                .bind(scope)
                .fetch_all(db)
                .await
                .unwrap();
        options.extend(rows);
    }
    let (ge, de) = (epoch(db, "*").await, epoch(db, device).await);
    let canonical = serde_json::json!([options, ge, de]).to_string();
    let digest = Sha256::digest(canonical.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    match i64::from_be_bytes(first) & i64::MAX {
        0 => 1,
        v => v,
    }
}

/// `device_policy.strategy_epoch` (0 when the row does not exist).
pub async fn epoch(db: &SqlitePool, device: &str) -> i64 {
    sqlx::query_scalar::<_, i64>("select strategy_epoch from device_policy where device_id = ?")
        .bind(device)
        .fetch_optional(db)
        .await
        .unwrap()
        .unwrap_or(0)
}

// ---- Server process ----

/// A running `porta-server` in server mode; killed on drop.
pub struct Server {
    child: Child,
    pub port: u16,
    log: PathBuf,
}

impl Server {
    /// Starts the server in `work` (cwd, `DB_URL`, a `porta.toml` with `[geo] auto_update = false`),
    /// on a random free `-p P` (P-2, P-1, P, P+2 free), and waits until the API port (P-2) accepts.
    pub fn start(work: &Work) -> Self {
        std::fs::write(work.path().join("porta.toml"), "[geo]\nauto_update = false\n").unwrap();
        let port = free_base_port();
        let log = work.path().join(format!("server-{port}.log"));
        let out = std::fs::File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        let child = Command::new(bin())
            .args(["-p", &port.to_string()])
            .current_dir(work.path())
            .env("DB_URL", work.db_path())
            .env("TEST_HBBS", "no")
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn()
            .unwrap();
        let mut server = Self { child, port, log };
        server.wait_ready();
        server
    }

    pub fn api_port(&self) -> u16 {
        self.port - 2
    }

    pub fn api_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.api_port())
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn wait_ready(&mut self) {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.api_port()));
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("porta-server exited early ({status})\n{}", self.log());
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                return;
            }
            if Instant::now() > deadline {
                panic!("API port {} never opened\n{}", self.api_port(), self.log());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A random P with TCP P-2, P-1, P, P+2 and UDP P all free.
fn free_base_port() -> u16 {
    let mut rng = hbb_common::rand::thread_rng();
    for _ in 0..200 {
        let p: u16 = rng.gen_range(20000..60000);
        let tcp_ok = [p - 2, p - 1, p, p + 2]
            .iter()
            .all(|&q| TcpListener::bind((Ipv4Addr::UNSPECIFIED, q)).is_ok());
        if tcp_ok && UdpSocket::bind((Ipv4Addr::UNSPECIFIED, p)).is_ok() {
            return p;
        }
    }
    panic!("no free port range found");
}

/// `POST /api/login` like the client (note 03 §2.2). Returns `(status, parsed body or Null)`.
pub async fn login(server: &Server, username: &str, password: &str) -> (u16, serde_json::Value) {
    let body = serde_json::json!({
        "username": username,
        "password": password,
        "id": "123123123",
        "uuid": "dGVzdC11dWlk",
        "autoLogin": true,
        "type": "account",
        "deviceInfo": {"os": "linux", "type": "client", "name": "test-host"},
    });
    let resp = reqwest::Client::new()
        .post(server.api_url("/api/login"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(serde_json::Value::Null))
}

// ---- Fake rustdesk-api database (note 05 §2, DDL as measured) ----

/// Tables the importer may read, with the measured DDL of note 05 §2 (`versions` from
/// `model/version.go`: IdModel + `version uint not null default 0` + TimeModel).
const RUSTDESK_API_DDL: &str = r#"
CREATE TABLE `users` (`id` integer PRIMARY KEY AUTOINCREMENT,`username` text NOT NULL DEFAULT "",`email` text NOT NULL DEFAULT "",`password` text NOT NULL DEFAULT "",`nickname` text NOT NULL DEFAULT "",`avatar` text NOT NULL DEFAULT "",`group_id` integer NOT NULL DEFAULT 0,`is_admin` numeric NOT NULL DEFAULT false,`status` integer NOT NULL DEFAULT 1,`remark` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);
CREATE INDEX `idx_users_email` ON `users`(`email`);
CREATE INDEX `idx_users_group_id` ON `users`(`group_id`);
CREATE UNIQUE INDEX `idx_users_username` ON `users`(`username`);
CREATE TABLE `groups` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL DEFAULT "",`type` integer NOT NULL DEFAULT 1,`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `address_book_collections` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`name` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);
CREATE INDEX `idx_address_book_collections_user_id` ON `address_book_collections`(`user_id`);
CREATE TABLE `address_book_collection_rules` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`collection_id` integer NOT NULL DEFAULT 0,`rule` integer NOT NULL DEFAULT 0,`type` integer NOT NULL DEFAULT 1,`to_id` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);
CREATE INDEX `idx_address_book_collection_rules_collection_id` ON `address_book_collection_rules`(`collection_id`);
CREATE TABLE `address_books` (`row_id` integer PRIMARY KEY AUTOINCREMENT,`id` text NOT NULL DEFAULT "0",`username` text NOT NULL DEFAULT "",`password` text NOT NULL DEFAULT "",`hostname` text NOT NULL DEFAULT "",`alias` text NOT NULL DEFAULT "",`platform` text NOT NULL DEFAULT "",`tags` text NOT NULL,`hash` text NOT NULL DEFAULT "",`user_id` integer NOT NULL DEFAULT 0,`force_always_relay` numeric NOT NULL DEFAULT false,`rdp_port` text NOT NULL DEFAULT "",`rdp_username` text NOT NULL DEFAULT "",`online` numeric NOT NULL DEFAULT false,`login_name` text NOT NULL DEFAULT "",`same_server` numeric NOT NULL DEFAULT false,`collection_id` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);
CREATE INDEX `idx_address_books_collection_id` ON `address_books`(`collection_id`);
CREATE INDEX `idx_address_books_id` ON `address_books`(`id`);
CREATE INDEX `idx_address_books_user_id` ON `address_books`(`user_id`);
CREATE TABLE `tags` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL DEFAULT "",`user_id` integer NOT NULL DEFAULT 0,`color` integer NOT NULL DEFAULT 0,`collection_id` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);
CREATE INDEX `idx_tags_collection_id` ON `tags`(`collection_id`);
CREATE INDEX `idx_tags_user_id` ON `tags`(`user_id`);
CREATE TABLE `peers` (`row_id` integer PRIMARY KEY AUTOINCREMENT,`id` text NOT NULL DEFAULT "",`cpu` text NOT NULL DEFAULT "",`hostname` text NOT NULL DEFAULT "",`memory` text NOT NULL DEFAULT "",`os` text NOT NULL DEFAULT "",`username` text NOT NULL DEFAULT "",`uuid` text NOT NULL DEFAULT "",`version` text NOT NULL DEFAULT "",`user_id` integer NOT NULL DEFAULT 0,`last_online_time` integer NOT NULL DEFAULT 0,`last_online_ip` text NOT NULL DEFAULT "",`group_id` integer NOT NULL DEFAULT 0,`alias` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `user_tokens` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`device_uuid` text DEFAULT "",`device_id` text DEFAULT "",`token` text NOT NULL DEFAULT "",`expired_at` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `user_thirds` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL,`open_id` text NOT NULL,`name` text,`username` text,`email` text,`verified_email` numeric,`picture` text,`union_id` text NOT NULL DEFAULT "",`third_type` text NOT NULL DEFAULT "",`oauth_type` text NOT NULL DEFAULT "",`op` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `device_groups` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `login_logs` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`client` text,`device_id` text,`uuid` text,`ip` text,`type` text,`platform` text,`user_token_id` integer NOT NULL DEFAULT 0,`is_deleted` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `versions` (`id` integer PRIMARY KEY AUTOINCREMENT,`version` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);
"#;

/// Plain passwords of the fixture users that can log in after the import.
pub const ADMIN_PW: &str = "adminpw1";
pub const BOB_PW: &str = "bobpass1";
pub const ERIN_PW: &str = "erinpw12";
pub const FRANK_PW: &str = "frankpw1";

pub const ADMIN_CREATED: &str = "2026-10-22 18:37:17.4472008+08:00";
pub const FRANK_CREATED: &str = "2025-01-02 03:04:05+00:00";
pub const DAVE_CREATED: &str = "2024-06-01 12:00:00.5+08:00";

pub fn bcrypt_as(plain: &str, version: bcrypt::Version) -> String {
    bcrypt::hash_with_result(plain, 4).unwrap().format_for_version(version)
}

/// rustdesk-api's legacy format: lowercase hex of md5(plain + "rustdesk-api") (note 05 §3.1).
pub fn rustdesk_api_md5(plain: &str) -> String {
    use md5::{Digest as _, Md5};
    Md5::digest(format!("{plain}rustdesk-api").as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The fixture's hashes, kept so tests can compare what was imported.
pub struct Fixture {
    pub path: PathBuf,
    pub admin_hash: String, // $2a$
    pub bob_hash: String,   // 32 lowercase hex
    pub erin_hash: String,  // $2y$
    pub frank_hash: String, // $2b$
}

/// Builds a rustdesk-api database (rollback journal, like rustdesk-api's own DSN) covering every
/// rule of PORTA.md §15. Users (old id → name): 1 admin, 2 bob, 3 carol, 4 dave, 5 erin, 10 frank, 11 hank.
pub async fn build_rustdesk_api(dir: &Path) -> Fixture {
    let path = dir.join("rustdeskapi.db");
    let opt = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Delete);
    let db = SqlitePoolOptions::new().max_connections(1).connect_with(opt).await.unwrap();
    sqlx::raw_sql(RUSTDESK_API_DDL).execute(&db).await.unwrap();

    let fx = Fixture {
        path: path.clone(),
        admin_hash: bcrypt_as(ADMIN_PW, bcrypt::Version::TwoA),
        bob_hash: rustdesk_api_md5(BOB_PW),
        erin_hash: bcrypt_as(ERIN_PW, bcrypt::Version::TwoY),
        frank_hash: bcrypt_as(FRANK_PW, bcrypt::Version::TwoB),
    };

    sqlx::query("INSERT INTO versions(version) VALUES (265)").execute(&db).await.unwrap();

    // users: (id, username, email, password, nickname, avatar, group_id, is_admin, status, remark, created_at)
    let users: Vec<(i64, &str, &str, String, &str, i64, i64, i64, &str, Option<&str>)> = vec![
        (1, "admin", "admin@example.com", fx.admin_hash.clone(), "Admin", 1, 1, 1, "first admin", Some(ADMIN_CREATED)),
        (2, "bob", "", fx.bob_hash.clone(), "Bob", 2, 0, 1, "", None),
        // OAuth-only user (empty password), disabled (2).
        (3, "carol", "carol@example.com", String::new(), "", 7, 0, 2, "", Some("garbage")),
        // 32 hex digits but uppercase: not rustdesk-api's md5 format → ''.
        (4, "dave", "", "0123456789ABCDEF0123456789ABCDEF".to_owned(), "", 2, 0, 1, "", Some(DAVE_CREATED)),
        // Unknown status value 3 → disabled.
        (5, "erin", "", fx.erin_hash.clone(), "", 1, 0, 3, "", None),
        // is_admin 2 (non-zero) → 1.
        (10, "frank", "", fx.frank_hash.clone(), "", 7, 2, 1, "", Some(FRANK_CREATED)),
        // Unrecognizable non-empty password → ''.
        (11, "hank", "", "{SSHA}abcdef".to_owned(), "", 1, 0, 1, "", None),
    ];
    for (id, name, email, pw, nick, gid, admin, status, remark, created) in users {
        sqlx::query(
            "INSERT INTO users(id, username, email, password, nickname, avatar, group_id, is_admin, status, remark, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, 'https://example.com/a.png', ?, ?, ?, ?, ?, ?)",
        )
        .bind(id).bind(name).bind(email).bind(pw).bind(nick).bind(gid).bind(admin).bind(status)
        .bind(remark).bind(created).bind(created)
        .execute(&db).await.unwrap();
    }
    sqlx::query("INSERT INTO user_thirds(user_id, open_id, op, oauth_type) VALUES (3, 'gh-3', 'github', 'github')")
        .execute(&db).await.unwrap();

    // groups: 1 default, 2 share, 3 duplicate name of 1, 4 share group without members.
    // users.group_id 7 has no groups row → placeholder group.
    for (id, name, ty) in [(1, "默认组", 1), (2, "共享组", 2), (3, "默认组", 1), (4, "empty", 2)] {
        sqlx::query("INSERT INTO `groups`(id, name, type) VALUES (?, ?, ?)")
            .bind(id).bind(name).bind(ty)
            .execute(&db).await.unwrap();
    }

    // address_book_collections: (id, owner, name)
    for (id, owner, name) in [
        (1, 1, "Team"),
        (2, 2, "Team"),                // duplicate shared name
        (3, 1, "My address book"),     // reserved
        (4, 2, "Legacy address book"), // reserved
        (5, 99, "Orphan"),             // owner deleted → dropped
        (6, 3, "Carol book"),
    ] {
        sqlx::query("INSERT INTO address_book_collections(id, user_id, name) VALUES (?, ?, ?)")
            .bind(id).bind(owner).bind(name)
            .execute(&db).await.unwrap();
    }

    // address_book_collection_rules: (rule owner user_id, collection_id, rule, type, to_id)
    for (uid, cid, rule, ty, to) in [
        (1, 1, 1, 1, 2),   // bob ro on Team ...
        (1, 1, 2, 1, 2),   // ... and rw: MAX → 2
        (1, 1, 3, 1, 1),   // to the owner → skipped
        (1, 1, 4, 1, 3),   // rule out of 1..3 → skipped
        (2, 1, 3, 1, 4),   // rule.user_id ≠ collection owner → skipped
        (1, 1, 1, 1, 500), // user does not exist → skipped
        (99, 5, 2, 1, 2),  // collection 5 is dropped (owner gone) → skipped
        (1, 99, 2, 1, 2),  // collection does not exist → skipped
        (1, 3, 1, 1, 2),   // bob ro on the renamed "My address book"
        (1, 1, 1, 2, 2),   // group 共享组 ro on Team ...
        (1, 1, 3, 2, 2),   // ... and full: MAX → 3
        (1, 1, 2, 2, 7),   // placeholder group 7 rw on Team
        (1, 1, 2, 2, 88),  // no group 88, nobody in it → skipped
        (3, 6, 2, 2, 4),   // group "empty" rw on Carol book
        (1, 1, 1, 3, 2),   // unknown type → skipped
    ] {
        sqlx::query(
            "INSERT INTO address_book_collection_rules(user_id, collection_id, rule, type, to_id) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(uid).bind(cid).bind(rule).bind(ty).bind(to)
        .execute(&db).await.unwrap();
    }

    // address_books. tags is TEXT on the create path, BLOB after PeerUpdate/BatchUpdateTags (note 05 §5).
    struct Entry {
        id: &'static str,
        user: i64,
        coll: i64,
        tags: Tags,
        hash: &'static str,
        password: &'static str,
        alias: &'static str,
        far: i64,
    }
    enum Tags {
        Text(&'static str),
        Blob(&'static str),
    }
    let entries = [
        // 1: every field filled (the other text fields are set below for this row only)
        Entry { id: "111111111", user: 1, coll: 0, tags: Tags::Text(r#"["t1","t2"]"#), hash: "HASH111", password: "", alias: "a1", far: 1 },
        // 2: duplicate of row 1 → dropped (MIN(row_id) wins)
        Entry { id: "111111111", user: 1, coll: 0, tags: Tags::Text(r#"["dup"]"#), hash: "DUP", password: "", alias: "dup", far: 0 },
        // 3: BLOB tags with non-string elements; a personal entry carrying a password
        Entry { id: "222222222", user: 1, coll: 0, tags: Tags::Blob(r#"["t1",5,null,"t3"]"#), hash: "", password: "plainpw", alias: "", far: 0 },
        Entry { id: "333333333", user: 1, coll: 0, tags: Tags::Text("null"), hash: "", password: "", alias: "", far: 0 },
        Entry { id: "444444444", user: 1, coll: 0, tags: Tags::Blob("null"), hash: "", password: "", alias: "", far: 0 },
        Entry { id: "555555555", user: 1, coll: 0, tags: Tags::Text("not json"), hash: "", password: "", alias: "", far: 0 },
        Entry { id: "666666666", user: 1, coll: 0, tags: Tags::Text(r#"{"a":1}"#), hash: "", password: "", alias: "", far: 0 },
        // empty id → skipped
        Entry { id: "", user: 1, coll: 0, tags: Tags::Text("[]"), hash: "", password: "", alias: "", far: 0 },
        // owner deleted → skipped
        Entry { id: "777777777", user: 99, coll: 0, tags: Tags::Text("[]"), hash: "", password: "", alias: "", far: 0 },
        // bob's personal book
        Entry { id: "111111111", user: 2, coll: 0, tags: Tags::Text("[]"), hash: "HB", password: "", alias: "", far: 0 },
        // Team (admin): shared entry with a plain password
        Entry { id: "888888888", user: 1, coll: 1, tags: Tags::Text(r#"["team"]"#), hash: "", password: "sharedpw", alias: "srv", far: 0 },
        Entry { id: "888888888", user: 1, coll: 1, tags: Tags::Text("[]"), hash: "", password: "dup", alias: "dup", far: 0 },
        // user_id ≠ collection owner → skipped
        Entry { id: "999999999", user: 2, coll: 1, tags: Tags::Text("[]"), hash: "", password: "", alias: "", far: 0 },
        // orphan collection (owner gone) → skipped
        Entry { id: "121212121", user: 99, coll: 5, tags: Tags::Text("[]"), hash: "", password: "", alias: "", far: 0 },
        // bob's Team
        Entry { id: "131313131", user: 2, coll: 2, tags: Tags::Text("[]"), hash: "", password: "", alias: "", far: 0 },
        // collection does not exist → skipped
        Entry { id: "141414141", user: 1, coll: 42, tags: Tags::Text("[]"), hash: "", password: "", alias: "", far: 0 },
    ];
    for (i, e) in entries.iter().enumerate() {
        let first = i == 0;
        let q = sqlx::query(
            "INSERT INTO address_books(id, username, password, hostname, alias, platform, tags, hash, user_id,
               force_always_relay, rdp_port, rdp_username, online, login_name, same_server, collection_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(e.id)
        .bind(if first { "u1" } else { "" })
        .bind(e.password)
        .bind(if first { "h1" } else { "" })
        .bind(e.alias)
        .bind(if first { "Windows" } else { "" });
        let q = match e.tags {
            Tags::Text(s) => q.bind(s),
            Tags::Blob(s) => q.bind(s.as_bytes().to_vec()),
        };
        q.bind(e.hash)
            .bind(e.user)
            .bind(e.far)
            .bind(if first { "3389" } else { "" })
            .bind(if first { "ru" } else { "" })
            .bind(if first { 1 } else { 0 })
            .bind(if first { "ln" } else { "" })
            .bind(if first { 1 } else { 0 })
            .bind(e.coll)
            .execute(&db)
            .await
            .unwrap();
    }

    // tags: (name, user_id, color, collection_id)
    for (name, uid, color, cid) in [
        ("t1", 1, 4280391411i64, 0), // 0xFF2196F3
        ("t1", 1, 1, 0),             // duplicate → dropped (MIN(id) keeps the color above)
        ("t2", 1, 4294967295, 0),    // largest ARGB value
        ("", 1, 5, 0),               // empty name → skipped
        ("team", 1, 7, 1),
        ("orph", 1, 8, 42),          // collection does not exist → skipped
        ("x", 99, 9, 0),             // owner deleted → skipped
        ("wrongowner", 2, 10, 1),    // tag user ≠ collection owner → skipped
        ("bobtag", 2, 16711680, 0),
    ] {
        sqlx::query("INSERT INTO tags(name, user_id, color, collection_id) VALUES (?, ?, ?, ?)")
            .bind(name).bind(uid).bind(color).bind(cid)
            .execute(&db).await.unwrap();
    }

    // peers: (id, uuid, user_id, hostname, os, username, version, last_online_time, last_online_ip)
    for (id, uuid, uid, host, os, user, ver, t, ip) in [
        ("111111111", "uuid-a", 1, "pc1", "windows", "win", "1.4.2", 1700000000i64, "1.2.3.4"),
        ("111111111", "uuid-dup", 2, "dup", "", "", "", 1, "9.9.9.9"), // duplicate id → dropped
        ("222222222", "uuid-b", 0, "pc2", "linux", "lin", "1.3.0", 0, ""),
        ("333333333", "uuid-c", 99, "pc3", "", "", "", 1600000000, "5.6.7.8"),
        ("444444444", "uuid-d", 2, "pc4", "macos", "mac", "1.4.0", 1650000000, "2408:8256::1"),
    ] {
        sqlx::query(
            "INSERT INTO peers(id, uuid, user_id, hostname, os, username, version, last_online_time, last_online_ip)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id).bind(uuid).bind(uid).bind(host).bind(os).bind(user).bind(ver).bind(t).bind(ip)
        .execute(&db).await.unwrap();
    }

    db.close().await;
    fx
}
