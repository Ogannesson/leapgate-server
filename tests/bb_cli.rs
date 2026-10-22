//! 命令行与导入的黑盒测试（PORTA.md §13、§14、§15，笔记 05）。
//!
//! 只依据契约、笔记和上游客户端代码写，不看 `src/cli/`、`src/import.rs` 的实现：以子进程方式跑
//! `porta-server <子命令>`（工作目录是临时目录，`DB_URL` 指向临时库，密码经标准输入传入），
//! 再直接查 SQLite 断言结果；导入后的登录用真实的服务进程走 HTTP。

mod bb_cli_support;

use bb_cli_support::*;
use hbb_common::tokio;
use serde_json::{json, Value};
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use std::collections::{BTreeMap, BTreeSet};

/// 客户端 `Peer.fromJson` 认的键（PORTA.md §15"条目"、§4.2 `ab_peer.data` 不含 id/tags/hash/password）。
const PEER_DATA_KEYS: &[&str] = &[
    "username",
    "hostname",
    "platform",
    "alias",
    "rdpPort",
    "rdpUsername",
    "loginName",
    "forceAlwaysRelay",
];
const RESERVED_BOOK_NAMES: &[&str] = &["My address book", "Legacy address book"];

fn unix(ts: &str) -> i64 {
    chrono::DateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S%.f%:z")
        .unwrap_or_else(|e| panic!("fixture timestamp {ts:?} must parse with the §15 format: {e}"))
        .timestamp()
}

fn src_arg(fx: &Fixture) -> &str {
    fx.path.to_str().unwrap()
}

fn got_token(status: u16, body: &Value) -> bool {
    status == 200
        && body["type"] == "access_token"
        && body["access_token"].as_str().is_some_and(|t| !t.is_empty())
}

async fn password_hash(db: &SqlitePool, name: &str) -> String {
    sqlx::query_scalar("select password_hash from user where name = ?")
        .bind(name)
        .fetch_one(db)
        .await
        .unwrap()
}

async fn tokens_of(db: &SqlitePool, uid: i64) -> i64 {
    sqlx::query_scalar("select count(*) from token where user_id = ?")
        .bind(uid)
        .fetch_one(db)
        .await
        .unwrap()
}

async fn option_value(db: &SqlitePool, scope: &str, key: &str) -> Option<String> {
    sqlx::query_scalar("select value from strategy_option where scope = ? and key = ?")
        .bind(scope)
        .bind(key)
        .fetch_optional(db)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// 自检：这一组不依赖待实现的模块，现在就应通过，用来证明进程管理、请求发送和夹具本身是对的。
// ---------------------------------------------------------------------------------------------

/// 自检：假 rustdesk-api 库按笔记 05 §2 的实测 DDL 建成，笔记 05 §8 / 契约 §15 的读取 SQL 在上面
/// 读出的行数和夹具设计一致；Porta 库迁移后是空的；服务进程能起来，`GET /` 回说明页（§9.4）。
#[tokio::test]
async fn harness_fixture_and_server_process() {
    let work = Work::new();
    let fx = build_rustdesk_api(work.path()).await;
    for ts in [ADMIN_CREATED, FRANK_CREATED, DAVE_CREATED] {
        unix(ts);
    }

    let src = sqlx::SqlitePool::connect_with(
        SqliteConnectOptions::new().filename(&fx.path).read_only(true),
    )
    .await
    .unwrap();
    // 笔记 05 §8.1：7 个用户，password 恰为空串的只有 carol（dave、hank 的值非空但无法识别）。
    assert_eq!(count(&src, "SELECT count(*) FROM users").await, 7);
    assert_eq!(count(&src, "SELECT count(*) FROM users WHERE password = ''").await, 1);
    // 笔记 05 §8.2：主人已删的簿（5）丢弃。
    assert_eq!(
        count(&src, "SELECT count(*) FROM address_book_collections c JOIN users u ON u.id = c.user_id").await,
        5
    );
    // 契约 §15 个人规则 SQL：(1,bob,2)、(3,bob,1)，以及簿 5 的一条（簿 5 没导入，导入器要跳过）。
    assert_eq!(
        count(
            &src,
            "SELECT count(*) FROM (SELECT r.collection_id, r.to_id, MAX(r.rule) FROM address_book_collection_rules r
             JOIN address_book_collections c ON c.id=r.collection_id AND c.user_id=r.user_id
             JOIN users u ON u.id=r.to_id
             WHERE r.type=1 AND r.rule BETWEEN 1 AND 3 AND r.to_id<>c.user_id GROUP BY r.collection_id, r.to_id)"
        )
        .await,
        3
    );
    // 契约 §15 组规则 SQL：(1,g2,3)、(1,g7,2)、(1,g88,2)、(6,g4,2)；g88 由导入器跳过。
    assert_eq!(
        count(
            &src,
            "SELECT count(*) FROM (SELECT r.collection_id, r.to_id, MAX(r.rule) FROM address_book_collection_rules r
             JOIN address_book_collections c ON c.id=r.collection_id AND c.user_id=r.user_id
             WHERE r.type=2 AND r.rule BETWEEN 1 AND 3 GROUP BY r.collection_id, r.to_id)"
        )
        .await,
        4
    );
    // 笔记 05 §8.4：个人簿条目 7 条（admin 6 + bob 1），共享簿条目 2 条。
    assert_eq!(
        count(
            &src,
            "SELECT count(*) FROM address_books a JOIN users u ON u.id = a.user_id
             WHERE a.collection_id = 0 AND a.id <> ''
               AND a.row_id IN (SELECT MIN(row_id) FROM address_books GROUP BY user_id, collection_id, id)"
        )
        .await,
        7
    );
    assert_eq!(
        count(
            &src,
            "SELECT count(*) FROM address_books a
             JOIN address_book_collections c ON c.id = a.collection_id AND c.user_id = a.user_id
             JOIN users u ON u.id = c.user_id
             WHERE a.collection_id > 0 AND a.id <> ''
               AND a.row_id IN (SELECT MIN(row_id) FROM address_books GROUP BY user_id, collection_id, id)"
        )
        .await,
        2
    );
    // 部分行的 tags 是 BLOB（笔记 05 §5），必须 CAST 才能按文本读。
    assert_eq!(count(&src, "SELECT count(*) FROM address_books WHERE typeof(tags) = 'blob'").await, 2);
    // 笔记 05 §8.5：4 个标签。§8.6：去重后 4 台设备。
    assert_eq!(
        count(
            &src,
            "SELECT count(*) FROM tags t JOIN users u ON u.id = t.user_id
             LEFT JOIN address_book_collections c ON c.id = t.collection_id
             WHERE (t.collection_id = 0 OR (c.id IS NOT NULL AND c.user_id = t.user_id)) AND t.name <> ''
               AND t.id IN (SELECT MIN(id) FROM tags GROUP BY user_id, collection_id, name)"
        )
        .await,
        4
    );
    assert_eq!(
        count(&src, "SELECT count(*) FROM peers WHERE row_id IN (SELECT MIN(row_id) FROM peers GROUP BY id)").await,
        4
    );
    src.close().await;

    let db = work.pool().await;
    assert_eq!(count(&db, "select count(*) from user").await, 0);

    let server = Server::start(&work);
    let resp = reqwest::Client::new().get(server.api_url("/")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    assert!(ct.starts_with("text/html"), "content-type {ct}");
    assert!(resp.text().await.unwrap().contains("Porta"));
}

// ---------------------------------------------------------------------------------------------
// §13：命令行只读已有的密钥文件
// ---------------------------------------------------------------------------------------------

/// §13：命令行（含 import）只读已有的 `porta_secret.key`，不存在就报错退出，不生成密钥
/// （否则在别处跑命令行会多出一把密钥，导入的密码解不开）。
#[tokio::test]
async fn cli_without_secret_key_refuses_and_never_creates_one() {
    let work = Work::new();
    let fx = build_rustdesk_api(work.path()).await;
    let db = work.pool().await;

    work.cli(&["import", "rustdesk-api", src_arg(&fx)], "").refused();
    assert!(!work.key_path().exists(), "import must not create porta_secret.key");
    assert_eq!(count(&db, "select count(*) from user").await, 0, "nothing imported");

    // 其他子命令也不能生成密钥（是否因此报错，契约只对"命令行"整体说了报错退出，这里只断言不生成）。
    work.cli(&["user", "add", "zed"], "zedpw123\n");
    work.cli(&["user", "list"], "");
    assert!(!work.key_path().exists(), "command line must never create porta_secret.key");
}

/// 命令行不新建数据库（同 §13 不生成密钥的理由：在别的目录下跑，改动会落进服务看不到的新库）：
/// 库不存在时报错退出，提示里有库的绝对路径和 `DB_URL`，不留下任何库文件；写操作的输出带上所用库的
/// 绝对路径，只读命令不带。
#[tokio::test]
async fn cli_never_creates_the_database_and_writes_name_it() {
    let work = Work::new();
    work.write_secret_key();
    let db_path = work.db_path().display().to_string();

    let out = work.cli(&["user", "add", "zed"], "zedpw123\n");
    out.refused();
    assert!(out.all().contains(&db_path) && out.all().contains("DB_URL"), "{}", out.all());
    work.cli(&["user", "list"], "").refused();
    let left: Vec<_> = std::fs::read_dir(work.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("porta.sqlite3"))
        .collect();
    assert!(left.is_empty(), "command line created {left:?}");

    let db = work.pool().await;
    let out = work.cli(&["user", "add", "zed"], "zedpw123\n");
    out.ok();
    assert!(out.stdout.lines().any(|l| l == format!("Database: {db_path}")), "{}", out.stdout);
    assert!(user_id(&db, "zed").await.is_some());
    let out = work.cli(&["user", "list"], "");
    out.ok();
    assert!(!out.stdout.contains("Database:"), "{}", out.stdout);
}

// ---------------------------------------------------------------------------------------------
// §14：user / group / ab / strategy / device
// ---------------------------------------------------------------------------------------------

/// §14 `user …`；§11 密码 argon2id、改密码和禁用时删掉该用户的令牌；§14 名字不能为空；
/// `user del` 依赖外键级联（§4.1 `foreign_keys` 打开）删掉他名下的簿。
#[tokio::test]
async fn user_commands() {
    let work = Work::new();
    work.write_secret_key();
    let db = work.pool().await;

    work.cli(
        &["user", "add", "alice", "--admin", "--display-name", "Alice A", "--email", "alice@example.com"],
        "alicepw1\n",
    )
    .ok();
    let (dn, email, hash, admin, status): (String, String, String, i64, i64) = sqlx::query_as(
        "select display_name, email, password_hash, is_admin, status from user where name = 'alice'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!((dn.as_str(), email.as_str(), admin, status), ("Alice A", "alice@example.com", 1, 1));
    // 密码从标准输入读一行：不含换行符，存 argon2id（§11、§14）。
    assert!(is_argon2id_of(&hash, "alicepw1"), "hash {hash}");

    work.cli(&["user", "add", "bob"], "bobpw123\n").ok();
    let (admin, status): (i64, i64) =
        sqlx::query_as("select is_admin, status from user where name = 'bob'").fetch_one(&db).await.unwrap();
    assert_eq!((admin, status), (0, 1));
    assert!(is_argon2id_of(&password_hash(&db, "bob").await, "bobpw123"));

    // §14 名字校验：用户名不能为空。
    work.cli(&["user", "add", ""], "emptypw1\n").refused();
    assert_eq!(count(&db, "select count(*) from user where name = ''").await, 0);
    // 登录名唯一（§4.2 `name unique`）：重复添加报错，原密码不变。
    work.cli(&["user", "add", "alice"], "otherpw1\n").refused();
    assert!(is_argon2id_of(&password_hash(&db, "alice").await, "alicepw1"));

    let out = work.cli(&["user", "list"], "");
    out.ok();
    assert!(out.stdout.contains("alice") && out.stdout.contains("bob"), "{}", out.stdout);

    let alice = user_id(&db, "alice").await.unwrap();
    let bob = user_id(&db, "bob").await.unwrap();
    insert_token(&db, alice, "aa01").await;
    insert_token(&db, alice, "aa02").await;
    insert_token(&db, bob, "bb01").await;

    // §11：改密码删掉该用户的令牌，别人的不动。
    work.cli(&["user", "passwd", "alice"], "newpw456\n").ok();
    let hash = password_hash(&db, "alice").await;
    assert!(is_argon2id_of(&hash, "newpw456") && !is_argon2id_of(&hash, "alicepw1"));
    assert_eq!(tokens_of(&db, alice).await, 0);
    assert_eq!(tokens_of(&db, bob).await, 1);
    work.cli(&["user", "passwd", "nobody"], "whatever1\n").refused();

    // §11：禁用账号删掉令牌；§4.2 status 1 正常 / 0 禁用。
    work.cli(&["user", "disable", "bob"], "").ok();
    let st: i64 = sqlx::query_scalar("select status from user where id = ?").bind(bob).fetch_one(&db).await.unwrap();
    assert_eq!(st, 0);
    assert_eq!(tokens_of(&db, bob).await, 0);
    work.cli(&["user", "enable", "bob"], "").ok();
    let st: i64 = sqlx::query_scalar("select status from user where id = ?").bind(bob).fetch_one(&db).await.unwrap();
    assert_eq!(st, 1);

    work.cli(&["user", "admin", "bob", "on"], "").ok();
    let a: i64 = sqlx::query_scalar("select is_admin from user where id = ?").bind(bob).fetch_one(&db).await.unwrap();
    assert_eq!(a, 1);
    work.cli(&["user", "admin", "bob", "off"], "").ok();
    let a: i64 = sqlx::query_scalar("select is_admin from user where id = ?").bind(bob).fetch_one(&db).await.unwrap();
    assert_eq!(a, 0);

    // `user del`：用户和他名下的共享簿（ab.owner_id on delete cascade）一起没了。
    let t = now();
    sqlx::query("insert into ab(guid, name, owner_id, personal, created_at, updated_at) values(?, 'BobBook', ?, 0, ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(bob)
        .bind(t)
        .bind(t)
        .execute(&db)
        .await
        .unwrap();
    work.cli(&["user", "del", "bob"], "").ok();
    assert_eq!(user_id(&db, "bob").await, None);
    assert_eq!(shared_ab_guid(&db, "BobBook").await, None);
    assert!(user_id(&db, "alice").await.is_some());
}

/// §14 `group …`；§12.2 一个用户可以在多个组里，成员关系在 `group_member`；§14 组名不能为空。
#[tokio::test]
async fn group_commands() {
    let work = Work::new();
    work.write_secret_key();
    let db = work.pool().await;
    let alice = insert_user(&db, "alice", "").await;
    let bob = insert_user(&db, "bob", "").await;

    work.cli(&["group", "add", "ops", "--share-devices"], "").ok();
    work.cli(&["group", "add", "dev"], "").ok();
    let share: Vec<(String, i64)> =
        sqlx::query_as("select name, share_devices from user_group order by name").fetch_all(&db).await.unwrap();
    assert_eq!(share, vec![("dev".to_owned(), 0), ("ops".to_owned(), 1)]);

    // §14 名字校验：组名不能为空；组名唯一（§4.2）。
    work.cli(&["group", "add", ""], "").refused();
    work.cli(&["group", "add", "ops"], "").refused();
    assert_eq!(count(&db, "select count(*) from user_group").await, 2);

    let ops = group_id(&db, "ops").await.unwrap();
    let dev = group_id(&db, "dev").await.unwrap();
    work.cli(&["group", "member", "add", "ops", "alice"], "").ok();
    work.cli(&["group", "member", "add", "ops", "bob"], "").ok();
    work.cli(&["group", "member", "add", "dev", "alice"], "").ok();
    work.cli(&["group", "member", "add", "ops", "nobody"], "").refused();
    work.cli(&["group", "member", "add", "nogroup", "alice"], "").refused();
    let members: BTreeSet<(i64, i64)> = sqlx::query_as("select group_id, user_id from group_member")
        .fetch_all(&db)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(members, BTreeSet::from([(ops, alice), (ops, bob), (dev, alice)]));

    work.cli(&["group", "member", "rm", "ops", "bob"], "").ok();
    let members: BTreeSet<(i64, i64)> = sqlx::query_as("select group_id, user_id from group_member")
        .fetch_all(&db)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(members, BTreeSet::from([(ops, alice), (dev, alice)]));

    let out = work.cli(&["group", "list"], "");
    out.ok();
    assert!(out.stdout.contains("ops") && out.stdout.contains("dev"), "{}", out.stdout);

    // 删组：成员关系级联删除，用户还在。
    work.cli(&["group", "del", "ops"], "").ok();
    assert_eq!(group_id(&db, "ops").await, None);
    assert_eq!(count(&db, &format!("select count(*) from group_member where group_id = {ops}")).await, 0);
    assert!(user_id(&db, "alice").await.is_some());
}

/// §14 `ab …`；§12.1 共享簿名全局唯一、不能叫 `My address book` / `Legacy address book`、不能为空；
/// §4.2 `ab.guid` 是 UUIDv4 字符串、`ab_rule.rule` 1 只读 / 2 读写 / 3 完全控制。
#[tokio::test]
async fn ab_commands() {
    let work = Work::new();
    work.write_secret_key();
    let db = work.pool().await;
    let alice = insert_user(&db, "alice", "").await;
    let bob = insert_user(&db, "bob", "").await;
    sqlx::query("insert into user_group(name, created_at) values('team', ?)").bind(now()).execute(&db).await.unwrap();
    let team = group_id(&db, "team").await.unwrap();
    // alice 已有一本个人簿（名字固定 My address book，§12.1）。
    let t = now();
    sqlx::query("insert into ab(guid, name, owner_id, personal, created_at, updated_at) values(?, 'My address book', ?, 1, ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(alice)
        .bind(t)
        .bind(t)
        .execute(&db)
        .await
        .unwrap();

    work.cli(&["ab", "create", "Servers", "--owner", "alice", "--note", "prod boxes"], "").ok();
    let (guid, owner, personal, note): (String, i64, i64, String) =
        sqlx::query_as("select guid, owner_id, personal, note from ab where name = 'Servers'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!((owner, personal, note.as_str()), (alice, 0, "prod boxes"));
    let parsed = uuid::Uuid::parse_str(&guid).unwrap_or_else(|e| panic!("guid {guid}: {e}"));
    assert_eq!(parsed.get_version_num(), 4, "guid {guid}");

    // §14 名字校验。
    for bad in ["", "My address book", "Legacy address book"] {
        work.cli(&["ab", "create", bad, "--owner", "alice"], "").refused();
    }
    // 共享簿重名（主人不同也不行）。
    work.cli(&["ab", "create", "Servers", "--owner", "bob"], "").refused();
    work.cli(&["ab", "create", "Ghost", "--owner", "nobody"], "").refused();
    assert_eq!(count(&db, "select count(*) from ab where personal = 0").await, 1);

    work.cli(&["ab", "create", "Other", "--owner", "bob"], "").ok();
    // 改名同样受名字校验约束。
    for bad in ["", "My address book", "Legacy address book", "Other"] {
        work.cli(&["ab", "rename", "Servers", bad], "").refused();
    }
    work.cli(&["ab", "rename", "Servers", "Servers2"], "").ok();
    assert_eq!(shared_ab_guid(&db, "Servers2").await.as_deref(), Some(guid.as_str()));
    assert_eq!(shared_ab_guid(&db, "Servers").await, None);

    let rules = |db: SqlitePool, guid: String| async move {
        sqlx::query_as::<_, (Option<i64>, Option<i64>, i64)>(
            "select user_id, group_id, rule from ab_rule where ab_guid = ? order by user_id, group_id",
        )
        .bind(guid)
        .fetch_all(&db)
        .await
        .unwrap()
    };
    work.cli(&["ab", "grant", "Servers2", "--user", "bob", "ro"], "").ok();
    assert_eq!(rules(db.clone(), guid.clone()).await, vec![(Some(bob), None, 1)]);
    // 再授一次是改级别，不是多一条（§4.2 每本簿每人一条规则）。
    work.cli(&["ab", "grant", "Servers2", "--user", "bob", "rw"], "").ok();
    assert_eq!(rules(db.clone(), guid.clone()).await, vec![(Some(bob), None, 2)]);
    work.cli(&["ab", "grant", "Servers2", "--group", "team", "full"], "").ok();
    let mut got = rules(db.clone(), guid.clone()).await;
    got.sort();
    assert_eq!(got, vec![(None, Some(team), 3), (Some(bob), None, 2)]);
    work.cli(&["ab", "grant", "Servers2", "--user", "nobody", "ro"], "").refused();
    work.cli(&["ab", "grant", "Servers2", "--group", "nogroup", "ro"], "").refused();

    let out = work.cli(&["ab", "list"], "");
    out.ok();
    assert!(out.stdout.contains("Servers2") && out.stdout.contains("Other"), "{}", out.stdout);

    work.cli(&["ab", "revoke", "Servers2", "--user", "bob"], "").ok();
    assert_eq!(rules(db.clone(), guid.clone()).await, vec![(None, Some(team), 3)]);
    work.cli(&["ab", "revoke", "Servers2", "--group", "team"], "").ok();
    assert!(rules(db.clone(), guid.clone()).await.is_empty());

    // 删簿：条目、规则级联删除；别的簿不动。
    work.cli(&["ab", "grant", "Servers2", "--user", "bob", "ro"], "").ok();
    sqlx::query("insert into ab_peer(ab_guid, id, created_at, updated_at) values(?, '123456789', ?, ?)")
        .bind(&guid)
        .bind(t)
        .bind(t)
        .execute(&db)
        .await
        .unwrap();
    work.cli(&["ab", "del", "Servers2"], "").ok();
    assert_eq!(shared_ab_guid(&db, "Servers2").await, None);
    assert_eq!(count(&db, &format!("select count(*) from ab_rule where ab_guid = '{guid}'")).await, 0);
    assert_eq!(count(&db, &format!("select count(*) from ab_peer where ab_guid = '{guid}'")).await, 0);
    assert!(shared_ab_guid(&db, "Other").await.is_some());
    assert_eq!(count(&db, "select count(*) from ab where personal = 1").await, 1);
}

/// §14 `strategy …`、§10：`set` 写行；`unset` 写墓碑 `''`（设备级墓碑照样覆盖全局值）；`forget` 删行；
/// `repush` 递增 epoch（`'*'` 存全局 epoch）；`show` 列出生效选项和 rev。
#[tokio::test]
async fn strategy_commands() {
    let work = Work::new();
    work.write_secret_key();
    let db = work.pool().await;
    const DEV: &str = "123456789";

    work.cli(&["strategy", "set", "*", "k1", "v1"], "").ok();
    work.cli(&["strategy", "set", DEV, "k1", "v2"], "").ok();
    assert_eq!(option_value(&db, "*", "k1").await.as_deref(), Some("v1"));
    assert_eq!(option_value(&db, DEV, "k1").await.as_deref(), Some("v2"));
    // 迁移种下的全局墓碑（§4.2）不受影响。
    assert_eq!(option_value(&db, "*", "relay-server").await.as_deref(), Some(""));

    let out = work.cli(&["strategy", "show", DEV], "");
    out.ok();
    let rev = expected_rev(&db, DEV).await;
    assert!(
        out.stdout.contains("k1") && out.stdout.contains("v2") && out.stdout.contains(&rev.to_string()),
        "show must list effective options and rev {rev}:\n{}",
        out.stdout
    );
    let out = work.cli(&["strategy", "show"], "");
    out.ok();
    assert!(out.stdout.contains("relay-server") && out.stdout.contains("k1"), "{}", out.stdout);

    // unset：写成墓碑，行还在。
    work.cli(&["strategy", "unset", DEV, "k1"], "").ok();
    assert_eq!(option_value(&db, DEV, "k1").await.as_deref(), Some(""));
    // forget：删行，设备级回到全局值。
    work.cli(&["strategy", "forget", DEV, "k1"], "").ok();
    assert_eq!(option_value(&db, DEV, "k1").await, None);
    assert_eq!(option_value(&db, "*", "k1").await.as_deref(), Some("v1"));

    // 只有全局值时 unset 设备：建设备级墓碑，让这台设备删掉这个键（§10），全局值不动。
    work.cli(&["strategy", "set", "*", "k2", "v3"], "").ok();
    work.cli(&["strategy", "unset", DEV, "k2"], "").ok();
    assert_eq!(option_value(&db, DEV, "k2").await.as_deref(), Some(""));
    assert_eq!(option_value(&db, "*", "k2").await.as_deref(), Some("v3"));

    work.cli(&["strategy", "unset", "*", "k1"], "").ok();
    assert_eq!(option_value(&db, "*", "k1").await.as_deref(), Some(""));
    work.cli(&["strategy", "forget", "*", "k1"], "").ok();
    assert_eq!(option_value(&db, "*", "k1").await, None);

    // repush：epoch 递增，设备和全局分开记。
    work.cli(&["strategy", "repush", DEV], "").ok();
    work.cli(&["strategy", "repush", DEV], "").ok();
    assert_eq!(epoch(&db, DEV).await, 2);
    assert_eq!(epoch(&db, "*").await, 0);
    work.cli(&["strategy", "repush", "*"], "").ok();
    assert_eq!(epoch(&db, "*").await, 1);
    assert_eq!(epoch(&db, DEV).await, 2);

    let new_rev = expected_rev(&db, DEV).await;
    assert_ne!(new_rev, rev);
    let out = work.cli(&["strategy", "show", DEV], "");
    out.ok();
    assert!(out.stdout.contains(&new_rev.to_string()), "rev {new_rev}:\n{}", out.stdout);
}

/// §14 `device list [--legacy]`、`device pin-relay <device> <host|none>`：
/// - list 列 id、主机名、账号、客户端类型和版本；`--legacy` 只列原版客户端，并列出 `conn_attempt` 里出现过、
///   `device` 表里没有的 id（`b_id` 配 `b_version`；`a_device_id` 非空时配 `a_version`）。
/// - pin-relay 写 `device_policy.relay_pin`，`none` 写 `''`；不能动同一行的 `strategy_epoch`（反之 repush 也不能动 pin）。
#[tokio::test]
async fn device_commands() {
    let work = Work::new();
    work.write_secret_key();
    let db = work.pool().await;
    let alice = insert_user(&db, "alice", "").await;
    const D1: &str = "111222333"; // 原版客户端，归 alice
    const D2: &str = "987654321"; // Porta 客户端
    let t = now();
    for (id, uid, host, ver, ty) in [
        (D1, Some(alice), "host-d1", "1.4.2", "rustdesk"),
        (D2, None, "host-d2", "0.1.0", "porta"),
    ] {
        sqlx::query(
            "insert into device(id, user_id, hostname, version, client_type, first_seen_at, last_seen_at)
             values(?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(uid)
        .bind(host)
        .bind(ver)
        .bind(ty)
        .bind(t)
        .bind(t)
        .execute(&db)
        .await
        .unwrap();
    }
    // (b_id, b_version, a_device_id, a_version)
    for (b_id, b_ver, a_dev, a_ver) in [
        ("555000555", Some("1.3.9"), None, Some("1.4.0")), // 只见于会合的被控端
        (D1, Some("1.4.2"), Some("666000666"), Some("1.2.0")), // 只见于会合的控制端
        (D2, Some("0.1.0"), None, None),
    ] {
        sqlx::query(
            "insert into conn_attempt(started_at, a_ip, a_port, via, a_device_id, a_version, b_id, conn_type,
               a_nat_type, a_force_relay, a_has_v6, signal, server_forced_relay, b_version)
             values(?, '1.2.3.4', 1000, 'tcp', ?, ?, ?, 0, 0, 0, 0, 'punch_hole', 0, ?)",
        )
        .bind(t * 1000)
        .bind(a_dev)
        .bind(a_ver)
        .bind(b_id)
        .bind(b_ver)
        .execute(&db)
        .await
        .unwrap();
    }

    let out = work.cli(&["device", "list"], "");
    out.ok();
    for s in [D1, "host-d1", "alice", "rustdesk", "1.4.2", D2, "host-d2", "porta", "0.1.0"] {
        assert!(out.stdout.contains(s), "device list lacks {s:?}:\n{}", out.stdout);
    }

    let out = work.cli(&["device", "list", "--legacy"], "");
    out.ok();
    for s in [D1, "host-d1", "555000555", "1.3.9", "666000666", "1.2.0"] {
        assert!(out.stdout.contains(s), "device list --legacy lacks {s:?}:\n{}", out.stdout);
    }
    for s in [D2, "host-d2"] {
        assert!(!out.stdout.contains(s), "device list --legacy must not list the Porta client {s:?}:\n{}", out.stdout);
    }

    let pin = |db: SqlitePool| async move {
        sqlx::query_as::<_, (String, i64)>("select relay_pin, strategy_epoch from device_policy where device_id = ?")
            .bind(D1)
            .fetch_one(&db)
            .await
            .unwrap()
    };
    work.cli(&["strategy", "repush", D1], "").ok();
    work.cli(&["device", "pin-relay", D1, "relay9.example.com:21117"], "").ok();
    assert_eq!(pin(db.clone()).await, ("relay9.example.com:21117".to_owned(), 1));
    work.cli(&["strategy", "repush", D1], "").ok();
    assert_eq!(pin(db.clone()).await, ("relay9.example.com:21117".to_owned(), 2));
    work.cli(&["device", "pin-relay", D1, "none"], "").ok();
    assert_eq!(pin(db.clone()).await, (String::new(), 2));
}

// ---------------------------------------------------------------------------------------------
// §15：从 rustdesk-api 导入
// ---------------------------------------------------------------------------------------------

/// §15 全部规则，逐项查 Porta 库（夹具见 `bb_cli_support::build_rustdesk_api`，每行的用意写在那里）。
#[tokio::test]
async fn import_rustdesk_api_applies_section_15() {
    let work = Work::new();
    work.write_secret_key();
    let fx = build_rustdesk_api(work.path()).await;
    let (admin_created, frank_created, dave_created) = (unix(ADMIN_CREATED), unix(FRANK_CREATED), unix(DAVE_CREATED));
    let db = work.pool().await;

    let src_before = std::fs::read(&fx.path).unwrap();
    let t0 = now();
    let out = work.cli(&["import", "rustdesk-api", src_arg(&fx)], "");
    let t1 = now();
    out.ok();
    let in_import = |t: i64| (t0..=t1).contains(&t);
    // §15：只读打开源库。
    assert!(std::fs::read(&fx.path).unwrap() == src_before, "rustdesk-api database was modified");
    // §15：结束时打印所用密钥文件的绝对路径。
    let key = work.key_path();
    assert!(out.all().contains(key.to_str().unwrap()), "key path not printed:\n{}", out.all());
    // §15：密码为 '' 的用户打印清单（carol 原本为空，dave、hank 的值无法识别）。
    for name in ["carol", "dave", "hank"] {
        assert!(out.all().contains(name), "empty-password list lacks {name}:\n{}", out.all());
    }

    // ---- 用户：字段映射、状态映射、is_admin、created_at、密码转换（§15"用户""密码"）----
    let users: BTreeMap<String, (String, String, String, String, i64, i64, i64)> = sqlx::query_as::<
        _,
        (String, String, String, String, String, i64, i64, i64),
    >(
        "select name, display_name, email, note, password_hash, is_admin, status, created_at from user",
    )
    .fetch_all(&db)
    .await
    .unwrap()
    .into_iter()
    .map(|(n, d, e, no, p, a, s, c)| (n, (d, e, no, p, a, s, c)))
    .collect();
    assert_eq!(
        users.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["admin", "bob", "carol", "dave", "erin", "frank", "hank"]
    );
    let u = |n: &str| users[n].clone();
    assert_eq!(
        u("admin"),
        ("Admin".into(), "admin@example.com".into(), "first admin".into(), fx.admin_hash.clone(), 1, 1, admin_created)
    );
    let bob = u("bob");
    assert_eq!((bob.0.as_str(), bob.3.clone(), bob.4, bob.5), ("Bob", format!("md5:{}", fx.bob_hash), 0, 1));
    assert!(in_import(bob.6), "NULL created_at → import time");
    let carol = u("carol");
    assert_eq!((carol.3.as_str(), carol.4, carol.5), ("", 0, 0), "OAuth-only, status 2 → 0");
    assert!(in_import(carol.6), "unparsable created_at → import time");
    let dave = u("dave");
    assert_eq!((dave.3.as_str(), dave.5, dave.6), ("", 1, dave_created), "uppercase hex is not md5 format");
    let erin = u("erin");
    assert_eq!((erin.3.clone(), erin.5), (fx.erin_hash.clone(), 0), "$2y$ kept verbatim; status 3 → 0");
    let frank = u("frank");
    assert_eq!((frank.3.clone(), frank.4, frank.5, frank.6), (fx.frank_hash.clone(), 1, 1, frank_created));
    let hank = u("hank");
    assert_eq!((hank.3.as_str(), hank.5), ("", 1), "unrecognizable password → ''");
    // 令牌、登录日志、审计不导入。
    assert_eq!(count(&db, "select count(*) from token").await, 0);
    assert_eq!(count(&db, "select count(*) from audit_conn").await, 0);

    // ---- 用户组：groups 行 ∪ 占位组、type=2 → share_devices、重名改名、成员（§15"用户组"）----
    let groups: BTreeMap<String, i64> = sqlx::query_as::<_, (String, i64)>("select name, share_devices from user_group")
        .fetch_all(&db)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        groups,
        BTreeMap::from([
            ("默认组".to_owned(), 0),
            ("共享组".to_owned(), 1),
            ("默认组-3".to_owned(), 0),
            ("empty".to_owned(), 1),
            ("rustdesk-api-group-7".to_owned(), 0),
        ])
    );
    assert_eq!(count(&db, &format!("select count(*) from user_group where created_at not between {t0} and {t1}")).await, 0);
    let members: BTreeSet<(String, String)> = sqlx::query_as(
        "select g.name, u.name from group_member m join user_group g on g.id = m.group_id join user u on u.id = m.user_id",
    )
    .fetch_all(&db)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let expect_members: BTreeSet<(String, String)> = [
        ("默认组", "admin"),
        ("默认组", "erin"),
        ("默认组", "hank"),
        ("共享组", "bob"),
        ("共享组", "dave"),
        ("rustdesk-api-group-7", "carol"),
        ("rustdesk-api-group-7", "frank"),
    ]
    .into_iter()
    .map(|(g, u)| (g.to_owned(), u.to_owned()))
    .collect();
    assert_eq!(members, expect_members);

    // ---- 簿：个人簿、共享簿、保留名和重名改名（§15"清洗"、§12.1）----
    let personal: BTreeMap<String, (String, String)> = sqlx::query_as::<_, (String, String, String)>(
        "select u.name, ab.guid, ab.name from ab join user u on u.id = ab.owner_id where ab.personal = 1",
    )
    .fetch_all(&db)
    .await
    .unwrap()
    .into_iter()
    .map(|(u, g, n)| (u, (g, n)))
    .collect();
    for owner in ["admin", "bob"] {
        assert_eq!(personal[owner].1, "My address book", "personal book of {owner}");
    }
    let admin_personal = personal["admin"].0.clone();
    let bob_personal = personal["bob"].0.clone();

    let shared: Vec<(String, String, String)> = sqlx::query_as(
        "select ab.guid, ab.name, u.name from ab join user u on u.id = ab.owner_id where ab.personal = 0",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(shared.len(), 5, "collection 5 (owner deleted) is dropped: {shared:?}");
    let names: BTreeSet<&str> = shared.iter().map(|s| s.1.as_str()).collect();
    assert_eq!(names.len(), 5, "shared names must be unique: {shared:?}");
    for reserved in RESERVED_BOOK_NAMES {
        assert!(!names.contains(reserved), "reserved name {reserved} must be renamed: {shared:?}");
    }
    assert!(names.contains("Team") && names.contains("Carol book"), "{shared:?}");
    assert!(shared.iter().any(|s| s.1 == "Carol book" && s.2 == "carol"));
    let all_books: Vec<(String, i64, i64)> =
        sqlx::query_as("select guid, created_at, updated_at from ab").fetch_all(&db).await.unwrap();
    for (guid, c, u) in &all_books {
        let parsed = uuid::Uuid::parse_str(guid).unwrap_or_else(|e| panic!("guid {guid}: {e}"));
        assert_eq!(parsed.get_version_num(), 4, "guid {guid}");
        assert!(in_import(*c) && in_import(*u), "ab times are import time");
    }

    // ---- 条目：去重、孤儿、键名、tags 清洗、密码哈希加密（§15"条目""清洗"、§13）----
    let peers: Vec<(String, String, String, String, String, String, i64, i64)> = sqlx::query_as(
        "select ab_guid, id, data, tags, hash_enc, password_enc, created_at, updated_at from ab_peer",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(peers.len(), 9, "{peers:?}");
    let book_of = |id: &str, owner: &str| -> String {
        let owner_books: Vec<&String> = shared.iter().filter(|s| s.2 == owner).map(|s| &s.0).collect();
        peers
            .iter()
            .find(|p| p.1 == id && owner_books.contains(&&p.0))
            .unwrap_or_else(|| panic!("entry {id} not found in a shared book of {owner}"))
            .0
            .clone()
    };
    let admin_team = book_of("888888888", "admin");
    let bob_team = book_of("131313131", "bob");
    let other_of = |owner: &str, not: &str| -> String {
        let v: Vec<&(String, String, String)> = shared.iter().filter(|s| s.2 == owner && s.0 != not).collect();
        assert_eq!(v.len(), 1, "{owner} should own exactly one more shared book: {shared:?}");
        v[0].0.clone()
    };
    let admin_renamed = other_of("admin", &admin_team); // 原名 My address book
    let bob_renamed = other_of("bob", &bob_team); // 原名 Legacy address book
    let carol_book = shared.iter().find(|s| s.1 == "Carol book").unwrap().0.clone();

    let ids_in = |guid: &str| -> BTreeSet<String> {
        peers.iter().filter(|p| p.0 == guid).map(|p| p.1.clone()).collect()
    };
    let set = |v: &[&str]| -> BTreeSet<String> { v.iter().map(|s| s.to_string()).collect() };
    assert_eq!(
        ids_in(&admin_personal),
        set(&["111111111", "222222222", "333333333", "444444444", "555555555", "666666666"])
    );
    assert_eq!(ids_in(&bob_personal), set(&["111111111"]));
    assert_eq!(ids_in(&admin_team), set(&["888888888"]));
    assert_eq!(ids_in(&bob_team), set(&["131313131"]));
    assert!(ids_in(&admin_renamed).is_empty() && ids_in(&bob_renamed).is_empty() && ids_in(&carol_book).is_empty());

    for (guid, id, data, tags, hash_enc, password_enc, c, u) in &peers {
        let data: Value = serde_json::from_str(data).unwrap_or_else(|e| panic!("{guid}/{id} data: {e}"));
        let obj = data.as_object().unwrap_or_else(|| panic!("{guid}/{id} data is not an object"));
        for k in obj.keys() {
            assert!(PEER_DATA_KEYS.contains(&k.as_str()), "{guid}/{id}: unexpected data key {k}");
        }
        for (k, v) in obj {
            assert!(v.is_string(), "{guid}/{id}: data.{k} must be a string, got {v}");
        }
        let far = obj.get("forceAlwaysRelay").and_then(Value::as_str);
        assert!(matches!(far, Some("true") | Some("false")), "{guid}/{id}: forceAlwaysRelay {far:?}");
        let tags: Value = serde_json::from_str(tags).unwrap_or_else(|e| panic!("{guid}/{id} tags: {e}"));
        assert!(tags.as_array().is_some_and(|a| a.iter().all(Value::is_string)), "{guid}/{id} tags {tags}");
        for enc in [hash_enc, password_enc] {
            assert!(enc.is_empty() || enc.starts_with("sb1:"), "{guid}/{id}: not encrypted: {enc}");
        }
        assert!(in_import(*c) && in_import(*u));
    }
    let entry = |guid: &str, id: &str| peers.iter().find(|p| p.0 == guid && p.1 == id).unwrap().clone();

    let e = entry(&admin_personal, "111111111");
    assert_eq!(
        serde_json::from_str::<Value>(&e.2).unwrap(),
        json!({"username": "u1", "hostname": "h1", "platform": "Windows", "alias": "a1",
               "rdpPort": "3389", "rdpUsername": "ru", "loginName": "ln", "forceAlwaysRelay": "true"}),
        "row_id 1 wins over its duplicate; same_server/online are not written"
    );
    assert_eq!(serde_json::from_str::<Value>(&e.3).unwrap(), json!(["t1", "t2"]));
    assert_eq!(decrypt(&key, &e.4), "HASH111");
    assert_eq!(e.5, "");

    let e = entry(&admin_personal, "222222222");
    assert_eq!(serde_json::from_str::<Value>(&e.3).unwrap(), json!(["t1", "t3"]), "BLOB tags, strings only");
    assert_eq!(serde_json::from_str::<Value>(&e.2).unwrap()["forceAlwaysRelay"], "false");
    assert_eq!(e.4, "");
    assert_eq!(decrypt(&key, &e.5), "plainpw");
    for id in ["333333333", "444444444", "555555555", "666666666"] {
        let e = entry(&admin_personal, id);
        assert_eq!(serde_json::from_str::<Value>(&e.3).unwrap(), json!([]), "{id}: null/bad tags → []");
    }
    let e = entry(&bob_personal, "111111111");
    assert_eq!(decrypt(&key, &e.4), "HB");
    let e = entry(&admin_team, "888888888");
    assert_eq!(serde_json::from_str::<Value>(&e.2).unwrap()["alias"], "srv");
    assert_eq!(serde_json::from_str::<Value>(&e.3).unwrap(), json!(["team"]));
    assert_eq!(e.4, "");
    assert_eq!(decrypt(&key, &e.5), "sharedpw");

    // ---- 标签：重复取 MIN(id)、空名和孤儿丢弃、颜色按 i64（§15"清洗"、笔记 05 §6）----
    let tags: BTreeSet<(String, String, i64)> = sqlx::query_as("select ab_guid, name, color from ab_tag")
        .fetch_all(&db)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        tags,
        BTreeSet::from([
            (admin_personal.clone(), "t1".to_owned(), 4280391411),
            (admin_personal.clone(), "t2".to_owned(), 4294967295),
            (admin_team.clone(), "team".to_owned(), 7),
            (bob_personal.clone(), "bobtag".to_owned(), 16711680),
        ])
    );

    // ---- 授权规则：个人规则和组规则分开、各按 MAX 去重，不展开成个人（§15"授权规则"）----
    let rules: BTreeSet<(String, Option<String>, Option<String>, i64)> = sqlx::query_as(
        "select r.ab_guid, u.name, g.name, r.rule from ab_rule r
         left join user u on u.id = r.user_id left join user_group g on g.id = r.group_id",
    )
    .fetch_all(&db)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let s = |v: &str| Some(v.to_owned());
    assert_eq!(
        rules,
        BTreeSet::from([
            (admin_team.clone(), s("bob"), None, 2),
            (admin_team.clone(), None, s("共享组"), 3),
            (admin_team.clone(), None, s("rustdesk-api-group-7"), 2),
            (admin_renamed.clone(), s("bob"), None, 1),
            (carol_book.clone(), None, s("empty"), 2),
        ])
    );

    // ---- 设备：MIN(row_id) 去重、归属映射、时间、sysinfo 留空（§15"设备"）----
    let devices: BTreeMap<String, (String, Option<String>, String, String, String, String, i64, i64, String, String)> =
        sqlx::query_as::<_, (String, String, Option<String>, String, String, String, String, i64, i64, String, String)>(
            "select d.id, d.uuid, u.name, d.hostname, d.username, d.os, d.version, d.first_seen_at, d.last_seen_at,
                    d.last_ip, d.sysinfo
             from device d left join user u on u.id = d.user_id",
        )
        .fetch_all(&db)
        .await
        .unwrap()
        .into_iter()
        .map(|(id, a, b, c, d, e, f, g, h, i, j)| (id, (a, b, c, d, e, f, g, h, i, j)))
        .collect();
    assert_eq!(
        devices.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["111111111", "222222222", "333333333", "444444444"]
    );
    assert_eq!(
        devices["111111111"],
        (
            "uuid-a".into(),
            s("admin"),
            "pc1".into(),
            "win".into(),
            "windows".into(),
            "1.4.2".into(),
            1700000000,
            1700000000,
            "1.2.3.4".into(),
            String::new()
        )
    );
    let d2 = devices["222222222"].clone();
    assert_eq!((d2.1.clone(), d2.2.as_str(), d2.5.as_str()), (None, "pc2", "1.3.0"), "user_id 0 → NULL");
    assert!(in_import(d2.6) && in_import(d2.7), "last_online_time 0 → import time");
    let d3 = devices["333333333"].clone();
    assert_eq!((d3.1.clone(), d3.6, d3.7, d3.8.as_str()), (None, 1600000000, 1600000000, "5.6.7.8"), "unmapped user → NULL");
    let d4 = devices["444444444"].clone();
    assert_eq!((d4.1.clone(), d4.6, d4.8.as_str(), d4.9.as_str()), (s("bob"), 1650000000, "2408:8256::1", ""));
}

/// §15：Porta 库里已有用户时拒绝执行（只支持往空库导入一次），库不被改动。
#[tokio::test]
async fn import_refuses_non_empty_database() {
    let work = Work::new();
    work.write_secret_key();
    let fx = build_rustdesk_api(work.path()).await;
    let db = work.pool().await;
    insert_user(&db, "existing", "").await;

    work.cli(&["import", "rustdesk-api", src_arg(&fx)], "").refused();
    assert_eq!(count(&db, "select count(*) from user").await, 1);
    for table in ["user_group", "group_member", "ab", "ab_rule", "ab_peer", "ab_tag", "device"] {
        assert_eq!(count(&db, &format!("select count(*) from {table}")).await, 0, "{table}");
    }
}

/// §15：`--dry-run` 只打印数量、冲突和被丢弃的数据，不写库；之后真正导入照常可以执行。
#[tokio::test]
async fn import_dry_run_writes_nothing() {
    let work = Work::new();
    work.write_secret_key();
    let fx = build_rustdesk_api(work.path()).await;
    let db = work.pool().await;

    let out = work.cli(&["import", "rustdesk-api", src_arg(&fx), "--dry-run"], "");
    out.ok();
    for table in ["user", "user_group", "group_member", "ab", "ab_rule", "ab_peer", "ab_tag", "device"] {
        assert_eq!(count(&db, &format!("select count(*) from {table}")).await, 0, "dry run wrote {table}");
    }

    work.cli(&["import", "rustdesk-api", src_arg(&fx)], "").ok();
    assert_eq!(count(&db, "select count(*) from user").await, 7);
}

/// §15 + §11：导入的 bcrypt（`$2a$`、`$2b$`）和 md5（`md5:`）用户经 HTTP `/api/login` 登录成功
/// （笔记 03 §2.2：200、`type == "access_token"`、`user.name` 非空），哈希当场升级为 argon2id；
/// 密码错误时不升级；禁用（status 3 → 0）的用户不能登录（§11 账号可用写死为 status = 1）。
#[tokio::test]
async fn imported_users_log_in_and_hashes_upgrade() {
    let work = Work::new();
    work.write_secret_key();
    let fx = build_rustdesk_api(work.path()).await;
    let db = work.pool().await;
    work.cli(&["import", "rustdesk-api", src_arg(&fx)], "").ok();
    let server = Server::start(&work);

    for (name, pw) in [("admin", ADMIN_PW), ("frank", FRANK_PW)] {
        let (status, body) = login(&server, name, pw).await;
        assert!(got_token(status, &body), "{name}: {status} {body}\n{}", server.log());
        assert_eq!(body["user"]["name"], name);
        let hash = password_hash(&db, name).await;
        assert!(is_argon2id_of(&hash, pw), "{name}: bcrypt not upgraded: {hash}");
    }

    let (status, body) = login(&server, "bob", "wrong-pw").await;
    assert!(!got_token(status, &body), "wrong password accepted: {status} {body}");
    assert_eq!(password_hash(&db, "bob").await, format!("md5:{}", fx.bob_hash), "no upgrade on failure");
    let (status, body) = login(&server, "bob", BOB_PW).await;
    assert!(got_token(status, &body), "bob: {status} {body}\n{}", server.log());
    assert_eq!(body["user"]["name"], "bob");
    let hash = password_hash(&db, "bob").await;
    assert!(is_argon2id_of(&hash, BOB_PW), "md5 not upgraded: {hash}");

    let (status, body) = login(&server, "erin", ERIN_PW).await;
    assert!(!got_token(status, &body), "disabled user logged in: {status} {body}");
}
