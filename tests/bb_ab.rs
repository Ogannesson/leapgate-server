//! 地址簿 12 个接口的黑盒测试：起真实的 porta-server 进程，只依据 PORTA.md（§9.1 第 6、9、10 条，§12.1，§12.2）、
//! migrations/0001_init.sql 和笔记 04（docs/research/第一期服务端/04-地址簿接口.md）断言，
//! 请求体照笔记 04 引用的客户端代码（flutter/lib/models/ab_model.dart、peer_model.dart、common/widgets/dialog.dart）构造。

mod bb_ab_support;

use bb_ab_support::*;
use hbb_common::tokio;
use serde_json::{json, Value};
use std::net::TcpStream;

/// 客户端生成的标签颜色 alpha 恒为 0xFF，超过 i32（笔记 04 §0 第 11 条）。
const RED: i64 = 0xFFFF_0000;
const GREEN: i64 = 0xFF00_FF00;
const BLUE: i64 = 0xFF00_00FF;
const WHITE: i64 = 0xFFFF_FFFF;

/// §12.1 的写入上限。
const MAX_PEERS: i64 = 10_000;
const MAX_TAGS: i64 = 1000;
const MAX_ID: usize = 253;
const MAX_DATA: usize = 8 << 10;
const MAX_PEER_TAGS: usize = 64;
const MAX_TAG: usize = 64;
const MAX_SECRET: usize = 1 << 10;

fn peers_path(guid: &str) -> String {
    format!("/api/ab/peers?current=1&pageSize=100&ab={guid}")
}

/// 5 个读接口（笔记 04 §1.1：POST、空 body）。
fn read_endpoints(guid: &str) -> Vec<(&'static str, String, String)> {
    vec![
        ("POST", "/api/ab/personal".to_owned(), String::new()),
        ("POST", "/api/ab/settings".to_owned(), String::new()),
        ("POST", "/api/ab/shared/profiles?current=1&pageSize=100".to_owned(), String::new()),
        ("POST", peers_path(guid), String::new()),
        ("POST", format!("/api/ab/tags/{guid}"), String::new()),
    ]
}

/// 7 个写接口的一组合法请求（笔记 04 §3.6~§3.12 的请求体），按顺序在一本有 `p1`、标签 `t1` 的簿上全部能成功：
/// 加 n1、改 p1 别名、加标签 t2、改 t1 颜色、t2 改名 t3、删 t3、删 n1 和 p1。
fn write_sequence(guid: &str) -> Vec<(&'static str, String, String)> {
    vec![
        ("POST", format!("/api/ab/peer/add/{guid}"), r#"{"id":"n1","alias":"","tags":[]}"#.to_owned()),
        ("PUT", format!("/api/ab/peer/update/{guid}"), r#"{"id":"p1","alias":"changed"}"#.to_owned()),
        ("POST", format!("/api/ab/tag/add/{guid}"), format!(r#"{{"name":"t2","color":{BLUE}}}"#)),
        ("PUT", format!("/api/ab/tag/update/{guid}"), format!(r#"{{"name":"t1","color":{GREEN}}}"#)),
        ("PUT", format!("/api/ab/tag/rename/{guid}"), r#"{"old":"t2","new":"t3"}"#.to_owned()),
        ("DELETE", format!("/api/ab/tag/{guid}"), r#"["t3"]"#.to_owned()),
        ("DELETE", format!("/api/ab/peer/{guid}"), r#"["n1","p1"]"#.to_owned()),
    ]
}

/// 给一本簿放上 `write_sequence` 需要的初始数据：设备 p1（标签 t1）、标签 t1（红色）。
async fn seed_book(s: &Server, guid: &str) {
    s.insert_peer(guid, "p1", json!({"alias": "orig"}), json!(["t1"]), "", "").await;
    s.insert_tag(guid, "t1", RED).await;
}

async fn put_ok(s: &Server, token: &str, path: String, body: String) {
    let r = s.call("PUT", &path, token, &body).await;
    assert_action_ok(&r, &format!("PUT {path} {body}"));
}

/// 跑完整组写请求，每条都必须成功；最后簿里没有设备，只剩颜色改成绿色的 t1。
async fn assert_can_write(s: &Server, token: &str, guid: &str, who: &str) {
    for (method, path, body) in write_sequence(guid) {
        let r = s.call(method, &path, token, &body).await;
        assert_action_ok(&r, &format!("{who} {method} {path} {body}"));
    }
    assert!(s.peer_ids(guid).await.is_empty(), "{who}：设备应已全部删掉");
    assert_eq!(s.tag_rows(guid).await, vec![("t1".to_owned(), GREEN)], "{who}");
}

/// 整组写请求都必须 403 + error，且库里的数据一点不变（§12.1：只读簿收到写请求要拒绝，无权访问时读写一律 403；
/// 笔记 04 §4.2：多选模式下只读簿仍会发 DELETE peer 和 peer/update）。
async fn assert_cannot_write(s: &Server, token: &str, guid: &str, who: &str) {
    let before = (s.peer_row(guid, "p1").await, s.peer_ids(guid).await, s.tag_rows(guid).await);
    for (method, path, body) in write_sequence(guid) {
        let r = s.call(method, &path, token, &body).await;
        assert_error(&r, 403, &format!("{who} {method} {path}"));
    }
    let after = (s.peer_row(guid, "p1").await, s.peer_ids(guid).await, s.tag_rows(guid).await);
    assert_eq!(before, after, "{who}：被拒的写请求不能改动数据");
}

/// 进程管理和请求发送的自检（现在就应通过）：GET / 是说明页（§9.4），会合端口都在监听，未知路径 404（§9.4），
/// 库已迁移、能直接写。
#[tokio::test]
async fn smoke_server_process_and_index_page() {
    let s = Server::start().await;
    let r = s.get("/").await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.content_type.starts_with("text/html"), "{}", r.content_type);
    let page = r.text();
    assert!(page.contains("Porta") && page.contains("https://db-ip.com"), "{page}");
    for p in [s.port - 1, s.port, s.port + 2] {
        TcpStream::connect(("127.0.0.1", p)).unwrap_or_else(|e| panic!("端口 {p} 没在监听：{e}"));
    }
    assert_eq!(s.get("/api/no-such-endpoint").await.status, 404);
    let u = s.user("smoke", false).await;
    let guid = s.book("Smoke", u.id, false).await;
    s.insert_tag(&guid, "t", WHITE).await;
    assert_eq!(s.tag_rows(&guid).await, vec![("t".to_owned(), WHITE)]);
}

/// §9.1 第 9 条：personal 永远回 200 + 非空 guid，个人簿不存在就当场建；§12.1：每人一本、名字固定 `My address book`。
/// 笔记 04 §1.2A / §2.4：对象型解析器，guid 必须是字符串；§1.1：guid 直接拼进 URL，表结构定为 UUIDv4 字符串；
/// §3.1：guid 对同一用户稳定（每人只有一本个人簿，ab_personal 唯一索引）。
#[tokio::test]
async fn personal_always_returns_guid_and_creates_book_once() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let guid = s.personal_guid(&alice.token).await;
    assert!(uuid::Uuid::parse_str(&guid).is_ok(), "guid 应是 UUID 字符串：{guid}");
    let rows: Vec<(String, String, i64)> =
        sqlx::query_as("select guid, name, personal from ab where owner_id = ?")
            .bind(alice.id)
            .fetch_all(&s.db)
            .await
            .unwrap();
    assert_eq!(rows, vec![(guid.clone(), PERSONAL_NAME.to_owned(), 1)]);

    // 再调一次（客户端每次拉列表都重读）：同一个 guid，不多建。
    assert_eq!(s.personal_guid(&alice.token).await, guid);
    let n: i64 = sqlx::query_scalar("select count(*) from ab where owner_id = ?")
        .bind(alice.id)
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert_eq!(n, 1);

    // 别人的个人簿是另一本。
    let bob = s.user("bob", false).await;
    assert_ne!(s.personal_guid(&bob.token).await, guid);

    // 已有个人簿（命令行 / 导入建的）就回它；有共享簿不影响。
    let carol = s.user("carol", false).await;
    s.book("Carol shared", carol.id, false).await;
    let existing = s.personal_book(carol.id).await;
    assert_eq!(s.personal_guid(&carol.token).await, existing);
}

/// 笔记 04 §3.2：settings 回 `{"max_peer_one_ab": N}`（整数）；§12.1：`max_peer_one_ab` 回 10000，和每本簿的设备上限一致。
/// §9.1 第 9 条：settings 正常实现，不回 404。
#[tokio::test]
async fn settings_returns_peer_limit() {
    let s = Server::start().await;
    let u = s.user("u", false).await;
    let obj = assert_object(&s.read("/api/ab/settings", &u.token).await, "settings");
    let v = obj.get("max_peer_one_ab").unwrap_or_else(|| panic!("缺 max_peer_one_ab：{obj:?}"));
    assert!(is_int(v) && v.as_i64() == Some(MAX_PEERS), "max_peer_one_ab 必须是整数 {MAX_PEERS}：{v}");
}

/// §9.1 第 3 条：令牌无效、过期、账号禁用 → 401（笔记 04 §0 第 12 条）。12 个接口都查：
/// 空令牌（客户端发 `Bearer `）、不存在的令牌、被禁用账号的令牌。
#[tokio::test]
async fn invalid_token_or_disabled_account_is_401_everywhere() {
    let s = Server::start().await;
    let owner = s.user("owner", false).await;
    let guid = s.book("Shared", owner.id, false).await;
    seed_book(&s, &guid).await;
    let disabled = s.user("disabled", false).await;
    s.grant_user(&guid, disabled.id, 3).await;
    s.disable(disabled.id).await;
    let mut endpoints = read_endpoints(&guid);
    endpoints.extend(write_sequence(&guid));
    for token in ["", "no-such-token", disabled.token.as_str()] {
        for (method, path, body) in &endpoints {
            let r = s.call(method, path, token, body).await;
            assert_error(&r, 401, &format!("token {token:?}: {method} {path}"));
        }
    }
    // 被拒的请求没有改动数据。
    assert_eq!(s.peer_ids(&guid).await, vec!["p1".to_owned()]);
    assert_eq!(s.tag_rows(&guid).await, vec![("t1".to_owned(), RED)]);
}

/// §12.1：shared/profiles 列出当前用户能看到的共享簿（主人或有规则），`owner` 填主人的用户名，`rule` 填有效权限，
/// `info` 回 `{}`；个人簿不出现。有效权限 = 主人为 3，否则取直接规则和所在任一组规则的最大值；没有就看不到。
/// 笔记 04 §2.2：guid/name/owner 是字符串、rule 是 int、note 只能是字符串或省略；§1.6：total 是整数。
/// §9.1 第 10 条：纯数字的用户名也要是字符串。管理员在地址簿上没有特权（§12.1 的有效权限里没有管理员这一项）。
#[tokio::test]
async fn shared_profiles_fields_visibility_and_effective_rule() {
    let s = Server::start().await;
    let alice = s.user("10086", false).await;
    let bob = s.user("bob", false).await;
    let carol = s.user("carol", false).await;
    let dave = s.user("dave", false).await;
    let admin = s.user("admin", true).await;
    s.personal_book(alice.id).await;
    s.personal_book(bob.id).await;
    let team = s.book("Team", alice.id, false).await;
    let ops = s.book("Ops", alice.id, false).await;
    let bobs = s.book("Bob's", bob.id, false).await;
    let g = s.group("staff").await;
    s.join(g, bob.id).await;
    s.join(g, carol.id).await;
    s.grant_user(&team, bob.id, 1).await;
    s.grant_group(&team, g, 2).await;
    s.grant_user(&ops, carol.id, 3).await;
    s.grant_group(&ops, g, 1).await;

    let check = |name: &str, p: &serde_json::Map<String, Value>, guid: &str, owner: &str, rule: i64| {
        assert_eq!(p.get("guid"), Some(&json!(guid)), "{name}: {p:?}");
        assert_eq!(p.get("name"), Some(&json!(name)), "{p:?}");
        assert_eq!(p.get("owner"), Some(&json!(owner)), "{name}: owner 必须是主人用户名字符串：{p:?}");
        let r = p.get("rule").unwrap_or_else(|| panic!("{name}: 缺 rule：{p:?}"));
        assert!(is_int(r) && r.as_i64() == Some(rule), "{name}: rule 应为整数 {rule}：{p:?}");
        assert_eq!(p.get("info"), Some(&json!({})), "{name}: info 应为 {{}}：{p:?}");
        if let Some(note) = p.get("note") {
            assert!(note.is_string(), "{name}: note 只能是字符串：{p:?}");
        }
    };

    let ps = s.profiles(&alice.token).await;
    assert_eq!(ps.keys().collect::<Vec<_>>(), vec!["Ops", "Team"], "alice 看到自己的两本、看不到个人簿和 Bob's");
    check("Team", &ps["Team"], &team, "10086", 3);
    check("Ops", &ps["Ops"], &ops, "10086", 3);

    let ps = s.profiles(&bob.token).await;
    assert_eq!(ps.keys().collect::<Vec<_>>(), vec!["Bob's", "Ops", "Team"]);
    check("Team", &ps["Team"], &team, "10086", 2); // 直接 1、组 2 → 2
    check("Ops", &ps["Ops"], &ops, "10086", 1); // 只有组 1
    check("Bob's", &ps["Bob's"], &bobs, "bob", 3); // 主人

    let ps = s.profiles(&carol.token).await;
    assert_eq!(ps.keys().collect::<Vec<_>>(), vec!["Ops", "Team"]);
    check("Team", &ps["Team"], &team, "10086", 2); // 组 2
    check("Ops", &ps["Ops"], &ops, "10086", 3); // 直接 3、组 1 → 3

    for u in [&dave, &admin] {
        let obj = assert_object(&s.read("/api/ab/shared/profiles?current=1&pageSize=100", &u.token).await, &u.name);
        assert!(is_int(&obj["total"]) && obj["total"].as_i64() == Some(0), "{}: {obj:?}", u.name);
        assert_eq!(obj.get("data"), Some(&json!([])), "{}: 没有可见的簿时 data 是空数组：{obj:?}", u.name);
    }

    // 个人簿的 guid 不出现在任何人的 profiles 里（笔记 04 §3.3、§4.1）。
    let alice_personal = s.personal_guid(&alice.token).await;
    for u in [&alice, &bob, &carol] {
        assert!(s.profiles(&u.token).await.values().all(|p| p["guid"] != json!(alice_personal)));
    }
}

/// §9.1 第 6 条、笔记 04 §1.6：列表回 `{"total": int, "data": [...]}`，按 current/pageSize 翻页不漏，
/// 不能把每页压到 100 以下。shared/profiles 用 150 本共享簿、peers 用 250 个设备，照客户端的循环拉完。
#[tokio::test]
async fn pagination_total_is_int_and_pages_lose_nothing() {
    let s = Server::start().await;
    let owner = s.user("owner", false).await;
    let reader = s.user("reader", false).await;
    let g = s.group("readers").await;
    s.join(g, reader.id).await;
    let mut names = Vec::new();
    for i in 0..150 {
        let name = format!("book-{i:03}");
        let guid = s.book(&name, owner.id, false).await;
        if i % 2 == 0 {
            s.grant_user(&guid, reader.id, 1).await;
        } else {
            s.grant_group(&guid, g, 2).await;
        }
        names.push(name);
    }
    for u in [&owner, &reader] {
        let (items, total, lens) = s.pull_pages(&u.token, "/api/ab/shared/profiles", "", "name").await;
        assert_eq!(total, 150, "{}", u.name);
        assert!(lens[0] >= 100, "{}: 第一页不能少于 100 条：{lens:?}", u.name);
        let mut got: Vec<String> = items.iter().map(|m| m["name"].as_str().unwrap().to_owned()).collect();
        got.sort();
        assert_eq!(got, names, "{}", u.name);
    }

    let guid = s.book("Big", owner.id, false).await;
    let mut ids = Vec::new();
    for i in 0..250 {
        let id = format!("{:09}", 100_000_000 + i);
        s.insert_peer(&guid, &id, json!({}), json!([]), "", "").await;
        ids.push(id);
    }
    let (items, total, lens) = s
        .pull_pages(&owner.token, "/api/ab/peers", &format!("&ab={guid}"), "id")
        .await;
    assert_eq!(total, 250);
    assert!(lens[0] >= 100, "第一页不能少于 100 条：{lens:?}");
    let mut got: Vec<String> = items.iter().map(|m| m["id"].as_str().unwrap().to_owned()).collect();
    got.sort();
    assert_eq!(got, ids);
    // 库里只有 id 的设备回 {"id", "tags": []}（§12.1：data 的全部键 + id + tags）。
    for m in &items {
        assert_eq!(m.len(), 2, "{m:?}");
        assert_eq!(m["tags"], json!([]));
    }
}

/// §12.1 / §9.1 第 9 条：读接口按对象型（peers）和数组型（tags）解析器回；`peers` 每条 = data 的全部键 + id + tags
/// + 个人簿的 hash 或共享簿的 password（解密后）；`hash_enc`/`password_enc` 为 '' 时省略。
/// §9.1 第 10 条：纯数字字符串保持字符串。笔记 04 §3.4：只读成员也要拿到共享密码。
/// 数据直接写库（用服务的 porta_secret.key 加密），所以只考读路径。
#[tokio::test]
async fn peers_response_composition_and_decryption() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let bob = s.user("bob", false).await;
    let personal = s.personal_book(alice.id).await;
    let shared = s.book("Shared", alice.id, false).await;
    s.grant_user(&shared, bob.id, 1).await;

    s.insert_peer(
        &personal,
        "123456789",
        json!({"alias": "007", "note": "n", "platform": "Mac OS", "rdpPort": "3389"}),
        json!(["a", "b"]),
        &s.encrypt("q83vEjRWeJA="),
        "",
    )
    .await;
    s.insert_peer(&personal, "2", json!({"alias": ""}), json!([]), "", "").await;
    s.insert_peer(
        &shared,
        "s1",
        json!({"same_server": true, "extra": [1, 2], "username": "u"}),
        json!(["x"]),
        "",
        &s.encrypt("PW 密码"),
    )
    .await;
    s.insert_peer(&shared, "s2", json!({"hostname": "h"}), json!([]), "", "").await;

    let ps = s.peers(&alice.token, &personal).await;
    assert_eq!(ps.len(), 2);
    assert_eq!(
        ps["123456789"],
        json!({"id": "123456789", "alias": "007", "note": "n", "platform": "Mac OS", "rdpPort": "3389",
               "tags": ["a", "b"], "hash": "q83vEjRWeJA="})
    );
    assert_eq!(ps["2"], json!({"id": "2", "alias": "", "tags": []}));

    for u in [&alice, &bob] {
        let ps = s.peers(&u.token, &shared).await;
        assert_eq!(
            ps["s1"],
            json!({"id": "s1", "same_server": true, "extra": [1, 2], "username": "u", "tags": ["x"],
                   "password": "PW 密码"}),
            "{}",
            u.name
        );
        assert_eq!(ps["s2"], json!({"id": "s2", "hostname": "h", "tags": []}), "{}", u.name);
    }
}

/// §12.1 权限：只读（1）和无权访问。只读用户能读 peers、tags，7 个写接口全部 403 + error 且不改数据；
/// 无权访问的用户读写一律 403（含别人的个人簿、管理员没有特权）；只读来自组授权时同样只读（§12.2）。
/// 不存在的 guid：笔记 04 §1.4 说 404 / 403 + error 都行（契约没规定具体码），这里只要求 400/403/404 + error。
#[tokio::test]
async fn read_only_and_no_access_are_rejected() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let ro = s.user("ro", false).await;
    let ro_group = s.user("ro-group", false).await;
    let stranger = s.user("stranger", false).await;
    let admin = s.user("admin", true).await;
    let shared = s.book("Shared", alice.id, false).await;
    seed_book(&s, &shared).await;
    let personal = s.personal_book(alice.id).await;
    seed_book(&s, &personal).await;
    s.grant_user(&shared, ro.id, 1).await;
    let g = s.group("viewers").await;
    s.join(g, ro_group.id).await;
    s.grant_group(&shared, g, 1).await;

    for u in [&ro, &ro_group] {
        let ps = s.peers(&u.token, &shared).await;
        assert_eq!(ps.keys().collect::<Vec<_>>(), vec!["p1"], "{}", u.name);
        let tags = assert_array(&s.read(&format!("/api/ab/tags/{shared}"), &u.token).await, &u.name);
        assert_eq!(tags, vec![json!({"name": "t1", "color": RED})], "{}", u.name);
        assert_cannot_write(&s, &u.token, &shared, &u.name).await;
    }

    for (u, guid, what) in [
        (&stranger, &shared, "无规则的共享簿"),
        (&admin, &shared, "管理员看别人的共享簿"),
        (&ro, &personal, "别人的个人簿"),
        (&admin, &personal, "管理员看别人的个人簿"),
    ] {
        let ctx = format!("{} {what}", u.name);
        assert_error(&s.read(&peers_path(guid), &u.token).await, 403, &ctx);
        assert_error(&s.read(&format!("/api/ab/tags/{guid}"), &u.token).await, 403, &ctx);
        assert_cannot_write(&s, &u.token, guid, &ctx).await;
    }

    let ghost = uuid::Uuid::new_v4().to_string();
    let mut endpoints = read_endpoints(&ghost).split_off(3);
    endpoints.extend(write_sequence(&ghost));
    for (method, path, body) in endpoints {
        let r = s.call(method, &path, &alice.token, &body).await;
        assert_error_in(&r, &[400, 403, 404], &format!("不存在的簿 {method} {path}"));
    }
}

/// §12.1：2 读写，可以增删改簿内的设备和标签；3 在 12 个接口里和 2 相同；主人隐含 3。
/// 笔记 04 §4.3：不能照搬 rustdesk-api 的"删除要 3"。规则来自直接授权或组授权（§12.2）都一样。
#[tokio::test]
async fn read_write_and_full_control_can_use_every_write_endpoint() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let rw = s.user("rw", false).await;
    let full = s.user("full", false).await;
    let rw_group = s.user("rw-group", false).await;
    let full_group = s.user("full-group", false).await;
    let g2 = s.group("g2").await;
    let g3 = s.group("g3").await;
    s.join(g2, rw_group.id).await;
    s.join(g3, full_group.id).await;

    let cases: Vec<(&User, &str)> = vec![
        (&alice, "owner"),
        (&rw, "direct-2"),
        (&full, "direct-3"),
        (&rw_group, "group-2"),
        (&full_group, "group-3"),
    ];
    for (u, label) in cases {
        let guid = s.book(&format!("Book {label}"), alice.id, false).await;
        seed_book(&s, &guid).await;
        match label {
            "direct-2" => s.grant_user(&guid, rw.id, 2).await,
            "direct-3" => s.grant_user(&guid, full.id, 3).await,
            "group-2" => s.grant_group(&guid, g2, 2).await,
            "group-3" => s.grant_group(&guid, g3, 3).await,
            _ => {}
        }
        assert_can_write(&s, &u.token, &guid, label).await;
    }

    // 个人簿：主人能写。
    let personal = s.personal_book(alice.id).await;
    seed_book(&s, &personal).await;
    assert_can_write(&s, &alice.token, &personal, "personal").await;
}

/// §12.2：共享簿可以授权给组，成员变动后权限立即跟着变；有效权限取所在各组规则和直接规则的最大值（§12.1）。
/// 组被删除时（命令行 group del，外键级联删掉授权规则）权限随之消失。
#[tokio::test]
async fn group_membership_changes_take_effect_immediately() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let carol = s.user("carol", false).await;
    let guid = s.book("Team", alice.id, false).await;
    let g = s.group("editors").await;
    let h = s.group("admins").await;
    s.grant_group(&guid, g, 2).await;
    s.grant_group(&guid, h, 3).await;

    let rule_of = |ps: &std::collections::BTreeMap<String, serde_json::Map<String, Value>>| {
        ps.get("Team").map(|p| p["rule"].as_i64().unwrap())
    };
    let add = |id: &str| (format!("/api/ab/peer/add/{guid}"), format!(r#"{{"id":"{id}","alias":"","tags":[]}}"#));

    // 不在组里：看不到、不能读。
    assert_eq!(rule_of(&s.profiles(&carol.token).await), None);
    assert_error(&s.read(&peers_path(&guid), &carol.token).await, 403, "未入组");

    // 入组 g（2）：立刻可写。
    s.join(g, carol.id).await;
    assert_eq!(rule_of(&s.profiles(&carol.token).await), Some(2));
    let (path, body) = add("a1");
    assert_action_ok(&s.call("POST", &path, &carol.token, &body).await, "入组 g 后添加");

    // g 的规则降为 1：立刻只读。
    s.set_group_rule(&guid, g, 1).await;
    assert_eq!(rule_of(&s.profiles(&carol.token).await), Some(1));
    let (path, body) = add("a2");
    assert_error(&s.call("POST", &path, &carol.token, &body).await, 403, "g 降为只读后添加");
    assert_eq!(s.peers(&carol.token, &guid).await.keys().collect::<Vec<_>>(), vec!["a1"]);

    // 再入组 h（3）：取最大 3。
    s.join(h, carol.id).await;
    assert_eq!(rule_of(&s.profiles(&carol.token).await), Some(3));
    let (path, body) = add("a3");
    assert_action_ok(&s.call("POST", &path, &carol.token, &body).await, "入组 h 后添加");

    // 退出 h：回到 1；退出 g：无权访问。
    s.leave(h, carol.id).await;
    assert_eq!(rule_of(&s.profiles(&carol.token).await), Some(1));
    s.leave(g, carol.id).await;
    assert_eq!(rule_of(&s.profiles(&carol.token).await), None);
    assert_error(&s.read(&peers_path(&guid), &carol.token).await, 403, "退组后读");

    // 重新入组 g 后删除组 g：规则级联删除，立刻无权访问。
    s.join(g, carol.id).await;
    assert_eq!(rule_of(&s.profiles(&carol.token).await), Some(1));
    s.delete_group(g).await;
    assert_eq!(rule_of(&s.profiles(&carol.token).await), None);
    assert_error(&s.read(&format!("/api/ab/tags/{guid}"), &carol.token).await, 403, "组删除后读");
}

/// peer/add 的两种客户端请求体（笔记 04 §3.6）：
/// (a)「添加 ID」`{"id","alias","tags"[,"password"][,"note"]}`；(b)「添加到地址簿」= `Peer.toJson()` 去掉 password、hash，
/// 其中 `same_server` 可能是 null、`forceAlwaysRelay` 是字符串（peer_model.dart `toJson`）。
/// §12.1：其余字段原样存进 data（保留 JSON 类型），值为 null 的键丢掉；个人簿存 hash、共享簿存 password，都加密落盘
/// （§13：`sb1:` 密文），`hash:""`/`password:""` 存 ''；peers 回包 = data 的全部键 + id + tags + hash/password。
/// 表结构：data 不含 id/tags/hash/password；hash_enc 只属于个人簿、password_enc 只属于共享簿。
#[tokio::test]
async fn peer_add_stores_client_bodies_faithfully() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let personal = s.personal_book(alice.id).await;
    let shared = s.book("Shared", alice.id, false).await;
    let add_p = format!("/api/ab/peer/add/{personal}");
    let add_s = format!("/api/ab/peer/add/{shared}");
    let ok = |r: Resp, ctx: &str| assert_action_ok(&r, ctx);

    // (a) 添加 ID。
    ok(s.call("POST", &add_p, &alice.token, r#"{"id":"100200300","alias":"Home","tags":[]}"#).await, "a1");
    ok(s.call("POST", &add_p, &alice.token, r#"{"id":"2","alias":"","tags":["t"],"note":"memo"}"#).await, "a2");
    // (b) 添加到地址簿，same_server 为 null。
    let b = r#"{"id":"3","username":"user","hostname":"host","platform":"Windows","alias":"","tags":[],
        "forceAlwaysRelay":"false","rdpPort":"","rdpUsername":"","loginName":"","device_group_name":"",
        "note":"","same_server":null}"#;
    ok(s.call("POST", &add_p, &alice.token, b).await, "b null");
    // (b) same_server 为 true，外加客户端以后可能多给的未知键。
    let b2 = r#"{"id":"4","username":"","hostname":"","platform":"Linux","alias":"x","tags":[],
        "forceAlwaysRelay":"true","rdpPort":"3389","rdpUsername":"r","loginName":"l","device_group_name":"d",
        "note":"","same_server":true,"extra":5}"#;
    ok(s.call("POST", &add_p, &alice.token, b2).await, "b true");
    // 个人簿带 hash；hash 为空串；值为 null 的 alias 当没给。
    ok(s.call("POST", &add_p, &alice.token, r#"{"id":"5","alias":"","tags":[],"hash":"q83vEjRWeJA="}"#).await, "hash");
    ok(s.call("POST", &add_p, &alice.token, r#"{"id":"6","alias":"","tags":[],"hash":""}"#).await, "hash 空");
    ok(s.call("POST", &add_p, &alice.token, r#"{"id":"7","alias":null,"tags":[]}"#).await, "alias null");

    let ps = s.peers(&alice.token, &personal).await;
    assert_eq!(ps.len(), 7);
    assert_eq!(ps["100200300"], json!({"id": "100200300", "alias": "Home", "tags": []}));
    assert_eq!(ps["2"], json!({"id": "2", "alias": "", "tags": ["t"], "note": "memo"}));
    assert_eq!(
        ps["3"],
        json!({"id": "3", "username": "user", "hostname": "host", "platform": "Windows", "alias": "", "tags": [],
               "forceAlwaysRelay": "false", "rdpPort": "", "rdpUsername": "", "loginName": "",
               "device_group_name": "", "note": ""})
    );
    assert_eq!(
        ps["4"],
        json!({"id": "4", "username": "", "hostname": "", "platform": "Linux", "alias": "x", "tags": [],
               "forceAlwaysRelay": "true", "rdpPort": "3389", "rdpUsername": "r", "loginName": "l",
               "device_group_name": "d", "note": "", "same_server": true, "extra": 5})
    );
    assert_eq!(ps["5"], json!({"id": "5", "alias": "", "tags": [], "hash": "q83vEjRWeJA="}));
    assert_eq!(ps["6"], json!({"id": "6", "alias": "", "tags": []}));
    assert_eq!(ps["7"], json!({"id": "7", "tags": []}));

    // 落盘：data 不含 id/tags/hash/password、不含 null；hash 是 sb1: 密文、能用服务的密钥解开；空 hash 存 ''。
    for id in ["100200300", "2", "3", "4", "5", "6", "7"] {
        let row = s.peer_row(&personal, id).await.unwrap();
        let data = row.data.as_object().unwrap_or_else(|| panic!("{id}: data 不是对象：{:?}", row.data));
        for k in ["id", "tags", "hash", "password"] {
            assert!(!data.contains_key(k), "{id}: data 里不该有 {k}：{data:?}");
        }
        assert_no_null(&row.data, id);
        assert!(row.tags.is_array(), "{id}: tags 列应是 JSON 数组：{:?}", row.tags);
        assert_eq!(row.password_enc, "", "{id}: 个人簿没有 password_enc");
    }
    assert_eq!(s.peer_row(&personal, "2").await.unwrap().tags, json!(["t"]));
    assert_eq!(s.peer_row(&personal, "3").await.unwrap().data.get("same_server"), None);
    let row5 = s.peer_row(&personal, "5").await.unwrap();
    assert!(row5.hash_enc.starts_with("sb1:") && !row5.hash_enc.contains("q83vEjRWeJA="), "{row5:?}");
    assert_eq!(s.decrypt(&row5.hash_enc), "q83vEjRWeJA=");
    assert_eq!(s.peer_row(&personal, "6").await.unwrap().hash_enc, "");

    // 共享簿：添加 ID 带 password（笔记 04 §3.6 (a)）→ 加密存、回明文；不带就省略。
    ok(s.call("POST", &add_s, &alice.token, r#"{"id":"s1","alias":"A","tags":[],"password":"s3cret 密"}"#).await, "s1");
    ok(s.call("POST", &add_s, &alice.token, r#"{"id":"s2","alias":"","tags":[]}"#).await, "s2");
    ok(s.call("POST", &add_s, &alice.token, r#"{"id":"s3","alias":"","tags":[],"password":""}"#).await, "s3");
    let ps = s.peers(&alice.token, &shared).await;
    assert_eq!(ps["s1"], json!({"id": "s1", "alias": "A", "tags": [], "password": "s3cret 密"}));
    assert_eq!(ps["s2"], json!({"id": "s2", "alias": "", "tags": []}));
    assert_eq!(ps["s3"], json!({"id": "s3", "alias": "", "tags": []}));
    let row = s.peer_row(&shared, "s1").await.unwrap();
    assert!(row.password_enc.starts_with("sb1:") && !row.password_enc.contains("s3cret"), "{row:?}");
    assert_eq!(s.decrypt(&row.password_enc), "s3cret 密");
    assert_eq!(row.hash_enc, "", "共享簿没有 hash_enc");
    assert_eq!(s.peer_row(&shared, "s3").await.unwrap().password_enc, "");

    // 客户端不会往个人簿发 password、往共享簿发 hash（ab_model `Ab.addPeers` 的 removePassword/removeHash），
    // 状态码不作要求；但无论如何不能当成另一种簿的密码字段存，也不能进 data 回给客户端。
    let _ = s.call("POST", &add_p, &alice.token, r#"{"id":"8","alias":"","tags":[],"password":"pw"}"#).await;
    if let Some(row) = s.peer_row(&personal, "8").await {
        assert_eq!(row.password_enc, "");
        assert!(row.data.get("password").is_none(), "{row:?}");
        assert!(s.peers(&alice.token, &personal).await["8"].get("password").is_none());
    }
    let _ = s.call("POST", &add_s, &alice.token, r#"{"id":"s4","alias":"","tags":[],"hash":"h"}"#).await;
    if let Some(row) = s.peer_row(&shared, "s4").await {
        assert_eq!(row.hash_enc, "");
        assert!(row.data.get("hash").is_none(), "{row:?}");
        assert!(s.peers(&alice.token, &shared).await["s4"].get("hash").is_none());
    }
}

/// §12.1：peer/add 遇到簿内已存在的 id 不改任何字段，直接 200 空 body（笔记 04 §3.6、§4.4：目标簿没拉取过时，
/// 客户端会带着清空的 tags 和空 alias/note 重发）。
#[tokio::test]
async fn peer_add_duplicate_id_changes_nothing() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let personal = s.personal_book(alice.id).await;
    let shared = s.book("Shared", alice.id, false).await;
    s.insert_peer(&personal, "9", json!({"alias": "Keep", "note": "n"}), json!(["t1"]), &s.encrypt("H"), "").await;
    s.insert_peer(&shared, "9", json!({"alias": "Keep"}), json!(["t1"]), "", &s.encrypt("P")).await;
    let before_p = s.peer_row(&personal, "9").await.unwrap();
    let before_s = s.peer_row(&shared, "9").await.unwrap();

    let dup = r#"{"id":"9","username":"other","hostname":"h","platform":"Windows","alias":"","tags":[],
        "forceAlwaysRelay":"false","rdpPort":"","rdpUsername":"","loginName":"","device_group_name":"",
        "note":"","same_server":null}"#;
    for guid in [&personal, &shared] {
        let r = s.call("POST", &format!("/api/ab/peer/add/{guid}"), &alice.token, dup).await;
        assert_action_ok(&r, "重复添加");
    }
    let r = s
        .call("POST", &format!("/api/ab/peer/add/{personal}"), &alice.token, r#"{"id":"9","alias":"New","tags":["t2"],"hash":"X"}"#)
        .await;
    assert_action_ok(&r, "重复添加（带 hash）");
    let r = s
        .call("POST", &format!("/api/ab/peer/add/{shared}"), &alice.token, r#"{"id":"9","alias":"New","tags":[],"password":"Q"}"#)
        .await;
    assert_action_ok(&r, "重复添加（带 password）");

    assert_eq!(s.peer_row(&personal, "9").await.unwrap(), before_p, "个人簿的现有记录不能变");
    assert_eq!(s.peer_row(&shared, "9").await.unwrap(), before_s, "共享簿的现有记录不能变");
    assert_eq!(
        s.peers(&alice.token, &personal).await["9"],
        json!({"id": "9", "alias": "Keep", "note": "n", "tags": ["t1"], "hash": "H"})
    );
    assert_eq!(
        s.peers(&alice.token, &shared).await["9"],
        json!({"id": "9", "alias": "Keep", "tags": ["t1"], "password": "P"})
    );
}

/// §12.1：`alias、note、username、hostname、platform、rdpPort、rdpUsername、loginName、device_group_name、forceAlwaysRelay`
/// 不是字符串、`same_server` 不是 bool 时回 400 + error（不建记录、不改记录）；§9.1 第 1、2 条：请求体解析失败回 400 + JSON error
/// （不是 axum Json 提取器的 415/422 纯文本）。缺 id 的 add/update 按 §9.1 第 1 条回 400（笔记 04 §3.7：id 必带）。
#[tokio::test]
async fn invalid_bodies_are_400_with_json_error() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let guid = s.book("Shared", alice.id, false).await;
    seed_book(&s, &guid).await;
    let add = format!("/api/ab/peer/add/{guid}");
    let update = format!("/api/ab/peer/update/{guid}");
    let before = s.peer_row(&guid, "p1").await;

    let string_fields = [
        "alias", "note", "username", "hostname", "platform", "rdpPort", "rdpUsername", "loginName",
        "device_group_name", "forceAlwaysRelay",
    ];
    for field in string_fields {
        for bad in [json!(1), json!(true), json!(["x"])] {
            let mut body = json!({"id": "bad", "tags": []});
            body[field] = bad.clone();
            let r = s.call("POST", &add, &alice.token, &body.to_string()).await;
            assert_error(&r, 400, &format!("add {field}={bad}"));
            let mut body = json!({"id": "p1"});
            body[field] = bad.clone();
            let r = s.call("PUT", &update, &alice.token, &body.to_string()).await;
            assert_error(&r, 400, &format!("update {field}={bad}"));
        }
    }
    for bad in [json!("true"), json!(1), json!("")] {
        let body = json!({"id": "bad", "alias": "", "tags": [], "same_server": bad});
        let r = s.call("POST", &add, &alice.token, &body.to_string()).await;
        assert_error(&r, 400, &format!("add same_server={bad}"));
    }
    assert!(s.peer_row(&guid, "bad").await.is_none(), "被拒的 add 不能建记录");
    assert_eq!(s.peer_row(&guid, "p1").await, before, "被拒的 update 不能改记录");

    for (method, path, body) in [
        ("POST", add.clone(), "not json"),
        ("POST", add.clone(), r#"{"alias":"no id","tags":[]}"#),
        ("PUT", update.clone(), r#"{"alias":"no id"}"#),
        ("PUT", update.clone(), "[1,2"),
        ("DELETE", format!("/api/ab/peer/{guid}"), r#"{"id":"p1"}"#),
        ("POST", format!("/api/ab/tag/add/{guid}"), "{"),
        ("DELETE", format!("/api/ab/tag/{guid}"), r#""t1""#),
    ] {
        let r = s.call(method, &path, &alice.token, body).await;
        assert_error(&r, 400, &format!("{method} {path} {body}"));
    }
    assert_eq!(s.peer_ids(&guid).await, vec!["p1".to_owned()]);
    assert_eq!(s.peer_row(&guid, "p1").await, before);
    assert_eq!(s.tag_rows(&guid).await, vec![("t1".to_owned(), RED)]);
}

/// 直接往库里给一本簿灌 n 个设备（id `f0`…）或 n 个标签（名字 `f0`…），不必真发上万次请求。
async fn fill(s: &Server, guid: &str, peers: bool, n: i64) {
    let sql = if peers {
        "with recursive c(i) as (select 0 union all select i + 1 from c where i + 1 < ?2)
         insert into ab_peer(ab_guid, id, created_at, updated_at) select ?1, 'f' || i, 1, 1 from c"
    } else {
        "with recursive c(i) as (select 0 union all select i + 1 from c where i + 1 < ?2)
         insert into ab_tag(ab_guid, name, color) select ?1, 'f' || i, 1 from c"
    };
    sqlx::query(sql).bind(guid).bind(n).execute(&s.db).await.unwrap();
}

/// §12.1 写入上限：设备 id ≤ 253 字节；data 按落盘的 JSON 序列化后 ≤ 8 KB（peer/update 合并后再查）；tags ≤ 64 个、
/// 每个 ≤ 64 字节；本簿要存的 hash/password ≤ 1 KB；tag/add、tag/rename 的新名字 ≤ 64 字节。刚好等于上限通过，
/// 超 1 字节回 400 + error，库里不建、不改。长度按 UTF-8 字节算（中文一个字 3 字节）。
#[tokio::test]
async fn write_limits_exact_ok_one_byte_over_400() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let personal = s.personal_book(alice.id).await;
    let shared = s.book("Shared", alice.id, false).await;
    let add = format!("/api/ab/peer/add/{personal}");
    let update = format!("/api/ab/peer/update/{personal}");
    // 21 个汉字 + 1 个 ASCII = 64 字节。
    let tag = format!("{}a", "标".repeat(21));
    let tag_over = "标".repeat(22);
    let secret = "h".repeat(MAX_SECRET);
    let id = "1".repeat(MAX_ID);
    // `{"note":"…"}` 序列化后比 note 本身多 11 字节。
    let note = |extra: usize| "n".repeat(MAX_DATA - 11 + extra);

    let body = json!({"id": id, "tags": vec![tag.clone(); MAX_PEER_TAGS], "hash": secret, "note": note(0)});
    assert_action_ok(&s.call("POST", &add, &alice.token, &body.to_string()).await, "全部刚好等于上限");
    let row = s.peer_row(&personal, &id).await.expect("应已建记录");
    assert_eq!(row.data.to_string().len(), MAX_DATA);
    assert_eq!(row.tags.as_array().unwrap().len(), MAX_PEER_TAGS);
    assert_eq!(s.decrypt(&row.hash_enc), secret);
    let listed = &s.peers(&alice.token, &personal).await[&id];
    assert_eq!((listed["note"].as_str().unwrap().len(), listed["hash"].as_str()), (MAX_DATA - 11, Some(secret.as_str())));

    let over_id = json!({"id": "1".repeat(MAX_ID + 1)}).to_string();
    assert_error(&s.call("POST", &add, &alice.token, &over_id).await, 400, "add id 超长");
    assert_error(&s.call("PUT", &update, &alice.token, &over_id).await, 400, "update id 超长");
    for (what, bad) in [
        ("tags 个数", json!({"tags": vec!["t"; MAX_PEER_TAGS + 1]})),
        ("tag 名字", json!({"tags": ["ok", tag_over]})),
        ("hash", json!({"hash": format!("{secret}h")})),
        ("data", json!({"note": note(1)})),
    ] {
        let mut body = bad;
        body["id"] = json!("new");
        assert_error(&s.call("POST", &add, &alice.token, &body.to_string()).await, 400, &format!("add {what}超限"));
        body["id"] = json!(id);
        assert_error(&s.call("PUT", &update, &alice.token, &body.to_string()).await, 400, &format!("update {what}超限"));
    }
    assert_eq!(s.peer_ids(&personal).await, vec![id.clone()], "被拒的 add 不能建记录");
    assert_eq!(s.peer_row(&personal, &id).await.unwrap(), row, "被拒的 update 不能改记录");

    // 共享簿存 password，同样 ≤ 1 KB。
    let shared_add = format!("/api/ab/peer/add/{shared}");
    let r = s.call("POST", &shared_add, &alice.token, &json!({"id": "1", "password": secret}).to_string()).await;
    assert_action_ok(&r, "共享簿 password 刚好 1 KB");
    let r = s.call("POST", &shared_add, &alice.token, &json!({"id": "2", "password": format!("{secret}p")}).to_string()).await;
    assert_error(&r, 400, "共享簿 password 超长");
    assert_eq!(s.peer_ids(&shared).await, vec!["1".to_owned()]);

    // peer/update 合并后超限：两次各自不超，合起来超，第二次被拒且整行不变；换成更短的值照常成功。
    s.insert_peer(&personal, "m", json!({}), json!([]), "", "").await;
    let half = "a".repeat(MAX_DATA / 2);
    put_ok(&s, &alice.token, update.clone(), json!({"id": "m", "alias": half}).to_string()).await;
    let before = s.peer_row(&personal, "m").await.unwrap();
    let r = s.call("PUT", &update, &alice.token, &json!({"id": "m", "note": half}).to_string()).await;
    assert_error(&r, 400, "合并后超 8 KB");
    assert_eq!(s.peer_row(&personal, "m").await.unwrap(), before);
    put_ok(&s, &alice.token, update.clone(), json!({"id": "m", "alias": "short", "note": half}).to_string()).await;
    assert_eq!(s.peer_row(&personal, "m").await.unwrap().data, json!({"alias": "short", "note": half}));

    // 标签名字。
    let tag_add = format!("/api/ab/tag/add/{personal}");
    let rename = format!("/api/ab/tag/rename/{personal}");
    let r = s.call("POST", &tag_add, &alice.token, &json!({"name": tag, "color": RED}).to_string()).await;
    assert_action_ok(&r, "标签名刚好 64 字节");
    let r = s.call("POST", &tag_add, &alice.token, &json!({"name": tag_over, "color": RED}).to_string()).await;
    assert_error(&r, 400, "标签名超长");
    let r = s.call("PUT", &rename, &alice.token, &json!({"old": tag, "new": format!("{tag}b")}).to_string()).await;
    assert_error(&r, 400, "改名超长");
    assert_eq!(s.tag_rows(&personal).await, vec![(tag.clone(), RED)]);
    let new = "b".repeat(MAX_TAG);
    put_ok(&s, &alice.token, rename, json!({"old": tag, "new": new}).to_string()).await;
    assert_eq!(s.tag_rows(&personal).await, vec![(new, RED)]);
}

/// §12.1：每本簿最多 1 万个设备、1000 个标签。簿满后 peer/add 新 id、tag/add 新名字回 400 + error；
/// 已有的 id/名字照旧 200 空 body、不改；别的簿各算各的；删掉一个就又能加。
#[tokio::test]
async fn full_book_refuses_new_peers_and_tags() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let book = s.personal_book(alice.id).await;
    let other = s.book("Other", alice.id, false).await;
    let add = format!("/api/ab/peer/add/{book}");
    let tag_add = format!("/api/ab/tag/add/{book}");
    fill(&s, &book, true, MAX_PEERS - 1).await;
    fill(&s, &book, false, MAX_TAGS - 1).await;

    assert_action_ok(&s.call("POST", &add, &alice.token, r#"{"id":"last","alias":"A"}"#).await, "第 1 万个设备");
    let r = s.call("POST", &tag_add, &alice.token, &format!(r#"{{"name":"last","color":{RED}}}"#)).await;
    assert_action_ok(&r, "第 1000 个标签");

    assert_error(&s.call("POST", &add, &alice.token, r#"{"id":"new"}"#).await, 400, "簿满后加新设备");
    assert_action_ok(&s.call("POST", &add, &alice.token, r#"{"id":"last","alias":"B"}"#).await, "簿满后重复添加");
    let r = s.call("POST", &tag_add, &alice.token, &format!(r#"{{"name":"new","color":{RED}}}"#)).await;
    assert_error(&r, 400, "标签满后加新标签");
    let r = s.call("POST", &tag_add, &alice.token, &format!(r#"{{"name":"last","color":{BLUE}}}"#)).await;
    assert_action_ok(&r, "标签满后重复添加");
    assert_eq!(s.peer_ids(&book).await.len() as i64, MAX_PEERS);
    assert!(s.peer_row(&book, "new").await.is_none());
    assert_eq!(s.peer_row(&book, "last").await.unwrap().data, json!({"alias": "A"}));
    let tags = s.tag_rows(&book).await;
    assert_eq!(tags.len() as i64, MAX_TAGS);
    assert!(tags.contains(&("last".to_owned(), RED)) && !tags.iter().any(|t| t.0 == "new"));

    assert_action_ok(&s.call("POST", &format!("/api/ab/peer/add/{other}"), &alice.token, r#"{"id":"new"}"#).await, "别的簿");
    let r = s.call("POST", &format!("/api/ab/tag/add/{other}"), &alice.token, r#"{"name":"new","color":1}"#).await;
    assert_action_ok(&r, "别的簿的标签");

    assert_action_ok(&s.call("DELETE", &format!("/api/ab/peer/{book}"), &alice.token, r#"["f0"]"#).await, "删设备");
    assert_action_ok(&s.call("POST", &add, &alice.token, r#"{"id":"new"}"#).await, "删掉一个后再加");
    assert_action_ok(&s.call("DELETE", &format!("/api/ab/tag/{book}"), &alice.token, r#"["f0"]"#).await, "删标签");
    let r = s.call("POST", &tag_add, &alice.token, r#"{"name":"new","color":1}"#).await;
    assert_action_ok(&r, "删掉一个标签后再加");
}

/// §12.1：pageSize 最大 1000，超过按 1000 截断，total 照样是全部条数，按截断后的页大小翻页不重不漏。
#[tokio::test]
async fn page_size_capped_at_1000_total_unchanged() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let book = s.personal_book(alice.id).await;
    fill(&s, &book, true, 1500).await;
    let mut got = Vec::new();
    for (current, want) in [(1, 1000), (2, 500)] {
        let r = s.read(&format!("/api/ab/peers?current={current}&pageSize=5000&ab={book}"), &alice.token).await;
        let obj = assert_object(&r, "peers");
        assert!(is_int(&obj["total"]) && obj["total"].as_i64() == Some(1500), "total：{}", obj["total"]);
        let data = obj["data"].as_array().unwrap();
        assert_eq!(data.len(), want, "第 {current} 页");
        got.extend(data.iter().map(|p| p["id"].as_str().unwrap().to_owned()));
    }
    assert_eq!(got, s.peer_ids(&book).await);
}

/// §12.1：peer/update 只合并请求里出现的字段；id 不在簿里回 404 + error、不新建；`hash:""`/`password:""` 存 ''、回包省略；
/// 个人簿存 hash、共享簿存 password，都是 sb1: 密文。请求体照笔记 04 §3.7 的全部调用点
/// （改标签、改别名、改备注、记住/忘记密码哈希、设/删共享密码、从最近会话同步）。
#[tokio::test]
async fn peer_update_merges_only_given_fields() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let personal = s.personal_book(alice.id).await;
    let shared = s.book("Shared", alice.id, false).await;
    s.insert_peer(
        &personal,
        "p1",
        json!({"alias": "A", "note": "N", "username": "u0", "hostname": "h0", "platform": "Linux", "extra": 7}),
        json!(["x"]),
        &s.encrypt("H0"),
        "",
    )
    .await;
    s.insert_peer(&shared, "p2", json!({"alias": "B"}), json!([]), "", "").await;
    let up_p = format!("/api/ab/peer/update/{personal}");
    let up_s = format!("/api/ab/peer/update/{shared}");
    let (sr, token, pg) = (&s, alice.token.as_str(), personal.as_str());
    let put = move |path: &str, body: &str| put_ok(sr, token, path.to_owned(), body.to_owned());
    let personal_p1 = move || async move { sr.peers(token, pg).await["p1"].clone() };

    put(&up_p, r#"{"id":"p1","tags":["y","z"]}"#).await;
    assert_eq!(
        personal_p1().await,
        json!({"id": "p1", "alias": "A", "note": "N", "username": "u0", "hostname": "h0", "platform": "Linux",
               "extra": 7, "tags": ["y", "z"], "hash": "H0"})
    );
    put(&up_p, r#"{"id":"p1","tags":[]}"#).await;
    put(&up_p, r#"{"id":"p1","alias":""}"#).await;
    put(&up_p, r#"{"id":"p1","note":"N2"}"#).await;
    assert_eq!(
        personal_p1().await,
        json!({"id": "p1", "alias": "", "note": "N2", "username": "u0", "hostname": "h0", "platform": "Linux",
               "extra": 7, "tags": [], "hash": "H0"})
    );

    // 记住密码哈希 → sb1: 密文；忘记密码 → ''，回包省略 hash。
    put(&up_p, r#"{"id":"p1","hash":"H1=="}"#).await;
    let row = s.peer_row(&personal, "p1").await.unwrap();
    assert!(row.hash_enc.starts_with("sb1:") && !row.hash_enc.contains("H1=="), "{row:?}");
    assert_eq!(s.decrypt(&row.hash_enc), "H1==");
    assert_eq!(personal_p1().await["hash"], json!("H1=="));
    put(&up_p, r#"{"id":"p1","hash":""}"#).await;
    assert_eq!(s.peer_row(&personal, "p1").await.unwrap().hash_enc, "");
    assert!(personal_p1().await.get("hash").is_none());

    // 从最近会话同步（值全是字符串，hash 仅个人簿）。
    put(&up_p, r#"{"id":"p1","username":"u1","hostname":"h1","platform":"Windows","hash":"H2"}"#).await;
    assert_eq!(
        personal_p1().await,
        json!({"id": "p1", "alias": "", "note": "N2", "username": "u1", "hostname": "h1", "platform": "Windows",
               "extra": 7, "tags": [], "hash": "H2"})
    );
    let row = s.peer_row(&personal, "p1").await.unwrap();
    assert_eq!(s.decrypt(&row.hash_enc), "H2");
    assert_eq!(row.password_enc, "");
    for k in ["id", "tags", "hash", "password"] {
        assert!(row.data.get(k).is_none(), "data 里不该有 {k}：{:?}", row.data);
    }

    // 共享簿：设置、修改、删除共享密码。
    put(&up_s, r#"{"id":"p2","password":"s1"}"#).await;
    let row = s.peer_row(&shared, "p2").await.unwrap();
    assert!(row.password_enc.starts_with("sb1:") && !row.password_enc.contains("s1"), "{row:?}");
    assert_eq!(s.decrypt(&row.password_enc), "s1");
    assert_eq!(
        s.peers(&alice.token, &shared).await["p2"],
        json!({"id": "p2", "alias": "B", "tags": [], "password": "s1"})
    );
    put(&up_s, r#"{"id":"p2","password":"s2"}"#).await;
    assert_eq!(s.decrypt(&s.peer_row(&shared, "p2").await.unwrap().password_enc), "s2");
    put(&up_s, r#"{"id":"p2","password":""}"#).await;
    assert_eq!(s.peer_row(&shared, "p2").await.unwrap().password_enc, "");
    assert_eq!(s.peers(&alice.token, &shared).await["p2"], json!({"id": "p2", "alias": "B", "tags": []}));
    assert_eq!(s.peer_row(&shared, "p2").await.unwrap().hash_enc, "");

    // 不在簿里的 id：404 + error，不新建。
    for (path, guid) in [(&up_p, &personal), (&up_s, &shared)] {
        let r = s.call("PUT", path, &alice.token, r#"{"id":"ghost","alias":"x"}"#).await;
        assert_error(&r, 404, "update 不存在的 id");
        assert!(s.peer_row(guid, "ghost").await.is_none());
    }
    // 另一本簿里有这个 id 也不算。
    let r = s.call("PUT", &up_s, &alice.token, r#"{"id":"p1","alias":"x"}"#).await;
    assert_error(&r, 404, "update 别的簿里的 id");
}

/// §12.1：DELETE peer 一个事务里删掉存在的、忽略不存在的，回 200 空 body（笔记 04 §3.8：body 是 id 数组）；
/// 只删本簿的。
#[tokio::test]
async fn peer_delete_removes_existing_and_ignores_missing() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let guid = s.book("Shared", alice.id, false).await;
    let other = s.book("Other", alice.id, false).await;
    for id in ["a", "b", "c"] {
        s.insert_peer(&guid, id, json!({}), json!([]), "", "").await;
        s.insert_peer(&other, id, json!({}), json!([]), "", "").await;
    }
    let r = s
        .call("DELETE", &format!("/api/ab/peer/{guid}"), &alice.token, r#"["a","ghost","b"]"#)
        .await;
    assert_action_ok(&r, "DELETE peer");
    assert_eq!(s.peer_ids(&guid).await, vec!["c".to_owned()]);
    assert_eq!(s.peer_ids(&other).await, vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]);
    let r = s
        .call("DELETE", &format!("/api/ab/peer/{guid}"), &alice.token, r#"["ghost"]"#)
        .await;
    assert_action_ok(&r, "DELETE 只有不存在的 id");
    assert_eq!(s.peers(&alice.token, &guid).await.keys().collect::<Vec<_>>(), vec!["c"]);
}

/// 标签读接口和 add/update（§9.1 第 6 条例外、§12.1）：`tags/<guid>` 回顶层数组 `[{"name":string,"color":int}]`，
/// 没有标签回 `[]`，按 name 排序；color 按 i64 原样存取（超过 i32）；tag/add 同名不改颜色、回 200 空 body；
/// tag/update 改颜色，name 不存在回 404。
#[tokio::test]
async fn tags_list_add_and_update() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let guid = s.book("Shared", alice.id, false).await;
    let other = s.book("Other", alice.id, false).await;
    let tags_path = format!("/api/ab/tags/{guid}");

    let r = s.read(&tags_path, &alice.token).await;
    assert_eq!(assert_array(&r, "空簿的 tags"), Vec::<Value>::new());

    for (name, color) in [("beta", RED), ("alpha", WHITE), ("gamma", BLUE)] {
        let body = json!({"name": name, "color": color}).to_string();
        assert_action_ok(&s.call("POST", &format!("/api/ab/tag/add/{guid}"), &alice.token, &body).await, name);
    }
    let body = json!({"name": "alpha", "color": GREEN}).to_string();
    assert_action_ok(&s.call("POST", &format!("/api/ab/tag/add/{guid}"), &alice.token, &body).await, "同名 add");
    let tags = assert_array(&s.read(&tags_path, &alice.token).await, "tags");
    assert_eq!(
        tags,
        vec![
            json!({"name": "alpha", "color": WHITE}),
            json!({"name": "beta", "color": RED}),
            json!({"name": "gamma", "color": BLUE}),
        ]
    );
    for t in &tags {
        assert!(is_int(&t["color"]), "color 必须是 JSON 整数：{t}");
    }
    assert_eq!(
        s.tag_rows(&guid).await,
        vec![("alpha".to_owned(), WHITE), ("beta".to_owned(), RED), ("gamma".to_owned(), BLUE)]
    );

    let body = json!({"name": "beta", "color": GREEN}).to_string();
    assert_action_ok(&s.call("PUT", &format!("/api/ab/tag/update/{guid}"), &alice.token, &body).await, "update");
    assert_eq!(s.tag_rows(&guid).await[1], ("beta".to_owned(), GREEN));
    let body = json!({"name": "ghost", "color": GREEN}).to_string();
    assert_error(&s.call("PUT", &format!("/api/ab/tag/update/{guid}"), &alice.token, &body).await, 404, "update 不存在");
    assert_eq!(s.tag_rows(&guid).await.len(), 3);

    // 别的簿不受影响。
    assert_eq!(assert_array(&s.read(&format!("/api/ab/tags/{other}"), &alice.token).await, "other"), Vec::<Value>::new());
}

/// §12.1 / 笔记 04 §4.5：tag/rename 时 old 不存在回 404、new 已存在回 409；成功时同一事务里改 ab_tag，
/// 并把本簿所有设备 tags 里的 old 换成 new、去重。DELETE tag 忽略不存在的名字，同一事务里删标签并从本簿所有设备的
/// tags 中移除。级联只在本簿内。
#[tokio::test]
async fn tag_rename_and_delete_cascade_to_peers() {
    let s = Server::start().await;
    let alice = s.user("alice", false).await;
    let guid = s.book("Shared", alice.id, false).await;
    let other = s.book("Other", alice.id, false).await;
    s.insert_tag(&guid, "x", RED).await;
    s.insert_tag(&guid, "z", BLUE).await;
    // y 只出现在设备上、ab_tag 里没有（rustdesk-api 遗留的孤儿标签就是这样）。
    s.insert_peer(&guid, "p1", json!({}), json!(["x", "y"]), "", "").await;
    s.insert_peer(&guid, "p2", json!({}), json!(["y", "x", "z"]), "", "").await;
    s.insert_peer(&guid, "p3", json!({}), json!(["z"]), "", "").await;
    s.insert_tag(&other, "x", RED).await;
    s.insert_peer(&other, "q1", json!({}), json!(["x"]), "", "").await;
    let rename = format!("/api/ab/tag/rename/{guid}");
    let sorted_tags = |v: &Value| {
        let mut t: Vec<String> = v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_owned()).collect();
        t.sort();
        t
    };

    assert_error(&s.call("PUT", &rename, &alice.token, r#"{"old":"ghost","new":"w"}"#).await, 404, "rename 不存在");
    assert_error(&s.call("PUT", &rename, &alice.token, r#"{"old":"x","new":"z"}"#).await, 409, "rename 到已存在");
    assert_eq!(s.tag_rows(&guid).await, vec![("x".to_owned(), RED), ("z".to_owned(), BLUE)]);
    assert_eq!(s.peer_row(&guid, "p1").await.unwrap().tags, json!(["x", "y"]));

    assert_action_ok(&s.call("PUT", &rename, &alice.token, r#"{"old":"x","new":"y"}"#).await, "rename x→y");
    assert_eq!(s.tag_rows(&guid).await, vec![("y".to_owned(), RED), ("z".to_owned(), BLUE)]);
    let ps = s.peers(&alice.token, &guid).await;
    assert_eq!(sorted_tags(&ps["p1"]["tags"]), vec!["y"]);
    assert_eq!(sorted_tags(&ps["p2"]["tags"]), vec!["y", "z"]);
    assert_eq!(sorted_tags(&ps["p3"]["tags"]), vec!["z"]);
    let tags = assert_array(&s.read(&format!("/api/ab/tags/{guid}"), &alice.token).await, "rename 后 tags");
    assert_eq!(tags, vec![json!({"name": "y", "color": RED}), json!({"name": "z", "color": BLUE})]);
    // 改名可以带空格（笔记 04 §3.9）。
    assert_action_ok(&s.call("PUT", &rename, &alice.token, r#"{"old":"z","new":"z z"}"#).await, "rename 带空格");
    assert_eq!(sorted_tags(&s.peer_row(&guid, "p3").await.unwrap().tags), vec!["z z"]);

    let del = format!("/api/ab/tag/{guid}");
    assert_action_ok(&s.call("DELETE", &del, &alice.token, r#"["y","ghost"]"#).await, "DELETE tag");
    assert_eq!(s.tag_rows(&guid).await, vec![("z z".to_owned(), BLUE)]);
    let ps = s.peers(&alice.token, &guid).await;
    assert_eq!(ps["p1"]["tags"], json!([]));
    assert_eq!(ps["p2"]["tags"], json!(["z z"]));
    assert_eq!(ps["p3"]["tags"], json!(["z z"]));
    assert_action_ok(&s.call("DELETE", &del, &alice.token, r#"["ghost"]"#).await, "DELETE 不存在的 tag");

    // 别的簿：标签和设备都没动。
    assert_eq!(s.tag_rows(&other).await, vec![("x".to_owned(), RED)]);
    assert_eq!(s.peer_row(&other, "q1").await.unwrap().tags, json!(["x"]));
}
