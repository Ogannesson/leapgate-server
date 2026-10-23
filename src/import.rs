//! One-off import from rustdesk-api's SQLite (PORTA.md §15, note 05 §8).
//!
//! Everything is read into a [`Plan`] first (old rustdesk-api ids), the report is printed, and unless
//! `--dry-run` the plan is written in one transaction, mapping old ids to new ones as rows are inserted.

use crate::{
    api::{
        ab::{check_tag, MAX_PEERS, MAX_PEER_TAGS},
        account::MAX_NAME_LEN,
    },
    cli::RESERVED_BOOK_NAMES,
    crypto::SecretBox,
    peer::MAX_PEER_ID_LEN,
};
use hbb_common::{bail, ResultType};
use sqlx::{
    sqlite::SqliteConnectOptions, Connection as _, SqliteConnection, SqlitePool,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as _,
    path::Path,
};

/// The rustdesk-api schema version note 05 was written against.
const EXPECTED_VERSION: i64 = 265;

/// `porta-server import rustdesk-api <src> [--dry-run]`: opens `src` read-only and imports into an
/// empty Porta database `db` in one transaction; `dry_run` only prints counts and conflicts.
pub(crate) async fn rustdesk_api(
    db: &SqlitePool,
    secret: &SecretBox,
    src: &Path,
    dry_run: bool,
) -> ResultType<()> {
    let plan = plan(db, src).await?;
    print!("{}", plan.report);
    if dry_run {
        println!("Dry run: nothing was written.");
        return Ok(());
    }
    write(db, secret, &plan).await?;
    println!("Imported.");
    Ok(())
}

struct User {
    old_id: i64,
    name: String,
    display_name: String,
    email: String,
    note: String,
    password_hash: String,
    is_admin: bool,
    status: i64,
    created_at: i64,
    group: i64,
}

struct Group {
    old_id: i64,
    name: String,
    share_devices: bool,
}

struct Book {
    old_id: i64,
    owner: i64,
    name: String,
}

/// Where an entry or tag lives: a user's personal book, or a shared book (old ids).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum BookRef {
    Personal(i64),
    Shared(i64),
}

struct Entry {
    book: BookRef,
    id: String,
    data: String,
    tags: String,
    hash: String,
    password: String,
}

struct Tag {
    book: BookRef,
    name: String,
    color: i64,
}

struct Device {
    id: String,
    uuid: String,
    user: Option<i64>,
    hostname: String,
    os: String,
    username: String,
    version: String,
    seen: i64,
    ip: String,
    known: bool,
}

struct Plan {
    users: Vec<User>,
    groups: Vec<Group>,
    books: Vec<Book>,
    /// Owners (old user ids) that get a personal book.
    personal: BTreeSet<i64>,
    /// (old book id, old user id, rule).
    user_rules: Vec<(i64, i64, i64)>,
    /// (old book id, old group id, rule).
    group_rules: Vec<(i64, i64, i64)>,
    entries: Vec<Entry>,
    tags: Vec<Tag>,
    devices: Vec<Device>,
    report: String,
}

async fn open_source(src: &Path) -> ResultType<SqliteConnection> {
    if !src.is_file() {
        bail!("{} is not a file", src.display());
    }
    let opt = SqliteConnectOptions::new().filename(src).read_only(true);
    Ok(SqliteConnection::connect_with(&opt).await?)
}

async fn plan(db: &SqlitePool, src_path: &Path) -> ResultType<Plan> {
    let existing: i64 = sqlx::query_scalar("select count(*) from user").fetch_one(db).await?;
    if existing > 0 {
        bail!("The Porta database already has {existing} user(s); importing is only supported once, into an empty database");
    }
    let src = &mut open_source(src_path).await?;
    let now = crate::common::now() as i64;
    let mut r = String::new();
    let _ = writeln!(r, "Importing from {}", src_path.display());
    match sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(version) FROM versions")
        .fetch_one(&mut *src)
        .await
    {
        Ok(Some(v)) if v == EXPECTED_VERSION => {}
        Ok(v) => {
            let _ = writeln!(r, "WARNING: rustdesk-api schema version {v:?}, this importer was written for {EXPECTED_VERSION}");
        }
        Err(e) => {
            let _ = writeln!(r, "WARNING: cannot read the rustdesk-api schema version ({e})");
        }
    }

    // ---- Users ----
    let rows = sqlx::query_as::<_, (i64, String, String, String, String, String, i64, i64, i64, Option<String>)>(
        "SELECT id, username, email, password, nickname, remark, group_id,
                CAST(is_admin AS INTEGER), status, CAST(created_at AS TEXT)
         FROM users ORDER BY id",
    )
    .fetch_all(&mut *src)
    .await?;
    let mut users = Vec::new();
    let mut unknown_pw = Vec::new();
    for (old_id, name, email, password, nickname, remark, group, is_admin, status, created_at) in rows {
        // Like every user that is not imported, their books, entries, tags and rules are dropped
        // too, and their devices are imported without an owner.
        if name.is_empty() {
            let _ = writeln!(r, "Dropped: user id {old_id} has an empty username, with their address books and device ownership");
            continue;
        }
        // Login refuses longer names, so such a user could never sign in.
        if name.len() > MAX_NAME_LEN {
            let _ = writeln!(
                r,
                "Dropped: user id {old_id} has a user name longer than {MAX_NAME_LEN} bytes ({:?}…), with their address books and device ownership",
                name.chars().take(32).collect::<String>()
            );
            continue;
        }
        let password_hash = if ["$2a$", "$2b$", "$2y$"].iter().any(|p| password.starts_with(p)) {
            password
        } else if password.len() == 32 && password.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            format!("md5:{password}")
        } else {
            if !password.is_empty() {
                unknown_pw.push(name.clone());
            }
            String::new()
        };
        let created_at = created_at
            .and_then(|s| chrono::DateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S%.f%:z").ok())
            .map_or(now, |t| t.timestamp());
        users.push(User {
            old_id,
            name,
            display_name: nickname,
            email,
            note: remark,
            password_hash,
            is_admin: is_admin != 0,
            status: if status == 1 { 1 } else { 0 },
            created_at,
            group,
        });
    }
    let user_ids: HashMap<i64, &User> = users.iter().map(|u| (u.old_id, u)).collect();

    // ---- Groups: the groups table ∪ group ids users point at that the table lacks ----
    let rows = sqlx::query_as::<_, (i64, String, i64)>("SELECT id, name, type FROM groups ORDER BY id")
        .fetch_all(&mut *src)
        .await?;
    let mut group_names: HashSet<String> = sqlx::query_scalar("select name from user_group")
        .fetch_all(db)
        .await?
        .into_iter()
        .collect();
    let mut groups = Vec::new();
    for (old_id, name, typ) in rows {
        let base = if name.is_empty() { format!("rustdesk-api-group-{old_id}") } else { name.clone() };
        let new = unique_group_name(&mut group_names, base, old_id);
        if new != name {
            let _ = writeln!(r, "Renamed group {name:?} (id {old_id}) to {new:?}");
        }
        groups.push(Group { old_id, name: new, share_devices: typ == 2 });
    }
    let missing: BTreeSet<i64> = users
        .iter()
        .map(|u| u.group)
        .filter(|g| !groups.iter().any(|x| x.old_id == *g))
        .collect();
    for old_id in missing {
        let new = unique_group_name(&mut group_names, format!("rustdesk-api-group-{old_id}"), old_id);
        let _ = writeln!(r, "Placeholder group {new:?} for group id {old_id}, which users belong to but the groups table lacks");
        groups.push(Group { old_id, name: new, share_devices: false });
    }
    let group_ids: HashSet<i64> = groups.iter().map(|g| g.old_id).collect();

    // ---- Shared books ----
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT c.id, c.name FROM address_book_collections c
         LEFT JOIN users u ON u.id = c.user_id WHERE u.id IS NULL ORDER BY c.id",
    )
    .fetch_all(&mut *src)
    .await?;
    for (id, name) in rows {
        let _ = writeln!(r, "Dropped: shared address book {name:?} (id {id}), its owner no longer exists");
    }
    let rows = sqlx::query_as::<_, (i64, i64, String)>(
        "SELECT c.id, c.user_id AS owner_id, c.name
         FROM address_book_collections c
         JOIN users u ON u.id = c.user_id
         ORDER BY c.id",
    )
    .fetch_all(&mut *src)
    .await?;
    let mut book_names: HashSet<String> = RESERVED_BOOK_NAMES.iter().map(|s| s.to_string()).collect();
    let mut books = Vec::new();
    for (old_id, owner, name) in rows {
        let Some(owner_user) = user_ids.get(&owner) else {
            let _ = writeln!(r, "Dropped: shared address book {name:?} (id {old_id}), its owner was not imported");
            continue;
        };
        let base = if name.is_empty() { format!("rustdesk-api-book-{old_id}") } else { name.clone() };
        let mut new = base.clone();
        if book_names.contains(&new) {
            new = format!("{base} ({})", owner_user.name);
            let mut n = 2;
            while book_names.contains(&new) {
                new = format!("{base} ({}) {n}", owner_user.name);
                n += 1;
            }
        }
        if new != name {
            let _ = writeln!(r, "Renamed shared address book {name:?} (id {old_id}) to {new:?}");
        }
        book_names.insert(new.clone());
        books.push(Book { old_id, owner, name: new });
    }
    let book_ids: HashSet<i64> = books.iter().map(|b| b.old_id).collect();

    // ---- Rules (not expanded: group rules stay group rules, PORTA.md §15) ----
    let rows = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT r.collection_id, r.to_id, MAX(r.rule) FROM address_book_collection_rules r
         JOIN address_book_collections c ON c.id=r.collection_id AND c.user_id=r.user_id
         JOIN users u ON u.id=r.to_id
         WHERE r.type=1 AND r.rule BETWEEN 1 AND 3 AND r.to_id<>c.user_id
         GROUP BY r.collection_id, r.to_id",
    )
    .fetch_all(&mut *src)
    .await?;
    let user_rules: Vec<(i64, i64, i64)> = rows
        .into_iter()
        .filter(|(book, user, _)| book_ids.contains(book) && user_ids.contains_key(user))
        .collect();
    let rows = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT r.collection_id, r.to_id, MAX(r.rule) FROM address_book_collection_rules r
         JOIN address_book_collections c ON c.id=r.collection_id AND c.user_id=r.user_id
         WHERE r.type=2 AND r.rule BETWEEN 1 AND 3
         GROUP BY r.collection_id, r.to_id",
    )
    .fetch_all(&mut *src)
    .await?;
    let mut group_rules = Vec::new();
    for (book, group, rule) in rows {
        if !group_ids.contains(&group) {
            let _ = writeln!(r, "Dropped: rule of shared address book id {book} for group id {group}, which neither exists nor has members (no effect in rustdesk-api either)");
        } else if book_ids.contains(&book) {
            group_rules.push((book, group, rule));
        }
    }
    let rows = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(
        "SELECT r.id, r.user_id, r.collection_id, r.type, r.to_id, r.rule FROM address_book_collection_rules r
         LEFT JOIN address_book_collections c ON c.id = r.collection_id
         WHERE c.id IS NULL OR c.user_id <> r.user_id OR r.rule NOT BETWEEN 1 AND 3
            OR (r.type = 1 AND NOT EXISTS (SELECT 1 FROM users WHERE id = r.to_id))
            OR r.type NOT IN (1, 2)",
    )
    .fetch_all(&mut *src)
    .await?;
    for (id, owner, book, typ, to, rule) in rows {
        let _ = writeln!(
            r,
            "Dropped: rule id {id} (user_id {owner}, collection {book}, type {typ}, to {to}, rule {rule}): \
             no such book, not set by the book's owner, invalid rule, or the user no longer exists"
        );
    }

    // ---- Entries ----
    const ENTRY_COLUMNS: &str = "a.id AS peer_id, a.username, a.hostname, a.platform, a.alias,
               CAST(a.tags AS TEXT) AS tags_json, a.hash, a.password,
               CAST(a.force_always_relay AS INTEGER) AS force_always_relay,
               a.rdp_port, a.rdp_username, a.login_name";
    type EntryRow = (i64, String, String, String, String, String, String, String, String, i64, String, String, String);
    let personal_rows = sqlx::query_as::<_, EntryRow>(&format!(
        "SELECT a.user_id, {ENTRY_COLUMNS}
         FROM address_books a
         JOIN users u ON u.id = a.user_id
         WHERE a.collection_id = 0
           AND a.id <> ''
           AND a.row_id IN (SELECT MIN(row_id) FROM address_books GROUP BY user_id, collection_id, id)
         ORDER BY a.user_id, a.row_id"
    ))
    .fetch_all(&mut *src)
    .await?;
    let shared_rows = sqlx::query_as::<_, EntryRow>(&format!(
        "SELECT a.collection_id, {ENTRY_COLUMNS}
         FROM address_books a
         JOIN address_book_collections c ON c.id = a.collection_id AND c.user_id = a.user_id
         JOIN users u ON u.id = c.user_id
         WHERE a.collection_id > 0
           AND a.id <> ''
           AND a.row_id IN (SELECT MIN(row_id) FROM address_books GROUP BY user_id, collection_id, id)
         ORDER BY a.collection_id, a.row_id"
    ))
    .fetch_all(&mut *src)
    .await?;
    let mut entries = Vec::new();
    // Tags that Porta's address book writes refuse (`ab::check_tag`), by book and name: imported as
    // they are, only reported (review C-6).
    let mut refused_tags: BTreeMap<(BookRef, String), &str> = BTreeMap::new();
    let mut too_many_tags = false;
    // Entries over what Porta's writes take (review E-4): imported as they are, only reported.
    let mut long_ids = false;
    let mut per_book: BTreeMap<BookRef, i64> = BTreeMap::new();
    let rows = personal_rows
        .into_iter()
        .map(|row| (BookRef::Personal(row.0), row))
        .chain(shared_rows.into_iter().map(|row| (BookRef::Shared(row.0), row)));
    for (book, row) in rows {
        let (_, id, username, hostname, platform, alias, tags, hash, password, far, rdp_port, rdp_username, login_name) = row;
        let imported = match book {
            BookRef::Personal(owner) => user_ids.contains_key(&owner),
            BookRef::Shared(b) => book_ids.contains(&b),
        };
        if !imported {
            continue;
        }
        *per_book.entry(book).or_default() += 1;
        if id.len() > MAX_PEER_ID_LEN {
            long_ids = true;
            let _ = writeln!(
                r,
                "Over the limits: entry {:?}… in {} has an id of {} bytes (Porta takes at most {MAX_PEER_ID_LEN})",
                id.chars().take(32).collect::<String>(),
                book_name(book),
                id.len()
            );
        }
        let data = serde_json::json!({
            "username": username,
            "hostname": hostname,
            "platform": platform,
            "alias": alias,
            "rdpPort": rdp_port,
            "rdpUsername": rdp_username,
            "loginName": login_name,
            "forceAlwaysRelay": if far != 0 { "true" } else { "false" },
        });
        let tags = parse_tags(&tags);
        if tags.len() > MAX_PEER_TAGS {
            too_many_tags = true;
            let _ = writeln!(
                r,
                "Over the limits: entry {id:?} in {} has {} tags (Porta takes at most {MAX_PEER_TAGS} on a peer)",
                book_name(book),
                tags.len()
            );
        }
        for tag in &tags {
            if let Err(why) = check_tag(tag) {
                refused_tags.insert((book, tag.clone()), why);
            }
        }
        entries.push(Entry {
            book,
            id,
            data: data.to_string(),
            tags: serde_json::Value::from(tags).to_string(),
            hash,
            password,
        });
    }
    let full: Vec<(BookRef, i64)> = per_book.into_iter().filter(|(_, n)| *n > MAX_PEERS).collect();
    for (book, n) in &full {
        let _ = writeln!(r, "Over the limits: {} has {n} entries (Porta takes at most {MAX_PEERS} in a book)", book_name(*book));
    }
    if long_ids || !full.is_empty() {
        let _ = writeln!(
            r,
            "These entries and books are imported as they are. An entry whose id is over {MAX_PEER_ID_LEN} bytes \
             cannot be edited (400), only deleted. In a book of more than {MAX_PEERS} entries the client adds no \
             more, and deleting more than {MAX_PEERS} entries at once (select all > Delete) fails (400): delete \
             them in batches of at most {MAX_PEERS}."
        );
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM address_books WHERE id = ''")
        .fetch_one(&mut *src)
        .await?;
    if n > 0 {
        let _ = writeln!(r, "Dropped: {n} address book entr(ies) with an empty device id");
    }
    let rows = sqlx::query_as::<_, (i64, i64, String, i64)>(
        "SELECT user_id, collection_id, id, COUNT(*) FROM address_books
         GROUP BY user_id, collection_id, id HAVING COUNT(*) > 1",
    )
    .fetch_all(&mut *src)
    .await?;
    for (user, book, id, n) in rows {
        let _ = writeln!(r, "Duplicate: entry {id:?} of user_id {user}, collection {book} appears {n} times; kept the first (as rustdesk-api uses it)");
    }
    let rows = sqlx::query_as::<_, (i64, i64, i64, String)>(
        "SELECT a.row_id, a.user_id, a.collection_id, a.id FROM address_books a
         LEFT JOIN address_book_collections c ON c.id = a.collection_id
         LEFT JOIN users u ON u.id = a.user_id
         WHERE u.id IS NULL OR (a.collection_id > 0 AND (c.id IS NULL OR c.user_id <> a.user_id))",
    )
    .fetch_all(&mut *src)
    .await?;
    for (row_id, user, book, id) in rows {
        let _ = writeln!(r, "Dropped: entry {id:?} (row {row_id}, user_id {user}, collection {book}): no such user or book, or not owned by the book's owner");
    }

    // ---- Tags ----
    let rows = sqlx::query_as::<_, (i64, i64, String, i64)>(
        "SELECT t.user_id, t.collection_id, t.name, t.color
         FROM tags t
         JOIN users u ON u.id = t.user_id
         LEFT JOIN address_book_collections c ON c.id = t.collection_id
         WHERE (t.collection_id = 0 OR (c.id IS NOT NULL AND c.user_id = t.user_id))
           AND t.name <> ''
           AND t.id IN (SELECT MIN(id) FROM tags GROUP BY user_id, collection_id, name)
         ORDER BY t.user_id, t.collection_id, t.name",
    )
    .fetch_all(&mut *src)
    .await?;
    let mut tags = Vec::new();
    for (user, book, name, color) in rows {
        let book = if book == 0 { BookRef::Personal(user) } else { BookRef::Shared(book) };
        let imported = match book {
            BookRef::Personal(owner) => user_ids.contains_key(&owner),
            BookRef::Shared(b) => book_ids.contains(&b),
        };
        if imported {
            if let Err(why) = check_tag(&name) {
                refused_tags.insert((book, name.clone()), why);
            }
            tags.push(Tag { book, name, color });
        }
    }
    let listed: HashSet<(BookRef, &str)> = tags.iter().map(|t| (t.book, t.name.as_str())).collect();
    for ((book, name), why) in &refused_tags {
        let orphan = if listed.contains(&(*book, name.as_str())) {
            ""
        } else {
            "; not in the book's tag list, so the client can neither rename nor untick it"
        };
        let _ = writeln!(r, "Over the limits: tag {name:?} in {}: {why}{orphan}", book_name(*book));
    }
    if !refused_tags.is_empty() || too_many_tags {
        let _ = writeln!(
            r,
            "Entries and tags over the limits are imported as they are, but Porta refuses them in a peer's \
             tags (400): editing the tags of such an entry fails as long as it keeps such a tag or more than \
             {MAX_PEER_TAGS} tags, and so does adding the entry to a book that has the tag. After the import, \
             rename these tags (client: tag menu > Rename) and untick tags on those entries."
        );
    }
    let rows = sqlx::query_as::<_, (i64, i64, String, i64)>(
        "SELECT user_id, collection_id, name, COUNT(*) FROM tags
         GROUP BY user_id, collection_id, name HAVING COUNT(*) > 1",
    )
    .fetch_all(&mut *src)
    .await?;
    for (user, book, name, n) in rows {
        let _ = writeln!(r, "Duplicate: tag {name:?} of user_id {user}, collection {book} appears {n} times; kept the first");
    }
    let rows = sqlx::query_as::<_, (i64, i64, i64, String)>(
        "SELECT t.id, t.user_id, t.collection_id, t.name FROM tags t
         LEFT JOIN users u ON u.id = t.user_id
         LEFT JOIN address_book_collections c ON c.id = t.collection_id
         WHERE u.id IS NULL OR (t.collection_id > 0 AND (c.id IS NULL OR c.user_id <> t.user_id))
            OR t.name = ''",
    )
    .fetch_all(&mut *src)
    .await?;
    for (id, user, book, name) in rows {
        let _ = writeln!(r, "Dropped: tag {name:?} (id {id}, user_id {user}, collection {book}): empty name, or no such user or book");
    }

    let personal: BTreeSet<i64> = entries
        .iter()
        .map(|e| e.book)
        .chain(tags.iter().map(|t| t.book))
        .filter_map(|b| match b {
            BookRef::Personal(owner) => Some(owner),
            BookRef::Shared(_) => None,
        })
        .collect();

    // ---- Devices (owner of each device) ----
    let known: HashSet<String> = sqlx::query_scalar("select id from device").fetch_all(db).await?.into_iter().collect();
    let rows = sqlx::query_as::<_, (String, String, i64, String, String, String, String, i64, String)>(
        "SELECT p.id AS peer_id, p.uuid, p.user_id, p.hostname, p.os, p.username, p.version,
                p.last_online_time, p.last_online_ip
         FROM peers p
         WHERE p.row_id IN (SELECT MIN(row_id) FROM peers GROUP BY id)",
    )
    .fetch_all(&mut *src)
    .await?;
    let devices: Vec<Device> = rows
        .into_iter()
        .map(|(id, uuid, user, hostname, os, username, version, seen, ip)| Device {
            known: known.contains(&id),
            id,
            uuid,
            user: user_ids.contains_key(&user).then_some(user),
            hostname,
            os,
            username,
            version,
            seen: if seen == 0 { now } else { seen },
            ip,
        })
        .collect();

    // ---- Summary ----
    let thirds: HashMap<i64, String> = sqlx::query_as::<_, (i64, String)>(
        "SELECT user_id, group_concat(op) FROM user_thirds GROUP BY user_id",
    )
    .fetch_all(&mut *src)
    .await?
    .into_iter()
    .collect();
    for name in &unknown_pw {
        let _ = writeln!(r, "Unrecognized password format for {name:?}: imported without a password");
    }
    let no_pw: Vec<String> = users
        .iter()
        .filter(|u| u.password_hash.is_empty())
        .map(|u| match thirds.get(&u.old_id) {
            Some(ops) => format!("{} (third-party login: {ops})", u.name),
            None => u.name.clone(),
        })
        .collect();
    if !no_pw.is_empty() {
        let _ = writeln!(r, "Users without a password (set one with `porta-server user passwd <name>`): {}", no_pw.join(", "));
    }
    let _ = writeln!(
        r,
        "Users: {} ({} admin, {} disabled)",
        users.len(),
        users.iter().filter(|u| u.is_admin).count(),
        users.iter().filter(|u| u.status != 1).count()
    );
    let _ = writeln!(
        r,
        "Groups: {} ({} sharing devices), memberships: {}",
        groups.len(),
        groups.iter().filter(|g| g.share_devices).count(),
        users.len()
    );
    let _ = writeln!(r, "Address books: {} personal, {} shared", personal.len(), books.len());
    let _ = writeln!(r, "Rules: {} for users, {} for groups", user_rules.len(), group_rules.len());
    let _ = writeln!(r, "Entries: {}, tags: {}", entries.len(), tags.len());
    let _ = writeln!(
        r,
        "Devices: {} ({} with an owner; {} already known to Porta, only their owner is filled in)",
        devices.len(),
        devices.iter().filter(|d| d.user.is_some()).count(),
        devices.iter().filter(|d| d.known).count()
    );
    let _ = writeln!(r, "Not imported: login tokens (everyone signs in again), login logs, audit records");

    Ok(Plan {
        users,
        groups,
        books,
        personal,
        user_rules,
        group_rules,
        entries,
        tags,
        devices,
        report: r,
    })
}

/// A book in the report, by its rustdesk-api ids.
fn book_name(book: BookRef) -> String {
    match book {
        BookRef::Personal(owner) => format!("the personal book of user_id {owner}"),
        BookRef::Shared(id) => format!("collection {id}"),
    }
}

/// Duplicate group names get `-<old id>` appended (PORTA.md §15).
fn unique_group_name(taken: &mut HashSet<String>, base: String, old_id: i64) -> String {
    let mut name = base;
    while taken.contains(&name) {
        name = format!("{name}-{old_id}");
    }
    taken.insert(name.clone());
    name
}

/// `tags` as TEXT (some rows are BLOB): a JSON array; only its string elements count, without
/// duplicates. `null`, empty or malformed → no tags.
fn parse_tags(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(serde_json::Value::Array(items)) = serde_json::from_str(text) {
        for item in items {
            if let serde_json::Value::String(s) = item {
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    }
    out
}

async fn write(db: &SqlitePool, secret: &SecretBox, plan: &Plan) -> ResultType<()> {
    let now = crate::common::now() as i64;
    let mut tx = db.begin().await?;
    let mut users = HashMap::new();
    for u in &plan.users {
        let id: i64 = sqlx::query_scalar(
            "insert into user(name, display_name, email, note, password_hash, is_admin, status, created_at, updated_at)
             values(?, ?, ?, ?, ?, ?, ?, ?, ?) returning id",
        )
        .bind(&u.name)
        .bind(&u.display_name)
        .bind(&u.email)
        .bind(&u.note)
        .bind(&u.password_hash)
        .bind(u.is_admin)
        .bind(u.status)
        .bind(u.created_at)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        users.insert(u.old_id, id);
    }
    let mut groups = HashMap::new();
    for g in &plan.groups {
        let id: i64 = sqlx::query_scalar(
            "insert into user_group(name, share_devices, created_at) values(?, ?, ?) returning id",
        )
        .bind(&g.name)
        .bind(g.share_devices)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        groups.insert(g.old_id, id);
    }
    for u in &plan.users {
        sqlx::query("insert into group_member(group_id, user_id) values(?, ?)")
            .bind(groups.get(&u.group))
            .bind(users.get(&u.old_id))
            .execute(&mut *tx)
            .await?;
    }
    let mut books: BTreeMap<BookRef, String> = BTreeMap::new();
    let books_to_create = plan
        .personal
        .iter()
        .map(|owner| (BookRef::Personal(*owner), *owner, "My address book", 1))
        .chain(plan.books.iter().map(|b| (BookRef::Shared(b.old_id), b.owner, b.name.as_str(), 0)));
    for (book, owner, name, personal) in books_to_create {
        let guid = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "insert into ab(guid, name, owner_id, personal, created_at, updated_at) values(?, ?, ?, ?, ?, ?)",
        )
        .bind(&guid)
        .bind(name)
        .bind(users.get(&owner))
        .bind(personal)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        books.insert(book, guid);
    }
    for (book, user, rule) in &plan.user_rules {
        sqlx::query("insert into ab_rule(ab_guid, user_id, rule) values(?, ?, ?)")
            .bind(books.get(&BookRef::Shared(*book)))
            .bind(users.get(user))
            .bind(rule)
            .execute(&mut *tx)
            .await?;
    }
    for (book, group, rule) in &plan.group_rules {
        sqlx::query("insert into ab_rule(ab_guid, group_id, rule) values(?, ?, ?)")
            .bind(books.get(&BookRef::Shared(*book)))
            .bind(groups.get(group))
            .bind(rule)
            .execute(&mut *tx)
            .await?;
    }
    for e in &plan.entries {
        sqlx::query(
            "insert into ab_peer(ab_guid, id, data, tags, hash_enc, password_enc, created_at, updated_at)
             values(?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(books.get(&e.book))
        .bind(&e.id)
        .bind(&e.data)
        .bind(&e.tags)
        .bind(secret.encrypt(&e.hash))
        .bind(secret.encrypt(&e.password))
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    for t in &plan.tags {
        sqlx::query("insert into ab_tag(ab_guid, name, color) values(?, ?, ?)")
            .bind(books.get(&t.book))
            .bind(&t.name)
            .bind(t.color)
            .execute(&mut *tx)
            .await?;
    }
    for d in &plan.devices {
        // Devices that already reported to Porta keep their fresher data; only the owner is filled in.
        sqlx::query(
            "insert into device(id, uuid, user_id, hostname, username, os, version, first_seen_at, last_seen_at, last_ip)
             values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             on conflict(id) do update set user_id = coalesce(device.user_id, excluded.user_id)",
        )
        .bind(&d.id)
        .bind(&d.uuid)
        .bind(d.user.and_then(|u| users.get(&u)))
        .bind(&d.hostname)
        .bind(&d.username)
        .bind(&d.os)
        .bind(&d.version)
        .bind(d.seen)
        .bind(d.seen)
        .bind(&d.ip)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{verify_password, PasswordCheck};
    use hbb_common::tokio;

    /// rustdesk-api's tables as gorm creates them (note 05 §2, measured DDL).
    const SOURCE_DDL: &str = r#"
CREATE TABLE `users` (`id` integer PRIMARY KEY AUTOINCREMENT,`username` text NOT NULL DEFAULT "",`email` text NOT NULL DEFAULT "",`password` text NOT NULL DEFAULT "",`nickname` text NOT NULL DEFAULT "",`avatar` text NOT NULL DEFAULT "",`group_id` integer NOT NULL DEFAULT 0,`is_admin` numeric NOT NULL DEFAULT false,`status` integer NOT NULL DEFAULT 1,`remark` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);
CREATE UNIQUE INDEX `idx_users_username` ON `users`(`username`);
CREATE TABLE `groups` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL DEFAULT "",`type` integer NOT NULL DEFAULT 1,`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `address_book_collections` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`name` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `address_book_collection_rules` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`collection_id` integer NOT NULL DEFAULT 0,`rule` integer NOT NULL DEFAULT 0,`type` integer NOT NULL DEFAULT 1,`to_id` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `address_books` (`row_id` integer PRIMARY KEY AUTOINCREMENT,`id` text NOT NULL DEFAULT "0",`username` text NOT NULL DEFAULT "",`password` text NOT NULL DEFAULT "",`hostname` text NOT NULL DEFAULT "",`alias` text NOT NULL DEFAULT "",`platform` text NOT NULL DEFAULT "",`tags` text NOT NULL,`hash` text NOT NULL DEFAULT "",`user_id` integer NOT NULL DEFAULT 0,`force_always_relay` numeric NOT NULL DEFAULT false,`rdp_port` text NOT NULL DEFAULT "",`rdp_username` text NOT NULL DEFAULT "",`online` numeric NOT NULL DEFAULT false,`login_name` text NOT NULL DEFAULT "",`same_server` numeric NOT NULL DEFAULT false,`collection_id` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `tags` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL DEFAULT "",`user_id` integer NOT NULL DEFAULT 0,`color` integer NOT NULL DEFAULT 0,`collection_id` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `peers` (`row_id` integer PRIMARY KEY AUTOINCREMENT,`id` text NOT NULL DEFAULT "",`cpu` text NOT NULL DEFAULT "",`hostname` text NOT NULL DEFAULT "",`memory` text NOT NULL DEFAULT "",`os` text NOT NULL DEFAULT "",`username` text NOT NULL DEFAULT "",`uuid` text NOT NULL DEFAULT "",`version` text NOT NULL DEFAULT "",`user_id` integer NOT NULL DEFAULT 0,`last_online_time` integer NOT NULL DEFAULT 0,`last_online_ip` text NOT NULL DEFAULT "",`group_id` integer NOT NULL DEFAULT 0,`alias` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `user_thirds` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL,`open_id` text NOT NULL,`name` text,`username` text,`email` text,`verified_email` numeric,`picture` text,`union_id` text NOT NULL DEFAULT "",`third_type` text NOT NULL DEFAULT "",`oauth_type` text NOT NULL DEFAULT "",`op` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);
CREATE TABLE `versions` (`id` integer PRIMARY KEY AUTOINCREMENT,`version` integer,`created_at` timestamp,`updated_at` timestamp);
"#;

    const BCRYPT: &str = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    /// Edge cases of note 05: password formats, disabled users, type=2 and placeholder groups, rules
    /// with duplicates and every drop reason, TEXT/BLOB/null tags, duplicate entries and tags,
    /// orphans, reserved and duplicate shared book names, device owners.
    fn source_data(md5: &str) -> String {
        format!(
            r#"
INSERT INTO versions(version) VALUES (264), (265);
INSERT INTO users(id, username, password, nickname, email, remark, group_id, is_admin, status, created_at) VALUES
 (1, 'admin', '{BCRYPT}', 'Admin', 'a@x', 'boss', 1, true, 1, '2026-10-22 18:37:17.4472008+08:00'),
 (2, 'bob', '{md5}', '', '', '', 2, false, 2, NULL),
 (3, 'carol', '', '', '', '', 7, 0, 1, '2026-10-22 18:37:17+08:00'),
 (4, 'dave', 'plaintext', '', '', '', 2, 0, 1, 'garbage'),
 (5, 'eve', '$2y$10$abcdefghijklmnopqrstuuJ1Hf7eAr0v0p4SE1mKlE5eKcV9HnX5e', '', '', '', 1, 0, 1, NULL),
 (6, '', '', '', '', '', 1, 0, 1, NULL);
INSERT INTO user_thirds(user_id, open_id, op) VALUES (3, 'o1', 'github'), (3, 'o2', 'google');
INSERT INTO groups(id, name, type) VALUES (1, 'Default', 1), (2, 'Share', 2), (3, 'Default', 1), (4, 'rustdesk-api-group-7', 1), (5, '', 1);
INSERT INTO address_book_collections(id, user_id, name) VALUES
 (10, 1, 'Team'), (11, 2, 'Team'), (12, 5, 'My address book'), (13, 99, 'Ghost'), (14, 6, 'Nameless owner');
INSERT INTO address_book_collection_rules(user_id, collection_id, type, to_id, rule) VALUES
 (1, 10, 1, 2, 1), (1, 10, 1, 2, 2), (1, 10, 1, 1, 3),
 (1, 10, 2, 2, 1), (1, 10, 2, 2, 3), (1, 10, 2, 7, 2), (1, 10, 2, 42, 1),
 (2, 10, 1, 3, 1), (1, 10, 1, 77, 1), (1, 10, 1, 3, 5), (1, 10, 3, 3, 1), (1, 55, 1, 3, 1),
 (2, 11, 1, 1, 2), (5, 12, 2, 1, 1);
INSERT INTO address_books(row_id, user_id, collection_id, id, alias, hash, password, tags, force_always_relay, rdp_port, username, hostname, platform, rdp_username, login_name, same_server, online) VALUES
 (1, 1, 0, '111', 'pc', 'H1', '', '["a","b","a",3,null]', true, '3389', 'u', 'h', 'Windows', 'ru', 'ln', true, true),
 (2, 1, 0, '111', 'dup', '', '', '[]', false, '', '', '', '', '', '', false, false),
 (3, 1, 0, '222', '', '', '', X'5B2263225D', false, '', '', '', '', '', '', false, false),
 (4, 1, 0, '333', '', '', '', 'null', false, '', '', '', '', '', '', false, false),
 (5, 2, 0, '111', '', '', '', X'6E756C6C', false, '', '', '', '', '', '', false, false),
 (6, 1, 0, '', '', '', '', '[]', false, '', '', '', '', '', '', false, false),
 (7, 1, 10, '444', '', '', 'secret', 'not json', false, '', '', '', '', '', '', false, false),
 (8, 2, 10, '555', '', '', '', '[]', false, '', '', '', '', '', '', false, false),
 (9, 99, 13, '666', '', '', '', '[]', false, '', '', '', '', '', '', false, false),
 (10, 99, 0, '777', '', '', '', '[]', false, '', '', '', '', '', '', false, false),
 (11, 5, 12, '888', '', '', '', '{{"a":1}}', false, '', '', '', '', '', '', false, false);
INSERT INTO tags(id, user_id, collection_id, name, color) VALUES
 (1, 1, 0, 'a', 4280391411), (2, 1, 0, 'a', 1), (3, 1, 10, 'x', 5), (4, 1, 13, 'y', 6), (5, 1, 50, 'z', 6),
 (6, 2, 0, 'b', 7), (7, 5, 0, '', 8), (8, 3, 0, 'c', 9);
INSERT INTO peers(row_id, id, uuid, user_id, hostname, os, username, version, last_online_time, last_online_ip) VALUES
 (1, '111', 'u1', 1, 'h1', 'Windows 11', 'x', '1.4.2', 1700000000, '1.2.3.4'),
 (2, '111', 'u1b', 2, 'h1b', '', '', '', 1, ''),
 (3, '222', 'u2', 0, 'h2', '', '', '', 0, ''),
 (4, '333', 'u3', 99, 'h3', '', '', '', 5, ''),
 (5, '900', 'u9', 2, 'old', '', '', '1.3.0', 5, '');
"#
        )
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        db: SqlitePool,
        secret: SecretBox,
        src: std::path::PathBuf,
    }

    async fn fixture() -> Fixture {
        let (dir, db) = crate::testutil::pool().await;
        let secret = SecretBox::load_or_create(&dir.path().join(crate::crypto::SECRET_KEY_FILE)).unwrap();
        let src = dir.path().join("rustdeskapi.db");
        // rustdesk-api does not set WAL (note 05 §0).
        let opt = SqliteConnectOptions::new()
            .filename(&src)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete);
        let mut conn = SqliteConnection::connect_with(&opt).await.unwrap();
        // md5("pw" + "rustdesk-api"), lowercase hex
        let md5 = {
            use md5::{Digest as _, Md5};
            Md5::digest(b"pwrustdesk-api").iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        sqlx::raw_sql(SOURCE_DDL).execute(&mut conn).await.unwrap();
        sqlx::raw_sql(&source_data(&md5)).execute(&mut conn).await.unwrap();
        conn.close().await.unwrap();
        Fixture { _dir: dir, db, secret, src }
    }

    async fn count(db: &SqlitePool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(db).await.unwrap()
    }

    #[tokio::test]
    async fn imports_everything() {
        let f = fixture().await;
        let db = &f.db;
        // A device that already reported to Porta before the import.
        sqlx::query("insert into device(id, hostname, first_seen_at, last_seen_at) values('900', 'fresh', 10, 20)")
            .execute(db)
            .await
            .unwrap();
        let before = crate::common::now() as i64;
        let p = plan(db, &f.src).await.unwrap();
        let report = p.report.clone();
        write(db, &f.secret, &p).await.unwrap();

        // Users.
        let users: Vec<(String, String, String, String, String, bool, i64, i64)> = sqlx::query_as(
            "select name, display_name, email, note, password_hash, is_admin, status, created_at from user order by name",
        )
        .fetch_all(db)
        .await
        .unwrap();
        assert_eq!(users.len(), 5);
        let u = |name: &str| users.iter().find(|u| u.0 == name).unwrap().clone();
        let admin = u("admin");
        assert_eq!((admin.1.as_str(), admin.2.as_str(), admin.3.as_str()), ("Admin", "a@x", "boss"));
        assert_eq!(admin.4, BCRYPT);
        assert!(admin.5);
        assert_eq!(admin.6, 1);
        let created = chrono::DateTime::parse_from_rfc3339("2026-10-22T10:37:17Z").unwrap().timestamp();
        assert_eq!(admin.7, created);
        let bob = u("bob");
        assert!(bob.4.starts_with("md5:"));
        assert_eq!(verify_password("pw", &bob.4), PasswordCheck::OkNeedsUpgrade);
        assert!(!bob.5);
        assert_eq!(bob.6, 0, "rustdesk-api status 2 = disabled");
        assert!(bob.7 >= before);
        assert_eq!(u("carol").4, "");
        assert_eq!(u("carol").7, created);
        assert_eq!(u("dave").4, "", "unrecognized format");
        assert!(u("dave").7 >= before);
        assert!(u("eve").4.starts_with("$2y$"));

        // Groups and members.
        let groups: Vec<(String, bool)> = sqlx::query_as("select name, share_devices from user_group order by name")
            .fetch_all(db)
            .await
            .unwrap();
        let names: Vec<&str> = groups.iter().map(|g| g.0.as_str()).collect();
        assert_eq!(
            names,
            ["Default", "Default-3", "Share", "rustdesk-api-group-5", "rustdesk-api-group-7", "rustdesk-api-group-7-7"]
        );
        assert!(groups.iter().find(|g| g.0 == "Share").unwrap().1);
        assert_eq!(groups.iter().filter(|g| g.1).count(), 1);
        let members: Vec<(String, String)> = sqlx::query_as(
            "select g.name, u.name from group_member m join user_group g on g.id = m.group_id
             join user u on u.id = m.user_id order by u.name",
        )
        .fetch_all(db)
        .await
        .unwrap();
        let pair = |g: &str, u: &str| (g.to_owned(), u.to_owned());
        assert_eq!(
            members,
            vec![
                pair("Default", "admin"),
                pair("Share", "bob"),
                pair("rustdesk-api-group-7-7", "carol"),
                pair("Share", "dave"),
                pair("Default", "eve")
            ]
        );

        // Books.
        let books: Vec<(String, String, bool)> = sqlx::query_as(
            "select a.name, u.name, a.personal from ab a join user u on u.id = a.owner_id order by a.personal, a.name, u.name",
        )
        .fetch_all(db)
        .await
        .unwrap();
        let book = |n: &str, o: &str, p: bool| (n.to_owned(), o.to_owned(), p);
        assert_eq!(
            books,
            vec![
                book("My address book (eve)", "eve", false),
                book("Team", "admin", false),
                book("Team (bob)", "bob", false),
                book("My address book", "admin", true),
                book("My address book", "bob", true),
                book("My address book", "carol", true),
            ]
        );

        // Rules: group rules stay group rules, duplicates collapse to the maximum.
        let rules: Vec<(String, Option<String>, Option<String>, i64)> = sqlx::query_as(
            "select a.name, u.name, g.name, r.rule from ab_rule r join ab a on a.guid = r.ab_guid
             left join user u on u.id = r.user_id left join user_group g on g.id = r.group_id
             order by a.name, u.name, g.name",
        )
        .fetch_all(db)
        .await
        .unwrap();
        let rule = |b: &str, u: Option<&str>, g: Option<&str>, r: i64| {
            (b.to_owned(), u.map(str::to_owned), g.map(str::to_owned), r)
        };
        assert_eq!(
            rules,
            vec![
                rule("My address book (eve)", None, Some("Default"), 1),
                rule("Team", None, Some("Share"), 3),
                rule("Team", None, Some("rustdesk-api-group-7-7"), 2),
                rule("Team", Some("bob"), None, 2),
                rule("Team (bob)", Some("admin"), None, 2),
            ]
        );

        // Entries.
        let entries: Vec<(String, String, String, String, String, String, String)> = sqlx::query_as(
            "select a.name, u.name, p.id, p.data, p.tags, p.hash_enc, p.password_enc from ab_peer p
             join ab a on a.guid = p.ab_guid join user u on u.id = a.owner_id order by a.name, u.name, p.id",
        )
        .fetch_all(db)
        .await
        .unwrap();
        let keys: Vec<(&str, &str, &str)> = entries.iter().map(|e| (e.0.as_str(), e.1.as_str(), e.2.as_str())).collect();
        assert_eq!(
            keys,
            [
                ("My address book", "admin", "111"),
                ("My address book", "admin", "222"),
                ("My address book", "admin", "333"),
                ("My address book", "bob", "111"),
                ("My address book (eve)", "eve", "888"),
                ("Team", "admin", "444"),
            ]
        );
        let first: serde_json::Value = serde_json::from_str(&entries[0].3).unwrap();
        assert_eq!(
            first,
            serde_json::json!({"username": "u", "hostname": "h", "platform": "Windows", "alias": "pc",
                "rdpPort": "3389", "rdpUsername": "ru", "loginName": "ln", "forceAlwaysRelay": "true"})
        );
        assert_eq!(entries[0].4, r#"["a","b"]"#);
        assert!(entries[0].5.starts_with("sb1:"));
        assert_eq!(f.secret.decrypt(&entries[0].5).unwrap(), "H1");
        assert_eq!(entries[0].6, "");
        let second: serde_json::Value = serde_json::from_str(&entries[1].3).unwrap();
        assert_eq!(second["forceAlwaysRelay"], "false");
        assert_eq!(entries[1].4, r#"["c"]"#, "BLOB tags");
        assert_eq!(entries[2].4, "[]", "TEXT null");
        assert_eq!(entries[3].4, "[]", "BLOB null");
        assert_eq!(entries[4].4, "[]", "not an array");
        assert_eq!(entries[5].4, "[]", "not JSON");
        assert_eq!(entries[5].5, "");
        assert_eq!(f.secret.decrypt(&entries[5].6).unwrap(), "secret");

        // Tags.
        let tags: Vec<(String, String, String, i64)> = sqlx::query_as(
            "select a.name, u.name, t.name, t.color from ab_tag t join ab a on a.guid = t.ab_guid
             join user u on u.id = a.owner_id order by a.name, u.name, t.name",
        )
        .fetch_all(db)
        .await
        .unwrap();
        let tag = |b: &str, o: &str, n: &str, c: i64| (b.to_owned(), o.to_owned(), n.to_owned(), c);
        assert_eq!(
            tags,
            vec![
                tag("My address book", "admin", "a", 4280391411),
                tag("My address book", "bob", "b", 7),
                tag("My address book", "carol", "c", 9),
                tag("Team", "admin", "x", 5),
            ]
        );

        // Devices.
        let devices: Vec<(String, String, Option<String>, String, String, String, String, i64, i64, String, String, String)> =
            sqlx::query_as(
                "select d.id, d.uuid, u.name, d.hostname, d.os, d.username, d.version, d.first_seen_at, d.last_seen_at,
                   d.last_ip, d.sysinfo, d.client_type from device d left join user u on u.id = d.user_id order by d.id",
            )
            .fetch_all(db)
            .await
            .unwrap();
        assert_eq!(devices.len(), 4);
        let d111 = &devices[0];
        assert_eq!(
            (d111.1.as_str(), d111.2.as_deref(), d111.3.as_str(), d111.4.as_str(), d111.5.as_str(), d111.6.as_str()),
            ("u1", Some("admin"), "h1", "Windows 11", "x", "1.4.2")
        );
        assert_eq!((d111.7, d111.8, d111.9.as_str(), d111.10.as_str(), d111.11.as_str()), (1700000000, 1700000000, "1.2.3.4", "", "rustdesk"));
        assert_eq!(devices[1].0, "222");
        assert_eq!(devices[1].2, None, "user_id 0");
        assert!(devices[1].7 >= before, "last_online_time 0");
        assert_eq!(devices[2].0, "333");
        assert_eq!(devices[2].2, None, "unknown user");
        assert_eq!(devices[3].0, "900");
        assert_eq!(devices[3].2.as_deref(), Some("bob"));
        assert_eq!((devices[3].3.as_str(), devices[3].7), ("fresh", 10), "existing row keeps its data");

        // Report.
        for needle in [
            "user id 6 has an empty username",
            "Renamed group \"Default\" (id 3) to \"Default-3\"",
            "Renamed group \"\" (id 5) to \"rustdesk-api-group-5\"",
            "Placeholder group \"rustdesk-api-group-7-7\" for group id 7",
            "Renamed shared address book \"Team\" (id 11) to \"Team (bob)\"",
            "Renamed shared address book \"My address book\" (id 12) to \"My address book (eve)\"",
            "\"Ghost\" (id 13), its owner no longer exists",
            "\"Nameless owner\" (id 14), its owner was not imported",
            "for group id 42",
            "to 77",
            "to 3, rule 5",
            "type 3",
            "collection 55",
            "1 address book entr(ies) with an empty device id",
            "entry \"111\" of user_id 1, collection 0 appears 2 times",
            "entry \"555\"",
            "entry \"666\"",
            "entry \"777\"",
            "tag \"a\" of user_id 1, collection 0 appears 2 times",
            "tag \"y\"",
            "tag \"z\"",
            "Unrecognized password format for \"dave\"",
            "carol (third-party login: github,google)",
            "Users: 5 (1 admin, 1 disabled)",
            "Address books: 3 personal, 3 shared",
            "Rules: 2 for users, 3 for groups",
            "Entries: 6, tags: 4",
            "Devices: 4 (2 with an owner; 1 already known",
        ] {
            assert!(report.contains(needle), "missing {needle:?} in:\n{report}");
        }
        assert!(report.contains("rule id 8 (user_id 2, collection 10, type 1, to 3, rule 1)"), "{report}");
        assert!(!report.contains("WARNING"), "{report}");
        assert!(!report.contains("Over the limits") && !report.contains("as they are"), "{report}");

        // Only once.
        let err = plan(db, &f.src).await.err().unwrap().to_string();
        assert!(err.contains("already has 5 user(s)"), "{err}");
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let f = fixture().await;
        rustdesk_api(&f.db, &f.secret, &f.src, true).await.unwrap();
        for table in ["user", "user_group", "ab", "ab_peer", "ab_tag", "ab_rule", "device"] {
            assert_eq!(count(&f.db, &format!("select count(*) from {table}")).await, 0, "{table}");
        }
        rustdesk_api(&f.db, &f.secret, &f.src, false).await.unwrap();
        assert_eq!(count(&f.db, "select count(*) from user").await, 5);
        // The source was opened read-only and is unchanged.
        let opt = SqliteConnectOptions::new().filename(&f.src).read_only(true);
        let mut conn = SqliteConnection::connect_with(&opt).await.unwrap();
        let n: i64 = sqlx::query_scalar("select count(*) from users").fetch_one(&mut conn).await.unwrap();
        assert_eq!(n, 6);
    }

    /// Login refuses names over `MAX_NAME_LEN` bytes: such users are dropped like nameless ones.
    #[tokio::test]
    async fn over_long_user_names_dropped() {
        let f = fixture().await;
        let long = "é".repeat(MAX_NAME_LEN / 2) + "x";
        let max = "m".repeat(MAX_NAME_LEN);
        let mut conn = SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&f.src)).await.unwrap();
        sqlx::query("INSERT INTO users(id, username, group_id) VALUES (20, ?, 1), (21, ?, 1)")
            .bind(&long)
            .bind(&max)
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::raw_sql(
            "INSERT INTO address_books(user_id, collection_id, id, tags) VALUES (20, 0, 'L1', '[]'), (20, 15, 'L2', '[]');
             INSERT INTO address_book_collections(id, user_id, name) VALUES (15, 20, 'Long owner');
             INSERT INTO address_book_collection_rules(user_id, collection_id, type, to_id, rule) VALUES (1, 10, 1, 20, 2);
             INSERT INTO peers(id, uuid, user_id) VALUES ('L3', 'u', 20);",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        conn.close().await.unwrap();

        let p = plan(&f.db, &f.src).await.unwrap();
        assert!(p.users.iter().all(|u| u.old_id != 20));
        assert!(p.users.iter().any(|u| u.old_id == 21), "exactly {MAX_NAME_LEN} bytes is fine");
        assert!(p.entries.iter().all(|e| e.id != "L1" && e.id != "L2"));
        assert!(p.books.iter().all(|b| b.old_id != 15));
        assert!(p.user_rules.iter().all(|r| r.1 != 20));
        assert_eq!(p.devices.iter().find(|d| d.id == "L3").unwrap().user, None);
        let short: String = long.chars().take(32).collect();
        for needle in [
            format!("Dropped: user id 20 has a user name longer than {MAX_NAME_LEN} bytes ({short:?}…)"),
            "\"Long owner\" (id 15), its owner was not imported".to_owned(),
            "Users: 6 ".to_owned(),
        ] {
            assert!(p.report.contains(&needle), "missing {needle:?} in:\n{}", p.report);
        }
        write(&f.db, &f.secret, &p).await.unwrap();
        assert_eq!(count(&f.db, "select max(length(cast(name as blob))) from user").await, MAX_NAME_LEN as i64);
    }

    /// Tags Porta's writes refuse (over 64 bytes, control characters) and entries with more than 64
    /// tags are imported unchanged and listed in the report (review C-6).
    #[tokio::test]
    async fn over_limit_tags_reported() {
        let f = fixture().await;
        let long = "长".repeat(30);
        let many: Vec<String> = (0..65).map(|i| format!("t{i}")).collect();
        let entry_tags = serde_json::json!([long, "ok", "a\u{1}b"]).to_string();
        let mut conn = SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&f.src)).await.unwrap();
        sqlx::query("INSERT INTO address_books(user_id, collection_id, id, tags) VALUES (1, 0, 'T1', ?), (1, 10, 'T2', ?)")
            .bind(&entry_tags)
            .bind(serde_json::json!(many).to_string())
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO tags(user_id, collection_id, name, color) VALUES (1, 0, ?, 1), (1, 0, 'ok', 1)")
            .bind(&long)
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();

        let p = plan(&f.db, &f.src).await.unwrap();
        for needle in [
            format!("Over the limits: tag {long:?} in the personal book of user_id 1: Tag name too long\n"),
            "Over the limits: tag \"a\\u{1}b\" in the personal book of user_id 1: Tag name contains control \
             characters; not in the book's tag list"
                .to_owned(),
            "Over the limits: entry \"T2\" in collection 10 has 65 tags".to_owned(),
            "rename these tags".to_owned(),
        ] {
            assert!(p.report.contains(&needle), "missing {needle:?} in:\n{}", p.report);
        }
        assert!(!p.report.contains("tag \"ok\""), "{}", p.report);
        write(&f.db, &f.secret, &p).await.unwrap();
        let stored: Vec<String> = sqlx::query_scalar("select tags from ab_peer where id in ('T1', 'T2') order by id")
            .fetch_all(&f.db)
            .await
            .unwrap();
        assert_eq!(stored, [entry_tags, serde_json::json!(many).to_string()], "imported unchanged");
        assert_eq!(count(&f.db, &format!("select count(*) from ab_tag where name = '{long}'")).await, 1);
    }

    /// Entries with an id over `MAX_PEER_ID_LEN` and books of more than `MAX_PEERS` entries are
    /// imported unchanged and listed in the report (review E-4).
    #[tokio::test]
    async fn over_limit_entries_reported() {
        let f = fixture().await;
        let long = "長".repeat(MAX_PEER_ID_LEN / 3 + 1);
        let mut conn = SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&f.src)).await.unwrap();
        sqlx::query("INSERT INTO address_books(user_id, collection_id, id, tags) VALUES (1, 0, ?, '[]'), (1, 0, ?, '[]')")
            .bind(&long)
            .bind("i".repeat(MAX_PEER_ID_LEN))
            .execute(&mut conn)
            .await
            .unwrap();
        // Collection 10 has 1 entry imported already ('555' is not its owner's).
        sqlx::query(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
             INSERT INTO address_books(user_id, collection_id, id, tags) SELECT 1, 10, 'B' || i, '[]' FROM n",
        )
        .bind(MAX_PEERS)
        .execute(&mut conn)
        .await
        .unwrap();
        conn.close().await.unwrap();

        let p = plan(&f.db, &f.src).await.unwrap();
        let short: String = long.chars().take(32).collect();
        for needle in [
            format!("Over the limits: entry {short:?}… in the personal book of user_id 1 has an id of {} bytes", long.len()),
            format!("Over the limits: collection 10 has {} entries (Porta takes at most {MAX_PEERS} in a book)", MAX_PEERS + 1),
            format!("delete them in batches of at most {MAX_PEERS}"),
        ] {
            assert!(p.report.contains(&needle), "missing {needle:?} in:\n{}", p.report);
        }
        // Exactly at the limits: not listed.
        assert_eq!(p.report.matches("Over the limits").count(), 2, "{}", p.report);
        write(&f.db, &f.secret, &p).await.unwrap();
        assert_eq!(count(&f.db, &format!("select count(*) from ab_peer where id = '{long}'")).await, 1);
        let shared: i64 = sqlx::query_scalar(
            "select count(*) from ab_peer p join ab a on a.guid = p.ab_guid where a.name = 'Team' and a.personal = 0
               and a.owner_id = (select id from user where name = 'admin')",
        )
        .fetch_one(&f.db)
        .await
        .unwrap();
        assert_eq!(shared, MAX_PEERS + 1, "imported unchanged");
    }

    #[tokio::test]
    async fn rolls_back_on_failure() {
        let f = fixture().await;
        let mut p = plan(&f.db, &f.src).await.unwrap();
        // Make the last write fail: an entry pointing at a book that is not created.
        p.entries.push(Entry {
            book: BookRef::Shared(12345),
            id: "x".into(),
            data: "{}".into(),
            tags: "[]".into(),
            hash: String::new(),
            password: String::new(),
        });
        assert!(write(&f.db, &f.secret, &p).await.is_err());
        assert_eq!(count(&f.db, "select count(*) from user").await, 0);
        assert_eq!(count(&f.db, "select count(*) from ab").await, 0);
    }

    #[tokio::test]
    async fn via_command_line() {
        let f = fixture().await;
        let ctx = crate::cli::tests::ctx_with(f.db.clone(), f._dir.path());
        let out = crate::cli::tests::cli(&ctx, &["import", "rustdesk-api", f.src.to_str().unwrap(), "--dry-run"], "")
            .await
            .unwrap();
        assert_eq!(out, "");
        let out = crate::cli::tests::cli(&ctx, &["import", "rustdesk-api", f.src.to_str().unwrap()], "")
            .await
            .unwrap();
        assert!(out.contains(crate::crypto::SECRET_KEY_FILE) && out.contains("back it up"), "{out}");
        assert!(crate::cli::tests::cli(&ctx, &["import", "rustdesk-api", "/nonexistent/x.db"], "").await.is_err());
    }

    #[test]
    fn tags_are_cleaned() {
        assert_eq!(parse_tags(r#"["a", 1, "b", "a", null, {"x": 1}]"#), ["a", "b"]);
        assert!(parse_tags("null").is_empty());
        assert!(parse_tags("").is_empty());
        assert!(parse_tags("{}").is_empty());
        assert!(parse_tags("[").is_empty());
    }
}
