//! `user …`, `group …`, `ab …`, `exit …`: accounts, user groups, shared address books and exit
//! grants (LEAPGATE.md §12, §14).

use super::{check_name, read_password, table, Args, Ctx, RESERVED_BOOK_NAMES, USAGE};
use hbb_common::{bail, ResultType};
use sqlx::SqlitePool;
use std::{collections::BTreeMap, io::BufRead};

pub(super) async fn exec(ctx: &Ctx, cmd: &str, mut args: Args, input: &mut dyn BufRead) -> ResultType<String> {
    let db = &ctx.db;
    let sub = args.next("subcommand")?;
    match (cmd, sub.as_str()) {
        ("user", "add") => {
            let name = args.next("user name")?;
            let admin = args.flag("--admin");
            let display_name = args.value(&["--display-name"]).unwrap_or_default();
            let email = args.value(&["--email"]).unwrap_or_default();
            args.finish()?;
            check_name("user", &name)?;
            if name.len() > crate::api::account::MAX_NAME_LEN {
                // Login refuses longer names, so such a user could never sign in.
                bail!("The user name must be at most {} bytes", crate::api::account::MAX_NAME_LEN);
            }
            if find_user(db, &name).await?.is_some() {
                bail!("User '{name}' already exists");
            }
            let hash = crate::auth::hash_password(&read_password(input, &name)?)?;
            let now = now();
            sqlx::query(
                "insert into user(name, display_name, email, password_hash, is_admin, created_at, updated_at)
                 values(?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&name)
            .bind(display_name)
            .bind(email)
            .bind(hash)
            .bind(admin)
            .bind(now)
            .bind(now)
            .execute(db)
            .await?;
            Ok(format!("Added user {name}{}\n", if admin { " (admin)" } else { "" }))
        }
        ("user", "passwd") => {
            let name = args.next("user name")?;
            args.finish()?;
            let uid = user_id(db, &name).await?;
            let hash = crate::auth::hash_password(&read_password(input, &name)?)?;
            let mut tx = db.begin().await?;
            sqlx::query("update user set password_hash = ?, updated_at = ? where id = ?")
                .bind(hash)
                .bind(now())
                .bind(uid)
                .execute(&mut *tx)
                .await?;
            let n = logout_all(&mut tx, uid).await?;
            tx.commit().await?;
            Ok(format!("Password of {name} changed; {n} login(s) signed out\n"))
        }
        ("user", "list") => {
            args.finish()?;
            let rows = sqlx::query_as::<_, (String, String, String, bool, i64, bool, Option<String>)>(
                "select u.name, u.display_name, u.email, u.is_admin, u.status, u.password_hash <> '',
                   (select group_concat(g.name, ',') from group_member m join user_group g on g.id = m.group_id
                    where m.user_id = u.id)
                 from user u order by u.name",
            )
            .fetch_all(db)
            .await?;
            let rows: Vec<Vec<String>> = rows
                .into_iter()
                .map(|(name, display, email, admin, status, has_pw, groups)| {
                    vec![
                        name,
                        yes_no(admin),
                        if status == 1 { "enabled" } else { "disabled" }.to_owned(),
                        yes_no(has_pw),
                        groups.unwrap_or_default(),
                        display,
                        email,
                    ]
                })
                .collect();
            Ok(table(
                &["NAME", "ADMIN", "STATUS", "PASSWORD", "GROUPS", "DISPLAY NAME", "EMAIL"],
                &rows,
            ))
        }
        ("user", "disable" | "enable") => {
            let name = args.next("user name")?;
            args.finish()?;
            let uid = user_id(db, &name).await?;
            let enable = sub == "enable";
            let mut tx = db.begin().await?;
            sqlx::query("update user set status = ?, updated_at = ? where id = ?")
                .bind(if enable { 1 } else { 0 })
                .bind(now())
                .bind(uid)
                .execute(&mut *tx)
                .await?;
            let mut out = format!("{} {name}", if enable { "Enabled" } else { "Disabled" });
            if !enable {
                let n = logout_all(&mut tx, uid).await?;
                out += &format!("; {n} login(s) signed out");
            }
            tx.commit().await?;
            Ok(out + "\n")
        }
        ("user", "admin") => {
            let name = args.next("user name")?;
            let on = match args.next("on|off")?.as_str() {
                "on" => true,
                "off" => false,
                other => bail!("Expected on or off, got '{other}'"),
            };
            args.finish()?;
            let uid = user_id(db, &name).await?;
            sqlx::query("update user set is_admin = ?, updated_at = ? where id = ?")
                .bind(on)
                .bind(now())
                .bind(uid)
                .execute(db)
                .await?;
            Ok(format!("{name} is {}an admin now\n", if on { "" } else { "not " }))
        }
        ("user", "del") => {
            let name = args.next("user name")?;
            args.finish()?;
            let uid = user_id(db, &name).await?;
            let books: i64 = sqlx::query_scalar("select count(*) from ab where owner_id = ? and personal = 0")
                .bind(uid)
                .fetch_one(db)
                .await?;
            // Cascades: tokens, memberships, own address books and rules for this user; devices are unassigned.
            sqlx::query("delete from user where id = ?").bind(uid).execute(db).await?;
            Ok(format!(
                "Deleted user {name}, with their personal address book and {books} shared address book(s) they owned\n"
            ))
        }
        ("group", "add") => {
            let name = args.next("group name")?;
            let share = args.flag("--share-devices");
            args.finish()?;
            check_name("group", &name)?;
            if find_group(db, &name).await?.is_some() {
                bail!("Group '{name}' already exists");
            }
            sqlx::query("insert into user_group(name, share_devices, created_at) values(?, ?, ?)")
                .bind(&name)
                .bind(share)
                .bind(now())
                .execute(db)
                .await?;
            Ok(format!("Added group {name}\n"))
        }
        ("group", "del") => {
            let name = args.next("group name")?;
            args.finish()?;
            let gid = group_id(db, &name).await?;
            // Cascades: memberships and address book rules for this group.
            sqlx::query("delete from user_group where id = ?").bind(gid).execute(db).await?;
            Ok(format!("Deleted group {name}\n"))
        }
        ("group", "list") => {
            args.finish()?;
            let rows = sqlx::query_as::<_, (String, bool, Option<String>)>(
                "select g.name, g.share_devices,
                   (select group_concat(u.name, ',') from group_member m join user u on u.id = m.user_id
                    where m.group_id = g.id)
                 from user_group g order by g.name",
            )
            .fetch_all(db)
            .await?;
            let rows: Vec<Vec<String>> = rows
                .into_iter()
                .map(|(name, share, members)| vec![name, yes_no(share), members.unwrap_or_default()])
                .collect();
            Ok(table(&["NAME", "SHARE DEVICES", "MEMBERS"], &rows))
        }
        ("group", "member") => {
            let action = args.next("add|rm")?;
            let group = args.next("group name")?;
            let user = args.next("user name")?;
            args.finish()?;
            let gid = group_id(db, &group).await?;
            let uid = user_id(db, &user).await?;
            match action.as_str() {
                "add" => {
                    let n = sqlx::query(
                        "insert into group_member(group_id, user_id) values(?, ?) on conflict do nothing",
                    )
                    .bind(gid)
                    .bind(uid)
                    .execute(db)
                    .await?
                    .rows_affected();
                    Ok(if n == 0 {
                        format!("{user} is already in {group}\n")
                    } else {
                        format!("Added {user} to {group}\n")
                    })
                }
                "rm" => {
                    let n = sqlx::query("delete from group_member where group_id = ? and user_id = ?")
                        .bind(gid)
                        .bind(uid)
                        .execute(db)
                        .await?
                        .rows_affected();
                    Ok(if n == 0 {
                        format!("{user} was not in {group}\n")
                    } else {
                        format!("Removed {user} from {group}\n")
                    })
                }
                other => bail!("Expected add or rm, got '{other}'"),
            }
        }
        ("ab", "list") => {
            args.finish()?;
            ab_list(db).await
        }
        ("ab", "create") => {
            let name = args.next("address book name")?;
            let owner = args.value(&["--owner"]);
            let note = args.value(&["--note"]).unwrap_or_default();
            args.finish()?;
            let Some(owner) = owner else {
                bail!("ab create needs --owner <user>");
            };
            check_book_name(db, &name).await?;
            let uid = user_id(db, &owner).await?;
            let now = now();
            sqlx::query(
                "insert into ab(guid, name, owner_id, personal, note, created_at, updated_at)
                 values(?, ?, ?, 0, ?, ?, ?)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&name)
            .bind(uid)
            .bind(note)
            .bind(now)
            .bind(now)
            .execute(db)
            .await?;
            Ok(format!("Created shared address book '{name}' owned by {owner}\n"))
        }
        ("ab", "rename") => {
            let name = args.next("address book name")?;
            let new = args.next("new name")?;
            args.finish()?;
            let guid = book_guid(db, &name).await?;
            check_book_name(db, &new).await?;
            sqlx::query("update ab set name = ?, updated_at = ? where guid = ?")
                .bind(&new)
                .bind(now())
                .bind(guid)
                .execute(db)
                .await?;
            Ok(format!("Renamed '{name}' to '{new}'\n"))
        }
        ("ab", "del") => {
            let name = args.next("address book name")?;
            args.finish()?;
            let guid = book_guid(db, &name).await?;
            // Cascades: entries, tags, rules.
            sqlx::query("delete from ab where guid = ?").bind(guid).execute(db).await?;
            Ok(format!("Deleted shared address book '{name}'\n"))
        }
        ("ab", "grant" | "revoke") => {
            let book = args.next("address book name")?;
            let target = Target::take(&mut args)?;
            let rule = if sub == "grant" {
                Some(match args.next("ro|rw|full")?.as_str() {
                    "ro" => 1,
                    "rw" => 2,
                    "full" => 3,
                    other => bail!("Expected ro, rw or full, got '{other}'"),
                })
            } else {
                None
            };
            args.finish()?;
            let guid = book_guid(db, &book).await?;
            let (column, id) = match &target {
                Target::User(u) => {
                    let uid = user_id(db, u).await?;
                    let owner: i64 = sqlx::query_scalar("select owner_id from ab where guid = ?")
                        .bind(&guid)
                        .fetch_one(db)
                        .await?;
                    if uid == owner {
                        bail!("{u} owns '{book}' and always has full control");
                    }
                    ("user_id", uid)
                }
                Target::Group(g) => ("group_id", group_id(db, g).await?),
            };
            let who = target.to_string();
            match rule {
                Some(rule) => {
                    sqlx::query(&format!(
                        "insert into ab_rule(ab_guid, {column}, rule) values(?, ?, ?)
                         on conflict(ab_guid, {column}) where {column} is not null do update set rule = excluded.rule"
                    ))
                    .bind(&guid)
                    .bind(id)
                    .bind(rule)
                    .execute(db)
                    .await?;
                    Ok(format!("{who} now has {} on '{book}'\n", rule_name(rule)))
                }
                None => {
                    let n = sqlx::query(&format!("delete from ab_rule where ab_guid = ? and {column} = ?"))
                        .bind(&guid)
                        .bind(id)
                        .execute(db)
                        .await?
                        .rows_affected();
                    Ok(if n == 0 {
                        format!("{who} had no rule on '{book}'\n")
                    } else {
                        format!("Revoked {who} on '{book}'\n")
                    })
                }
            }
        }
        // Grants only change the exit directory (LEAPGATE.md §12.4), read from the database at each
        // query: no console needed.
        ("exit", "grant" | "revoke") => {
            let device = args.next("device id")?;
            let target = Target::take(&mut args)?;
            args.finish()?;
            let grant = sub == "grant";
            if grant {
                // Against typos, and against granting an id before someone else registers it.
                let registered: bool = sqlx::query_scalar("select exists(select 1 from peer where id = ?)")
                    .bind(&device)
                    .fetch_one(db)
                    .await?;
                if !registered {
                    bail!("{device} is not registered with this server");
                }
            }
            let (column, id) = match &target {
                Target::User(u) => ("user_id", user_id(db, u).await?),
                Target::Group(g) => ("group_id", group_id(db, g).await?),
            };
            let who = target.to_string();
            if grant {
                sqlx::query(&format!(
                    "insert into exit_grant(device_id, {column}) values(?, ?)
                     on conflict(device_id, {column}) where {column} is not null do nothing"
                ))
                .bind(&device)
                .bind(id)
                .execute(db)
                .await?;
                return Ok(format!(
                    "{who} may use exit {device}: it shows in their exit directory while it is online with the exit on\n"
                ));
            }
            let n = sqlx::query(&format!("delete from exit_grant where device_id = ? and {column} = ?"))
                .bind(&device)
                .bind(id)
                .execute(db)
                .await?
                .rows_affected();
            Ok(if n == 0 {
                format!("{who} had no grant on exit {device}\n")
            } else {
                format!(
                    "Revoked {who} on exit {device}. This only changes the exit directory: sessions already open \
                     stay, and anyone who knows the device's password can still use it\n"
                )
            })
        }
        ("exit", "list") => {
            args.finish()?;
            exit_list(db).await
        }
        _ => bail!("Unknown command '{cmd} {sub}'\n\n{USAGE}"),
    }
}

/// `--user <u>` or `--group <g>`, exactly one.
enum Target {
    User(String),
    Group(String),
}

impl Target {
    fn take(args: &mut Args) -> ResultType<Self> {
        match (args.value(&["--user"]), args.value(&["--group"])) {
            (Some(u), None) => Ok(Self::User(u)),
            (None, Some(g)) => Ok(Self::Group(g)),
            _ => bail!("Give exactly one of --user <u> or --group <g>"),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(u) => write!(f, "user:{u}"),
            Self::Group(g) => write!(f, "group:{g}"),
        }
    }
}

fn rule_name(rule: i64) -> &'static str {
    match rule {
        1 => "ro",
        2 => "rw",
        _ => "full",
    }
}

async fn ab_list(db: &SqlitePool) -> ResultType<String> {
    let mut access: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let rules = sqlx::query_as::<_, (String, Option<String>, Option<String>, i64)>(
        "select r.ab_guid, u.name, g.name, r.rule from ab_rule r
         left join user u on u.id = r.user_id left join user_group g on g.id = r.group_id
         order by g.name is not null, coalesce(u.name, g.name)",
    )
    .fetch_all(db)
    .await?;
    for (guid, user, group, rule) in rules {
        let who = match (user, group) {
            (Some(u), _) => format!("user:{u}"),
            (None, g) => format!("group:{}", g.unwrap_or_default()),
        };
        access.entry(guid).or_default().push(format!("{who}={}", rule_name(rule)));
    }
    let books = sqlx::query_as::<_, (String, String, bool, String, String, i64)>(
        "select a.guid, a.name, a.personal, u.name, a.note,
           (select count(*) from ab_peer p where p.ab_guid = a.guid)
         from ab a join user u on u.id = a.owner_id order by a.personal, a.name, u.name",
    )
    .fetch_all(db)
    .await?;
    let rows: Vec<Vec<String>> = books
        .into_iter()
        .map(|(guid, name, personal, owner, note, entries)| {
            vec![
                name,
                if personal { "personal" } else { "shared" }.to_owned(),
                owner,
                entries.to_string(),
                access.remove(&guid).unwrap_or_default().join(", "),
                note,
            ]
        })
        .collect();
    Ok(table(&["NAME", "KIND", "OWNER", "ENTRIES", "ACCESS", "NOTE"], &rows))
}

/// One line per granted device: its owner and whom it is granted to, users first.
async fn exit_list(db: &SqlitePool) -> ResultType<String> {
    let grants = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "select g.device_id, coalesce(o.name, ''), u.name, gr.name from exit_grant g
           left join device d on d.id = g.device_id left join user o on o.id = d.user_id
           left join user u on u.id = g.user_id left join user_group gr on gr.id = g.group_id
          order by g.device_id, g.group_id is not null, coalesce(u.name, gr.name)",
    )
    .fetch_all(db)
    .await?;
    let mut rows: Vec<Vec<String>> = Vec::new();
    for (device, owner, user, group) in grants {
        let who = match (user, group) {
            (Some(u), _) => format!("user:{u}"),
            (None, g) => format!("group:{}", g.unwrap_or_default()),
        };
        match rows.last_mut() {
            Some(row) if row[0] == device => {
                row[2] += ", ";
                row[2] += &who;
            }
            _ => rows.push(vec![device, owner, who]),
        }
    }
    let mut out = if rows.is_empty() {
        "(no exit grants)\n".to_owned()
    } else {
        table(&["DEVICE", "OWNER", "GRANTED TO"], &rows)
    };
    out += "Owners always see their own devices. Whether an exit is online and on is known only to the running server.\n";
    Ok(out)
}

/// Shared book names: not empty, not a name the client reserves for the personal book, unique.
async fn check_book_name(db: &SqlitePool, name: &str) -> ResultType<()> {
    check_name("address book", name)?;
    if RESERVED_BOOK_NAMES.contains(&name) {
        bail!("'{name}' is reserved by the client for the personal address book");
    }
    let taken: Option<i64> = sqlx::query_scalar("select 1 from ab where personal = 0 and name = ?")
        .bind(name)
        .fetch_optional(db)
        .await?;
    if taken.is_some() {
        bail!("A shared address book named '{name}' already exists");
    }
    Ok(())
}

async fn find_user(db: &SqlitePool, name: &str) -> ResultType<Option<i64>> {
    Ok(sqlx::query_scalar("select id from user where name = ?")
        .bind(name)
        .fetch_optional(db)
        .await?)
}

pub(super) async fn user_id(db: &SqlitePool, name: &str) -> ResultType<i64> {
    match find_user(db, name).await? {
        Some(id) => Ok(id),
        None => bail!("No user named '{name}'"),
    }
}

async fn find_group(db: &SqlitePool, name: &str) -> ResultType<Option<i64>> {
    Ok(sqlx::query_scalar("select id from user_group where name = ?")
        .bind(name)
        .fetch_optional(db)
        .await?)
}

async fn group_id(db: &SqlitePool, name: &str) -> ResultType<i64> {
    match find_group(db, name).await? {
        Some(id) => Ok(id),
        None => bail!("No group named '{name}'"),
    }
}

async fn book_guid(db: &SqlitePool, name: &str) -> ResultType<String> {
    let guid: Option<String> = sqlx::query_scalar("select guid from ab where personal = 0 and name = ?")
        .bind(name)
        .fetch_optional(db)
        .await?;
    match guid {
        Some(guid) => Ok(guid),
        None => bail!("No shared address book named '{name}'"),
    }
}

/// Deletes all tokens of a user (password change, disable; LEAPGATE.md §11).
async fn logout_all(tx: &mut sqlx::SqliteConnection, uid: i64) -> ResultType<u64> {
    Ok(sqlx::query("delete from token where user_id = ?")
        .bind(uid)
        .execute(tx)
        .await?
        .rows_affected())
}

fn yes_no(b: bool) -> String {
    if b { "yes" } else { "no" }.to_owned()
}

fn now() -> i64 {
    crate::common::now() as i64
}

#[cfg(test)]
mod tests {
    use super::super::tests::{cli, ctx};
    use crate::auth::{verify_password, PasswordCheck};
    use hbb_common::tokio;
    use std::net::SocketAddr;

    const NO_CONSOLE: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);

    async fn user(db: &sqlx::SqlitePool, name: &str) -> (i64, String, bool, i64, String, String) {
        sqlx::query_as("select id, password_hash, is_admin, status, display_name, email from user where name = ?")
            .bind(name)
            .fetch_one(db)
            .await
            .unwrap()
    }

    async fn count(db: &sqlx::SqlitePool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(db).await.unwrap()
    }

    #[tokio::test]
    async fn users() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        let db = &ctx.db;
        cli(&ctx, &["user", "add", "alice", "--admin", "--display-name", "Alice A", "--email", "a@x"], "pw1\n")
            .await
            .unwrap();
        let (id, hash, admin, status, display, email) = user(db, "alice").await;
        assert_eq!(verify_password("pw1", &hash), PasswordCheck::Ok);
        assert!(admin);
        assert_eq!(status, 1);
        assert_eq!((display.as_str(), email.as_str()), ("Alice A", "a@x"));

        // Duplicate, empty name, empty password, missing password.
        assert!(cli(&ctx, &["user", "add", "alice"], "pw\n").await.is_err());
        assert!(cli(&ctx, &["user", "add", " "], "pw\n").await.is_err());
        assert!(cli(&ctx, &["user", "add", "bob"], "\n").await.is_err());
        assert!(cli(&ctx, &["user", "add", "bob"], "").await.is_err());
        assert_eq!(count(db, "select count(*) from user").await, 1);
        // A password on the command line is not accepted.
        assert!(cli(&ctx, &["user", "add", "bob", "pw"], "pw\n").await.is_err());

        // passwd and disable sign out every token.
        crate::testutil::create_user(db, "bob", "old", false).await;
        sqlx::query("insert into token(token_hash, user_id, created_at, last_used_at) values('t2', ?, 0, 0)")
            .bind(id)
            .execute(db)
            .await
            .unwrap();
        let out = cli(&ctx, &["user", "passwd", "alice"], "pw2\n").await.unwrap();
        assert!(out.contains("1 login(s)"), "{out}");
        assert_eq!(verify_password("pw2", &user(db, "alice").await.1), PasswordCheck::Ok);
        assert_eq!(count(db, "select count(*) from token").await, 1);
        assert!(cli(&ctx, &["user", "passwd", "nobody"], "x\n").await.is_err());

        cli(&ctx, &["user", "disable", "bob"], "").await.unwrap();
        assert_eq!(user(db, "bob").await.3, 0);
        assert_eq!(count(db, "select count(*) from token").await, 0);
        cli(&ctx, &["user", "enable", "bob"], "").await.unwrap();
        assert_eq!(user(db, "bob").await.3, 1);
        cli(&ctx, &["user", "admin", "bob", "on"], "").await.unwrap();
        assert!(user(db, "bob").await.2);
        cli(&ctx, &["user", "admin", "alice", "off"], "").await.unwrap();
        assert!(!user(db, "alice").await.2);
        assert!(cli(&ctx, &["user", "admin", "alice", "maybe"], "").await.is_err());

        let list = cli(&ctx, &["user", "list"], "").await.unwrap();
        let lines: Vec<&str> = list.lines().collect();
        assert_eq!(lines.len(), 3, "{list}");
        assert!(lines[0].starts_with("NAME"));
        assert!(lines[1].starts_with("alice") && lines[1].contains("Alice A"), "{list}");
        assert!(lines[2].starts_with("bob") && lines[2].contains("yes"), "{list}");

        // del cascades to the user's books; devices are unassigned.
        cli(&ctx, &["ab", "create", "Team", "--owner", "bob"], "").await.unwrap();
        sqlx::query("insert into device(id, user_id, first_seen_at, last_seen_at) values('d1', (select id from user where name = 'bob'), 0, 0)")
            .execute(db)
            .await
            .unwrap();
        let out = cli(&ctx, &["user", "del", "bob"], "").await.unwrap();
        assert!(out.contains("1 shared"), "{out}");
        assert_eq!(count(db, "select count(*) from ab").await, 0);
        assert_eq!(count(db, "select count(*) from device where user_id is null").await, 1);
        assert!(cli(&ctx, &["user", "del", "bob"], "").await.is_err());
    }

    #[tokio::test]
    async fn groups() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        let db = &ctx.db;
        crate::testutil::create_user(db, "alice", "pw", false).await;
        crate::testutil::create_user(db, "bob", "pw", false).await;
        cli(&ctx, &["group", "add", "ops", "--share-devices"], "").await.unwrap();
        cli(&ctx, &["group", "add", "dev"], "").await.unwrap();
        assert!(cli(&ctx, &["group", "add", "ops"], "").await.is_err());
        assert!(cli(&ctx, &["group", "add", ""], "").await.is_err());
        assert_eq!(count(db, "select share_devices from user_group where name = 'ops'").await, 1);
        assert_eq!(count(db, "select share_devices from user_group where name = 'dev'").await, 0);

        cli(&ctx, &["group", "member", "add", "ops", "alice"], "").await.unwrap();
        let again = cli(&ctx, &["group", "member", "add", "ops", "alice"], "").await.unwrap();
        assert!(again.contains("already"), "{again}");
        cli(&ctx, &["group", "member", "add", "ops", "bob"], "").await.unwrap();
        cli(&ctx, &["group", "member", "add", "dev", "bob"], "").await.unwrap();
        assert!(cli(&ctx, &["group", "member", "add", "ops", "carol"], "").await.is_err());
        assert!(cli(&ctx, &["group", "member", "add", "nope", "bob"], "").await.is_err());
        assert!(cli(&ctx, &["group", "member", "join", "ops", "bob"], "").await.is_err());
        assert_eq!(count(db, "select count(*) from group_member").await, 3);
        cli(&ctx, &["group", "member", "rm", "ops", "bob"], "").await.unwrap();
        let again = cli(&ctx, &["group", "member", "rm", "ops", "bob"], "").await.unwrap();
        assert!(again.contains("was not"), "{again}");

        let list = cli(&ctx, &["group", "list"], "").await.unwrap();
        assert!(list.lines().any(|l| l.starts_with("ops") && l.contains("yes") && l.ends_with("alice")), "{list}");
        assert!(list.lines().any(|l| l.starts_with("dev") && l.ends_with("bob")), "{list}");
        let users = cli(&ctx, &["user", "list"], "").await.unwrap();
        assert!(users.lines().any(|l| l.starts_with("bob") && l.contains("dev")), "{users}");

        cli(&ctx, &["ab", "create", "Team", "--owner", "alice"], "").await.unwrap();
        cli(&ctx, &["ab", "grant", "Team", "--group", "dev", "ro"], "").await.unwrap();
        cli(&ctx, &["group", "del", "dev"], "").await.unwrap();
        assert_eq!(count(db, "select count(*) from ab_rule").await, 0);
        assert_eq!(count(db, "select count(*) from group_member").await, 1);
        assert!(cli(&ctx, &["group", "del", "dev"], "").await.is_err());
    }

    #[tokio::test]
    async fn address_books() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        let db = &ctx.db;
        crate::testutil::create_user(db, "alice", "pw", false).await;
        crate::testutil::create_user(db, "bob", "pw", false).await;
        cli(&ctx, &["group", "add", "ops"], "").await.unwrap();

        cli(&ctx, &["ab", "create", "Team", "--owner", "alice", "--note", "n1"], "").await.unwrap();
        let (guid, owner, personal, note): (String, String, bool, String) = sqlx::query_as(
            "select a.guid, u.name, a.personal, a.note from ab a join user u on u.id = a.owner_id",
        )
        .fetch_one(db)
        .await
        .unwrap();
        assert_eq!(uuid::Uuid::parse_str(&guid).unwrap().get_version_num(), 4);
        assert_eq!((owner.as_str(), personal, note.as_str()), ("alice", false, "n1"));

        for bad in [
            vec!["ab", "create", "Team", "--owner", "bob"],
            vec!["ab", "create", "My address book", "--owner", "bob"],
            vec!["ab", "create", "Legacy address book", "--owner", "bob"],
            vec!["ab", "create", "", "--owner", "bob"],
            vec!["ab", "create", "Other"],
            vec!["ab", "create", "Other", "--owner", "nobody"],
            vec!["ab", "rename", "Team", "My address book"],
            vec!["ab", "rename", "Nope", "X"],
        ] {
            assert!(cli(&ctx, &bad, "").await.is_err(), "{bad:?}");
        }
        // A personal book of the same name does not count as taken.
        sqlx::query("insert into ab(guid, name, owner_id, personal, created_at, updated_at) values('p1', 'Mine', 2, 1, 0, 0)")
            .execute(db)
            .await
            .unwrap();
        cli(&ctx, &["ab", "create", "Mine", "--owner", "bob"], "").await.unwrap();
        assert!(cli(&ctx, &["ab", "del", "Mine"], "").await.is_ok());
        assert_eq!(count(db, "select count(*) from ab where guid = 'p1'").await, 1);

        // grant: user and group, upgrade, owner refused, exactly one target.
        cli(&ctx, &["ab", "grant", "Team", "--user", "bob", "ro"], "").await.unwrap();
        cli(&ctx, &["ab", "grant", "Team", "--user", "bob", "full"], "").await.unwrap();
        cli(&ctx, &["ab", "grant", "Team", "--group", "ops", "rw"], "").await.unwrap();
        assert!(cli(&ctx, &["ab", "grant", "Team", "--user", "alice", "rw"], "").await.is_err());
        assert!(cli(&ctx, &["ab", "grant", "Team", "--user", "bob", "--group", "ops", "rw"], "").await.is_err());
        assert!(cli(&ctx, &["ab", "grant", "Team", "rw"], "").await.is_err());
        assert!(cli(&ctx, &["ab", "grant", "Team", "--user", "bob", "admin"], "").await.is_err());
        let rules: Vec<(Option<i64>, Option<i64>, i64)> =
            sqlx::query_as("select user_id, group_id, rule from ab_rule order by user_id is null")
                .fetch_all(db)
                .await
                .unwrap();
        assert_eq!(rules, vec![(Some(2), None, 3), (None, Some(1), 2)]);

        let list = cli(&ctx, &["ab", "list"], "").await.unwrap();
        let team = list.lines().find(|l| l.starts_with("Team")).unwrap();
        assert!(team.contains("shared") && team.contains("alice"), "{list}");
        assert!(team.contains("user:bob=full, group:ops=rw"), "{list}");
        assert!(list.lines().any(|l| l.starts_with("Mine") && l.contains("personal")), "{list}");

        cli(&ctx, &["ab", "revoke", "Team", "--user", "bob"], "").await.unwrap();
        let again = cli(&ctx, &["ab", "revoke", "Team", "--user", "bob"], "").await.unwrap();
        assert!(again.contains("no rule"), "{again}");
        assert_eq!(count(db, "select count(*) from ab_rule").await, 1);

        cli(&ctx, &["ab", "rename", "Team", "Crew"], "").await.unwrap();
        assert_eq!(count(db, "select count(*) from ab where name = 'Crew'").await, 1);
        sqlx::query("insert into ab_peer(ab_guid, id, created_at, updated_at) values(?, '123', 0, 0)")
            .bind(&guid)
            .execute(db)
            .await
            .unwrap();
        cli(&ctx, &["ab", "del", "Crew"], "").await.unwrap();
        assert_eq!(count(db, "select count(*) from ab_peer").await, 0);
        assert_eq!(count(db, "select count(*) from ab_rule").await, 0);
    }

    #[tokio::test]
    async fn exit_grants() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        let db = &ctx.db;
        let (alice, _) = crate::testutil::create_user(db, "alice", "pw", false).await;
        crate::testutil::create_user(db, "bob", "pw", false).await;
        cli(&ctx, &["group", "add", "ops"], "").await.unwrap();
        for id in ["d1", "d2"] {
            crate::database::Database::new(db.clone()).insert_peer(id, b"u", b"pk", "{}").await.unwrap();
        }
        sqlx::query("insert into device(id, user_id, first_seen_at, last_seen_at) values('d1', ?, 0, 0)")
            .bind(alice)
            .execute(db)
            .await
            .unwrap();
        let list = || cli(&ctx, &["exit", "list"], "");
        const FOOTER: &str = "Owners always see their own devices. Whether an exit is online and on is known only to the running server.\n";
        assert_eq!(list().await.unwrap(), format!("(no exit grants)\n{FOOTER}"));

        for bad in [
            &["exit", "grant", "nosuch", "--user", "bob"][..],
            &["exit", "grant", "d1", "--user", "nobody"],
            &["exit", "grant", "d1", "--group", "nogroup"],
            &["exit", "grant", "d1"],
            &["exit", "grant", "d1", "--user", "bob", "--group", "ops"],
            &["exit", "revoke", "d1"],
            &["exit", "revoke", "d1", "--user", "bob", "--group", "ops"],
            &["exit", "grant", "d1", "--user", "bob", "extra"],
        ] {
            assert!(cli(&ctx, bad, "").await.is_err(), "{bad:?}");
        }
        let err = cli(&ctx, &["exit", "grant", "nosuch", "--user", "bob"], "").await.unwrap_err().to_string();
        assert!(err.contains("nosuch is not registered with this server"), "{err}");
        assert_eq!(count(db, "select count(*) from exit_grant").await, 0);

        let out = cli(&ctx, &["exit", "grant", "d1", "--user", "bob"], "").await.unwrap();
        assert_eq!(out, "user:bob may use exit d1: it shows in their exit directory while it is online with the exit on\n");
        cli(&ctx, &["exit", "grant", "d1", "--user", "bob"], "").await.unwrap();
        assert_eq!(count(db, "select count(*) from exit_grant").await, 1);
        cli(&ctx, &["exit", "grant", "d1", "--group", "ops"], "").await.unwrap();
        cli(&ctx, &["exit", "grant", "d1", "--user", "alice"], "").await.unwrap();
        cli(&ctx, &["exit", "grant", "d2", "--group", "ops"], "").await.unwrap();
        assert_eq!(
            list().await.unwrap(),
            format!(
                "DEVICE  OWNER  GRANTED TO\n\
                 d1      alice  user:alice, user:bob, group:ops\n\
                 d2             group:ops\n{FOOTER}"
            )
        );

        let out = cli(&ctx, &["exit", "revoke", "d1", "--user", "bob"], "").await.unwrap();
        assert_eq!(
            out,
            "Revoked user:bob on exit d1. This only changes the exit directory: sessions already open stay, \
             and anyone who knows the device's password can still use it\n"
        );
        let out = cli(&ctx, &["exit", "revoke", "d1", "--user", "bob"], "").await.unwrap();
        assert_eq!(out, "user:bob had no grant on exit d1\n");
        // Revoking needs no registered device.
        sqlx::query("delete from peer where id = 'd2'").execute(db).await.unwrap();
        cli(&ctx, &["exit", "revoke", "d2", "--group", "ops"], "").await.unwrap();
        assert_eq!(count(db, "select count(*) from exit_grant").await, 2);
    }
}
