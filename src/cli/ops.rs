//! `device …`, `strategy …`, `relay status`, `route test`, `geo …`, `stats` (LEAPGATE.md §7, §8, §10, §14).

use super::{console, console_connect, console_send, fmt_time, table, Args, Ctx, USAGE};
use crate::strategy::GLOBAL;
use hbb_common::{bail, ResultType};
use sqlx::SqlitePool;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};

/// `rs` and `tg` answer at once; `gu` downloads and verifies the databases first.
const CONSOLE_WAIT: Duration = Duration::from_secs(10);
const GEO_UPDATE_WAIT: Duration = Duration::from_secs(600);
const DEFAULT_STATS_DAYS: i64 = 7;

pub(super) async fn exec(ctx: &Ctx, cmd: &str, mut args: Args) -> ResultType<String> {
    let db = &ctx.db;
    if cmd == "stats" {
        let days = match args.value(&["--days"]) {
            Some(d) => match d.parse::<i64>() {
                Ok(d) if d > 0 => d,
                _ => bail!("--days needs a positive number"),
            },
            None => DEFAULT_STATS_DAYS,
        };
        args.finish()?;
        return stats(db, days).await;
    }
    let sub = args.next("subcommand")?;
    match (cmd, sub.as_str()) {
        ("device", "list") => {
            let legacy = args.flag("--legacy");
            args.finish()?;
            device_list(db, legacy).await
        }
        ("device", "pin-relay") => {
            let device = args.next("device id")?;
            let host = args.next("relay host or none")?;
            args.finish()?;
            if device.is_empty() || device == GLOBAL {
                bail!("pin-relay needs a device id");
            }
            let pin = if host == "none" { "" } else { host.as_str() };
            sqlx::query(
                "insert into device_policy(device_id, relay_pin) values(?, ?)
                 on conflict(device_id) do update set relay_pin = excluded.relay_pin",
            )
            .bind(&device)
            .bind(pin)
            .execute(db)
            .await?;
            Ok(if pin.is_empty() {
                format!("{device} no longer has a fixed relay\n")
            } else {
                format!("{device} uses relay {pin} as the controlled side from its next connection\n")
            })
        }
        ("device", "key") => {
            let first = args.next("device id or reset")?;
            if first != "reset" {
                args.finish()?;
                return device_key(db, &first).await;
            }
            let forget = args.flag("--forget");
            let device = args.next("device id")?;
            args.finish()?;
            // The console splits its command on spaces.
            if device.is_empty() || device.contains(char::is_whitespace) {
                bail!("Not a device id: {device:?}");
            }
            key_reset(ctx, &device, forget).await
        }
        ("strategy", "show") => {
            let device = args.next_opt().filter(|d| d != GLOBAL);
            args.finish()?;
            strategy_show(db, device.as_deref()).await
        }
        ("strategy", "set" | "unset") => {
            let scope = args.next("device id or '*'")?;
            let key = args.next("option key")?;
            let value = if sub == "set" { args.next("option value")? } else { String::new() };
            args.finish()?;
            check_scope_key(&scope, &key)?;
            // The Leapgate client's own options; it skips them in a pushed strategy too.
            if key.starts_with("leapgate-") {
                bail!("Options starting with leapgate- are the Leapgate client's own and are never pushed");
            }
            sqlx::query(
                "insert into strategy_option(scope, key, value) values(?, ?, ?)
                 on conflict(scope, key) do update set value = excluded.value",
            )
            .bind(&scope)
            .bind(&key)
            .bind(&value)
            .execute(db)
            .await?;
            Ok(if sub == "set" {
                format!("{scope}: {key} = {value:?}\n")
            } else {
                format!("{scope}: {key} = \"\" (clients delete the key)\n")
            })
        }
        ("strategy", "forget") => {
            let scope = args.next("device id or '*'")?;
            let key = args.next("option key")?;
            args.finish()?;
            check_scope_key(&scope, &key)?;
            let n = sqlx::query("delete from strategy_option where scope = ? and key = ?")
                .bind(&scope)
                .bind(&key)
                .execute(db)
                .await?
                .rows_affected();
            Ok(if n == 0 {
                format!("{scope} has no option {key}\n")
            } else {
                format!("{scope}: {key} is no longer pushed\n")
            })
        }
        ("strategy", "repush") => {
            let scope = args.next("device id or '*'")?;
            args.finish()?;
            check_scope_key(&scope, "-")?;
            sqlx::query(
                "insert into device_policy(device_id, strategy_epoch) values(?, 1)
                 on conflict(device_id) do update set strategy_epoch = strategy_epoch + 1",
            )
            .bind(&scope)
            .execute(db)
            .await?;
            Ok(format!("{scope}: options are pushed again on the next heartbeat\n"))
        }
        _ => bail!("Unknown command '{cmd} {sub}'\n\n{USAGE}"),
    }
}

/// `relay status`, `route test`, `geo …`: they talk to the console or read `leapgate.toml` and the mmdb
/// files, never the database, so they run without one (review R2-6).
pub(super) async fn runtime(
    console_addr: SocketAddr,
    leapgate_config: &Path,
    cmd: &str,
    mut args: Args,
) -> ResultType<String> {
    let sub = args.next("subcommand")?;
    match (cmd, sub.as_str()) {
        ("relay", "status") => {
            args.finish()?;
            console(console_addr, "rs", CONSOLE_WAIT).await
        }
        ("route", "test") => {
            let a = parse_ip(&args.next("ipA")?)?;
            let b = parse_ip(&args.next("ipB")?)?;
            // Whose relay measurements to use (routing level two); `-` tells the console "none".
            let mut id = |name: &str| -> ResultType<String> {
                match args.value(&[name]) {
                    None => Ok("-".to_owned()),
                    // The console splits its command on spaces.
                    Some(id) if id.is_empty() || id == "-" || id.contains(char::is_whitespace) => {
                        bail!("Not a device id: {id:?}")
                    }
                    Some(id) => Ok(id),
                }
            };
            let (a_id, b_id) = (id("--a")?, id("--b")?);
            args.finish()?;
            console(console_addr, &format!("tg {a} {b} {a_id} {b_id}"), CONSOLE_WAIT).await
        }
        ("geo", "lookup") => {
            let ip = parse_ip(&args.next("ip")?)?;
            args.finish()?;
            let cfg = crate::config::Config::load(leapgate_config, "")?;
            Ok(crate::router::geo_lookup(&cfg, ip)? + "\n")
        }
        ("geo", "update") => {
            args.finish()?;
            match console_connect(console_addr).await {
                Ok(stream) => console_send(stream, "gu", GEO_UPDATE_WAIT).await,
                Err(err) => {
                    eprintln!("{err}; downloading in this process instead");
                    let cfg = crate::config::Config::load(leapgate_config, "")?;
                    Ok(crate::router::geo_download(&cfg.geo).await? + "\n")
                }
            }
        }
        _ => bail!("Unknown command '{cmd} {sub}'\n\n{USAGE}"),
    }
}

/// `device key <id>`: what the database has on the device's key (read only).
async fn device_key(db: &SqlitePool, id: &str) -> ResultType<String> {
    let Some((pk, pinned_at, uuid)) =
        sqlx::query_as::<_, (Vec<u8>, Option<i64>, Vec<u8>)>("select pk, pk_pinned_at, uuid from peer where id = ?")
            .bind(id)
            .fetch_optional(db)
            .await?
    else {
        bail!("No registered device {id}");
    };
    // A reinstall that lost its id shows here: its new id has the same machine uuid.
    let others: Vec<String> = sqlx::query_scalar("select id from peer where uuid = ? and id <> ? order by id")
        .bind(&uuid)
        .bind(id)
        .fetch_all(db)
        .await?;
    let pinned = match pinned_at {
        Some(at) => format!("pinned since {}", fmt_time(at)),
        None => "not pinned".to_owned(),
    };
    Ok(format!(
        "Device {id}\nKey fingerprint: {}\nKey: {pinned}\nuuid: {} bytes\nOther ids with this uuid: {}\n",
        fingerprint(&pk),
        uuid.len(),
        if others.is_empty() { "none".to_owned() } else { others.join(", ") }
    ))
}

/// Lowercase hex, a space every 4 characters: what the client shows (rustdesk `pk_to_fingerprint`).
fn fingerprint(pk: &[u8]) -> String {
    let hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
    let mut out = String::with_capacity(hex.len() * 5 / 4);
    for (i, c) in hex.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// `device key reset [--forget] <id>` (LEAPGATE.md §14): unpins the key of `id`, keeping its uuid and
/// key (a reinstall keeps its id by the usual rule: same uuid, same IP may change the key), or with
/// `forget` deletes its row (the uuid changed too; the next registration of the id is a new device).
/// Only the command line changes the database: whoever can open its file may. Then the running
/// server's console reloads the entry from the database (`kl`, which anyone may trigger and only
/// aligns memory); unreachable, the change stands and the command fails, saying a running server
/// must be restarted. (The server also reloads a pinned entry by itself on a registration with
/// another key, so an unpinning reaches it at the device's next registration anyway.)
async fn key_reset(ctx: &Ctx, id: &str, forget: bool) -> ResultType<String> {
    let sql = if forget {
        "delete from peer where id = ?"
    } else {
        "update peer set pk_pinned_at = null where id = ?"
    };
    if sqlx::query(sql).bind(id).execute(&ctx.db).await?.rows_affected() == 0 {
        bail!(
            "No registered device {id}. If an earlier reset of it was not reloaded by the server, \
             restart leapgate-server."
        );
    }
    let done = if forget {
        format!("{id}: forgotten; the next registration of this id is taken as a new device\n")
    } else {
        format!("{id}: key no longer pinned (uuid and key kept); the next signed report pins the key it is signed with\n")
    };
    // Every answer of a server that reloaded starts with "<id>: " (`PeerMap::reload_from_main`).
    let failure = match console(ctx.console, &format!("kl {id}"), CONSOLE_WAIT).await {
        Ok(reply) if reply.starts_with(&format!("{id}: ")) => return Ok(done + &reply),
        Ok(reply) => format!("it answered {:?}", reply.trim_end()),
        Err(err) => err.to_string(),
    };
    bail!(
        "{done}The database is changed, but the server did not reload it ({failure}).\n\
         If leapgate-server is running, restart it for this to take effect."
    )
}

fn parse_ip(s: &str) -> ResultType<IpAddr> {
    match s.parse::<IpAddr>() {
        Ok(ip) => Ok(ip.to_canonical()),
        Err(_) => bail!("'{s}' is not an IP address"),
    }
}

fn check_scope_key(scope: &str, key: &str) -> ResultType<()> {
    if scope.is_empty() {
        bail!("The device id must not be empty (use '*' for all devices)");
    }
    if key.is_empty() {
        bail!("The option key must not be empty");
    }
    Ok(())
}

/// Effective options and `rev` of a device, or (no device) of a device without options or epoch of its own.
async fn strategy_show(db: &SqlitePool, device: Option<&str>) -> ResultType<String> {
    let (rev, options) = crate::strategy::effective(db, device.unwrap_or("")).await?;
    let own: HashSet<String> = match device {
        Some(d) => sqlx::query_scalar("select key from strategy_option where scope = ?")
            .bind(d)
            .fetch_all(db)
            .await?
            .into_iter()
            .collect(),
        None => HashSet::new(),
    };
    let mut out = match device {
        Some(d) => format!("Device {d}: rev {rev}\n"),
        None => format!("All devices (global options): rev {rev} for devices without options of their own\n"),
    };
    if options.is_empty() {
        out += "(no options)\n";
    }
    for (key, value) in options {
        let source = if own.contains(&key) { "device" } else { "global" };
        let note = if value.is_empty() { ", clients delete the key" } else { "" };
        out += &format!("{key} = {value:?}  ({source}{note})\n");
    }
    Ok(out)
}

async fn device_list(db: &SqlitePool, legacy: bool) -> ResultType<String> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, i64)>(&format!(
        "select d.id, d.hostname, coalesce(u.name, ''), d.client_type, d.version, d.last_seen_at
         from device d left join user u on u.id = d.user_id {} order by d.id",
        if legacy { "where d.client_type = 'rustdesk'" } else { "" }
    ))
    .fetch_all(db)
    .await?;
    let mut out_rows: Vec<Vec<String>> = rows
        .into_iter()
        .map(|(id, host, user, client, version, seen)| {
            vec![id, host, user, client, version, fmt_time(seen), String::new()]
        })
        .collect();
    if !legacy {
        for row in &mut out_rows {
            row.pop();
        }
        return Ok(table(&["ID", "HOSTNAME", "USER", "CLIENT", "VERSION", "LAST SEEN"], &out_rows));
    }
    // Ids that only the rendezvous side has seen: B with the version it replied with, A with the
    // device id its login token recorded. The latest attempt gives the version.
    let seen = sqlx::query_as::<_, (String, String, i64)>(
        "select id, version, max(at) from (
           select b_id as id, b_version as version, started_at as at from conn_attempt
             where coalesce(b_version, '') <> ''
           union all
           select a_device_id, coalesce(a_version, ''), started_at from conn_attempt
             where coalesce(a_device_id, '') <> ''
         ) where id not in (select id from device) group by id order by id",
    )
    .fetch_all(db)
    .await?;
    for (id, version, at_ms) in seen {
        out_rows.push(vec![
            id,
            String::new(),
            String::new(),
            String::new(),
            version,
            fmt_time(at_ms / 1000),
            "rendezvous only".to_owned(),
        ]);
    }
    let mut out = table(&["ID", "HOSTNAME", "USER", "CLIENT", "VERSION", "LAST SEEN", "NOTE"], &out_rows);
    out += "Original RustDesk clients only. Devices that never sent a heartbeat and never took part in a connection are not counted.\n";
    Ok(out)
}

async fn stats(db: &SqlitePool, days: i64) -> ResultType<String> {
    let until_ms = crate::common::now() as i64 * 1000;
    let since_ms = until_ms - days * 86_400_000;
    let s = crate::conn_tracker::ConnTracker::stats(db, since_ms, until_ms).await?;
    let mut out = format!("Connections started in the last {days} day(s), since {}:\n", fmt_time(since_ms / 1000));
    out += &match s.relay_rate {
        Some(r) => format!("Relay fallback rate: {:.1}% (relay, relay_or_v6 over relayed + direct)\n", r * 100.0),
        None => "Relay fallback rate: n/a (no relayed or direct connections)\n".to_owned(),
    };
    out += &format!("Controlled side used its own hard-coded relay: {}\n", s.b_relay_mismatch);
    let rows: Vec<Vec<String>> = s
        .outcomes
        .into_iter()
        .map(|(outcome, n)| vec![outcome, n.to_string()])
        .collect();
    out += &table(&["OUTCOME", "COUNT"], &rows);
    // Contract 05 §3.8: the self-built ICE's own results.
    out += &format!("\nICE results recorded in the last {days} day(s):\n");
    let rows: Vec<Vec<String>> = s
        .ice_outcomes
        .into_iter()
        .map(|(outcome, n)| vec![outcome, n.to_string()])
        .collect();
    out += &table(&["ICE OUTCOME", "COUNT"], &rows);
    out += "Connections ICE won are still counted above as relay/direct_tcp, by the upstream signaling, \
            so the relay fallback rate above reads high; ICE's actual direct connections are its 'connected' here.\n";
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{cli, ctx};
    use hbb_common::tokio::{
        self,
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };
    use std::net::SocketAddr;

    const NO_CONSOLE: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);

    /// A console like the server's: one read, write the reply, close.
    async fn fake_console() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).await.unwrap();
                let reply = format!("got {}", String::from_utf8_lossy(&buf[..n]));
                s.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        addr
    }

    /// A console that answers `reply` to anything.
    async fn console_replying(reply: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                s.read(&mut buf).await.unwrap();
                s.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn console_commands() {
        let (_dir, ctx) = ctx(fake_console().await).await;
        assert_eq!(cli(&ctx, &["relay", "status"], "").await.unwrap(), "got rs\n");
        assert_eq!(
            cli(&ctx, &["route", "test", "1.2.3.4", "::ffff:5.6.7.8"], "").await.unwrap(),
            "got tg 1.2.3.4 5.6.7.8 - -\n"
        );
        assert_eq!(
            cli(&ctx, &["route", "test", "1.2.3.4", "5.6.7.8", "--b", "123456789"], "").await.unwrap(),
            "got tg 1.2.3.4 5.6.7.8 - 123456789\n"
        );
        assert_eq!(
            cli(&ctx, &["route", "test", "--a", "a1b2c3", "1.2.3.4", "5.6.7.8", "--b=987654"], "").await.unwrap(),
            "got tg 1.2.3.4 5.6.7.8 a1b2c3 987654\n"
        );
        assert_eq!(cli(&ctx, &["geo", "update"], "").await.unwrap(), "got gu\n");
        assert!(cli(&ctx, &["route", "test", "1.2.3.4", "nope"], "").await.is_err());
        assert!(cli(&ctx, &["route", "test", "1.2.3.4"], "").await.is_err());
        for bad in ["", "-", "a b"] {
            assert!(cli(&ctx, &["route", "test", "1.2.3.4", "5.6.7.8", "--a", bad], "").await.is_err(), "{bad:?}");
        }
        assert!(cli(&ctx, &["geo", "lookup", "x"], "").await.is_err());

        let (_dir2, ctx2) = super::super::tests::ctx(NO_CONSOLE).await;
        let err = cli(&ctx2, &["relay", "status"], "").await.unwrap_err().to_string();
        assert!(err.contains("Cannot reach the server console"), "{err}");
    }

    async fn rows(db: &sqlx::SqlitePool) -> Vec<(String, String, String)> {
        sqlx::query_as("select scope, key, value from strategy_option order by scope, key")
            .fetch_all(db)
            .await
            .unwrap()
    }

    fn row(scope: &str, key: &str, value: &str) -> (String, String, String) {
        (scope.into(), key.into(), value.into())
    }

    async fn rev(db: &sqlx::SqlitePool, device: &str) -> i64 {
        crate::strategy::effective(db, device).await.unwrap().0
    }

    #[tokio::test]
    async fn strategy() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        let db = &ctx.db;
        let r0 = rev(db, "dev1").await;
        cli(&ctx, &["strategy", "set", "*", "a", "1"], "").await.unwrap();
        cli(&ctx, &["strategy", "set", "dev1", "a", "2"], "").await.unwrap();
        cli(&ctx, &["strategy", "set", "dev1", "a", "3"], "").await.unwrap();
        cli(&ctx, &["strategy", "unset", "dev1", "b"], "").await.unwrap();
        assert_eq!(
            rows(db).await,
            vec![row("*", "a", "1"), row("*", "relay-server", ""), row("dev1", "a", "3"), row("dev1", "b", "")]
        );
        let r1 = rev(db, "dev1").await;
        assert_ne!(r1, r0);

        let show = cli(&ctx, &["strategy", "show", "dev1"], "").await.unwrap();
        assert!(show.starts_with(&format!("Device dev1: rev {r1}\n")), "{show}");
        assert!(show.contains("a = \"3\"  (device)\n"), "{show}");
        assert!(show.contains("b = \"\"  (device, clients delete the key)\n"), "{show}");
        assert!(show.contains("relay-server = \"\"  (global, clients delete the key)\n"), "{show}");
        let global = cli(&ctx, &["strategy", "show"], "").await.unwrap();
        assert!(global.contains(&format!("rev {}", rev(db, "other").await)), "{global}");
        assert!(global.contains("a = \"1\"  (global)\n"), "{global}");
        assert_eq!(cli(&ctx, &["strategy", "show", "*"], "").await.unwrap(), global);

        cli(&ctx, &["strategy", "forget", "dev1", "a"], "").await.unwrap();
        let out = cli(&ctx, &["strategy", "forget", "dev1", "a"], "").await.unwrap();
        assert!(out.contains("has no option"), "{out}");
        assert_eq!(crate::strategy::effective(db, "dev1").await.unwrap().1["a"], "1");

        let before = rev(db, "dev1").await;
        cli(&ctx, &["strategy", "repush", "dev1"], "").await.unwrap();
        assert_ne!(rev(db, "dev1").await, before);
        let other = rev(db, "dev2").await;
        cli(&ctx, &["strategy", "repush", "*"], "").await.unwrap();
        cli(&ctx, &["strategy", "repush", "*"], "").await.unwrap();
        assert_ne!(rev(db, "dev2").await, other);
        let epoch: i64 = sqlx::query_scalar("select strategy_epoch from device_policy where device_id = '*'")
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(epoch, 2);

        assert!(cli(&ctx, &["strategy", "set", "", "a", "1"], "").await.is_err());
        assert!(cli(&ctx, &["strategy", "set", "dev1", "", "1"], "").await.is_err());
        assert!(cli(&ctx, &["strategy", "set", "dev1", "a"], "").await.is_err());
        assert!(cli(&ctx, &["strategy", "unset", "dev1", "a", "x"], "").await.is_err());
    }

    #[tokio::test]
    async fn pin_relay_and_device_list() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        let db = &ctx.db;
        let pin = || async {
            sqlx::query_scalar::<_, String>("select relay_pin from device_policy where device_id = 'd1'")
                .fetch_one(db)
                .await
                .unwrap()
        };
        cli(&ctx, &["device", "pin-relay", "d1", "r1.example:21117"], "").await.unwrap();
        assert_eq!(pin().await, "r1.example:21117");
        // Keeps the strategy epoch of the same row.
        cli(&ctx, &["strategy", "repush", "d1"], "").await.unwrap();
        cli(&ctx, &["device", "pin-relay", "d1", "none"], "").await.unwrap();
        assert_eq!(pin().await, "");
        let epoch: i64 = sqlx::query_scalar("select strategy_epoch from device_policy where device_id = 'd1'")
            .fetch_one(db)
            .await
            .unwrap();
        assert_eq!(epoch, 1);
        assert!(cli(&ctx, &["device", "pin-relay", "*", "r"], "").await.is_err());

        let (alice, _) = crate::testutil::create_user(db, "alice", "pw", false).await;
        sqlx::query(
            "insert into device(id, user_id, hostname, client_type, version, first_seen_at, last_seen_at) values
             ('100', ?, 'pc-a', 'rustdesk', '1.4.2', 0, 1700000000),
             ('200', null, 'pc-b', 'leapgate', '0.1.0', 0, 1700000000)",
        )
        .bind(alice)
        .execute(db)
        .await
        .unwrap();
        let attempt = |b_id: &str, b_version: Option<&str>, a_device: Option<&str>, a_version: &str, at: i64| {
            sqlx::query(
                "insert into conn_attempt(started_at, a_ip, a_port, via, a_device_id, a_version, b_id, conn_type,
                   a_nat_type, a_force_relay, a_has_v6, signal, server_forced_relay, b_version)
                 values(?, '1.1.1.1', 1, 'tcp', ?, ?, ?, 0, 0, 0, 0, 'punch_hole', 0, ?)",
            )
            .bind(at)
            .bind(a_device.map(str::to_owned))
            .bind(a_version.to_owned())
            .bind(b_id.to_owned())
            .bind(b_version.map(str::to_owned))
        };
        attempt("300", Some("1.3.0"), Some("100"), "1.4.2", 1_000_000).execute(db).await.unwrap();
        attempt("300", Some("1.3.9"), Some("400"), "1.4.0", 2_000_000).execute(db).await.unwrap();
        // B never answered: not a device we know anything about.
        attempt("500", None, None, "1.4.2", 3_000_000).execute(db).await.unwrap();
        attempt("200", Some("1.5.0"), Some(""), "1.4.2", 4_000_000).execute(db).await.unwrap();

        let all = cli(&ctx, &["device", "list"], "").await.unwrap();
        let lines: Vec<&str> = all.lines().collect();
        assert_eq!(lines.len(), 3, "{all}");
        assert!(lines[1].starts_with("100") && lines[1].contains("alice") && lines[1].contains("1.4.2"), "{all}");
        assert!(lines[2].starts_with("200") && lines[2].contains("leapgate"), "{all}");

        let legacy = cli(&ctx, &["device", "list", "--legacy"], "").await.unwrap();
        let lines: Vec<&str> = legacy.lines().collect();
        assert_eq!(lines.len(), 5, "{legacy}");
        assert!(lines[1].starts_with("100"), "{legacy}");
        assert!(lines[2].starts_with("300") && lines[2].contains("1.3.9") && lines[2].ends_with("rendezvous only"), "{legacy}");
        assert!(lines[3].starts_with("400") && lines[3].contains("1.4.0") && lines[3].ends_with("rendezvous only"), "{legacy}");
        assert!(lines[4].contains("never sent a heartbeat"), "{legacy}");
    }

    #[test]
    fn fingerprint_like_the_client() {
        // rustdesk `pk_to_fingerprint`: lowercase hex, a space every 4 characters.
        assert_eq!(super::fingerprint(&[0xab, 0x01, 0xff]), "ab01 ff");
        let fp = super::fingerprint(&[0x0f; 32]);
        assert_eq!(fp.len(), 64 + 15);
        assert!(fp.starts_with("0f0f 0f0f ") && fp.ends_with(" 0f0f"));
    }

    async fn peer(db: &sqlx::SqlitePool, id: &str, uuid: &[u8], pk: &[u8], pinned_at: Option<i64>) {
        crate::database::Database::new(db.clone()).insert_peer(id, uuid, pk, "{}").await.unwrap();
        sqlx::query("update peer set pk_pinned_at = ? where id = ?").bind(pinned_at).bind(id).execute(db).await.unwrap();
    }

    async fn pinned_at(db: &sqlx::SqlitePool, id: &str) -> Option<Option<i64>> {
        sqlx::query_scalar("select pk_pinned_at from peer where id = ?").bind(id).fetch_optional(db).await.unwrap()
    }

    #[tokio::test]
    async fn device_key_and_reset() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        let db = &ctx.db;
        peer(db, "dev001", b"machine-1", &[0xab; 32], Some(1_700_000_000)).await;
        peer(db, "dev002", b"machine-1", &[0xcd; 32], None).await;
        peer(db, "dev003", b"machine-2", &[0xef; 32], None).await;

        let out = cli(&ctx, &["device", "key", "dev001"], "").await.unwrap();
        assert!(out.contains(&format!("Key fingerprint: {}\n", super::fingerprint(&[0xab; 32]))), "{out}");
        assert!(out.contains(&format!("Key: pinned since {}\n", super::fmt_time(1_700_000_000))), "{out}");
        assert!(out.contains("uuid: 9 bytes\n") && out.contains("Other ids with this uuid: dev002\n"), "{out}");
        let out = cli(&ctx, &["device", "key", "dev003"], "").await.unwrap();
        assert!(out.contains("Key: not pinned\n") && out.contains("Other ids with this uuid: none\n"), "{out}");
        assert!(cli(&ctx, &["device", "key", "nosuch"], "").await.is_err());

        // No server console: the database is changed all the same (not rolled back), and the command
        // fails saying a running server must be restarted. Reset keeps the uuid and key.
        let err = cli(&ctx, &["device", "key", "reset", "dev001"], "").await.unwrap_err().to_string();
        assert!(err.contains("no longer pinned") && err.contains("restart it"), "{err}");
        assert_eq!(pinned_at(db, "dev001").await, Some(None));
        let (uuid, pk): (Vec<u8>, Vec<u8>) =
            sqlx::query_as("select uuid, pk from peer where id = 'dev001'").fetch_one(db).await.unwrap();
        assert_eq!((uuid, pk), (b"machine-1".to_vec(), vec![0xab; 32]));
        let err = cli(&ctx, &["device", "key", "reset", "--forget", "dev001"], "").await.unwrap_err().to_string();
        assert!(err.contains("forgotten") && err.contains("restart it"), "{err}");
        assert_eq!(pinned_at(db, "dev001").await, None);
        let err = cli(&ctx, &["device", "key", "reset", "dev001"], "").await.unwrap_err().to_string();
        assert!(err.contains("No registered device") && err.contains("restart leapgate-server"), "{err}");
        assert!(cli(&ctx, &["device", "key", "reset", "a b"], "").await.is_err());
        assert!(cli(&ctx, &["device", "key", "reset"], "").await.is_err());

        // With a server running: the command line changes the database, then the console reloads
        // the entry (`kl`; the server side is in `rendezvous_server`'s tests). The console is sent
        // `kl <id>` (`fake_console` echoes it).
        let (_dir2, ctx2) = super::super::tests::ctx(fake_console().await).await;
        peer(&ctx2.db, "dev004", b"machine-4", &[0x44; 32], Some(1)).await;
        let err = cli(&ctx2, &["device", "key", "reset", "dev004"], "").await.unwrap_err().to_string();
        assert!(err.contains(r#""got kl dev004""#), "{err}");
        // Answered like the server: success.
        let (_dir3, ctx3) = super::super::tests::ctx(console_replying("dev005: reloaded from the database\n").await).await;
        peer(&ctx3.db, "dev005", b"machine-5", &[0x55; 32], Some(1)).await;
        let out = cli(&ctx3, &["device", "key", "reset", "dev005"], "").await.unwrap();
        assert!(out.contains("no longer pinned") && out.ends_with("dev005: reloaded from the database\n"), "{out}");
        assert_eq!(pinned_at(&ctx3.db, "dev005").await, Some(None));
        let out = cli(&ctx3, &["device", "key", "reset", "dev005", "--forget"], "").await.unwrap();
        assert!(out.contains("forgotten"), "{out}");
        assert_eq!(pinned_at(&ctx3.db, "dev005").await, None);
        // A failed or empty answer: the change stands, the command fails saying to restart.
        for reply in ["Failed: x", ""] {
            let (_dir4, ctx4) = super::super::tests::ctx(console_replying(reply).await).await;
            peer(&ctx4.db, "dev006", b"machine-6", &[0x66; 32], Some(1)).await;
            let err = cli(&ctx4, &["device", "key", "reset", "dev006"], "").await.unwrap_err().to_string();
            assert!(err.contains("restart it") && err.contains(&format!("{reply:?}")), "{err}");
            assert_eq!(pinned_at(&ctx4.db, "dev006").await, Some(None));
        }
    }

    #[tokio::test]
    async fn strategy_never_takes_leapgate_keys() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        for words in [&["strategy", "set", "*", "leapgate-api-caps", "x"][..], &["strategy", "unset", "dev1", "leapgate-x"]] {
            let err = cli(&ctx, words, "").await.unwrap_err().to_string();
            assert!(err.contains("leapgate-"), "{err}");
        }
        assert_eq!(rows(&ctx.db).await, vec![row("*", "relay-server", "")]);
    }

    #[tokio::test]
    async fn stats_arguments() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        for bad in [&["stats", "--days", "0"][..], &["stats", "--days", "x"], &["stats", "extra"]] {
            assert!(cli(&ctx, bad, "").await.is_err(), "{bad:?}");
        }
    }

    /// Contract 05 §3.8: the ICE results are counted in a table of their own, with the caveat.
    #[tokio::test]
    async fn stats_counts_ice_results() {
        let (_dir, ctx) = ctx(NO_CONSOLE).await;
        let now = crate::common::now() as i64 * 1000;
        for (outcome, at) in [("connected", now - 1_000), ("connected", now - 2_000), ("abandoned", now - 3_000), ("no_pair", 0)] {
            sqlx::query("insert into ice_result(at, a_ip, b_id, outcome) values(?, '1.2.3.4', 'B1', ?)")
                .bind(at)
                .bind(outcome)
                .execute(&ctx.db)
                .await
                .unwrap();
        }
        let out = cli(&ctx, &["stats", "--days", "1"], "").await.unwrap();
        let (_, ice) = out.split_once("ICE OUTCOME").unwrap_or_else(|| panic!("{out}"));
        let lines: Vec<&str> = ice.lines().collect();
        assert_eq!(lines[1..3], ["abandoned    1", "connected    2"], "{out}");
        assert!(lines[3].contains("relay fallback rate above reads high"), "{out}");
    }
}
