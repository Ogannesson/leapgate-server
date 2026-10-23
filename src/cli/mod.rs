//! Command line management (LEAPGATE.md §14): `leapgate-server <subcommand> …`.
//! Opens the same database as the server (`DB_URL`, read the same way: `.env`, `-c` INI, environment,
//! command line; migrations run on open; a missing database is an error, not created); subcommands
//! that write print its absolute path; subcommands that need runtime state talk to the local
//! console (127.0.0.1:`port-1`). `relay`, `route` and `geo` never use the database and do not open it.

mod manage;
mod ops;

use crate::common::{get_arg_or, set_arg};
use hbb_common::{
    bail,
    config::RENDEZVOUS_PORT,
    tokio::{
        self,
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    },
    ResultType,
};
use ini::Ini;
use sqlx::SqlitePool;
use std::{
    io::BufRead,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

/// Names the client treats as the personal address book; a shared book may not use them (§12.1).
pub(crate) const RESERVED_BOOK_NAMES: [&str; 2] = ["My address book", "Legacy address book"];

const USAGE: &str = "Usage: leapgate-server <command> [options]

  user add <name> [--admin] [--display-name <s>] [--email <s>]   (password: one line on stdin)
  user passwd <name>                                             (password: one line on stdin)
  user list | user disable|enable <name> | user admin <name> on|off | user del <name>
  group add <name> [--share-devices] | group del <name> | group list
  group member add|rm <group> <user>
  ab list | ab create <name> --owner <user> [--note <s>] | ab rename <name> <new> | ab del <name>
  ab grant <book> --user <u>|--group <g> ro|rw|full | ab revoke <book> --user <u>|--group <g>
  device list [--legacy] | device pin-relay <device> <host|none>
  device key <device> | device key reset [--forget] <device>
  strategy show [<device>] | strategy set <device|'*'> <key> <value>
  strategy unset|forget <device|'*'> <key> | strategy repush <device|'*'>
  relay status | route test <ipA> <ipB> [--a <device>] [--b <device>]
  geo lookup <ip> | geo update
  stats [--days N]
  import rustdesk-api <db path> [--dry-run]

Options read like the server's: -p/--port (console = 127.0.0.1:port-1), -c/--config <INI>,
--leapgate-config <file>; DB_URL from the environment or .env.
";

/// `args` starts at the subcommand (`["user", "add", "alice", …]`); `main` only dispatches here when
/// the first argument is one of the known subcommands.
pub fn run(argv: Vec<String>) -> ResultType<()> {
    let mut args = Args::parse(argv)?;
    if args.flag("-h") || args.flag("--help") {
        print!("{USAGE}");
        return Ok(());
    }
    load_settings(args.value(&["-c", "--config"]).as_deref());
    if let Some(port) = args.value(&["-p", "--port"]) {
        set_arg("port", &port);
    }
    if let Some(path) = args.value(&["--leapgate-config"]) {
        set_arg("leapgate-config", &path);
    }
    let port: u16 = get_arg_or("port", RENDEZVOUS_PORT.to_string()).parse()?;
    if port < 3 {
        bail!("Invalid port");
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let db_url = crate::database::db_url();
    let changes = changes_database(&args);
    rt.block_on(async {
        let console = SocketAddr::from(([127, 0, 0, 1], port - 1));
        let leapgate_config = PathBuf::from(get_arg_or("leapgate-config", "leapgate.toml".to_owned()));
        let mut out = match args.pos.front().map(String::as_str) {
            // No database needed, so none is required or opened (review R2-6).
            Some(cmd @ ("relay" | "route" | "geo")) => {
                let cmd = cmd.to_owned();
                args.pos.pop_front();
                ops::runtime(console, &leapgate_config, &cmd, args).await?
            }
            _ => {
                let ctx = Ctx {
                    db: crate::database::open(&db_url, false).await?,
                    console,
                    leapgate_config,
                    secret_key: PathBuf::from(crate::crypto::SECRET_KEY_FILE),
                };
                let stdin = std::io::stdin();
                let out = exec(&ctx, args, &mut stdin.lock()).await;
                // No automatic checkpoints (LEAPGATE.md §4.1), and dropping the pool does not wait for
                // the connections to close: copy the WAL into the database before exiting, so that
                // with the service stopped the database file alone has every change. PASSIVE: with
                // the service running it holds up no writer (its own task checkpoints then).
                let _ = sqlx::query("pragma wal_checkpoint(passive)").execute(&ctx.db).await;
                ctx.db.close().await;
                out?
            }
        };
        if changes {
            out += &format!("Database: {}\n", crate::database::db_file(&db_url)?.display());
        }
        print!("{out}");
        Ok(())
    })
}

/// Whether the subcommand in `args` writes to the database. Its output then names the database file,
/// so a change made through a wrong `DB_URL` shows.
fn changes_database(args: &Args) -> bool {
    let mut words = args.pos.iter().map(String::as_str);
    match (words.next(), words.next()) {
        (Some("user" | "group" | "ab" | "device"), Some("list")) | (Some("strategy"), Some("show")) => false,
        (Some("device"), Some("key")) => words.next() == Some("reset"),
        (Some("relay" | "route" | "geo" | "stats"), _) => false,
        (Some("import"), _) => !args.opts.iter().any(|(n, _)| n == "--dry-run"),
        _ => true,
    }
}

/// The same sources as the server's `init_args`, in the same order: `.env`, then the `-c` INI
/// (a missing file is ignored, as there); command line options are applied afterwards by `run`.
fn load_settings(config: Option<&str>) {
    for file in std::iter::once(".env").chain(config) {
        if let Ok(ini) = Ini::load_from_file(file) {
            if let Some(section) = ini.section(None::<String>) {
                section.iter().for_each(|(k, v)| set_arg(k, v));
            }
        }
    }
}

pub(super) struct Ctx {
    pub db: SqlitePool,
    /// The running server's console, 127.0.0.1:`port-1`.
    pub console: SocketAddr,
    pub leapgate_config: PathBuf,
    /// `leapgate_secret.key` in the working directory; only `import` needs it.
    pub secret_key: PathBuf,
}

/// Runs one subcommand and returns what it prints. Passwords are read from `input`.
pub(super) async fn exec(ctx: &Ctx, mut args: Args, input: &mut dyn BufRead) -> ResultType<String> {
    let cmd = args.next("command")?;
    match cmd.as_str() {
        "user" | "group" | "ab" => manage::exec(ctx, &cmd, args, input).await,
        "device" | "strategy" | "stats" => ops::exec(ctx, &cmd, args).await,
        "relay" | "route" | "geo" => ops::runtime(ctx.console, &ctx.leapgate_config, &cmd, args).await,
        "import" => {
            let kind = args.next("source kind")?;
            if kind != "rustdesk-api" {
                bail!("Unknown import source '{kind}' (only rustdesk-api)\n\n{USAGE}");
            }
            let src = args.next("rustdesk-api database path")?;
            let dry_run = args.flag("--dry-run");
            args.finish()?;
            let secret = crate::crypto::SecretBox::load_existing(&ctx.secret_key)?;
            crate::import::rustdesk_api(&ctx.db, &secret, Path::new(&src), dry_run).await?;
            if dry_run {
                return Ok(String::new());
            }
            let key = std::fs::canonicalize(&ctx.secret_key).unwrap_or_else(|_| ctx.secret_key.clone());
            Ok(format!(
                "Passwords were encrypted with {}; back it up together with the database.\n",
                key.display()
            ))
        }
        _ => bail!("Unknown command '{cmd}'\n\n{USAGE}"),
    }
}

/// Flags that take a value (`--name value` or `--name=value`).
const VALUE_FLAGS: &[&str] = &[
    "-p", "--port", "-c", "--config", "--leapgate-config", "--display-name", "--email", "--owner",
    "--note", "--user", "--group", "--days", "--a", "--b",
];
const BOOL_FLAGS: &[&str] = &[
    "-h", "--help", "--admin", "--share-devices", "--legacy", "--dry-run", "--forget",
];

/// Command line words: positionals in order, plus options from anywhere on the line.
/// Each subcommand takes what it accepts, then `finish` rejects anything left over.
/// `--` ends option parsing (for values starting with `-`).
pub(super) struct Args {
    pos: std::collections::VecDeque<String>,
    opts: Vec<(String, Option<String>)>,
}

impl Args {
    pub fn parse(argv: Vec<String>) -> ResultType<Self> {
        let mut pos = std::collections::VecDeque::new();
        let mut opts = Vec::new();
        let mut it = argv.into_iter();
        while let Some(a) = it.next() {
            if a == "--" {
                pos.extend(it.by_ref());
                break;
            }
            if !a.starts_with('-') || a.len() == 1 {
                pos.push_back(a);
                continue;
            }
            let (name, inline) = match a.split_once('=') {
                Some((n, v)) if n.starts_with("--") => (n.to_owned(), Some(v.to_owned())),
                _ => (a.clone(), None),
            };
            if VALUE_FLAGS.contains(&name.as_str()) {
                let Some(v) = inline.or_else(|| it.next()) else {
                    bail!("Option {name} needs a value");
                };
                opts.push((name, Some(v)));
            } else if BOOL_FLAGS.contains(&name.as_str()) && inline.is_none() {
                opts.push((name, None));
            } else {
                bail!("Unknown option '{a}'\n\n{USAGE}");
            }
        }
        Ok(Self { pos, opts })
    }

    /// The next positional argument; `what` names it in the error.
    pub fn next(&mut self, what: &str) -> ResultType<String> {
        match self.pos.pop_front() {
            Some(v) => Ok(v),
            None => bail!("Missing {what}\n\n{USAGE}"),
        }
    }

    pub fn next_opt(&mut self) -> Option<String> {
        self.pos.pop_front()
    }

    /// Takes the value of an option given under any of `names` (the last one wins).
    pub fn value(&mut self, names: &[&str]) -> Option<String> {
        let mut found = None;
        self.opts.retain(|(n, v)| {
            if names.contains(&n.as_str()) {
                found = v.clone();
                false
            } else {
                true
            }
        });
        found
    }

    pub fn flag(&mut self, name: &str) -> bool {
        let before = self.opts.len();
        self.opts.retain(|(n, _)| n != name);
        self.opts.len() != before
    }

    pub fn finish(self) -> ResultType<()> {
        if let Some(p) = self.pos.front() {
            bail!("Unexpected argument '{p}'\n\n{USAGE}");
        }
        if let Some((n, _)) = self.opts.first() {
            bail!("Option {n} does not apply here\n\n{USAGE}");
        }
        Ok(())
    }
}

/// One line from stdin (without the line break); empty is refused.
fn read_password(input: &mut dyn BufRead, user: &str) -> ResultType<String> {
    eprint!("Password for {user} (one line on stdin): ");
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        bail!("No password on stdin");
    }
    let pw = line.trim_end_matches(['\n', '\r']);
    if pw.is_empty() {
        bail!("The password must not be empty");
    }
    Ok(pw.to_owned())
}

/// Sends one console command and returns the reply (the server writes it and closes the stream).
async fn console(addr: SocketAddr, cmd: &str, wait: Duration) -> ResultType<String> {
    let stream = console_connect(addr).await?;
    console_send(stream, cmd, wait).await
}

async fn console_connect(addr: SocketAddr) -> ResultType<TcpStream> {
    match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => bail!("Cannot reach the server console at {addr} ({e}); is leapgate-server running with this -p?"),
        Err(_) => bail!("Cannot reach the server console at {addr} (timed out)"),
    }
}

async fn console_send(mut stream: TcpStream, cmd: &str, wait: Duration) -> ResultType<String> {
    stream.write_all(cmd.as_bytes()).await?;
    let mut buf = Vec::new();
    if tokio::time::timeout(wait, stream.read_to_end(&mut buf)).await.is_err() {
        bail!("The server console did not answer within {} s", wait.as_secs());
    }
    let mut out = String::from_utf8_lossy(&buf).into_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

fn check_name(kind: &str, name: &str) -> ResultType<()> {
    if name.trim().is_empty() {
        bail!("The {kind} name must not be empty");
    }
    Ok(())
}

/// Local time `YYYY-MM-DD HH:MM:SS` of a unix timestamp.
fn fmt_time(secs: i64) -> String {
    use chrono::TimeZone as _;
    match chrono::Local.timestamp_opt(secs, 0).single() {
        Some(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => secs.to_string(),
    }
}

/// Columns padded to their widest cell, separated by two spaces.
fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let mut s = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                s.push_str(cell);
            } else {
                s.push_str(cell);
                s.push_str(&" ".repeat(widths[i] - cell.chars().count() + 2));
            }
        }
        s.trim_end().to_owned() + "\n"
    };
    let mut out = line(header.to_vec());
    for row in rows {
        out += &line(row.iter().map(String::as_str).collect());
    }
    out
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub fn args(words: &[&str]) -> Args {
        Args::parse(words.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    /// A context on a fresh migrated database; the console points at `console`.
    pub async fn ctx(console: SocketAddr) -> (tempfile::TempDir, Ctx) {
        let (dir, db) = crate::testutil::pool().await;
        let mut ctx = ctx_with(db, dir.path());
        ctx.console = console;
        (dir, ctx)
    }

    /// Files in `dir`; no console listens on 127.0.0.1:1.
    pub fn ctx_with(db: SqlitePool, dir: &Path) -> Ctx {
        Ctx {
            db,
            console: SocketAddr::from(([127, 0, 0, 1], 1)),
            leapgate_config: dir.join("leapgate.toml"),
            secret_key: dir.join(crate::crypto::SECRET_KEY_FILE),
        }
    }

    /// Runs one command line with `stdin` as standard input.
    pub async fn cli(ctx: &Ctx, words: &[&str], stdin: &str) -> ResultType<String> {
        exec(ctx, Args::parse(words.iter().map(|s| s.to_string()).collect())?, &mut stdin.as_bytes()).await
    }

    #[test]
    fn parses_options_anywhere() {
        let mut a = args(&["user", "add", "--admin", "alice", "--email=a@x", "--display-name", "A B", "-p", "30000"]);
        assert_eq!(a.value(&["-p", "--port"]).as_deref(), Some("30000"));
        assert_eq!(a.next("cmd").unwrap(), "user");
        assert_eq!(a.next("sub").unwrap(), "add");
        assert_eq!(a.next("name").unwrap(), "alice");
        assert!(a.flag("--admin"));
        assert!(!a.flag("--admin"));
        assert_eq!(a.value(&["--email"]).as_deref(), Some("a@x"));
        assert_eq!(a.value(&["--display-name"]).as_deref(), Some("A B"));
        a.finish().unwrap();

        // Leftovers are errors.
        let mut a = args(&["group", "list", "--admin"]);
        a.next("").unwrap();
        a.next("").unwrap();
        assert!(a.finish().is_err());
        let a = args(&["x", "y"]);
        assert!(a.finish().is_err());

        // `--` and a lone `-` are positionals.
        let mut a = args(&["strategy", "set", "-", "--", "k", "-v"]);
        assert_eq!(a.next_opt().as_deref(), Some("strategy"));
        assert_eq!(a.next_opt().as_deref(), Some("set"));
        assert_eq!(a.next_opt().as_deref(), Some("-"));
        assert_eq!(a.next_opt().as_deref(), Some("k"));
        assert_eq!(a.next_opt().as_deref(), Some("-v"));

        assert!(Args::parse(vec!["user".into(), "--nope".into()]).is_err());
        assert!(Args::parse(vec!["user".into(), "--owner".into()]).is_err());
        assert!(Args::parse(vec!["user".into(), "--admin=1".into()]).is_err());
    }

    #[test]
    fn only_writes_name_the_database() {
        for words in [
            &["user", "add", "alice"][..],
            &["user", "passwd", "alice"],
            &["group", "member", "add", "g", "alice"],
            &["ab", "grant", "b", "--user", "alice", "rw"],
            &["device", "pin-relay", "123", "none"],
            &["device", "key", "reset", "123456"],
            &["device", "key", "reset", "--forget", "123456"],
            &["strategy", "set", "*", "k", "v"],
            &["strategy", "repush", "*"],
            &["import", "rustdesk-api", "x.db"],
        ] {
            assert!(changes_database(&args(words)), "{words:?}");
        }
        for words in [
            &["user", "list"][..],
            &["group", "list"],
            &["ab", "list"],
            &["device", "list", "--legacy"],
            &["device", "key", "123456"],
            &["strategy", "show", "123"],
            &["relay", "status"],
            &["route", "test", "1.1.1.1", "8.8.8.8"],
            &["geo", "update"],
            &["stats", "--days", "7"],
            &["import", "rustdesk-api", "x.db", "--dry-run"],
        ] {
            assert!(!changes_database(&args(words)), "{words:?}");
        }
    }

    #[test]
    fn password_from_one_line() {
        assert_eq!(read_password(&mut "s3 cret\r\nnext\n".as_bytes(), "a").unwrap(), "s3 cret");
        assert_eq!(read_password(&mut "last".as_bytes(), "a").unwrap(), "last");
        assert!(read_password(&mut "\n".as_bytes(), "a").is_err());
        assert!(read_password(&mut "".as_bytes(), "a").is_err());
    }

    #[test]
    fn table_pads_columns() {
        let t = table(&["A", "BB"], &[vec!["xyz".into(), "1".into()], vec!["中文".into(), "".into()]]);
        assert_eq!(t, "A    BB\nxyz  1\n中文\n");
    }

    #[tokio::test]
    async fn unknown_commands_and_import_needs_the_key() {
        let (_dir, ctx) = ctx(SocketAddr::from(([127, 0, 0, 1], 1))).await;
        assert!(cli(&ctx, &["nope"], "").await.is_err());
        assert!(cli(&ctx, &["import", "other", "x.db"], "").await.is_err());
        let err = cli(&ctx, &["import", "rustdesk-api", "x.db"], "").await.unwrap_err().to_string();
        assert!(err.contains("start the server once"), "{err}");
        assert!(!ctx.secret_key.exists());
    }
}
