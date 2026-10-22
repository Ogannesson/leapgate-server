use hbb_common::{bail, log, ResultType};
use sqlx::{
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
    },
    ConnectOptions,
};
use std::{path::PathBuf, str::FromStr, time::Duration};

/// How long a query of the main pool (API, command line, background tasks) waits for a connection
/// (sqlx's default is 30 s): an API flood queues behind the pool, and a request is better failed
/// in seconds than answered after its client gave up (review C-21).
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);
/// The rendezvous pool (`rendezvous_pool`): connections, and how long its queries wait for a
/// connection and for SQLite's write lock. `io_loop` awaits them, so every wait stalls UDP and the
/// rendezvous ports' accepts; a lookup or write that does not fit is given up, and the client
/// retries in its next registration round (review C-21/C-11).
const RENDEZVOUS_CONNECTIONS: u32 = 2;
const RENDEZVOUS_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(200);
const RENDEZVOUS_BUSY_TIMEOUT: Duration = Duration::from_millis(200);

/// `DB_URL`, or `db_v2.sqlite3` next to the executable's data (same default as upstream hbbs).
pub(crate) fn db_url() -> String {
    crate::common::get_arg_opt("DB_URL").unwrap_or_else(|| {
        let mut db = "db_v2.sqlite3".to_owned();
        #[cfg(all(windows, not(debug_assertions)))]
        {
            if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
            }
        }
        #[cfg(not(windows))]
        {
            db = format!("./{db}");
        }
        db
    })
}

/// The database file `url` names, made absolute against the working directory (as SQLite opens it).
pub(crate) fn db_file(url: &str) -> ResultType<PathBuf> {
    Ok(std::path::absolute(SqliteConnectOptions::from_str(url)?.get_filename())?)
}

/// Opens the process-wide pool and applies the embedded migrations.
/// The server creates a missing database (`create`); the command line does not: run from another
/// directory, it would otherwise write into a fresh database the running server never reads.
pub(crate) async fn open(url: &str, create: bool) -> ResultType<SqlitePool> {
    log::info!("DB_URL={}", url);
    let n: u32 = crate::common::get_arg_or("MAX_DATABASE_CONNECTIONS", "8".to_owned())
        .parse()
        .unwrap_or(8);
    log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
    let opt = SqliteConnectOptions::from_str(url)?;
    if !create {
        // Only NotFound means missing: a file we may not access (permissions) is reported as such.
        match opt.get_filename().try_exists() {
            Ok(true) => {}
            Ok(false) => bail!(
                "{} not found: run this from the server's working directory, or set DB_URL",
                db_file(url)?.display()
            ),
            Err(e) => bail!("cannot access {}: {e}", db_file(url)?.display()),
        }
    }
    // NORMAL in WAL mode: a commit no longer waits for an fsync (only checkpoints do), so the write
    // lock is held for microseconds instead of a disk flush. The database cannot be corrupted; a
    // power loss may drop the last commits.
    let opt = opt
        .create_if_missing(create)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true)
        .log_statements(log::LevelFilter::Debug);
    let pool = SqlitePoolOptions::new()
        .max_connections(n)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_with(opt)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// The rendezvous module's own pool on the database of `main` (PORTA.md §4.1): `PeerMap` looks up
/// and writes peers from `io_loop`, which must not queue behind unauthenticated API requests in
/// `main`'s fair queue (review C-21). Short waits (`RENDEZVOUS_*`); connections open on first use.
pub(crate) fn rendezvous_pool(main: &SqlitePool) -> SqlitePool {
    let opt = (*main.connect_options())
        .clone()
        .busy_timeout(RENDEZVOUS_BUSY_TIMEOUT);
    SqlitePoolOptions::new()
        .max_connections(RENDEZVOUS_CONNECTIONS)
        .acquire_timeout(RENDEZVOUS_ACQUIRE_TIMEOUT)
        .connect_lazy_with(opt)
}

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

#[derive(Default, sqlx::FromRow)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

impl Database {
    pub fn new(pool: SqlitePool) -> Database {
        Database { pool }
    }

    /// Closes the pool: every query fails from then on (tests of database errors).
    #[cfg(test)]
    pub async fn close(&self) {
        self.pool.close().await
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as::<_, Peer>(
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query("insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)")
            .bind(&guid)
            .bind(id)
            .bind(uuid)
            .bind(pk)
            .bind(info)
            .execute(&self.pool)
            .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query("update peer set id=?, pk=?, info=? where guid=?")
            .bind(id)
            .bind(pk)
            .bind(info)
            .bind(guid)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hbb_common::tokio;

    // The queries are no longer checked at compile time, so run each one against a real database.
    #[tokio::test]
    async fn peer_roundtrip() {
        let (_dir, pool) = crate::testutil::pool().await;
        let db = super::Database::new(pool);
        assert!(db.get_peer("123456").await.unwrap().is_none());
        let guid = db
            .insert_peer("123456", b"uuid", b"pk1", r#"{"ip":"1.2.3.4"}"#)
            .await
            .unwrap();
        let peer = db.get_peer("123456").await.unwrap().unwrap();
        assert_eq!(peer.guid, guid);
        assert_eq!(peer.id, "123456");
        assert_eq!(peer.uuid, b"uuid");
        assert_eq!(peer.pk, b"pk1");
        assert_eq!(peer.user, None);
        assert_eq!(peer.status, None);
        assert_eq!(peer.info, r#"{"ip":"1.2.3.4"}"#);
        db.update_pk(&guid, "654321", b"pk2", "{}").await.unwrap();
        assert!(db.get_peer("123456").await.unwrap().is_none());
        let peer = db.get_peer("654321").await.unwrap().unwrap();
        assert_eq!(peer.guid, guid);
        assert_eq!(peer.pk, b"pk2");
        assert_eq!(peer.info, "{}");
    }

    // An existing hbbs database (peer table only, no migration history) is taken over in place.
    #[tokio::test]
    async fn migrates_existing_hbbs_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        let url = path.to_str().unwrap();
        {
            let opt = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(url)
                .create_if_missing(true);
            let pool = sqlx::SqlitePool::connect_with(opt).await.unwrap();
            sqlx::raw_sql(
                "create table peer ( guid blob primary key not null, id varchar(100) not null,
                 uuid blob not null, pk blob not null, created_at datetime not null default(current_timestamp),
                 user blob, status tinyint, note varchar(300), info text not null ) without rowid;
                 create unique index index_peer_id on peer (id);
                 insert into peer(guid, id, uuid, pk, info) values(x'01', '123456', x'02', x'03', '{}');",
            )
            .execute(&pool)
            .await
            .unwrap();
            pool.close().await;
        }
        let pool = super::open(url, true).await.unwrap();
        let db = super::Database::new(pool.clone());
        assert!(db.get_peer("123456").await.unwrap().is_some());
        let n: i64 = sqlx::query_scalar("select count(*) from _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        // Running again is a no-op.
        drop(super::open(url, true).await.unwrap());
    }

    // Only the server creates a missing database; the command line refuses and names the absolute path.
    #[tokio::test]
    async fn creates_a_missing_database_only_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        let url = path.to_str().unwrap();
        let err = super::open(url, false).await.unwrap_err().to_string();
        assert!(err.contains(&format!("{} not found", path.display())), "{err}");
        assert!(err.contains("DB_URL"), "{err}");
        assert!(!path.exists());

        drop(super::open(url, true).await.unwrap());
        assert!(path.exists());
        drop(super::open(url, false).await.unwrap());

        // Relative names resolve against the working directory, like SQLite's own open.
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(super::db_file("./x.sqlite3").unwrap(), cwd.join("x.sqlite3"));
        assert_eq!(super::db_file("sqlite://x.sqlite3").unwrap(), cwd.join("x.sqlite3"));
        assert_eq!(super::db_file(url).unwrap(), path);
    }

    // Review R2-7: a database in a directory we may not enter is not "not found"; the real error shows.
    #[cfg(unix)]
    #[tokio::test]
    async fn inaccessible_database_is_not_reported_missing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("locked");
        std::fs::create_dir(&sub).unwrap();
        let path = sub.join("db.sqlite3");
        let url = path.to_str().unwrap();
        drop(super::open(url, true).await.unwrap());
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
        let res = std::fs::metadata(&path);
        let err = super::open(url, false).await.map(drop);
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        if res.is_ok() {
            return; // running as root: permissions do not apply
        }
        let err = err.unwrap_err().to_string();
        assert!(err.starts_with(&format!("cannot access {}: ", path.display())), "{err}");
        assert!(err.contains("ermission denied") && !err.contains("not found"), "{err}");
    }
}
