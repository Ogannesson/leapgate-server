//! Process-wide shared handles (PORTA.md §3), one copy given to `RendezvousServer` and to axum.

use crate::{
    config::Config, conn_tracker::ConnTracker, crypto::SecretBox, peer::PeerMap, router::Router,
};
use hbb_common::{bail, tokio::sync::Semaphore, ResultType};
use sqlx::SqlitePool;
use std::{path::Path, sync::Arc};

#[derive(Clone)]
pub(crate) struct AppState {
    pub db: SqlitePool,
    /// Online = in memory and `last_reg_time` younger than 30 s (note 02 §2.5).
    pub pm: PeerMap,
    pub router: Arc<Router>,
    pub tracker: Arc<ConnTracker>,
    pub secret: Arc<SecretBox>,
    pub cfg: Arc<Config>,
    /// `/api/ab/peers` pages being built or sent (`api::ab::MAX_PAGES`); a slot goes with the
    /// response body.
    pub ab_pages: Arc<Semaphore>,
}

impl AppState {
    /// Builds the state; background tasks are not spawned here (`spawn_tasks`).
    pub async fn new(db: SqlitePool, cfg: Config, secret_key_file: &Path) -> ResultType<Self> {
        // No key file but ciphertext in the database means the key was lost (database restored
        // without it, another working directory): a new key would make every saved password
        // unreadable without anyone noticing, so refuse to start (PORTA.md §13).
        if !secret_key_file.try_exists()? {
            let encrypted: Option<i64> = sqlx::query_scalar(
                "select 1 from ab_peer where hash_enc <> '' or password_enc <> '' limit 1",
            )
            .fetch_optional(&db)
            .await?;
            if encrypted.is_some() {
                bail!(
                    "{} not found, but the address books hold encrypted passwords: restore the key file \
                     (run from the server's working directory), or clear ab_peer.hash_enc and \
                     ab_peer.password_enc on purpose (every saved password is lost)",
                    secret_key_file.display()
                );
            }
        }
        let cfg = Arc::new(cfg);
        Ok(Self {
            pm: PeerMap::new(crate::database::rendezvous_pool(&db)),
            router: Arc::new(Router::new(db.clone(), cfg.clone())),
            tracker: Arc::new(ConnTracker::new(db.clone())),
            secret: Arc::new(SecretBox::load_or_create(secret_key_file)?),
            cfg,
            ab_pages: Arc::new(Semaphore::new(crate::api::ab::MAX_PAGES)),
            db,
        })
    }

    /// Router health check / GeoIP update, the tracker's finalizer and the WAL checkpoints; call
    /// inside the server runtime.
    pub fn spawn_tasks(&self) {
        self.router.spawn_tasks();
        self.tracker.spawn_tasks();
        crate::database::spawn_checkpoints(&self.db);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::SECRET_KEY_FILE, testutil};
    use hbb_common::tokio;

    #[tokio::test]
    async fn missing_key_with_ciphertext_refuses_to_start() {
        let (dir, db) = testutil::pool().await;
        let path = dir.path().join(SECRET_KEY_FILE);
        let new = || AppState::new(db.clone(), Config::default(), &path);

        // Empty database: the first start creates the key.
        new().await.unwrap();
        assert!(path.exists());

        let (uid, _) = testutil::create_user(&db, "alice", "", false).await;
        sqlx::query("insert into ab(guid, name, owner_id, personal, created_at, updated_at) values('g', 'b', ?, 1, 0, 0)")
            .bind(uid)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("insert into ab_peer(ab_guid, id, hash_enc, created_at, updated_at) values('g', '1', 'sb1:x', 0, 0)")
            .execute(&db)
            .await
            .unwrap();
        // Key present: loads as before.
        new().await.unwrap();

        std::fs::remove_file(&path).unwrap();
        for (hash, password) in [("sb1:x", ""), ("", "sb1:y")] {
            sqlx::query("update ab_peer set hash_enc = ?, password_enc = ?")
                .bind(hash)
                .bind(password)
                .execute(&db)
                .await
                .unwrap();
            let err = new().await.err().unwrap().to_string();
            assert!(err.contains("restore the key file"), "{err}");
            assert!(!path.exists(), "no new key is generated");
        }

        // Columns cleared on purpose: a new key is created.
        sqlx::query("update ab_peer set hash_enc = '', password_enc = ''").execute(&db).await.unwrap();
        new().await.unwrap();
        assert!(path.exists());
    }
}
