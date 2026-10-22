//! Process-wide shared handles (PORTA.md §3), one copy given to `RendezvousServer` and to axum.

use crate::{
    config::Config, conn_tracker::ConnTracker, crypto::SecretBox, peer::PeerMap, router::Router,
};
use hbb_common::ResultType;
use sodiumoxide::crypto::sign;
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
    /// `get_server_sk`'s key (public key checked against `licence_key`; may be empty).
    pub server_pk: String,
    /// `get_server_sk`'s signing key (KeyExchange, `IdPk` signatures).
    pub sk: Option<sign::SecretKey>,
}

impl AppState {
    /// Builds the state; background tasks are not spawned here (`spawn_tasks`).
    pub fn new(
        db: SqlitePool,
        cfg: Config,
        secret_key_file: &Path,
        server_pk: String,
        sk: Option<sign::SecretKey>,
    ) -> ResultType<Self> {
        let cfg = Arc::new(cfg);
        Ok(Self {
            pm: PeerMap::new(db.clone()),
            router: Arc::new(Router::new(db.clone(), cfg.clone())),
            tracker: Arc::new(ConnTracker::new(db.clone())),
            secret: Arc::new(SecretBox::load_or_create(secret_key_file)?),
            cfg,
            server_pk,
            sk,
            db,
        })
    }

    /// Router health check / GeoIP update and the tracker's finalizer; call inside the server runtime.
    pub fn spawn_tasks(&self) {
        self.router.spawn_tasks();
        self.tracker.spawn_tasks();
    }
}
