use crate::common::*;
use crate::database;
use hbb_common::{
    anyhow,
    bytes::Bytes,
    rendezvous_proto::*,
    throttled_log,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

/// Keyed by source (`conn_tracker::source_key`: an IPv4 address or an IPv6 /64).
pub(crate) type IpBlockMap = HashMap<IpAddr, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
pub(crate) type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;
// Same bound as the Pro server: a longer id is not a normal RustDesk id or hostname,
// and every peer entry and punch-request record keeps its own copy.
pub const MAX_PEER_ID_LEN: usize = 253;
/// Longest `RegisterPk.uuid` (raw bytes) accepted (review A-1): the raw length of the API's
/// `MAX_UUID_LEN` (128 bytes of base64), so every registered device can pass `uuid_matches`. Real
/// clients send `hbb_common::get_uuid()`: the machine id (36 bytes on Windows/macOS, 32 on Linux)
/// or, without one (Android/iOS), their 32-byte public key.
pub const MAX_REG_UUID_LEN: usize = 96;

/// `id` cut to `MAX_PEER_ID_LEN` bytes at a char boundary, for log lines: ids that reach a log
/// unchecked (a TCP `PunchHoleRequest`'s) may be as long as a frame (review C-1/C-7).
pub(crate) fn log_id(id: &str) -> &str {
    let mut end = id.len().min(MAX_PEER_ID_LEN);
    while !id.is_char_boundary(end) {
        end -= 1;
    }
    &id[..end]
}

/// Whether `err` is SQLite refusing a duplicate key (for `peer`: an id already there).
fn is_unique_violation(err: &anyhow::Error) -> bool {
    err.downcast_ref::<sqlx::Error>()
        .and_then(|e| e.as_database_error())
        .is_some_and(|e| e.is_unique_violation())
}

/// Empties the id sets whose day window is over, then drops the `IP_BLOCKER` entries with neither a
/// live minute window nor any id (the console `ib` rule, which also kept an empty set's entry for a
/// day; nothing is lost dropping it, the next request starts a fresh one).
pub(crate) fn retain_live_ip_blocks(map: &mut IpBlockMap) {
    map.retain(|_, (a, b)| {
        if b.1.elapsed().as_secs() > DAY_SECONDS {
            b.0 = Default::default();
        }
        a.1.elapsed().as_secs() <= IP_BLOCK_DUR || !b.0.is_empty()
    });
}

/// Periodic cleanup of the two maps unauthenticated `RegisterPk`s add to (review A-1): the expiry
/// rules of the console `ib`/`ic`, without `ic`'s display filter (more than one IP).
pub(crate) async fn purge_ip_maps() {
    retain_live_ip_blocks(&mut *IP_BLOCKER.lock().await);
    retain_live_ip_changes(&mut *IP_CHANGES.lock().await);
}

/// Drops the `IP_CHANGES` records started `IP_CHANGE_DUR_X2` seconds ago or earlier.
pub(crate) fn retain_live_ip_changes(map: &mut IpChangesMap) {
    map.retain(|_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2);
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    pub(crate) fn new(db: sqlx::SqlitePool) -> Self {
        Self {
            map: Default::default(),
            db: database::Database::new(db),
        }
    }

    /// Writes a registration of `peer` (`id`): the database first, then memory, so a failed write
    /// leaves the entry as it was (review U-1: an entry holding a uuid the database does not would
    /// take the id over). The result is the `RegisterPk` answer: `SERVER_ERROR` when the write
    /// failed, which the client only logs before retrying in its next round.
    pub(crate) async fn update_pk(
        &self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        // Lengths only: uuid and pk come from an unauthenticated packet (review A-5). Throttled:
        // a source may change its own peer's pk about 30 times a minute (review C-17).
        throttled_log!(
            Duration::from_secs(60),
            info,
            "update_pk {:?} {:?} uuid {} bytes, pk {} bytes",
            id,
            addr,
            uuid.len(),
            pk.len()
        );
        let (mut guid, info) = {
            let r = peer.read().await;
            let mut info = r.info.clone();
            info.ip = ip;
            (r.guid.clone(), info)
        };
        let info_str = serde_json::to_string(&info).unwrap_or_default();
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Ok(g) => guid = g,
                Err(err) => {
                    if is_unique_violation(&err) {
                        // The id was added after `get` found nothing (the command line, an import):
                        // take its row, so the client's retry is judged against the row's uuid.
                        self.reload(&id, &peer).await;
                    }
                    throttled_log!(Duration::from_secs(60), error, "db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                throttled_log!(Duration::from_secs(60), error, "db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            throttled_log!(Duration::from_secs(60), info, "pk updated instead of insert");
        }
        let mut w = peer.write().await;
        w.guid = guid;
        w.socket_addr = addr;
        w.uuid = uuid;
        w.pk = pk;
        w.last_reg_time = Instant::now();
        w.info = info;
        register_pk_response::Result::OK
    }

    /// Replaces `peer`'s stored fields (guid, uuid, pk, info) with the database row of `id`, if
    /// one can be read.
    async fn reload(&self, id: &str, peer: &LockPeer) {
        if let Ok(Some(v)) = self.db.get_peer(id).await {
            let mut w = peer.write().await;
            w.guid = v.guid;
            w.uuid = v.uuid.into();
            w.pk = v.pk.into();
            w.info = serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default();
        }
    }

    /// The entry of `id`, from memory or else loaded from the database. `Ok(None)`: the database
    /// has no such id; `Err`: the lookup failed, which callers must not take for "no such id"
    /// (review C-22/U-1: `RegisterPk` would register it as new under another uuid).
    #[inline]
    pub(crate) async fn get(&self, id: &str) -> ResultType<Option<LockPeer>> {
        if let Some(p) = self.map.read().await.get(id).cloned() {
            return Ok(Some(p));
        }
        let Some(v) = self.db.get_peer(id).await? else {
            return Ok(None);
        };
        let peer = Peer {
            guid: v.guid,
            uuid: v.uuid.into(),
            pk: v.pk.into(),
            // user: v.user,
            info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
            // disabled: v.status == Some(0),
            ..Default::default()
        };
        // An entry added while the database was read (a registration in `io_loop`) is newer than
        // the row: keep it (review C-25).
        let peer = Arc::new(RwLock::new(peer));
        Ok(Some(
            self.map
                .write()
                .await
                .entry(id.to_owned())
                .or_insert(peer)
                .clone(),
        ))
    }

    /// An empty entry for `id`, which `get` just found in neither memory nor the database.
    #[inline]
    pub(crate) async fn insert_new(&self, id: &str) -> LockPeer {
        self.map
            .write()
            .await
            .entry(id.to_owned())
            .or_default()
            .clone()
    }

    #[cfg(test)]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        match self.get(id).await.unwrap() {
            Some(p) => p,
            None => self.insert_new(id).await,
        }
    }

    /// Drops the entries without a registration (`last_reg_time`) for `idle` or longer.
    /// Unregistered lookups (`get` of an offline peer, `insert_new` of a new id) leave entries
    /// too, so without this the map only grows (review A-1). Nothing is lost:
    /// - `guid`, `uuid`, `pk` and `info` (its IP) are in the database, and `get` loads them back
    ///   (a failed lookup is not "no such id": nothing is rebuilt from it);
    /// - `last_reg_time` comes back expired, which an idle peer is anyway (online needs it within
    ///   `REG_TIMEOUT`);
    /// - `socket_addr` only matters while online; `update_addr` compares `info.ip` instead when
    ///   the port is 0, as after a restart. It does not load: a peer back from eviction is asked
    ///   for `RegisterPk` again, which loads it;
    /// - `reg_pk` counts `RegisterPk`s within 6 seconds, long over by then.
    ///
    /// Callers holding a dropped entry's `Arc` keep a detached copy. Only the UDP path changes
    /// entries, and it runs serially with this; the TCP side's `get` may add one, never replace one.
    pub(crate) async fn evict_idle(&self, idle: std::time::Duration) {
        self.map.write().await.retain(|_, p| match p.try_read() {
            Ok(p) => p.last_reg_time.elapsed() < idle,
            // Locked for writing: being registered right now.
            Err(_) => true,
        });
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }
}
