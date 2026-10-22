//! Relay selection, level one (PORTA.md §7).
//!
//! Skeleton: round-robin over the configured list, no health check. The routing module replaces the
//! internals (geo cost, `device_policy.relay_pin`, health check, GeoIP loading) behind these signatures.

use crate::config::{Config, GeoConfig, RelayConfig};
use hbb_common::ResultType;
use sqlx::SqlitePool;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

/// Context of one relay choice (note 02 §3.5). IPs are canonical (`::ffff:a.b.c.d` → IPv4).
pub struct RouteQuery<'a> {
    /// Initiator (A).
    pub a_ip: IpAddr,
    /// Controlled side (B), its last UDP registration address.
    pub b_ip: IpAddr,
    /// B's id, for `device_policy.relay_pin`.
    pub b_id: &'a str,
    /// `PunchHoleRequest.token` (empty when A is not logged in).
    pub a_token: &'a str,
    pub conn_type: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RouteDecision {
    /// Sent to clients as is; empty keeps upstream's meaning (B falls back to "hbbs host:21117").
    pub relay: String,
    /// Logged and stored in `conn_attempt.route_reason`: "geo" | "fixed" | "rr" | "none" ...
    pub reason: &'static str,
}

pub struct Router {
    #[allow(dead_code)]
    db: SqlitePool,
    cfg: Arc<Config>,
    relays: RwLock<Vec<RelayConfig>>,
    rotation: AtomicUsize,
}

impl Router {
    /// Starts with `cfg.relay` (the file's `[[relay]]`, or `-r`).
    pub fn new(db: SqlitePool, cfg: Arc<Config>) -> Self {
        let relays = cfg.relay.clone();
        Self {
            db,
            cfg,
            relays: RwLock::new(relays),
            rotation: AtomicUsize::new(0),
        }
    }

    pub async fn select(&self, _q: &RouteQuery<'_>) -> RouteDecision {
        let relays = self.relays.read().unwrap();
        if relays.is_empty() {
            return RouteDecision {
                relay: String::new(),
                reason: "none",
            };
        }
        let i = self.rotation.fetch_add(1, Ordering::Relaxed) % relays.len();
        RouteDecision {
            relay: relays[i].host.clone(),
            reason: "rr",
        }
    }

    /// Console `rs a,b,c` (hosts from `config::parse_relay_list`): replaces the list at run time;
    /// a host also in the file keeps its `[[relay]]` settings, others get weight 1.
    pub fn set_configured(&self, hosts: Vec<String>) {
        let mut relays = self.relays.write().unwrap();
        *relays = hosts
            .into_iter()
            .map(|host| {
                self.cfg
                    .relay
                    .iter()
                    .find(|r| r.host == host)
                    .cloned()
                    .unwrap_or_else(|| RelayConfig::new(host))
            })
            .collect();
    }

    /// Console `rs` without arguments / `porta-server relay status`.
    pub fn status_text(&self) -> String {
        let relays = self.relays.read().unwrap();
        relays
            .iter()
            .map(|r| format!("{} weight={}\n", r.host, r.weight))
            .collect()
    }

    /// Console `tg a b` / `porta-server route test`: the decision for A=`a`, B=`b`, with an explanation.
    pub async fn test(&self, a: IpAddr, b: IpAddr) -> String {
        let d = self
            .select(&RouteQuery {
                a_ip: a,
                b_ip: b,
                b_id: "",
                a_token: "",
                conn_type: 0,
            })
            .await;
        format!("{:?} ({})", d.relay, d.reason)
    }

    /// Background tasks (health check, GeoIP update), spawned on the server's runtime.
    pub fn spawn_tasks(self: &Arc<Self>) {}

    /// Console `gu` (`porta-server geo update`): download/reload GeoIP now, hot-swap, report the result.
    pub async fn geo_update(&self) -> String {
        todo!()
    }
}

/// `porta-server geo lookup <ip>`: reads the local mmdb files (same loader as the server) and
/// describes country, coordinates, ASN and carrier group.
pub fn geo_lookup(_cfg: &GeoConfig, _ip: IpAddr) -> ResultType<String> {
    todo!()
}

/// `porta-server geo update` when the console is unreachable (server not running): download in the
/// command line process, without directory cleanup.
pub async fn geo_download(_cfg: &GeoConfig) -> ResultType<String> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    fn q() -> RouteQuery<'static> {
        RouteQuery {
            a_ip: "1.1.1.1".parse().unwrap(),
            b_ip: "2.2.2.2".parse().unwrap(),
            b_id: "b",
            a_token: "",
            conn_type: 0,
        }
    }

    #[tokio::test]
    async fn empty_list_gives_empty_relay() {
        let (_dir, db) = crate::testutil::pool().await;
        let r = Router::new(db, Arc::new(Config::default()));
        assert_eq!(r.select(&q()).await.relay, "");
    }

    #[tokio::test]
    async fn round_robin_and_replace() {
        let (_dir, db) = crate::testutil::pool().await;
        let mut cfg = Config::default();
        cfg.relay = vec![RelayConfig::new("a".into()), RelayConfig::new("b".into())];
        let r = Router::new(db, Arc::new(cfg));
        let picks = [r.select(&q()).await.relay, r.select(&q()).await.relay];
        assert!(picks.contains(&"a".to_owned()) && picks.contains(&"b".to_owned()));
        r.set_configured(vec!["c".into()]);
        assert_eq!(r.select(&q()).await.relay, "c");
        assert_eq!(r.status_text(), "c weight=1\n");
    }
}
