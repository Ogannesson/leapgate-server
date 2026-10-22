//! Relay selection, level one (PORTA.md §7): per-device fixed relay, geo cost
//! `(rtt(A,R) + rtt(B,R)) × weight(R)` over the reachable relays, round-robin fallback, the health check
//! and GeoIP loading/updating.

mod cost;
mod geo;

use crate::config::{Config, GeoConfig, GeoSource, RelayConfig};
use cost::{Candidate, Carriers, Loc, Locate};
use hbb_common::{
    bail, config::RELAY_PORT, futures::future::join_all, log, socket_client::check_port, tokio, ResultType,
};
use sqlx::SqlitePool;
use std::{
    fmt::Write as _,
    net::IpAddr,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

/// Health check period and per-relay connect timeout (resolution included), as upstream.
const HEALTH_INTERVAL: Duration = Duration::from_secs(3);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(3);
/// GeoIP update / mtime check period.
const GEO_INTERVAL: Duration = Duration::from_secs(24 * 3600);

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
    /// Logged and stored in `conn_attempt.route_reason`: "fixed" (device pin), "geo" (both ends located),
    /// "geo_a" / "geo_b" (only A / only B located), "rr" (round-robin), "none" (no relay configured).
    pub reason: &'static str,
}

/// One configured relay and what the health check knows about it.
struct RelayState {
    cfg: RelayConfig,
    /// Candidate for selection (all are at load; an all-failed round keeps the previous set).
    reachable: bool,
    /// Last check: `Some(Some(rtt))` connected, `Some(None)` failed, `None` not checked yet.
    last: Option<Option<Duration>>,
    loc: Loc,
    /// `loc` is final until the next reload; otherwise each health round computes it again.
    loc_done: bool,
}

impl RelayState {
    /// The overridden fields apply at once; the database part waits for the next health round.
    fn new(cfg: RelayConfig, carriers: &Carriers) -> Self {
        Self {
            loc: cost::relay_loc(&cfg, None, carriers),
            loc_done: !cost::needs_lookup(&cfg),
            cfg,
            reachable: true,
            last: None,
        }
    }
}

struct Relays {
    /// Bumped by `rs` replacements and GeoIP swaps; a health round that started before is discarded.
    gen: u64,
    list: Vec<RelayState>,
}

/// The loaded GeoIP databases.
struct Loaded {
    db: Box<dyn Locate>,
    info: geo::GeoInfo,
}

pub struct Router {
    db: SqlitePool,
    cfg: Arc<Config>,
    carriers: Carriers,
    relays: RwLock<Relays>,
    geo: RwLock<Option<Arc<Loaded>>>,
    rotation: AtomicUsize,
    /// Serializes GeoIP updates (daily task and console `gu`), which share the `*.part` names.
    geo_lock: tokio::sync::Mutex<()>,
}

/// A decision with what led to it, for the debug log and `tg`.
struct Explained {
    decision: RouteDecision,
    a: Loc,
    b: Loc,
    /// Per configured relay: host, reachable, cost (`None`: no cost, i.e. no position or no basis).
    rows: Vec<(String, bool, Option<f64>)>,
}

impl Router {
    /// Starts with `cfg.relay` (the file's `[[relay]]`, or `-r`).
    pub fn new(db: SqlitePool, cfg: Arc<Config>) -> Self {
        let carriers = Carriers::new(&cfg.routing.carriers);
        let list = cfg.relay.iter().map(|r| RelayState::new(r.clone(), &carriers)).collect();
        Self {
            db,
            carriers,
            cfg,
            relays: RwLock::new(Relays { gen: 0, list }),
            geo: RwLock::new(None),
            rotation: AtomicUsize::new(0),
            geo_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn select(&self, q: &RouteQuery<'_>) -> RouteDecision {
        if !q.b_id.is_empty() {
            match self.pinned(q.b_id).await {
                Ok(Some(relay)) => {
                    log::debug!("route b={} fixed relay {relay}", q.b_id);
                    return RouteDecision { relay, reason: "fixed" };
                }
                Ok(None) => {}
                Err(e) => log::error!("route: failed to read relay_pin of {}: {e}", q.b_id),
            }
        }
        let x = self.decide(q.a_ip, q.b_ip);
        log::debug!(
            "route a={} [{}] b={} [{}] costs [{}] -> {:?} ({})",
            q.a_ip,
            describe(&x.a),
            q.b_ip,
            describe(&x.b),
            x.rows
                .iter()
                .map(|(host, reachable, cost)| match (reachable, cost) {
                    (false, _) => format!("{host}=down"),
                    (true, Some(c)) => format!("{host}={c:.1}"),
                    (true, None) => format!("{host}=-"),
                })
                .collect::<Vec<_>>()
                .join(" "),
            x.decision.relay,
            x.decision.reason
        );
        x.decision
    }

    /// `device_policy.relay_pin` of `b_id` (primary key lookup, not cached: `device pin-relay` applies
    /// to the next connection).
    async fn pinned(&self, b_id: &str) -> ResultType<Option<String>> {
        let pin: Option<String> = sqlx::query_scalar("select relay_pin from device_policy where device_id = ?")
            .bind(b_id)
            .fetch_optional(&self.db)
            .await?;
        Ok(pin.filter(|p| !p.is_empty()))
    }

    fn geo_snapshot(&self) -> Option<Arc<Loaded>> {
        self.geo.read().unwrap().clone()
    }

    fn decide(&self, a_ip: IpAddr, b_ip: IpAddr) -> Explained {
        let geo = self.geo_snapshot();
        let locate = geo.as_ref().map(|g| g.db.as_ref());
        let server = self.cfg.geo.server_location.as_ref();
        let a = cost::client_loc(a_ip, locate, &self.carriers, server);
        let b = cost::client_loc(b_ip, locate, &self.carriers, server);
        let relays = self.relays.read().unwrap();
        let cands: Vec<&RelayState> = relays.list.iter().filter(|s| s.reachable).collect();
        let scored = cost::score(
            &self.cfg.routing,
            &a,
            &b,
            &cands
                .iter()
                .map(|s| Candidate {
                    loc: &s.loc,
                    weight: s.cfg.weight,
                    multi_bgp: s.cfg.multi_bgp,
                })
                .collect::<Vec<_>>(),
        );
        let picked = scored
            .as_ref()
            .and_then(|(reason, costs)| Some((cost::pick(costs)?, *reason)));
        let decision = if cands.is_empty() {
            RouteDecision {
                relay: String::new(),
                reason: "none",
            }
        } else if let Some((i, reason)) = picked {
            RouteDecision {
                relay: cands[i].cfg.host.clone(),
                reason,
            }
        } else {
            let i = self.rotation.fetch_add(1, Ordering::Relaxed) % cands.len();
            RouteDecision {
                relay: cands[i].cfg.host.clone(),
                reason: "rr",
            }
        };
        let mut costs = scored.map(|(_, c)| c).unwrap_or_default().into_iter();
        let rows = relays
            .list
            .iter()
            .map(|s| {
                let cost = if s.reachable { costs.next().flatten() } else { None };
                (s.cfg.host.clone(), s.reachable, cost)
            })
            .collect();
        Explained { decision, a, b, rows }
    }

    /// Console `rs a,b,c` (hosts from `config::parse_relay_list`): replaces the list at run time;
    /// a host also in the file keeps its `[[relay]]` settings, others get weight 1. All are reachable
    /// until the next health round, which also locates them.
    pub fn set_configured(&self, hosts: Vec<String>) {
        let mut relays = self.relays.write().unwrap();
        relays.gen += 1;
        relays.list = hosts
            .into_iter()
            .map(|host| {
                self.cfg
                    .relay
                    .iter()
                    .find(|r| r.host == host)
                    .cloned()
                    .unwrap_or_else(|| RelayConfig::new(host))
            })
            .map(|r| RelayState::new(r, &self.carriers))
            .collect();
    }

    /// Console `rs` without arguments / `porta-server relay status`.
    pub fn status_text(&self) -> String {
        let mut out = match self.geo_snapshot() {
            Some(g) => format!("GeoIP: {}\n", g.info),
            None => "GeoIP: not loaded (round-robin)\n".to_owned(),
        };
        let relays = self.relays.read().unwrap();
        if relays.list.is_empty() {
            out.push_str("no relay configured\n");
        }
        for s in &relays.list {
            let last = match s.last {
                None => "pending".to_owned(),
                Some(None) => "failed".to_owned(),
                Some(Some(rtt)) => format!("{}ms", rtt.as_millis()),
            };
            let c = &s.cfg;
            let mut overrides = Vec::new();
            for (name, set) in [
                ("lat", c.lat.is_some()),
                ("lon", c.lon.is_some()),
                ("country", c.country.as_deref().is_some_and(|v| !v.is_empty())),
                ("carrier", c.carrier.as_deref().is_some_and(|v| !v.is_empty())),
            ] {
                if set {
                    overrides.push(name);
                }
            }
            let _ = writeln!(
                out,
                "{} weight={}{} reachable={} last={} location={}{}",
                c.host,
                c.weight,
                if c.multi_bgp { " multi_bgp" } else { "" },
                if s.reachable { "yes" } else { "no" },
                last,
                describe(&s.loc),
                if overrides.is_empty() {
                    String::new()
                } else {
                    format!(" (override: {})", overrides.join(","))
                }
            );
        }
        out
    }

    /// Console `tg a b` / `porta-server route test`: the decision for A=`a`, B=`b`, with an explanation.
    pub async fn test(&self, a: IpAddr, b: IpAddr) -> String {
        let (a, b) = (a.to_canonical(), b.to_canonical());
        let x = self.decide(a, b);
        let mut out = format!(
            "A {a}: {}\nB {b}: {}\nrelay: {:?} ({})\n",
            describe(&x.a),
            describe(&x.b),
            x.decision.relay,
            x.decision.reason
        );
        for (host, reachable, cost) in &x.rows {
            let what = match (reachable, cost) {
                (false, _) => "unreachable".to_owned(),
                (true, Some(c)) => format!("cost {c:.1}"),
                (true, None) => "no cost (position unknown)".to_owned(),
            };
            let _ = writeln!(out, "  {host}: {what}");
        }
        out
    }

    /// Background tasks (health check, GeoIP update), spawned on the server's runtime. Server only:
    /// removes leftover `*.part` files and loads the local GeoIP files first.
    pub fn spawn_tasks(self: &Arc<Self>) {
        geo::remove_parts(Path::new(&self.cfg.geo.dir));
        match geo::load(&self.cfg.geo) {
            Ok((db, info)) => self.install(db, info),
            Err(e) => log::warn!("GeoIP not loaded ({e}); relays are chosen round-robin until it is"),
        }
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(HEALTH_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                me.health_round().await;
            }
        });
        if self.cfg.geo.source == GeoSource::Dbip && !self.cfg.geo.auto_update {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                match me.geo_check(false).await {
                    Ok(msg) => log::info!("GeoIP: {msg}"),
                    Err(e) => log::warn!("GeoIP update failed, keeping the current files: {e}"),
                }
                tokio::time::sleep(GEO_INTERVAL).await;
            }
        });
    }

    /// Console `gu` (`porta-server geo update`): download/reload GeoIP now, hot-swap, report the result.
    pub async fn geo_update(&self) -> String {
        match self.geo_check(true).await {
            Ok(msg) => msg,
            Err(e) => format!("GeoIP update failed, keeping the current files: {e}"),
        }
    }

    /// dbip: the update check; manual: reload when a file's mtime changed (`force`: always).
    async fn geo_check(&self, force: bool) -> ResultType<String> {
        let _guard = self.geo_lock.lock().await;
        let cur = self.geo_snapshot();
        let gcfg = &self.cfg.geo;
        match gcfg.source {
            GeoSource::Dbip => {
                let dir = Path::new(&gcfg.dir);
                match geo::update_dbip(dir, cur.and_then(|g| g.info.months)).await? {
                    geo::Update::UpToDate => Ok("DB-IP files are up to date".to_owned()),
                    geo::Update::NotPublished(ym) => {
                        Ok(format!("DB-IP {ym} is not published yet; keeping the current files"))
                    }
                    geo::Update::Updated(db, info) => {
                        let msg = format!("loaded {info}");
                        self.install(db, info.clone());
                        geo::remove_old_months(dir, &info);
                        Ok(msg)
                    }
                }
            }
            GeoSource::Manual => {
                if !force && cur.is_some_and(|g| g.info.mtimes == geo::manual_mtimes(gcfg)) {
                    return Ok("files unchanged".to_owned());
                }
                let gcfg = gcfg.clone();
                let (db, info) = tokio::task::spawn_blocking(move || geo::load(&gcfg)).await??;
                let msg = format!("loaded {info}");
                self.install(db, info);
                Ok(msg)
            }
        }
    }

    /// Hot-swaps the databases; relay positions are computed again in the next health round.
    fn install(&self, db: geo::GeoDb, info: geo::GeoInfo) {
        self.set_geo(Box::new(db), info);
        if self.cfg.geo.source == GeoSource::Dbip {
            log::info!("IP Geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0");
        }
    }

    fn set_geo(&self, db: Box<dyn Locate>, info: geo::GeoInfo) {
        log::info!("GeoIP: using {info}");
        *self.geo.write().unwrap() = Some(Arc::new(Loaded { db, info }));
        let mut relays = self.relays.write().unwrap();
        relays.gen += 1;
        for s in &mut relays.list {
            s.loc_done = false;
        }
    }

    /// One health round: TCP connect to every relay (even a single one), record reachability and the
    /// connect time; an all-failed round keeps the previous reachable set. Also (re)computes the
    /// positions that are not final yet from the resolved address.
    async fn health_round(&self) {
        let (gen, jobs): (u64, Vec<(RelayConfig, bool)>) = {
            let r = self.relays.read().unwrap();
            (r.gen, r.list.iter().map(|s| (s.cfg.clone(), !s.loc_done)).collect())
        };
        if jobs.is_empty() {
            return;
        }
        let results = join_all(jobs.iter().map(|(cfg, _)| check_relay(&cfg.host))).await;
        let geo = self.geo_snapshot();
        let locate = geo.as_ref().map(|g| g.db.as_ref());
        let locs: Vec<Option<(Loc, bool)>> = jobs
            .iter()
            .zip(&results)
            .map(|((cfg, need), (ip, _))| need.then(|| self.relay_loc(cfg, *ip, locate)))
            .collect();
        let any_ok = results.iter().any(|(_, rtt)| rtt.is_some());
        let mut relays = self.relays.write().unwrap();
        if relays.gen != gen {
            return;
        }
        for (s, ((_, rtt), loc)) in relays.list.iter_mut().zip(results.into_iter().zip(locs)) {
            if any_ok {
                s.reachable = rtt.is_some();
            }
            s.last = Some(rtt);
            if let Some((loc, done)) = loc {
                s.loc = loc;
                s.loc_done = done;
            }
        }
    }

    /// A relay's position and whether it is final: overrides first, then the database for the
    /// resolved address. An unresolved host or a database miss is retried next round.
    fn relay_loc(&self, cfg: &RelayConfig, ip: Option<IpAddr>, geo: Option<&dyn Locate>) -> (Loc, bool) {
        if !cost::needs_lookup(cfg) {
            return (cost::relay_loc(cfg, None, &self.carriers), true);
        }
        let rec = ip.zip(geo).and_then(|(ip, geo)| geo.locate(ip));
        let found = rec.is_some();
        let loc = cost::relay_loc(cfg, rec, &self.carriers);
        let done = found && loc.pos.is_some();
        (loc, done)
    }
}

/// Resolves and connects to one relay (`host` or `host:port`, default port 21117) within the timeout.
/// Returns the resolved address and the connect time (`None` when it failed).
async fn check_relay(host: &str) -> (Option<IpAddr>, Option<Duration>) {
    let deadline = tokio::time::Instant::now() + HEALTH_TIMEOUT;
    let addr = match tokio::time::timeout_at(deadline, tokio::net::lookup_host(check_port(host, RELAY_PORT))).await {
        Ok(Ok(mut addrs)) => addrs.next(),
        _ => None,
    };
    let Some(addr) = addr else {
        return (None, None);
    };
    let started = tokio::time::Instant::now();
    let ok = matches!(
        tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    );
    (Some(addr.ip().to_canonical()), ok.then(|| started.elapsed()))
}

/// `CN/cn-telecom (39.90,116.41)`, `?` for unknown parts.
fn describe(l: &Loc) -> String {
    let pos = l.pos.map_or("?".to_owned(), |(lat, lon)| format!("{lat:.2},{lon:.2}"));
    format!(
        "{}/{} ({pos})",
        l.country.as_deref().unwrap_or("?"),
        l.carrier.as_deref().unwrap_or("?")
    )
}

/// `porta-server geo lookup <ip>`: reads the local mmdb files (same loader as the server) and
/// describes country, coordinates, ASN and carrier group (built-in table plus `[routing.carriers]`,
/// as in route decisions).
pub fn geo_lookup(cfg: &Config, ip: IpAddr) -> ResultType<String> {
    let ip = ip.to_canonical();
    let (db, info) = geo::load(&cfg.geo)?;
    let mut out = format!("database: {info}\n");
    let Some(rec) = db.locate(ip) else {
        let _ = writeln!(out, "{ip}: not in the database");
        return Ok(out);
    };
    let pos = rec.lat.zip(rec.lon).map_or("?".to_owned(), |(lat, lon)| format!("{lat},{lon}"));
    let _ = writeln!(out, "{ip}: country {} position {pos}", rec.country.as_deref().unwrap_or("?"));
    match rec.asn {
        Some(asn) => {
            let group = Carriers::new(&cfg.routing.carriers).group(asn);
            let org = db.asn_org(ip).unwrap_or_default();
            let _ = writeln!(out, "AS{asn} {org}, carrier group {group}");
        }
        None => out.push_str("ASN unknown\n"),
    }
    Ok(out)
}

/// `porta-server geo update` when the console is unreachable (server not running): download in the
/// command line process, without directory cleanup.
pub async fn geo_download(cfg: &GeoConfig) -> ResultType<String> {
    if cfg.source == GeoSource::Manual {
        bail!("geo.source is \"manual\": nothing to download, update the files yourself (e.g. geoipupdate)");
    }
    let have = geo::load(cfg).ok().and_then(|(_, info)| info.months);
    Ok(match geo::update_dbip(Path::new(&cfg.dir), have).await? {
        geo::Update::UpToDate => "DB-IP files are up to date".to_owned(),
        geo::Update::NotPublished(ym) => format!("DB-IP {ym} is not published yet; keeping the current files"),
        geo::Update::Updated(_, info) => format!("downloaded {info}"),
    })
}

#[cfg(test)]
mod tests;
