//! Relay selection (PORTA.md §7): per-device fixed relay; level one, the geo cost
//! `(rtt(A,R) + rtt(B,R)) × weight(R)` over the reachable relays, round-robin fallback, the health check
//! and GeoIP loading/updating; level two, the relay measurements Porta devices report, replacing an
//! end's estimates.

mod cost;
mod geo;
mod measure;

use crate::config::{Config, GeoConfig, GeoSource, RelayConfig};
use cost::{Candidate, Carriers, Cost, Loc, Locate};
use hbb_common::{
    bail, config::RELAY_PORT, futures::future::join_all, log, socket_client::check_port, throttled_log, tokio,
    ResultType,
};
use measure::{Leg, Measurements};
use sqlx::SqlitePool;
use std::{
    fmt::Write as _,
    net::IpAddr,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

/// Health check period and per-relay connect timeout (resolution included), as upstream.
const HEALTH_INTERVAL: Duration = Duration::from_secs(3);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(3);
/// GeoIP update / mtime check period.
const GEO_INTERVAL: Duration = Duration::from_secs(24 * 3600);
/// Level two: only the first this many relays are sent to clients to measure.
pub const MAX_PROBED: usize = 32;
/// Level two: how often clients measure (Porta heartbeat `routing.probe_interval_secs`).
pub const PROBE_INTERVAL_SECS: u64 = 300;

/// Context of one relay choice (note 02 §3.5). IPs are canonical (`::ffff:a.b.c.d` → IPv4).
pub struct RouteQuery<'a> {
    /// Initiator (A).
    pub a_ip: IpAddr,
    /// Controlled side (B), its last UDP registration address.
    pub b_ip: IpAddr,
    /// A's own id as it claims (`PunchHoleRequest.porta_from_id`, not authenticated; empty when
    /// absent), for its level-two measurement.
    pub a_id: &'a str,
    /// B's id, for `device_policy.relay_pin` and its level-two measurement.
    pub b_id: &'a str,
    /// `PunchHoleRequest.token` (empty when A is not logged in).
    pub a_token: &'a str,
    pub conn_type: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RouteDecision {
    /// Sent to clients as is; empty keeps upstream's meaning (B falls back to "hbbs host:21117").
    pub relay: String,
    /// Logged and stored in `conn_attempt.route_reason`: "fixed" (device pin), "rtt" (both ends
    /// measured), "rtt_a" / "rtt_b" (only A / only B measured), "geo" (both ends located),
    /// "geo_a" / "geo_b" (only A / only B located), "rr" (round-robin), "none" (no relay configured).
    pub reason: &'static str,
    /// The chosen relay's two legs in ms, before the weight (measured or estimated as `reason`
    /// says); `None` for "fixed", "rr", "none" and for a leg without a value.
    pub a_ms: Option<f64>,
    pub b_ms: Option<f64>,
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
    /// Level two: version of the list sent to clients (`routing_rev` of `list`), so a round is
    /// matched with the list it measured.
    rev: i64,
}

impl Relays {
    fn new(list: Vec<RelayState>) -> Self {
        let rev = routing_rev(&list);
        Self { gen: 0, list, rev }
    }

    /// The list clients measure: the first `MAX_PROBED` hosts, verbatim.
    fn probed(&self) -> impl Iterator<Item = &str> {
        self.list.iter().take(MAX_PROBED).map(|s| s.cfg.host.as_str())
    }
}

/// sha256 of the probed hosts joined with `\n`, then `\n` and the probe interval (PORTA.md §7, as the
/// strategy `rev`): the same configuration gives the same rev across restarts. Warns when relays
/// beyond `MAX_PROBED` take no part in level two.
fn routing_rev(list: &[RelayState]) -> i64 {
    if list.len() > MAX_PROBED {
        log::warn!(
            "{} relays configured: only the first {MAX_PROBED} take part in routing level two (client measurements)",
            list.len()
        );
    }
    let hosts: Vec<&str> = list.iter().take(MAX_PROBED).map(|s| s.cfg.host.as_str()).collect();
    crate::strategy::digest_rev(format!("{}\n{PROBE_INTERVAL_SECS}", hosts.join("\n")).as_bytes())
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
    /// Level two: the devices' latest measurements.
    measured: Measurements,
}

/// A decision with what led to it, for the debug log and `tg`.
struct Explained {
    decision: RouteDecision,
    a: Loc,
    b: Loc,
    /// Whether A's / B's measurement replaced its estimates.
    use_a: bool,
    use_b: bool,
    rows: Vec<Row>,
}

/// One configured relay in an [`Explained`].
struct Row {
    host: String,
    reachable: bool,
    /// `None`: no part in the choice (no position or no basis, or down on a measured end).
    cost: Option<Cost>,
    /// What A's / B's usable measurement says of it.
    meas_a: Leg,
    meas_b: Leg,
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
            relays: RwLock::new(Relays::new(list)),
            geo: RwLock::new(None),
            rotation: AtomicUsize::new(0),
            geo_lock: tokio::sync::Mutex::new(()),
            measured: Measurements::default(),
        }
    }

    /// Level two: the current list `rev` and the hosts clients are to measure (the Porta heartbeat's
    /// `routing`).
    pub fn routing(&self) -> (i64, Vec<String>) {
        let relays = self.relays.read().unwrap();
        (relays.rev, relays.probed().map(str::to_owned).collect())
    }

    /// Level two: stores the `probes` of a signed heartbeat as `id`'s latest round (dropped unless it
    /// is for the current list; a bad shape drops it too, quietly).
    pub fn record_probes(&self, id: &str, probes: &serde_json::Value) {
        let relays = self.relays.read().unwrap();
        let hosts: Vec<&str> = relays.probed().collect();
        self.measured.record(id, probes, &hosts, relays.rev, Instant::now());
    }

    pub async fn select(&self, q: &RouteQuery<'_>) -> RouteDecision {
        if !q.b_id.is_empty() {
            match self.pinned(q.b_id).await {
                Ok(Some(relay)) => {
                    log::debug!("route b={} fixed relay {relay}", q.b_id);
                    return RouteDecision {
                        relay,
                        reason: "fixed",
                        a_ms: None,
                        b_ms: None,
                    };
                }
                Ok(None) => {}
                // Throttled: every punch request to an online peer gets here (PORTA.md §6 item 7).
                Err(e) => throttled_log!(
                    Duration::from_secs(60),
                    error,
                    "route: failed to read relay_pin of {:?}: {e}",
                    crate::peer::log_id(q.b_id)
                ),
            }
        }
        let x = self.decide(q.a_ip, q.b_ip, q.a_id, q.b_id);
        log::debug!(
            "route a={} [{}] b={} [{}] costs [{}] -> {:?} ({})",
            q.a_ip,
            describe(&x.a),
            q.b_ip,
            describe(&x.b),
            x.rows
                .iter()
                .map(|r| match (r.reachable, r.cost) {
                    (false, _) => format!("{}=down", r.host),
                    (true, Some(c)) => format!("{}={:.1}", r.host, c.cost),
                    (true, None) => format!("{}=-", r.host),
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

    /// `a_id`, `b_id`: whose level-two measurements to use (empty: none).
    fn decide(&self, a_ip: IpAddr, b_ip: IpAddr, a_id: &str, b_id: &str) -> Explained {
        let geo = self.geo_snapshot();
        let locate = geo.as_ref().map(|g| g.db.as_ref());
        let server = self.cfg.geo.server_location.as_ref();
        let a = cost::client_loc(a_ip, locate, &self.carriers, server);
        let b = cost::client_loc(b_ip, locate, &self.carriers, server);
        let relays = self.relays.read().unwrap();
        let (meas_a, meas_b) = self.measured.pair(a_id, b_id, relays.rev, Instant::now());
        // Indexed like the list; past the measured part (or without a measurement) unknown.
        let leg = |m: &Option<Vec<Leg>>, i: usize| m.as_ref().and_then(|m| m.get(i).copied()).unwrap_or(Leg::Unknown);
        let cands: Vec<(usize, &RelayState)> = relays.list.iter().enumerate().filter(|(_, s)| s.reachable).collect();
        let scored = cost::score(
            &self.cfg.routing,
            &a,
            &b,
            &cands
                .iter()
                .map(|(i, s)| Candidate {
                    loc: &s.loc,
                    weight: s.cfg.weight,
                    multi_bgp: s.cfg.multi_bgp,
                    meas_a: leg(&meas_a, *i),
                    meas_b: leg(&meas_b, *i),
                })
                .collect::<Vec<_>>(),
        );
        let picked = scored.as_ref().and_then(|s| {
            let i = cost::pick(&s.costs)?;
            Some((i, s.costs[i]?, s.reason))
        });
        let decision = if cands.is_empty() {
            RouteDecision {
                relay: String::new(),
                reason: "none",
                a_ms: None,
                b_ms: None,
            }
        } else if let Some((i, c, reason)) = picked {
            RouteDecision {
                relay: cands[i].1.cfg.host.clone(),
                reason,
                a_ms: c.a_ms,
                b_ms: c.b_ms,
            }
        } else {
            let i = self.rotation.fetch_add(1, Ordering::Relaxed) % cands.len();
            RouteDecision {
                relay: cands[i].1.cfg.host.clone(),
                reason: "rr",
                a_ms: None,
                b_ms: None,
            }
        };
        let (use_a, use_b) = scored.as_ref().map_or((false, false), |s| (s.use_a, s.use_b));
        let mut costs = scored.map(|s| s.costs).unwrap_or_default().into_iter();
        let rows = relays
            .list
            .iter()
            .enumerate()
            .map(|(i, s)| Row {
                host: s.cfg.host.clone(),
                reachable: s.reachable,
                cost: if s.reachable { costs.next().flatten() } else { None },
                meas_a: leg(&meas_a, i),
                meas_b: leg(&meas_b, i),
            })
            .collect();
        Explained {
            decision,
            a,
            b,
            use_a,
            use_b,
            rows,
        }
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
        relays.rev = routing_rev(&relays.list);
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
        let (n, fresh) = self.measured.counts(relays.rev, Instant::now());
        let _ = writeln!(out, "measurements: {n} devices, {fresh} fresh");
        out
    }

    /// Console `tg a b [idA idB]` / `porta-server route test`: the decision for A=`a`, B=`b`, with an
    /// explanation; with ids, also which legs are measured (empty id: none).
    pub async fn test(&self, a: IpAddr, b: IpAddr, a_id: &str, b_id: &str) -> String {
        let (a, b) = (a.to_canonical(), b.to_canonical());
        let x = self.decide(a, b, a_id, b_id);
        let mut out = format!(
            "A {a}: {}\nB {b}: {}\nrelay: {:?} ({})\n",
            describe(&x.a),
            describe(&x.b),
            x.decision.relay,
            x.decision.reason
        );
        // A leg as used: the measurement on a measured end, else the estimate.
        let leg = |used: bool, meas: Leg, ms: Option<f64>| match (used, meas) {
            (true, Leg::Rtt(ms)) => format!("rtt {ms}ms"),
            (true, _) => "down".to_owned(),
            (false, _) => ms.map_or("est ?".to_owned(), |ms| format!("est {ms:.1}ms")),
        };
        let with_ids = !a_id.is_empty() || !b_id.is_empty();
        for r in &x.rows {
            let mut what = match (r.reachable, r.cost) {
                (false, _) => "unreachable".to_owned(),
                (true, Some(c)) => format!("cost {:.1}", c.cost),
                (true, None) if (x.use_a && r.meas_a == Leg::Down) || (x.use_b && r.meas_b == Leg::Down) => {
                    "no cost (measured down)".to_owned()
                }
                (true, None) => "no cost (position unknown)".to_owned(),
            };
            if with_ids && r.reachable {
                let (a_ms, b_ms) = r.cost.map_or((None, None), |c| (c.a_ms, c.b_ms));
                let _ = write!(
                    what,
                    " [A {}, B {}]",
                    leg(x.use_a, r.meas_a, a_ms),
                    leg(x.use_b, r.meas_b, b_ms)
                );
            }
            let _ = writeln!(out, "  {}: {what}", r.host);
        }
        out
    }

    /// Background tasks (health check, GeoIP update), spawned on the server's runtime. Server only:
    /// removes leftover `*.part` files (of the downloads, or of the private copies of manual files;
    /// the operator's manual directory is never written to), loads the local GeoIP files and (dbip)
    /// removes the other months first.
    pub fn spawn_tasks(self: &Arc<Self>) {
        let dir = Path::new(&self.cfg.geo.dir);
        match self.cfg.geo.source {
            GeoSource::Dbip => geo::remove_parts(dir),
            GeoSource::Manual => geo::remove_parts(Path::new(geo::COPY_DIR)),
        }
        match geo::load(&self.cfg.geo) {
            Ok((db, info)) => {
                self.install(db, info.clone());
                if self.cfg.geo.source == GeoSource::Dbip {
                    // Ones a hot swap failed to delete, or `geo update` downloaded while we were down.
                    geo::remove_old_months(dir, &info);
                }
            }
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

/// `porta-server geo lookup <ip>`: reads the local mmdb files (the server's files, found the same
/// way; writes nothing) and describes country, coordinates, ASN and carrier group (built-in table
/// plus `[routing.carriers]`, as in route decisions).
pub fn geo_lookup(cfg: &Config, ip: IpAddr) -> ResultType<String> {
    match cfg.geo.source {
        // DB-IP files are only ever replaced by renaming, so mapping them directly is safe.
        GeoSource::Dbip => {
            let (db, info) = geo::load(&cfg.geo)?;
            Ok(describe_ip(cfg, &db, &info, ip))
        }
        // No private copy: the operator's files are read into memory.
        GeoSource::Manual => {
            let (db, info) = geo::load_in_memory(&cfg.geo)?;
            Ok(describe_ip(cfg, &db, &info, ip))
        }
    }
}

fn describe_ip<S: AsRef<[u8]> + Send + Sync>(
    cfg: &Config,
    db: &geo::GeoDb<S>,
    info: &geo::GeoInfo,
    ip: IpAddr,
) -> String {
    let ip = ip.to_canonical();
    let mut out = format!("database: {info}\n");
    let Some(rec) = db.locate(ip) else {
        let _ = writeln!(out, "{ip}: not in the database");
        return out;
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
    out
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
