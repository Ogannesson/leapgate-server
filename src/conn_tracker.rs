//! Connection outcome tracking (PORTA.md §8, note 02 §4.4).
//!
//! The rendezvous hooks H1~H5 call the `on_*` methods; they only touch memory (a std mutex never held
//! across an await). A sweeper finalizes due attempts every 5 seconds and hands them to a separate
//! writer task, which resolves `token` → `a_user`/`a_device_id` and inserts into `conn_attempt`.
//! All times are unix ms.

use hbb_common::{
    log,
    tokio::{self, sync::mpsc},
    try_into_v4, ResultType,
};
use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

/// Requests for the same (A IP, B id) within this long of the group's first request are one attempt
/// (`fallback_fut`'s parallel connection, io_loop reconnects). 待实测.
const PAIR_MERGE_MS: i64 = 2_000;
/// No reply this long after the last request → `no_reply`. 待实测.
const NO_REPLY_MS: i64 = 20_000;
/// Direct window W = max(45 s, 6 × (reply_at − started_at) + 20 s): A's direct timeout is the punch
/// time × 6 with no cap (client `connect_timeout`). The client's punch time also counts connecting to
/// hbbs and the KeyExchange, which hbbs never sees; the margin covers up to about 3 s of that. 待实测.
const DIRECT_MIN_MS: i64 = 45_000;
const DIRECT_PUNCH_FACTOR: i64 = 6;
const DIRECT_MARGIN_MS: i64 = 20_000;
/// An attempt with `RequestRelay`s is finalized this long after the last one (A waits up to 18 s for
/// each `RelayResponse`). 待实测.
const RELAY_SETTLE_MS: i64 = 20_000;
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// `conn_attempt.signal`: what hbbs did with a `PunchHoleRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    PunchHole,
    FetchLocalAddr,
    FailOffline,
    FailIdNotExist,
    FailLicense,
}

impl Signal {
    fn as_str(self) -> &'static str {
        match self {
            Signal::PunchHole => "punch_hole",
            Signal::FetchLocalAddr => "fetch_local_addr",
            Signal::FailOffline => "fail_offline",
            Signal::FailIdNotExist => "fail_id_not_exist",
            Signal::FailLicense => "fail_license",
        }
    }

    fn is_fail(self) -> bool {
        matches!(
            self,
            Signal::FailOffline | Signal::FailIdNotExist | Signal::FailLicense
        )
    }
}

/// H1 `handle_punch_hole_request`: one per request (failure branches and the success branch).
/// Fields are taken before `ph` is moved; addresses already `try_into_v4`.
#[derive(Debug, Clone)]
pub struct PunchRequest {
    /// A:p1 (port 0 over WebSocket with X-Real-IP).
    pub a_addr: SocketAddr,
    pub ws: bool,
    /// `ph.token`, resolved to `a_user`/`a_device_id` via `auth::token_owner` off the hot path.
    pub token: String,
    pub a_version: String,
    /// `ph.id`.
    pub b_id: String,
    /// B's registered `socket_addr`; `None` when B is unknown (failure branches).
    pub b_addr: Option<SocketAddr>,
    pub conn_type: i32,
    pub nat_type: i32,
    pub force_relay: bool,
    /// `ph.socket_addr_v6` non-empty.
    pub has_v6: bool,
    pub udp_port: i32,
    pub signal: Signal,
    /// `ALWAYS_USE_RELAY` or mask xor.
    pub server_forced_relay: bool,
    /// `relay_server` put into `PunchHole`/`FetchLocalAddr` (empty on failure).
    pub relay_offered: String,
    /// `RouteDecision::reason` (empty on failure).
    pub route_reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// H2 `handle_hole_sent`.
    PunchHoleSent,
    /// H3 `handle_local_addr`.
    LocalAddr,
}

/// H2/H3: B answered a punch request over a fresh TCP connection.
#[derive(Debug, Clone)]
pub struct Reply {
    /// A:p1 as carried back in the message's `socket_addr`.
    pub a_addr: SocketAddr,
    pub kind: ReplyKind,
    pub b_id: String,
    /// B's `relay_server`; differs from `relay_offered` when B has a relay hard-coded locally.
    pub b_relay: String,
    pub b_nat_type: i32,
    pub b_version: String,
    pub b_has_v6: bool,
}

/// H4 `handle_tcp` `RelayResponse` branch, before `relay_server` is rewritten.
/// Non-empty `uuid` (or `b_id`) = branch X keyed by A:p1; otherwise the fallback answer keyed by A:p3.
#[derive(Debug, Clone)]
pub struct RelayResponseInfo {
    pub a_addr: SocketAddr,
    pub uuid: String,
    pub b_id: String,
    pub b_relay: String,
    pub b_version: String,
    pub b_has_v6: bool,
}

/// H5 `handle_tcp` `RequestRelay` branch: A falls back to a relay over a new connection (A:p3).
#[derive(Debug, Clone)]
pub struct RelayRequest {
    pub a_addr: SocketAddr,
    /// Came in over WebSocket (`conn_attempt.via` of a `relay_only` row).
    pub ws: bool,
    pub b_id: String,
    pub uuid: String,
    pub relay_server: String,
    pub token: String,
    /// B was in memory, so the request was forwarded.
    pub found_in_memory: bool,
}

/// Relay fallback statistics over a time range (for `porta-server stats`).
#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// Count per `conn_attempt.outcome`.
    pub outcomes: Vec<(String, i64)>,
    /// (`relay` + `relay_or_v6`) / (`relay*` + `direct*`); `None` when the denominator is 0.
    pub relay_rate: Option<f64>,
    /// Attempts where `b_relay ≠ relay_offered` (B has a relay hard-coded locally).
    pub b_relay_mismatch: i64,
}

/// `conn_attempt.reply`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    PunchHoleSent,
    LocalAddr,
    /// Branch X: B answered the punch request with a relay.
    RelayResponse,
}

impl Answer {
    fn as_str(self) -> &'static str {
        match self {
            Answer::PunchHoleSent => "punch_hole_sent",
            Answer::LocalAddr => "local_addr",
            Answer::RelayResponse => "relay_response",
        }
    }
}

/// One connection attempt in memory, later one `conn_attempt` row.
#[derive(Debug, Clone)]
struct Attempt {
    started_at: i64,
    last_req_at: i64,
    /// First A:p1 (A:p3 for `relay_only`).
    a_addr: SocketAddr,
    ws: bool,
    token: String,
    b_id: String,
    /// The punch request whose hbbs decision A acts on; `None` for `relay_only`.
    req: Option<PunchRequest>,
    attempts: i64,
    reply: Option<(Answer, i64)>,
    b_version: Option<String>,
    b_nat_type: Option<i32>,
    b_has_v6: Option<bool>,
    b_relay: Option<String>,
    relay_uuid: Option<String>,
    relay_req_at: Option<i64>,
    last_relay_req_at: i64,
    relay_req_count: i64,
    relay_resp_at: Option<i64>,
    /// Map keys pointing here, removed on finalization.
    punch_keys: Vec<SocketAddr>,
    relay_keys: Vec<SocketAddr>,
}

impl Attempt {
    fn failed(&self) -> bool {
        self.req.as_ref().is_some_and(|r| r.signal.is_fail())
    }

    fn relay_only(&self) -> bool {
        self.req.is_none()
    }

    fn both_v6(&self) -> bool {
        self.req.as_ref().is_some_and(|r| r.has_v6) && self.b_has_v6 == Some(true)
    }

    /// W, for an attempt answered at `reply_at`.
    fn direct_window(&self, reply_at: i64) -> i64 {
        DIRECT_MIN_MS.max(DIRECT_PUNCH_FACTOR * (reply_at - self.started_at) + DIRECT_MARGIN_MS)
    }

    /// Whether a `RequestRelay` at `now` belongs to this attempt (same (A IP, B id) already checked).
    fn takes_relay_request(&self, now: i64) -> bool {
        if self.relay_req_count > 0 {
            // A retrying the fallback (or a `relay_only` row); still in memory = within RELAY_SETTLE_MS.
            return true;
        }
        match self.reply {
            Some((Answer::PunchHoleSent | Answer::LocalAddr, at)) => now <= at + self.direct_window(at),
            _ => false,
        }
    }

    fn deadline(&self) -> i64 {
        let due = if self.relay_req_count > 0 {
            self.last_relay_req_at + RELAY_SETTLE_MS
        } else {
            match self.reply {
                Some((Answer::RelayResponse, at)) => at,
                Some((_, at)) => at + self.direct_window(at),
                None if self.failed() => self.last_req_at,
                None => self.last_req_at + NO_REPLY_MS,
            }
        };
        // Leave room for a parallel request to merge in.
        due.max(self.started_at + PAIR_MERGE_MS)
    }

    fn outcome(&self) -> &'static str {
        if self.failed() {
            return "rejected";
        }
        if self.relay_req_count > 0 {
            return match (self.relay_resp_at, self.relay_only()) {
                (Some(_), false) => "relay",
                (Some(_), true) => "relay_unmatched",
                (None, _) => "relay_failed",
            };
        }
        match self.reply {
            None => "no_reply",
            Some((Answer::RelayResponse, _)) if self.both_v6() => "relay_or_v6",
            Some((Answer::RelayResponse, _)) => "relay",
            Some((Answer::LocalAddr, _)) => "direct_lan",
            Some((Answer::PunchHoleSent, _)) if self.both_v6() => "direct_tcp_or_v6",
            Some((Answer::PunchHoleSent, _)) => "direct_tcp",
        }
    }
}

#[derive(Debug)]
struct Finalized {
    attempt: Attempt,
    outcome: &'static str,
    finalized_at: i64,
}

#[derive(Default)]
struct TrackerState {
    next_id: u64,
    /// try_into_v4(A:p1) → attempt.
    by_punch_addr: HashMap<SocketAddr, u64>,
    /// (A public IP, B id) → attempts in memory.
    by_pair: HashMap<(IpAddr, String), Vec<u64>>,
    /// try_into_v4(A:p3) → attempt.
    by_relay_addr: HashMap<SocketAddr, u64>,
    attempts: HashMap<u64, Attempt>,
}

impl TrackerState {
    fn add(&mut self, attempt: Attempt) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.by_pair
            .entry((attempt.a_addr.ip(), attempt.b_id.clone()))
            .or_default()
            .push(id);
        for k in &attempt.punch_keys {
            self.by_punch_addr.insert(*k, id);
        }
        for k in &attempt.relay_keys {
            self.by_relay_addr.insert(*k, id);
        }
        self.attempts.insert(id, attempt);
        id
    }

    fn punch_request(&mut self, req: PunchRequest, now: i64) {
        let key = try_into_v4(req.a_addr);
        let pair = (key.ip(), req.b_id.clone());
        // Retry on the same connection: A only resends while it has no answer.
        let same_conn = self.by_punch_addr.get(&key).copied().filter(|id| {
            self.attempts
                .get(id)
                .is_some_and(|a| a.b_id == req.b_id && a.reply.is_none() && !a.failed())
        });
        let merged = same_conn.or_else(|| {
            self.by_pair.get(&pair)?.iter().copied().find(|id| {
                self.attempts
                    .get(id)
                    .is_some_and(|a| !a.relay_only() && now - a.started_at <= PAIR_MERGE_MS)
            })
        });
        if let Some(id) = merged {
            self.by_punch_addr.insert(key, id);
            if let Some(a) = self.attempts.get_mut(&id) {
                a.attempts += 1;
                a.last_req_at = now;
                // Until B answers, the latest successful hbbs decision is the one A acts on.
                if a.reply.is_none() && (!req.signal.is_fail() || a.failed()) {
                    a.req = Some(req);
                }
                if !a.punch_keys.contains(&key) {
                    a.punch_keys.push(key);
                }
            }
            return;
        }
        self.add(Attempt {
            started_at: now,
            last_req_at: now,
            a_addr: key,
            ws: req.ws,
            token: req.token.clone(),
            b_id: req.b_id.clone(),
            req: Some(req),
            attempts: 1,
            reply: None,
            b_version: None,
            b_nat_type: None,
            b_has_v6: None,
            b_relay: None,
            relay_uuid: None,
            relay_req_at: None,
            last_relay_req_at: 0,
            relay_req_count: 0,
            relay_resp_at: None,
            punch_keys: vec![key],
            relay_keys: vec![],
        });
    }

    fn punch_attempt(&mut self, a_addr: SocketAddr) -> Option<&mut Attempt> {
        let id = self.by_punch_addr.get(&try_into_v4(a_addr))?;
        self.attempts.get_mut(id)
    }

    fn reply(&mut self, r: Reply, now: i64) {
        let Some(a) = self.punch_attempt(r.a_addr) else {
            return;
        };
        // A second answer (to a merged parallel request) changes nothing.
        if a.reply.is_some() || a.b_id != r.b_id {
            return;
        }
        let kind = match r.kind {
            ReplyKind::PunchHoleSent => Answer::PunchHoleSent,
            ReplyKind::LocalAddr => Answer::LocalAddr,
        };
        a.reply = Some((kind, now));
        a.b_relay = Some(r.b_relay);
        a.b_nat_type = Some(r.b_nat_type);
        a.b_version = Some(r.b_version);
        a.b_has_v6 = Some(r.b_has_v6);
    }

    fn relay_response(&mut self, r: RelayResponseInfo, now: i64) {
        if r.uuid.is_empty() && r.b_id.is_empty() {
            // Fallback: B answers A's `RequestRelay`.
            let key = try_into_v4(r.a_addr);
            if let Some(a) = self
                .by_relay_addr
                .get(&key)
                .and_then(|id| self.attempts.get_mut(id))
            {
                a.relay_resp_at.get_or_insert(now);
            }
            return;
        }
        let Some(a) = self.punch_attempt(r.a_addr) else {
            return;
        };
        if a.reply.is_some() {
            return;
        }
        a.reply = Some((Answer::RelayResponse, now));
        a.b_relay = Some(r.b_relay);
        a.b_version = Some(r.b_version);
        a.b_has_v6 = Some(r.b_has_v6);
        a.relay_uuid = Some(r.uuid);
    }

    fn request_relay(&mut self, r: RelayRequest, now: i64) {
        let key = try_into_v4(r.a_addr);
        let pair = (key.ip(), r.b_id.clone());
        let matched = self.by_pair.get(&pair).and_then(|ids| {
            ids.iter()
                .filter_map(|id| Some((*id, self.attempts.get(id)?)))
                .filter(|(_, a)| a.takes_relay_request(now))
                .max_by_key(|(_, a)| {
                    (a.b_relay.as_deref() == Some(r.relay_server.as_str()), a.started_at)
                })
                .map(|(id, _)| id)
        });
        log::debug!(
            "RequestRelay {} → {} (in memory: {}), matched: {}",
            key,
            r.b_id,
            r.found_in_memory,
            matched.is_some()
        );
        if let Some(id) = matched {
            if let Some(a) = self.attempts.get_mut(&id) {
                a.relay_req_count += 1;
                a.last_relay_req_at = now;
                a.relay_req_at.get_or_insert(now);
                if a.relay_uuid.is_none() {
                    a.relay_uuid = Some(r.uuid);
                }
                if !a.relay_keys.contains(&key) {
                    a.relay_keys.push(key);
                }
            }
            self.by_relay_addr.insert(key, id);
            return;
        }
        self.add(Attempt {
            started_at: now,
            last_req_at: now,
            a_addr: key,
            ws: r.ws,
            token: r.token,
            b_id: r.b_id,
            req: None,
            attempts: 1,
            reply: None,
            b_version: None,
            b_nat_type: None,
            b_has_v6: None,
            b_relay: None,
            relay_uuid: Some(r.uuid),
            relay_req_at: Some(now),
            last_relay_req_at: now,
            relay_req_count: 1,
            relay_resp_at: None,
            punch_keys: vec![],
            relay_keys: vec![key],
        });
    }

    /// Removes and returns the attempts due at `now`.
    fn sweep(&mut self, now: i64) -> Vec<Finalized> {
        let due: Vec<u64> = self
            .attempts
            .iter()
            .filter(|(_, a)| now >= a.deadline())
            .map(|(id, _)| *id)
            .collect();
        due.into_iter()
            .filter_map(|id| self.remove(id))
            .map(|attempt| Finalized {
                outcome: attempt.outcome(),
                finalized_at: now,
                attempt,
            })
            .collect()
    }

    fn remove(&mut self, id: u64) -> Option<Attempt> {
        let a = self.attempts.remove(&id)?;
        for k in &a.punch_keys {
            if self.by_punch_addr.get(k) == Some(&id) {
                self.by_punch_addr.remove(k);
            }
        }
        for k in &a.relay_keys {
            if self.by_relay_addr.get(k) == Some(&id) {
                self.by_relay_addr.remove(k);
            }
        }
        let pair = (a.a_addr.ip(), a.b_id.clone());
        if let Some(ids) = self.by_pair.get_mut(&pair) {
            ids.retain(|x| *x != id);
            if ids.is_empty() {
                self.by_pair.remove(&pair);
            }
        }
        Some(a)
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|x| x.as_millis() as i64)
        .unwrap_or_default()
}

/// Inserts one finalized attempt, resolving its token first.
async fn write(db: &SqlitePool, f: &Finalized) -> ResultType<()> {
    let a = &f.attempt;
    let (a_user, a_device_id) = match crate::auth::token_owner(db, &a.token).await {
        Some((_, name, device_id)) => (Some(name), Some(device_id)),
        None => (None, None),
    };
    let req = a.req.as_ref();
    sqlx::query(
        "insert into conn_attempt(started_at, a_ip, a_port, via, a_user, a_device_id, a_version, b_id,
           b_ip, conn_type, a_nat_type, a_force_relay, a_has_v6, a_udp_port, attempts, signal,
           server_forced_relay, relay_offered, route_reason, reply, reply_at, b_version, b_nat_type,
           b_has_v6, b_relay, relay_uuid, relay_req_at, relay_req_count, relay_resp_at, outcome,
           finalized_at)
         values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(a.started_at)
    .bind(a.a_addr.ip().to_string())
    .bind(i64::from(a.a_addr.port()))
    .bind(if a.ws { "ws" } else { "tcp" })
    .bind(a_user)
    .bind(a_device_id)
    .bind(req.map(|r| r.a_version.as_str()))
    .bind(&a.b_id)
    .bind(req.and_then(|r| r.b_addr).map(|x| try_into_v4(x).ip().to_string()))
    .bind(req.map_or(0, |r| r.conn_type))
    .bind(req.map_or(0, |r| r.nat_type))
    .bind(req.is_some_and(|r| r.force_relay))
    .bind(req.is_some_and(|r| r.has_v6))
    .bind(req.map_or(0, |r| r.udp_port))
    .bind(a.attempts)
    .bind(req.map_or("relay_only", |r| r.signal.as_str()))
    .bind(req.is_some_and(|r| r.server_forced_relay))
    .bind(req.map(|r| r.relay_offered.as_str()))
    .bind(req.map(|r| r.route_reason))
    .bind(a.reply.map(|(kind, _)| kind.as_str()))
    .bind(a.reply.map(|(_, at)| at))
    .bind(a.b_version.as_deref())
    .bind(a.b_nat_type)
    .bind(a.b_has_v6)
    .bind(a.b_relay.as_deref())
    .bind(a.relay_uuid.as_deref())
    .bind(a.relay_req_at)
    .bind(a.relay_req_count)
    .bind(a.relay_resp_at)
    .bind(f.outcome)
    .bind(f.finalized_at)
    .execute(db)
    .await?;
    Ok(())
}

pub struct ConnTracker {
    db: SqlitePool,
    state: Mutex<TrackerState>,
}

impl ConnTracker {
    pub fn new(db: SqlitePool) -> Self {
        Self {
            db,
            state: Mutex::default(),
        }
    }

    /// H1.
    pub fn on_punch_request(&self, req: PunchRequest) {
        self.state.lock().unwrap().punch_request(req, now_ms());
    }

    /// H2, H3.
    pub fn on_reply(&self, reply: Reply) {
        self.state.lock().unwrap().reply(reply, now_ms());
    }

    /// H4.
    pub fn on_relay_response(&self, resp: RelayResponseInfo) {
        self.state.lock().unwrap().relay_response(resp, now_ms());
    }

    /// H5.
    pub fn on_request_relay(&self, req: RelayRequest) {
        self.state.lock().unwrap().request_relay(req, now_ms());
    }

    /// The 5-second finalizer and the database writer, spawned on the server's runtime.
    pub fn spawn_tasks(self: &Arc<Self>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<Finalized>();
        let this = self.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                timer.tick().await;
                let done = this.state.lock().unwrap().sweep(now_ms());
                for f in done {
                    tx.send(f).ok();
                }
            }
        });
        let db = self.db.clone();
        tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                if let Err(e) = write(&db, &f).await {
                    log::error!("conn_attempt insert: {e}");
                }
            }
        });
    }

    /// Statistics of attempts started in `[since_ms, until_ms)` (unix ms). Reads the database only.
    pub async fn stats(db: &SqlitePool, since_ms: i64, until_ms: i64) -> ResultType<Stats> {
        let outcomes: Vec<(String, i64)> = sqlx::query_as(
            "select outcome, count(*) from conn_attempt where started_at >= ? and started_at < ?
             group by outcome order by outcome",
        )
        .bind(since_ms)
        .bind(until_ms)
        .fetch_all(db)
        .await?;
        let count = |names: &[&str]| -> i64 {
            outcomes
                .iter()
                .filter(|(o, _)| names.contains(&o.as_str()))
                .map(|(_, n)| n)
                .sum()
        };
        let relayed = count(&["relay", "relay_or_v6"]);
        let total = relayed + count(&["direct_lan", "direct_tcp", "direct_tcp_or_v6"]);
        let b_relay_mismatch: i64 = sqlx::query_scalar(
            "select count(*) from conn_attempt where started_at >= ? and started_at < ?
             and relay_offered <> '' and b_relay <> '' and relay_offered <> b_relay",
        )
        .bind(since_ms)
        .bind(until_ms)
        .fetch_one(db)
        .await?;
        Ok(Stats {
            relay_rate: (total > 0).then(|| relayed as f64 / total as f64),
            outcomes,
            b_relay_mismatch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_700_000_000_000;

    fn a1() -> SocketAddr {
        "1.2.3.4:40001".parse().unwrap()
    }

    fn punch(a_addr: SocketAddr, signal: Signal) -> PunchRequest {
        PunchRequest {
            a_addr,
            ws: false,
            token: String::new(),
            a_version: "1.4.2".to_owned(),
            b_id: "123456789".to_owned(),
            b_addr: Some("5.6.7.8:21000".parse().unwrap()),
            conn_type: 0,
            nat_type: 1,
            force_relay: false,
            has_v6: false,
            udp_port: 0,
            signal,
            server_forced_relay: false,
            relay_offered: if signal.is_fail() { String::new() } else { "r1:21117".to_owned() },
            route_reason: if signal.is_fail() { "" } else { "geo" },
        }
    }

    fn reply(a_addr: SocketAddr, kind: ReplyKind) -> Reply {
        Reply {
            a_addr,
            kind,
            b_id: "123456789".to_owned(),
            b_relay: "r1:21117".to_owned(),
            b_nat_type: 1,
            b_version: "1.4.3".to_owned(),
            b_has_v6: false,
        }
    }

    fn branch_x(a_addr: SocketAddr, b_has_v6: bool) -> RelayResponseInfo {
        RelayResponseInfo {
            a_addr,
            uuid: "uuid-x".to_owned(),
            b_id: "123456789".to_owned(),
            b_relay: "r1:21117".to_owned(),
            b_version: "1.4.3".to_owned(),
            b_has_v6,
        }
    }

    fn fallback_resp(a_addr: SocketAddr) -> RelayResponseInfo {
        RelayResponseInfo {
            a_addr,
            uuid: String::new(),
            b_id: String::new(),
            b_relay: String::new(),
            b_version: "1.4.3".to_owned(),
            b_has_v6: false,
        }
    }

    fn relay_req(a_addr: SocketAddr, relay_server: &str) -> RelayRequest {
        RelayRequest {
            a_addr,
            ws: false,
            b_id: "123456789".to_owned(),
            uuid: format!("uuid-{}", a_addr.port()),
            relay_server: relay_server.to_owned(),
            token: String::new(),
            found_in_memory: true,
        }
    }

    fn p3(port: u16) -> SocketAddr {
        SocketAddr::new(a1().ip(), port)
    }

    /// Sweeps at `now` and returns the outcomes finalized then.
    fn sweep(s: &mut TrackerState, now: i64) -> Vec<&'static str> {
        s.sweep(now).into_iter().map(|f| f.outcome).collect()
    }

    fn only(s: &mut TrackerState, now: i64) -> Finalized {
        let mut v = s.sweep(now);
        assert_eq!(v.len(), 1, "{v:?}");
        v.remove(0)
    }

    #[test]
    fn tcp_punch_success_is_direct_tcp() {
        let mut s = TrackerState::default();
        s.punch_request(punch(a1(), Signal::PunchHole), T0);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 500);
        // W = 45 s (6 × 0.5 s + 20 s < 45 s)
        assert!(sweep(&mut s, T0 + 500 + 45_000 - 1).is_empty());
        let f = only(&mut s, T0 + 500 + 45_000);
        assert_eq!(f.outcome, "direct_tcp");
        assert_eq!(f.attempt.reply, Some((Answer::PunchHoleSent, T0 + 500)));
        assert!(s.attempts.is_empty() && s.by_pair.is_empty() && s.by_punch_addr.is_empty());
    }

    #[test]
    fn v6_both_sides_is_direct_tcp_or_v6() {
        let mut s = TrackerState::default();
        let mut req = punch(a1(), Signal::PunchHole);
        req.has_v6 = true;
        s.punch_request(req, T0);
        let mut r = reply(a1(), ReplyKind::PunchHoleSent);
        r.b_has_v6 = true;
        s.reply(r, T0 + 300);
        assert_eq!(sweep(&mut s, T0 + 60_000), ["direct_tcp_or_v6"]);

        // Only one side has v6: plain TCP punch.
        let mut req = punch(a1(), Signal::PunchHole);
        req.has_v6 = true;
        s.punch_request(req, T0 + 100_000);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 100_300);
        assert_eq!(sweep(&mut s, T0 + 160_000), ["direct_tcp"]);
    }

    #[test]
    fn lan_is_direct_lan() {
        let mut s = TrackerState::default();
        let mut req = punch(a1(), Signal::FetchLocalAddr);
        req.has_v6 = true;
        s.punch_request(req, T0);
        let mut r = reply(a1(), ReplyKind::LocalAddr);
        r.b_has_v6 = true;
        s.reply(r, T0 + 100);
        assert_eq!(sweep(&mut s, T0 + 60_000), ["direct_lan"]);
    }

    #[test]
    fn fallback_relay_success_is_relay() {
        let mut s = TrackerState::default();
        s.punch_request(punch(a1(), Signal::PunchHole), T0);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 1_000);
        // Direct attempt failed after 18 s; A opens A:p3.
        let req_at = T0 + 20_000;
        s.request_relay(relay_req(p3(40003), "r1:21117"), req_at);
        s.relay_response(fallback_resp(p3(40003)), req_at + 300);
        // Not finalized as direct at reply + W, only at last relay_req_at + 20 s.
        assert!(sweep(&mut s, req_at + 20_000 - 1).is_empty());
        let f = only(&mut s, req_at + 20_000);
        assert_eq!(f.outcome, "relay");
        assert_eq!(f.attempt.relay_req_at, Some(req_at));
        assert_eq!(f.attempt.relay_resp_at, Some(req_at + 300));
        assert_eq!(f.attempt.relay_req_count, 1);
        assert_eq!(f.attempt.relay_uuid.as_deref(), Some("uuid-40003"));
        assert!(s.by_relay_addr.is_empty());
    }

    #[test]
    fn fallback_relay_without_response_is_relay_failed() {
        let mut s = TrackerState::default();
        s.punch_request(punch(a1(), Signal::PunchHole), T0);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 1_000);
        // Three tries, each a new connection, 18 s apart; no RelayResponse.
        s.request_relay(relay_req(p3(40003), "r1:21117"), T0 + 20_000);
        s.request_relay(relay_req(p3(40004), "r1:21117"), T0 + 38_000);
        s.request_relay(relay_req(p3(40005), "r1:21117"), T0 + 56_000);
        assert!(sweep(&mut s, T0 + 75_999).is_empty());
        let f = only(&mut s, T0 + 76_000);
        assert_eq!(f.outcome, "relay_failed");
        assert_eq!(f.attempt.relay_req_count, 3);
        assert_eq!(f.attempt.relay_req_at, Some(T0 + 20_000));
        assert_eq!(f.attempt.relay_uuid.as_deref(), Some("uuid-40003"));

        // A later retry that succeeds counts as relay.
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 100_000);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 101_000);
        s.request_relay(relay_req(p3(40006), "r1:21117"), T0 + 120_000);
        s.request_relay(relay_req(p3(40007), "r1:21117"), T0 + 138_000);
        s.relay_response(fallback_resp(p3(40007)), T0 + 138_500);
        assert_eq!(sweep(&mut s, T0 + 158_000), ["relay"]);
    }

    #[test]
    fn branch_x_is_relay_or_relay_or_v6() {
        let mut s = TrackerState::default();
        // Server-forced relay and A-forced relay both end up in branch X.
        let mut req = punch(a1(), Signal::PunchHole);
        req.server_forced_relay = true;
        s.punch_request(req, T0);
        s.relay_response(branch_x(a1(), false), T0 + 400);
        let f = only(&mut s, T0 + 5_000);
        assert_eq!(f.outcome, "relay");
        assert_eq!(f.attempt.reply, Some((Answer::RelayResponse, T0 + 400)));
        assert_eq!(f.attempt.relay_uuid.as_deref(), Some("uuid-x"));

        let mut req = punch(a1(), Signal::PunchHole);
        req.force_relay = true;
        req.nat_type = 2;
        s.punch_request(req, T0 + 10_000);
        s.relay_response(branch_x(a1(), false), T0 + 10_400);
        assert_eq!(sweep(&mut s, T0 + 15_000), ["relay"]);

        let mut req = punch(a1(), Signal::PunchHole);
        req.has_v6 = true;
        s.punch_request(req, T0 + 20_000);
        s.relay_response(branch_x(a1(), true), T0 + 20_400);
        // Waits out the pair-merge window, then finalizes.
        assert!(sweep(&mut s, T0 + 20_400 + 1_000).is_empty());
        assert_eq!(sweep(&mut s, T0 + 22_000), ["relay_or_v6"]);
    }

    #[test]
    fn hbbs_failures_are_rejected() {
        let mut s = TrackerState::default();
        for (i, signal) in [Signal::FailOffline, Signal::FailIdNotExist, Signal::FailLicense]
            .into_iter()
            .enumerate()
        {
            let t = T0 + i as i64 * 10_000;
            s.punch_request(punch(a1(), signal), t);
            assert!(sweep(&mut s, t + PAIR_MERGE_MS - 1).is_empty());
            let f = only(&mut s, t + PAIR_MERGE_MS);
            assert_eq!(f.outcome, "rejected");
            assert_eq!(f.attempt.req.as_ref().unwrap().signal, signal);
        }
    }

    #[test]
    fn no_reply_after_20s_from_last_request() {
        let mut s = TrackerState::default();
        // Same connection resends after 3 and 6 more seconds.
        s.punch_request(punch(a1(), Signal::PunchHole), T0);
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 3_000);
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 9_000);
        assert!(sweep(&mut s, T0 + 28_999).is_empty());
        let f = only(&mut s, T0 + 29_000);
        assert_eq!(f.outcome, "no_reply");
        assert_eq!(f.attempt.attempts, 3);
    }

    #[test]
    fn punch_sent_but_empty_relay_still_counts_as_direct() {
        // Known blind spot (note 02 §4.3): A failed directly and had no relay to fall back to.
        let mut s = TrackerState::default();
        let mut req = punch(a1(), Signal::PunchHole);
        req.relay_offered = String::new();
        s.punch_request(req, T0);
        let mut r = reply(a1(), ReplyKind::PunchHoleSent);
        r.b_relay = String::new();
        s.reply(r, T0 + 200);
        assert_eq!(sweep(&mut s, T0 + 60_000), ["direct_tcp"]);
    }

    #[test]
    fn same_connection_retry_merges() {
        let mut s = TrackerState::default();
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:40001".parse().unwrap();
        s.punch_request(punch(mapped, Signal::PunchHole), T0);
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 3_000);
        // B answers the retry; the reply is keyed by the same A:p1.
        s.reply(reply(mapped, ReplyKind::PunchHoleSent), T0 + 3_500);
        let f = only(&mut s, T0 + 60_000);
        assert_eq!(f.outcome, "direct_tcp");
        assert_eq!(f.attempt.attempts, 2);
        assert_eq!(f.attempt.started_at, T0);
        assert_eq!(f.attempt.a_addr, a1());
    }

    #[test]
    fn parallel_requests_within_2s_merge() {
        let mut s = TrackerState::default();
        let a2: SocketAddr = "1.2.3.4:40002".parse().unwrap();
        s.punch_request(punch(a1(), Signal::PunchHole), T0);
        s.punch_request(punch(a2, Signal::PunchHole), T0 + 2_000);
        // B answers both; the second answer is ignored.
        s.reply(reply(a2, ReplyKind::PunchHoleSent), T0 + 2_300);
        s.reply(reply(a1(), ReplyKind::LocalAddr), T0 + 2_400);
        let f = only(&mut s, T0 + 60_000);
        assert_eq!(f.outcome, "direct_tcp");
        assert_eq!(f.attempt.attempts, 2);
        assert_eq!(f.attempt.a_addr, a1());
        assert!(s.by_punch_addr.is_empty());

        // 2.001 s apart: two attempts.
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 100_000);
        s.punch_request(punch(a2, Signal::PunchHole), T0 + 102_001);
        assert_eq!(s.attempts.len(), 2);

        // A different B from the same IP is a different attempt.
        let mut other = punch("1.2.3.4:40009".parse().unwrap(), Signal::PunchHole);
        other.b_id = "987654321".to_owned();
        s.punch_request(other, T0 + 102_002);
        assert_eq!(s.attempts.len(), 3);
    }

    #[test]
    fn merged_success_supersedes_failure() {
        let mut s = TrackerState::default();
        let a2: SocketAddr = "1.2.3.4:40002".parse().unwrap();
        s.punch_request(punch(a1(), Signal::FailOffline), T0);
        s.punch_request(punch(a2, Signal::PunchHole), T0 + 1_000);
        s.reply(reply(a2, ReplyKind::PunchHoleSent), T0 + 1_200);
        let f = only(&mut s, T0 + 60_000);
        assert_eq!(f.outcome, "direct_tcp");
        assert_eq!(f.attempt.req.as_ref().unwrap().relay_offered, "r1:21117");

        // A failure after a success does not overwrite it.
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 100_000);
        s.punch_request(punch(a2, Signal::FailOffline), T0 + 100_500);
        let f = only(&mut s, T0 + 130_000);
        assert_eq!(f.outcome, "no_reply");
        assert_eq!(f.attempt.attempts, 2);
    }

    #[test]
    fn request_relay_window_follows_punch_time() {
        let mut s = TrackerState::default();
        // Punch took 10 s → W = 6 × 10 + 20 = 80 s.
        s.punch_request(punch(a1(), Signal::PunchHole), T0);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 10_000);
        s.request_relay(relay_req(p3(40003), "r1:21117"), T0 + 10_000 + 80_000);
        s.relay_response(fallback_resp(p3(40003)), T0 + 90_200);
        assert_eq!(sweep(&mut s, T0 + 110_000), ["relay"]);

        // Fast punch → W = 45 s; a RequestRelay after that is relay_only, and the punch is direct.
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 200_000);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 200_100);
        s.request_relay(relay_req(p3(40004), "r1:21117"), T0 + 200_100 + 45_001);
        let mut v: Vec<_> = sweep(&mut s, T0 + 300_000);
        v.sort();
        assert_eq!(v, ["direct_tcp", "relay_failed"]);

        // Review C-12: 3 s of connect + KeyExchange that hbbs doesn't see, then 5 s request → reply
        // as hbbs sees it. A's direct timeout is 6 × 8 s = 48 s after the reply: still the same attempt
        // (W = 6 × 5 + 20 = 50 s).
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 400_000);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 405_000);
        s.request_relay(relay_req(p3(40005), "r1:21117"), T0 + 405_000 + 48_000);
        assert_eq!(sweep(&mut s, T0 + 500_000), ["relay_failed"]);
    }

    #[test]
    fn request_relay_prefers_matching_relay() {
        let mut s = TrackerState::default();
        let a2: SocketAddr = "1.2.3.4:40002".parse().unwrap();
        // Two separate attempts to the same B from the same IP (3 s apart, so not merged).
        s.punch_request(punch(a1(), Signal::PunchHole), T0);
        let mut r = reply(a1(), ReplyKind::PunchHoleSent);
        r.b_relay = "r2:21117".to_owned();
        s.reply(r, T0 + 200);
        s.punch_request(punch(a2, Signal::PunchHole), T0 + 3_000);
        s.reply(reply(a2, ReplyKind::PunchHoleSent), T0 + 3_200);
        // Asks for r2: the older attempt, even though the newer one is more recent.
        s.request_relay(relay_req(p3(40003), "r2:21117"), T0 + 22_000);
        let mut out: Vec<_> = s
            .sweep(T0 + 100_000)
            .into_iter()
            .map(|f| (f.attempt.a_addr.port(), f.outcome))
            .collect();
        out.sort();
        assert_eq!(out, [(40001, "relay_failed"), (40002, "direct_tcp")]);

        // No relay matches: the most recent one.
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 200_000);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 200_200);
        s.punch_request(punch(a2, Signal::PunchHole), T0 + 203_000);
        s.reply(reply(a2, ReplyKind::PunchHoleSent), T0 + 203_200);
        s.request_relay(relay_req(p3(40003), "r9:21117"), T0 + 222_000);
        let mut out: Vec<_> = s
            .sweep(T0 + 300_000)
            .into_iter()
            .map(|f| (f.attempt.a_addr.port(), f.outcome))
            .collect();
        out.sort();
        assert_eq!(out, [(40001, "direct_tcp"), (40002, "relay_failed")]);
    }

    #[test]
    fn unmatched_request_relay_is_relay_only() {
        let mut s = TrackerState::default();
        let mut rr = relay_req(p3(40003), "r1:21117");
        rr.ws = true;
        s.request_relay(rr, T0);
        s.relay_response(fallback_resp(p3(40003)), T0 + 500);
        assert!(sweep(&mut s, T0 + 19_999).is_empty());
        let f = only(&mut s, T0 + 20_000);
        assert_eq!(f.outcome, "relay_unmatched");
        assert!(f.attempt.req.is_none());
        assert_eq!(f.attempt.a_addr, p3(40003));
        assert_eq!(f.attempt.relay_req_at, Some(T0));

        // Retries merge into one row; no response → relay_failed.
        s.request_relay(relay_req(p3(40004), "r1:21117"), T0 + 100_000);
        s.request_relay(relay_req(p3(40005), "r1:21117"), T0 + 118_000);
        let f = only(&mut s, T0 + 138_000);
        assert_eq!(f.outcome, "relay_failed");
        assert_eq!(f.attempt.relay_req_count, 2);

        // A punch request never merges into a relay_only row.
        s.request_relay(relay_req(p3(40006), "r1:21117"), T0 + 200_000);
        s.punch_request(punch(a1(), Signal::PunchHole), T0 + 200_500);
        assert_eq!(s.attempts.len(), 2);
    }

    #[test]
    fn replies_to_unknown_or_finalized_attempts_are_ignored() {
        let mut s = TrackerState::default();
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0);
        s.relay_response(branch_x(a1(), false), T0);
        s.relay_response(fallback_resp(p3(40003)), T0);
        assert!(s.attempts.is_empty());

        s.punch_request(punch(a1(), Signal::PunchHole), T0);
        assert_eq!(sweep(&mut s, T0 + 20_000), ["no_reply"]);
        s.reply(reply(a1(), ReplyKind::PunchHoleSent), T0 + 21_000);
        assert!(s.attempts.is_empty());
    }

    async fn insert(db: &SqlitePool, s: &mut TrackerState, now: i64) {
        for f in s.sweep(now) {
            write(db, &f).await.unwrap();
        }
    }

    #[tokio::test]
    async fn write_resolves_token_and_fills_columns() {
        let (_dir, db) = crate::testutil::pool().await;
        let (uid, token) = crate::testutil::create_user(&db, "alice", "pw", false).await;
        sqlx::query("update token set device_id = '111222333' where user_id = ?")
            .bind(uid)
            .execute(&db)
            .await
            .unwrap();
        let mut s = TrackerState::default();
        let mut req = punch("[::ffff:1.2.3.4]:40001".parse().unwrap(), Signal::PunchHole);
        req.token = token;
        req.ws = true;
        req.udp_port = 5;
        s.punch_request(req, T0);
        let mut r = reply(a1(), ReplyKind::PunchHoleSent);
        r.b_relay = "hard-coded:21117".to_owned();
        s.reply(r, T0 + 700);
        let mut rr = relay_req(p3(40003), "hard-coded:21117");
        rr.token = "not-a-token".to_owned();
        s.request_relay(rr, T0 + 600_000); // outside W: relay_only
        insert(&db, &mut s, T0 + 700_000).await;

        let rows: Vec<(String, i64, String, Option<String>, Option<String>, String, Option<String>, String, i64)> =
            sqlx::query_as(
                "select a_ip, a_port, via, a_user, a_device_id, signal, b_ip, outcome, a_udp_port
                 from conn_attempt order by started_at",
            )
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(
            rows[0],
            (
                "1.2.3.4".to_owned(),
                40001,
                "ws".to_owned(),
                Some("alice".to_owned()),
                Some("111222333".to_owned()),
                "punch_hole".to_owned(),
                Some("5.6.7.8".to_owned()),
                "direct_tcp".to_owned(),
                5
            )
        );
        assert_eq!(
            rows[1],
            (
                "1.2.3.4".to_owned(),
                40003,
                "tcp".to_owned(),
                None,
                None,
                "relay_only".to_owned(),
                None,
                "relay_failed".to_owned(),
                0
            )
        );
        let (reply, reply_at, b_relay, relay_offered, finalized_at): (String, i64, String, String, i64) =
            sqlx::query_as(
                "select reply, reply_at, b_relay, relay_offered, finalized_at from conn_attempt
                 where signal = 'punch_hole'",
            )
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            (reply.as_str(), reply_at, b_relay.as_str(), relay_offered.as_str(), finalized_at),
            ("punch_hole_sent", T0 + 700, "hard-coded:21117", "r1:21117", T0 + 700_000)
        );
        let (conn_type, nat, force, v6, forced, relay_req_at, count): (i64, i64, i64, i64, i64, i64, i64) =
            sqlx::query_as(
                "select conn_type, a_nat_type, a_force_relay, a_has_v6, server_forced_relay,
                 relay_req_at, relay_req_count from conn_attempt where signal = 'relay_only'",
            )
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!((conn_type, nat, force, v6, forced, relay_req_at, count), (0, 0, 0, 0, 0, T0 + 600_000, 1));
    }

    #[tokio::test]
    async fn stats_counts_and_relay_rate() {
        let (_dir, db) = crate::testutil::pool().await;
        let empty = ConnTracker::stats(&db, 0, i64::MAX).await.unwrap();
        assert!(empty.outcomes.is_empty() && empty.relay_rate.is_none());

        let mut s = TrackerState::default();
        let mut port = 40000;
        let mut addr = || {
            port += 1;
            SocketAddr::new(a1().ip(), port)
        };
        let mut t = T0;
        let mut step = || {
            t += 10_000;
            t
        };
        // 2 direct_tcp (one with B's hard-coded relay), 1 direct_lan, 1 direct_tcp_or_v6.
        for b_relay in ["r1:21117", "hard-coded:21117"] {
            let (a, t1) = (addr(), step());
            s.punch_request(punch(a, Signal::PunchHole), t1);
            let mut r = reply(a, ReplyKind::PunchHoleSent);
            r.b_relay = b_relay.to_owned();
            s.reply(r, t1 + 100);
        }
        let (a, t1) = (addr(), step());
        s.punch_request(punch(a, Signal::FetchLocalAddr), t1);
        s.reply(reply(a, ReplyKind::LocalAddr), t1 + 100);
        let (a, t1) = (addr(), step());
        let mut req = punch(a, Signal::PunchHole);
        req.has_v6 = true;
        s.punch_request(req, t1);
        let mut r = reply(a, ReplyKind::PunchHoleSent);
        r.b_has_v6 = true;
        s.reply(r, t1 + 100);
        // relay (branch X) and relay_or_v6.
        let (a, t1) = (addr(), step());
        s.punch_request(punch(a, Signal::PunchHole), t1);
        s.relay_response(branch_x(a, false), t1 + 100);
        let (a, t1) = (addr(), step());
        let mut req = punch(a, Signal::PunchHole);
        req.has_v6 = true;
        s.punch_request(req, t1);
        s.relay_response(branch_x(a, true), t1 + 100);
        // Excluded: rejected, no_reply, relay_failed, relay_unmatched.
        let t1 = step();
        s.punch_request(punch(addr(), Signal::FailOffline), t1);
        let mut req = punch(addr(), Signal::PunchHole);
        req.b_id = "222".to_owned();
        s.punch_request(req, step());
        let mut rr = relay_req(addr(), "r1:21117");
        rr.b_id = "333".to_owned();
        s.request_relay(rr, step());
        let (a, t1) = (addr(), step());
        let mut rr = relay_req(a, "r1:21117");
        rr.b_id = "444".to_owned();
        s.request_relay(rr, t1);
        s.relay_response(fallback_resp(a), t1 + 100);
        insert(&db, &mut s, T0 + 1_000_000).await;

        let st = ConnTracker::stats(&db, 0, i64::MAX).await.unwrap();
        let expect: Vec<(String, i64)> = [
            ("direct_lan", 1),
            ("direct_tcp", 2),
            ("direct_tcp_or_v6", 1),
            ("no_reply", 1),
            ("rejected", 1),
            ("relay", 1),
            ("relay_failed", 1),
            ("relay_or_v6", 1),
            ("relay_unmatched", 1),
        ]
        .into_iter()
        .map(|(o, n)| (o.to_owned(), n))
        .collect();
        assert_eq!(st.outcomes, expect);
        assert_eq!(st.relay_rate, Some(2.0 / 6.0));
        // Failure rows have relay_offered '' and relay_only rows NULL; only the hard-coded one counts.
        assert_eq!(st.b_relay_mismatch, 1);

        // The range is on started_at, half-open.
        let first = ConnTracker::stats(&db, T0 + 10_000, T0 + 20_000).await.unwrap();
        assert_eq!(first.outcomes, [("direct_tcp".to_owned(), 1)]);
        assert_eq!(first.relay_rate, Some(0.0));
    }
}
