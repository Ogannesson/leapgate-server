//! Connection outcome tracking (PORTA.md §8, note 02 §4.4).
//!
//! The rendezvous hooks H1~H5 call the `on_*` methods; they only touch memory and never block
//! (hand-off to a background task that finalizes attempts into `conn_attempt` every 5 seconds).
//! Skeleton: every hook is a no-op.

use hbb_common::ResultType;
use sqlx::SqlitePool;
use std::{net::SocketAddr, sync::Arc};

/// `conn_attempt.signal`: what hbbs did with a `PunchHoleRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    PunchHole,
    FetchLocalAddr,
    FailOffline,
    FailIdNotExist,
    FailLicense,
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

pub struct ConnTracker {
    #[allow(dead_code)]
    db: SqlitePool,
}

impl ConnTracker {
    pub fn new(db: SqlitePool) -> Self {
        Self { db }
    }

    /// H1.
    pub fn on_punch_request(&self, _req: PunchRequest) {}

    /// H2, H3.
    pub fn on_reply(&self, _reply: Reply) {}

    /// H4.
    pub fn on_relay_response(&self, _resp: RelayResponseInfo) {}

    /// H5.
    pub fn on_request_relay(&self, _req: RelayRequest) {}

    /// The 5-second finalizer and the database writer, spawned on the server's runtime.
    pub fn spawn_tasks(self: &Arc<Self>) {}

    /// Statistics of attempts started in `[since_ms, until_ms)` (unix ms). Reads the database only.
    pub async fn stats(_db: &SqlitePool, _since_ms: i64, _until_ms: i64) -> ResultType<Stats> {
        todo!()
    }
}
