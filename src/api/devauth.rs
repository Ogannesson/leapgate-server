//! Porta device authentication (phase 3 contract 01 §2.1, §2.2, §3.2, §3.3): every request on
//! `/api/porta/v1/` is signed with the device's own key, the one it registered with hbbs (`peer.pk`),
//! and the first one that verifies pins that key (`peer.pk_pinned_at`). Answers are signed with the
//! rendezvous private key (`AppState::sk`), bound to the request's signature.
//!
//! Unlike the compatibility endpoints (PORTA.md §9.1 item 1) these answer 5xx: only Porta clients
//! call them, and they back off on it. Error bodies are `{"error": <code>, "message": <text>}`.

use super::{device::report_allowed, json, ClientIp};
use crate::{
    peer::{log_id, LockPeer, MAX_PEER_ID_LEN},
    state::AppState,
};
use axum::{
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Request},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use hbb_common::throttled_log;
use once_cell::sync::Lazy;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest as _, Sha256};
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, VecDeque},
    fmt::Display,
    net::IpAddr,
    sync::Mutex,
    time::Duration,
};

/// The Porta endpoints; what follows is the endpoint name the signature covers (`heartbeat`, `audit/conn`).
pub(crate) const PREFIX: &str = "/api/porta/v1/";
/// `Porta-Device-Auth: v1 id=<base64url(id)>, t=<unix seconds>, s=<base64url(signature)>`.
const AUTH_HEADER: &str = "porta-device-auth";
/// `Porta-Server-Sig: <base64url(signature)>` on the signed answers (`signed_json`).
pub(crate) const SIG_HEADER: &str = "porta-server-sig";
const REQUEST_DOMAIN: &[u8] = b"porta-device-v1\0";
const RESPONSE_DOMAIN: &[u8] = b"porta-server-v1\0";
/// A request's timestamp is at most this many seconds off the server's clock (`stale_time`); the
/// 401 carries the server's time, and the client corrects its offset and signs again.
const MAX_CLOCK_SKEW: u64 = 60;
/// Requests of one device may arrive out of order by this many seconds (`Replay`). A new entry
/// starts its floor this far back: after a restart a request captured before it can be replayed
/// within this window at most.
const MAX_REORDER: i64 = 30;
/// Signatures remembered per device; once over, the oldest goes and the floor rises to its time.
const REPLAY_RING: usize = 64;
/// Devices in the replay table (about 1.5 KB each, ~6 MB). Full: a new one evicts the one seen
/// longest ago. Only verified requests add entries, so filling it takes that many registered keys.
const MAX_REPLAY_IDS: usize = 4096;

/// A request on a Porta endpoint whose signature verified: the device id (from the header only; an
/// `id` in the body is ignored), the request's signature (`signed_json` binds the answer to it), the
/// raw body, the client address (`ClientIp`) and the device's in-memory entry. Last argument of the
/// handler; any failed check answers for the handler (§3.2 of the contract):
/// 1. header format → 401 `bad_auth` (unsigned, no `time`: there is no request signature to bind);
/// 2. the source's report budget, shared with the compatibility reports → 429;
/// 3. the body, within the route's limit → 413;
/// 4. `t` within `MAX_CLOCK_SKEW` → 401 `stale_time`;
/// 5. the device's key (`get_from_main`; database error → 503) → 401 `unknown_device`;
/// 6. the signature → 401 `bad_signature`;
/// 7. not a replay (`ReplayTable`) → 401 `replay`;
/// 8. a first verified request pins the key (`pin`), and goes through whatever that gives.
///
/// The 401s of steps 4~7 are signed and carry the server's `time`.
pub(crate) struct SignedBody {
    pub id: String,
    pub sig: [u8; 64],
    pub body: Bytes,
    pub ip: IpAddr,
    pub peer: LockPeer,
}

impl FromRequest<AppState> for SignedBody {
    type Rejection = Response;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Response> {
        let (mut parts, body) = req.into_parts();
        let Ok(ClientIp(ip)) = ClientIp::from_request_parts(&mut parts, state).await;
        let Some((id, t, sig)) = parts
            .headers
            .get(AUTH_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_auth)
        else {
            throttled_log!(Duration::from_secs(60), info, "Porta report from {ip}: bad or missing auth header");
            return Err(porta_error(
                StatusCode::UNAUTHORIZED,
                "bad_auth",
                "Missing or malformed Porta-Device-Auth header",
            ));
        };
        if !report_allowed(ip) {
            return Err(porta_error(StatusCode::TOO_MANY_REQUESTS, "too_many_requests", "Too many requests"));
        }
        let method = parts.method.as_str().to_owned();
        let endpoint = parts.uri.path().strip_prefix(PREFIX).unwrap_or_default().to_owned();
        let body = match Bytes::from_request(Request::from_parts(parts, body), state).await {
            Ok(body) => body,
            Err(err) if err.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                return Err(porta_error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "Request body too large"))
            }
            Err(err) => return Err(porta_error(StatusCode::BAD_REQUEST, "bad_request", &err.body_text())),
        };
        let now = crate::common::now() as i64;
        if !fresh(t, now) {
            return Err(rejected(state, &sig, Reason::StaleTime, ip, &id));
        }
        let peer = match state.pm.get_from_main(&id).await {
            Ok(Some(peer)) => peer,
            Ok(None) => return Err(rejected(state, &sig, Reason::UnknownDevice, ip, &id)),
            Err(err) => return Err(porta_internal(err)),
        };
        // `update_pk` writes the database before memory, so this key is never newer than the row's.
        let (pk, pinned) = {
            let p = peer.read().await;
            (p.pk.clone(), p.pinned)
        };
        // An empty key: the placeholder `insert_new` makes for an id being registered.
        if pk.is_empty() {
            return Err(rejected(state, &sig, Reason::UnknownDevice, ip, &id));
        }
        let message = request_message(&method, &endpoint, &id, t, &body);
        let verified = match (sign::PublicKey::from_slice(&pk), sign::Signature::from_bytes(&sig)) {
            (Some(pk), Ok(sig)) => sign::verify_detached(&sig, &message, &pk),
            _ => false,
        };
        if !verified {
            return Err(rejected(state, &sig, Reason::BadSignature, ip, &id));
        }
        if !REPLAY.lock().unwrap_or_else(|e| e.into_inner()).accept(&id, t, &sig, now) {
            return Err(rejected(state, &sig, Reason::Replay, ip, &id));
        }
        if !pinned {
            pin(state, &id, &pk, &peer, now).await;
        }
        Ok(Self { id, sig, body, ip, peer })
    }
}

/// `v1 id=<…>, t=<…>, s=<…>`, fields in this order, `, ` between them, base64url without padding
/// (strict: only the canonical text of the bytes). The id is 1~`MAX_PEER_ID_LEN` bytes of UTF-8 and
/// the signature exactly 64 bytes.
fn parse_auth(v: &str) -> Option<(String, i64, [u8; 64])> {
    let (id, rest) = v.strip_prefix("v1 id=")?.split_once(", t=")?;
    let (t, s) = rest.split_once(", s=")?;
    let id = String::from_utf8(b64url_decode(id)?).ok()?;
    if id.is_empty() || id.len() > MAX_PEER_ID_LEN {
        return None;
    }
    let t = t.parse::<i64>().ok()?;
    let sig = b64url_decode(s)?.try_into().ok()?;
    Some((id, t, sig))
}

/// Whether a request's timestamp `t` is within `MAX_CLOCK_SKEW` of the server's `now`.
fn fresh(t: i64, now: i64) -> bool {
    t.abs_diff(now) <= MAX_CLOCK_SKEW
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let raw = base64::decode_config(s, base64::URL_SAFE_NO_PAD).ok()?;
    (b64url(&raw) == s).then_some(raw)
}

pub(crate) fn b64url(raw: &[u8]) -> String {
    base64::encode_config(raw, base64::URL_SAFE_NO_PAD)
}

/// What a device signs: `"porta-device-v1\0" ‖ method ‖ "\0" ‖ endpoint ‖ "\0" ‖ id ‖ "\0" ‖ t (decimal)
/// ‖ "\0" ‖ sha256(body)`.
pub(crate) fn request_message(method: &str, endpoint: &str, id: &str, t: i64, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(REQUEST_DOMAIN.len() + method.len() + endpoint.len() + id.len() + 60);
    m.extend_from_slice(REQUEST_DOMAIN);
    for part in [method, endpoint, id, &t.to_string()] {
        m.extend_from_slice(part.as_bytes());
        m.push(0);
    }
    m.extend_from_slice(&Sha256::digest(body));
    m
}

/// What the server signs: `"porta-server-v1\0" ‖ the request's signature ‖ sha256(body)`.
pub(crate) fn response_message(req_sig: &[u8], body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(RESPONSE_DOMAIN.len() + req_sig.len() + 32);
    m.extend_from_slice(RESPONSE_DOMAIN);
    m.extend_from_slice(req_sig);
    m.extend_from_slice(&Sha256::digest(body));
    m
}

/// First verified request of a device whose key is not pinned: pins the key it was verified with,
/// if the row still has that key and no pin. The database alone decides (a key change of a pinned
/// row is refused there, `Database::update_pk`), so memory is only set when the row was written and
/// the entry still holds that key; a row not written (another key by now, pinned meanwhile) or a
/// failed write lets the request through, and the next one tries again.
async fn pin(state: &AppState, id: &str, pk: &[u8], peer: &LockPeer, now: i64) {
    match sqlx::query("update peer set pk_pinned_at = ? where id = ? and pk = ? and pk_pinned_at is null")
        .bind(now)
        .bind(id)
        .bind(pk)
        .execute(&state.db)
        .await
    {
        Ok(r) if r.rows_affected() == 1 => {
            let mut w = peer.write().await;
            if w.pk == pk {
                w.pinned = true;
            }
            drop(w);
            throttled_log!(Duration::from_secs(60), info, "Porta report: key of {:?} pinned", log_id(id));
        }
        Ok(_) => {}
        Err(err) => throttled_log!(
            Duration::from_secs(60),
            warn,
            "Porta report: pinning the key of {:?} failed: {}",
            log_id(id),
            err
        ),
    }
}

/// Why a request with a parsed header was refused (signed 401s).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Reason {
    StaleTime,
    UnknownDevice,
    BadSignature,
    Replay,
}

impl Reason {
    fn code(self) -> &'static str {
        match self {
            Reason::StaleTime => "stale_time",
            Reason::UnknownDevice => "unknown_device",
            Reason::BadSignature => "bad_signature",
            Reason::Replay => "replay",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Reason::StaleTime => "Timestamp too far from the server's time",
            Reason::UnknownDevice => "Device not registered",
            Reason::BadSignature => "Signature does not verify",
            Reason::Replay => "Request already seen",
        }
    }
}

#[derive(Serialize)]
struct AuthError {
    error: &'static str,
    message: &'static str,
    time: i64,
}

/// The signed 401 of steps 4~7, with the server's time; each reason logged at most once a minute
/// (the id clipped and escaped, PORTA.md §6 item 7; no signature or key).
fn rejected(state: &AppState, req_sig: &[u8; 64], reason: Reason, ip: IpAddr, id: &str) -> Response {
    let id = log_id(id);
    match reason {
        Reason::StaleTime => {
            throttled_log!(Duration::from_secs(60), info, "Porta report from {ip}: stale timestamp for {id:?}")
        }
        Reason::UnknownDevice => {
            throttled_log!(Duration::from_secs(60), info, "Porta report from {ip}: unknown device {id:?}")
        }
        Reason::BadSignature => {
            throttled_log!(Duration::from_secs(60), info, "Porta report from {ip}: bad signature for {id:?}")
        }
        Reason::Replay => throttled_log!(Duration::from_secs(60), info, "Porta report from {ip}: replay for {id:?}"),
    }
    let body = AuthError {
        error: reason.code(),
        message: reason.message(),
        time: crate::common::now() as i64,
    };
    signed_json(state, req_sig, StatusCode::UNAUTHORIZED, &body)
}

/// JSON (`charset=utf-8`) signed for the request signed `req_sig` (`Porta-Server-Sig`, §2.2 of the
/// contract): the 2xx answers and the 401s other than `bad_auth`. No header without a private key
/// (`-k` gave a public key; such a server cannot serve logged-in clients anyway).
pub(crate) fn signed_json<T: Serialize>(state: &AppState, req_sig: &[u8], status: StatusCode, v: &T) -> Response {
    let body = match serde_json::to_vec(v) {
        Ok(body) => body,
        Err(err) => return porta_internal(err),
    };
    let sig = state
        .sk
        .as_ref()
        .map(|sk| b64url(&sign::sign_detached(&response_message(req_sig, &body), sk).to_bytes()));
    let mut resp = json_bytes(status, body);
    if let Some(v) = sig.and_then(|s| HeaderValue::from_str(&s).ok()) {
        resp.headers_mut().insert(SIG_HEADER, v);
    }
    resp
}

fn json_bytes(status: StatusCode, body: Vec<u8>) -> Response {
    (status, [(axum::http::header::CONTENT_TYPE, super::JSON)], body).into_response()
}

/// `{"error": code, "message": message}`, unsigned: `bad_auth`, 400, 404, 405, 413, 429, 503.
pub(crate) fn porta_error(status: StatusCode, code: &'static str, message: &str) -> Response {
    json(status, &serde_json::json!({ "error": code, "message": message }))
}

/// Logged at most once a minute (signed requests can trigger it at the report budget's rate); 503
/// `internal` (database error, panic). The client retries later.
pub(crate) fn porta_internal(err: impl Display) -> Response {
    throttled_log!(Duration::from_secs(60), error, "Porta API internal error: {err}");
    porta_error(StatusCode::SERVICE_UNAVAILABLE, "internal", "Server error")
}

/// Parses a Porta request body; failure → 400 `bad_request`.
pub(crate) fn parse_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, Response> {
    serde_json::from_slice(body)
        .map_err(|err| porta_error(StatusCode::BAD_REQUEST, "bad_request", &format!("Invalid request body: {err}")))
}

/// Recent requests of one device (§3.3 of the contract). Accepted: `t ≥ max_ts − MAX_REORDER`,
/// `t > floor`, and `(t, first 16 bytes of the signature)` not in `ring`; Ed25519 signatures are
/// deterministic, so a replay carries the very same signature.
struct Replay {
    max_ts: i64,
    floor: i64,
    ring: VecDeque<(i64, [u8; 16])>,
    last_seen: i64,
}

impl Replay {
    fn push(&mut self, t: i64, key: [u8; 16], now: i64) {
        self.ring.push_back((t, key));
        if self.ring.len() > REPLAY_RING {
            if let Some((old, _)) = self.ring.pop_front() {
                self.floor = self.floor.max(old);
            }
        }
        self.max_ts = self.max_ts.max(t);
        self.last_seen = now;
    }
}

/// Device id → `Replay`, at most `MAX_REPLAY_IDS`; memory only (lost on restart, see `MAX_REORDER`).
#[derive(Default)]
struct ReplayTable {
    ids: HashMap<String, Replay>,
}

impl ReplayTable {
    /// Whether a verified request (`t` already within `MAX_CLOCK_SKEW` of `now`) is new; remembers it if so.
    fn accept(&mut self, id: &str, t: i64, sig: &[u8; 64], now: i64) -> bool {
        let mut key = [0u8; 16];
        key.copy_from_slice(&sig[..16]);
        if let Some(r) = self.ids.get_mut(id) {
            if t < r.max_ts - MAX_REORDER || t <= r.floor || r.ring.contains(&(t, key)) {
                return false;
            }
            r.push(t, key, now);
            return true;
        }
        let floor = now - MAX_REORDER;
        if t <= floor {
            return false;
        }
        if self.ids.len() >= MAX_REPLAY_IDS {
            let oldest = self.ids.iter().min_by_key(|(_, r)| r.last_seen).map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                self.ids.remove(&oldest);
            }
        }
        let mut r = Replay {
            max_ts: t,
            floor,
            ring: VecDeque::with_capacity(REPLAY_RING + 1),
            last_seen: now,
        };
        r.push(t, key, now);
        self.ids.insert(id.to_owned(), r);
        true
    }
}

static REPLAY: Lazy<Mutex<ReplayTable>> = Lazy::new(Default::default);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{self, porta_device, send_porta, verify_server_sig, Device};
    use hbb_common::{rendezvous_proto::register_pk_response::Result as RegisterResult, tokio};
    use serde_json::Value;

    /// The fixed vector the client's tests share (contract 01 §6.1/§6.2; porta-client
    /// `libs/porta/src/sign.rs`, computed there independently): device key from seed `[7; 32]`, id
    /// `123456789`, `t` 1761200000, `POST heartbeat`; server key from seed `[9; 32]`.
    const VECTOR_REQUEST_BODY: &[u8] = br#"{"uuid":"dGVzdA==","ver":1005010}"#;
    const VECTOR_HEADER: &str = "v1 id=MTIzNDU2Nzg5, t=1761200000, s=yx-Mzyt9ynHD1FCErdyWCz_Kx_iNzF7b4ZfZfJfCQaL2vH3VLHVBadR5BYSAbk5fdqXUHU7ImS9W2Wy46mw9Aw";
    const VECTOR_SERVER_PK: &str = "/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=";
    const VECTOR_RESPONSE_BODY: &[u8] = br#"{"api":1,"features":[],"time":1761200000}"#;
    const VECTOR_SERVER_SIG: &str = "zATBKIx6xPyFbAQVV7koFw0iuqmyvNQwuufqcxG-NNKjaI6BUx0uJiHThezCfpTmtYgZZmR2ApOOgEPNMKdsDA";

    #[test]
    fn signature_vector() {
        let (dev_pk, dev_sk) = sign::keypair_from_seed(&sign::Seed([7u8; 32]));
        let message = request_message("POST", "heartbeat", "123456789", 1761200000, VECTOR_REQUEST_BODY);
        let sig = sign::sign_detached(&message, &dev_sk).to_bytes();
        let header = format!("v1 id={}, t={}, s={}", b64url(b"123456789"), 1761200000, b64url(&sig));
        assert_eq!(header, VECTOR_HEADER);
        // The server side of the check: the header parses and verifies against the device's key.
        let (id, t, parsed) = parse_auth(VECTOR_HEADER).unwrap();
        assert_eq!((id.as_str(), t, parsed), ("123456789", 1761200000, sig));
        let message = request_message("POST", "heartbeat", &id, t, VECTOR_REQUEST_BODY);
        assert!(sign::verify_detached(&sign::Signature::from_bytes(&parsed).unwrap(), &message, &dev_pk));

        // The answer's signature, byte for byte.
        let (server_pk, server_sk) = sign::keypair_from_seed(&sign::Seed([9u8; 32]));
        assert_eq!(base64::encode(server_pk.0), VECTOR_SERVER_PK);
        let answer = sign::sign_detached(&response_message(&sig, VECTOR_RESPONSE_BODY), &server_sk);
        assert_eq!(b64url(&answer.to_bytes()), VECTOR_SERVER_SIG);
    }

    #[test]
    fn header_is_parsed_strictly() {
        let sig = b64url(&[1u8; 64]);
        let ok = format!("v1 id={}, t=5, s={sig}", b64url(b"abcdef"));
        assert_eq!(parse_auth(&ok), Some(("abcdef".to_owned(), 5, [1u8; 64])));
        let long_id = b64url("i".repeat(MAX_PEER_ID_LEN).as_bytes());
        assert!(parse_auth(&format!("v1 id={long_id}, t=5, s={sig}")).is_some());
        for bad in [
            format!("v1 id={}=, t=5, s={sig}", b64url(b"abcdefg")),               // padding
            format!("v1 id={}, t=5, s={sig}=", b64url(b"abcdef")),                // padding
            format!("v1 id={}, s={sig}, t=5", b64url(b"abcdef")),                 // order
            format!("v1 id={},t=5,s={sig}", b64url(b"abcdef")),                   // separator
            format!("v2 id={}, t=5, s={sig}", b64url(b"abcdef")),                 // version
            format!("v1 id=, t=5, s={sig}"),                                      // empty id
            format!("v1 id={}, t=5, s={sig}", b64url("i".repeat(MAX_PEER_ID_LEN + 1).as_bytes())),
            format!("v1 id={}, t=5, s={sig}", b64url(&[0xff, 0xfe])),             // not UTF-8
            format!("v1 id={}, t=x, s={sig}", b64url(b"abcdef")),                 // t
            format!("v1 id={}, t=5, s={}", b64url(b"abcdef"), b64url(&[1u8; 63])), // 63 bytes
            format!("v1 id={}, t=5, s={}", b64url(b"abcdef"), base64::encode([1u8; 64])), // standard alphabet
            format!("v1 id=YWJjZGVmZ, t=5, s={sig}"),                             // trailing bits
        ] {
            assert_eq!(parse_auth(&bad), None, "{bad}");
        }
    }

    async fn post(t: &testutil::TestApp, auth: Option<&str>, body: &[u8]) -> (StatusCode, axum::http::HeaderMap, Value) {
        let (status, headers, body) = send_porta(&t.app, "/api/porta/v1/audit/alarm", auth, body).await;
        (status, headers, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// The signed 401 of a chain step: code, `time`, and a server signature bound to `req_sig`.
    async fn assert_signed_401(t: &testutil::TestApp, auth: &str, sig: &[u8; 64], body: &[u8], code: &str) {
        let (status, headers, raw) = send_porta(&t.app, "/api/porta/v1/audit/alarm", Some(auth), body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{code}");
        let v: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["error"], code, "{v}");
        assert!(v["time"].is_i64() && v["message"].is_string(), "{v}");
        assert!(verify_server_sig(&t.state, sig, &headers, &raw), "{code}");
    }

    #[tokio::test]
    async fn every_rejection_of_the_chain() {
        let t = testutil::app().await;
        let dev = porta_device(&t.state, "chain01", b"uuid-chain").await;
        let body = br#"{"typ":1,"info":"{}"}"#;
        let now = crate::common::now() as i64;

        // Header format: 401 bad_auth, unsigned, no time.
        for auth in [None, Some("v1 id=x"), Some("Bearer x")] {
            let (status, headers, v) = post(&t, auth, body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(v["error"], "bad_auth");
            assert!(v.get("time").is_none() && !headers.contains_key(SIG_HEADER), "{v}");
        }
        // Well off either way (the bounds are `time_window`'s): stale_time, signed, with time.
        for t_off in [-90, 90] {
            let (auth, sig) = dev.auth("audit/alarm", now + t_off, body);
            assert_signed_401(&t, &auth, &sig, body, "stale_time").await;
        }
        // An id hbbs does not know, and the empty placeholder of an id being registered.
        let ghost = Device::new("ghost01");
        let (auth, sig) = ghost.auth("audit/alarm", now, body);
        assert_signed_401(&t, &auth, &sig, body, "unknown_device").await;
        t.state.pm.insert_new("ghost01").await;
        assert_signed_401(&t, &auth, &sig, body, "unknown_device").await;
        // One byte of the body, or the endpoint, changed: bad_signature.
        let (auth, sig) = dev.auth("audit/alarm", now, body);
        let mut tampered = body.to_vec();
        tampered[2] = b'X';
        assert_signed_401(&t, &auth, &sig, &tampered, "bad_signature").await;
        let (auth2, sig2) = dev.auth("audit/file", now, body);
        assert_signed_401(&t, &auth2, &sig2, body, "bad_signature").await;
        // Another device's key: bad_signature too.
        let other = Device::new("chain01");
        let (auth3, sig3) = other.auth("audit/alarm", now, body);
        assert_signed_401(&t, &auth3, &sig3, body, "bad_signature").await;
        // The same request twice: the second is a replay.
        let (status, headers, raw) = send_porta(&t.app, "/api/porta/v1/audit/alarm", Some(&auth), body).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&raw));
        assert!(verify_server_sig(&t.state, &sig, &headers, &raw));
        assert_signed_401(&t, &auth, &sig, body, "replay").await;
    }

    /// Without a private key (`-k` gave a public key) answers carry no signature.
    #[tokio::test]
    async fn no_private_key_no_signature() {
        let mut t = testutil::app().await;
        t.state.sk = None;
        let app = crate::api::router(t.state.clone());
        let dev = porta_device(&t.state, "nosk01", b"uuid").await;
        let body = br#"{"typ":1}"#;
        let (auth, _) = dev.auth("audit/alarm", crate::common::now() as i64, body);
        let (status, headers, _) = send_porta(&app, "/api/porta/v1/audit/alarm", Some(&auth), body).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!headers.contains_key(SIG_HEADER));
    }

    #[test]
    fn time_window() {
        let now = 1_761_200_000;
        for t in [now - 60, now, now + 60] {
            assert!(fresh(t, now), "{}", t - now);
        }
        for t in [now - 61, now + 61, i64::MIN, i64::MAX] {
            assert!(!fresh(t, now), "{t}");
        }
    }

    fn sig_of(n: u8) -> [u8; 64] {
        [n; 64]
    }

    #[test]
    fn replay_window_and_ring() {
        let mut r = ReplayTable::default();
        let now = 1_000_000;
        assert!(r.accept("a", now, &sig_of(1), now));
        assert!(!r.accept("a", now, &sig_of(1), now), "same signature, same t");
        assert!(r.accept("a", now, &sig_of(2), now), "same second, another request");
        // Out of order by up to 30 s behind the newest: accepted; more: refused.
        assert!(r.accept("a", now + 20, &sig_of(3), now));
        assert!(r.accept("a", now - 10, &sig_of(4), now));
        assert!(!r.accept("a", now - 11, &sig_of(5), now), "31 s behind the newest");
        // A new entry's floor is now - 30.
        assert!(!r.accept("b", now - 30, &sig_of(1), now));
        assert!(r.accept("b", now - 29, &sig_of(1), now));

        // Past 64 signatures the oldest goes and the floor rises to its time.
        let mut r = ReplayTable::default();
        for i in 0..REPLAY_RING as i64 {
            assert!(r.accept("c", now + i / 8, &sig_of(i as u8), now));
        }
        assert_eq!(r.ids["c"].floor, now - MAX_REORDER);
        assert!(r.accept("c", now + 8, &sig_of(200), now));
        assert_eq!(r.ids["c"].floor, now, "the popped entry was at now");
        assert!(!r.accept("c", now, &sig_of(201), now), "at the floor: refused");
        assert!(r.accept("c", now + 1, &sig_of(202), now));
    }

    #[test]
    fn replay_table_evicts_the_longest_unseen() {
        let mut r = ReplayTable::default();
        let now = 1_000_000;
        for i in 0..MAX_REPLAY_IDS {
            // "id0" is seen last, "id1" longest ago.
            let seen = if i == 0 { now + 10 } else { now + i as i64 % 7 };
            assert!(r.accept(&format!("id{i}"), now, &sig_of(1), seen));
        }
        r.ids.get_mut("id1").unwrap().last_seen = now - 5;
        assert!(r.accept("new", now, &sig_of(1), now));
        assert_eq!(r.ids.len(), MAX_REPLAY_IDS);
        assert!(!r.ids.contains_key("id1") && r.ids.contains_key("id0") && r.ids.contains_key("new"));
    }

    async fn pinned_at(t: &testutil::TestApp, id: &str) -> Option<i64> {
        sqlx::query_scalar("select pk_pinned_at from peer where id = ?")
            .bind(id)
            .fetch_one(&t.state.db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn first_verified_request_pins_the_key() {
        let t = testutil::app().await;
        let dev = porta_device(&t.state, "pin001", b"uuid-pin").await;
        assert_eq!(pinned_at(&t, "pin001").await, None);
        let status = dev.post(&t.app, "audit/alarm", br#"{"typ":1}"#).await.status;
        assert_eq!(status, StatusCode::OK);
        assert!(pinned_at(&t, "pin001").await.is_some());
        let peer = t.state.pm.get_in_memory("pin001").await.unwrap();
        assert!(peer.read().await.pinned);
        // Loaded again from the database (after eviction), the entry is pinned too.
        t.state.pm.evict_idle(Duration::ZERO).await;
        let reloaded = t.state.pm.get_from_main("pin001").await.unwrap().unwrap();
        assert!(!std::sync::Arc::ptr_eq(&peer, &reloaded));
        assert!(reloaded.read().await.pinned);

        // The row's key changed behind the entry's back: the pin writes nothing, the request still
        // goes through (verified against the entry's key).
        let dev2 = porta_device(&t.state, "pin002", b"uuid-pin2").await;
        t.state.pm.get_from_main("pin002").await.unwrap().unwrap();
        sqlx::query("update peer set pk = ? where id = 'pin002'").bind(&[9u8; 32][..]).execute(&t.state.db).await.unwrap();
        let status = dev2.post(&t.app, "audit/alarm", br#"{"typ":1}"#).await.status;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(pinned_at(&t, "pin002").await, None);
        assert!(!t.state.pm.get_in_memory("pin002").await.unwrap().read().await.pinned);
    }

    /// The database guards the pin (contract 01 §3.4): a stale entry (read before the pin) cannot
    /// change the key; an address change goes through; a row deleted meanwhile is SERVER_ERROR.
    #[tokio::test]
    async fn update_pk_is_guarded_by_the_database() {
        let t = testutil::app().await;
        let pm = &t.state.pm;
        let dev = porta_device(&t.state, "guard01", b"uuid-guard").await;
        let addr: std::net::SocketAddr = "198.51.100.1:5000".parse().unwrap();
        let stale = pm.get_from_main("guard01").await.unwrap().unwrap();
        stale.write().await.info.ip = "198.51.100.1".to_owned();
        // Evicted, then loaded again by the API and pinned there: `stale` still says not pinned.
        pm.evict_idle(Duration::ZERO).await;
        let status = dev.post(&t.app, "audit/alarm", br#"{"typ":1}"#).await.status;
        assert_eq!(status, StatusCode::OK);
        assert!(!stale.read().await.pinned);
        let new_pk = hbb_common::bytes::Bytes::from(vec![3u8; 32]);
        let uuid = hbb_common::bytes::Bytes::from_static(b"uuid-guard");
        let res = pm
            .update_pk("guard01".into(), stale.clone(), addr, uuid.clone(), new_pk.clone(), "198.51.100.1".into())
            .await;
        assert_eq!(res, RegisterResult::UUID_MISMATCH);
        let row: Vec<u8> = sqlx::query_scalar("select pk from peer where id = 'guard01'").fetch_one(&t.state.db).await.unwrap();
        assert_eq!(row, dev.pk.0.to_vec());
        assert!(stale.read().await.pinned, "memory takes the row's pin");
        // The same key from another address: written.
        let res = pm
            .update_pk("guard01".into(), stale.clone(), "198.51.100.2:5000".parse().unwrap(), uuid.clone(), dev.pk.0.to_vec().into(), "198.51.100.2".into())
            .await;
        assert_eq!(res, RegisterResult::OK);
        // Row gone (`--forget` meanwhile): a key change is SERVER_ERROR, not UUID_MISMATCH.
        sqlx::query("delete from peer where id = 'guard01'").execute(&t.state.db).await.unwrap();
        stale.write().await.pinned = false;
        let res = pm.update_pk("guard01".into(), stale, addr, uuid, new_pk, "198.51.100.1".into()).await;
        assert_eq!(res, RegisterResult::SERVER_ERROR);
    }

    #[tokio::test]
    async fn porta_errors_are_json() {
        let v = porta_internal("x");
        assert_eq!(v.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(v.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"internal","message":"Server error"}"#);
    }
}
