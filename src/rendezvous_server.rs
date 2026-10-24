use crate::common::*;
use crate::conn_limit::ConnLimiter;
use crate::ice_signal::{self, Reason};
use crate::ice_stun;
use crate::conn_tracker::{
    clip, source_key, IceResult, PunchRequest, RelayRequest, RelayResponseInfo, Reply, ReplyKind,
    Signal,
};
use crate::peer::*;
use crate::router::RouteQuery;
use crate::state::AppState;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        register_pk_response::Result::{TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    tcp::{Encrypt, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    throttled_log, AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
}

const REG_TIMEOUT: i64 = 30_000;

// Limits on what unauthenticated peers can make the rendezvous ports hold (review A-1..A-5).
// Fixed, not configurable.
/// Largest frame on 21116/TCP and largest WebSocket message/frame on 21118. The biggest message a
/// client sends there is `PunchHoleRequest` with a WebRTC offer: current clients trickle it without
/// candidates (~1 KB, hbb_common `webrtc.rs` `trickle_endpoint`/`UDP_ENDPOINT_BUDGET`), older ones
/// sent the full SDP with every candidate, a few KB in base64. Everything else is under 1 KB.
const MAX_FRAME: usize = 16 * 1024;
/// Largest frame on 21115, where `OnlineRequest` carries a peer list. The client does not batch it:
/// the Flutter peer view sends every id of the open tab in one request (rustdesk
/// `flutter/lib/common/widgets/peers_view.dart` `_queryOnlines` → `src/client.rs`
/// `peer_online::query_online_states_`). An address book holds at most 5,000 peers: ~90 KB even
/// with 16-character ids (18 bytes each on the wire).
const MAX_ONLINE_FRAME: usize = 128 * 1024;
/// More ids than a `MAX_ONLINE_FRAME` frame holds when every id is at least 6 bytes (the shortest
/// `RegisterPk` accepts, so the shortest that can be online) plus 2 bytes of tag and length. A
/// request over it is dropped: it can only be padding (an empty id costs 2 bytes on the wire and
/// a 24-byte `String` once parsed).
const MAX_ONLINE_PEERS: usize = MAX_ONLINE_FRAME / 8;
const WS_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
/// tungstenite allocates the read buffer up front (128 KiB by default) for every connection.
const WS_READ_BUFFER: usize = 4 * 1024;
/// Concurrent connections on 21116 and on 21118, each; far above a personal deployment. Worst case
/// held (review C-2/C-15/C-27; 21116 measured on Linux): ~26 KB a connection on 21116 (`Framed`'s
/// 8 KB write buffer, its read buffer grown to a 16 KB frame, the task), ~53 MB in all; on 21118,
/// before the handshake completes, at most `WS_HANDSHAKE_MAX` + a 4 KB read chunk, after it ~4 KB
/// of read buffer + a 16 KB frame + up to 16 KB of a fragmented message being joined, ~74 MB.
const MAX_CONNS: usize = 2048;
/// Concurrent connections on 21115. One serves a single request and closes, but may hold a
/// 128 KB frame: ~136 KB a connection, ~35 MB at worst.
const MAX_ONLINE_CONNS: usize = 256;
/// New ids registered per minute from all sources together (new: neither in `PeerMap` nor in the
/// database), a backstop for `RegisterPk`s spread over many sources; each one is a `peer` row that
/// is never deleted, so at most ~29,000 a day under a sustained flood. A personal deployment adds a
/// few devices a day; a mass rollout's clients retry in their next registration rounds.
const NEW_IDS_PER_MIN: u32 = 20;
/// `IP_BLOCKER` entries (sources) at most. When full, a source without an entry gets none and is
/// let through to `NEW_IDS_PER_MIN` (fail-open on purpose: that cap bounds the table's growth).
const MAX_IP_BLOCKER_ENTRIES: usize = 65_536;
/// Upstream's per-source limits: `RegisterPk`s in an `IP_BLOCK_DUR` window, new ids in a day window.
const IP_REGS_PER_MIN: u32 = 30;
const IP_NEW_IDS_PER_DAY: usize = 300;
/// The timer of `IP_BLOCKER`/`IP_CHANGES` cleanup and `PeerMap` eviction.
const IP_MAPS_PURGE_INTERVAL: Duration = Duration::from_secs(300);
/// `PeerMap` entries without a registration for this long are dropped (`PeerMap::evict_idle`).
/// A day, so a night off does not count (review C-3): a peer back from eviction is asked for
/// `RegisterPk` again, within its source's ~30 a minute, so a company's machines behind one address
/// coming back together in the morning would come online over minutes. The map holds about the
/// `peer` rows, so keeping entries longer costs little.
const PEER_IDLE_EVICT: Duration = Duration::from_secs(24 * 3600);
/// Database lookups of `RegisterPk`s for ids not in memory, from all sources together: a second's
/// worth on average, a burst on top (review C-12). Each one is a query `io_loop` waits for, and
/// the per-source limits do not hold for many sources or a full `IP_BLOCKER`. After a restart
/// every device misses: 1,000 come back at once, more within seconds.
const LOOKUPS_PER_SEC: f64 = 200.0;
const LOOKUP_BURST: f64 = 1000.0;
/// STUN Binding answers from all sources together (contract 05 §2.11): at most ~148 KB/s reflected
/// (IPv6 with headers), each answer smaller than its request. When it is used up, nobody gets a
/// mapped address or a proof for that moment and ICE is left with host candidates (§9 item 11).
const STUN_PER_SEC: f64 = 1000.0;
const STUN_BURST: f64 = 1000.0;

/// A token bucket of `rate` a second, holding at most `burst`.
#[derive(Clone)]
struct LookupBudget {
    tokens: f64,
    at: Instant,
    rate: f64,
    burst: f64,
}

impl LookupBudget {
    fn with(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            at: Instant::now(),
            rate,
            burst,
        }
    }

    /// The `RegisterPk` lookup budget.
    fn new() -> Self {
        Self::with(LOOKUPS_PER_SEC, LOOKUP_BURST)
    }

    fn take(&mut self) -> bool {
        self.take_at(Instant::now())
    }

    fn take_at(&mut self, now: Instant) -> bool {
        let earned = now.saturating_duration_since(self.at).as_secs_f64() * self.rate;
        self.tokens = (self.tokens + earned).min(self.burst);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// Concurrent connections per rendezvous port (review A-4, `ConnLimiter`).
#[derive(Clone)]
struct ConnLimits {
    tcp: ConnLimiter,
    ws: ConnLimiter,
    online: ConnLimiter,
}

impl Default for ConnLimits {
    fn default() -> Self {
        Self {
            tcp: ConnLimiter::new(MAX_CONNS),
            ws: ConnLimiter::new(MAX_CONNS),
            online: ConnLimiter::new(MAX_ONLINE_CONNS),
        }
    }
}

/// Most bytes read from a 21118 connection before its WebSocket handshake completed (review C-2):
/// tungstenite buffers the request up to 64 KB, re-parsing all of it on every read. A client's
/// upgrade request, or one forwarded by nginx, is 1~2 KB.
const WS_HANDSHAKE_MAX: usize = 8 * 1024;

/// A 21118 connection whose reads fail once more than `WS_HANDSHAKE_MAX` bytes came in before
/// `handshaken` is set.
struct HandshakeCap {
    stream: TcpStream,
    read: usize,
    handshaken: bool,
}

impl AsyncRead for HandshakeCap {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.stream).poll_read(cx, buf);
        if !this.handshaken {
            this.read += buf.filled().len() - before;
            if this.read > WS_HANDSHAKE_MAX {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "WebSocket handshake too long",
                )));
            }
        }
        res
    }
}

impl AsyncWrite for HandshakeCap {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<HandshakeCap>, tungstenite::Message>;
enum Sink {
    /// With the sending half of the cipher once the client completed the KeyExchange.
    TcpStream(TcpStreamSink, Option<Encrypt>),
    Ws(WsSink),
}
type Sender = mpsc::Sender<Data>;
type Receiver = mpsc::Receiver<Data>;
/// Messages queued for `io_loop` to send over UDP (`Sender`). Connection tasks queue without
/// waiting and drop a message when the queue is full, so a stalled `io_loop` holds at most this
/// many (review C-13); forwarded messages are small (`RequestRelay`'s strings are cut, below).
const UDP_SEND_QUEUE: usize = 4096;
/// `RequestRelay`s one 21116/21118 connection may send; a client sends one per attempt, three at
/// most. Over it the connection is closed (review C-13).
const MAX_RELAY_REQUESTS: usize = 12;
/// Longest `uuid`, `token` and `switch_code` forwarded in a `RequestRelay`; the first two as
/// `conn_tracker` keeps them (`MAX_TEXT_LEN`): a uuid is 36 characters.
const MAX_RELAY_TEXT: usize = 64;
/// Longest `AddrMangle` encoding: a v6 address is 16 bytes of IP + 2 of port, a v4 one at most
/// 11 (hbb_common `AddrMangle::encode`). A longer value is not an address.
const MAX_MANGLED_ADDR: usize = 18;
/// LAN candidates relayed from `LocalAddr.leapgate_local_addrs`; a Leapgate client sends at most 8
/// (`client/LEAPGATE.md` §3.3).
const MAX_LAN_CANDIDATES: usize = 8;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);
/// ICE sessions of A's signaling connections (contract 05 §3.3.2): registered in A's connection
/// task, answered from B's, so shared; a std mutex, never held across an `await` (the bare `Mutex`
/// of this file is tokio's).
static ICE_SESSIONS: once_cell::sync::Lazy<std::sync::Mutex<ice_signal::Sessions<Sink>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(ice_signal::Sessions::new()));

// Store punch hole requests. Up to `MAX_PUNCH_REQUESTS` (default 100,000: ~21 MB with 9-digit
// ids, ~45 MB with 253-byte ones), not counted in the port buffers above; only requests with the
// licence key to an online peer are recorded.
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<VecDeque<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(VecDeque::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;
static PUNCH_REQ_MAX: Lazy<usize> =
    Lazy::new(|| get_arg("MAX_PUNCH_REQUESTS").parse().unwrap_or(100_000));

async fn record_punch_req(from_ip: String, to_ip: String, to_id: String) {
    let max = *PUNCH_REQ_MAX;
    if max == 0 { return; }
    let mut lock = PUNCH_REQS.lock().await;
    let mut dup = false;
    for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
        if e.from_ip == from_ip && e.to_id == to_id {
            if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
            break;
        }
    }
    if !dup {
        if lock.len() >= max { lock.pop_front(); }
        lock.push_back(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id });
    }
}

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    pm: PeerMap,
    tx: Sender,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
    state: AppState,
    conns: ConnLimits,
    /// `(window start, new ids)`, one-minute windows (`NEW_IDS_PER_MIN`). Only the instance
    /// running `io_loop` handles `RegisterPk`, so a plain field is enough.
    new_ids: (Instant, u32),
    /// `LOOKUPS_PER_SEC`, a plain field for the same reason.
    lookups: LookupBudget,
    /// `STUN_PER_SEC`: STUN is answered in `io_loop` only, too.
    stun: LookupBudget,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
    ConsoleListener,
}

impl RendezvousServer {
    pub fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        Self::start_with_bind(None, port, serial, key, rmem)
    }

    #[tokio::main(flavor = "multi_thread")]
    pub async fn start_with_bind(
        bind_addr: Option<IpAddr>,
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
    ) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key)?;
        if sk.is_none() {
            log::error!("No private key, so no KeyExchange: clients that have logged in will fail to connect; use `-k -` or `-k <base64 private key>`");
        }
        let nat_port = port - 1;
        let ws_port = port + 2;
        let db = crate::database::open(&crate::database::db_url(), true).await?;
        let cfg = crate::config::Config::from_args()?;
        let api_listen = cfg.api.listen_addr(port)?;
        let state = AppState::new(db, cfg, sk, std::path::Path::new(crate::crypto::SECRET_KEY_FILE)).await?;
        let pm = state.pm.clone();
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        let mut socket = create_udp_listener(bind_addr, port, rmem).await?;
        let (tx, mut rx) = mpsc::channel::<Data>(UDP_SEND_QUEUE);
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                mask,
                local_ip,
            }),
            state: state.clone(),
            conns: Default::default(),
            new_ids: (Instant::now(), 0),
            lookups: LookupBudget::new(),
            stun: LookupBudget::with(STUN_PER_SEC, STUN_BURST),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        let mut listener = create_tcp_listener(bind_addr, port).await?;
        let mut listener2 = create_tcp_listener(bind_addr, nat_port).await?;
        let mut listener3 = create_tcp_listener(bind_addr, ws_port).await?;
        let mut listener_console = listen_console(bind_addr, nat_port as _).await?;
        log::info!("Listening on tcp/udp {}", listener.local_addr()?);
        log::info!(
            "Listening on tcp {}, extra port for NAT test",
            listener2.local_addr()?
        );
        log::info!("Listening on websocket {}", listener3.local_addr()?);
        let api_listener = TcpListener::bind(api_listen).await?;
        log::info!("Listening on API {}", api_listener.local_addr()?);
        state.spawn_tasks();
        tokio::spawn(crate::api::serve(api_listener, state));
        let test_addr = get_arg("TEST_HBBS");
        if get_arg("ALWAYS_USE_RELAY").to_uppercase() == "Y" {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut listener_console,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(bind_addr, port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(bind_addr, port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(bind_addr, nat_port).await?;
                    }
                    LoopFailure::ConsoleListener => {
                        drop(listener_console.take());
                        listener_console = listen_console(bind_addr, nat_port as _).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(bind_addr, ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        listener_console: &mut Option<TcpListener>,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut purge_timer = interval(IP_MAPS_PURGE_INTERVAL);
        loop {
            tokio::select! {
                _ = purge_timer.tick() => {
                    purge_ip_maps().await;
                    // Here, not in a task of its own: serial with `handle_udp`, so it never runs
                    // between a `RegisterPk`'s lookup (`get`/`insert_new`) and its `update_pk`.
                    self.pm.evict_idle(PEER_IDLE_EVICT).await;
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = accept_or_pending(listener_console.as_ref()) => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("console listener.accept failed: {}", err);
                           return LoopFailure::ConsoleListener;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        key: &str,
    ) -> ResultType<()> {
        // STUN before protobuf (contract 05 §2.9.2): a protobuf message starts with a field tag,
        // never 0x00 or 0x01; the top-two-bits rule of STUN would also take `RegisterPeer` (0x32).
        if bytes.len() >= 20 && (bytes[0] == 0x00 || bytes[0] == 0x01) && bytes[4..8] == ice_stun::STUN_MAGIC {
            self.handle_stun(bytes, addr, socket).await;
            return Ok(());
        }
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() && rp.id.len() <= MAX_PEER_ID_LEN {
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        self.update_addr(rp.id, addr, socket).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    // Before anything else (review A-1/A-5): real clients send their 32-byte
                    // ed25519 public key (`Config::get_key_pair().1`) and `get_uuid()`. Anything
                    // else is dropped without a reply, a write or a log line.
                    if rk.pk.len() != sign::PUBLICKEYBYTES
                        || rk.uuid.is_empty()
                        || rk.uuid.len() > MAX_REG_UUID_LEN
                    {
                        return Ok(());
                    }
                    let id = rk.id;
                    let ip = addr.ip().to_string();
                    if id.len() < 6 || id.len() > MAX_PEER_ID_LEN {
                        return send_rk_res(socket, addr, UUID_MISMATCH).await;
                    } else if !self.check_ip_rate(addr.ip()).await {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    let peer = match self.pm.get_in_memory(&id).await {
                        Some(peer) => peer,
                        // Not in memory: costs a database lookup, within a global budget
                        // (review C-12). A dropped client is asked for `RegisterPk` again by its
                        // next `RegisterPeer`.
                        None if !self.lookups.take() => {
                            throttled_log!(
                                Duration::from_secs(60),
                                warn,
                                "RegisterPk: over {} database lookups a second, dropped one from {}",
                                LOOKUPS_PER_SEC,
                                ip
                            );
                            return Ok(());
                        }
                        None => match self.pm.get(&id).await {
                            Ok(Some(peer)) => peer,
                            // Not "no such id" (review C-22/U-1): dropped, the client retries.
                            Err(err) => {
                                throttled_log!(
                                    Duration::from_secs(60),
                                    warn,
                                    "RegisterPk: lookup of {:?} failed, dropped: {}",
                                    id,
                                    err
                                );
                                return Ok(());
                            }
                            Ok(None) => match self.check_new_id(addr.ip(), &id).await {
                                NewId::Allowed => self.pm.insert_new(&id).await,
                                NewId::SourceFull => {
                                    return send_rk_res(socket, addr, TOO_FREQUENT).await;
                                }
                                NewId::GlobalFull => {
                                    throttled_log!(
                                        Duration::from_secs(60),
                                        warn,
                                        "RegisterPk: over {} new ids a minute, dropped {:?} from {}",
                                        NEW_IDS_PER_MIN,
                                        id,
                                        ip
                                    );
                                    return Ok(());
                                }
                            },
                        },
                    };
                    // A key pinned by a signed report takes no other. Memory may be behind the
                    // database (`device key reset` changes the database only), so in this rare
                    // case the entry is reloaded first and the row decides.
                    let pinned_to_other = {
                        let p = peer.read().await;
                        p.pinned && p.pk != rk.pk
                    };
                    if pinned_to_other {
                        // A database read on `io_loop`: within the global budget (review C-12).
                        // Not answered from memory instead: after an unpinning memory may lag, and
                        // UUID_MISMATCH would make the client take a new id.
                        if !self.lookups.take() {
                            throttled_log!(
                                Duration::from_secs(60),
                                warn,
                                "RegisterPk: over {} database lookups a second, dropped a pinned-key check from {}",
                                LOOKUPS_PER_SEC,
                                ip
                            );
                            return Ok(());
                        }
                        match self.pm.reload(&id, &peer).await {
                            Ok(true) => {}
                            // Deleted (`--forget`): the next round registers the id as new.
                            Ok(false) => {
                                self.pm.remove(&id).await;
                                return send_rk_res(socket, addr, register_pk_response::Result::SERVER_ERROR)
                                    .await;
                            }
                            Err(err) => {
                                throttled_log!(
                                    Duration::from_secs(60),
                                    warn,
                                    "RegisterPk: reload of {:?} failed, dropped: {}",
                                    log_id(&id),
                                    err
                                );
                                return Ok(());
                            }
                        }
                        let p = peer.read().await;
                        if p.pinned && p.pk != rk.pk {
                            throttled_log!(
                                Duration::from_secs(60),
                                warn,
                                "Peer {:?} has a pinned key, refused another from {}",
                                log_id(&id),
                                ip
                            );
                            drop(p);
                            return send_rk_res(socket, addr, UUID_MISMATCH).await;
                        }
                    }
                    let (changed, ip_changed) = {
                        let peer = peer.read().await;
                        if peer.uuid.is_empty() {
                            (true, false)
                        } else {
                            if peer.uuid == rk.uuid {
                                if peer.info.ip != ip && peer.pk != rk.pk {
                                    throttled_log!(
                                        Duration::from_secs(60),
                                        warn,
                                        "Peer {:?} ip/pk mismatch: {} vs {}",
                                        log_id(&id),
                                        ip,
                                        peer.info.ip
                                    );
                                    drop(peer);
                                    return send_rk_res(socket, addr, UUID_MISMATCH).await;
                                }
                            } else {
                                throttled_log!(
                                    Duration::from_secs(60),
                                    warn,
                                    "Peer {:?} uuid mismatch from {} ({} bytes)",
                                    log_id(&id),
                                    ip,
                                    rk.uuid.len()
                                );
                                drop(peer);
                                return send_rk_res(socket, addr, UUID_MISMATCH).await;
                            }
                            let ip_changed = peer.info.ip != ip;
                            (
                                peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                                ip_changed,
                            )
                        }
                    };
                    let mut req_pk = peer.read().await.reg_pk;
                    if req_pk.1.elapsed().as_secs() > 6 {
                        req_pk.0 = 0;
                    } else if req_pk.0 > 2 {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    req_pk.0 += 1;
                    req_pk.1 = Instant::now();
                    peer.write().await.reg_pk = req_pk;
                    if ip_changed {
                        let mut lock = IP_CHANGES.lock().await;
                        if let Some((tm, ips)) = lock.get_mut(&id) {
                            if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                                *tm = Instant::now();
                                ips.clear();
                                ips.insert(ip.clone(), 1);
                            } else if let Some(v) = ips.get_mut(&ip) {
                                *v += 1;
                            } else {
                                ips.insert(ip.clone(), 1);
                            }
                        } else {
                            lock.insert(
                                id.clone(),
                                (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                            );
                        }
                    }
                    let res = if changed {
                        self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await
                    } else {
                        register_pk_response::Result::OK
                    };
                    send_rk_res(socket, addr, res).await?
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // UDP PunchHoleRequest is intentionally unsupported.
                    // The supported client path sends PunchHoleRequest over TCP/WS.
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    // UDP PunchHoleSent is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    // UDP LocalAddr is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// A STUN message on 21116/UDP (contract 05 §2.9.3, §3.4.3): a Binding request of at least
    /// 100 bytes gets the source's address and a proof of it, within `STUN_PER_SEC`; anything else
    /// is dropped. No lookup and nothing awaited but the send. A failed send is only logged: an
    /// error out of `handle_udp` would make `io_loop` rebuild the whole socket.
    async fn handle_stun(&mut self, bytes: &[u8], addr: SocketAddr, socket: &mut FramedSocket) {
        let Some(txid) = ice_stun::parse_binding_request(bytes) else {
            return;
        };
        if !self.stun.take() {
            throttled_log!(
                Duration::from_secs(60),
                warn,
                "leapgate ice: over {} STUN Binding requests a second, dropped some",
                STUN_PER_SEC
            );
            return;
        }
        // A dual-stack socket reports IPv4 sources as `::ffff:a.b.c.d`; the answer and the proof
        // carry the IPv4 address, the datagram goes back to `addr` as received.
        let src = try_into_v4(addr);
        let proof = ice_stun::seal(src, crate::common::now());
        let resp = ice_stun::binding_response(&txid, src, &proof);
        if let FramedSocket::Direct(f) = socket {
            allow_err!(f.send((Bytes::from(resp), addr)).await);
        }
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
        relay_requests: &mut usize,
        // The connection completed the KeyExchange.
        encrypted: bool,
        // The ICE session this connection registered.
        ice: &mut Option<[u8; 16]>,
    ) -> bool {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    allow_err!(self.handle_tcp_punch_hole_request(addr, ph, key, ws).await);
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    // Forwarded to B without a check of anything: bounded per connection, and its
                    // strings cut (review C-13).
                    *relay_requests += 1;
                    if *relay_requests > MAX_RELAY_REQUESTS {
                        return false;
                    }
                    clip(&mut rf.uuid, MAX_RELAY_TEXT);
                    clip(&mut rf.token, MAX_RELAY_TEXT);
                    clip(&mut rf.switch_code, MAX_RELAY_TEXT);
                    clip(&mut rf.relay_server, MAX_PEER_ID_LEN);
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    let peer = self.pm.get_in_memory(&rf.id).await;
                    // H5
                    self.state.tracker.on_request_relay(RelayRequest {
                        a_addr: try_into_v4(addr),
                        b_id: rf.id.clone(),
                        uuid: rf.uuid.clone(),
                        relay_server: rf.relay_server.clone(),
                        token: rf.token.clone(),
                        found_in_memory: peer.is_some(),
                        ws,
                    });
                    if let Some(peer) = peer {
                        let mut msg_out = RendezvousMessage::new();
                        // Only the fields clients set (rustdesk `client.rs` `request_relay`/
                        // `create_relay`; the licence key B does not need): what else came in,
                        // unknown fields included, would be forwarded at any length.
                        msg_out.set_request_relay(RequestRelay {
                            id: rf.id,
                            uuid: rf.uuid,
                            socket_addr: AddrMangle::encode(addr).into(),
                            relay_server: rf.relay_server,
                            secure: rf.secure,
                            conn_type: rf.conn_type,
                            token: rf.token,
                            switch_code: rf.switch_code,
                            ..Default::default()
                        });
                        let peer_addr = peer.read().await.socket_addr;
                        self.send_udp(msg_out, peer_addr);
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    // H4, before relay_server is rewritten
                    self.state.tracker.on_relay_response(RelayResponseInfo {
                        a_addr: try_into_v4(addr_b),
                        uuid: rr.uuid.clone(),
                        b_id: rr.id().to_owned(),
                        b_relay: rr.relay_server.clone(),
                        b_version: rr.version.clone(),
                        b_has_v6: !rr.socket_addr_v6.is_empty(),
                    });
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            // addr is B (the controlled side), addr_b is A
                            rr.relay_server = self
                                .state
                                .router
                                .select(&RouteQuery {
                                    a_ip: try_into_v4(addr_b).ip(),
                                    b_ip: try_into_v4(addr).ip(),
                                    a_id: "",
                                    b_id: "",
                                    a_token: "",
                                    conn_type: 0,
                                })
                                .await
                                .relay;
                        }
                    }
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::RegisterPk(_)) => {
                    let res = register_pk_response::Result::NOT_SUPPORT;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: res.into(),
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::LeapgateIce(m)) => {
                    return self.handle_ice(m, sink, addr, key, ws, encrypted, ice).await;
                }
                _ => {}
            }
        }
        false
    }

    /// `LeapgateIce` (contract 05 §2.3, §3.4.2), on 21116 after the KeyExchange only: anywhere else
    /// the connection is closed without a reply. Returns whether to keep the connection.
    async fn handle_ice(
        &mut self,
        m: LeapgateIce,
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
        encrypted: bool,
        ice: &mut Option<[u8; 16]>,
    ) -> bool {
        if !encrypted || ws {
            return false;
        }
        match m.union {
            // A's OFFER, or its resend on the same connection: the same FORWARD to where B is now.
            Some(leapgate_ice::Union::Offer(o)) => {
                if let Some(registered) = *ice {
                    if o.session[..] == registered {
                        let resend = ICE_SESSIONS.lock().unwrap().resend(&registered);
                        if let Some((forward, b_id)) = resend {
                            if let Some(peer) = self.pm.get_in_memory(&b_id).await {
                                let to = peer.read().await.socket_addr;
                                self.send_udp(forward, to);
                            }
                        }
                    }
                    return true;
                }
                let session = o.session.clone();
                let Err(reason) = self.ice_offer(m.ver, o, sink, addr, key, ice).await else {
                    return true;
                };
                if reason == Reason::BAD {
                    // Every frame may be one: throttled, no address.
                    throttled_log!(
                        Duration::from_secs(60),
                        warn,
                        "leapgate ice: OFFER refused: malformed, wrong key or a session in use"
                    );
                }
                Self::send_to_sink(sink, ice_signal::reject(session, reason.into())).await;
                false
            }
            // B's ANSWER: B's filtered candidates and B's signed IdPk to A; looked at before the
            // session is marked answered, so a refused one is removed, not left to be abandoned.
            Some(leapgate_ice::Union::Answer(a)) => {
                let Ok(session) = <[u8; 16]>::try_from(&a.session[..]) else {
                    return false;
                };
                let b_id = ICE_SESSIONS.lock().unwrap().peek_unanswered(&session);
                let Some(b_id) = b_id else {
                    return false;
                };
                let reply = match ice_signal::check_answer(m.ver, &a, crate::common::now()) {
                    Err(_) => Err(Reason::BAD),
                    Ok(params) => {
                        // Memory only; any non-empty version is signed.
                        let pk = self.get_pk("ice", b_id).await;
                        if pk.is_empty() {
                            Err(Reason::UNSUPPORTED)
                        } else {
                            Ok(ice_signal::answer(a.session.clone(), params, pk))
                        }
                    }
                };
                let (sink, msg) = match reply {
                    Ok(msg) => (ICE_SESSIONS.lock().unwrap().take_sink_for_answer(&session), msg),
                    Err(reason) => (
                        ICE_SESSIONS.lock().unwrap().drop_for_reject(&session),
                        ice_signal::reject(a.session, reason.into()),
                    ),
                };
                if sink.is_some() {
                    Self::send_to_sink(&mut { sink }, msg).await;
                }
                false
            }
            // B's REJECT, passed on to A as it came.
            Some(leapgate_ice::Union::Reject(r)) if m.ver == ice_signal::ICE_VER => {
                if let Ok(session) = <[u8; 16]>::try_from(&r.session[..]) {
                    let sink = ICE_SESSIONS.lock().unwrap().drop_for_reject(&session);
                    if sink.is_some() {
                        Self::send_to_sink(&mut { sink }, ice_signal::reject(r.session, r.reason)).await;
                    }
                }
                false
            }
            // A's RESULT for its own session, the first only; statistics, recorded in `ice_result`
            // (§3.7). Any other is ignored, the connection kept: A closes it once it has sent one.
            Some(leapgate_ice::Union::Result(r)) => {
                let own = ice.filter(|s| m.ver == ice_signal::ICE_VER && r.session[..] == s[..]);
                if let Some(session) = own {
                    let first = ICE_SESSIONS.lock().unwrap().mark_result(&session);
                    if let Some((a_ip, b_id)) = first {
                        self.state.tracker.on_ice_result(IceResult::from(&r, a_ip, b_id));
                    }
                }
                true
            }
            // A FORWARD goes to B only, over UDP.
            _ => false,
        }
    }

    /// §2.4 steps 1~5 for a new OFFER on this connection: on success the session is registered
    /// (holding A's sink) and the FORWARD queued for B; otherwise the reason to reject with, the
    /// sink still here.
    async fn ice_offer(
        &mut self,
        ver: u32,
        o: LeapgateIceOffer,
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ice: &mut Option<[u8; 16]>,
    ) -> Result<(), Reason> {
        let (session, params) =
            ice_signal::check_offer(ver, &o, key, crate::common::now()).map_err(|_| Reason::BAD)?;
        // Memory only: an online peer is in memory (`update_addr` makes no entry for one that is
        // not), and connection tasks stay off the database.
        let peer = self.pm.get_in_memory(&o.id).await.ok_or(Reason::OFFLINE)?;
        let (peer_addr, elapsed, pk, supports) = {
            let r = peer.read().await;
            (
                r.socket_addr,
                r.last_reg_time.elapsed().as_millis() as i64,
                r.pk.clone(),
                ice_signal::b_supports_ice(r.pinned, r.leapgate_hb.as_ref()),
            )
        };
        if elapsed >= REG_TIMEOUT {
            return Err(Reason::OFFLINE);
        }
        if ice_signal::forced_relay(
            ALWAYS_USE_RELAY.load(Ordering::SeqCst),
            self.is_lan(addr),
            self.is_lan(peer_addr),
        ) {
            return Err(Reason::RELAY);
        }
        let forward = match &self.state.sk {
            Some(sk) if supports => {
                ice_signal::forward(sk, &o.id, &pk, &session, params, crate::common::now())
            }
            _ => None,
        }
        .ok_or(Reason::UNSUPPORTED)?;
        let a_ip = try_into_v4(addr).ip();
        let registered =
            ICE_SESSIONS.lock().unwrap().register(session, sink, forward.clone(), o.id, a_ip);
        match registered {
            Ok(()) => {}
            Err(ice_signal::Refused::Duplicate) => return Err(Reason::BAD),
            Err(ice_signal::Refused::Busy) => return Err(Reason::BUSY),
        }
        *ice = Some(session);
        self.send_udp(forward, peer_addr);
        Ok(())
    }

    #[inline]
    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(&id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            // Throttled: anyone may send `RegisterPeer` for any id from another address, and every
            // such packet would log a line (review C-8).
            throttled_log!(
                Duration::from_secs(60),
                info,
                "IP change of {:?} from {} to {}",
                log_id(&id),
                old,
                socket_addr
            );
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        // H2
        self.state.tracker.on_reply(Reply {
            a_addr: try_into_v4(addr_a),
            kind: ReplyKind::PunchHoleSent,
            b_id: phs.id.clone(),
            b_relay: phs.relay_server.clone(),
            b_nat_type: phs.nat_type.value(),
            b_version: phs.version.clone(),
            b_has_v6: !phs.socket_addr_v6.is_empty(),
        });
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            socket_addr_v6: phs.socket_addr_v6,
            upnp_port: phs.upnp_port,
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        // H3
        self.state.tracker.on_reply(Reply {
            a_addr: try_into_v4(addr_a),
            kind: ReplyKind::LocalAddr,
            b_id: la.id.clone(),
            b_relay: la.relay_server.clone(),
            b_nat_type: 0,
            b_version: la.version.clone(),
            b_has_v6: !la.socket_addr_v6.is_empty(),
        });
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            socket_addr_v6: la.socket_addr_v6,
            // Leapgate clients' LAN candidates, passed on undecoded (`client/LEAPGATE.md` §3).
            leapgate_local_addrs: la
                .leapgate_local_addrs
                .into_iter()
                .filter(|a| a.len() <= MAX_MANGLED_ADDR)
                .take(MAX_LAN_CANDIDATES)
                .collect(),
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        // H1: one record per request, taken before `ph` is changed or moved
        let mut track = PunchRequest {
            a_addr: try_into_v4(addr),
            ws,
            token: ph.token.clone(),
            a_version: ph.version.clone(),
            b_id: ph.id.clone(),
            b_addr: None,
            conn_type: ph.conn_type.value(),
            nat_type: ph.nat_type.value(),
            force_relay: ph.force_relay,
            has_v6: !ph.socket_addr_v6.is_empty(),
            udp_port: ph.udp_port,
            signal: Signal::FailLicense,
            server_forced_relay: false,
            relay_offered: String::new(),
            route_reason: "",
            route_a_ms: None,
            route_b_ms: None,
        };
        if !key.is_empty() && ph.licence_key != key {
            // Throttled, the id cut: every frame of a connection may be such a request, with an
            // id as long as the frame (review C-1/C-7).
            throttled_log!(
                Duration::from_secs(60),
                warn,
                "Authentication failed from {} for peer {:?} ({} bytes) - invalid key",
                addr,
                log_id(&ph.id),
                ph.id.len()
            );
            self.state.tracker.on_punch_request(track);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        // Forwarded to B: an `AddrMangle` v6 address is 18 bytes, a longer one is not an address
        // (and would sit in `UDP_SEND_QUEUE` at any length, review C-13).
        if ph.socket_addr_v6.len() > MAX_MANGLED_ADDR {
            ph.socket_addr_v6 = Default::default();
        }
        let id = ph.id;
        // leapgate: A's own id (routing level two); an overlong one is no id
        let a_id = if ph.leapgate_from_id.len() <= MAX_PEER_ID_LEN { ph.leapgate_from_id.as_str() } else { "" };
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        // A failed lookup is not "no such id": no answer, the client times out and may retry.
        // Through the main pool: this runs in a connection task (review D-15, LEAPGATE.md §4.1).
        if let Some(peer) = self.pm.get_from_main(&id).await.inspect_err(|err| {
            throttled_log!(
                Duration::from_secs(60),
                warn,
                "PunchHoleRequest: lookup of {:?} failed: {}",
                log_id(&id),
                err
            );
        })? {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i64, r.socket_addr)
            };
            track.b_addr = Some(try_into_v4(peer_addr));
            if elapsed >= REG_TIMEOUT {
                track.signal = Signal::FailOffline;
                self.state.tracker.on_punch_request(track);
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            
            // record punch hole request (from addr -> peer id/peer_addr)
            record_punch_req(
                try_into_v4(addr).ip().to_string(),
                try_into_v4(peer_addr).ip().to_string(),
                id.clone(),
            )
            .await;

            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let route = self
                .state
                .router
                .select(&RouteQuery {
                    a_ip: try_into_v4(addr).ip(),
                    b_ip: try_into_v4(peer_addr).ip(),
                    a_id,
                    b_id: &id,
                    a_token: &ph.token,
                    conn_type: ph.conn_type.value(),
                })
                .await;
            let mut relay_server = route.relay;
            let forced_relay =
                ice_signal::forced_relay(ALWAYS_USE_RELAY.load(Ordering::SeqCst), is_lan, peer_is_lan);
            if forced_relay {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
                // B would punch v6 beside the relay and A race the two (note 02 §6.4)
                ph.socket_addr_v6 = Default::default();
                ph.force_relay = true;
            }
            let same_intranet: bool = !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            track.server_forced_relay = forced_relay;
            track.relay_offered = relay_server.clone();
            track.route_reason = route.reason;
            track.route_a_ms = route.a_ms;
            track.route_b_ms = route.b_ms;
            // udp_port and the WebRTC offer are not forwarded (LEAPGATE.md §6.2)
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                track.signal = Signal::FetchLocalAddr;
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    socket_addr_v6: ph.socket_addr_v6,
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                track.signal = Signal::PunchHole;
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    force_relay: ph.force_relay,
                    socket_addr_v6: ph.socket_addr_v6,
                    ..Default::default()
                });
            }
            self.state.tracker.on_punch_request(track);
            Ok((msg_out, Some(peer_addr)))
        } else {
            track.signal = Signal::FailIdNotExist;
            self.state.tracker.on_punch_request(track);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let mut tcp = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        tokio::spawn(async move {
            Self::send_to_sink(&mut tcp, msg).await;
        });
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            if let Ok(bytes) = msg.write_to_bytes() {
                match sink {
                    Sink::TcpStream(s, enc) => {
                        let bytes = match enc {
                            Some(enc) => enc.enc(&bytes),
                            None => bytes,
                        };
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }
                    Sink::Ws(ws) => {
                        allow_err!(ws.send(tungstenite::Message::Binary(bytes.into())).await);
                    }
                }
            }
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let mut sink = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        Self::send_to_sink(&mut sink, msg).await;
        Ok(())
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(addr) = to_addr {
            self.send_udp(msg, addr);
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    #[inline]
    async fn handle_udp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, false).await?;
        self.send_udp(
            msg,
            match to_addr {
                Some(addr) => addr,
                None => addr,
            },
        );
        Ok(())
    }

    /// Queues `msg` for `io_loop` to send to `addr` over UDP, or drops it when `UDP_SEND_QUEUE` is
    /// full (review C-13).
    fn send_udp(&self, msg: RendezvousMessage, addr: SocketAddr) {
        if let Err(mpsc::error::TrySendError::Full(_)) =
            self.tx.try_send(Data::Msg(msg.into(), addr))
        {
            throttled_log!(
                Duration::from_secs(60),
                warn,
                "UDP send queue full ({} messages): dropped one to {}",
                UDP_SEND_QUEUE,
                addr
            );
        }
    }

    /// Whether a new id may enter `PeerMap` this minute (`NEW_IDS_PER_MIN`).
    fn new_id_allowed(&mut self) -> bool {
        let (start, n) = &mut self.new_ids;
        if start.elapsed() >= Duration::from_secs(60) {
            *start = Instant::now();
            *n = 0;
        }
        if *n >= NEW_IDS_PER_MIN {
            return false;
        }
        *n += 1;
        true
    }

    /// Upstream's per-minute `RegisterPk` limit of `ip`'s source (`ip_rate_ok`).
    async fn check_ip_rate(&self, ip: IpAddr) -> bool {
        let src = source_key(ip.to_canonical());
        ip_rate_ok(&mut *IP_BLOCKER.lock().await, src, MAX_IP_BLOCKER_ENTRIES)
    }

    /// For an id neither `PeerMap` nor the database knows (`new_id_ok`).
    async fn check_new_id(&mut self, ip: IpAddr, id: &str) -> NewId {
        let src = source_key(ip.to_canonical());
        let mut lock = IP_BLOCKER.lock().await;
        new_id_ok(&mut lock, src, id, || self.new_id_allowed())
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "geo-update(gu)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>",
                    "key-reload(kl) <id>"
                )
            }
            // Not authenticated (any local process reaches the console), so it changes nothing:
            // memory takes what the database has (`device key reset` changes the database).
            Some(cmd @ ("key-reload" | "kl")) => {
                res = match fds.next().filter(|id| !id.is_empty()) {
                    Some(id) => self.pm.reload_from_main(id).await.unwrap_or_else(|err| format!("Failed: {err}\n")),
                    None => format!("{cmd} needs a device id\n"),
                };
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    // The list lives in the shared Router: replaced before the console answers.
                    self.state.router.set_configured(crate::config::parse_relay_list(rs));
                } else {
                    res = self.state.router.status_text();
                }
            }
            Some("geo-update" | "gu") => {
                res = self.state.router.geo_update().await;
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                retain_live_ip_blocks(&mut lock);
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        // Any address finds its source entry (an IPv6 address its /64).
                        let ip = ip
                            .parse::<IpAddr>()
                            .ok()
                            .map(|ip| source_key(ip.to_canonical()));
                        if let Some((a, b)) = ip.and_then(|ip| lock.get(&ip)) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if let (Some(ip), Some("-")) = (ip, fds.next()) {
                            lock.remove(&ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        let a = a.to_canonical();
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                // Optional device ids of A and B (routing level two), `-` for none.
                                let mut id = || fds.next().filter(|id| *id != "-").unwrap_or("");
                                let (a_id, b_id) = (id(), id());
                                res = self.state.router.test(a, b.to_canonical(), a_id, b_id).await;
                            }
                        } else {
                            res = self.state.router.test(a, a, "", "").await;
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        stream.write_all(res.as_bytes()).await.ok();
                    }
                }
            });
            return;
        }
        let Some(permit) = self.conns.online.try_acquire(addr.ip()) else {
            throttled_log!(
                Duration::from_secs(60),
                warn,
                "NAT test port: too many connections, closed one from {}",
                addr
            );
            return;
        };
        let mut stream = FramedStream::from(stream, addr);
        stream.codec_mut().set_max_packet_length(MAX_ONLINE_FRAME);
        tokio::spawn(async move {
            let _permit = permit;
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or))
                            if or.peers.len() <= MAX_ONLINE_PEERS =>
                        {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        // Closed before the KeyExchange offer (two signatures) when over the limit.
        let limiter = if ws { &self.conns.ws } else { &self.conns.tcp };
        let Some(permit) = limiter.try_acquire(addr.ip()) else {
            throttled_log!(
                Duration::from_secs(60),
                warn,
                "Rendezvous: too many connections, closed one from {} (ws: {})",
                addr,
                ws
            );
            return;
        };
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            let _permit = permit;
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let mut sink;
        let mut relay_requests = 0;
        let mut ice_session: Option<[u8; 16]> = None;
        if ws {
            use tokio_tungstenite::tungstenite::{
                handshake::server::{Request, Response},
                protocol::WebSocketConfig,
            };
            let callback = |req: &Request, response: Response| {
                addr = ws_client_addr(addr, req.headers());
                Ok(response)
            };
            let config = WebSocketConfig::default()
                .read_buffer_size(WS_READ_BUFFER)
                .max_message_size(Some(MAX_FRAME))
                .max_frame_size(Some(MAX_FRAME));
            // tungstenite bounds the handshake's size at 64 KB (`HandshakeCap` at less), not its
            // time.
            let stream = HandshakeCap {
                stream,
                read: 0,
                handshaken: false,
            };
            let mut ws_stream = timeout(
                WS_HANDSHAKE_TIMEOUT_MS,
                tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(config)),
            )
            .await??;
            ws_stream.get_mut().handshaken = true;
            let (a, mut b) = ws_stream.split();
            sink = Some(Sink::Ws(a));
            while let Ok(Some(Ok(msg))) = timeout(30_000, b.next()).await {
                if let tungstenite::Message::Binary(bytes) = msg {
                    // 21118 never encrypts.
                    if !self
                        .handle_tcp(
                            &bytes,
                            &mut sink,
                            addr,
                            key,
                            ws,
                            &mut relay_requests,
                            false,
                            &mut ice_session,
                        )
                        .await
                    {
                        break;
                    }
                }
            }
        } else {
            let mut codec = BytesCodec::new();
            codec.set_max_packet_length(MAX_FRAME);
            let (mut a, mut b) = Framed::new(stream, codec).split();
            // KeyExchange (note 02 §6.2): offer first; the client's first frame either answers
            // it or is a plaintext message from a client that skips the offer.
            let mut offer = None;
            if let Some(sk) = &self.state.sk {
                let (o, msg) = crate::kx::Offer::new(sk)?;
                a.send(Bytes::from(msg.write_to_bytes()?)).await?;
                offer = Some(o);
            }
            sink = Some(Sink::TcpStream(a, None));
            let mut dec: Option<Encrypt> = None;
            while let Ok(Some(Ok(mut bytes))) = timeout(30_000, b.next()).await {
                if let Some(offer) = offer.take() {
                    if let Ok(RendezvousMessage {
                        union: Some(rendezvous_message::Union::KeyExchange(ex)),
                        ..
                    }) = RendezvousMessage::parse_from_bytes(&bytes)
                    {
                        if ex.keys.len() == 2 {
                            match offer.accept(&ex) {
                                Ok(enc) => {
                                    if let Some(Sink::TcpStream(_, e)) = sink.as_mut() {
                                        *e = Some(enc.clone());
                                    }
                                    dec = Some(enc);
                                    continue;
                                }
                                Err(err) => {
                                    log::debug!("Key exchange with {:?} failed: {}", addr, err);
                                    break;
                                }
                            }
                        }
                    }
                }
                if let Some(dec) = dec.as_mut() {
                    if let Err(err) = dec.dec(&mut bytes) {
                        log::debug!("Tcp connection from {:?}: {}", addr, err);
                        break;
                    }
                }
                if !self
                    .handle_tcp(
                        &bytes,
                        &mut sink,
                        addr,
                        key,
                        ws,
                        &mut relay_requests,
                        dec.is_some(),
                        &mut ice_session,
                    )
                    .await
                {
                    break;
                }
            }
        }
        if sink.is_none() {
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        }
        // The session lives as long as A's signaling connection (contract 05 §2.3); one without a
        // RESULT is abandoned, recorded in `ice_result` (§3.7).
        if let Some(session) = ice_session {
            let closed = ICE_SESSIONS.lock().unwrap().close(&session);
            if let Some((a_ip, b_id, true)) = closed {
                self.state.tracker.on_ice_result(IceResult::abandoned(a_ip, b_id));
            }
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        let Some(sk) = self.state.sk.as_ref().filter(|_| !version.is_empty()) else {
            return Bytes::new();
        };
        // Memory only (review D-15): the callers relay B's answer to a request just forwarded
        // to it, so B is online, in memory; an id not there is signed nothing, without a lookup
        // (these connection tasks would queue `io_loop` on the rendezvous pool).
        match self.pm.get_in_memory(&id).await {
            Some(peer) => {
                let pk = peer.read().await.pk.clone();
                sign::sign(
                    &IdPk {
                        id,
                        pk,
                        ..Default::default()
                    }
                    .write_to_bytes()
                    .unwrap_or_default(),
                    sk,
                )
                .into()
            }
            None => Bytes::new(),
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> ResultType<(String, Option<sign::SecretKey>)> {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0)?;
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        Ok((key, out_sk))
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

/// The client address of a WebSocket (21118) connection from TCP peer `addr`.
/// X-Real-IP / X-Forwarded-For keep the real client IP behind a reverse proxy (WSS) on the
/// same host. They are only trusted from a loopback peer: anyone reaching this port directly
/// could spoof an arbitrary IP otherwise, which would steer relay selection and bypass
/// IP-based limits (LEAPGATE.md §6.5a).
/// https://github.com/rustdesk/rustdesk-server/issues/634
fn ws_client_addr(addr: SocketAddr, headers: &tungstenite::http::HeaderMap) -> SocketAddr {
    if !try_into_v4(addr).ip().is_loopback() {
        return addr;
    }
    let real_ip = headers
        .get("X-Real-IP")
        .or_else(|| headers.get("X-Forwarded-For"))
        .and_then(|header_value| header_value.to_str().ok());
    if let Some(ip) = real_ip {
        if ip.contains('.') {
            return format!("{ip}:0").parse().unwrap_or(addr);
        } else {
            return format!("[{ip}]:0").parse().unwrap_or(addr);
        }
    }
    addr
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

// Upstream's `RegisterPk` limits per source, counted per `source_key` (an IPv4 address, an IPv6
// /64: one IPv6 host holds a whole /64, so counting full addresses let it register without limit)
// and bounded in memory (review A-1): at most `MAX_IP_BLOCKER_ENTRIES` sources, and a source's id
// set only holds ids that were new to the server and got through `NEW_IDS_PER_MIN`, in a fixed day
// window (cleared when it ends, here or by `retain_live_ip_blocks`). So all sets together hold at
// most about a day of that cap: 20 × 1,440 ids.

/// About `IP_REGS_PER_MIN` `RegisterPk`s a minute from `src`. A source without an entry gets one if
/// there is room; otherwise it goes unlimited here (see `MAX_IP_BLOCKER_ENTRIES`).
fn ip_rate_ok(map: &mut IpBlockMap, src: IpAddr, max_entries: usize) -> bool {
    let now = Instant::now();
    if let Some(((n, tm), _)) = map.get_mut(&src) {
        if tm.elapsed().as_secs() > IP_BLOCK_DUR {
            *n = 0;
        } else if *n > IP_REGS_PER_MIN {
            return false;
        }
        *n += 1;
        *tm = now;
    } else if map.len() < max_entries {
        map.insert(src, ((0, now), (Default::default(), now)));
    } else {
        throttled_log!(
            Duration::from_secs(60),
            warn,
            "IP_BLOCKER is full ({} sources): {} goes without the per-source limits",
            max_entries,
            src
        );
    }
    true
}

#[derive(Debug, PartialEq)]
enum NewId {
    Allowed,
    /// Over the source's new ids of the day: `TOO_FREQUENT`, as upstream.
    SourceFull,
    /// Over `NEW_IDS_PER_MIN`: dropped without a reply.
    GlobalFull,
}

/// A new id from `src`: `IP_NEW_IDS_PER_DAY` per source, then the global cap (`global_ok`, only
/// asked once the source's limit passed); the id joins the source's set only when both pass.
fn new_id_ok(
    map: &mut IpBlockMap,
    src: IpAddr,
    id: &str,
    global_ok: impl FnOnce() -> bool,
) -> NewId {
    let Some((_, (ids, window))) = map.get_mut(&src) else {
        return if global_ok() {
            NewId::Allowed
        } else {
            NewId::GlobalFull
        };
    };
    if window.elapsed().as_secs() > DAY_SECONDS {
        *ids = Default::default();
        *window = Instant::now();
    }
    let is_new = !ids.contains(id);
    if is_new && ids.len() > IP_NEW_IDS_PER_DAY {
        return NewId::SourceFull;
    }
    if !global_ok() {
        return NewId::GlobalFull;
    }
    if is_new {
        ids.insert(id.to_owned());
    }
    NewId::Allowed
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

async fn create_udp_listener(
    bind_addr: Option<IpAddr>,
    port: i32,
    rmem: usize,
) -> ResultType<FramedSocket> {
    if let Some(bind_addr) = bind_addr {
        let addr = SocketAddr::new(bind_addr, port as _);
        return FramedSocket::new_reuse(&addr, true, rmem).await;
    }
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(bind_addr: Option<IpAddr>, port: i32) -> ResultType<TcpListener> {
    let s = listen_tcp(bind_addr, port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn_limit::MAX_CONNS_PER_SOURCE;

    #[hbb_common::tokio::test]
    async fn udp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = create_udp_listener(Some(bind_addr), 0, 0).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), bind_addr);
    }

    #[hbb_common::tokio::test]
    async fn punch_reqs_bounded() {
        let max = *PUNCH_REQ_MAX;
        // 31 ids keep every request just outside the 30-entry dedupe window;
        // one request at least, so MAX_PUNCH_REQUESTS=0 is exercised too
        for i in 0..(max * 2).max(1) {
            record_punch_req(
                "1.2.3.4".to_owned(),
                "5.6.7.8".to_owned(),
                format!("peer{}", i % 31),
            )
            .await;
        }
        let lock = PUNCH_REQS.lock().await;
        assert_eq!(lock.len(), max);
        if max > 0 {
            // the oldest half is evicted and the newest kept; punch tests running meanwhile add
            // their own entries (from loopback), each pushing one more of ours out
            let ours: Vec<&PunchReqEntry> = lock.iter().filter(|e| e.from_ip == "1.2.3.4").collect();
            let others = max - ours.len();
            assert_eq!(ours[0].to_id, format!("peer{}", (max + others) % 31));
            assert_eq!(ours[ours.len() - 1].to_id, format!("peer{}", (max * 2 - 1) % 31));
        }
    }

    // ---- Loopback rendezvous tests: a real 21116/TCP listener, clients written after
    // rustdesk:src/common.rs (`key_exchange`, the `rendezvous_stub` tests). ----

    const RELAY: &str = "relay.example:21117";

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Client {
        /// Skips the offer and talks in the clear (not logged in, or from before the exchange).
        Plain,
        /// Answers the offer the way clients from before version 1 do.
        V0,
        V1,
    }

    struct Harness {
        _app: crate::testutil::TestApp,
        rs: RendezvousServer,
        rx: Receiver,
        addr: SocketAddr,
        server_pk: sign::PublicKey,
    }

    async fn harness(with_sk: bool, mask: Option<Ipv4Network>) -> Harness {
        harness_with(with_sk, mask, Default::default()).await
    }

    async fn harness_with(with_sk: bool, mask: Option<Ipv4Network>, conns: ConnLimits) -> Harness {
        let app = crate::testutil::app().await;
        app.state.router.set_configured(vec![RELAY.to_owned()]);
        let (server_pk, sk) = sign::gen_keypair();
        let (tx, rx) = mpsc::channel(UDP_SEND_QUEUE);
        let mut state = app.state.clone();
        state.sk = with_sk.then(|| Arc::new(sk));
        let rs = RendezvousServer {
            tcp_punch: Default::default(),
            pm: app.state.pm.clone(),
            tx,
            rendezvous_servers: Default::default(),
            inner: Arc::new(Inner {
                serial: 0,
                version: String::new(),
                software_url: String::new(),
                mask,
                local_ip: String::new(),
            }),
            state,
            conns,
            new_ids: (Instant::now(), 0),
            lookups: LookupBudget::new(),
            stun: LookupBudget::with(STUN_PER_SEC, STUN_BURST),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = rs.clone();
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                server.handle_listener(stream, peer, "", false).await;
            }
        });
        Harness {
            _app: app,
            rs,
            rx,
            addr,
            server_pk,
        }
    }

    impl Harness {
        /// A connection to 21116/TCP, after the key exchange unless `Plain`.
        async fn connect(&self, client: Client) -> FramedStream {
            self.connect_at(self.addr, client).await
        }

        /// `connect` to a listener of its own (`listener_as`).
        async fn connect_at(&self, addr: SocketAddr, client: Client) -> FramedStream {
            let stream = TcpStream::connect(addr).await.unwrap();
            let local = stream.local_addr().unwrap();
            let mut conn = FramedStream::from(stream, local);
            if client != Client::Plain {
                let offer = conn.next_timeout(3000).await.unwrap().unwrap();
                let offer = RendezvousMessage::parse_from_bytes(&offer).unwrap();
                let (answer, enc) =
                    crate::kx::tests::client_answer(&offer, &self.server_pk, client == Client::V0);
                let mut msg = RendezvousMessage::new();
                msg.set_key_exchange(answer);
                conn.send(&msg).await.unwrap();
                conn.2 = Some(enc);
            }
            conn
        }

        /// B registered from `addr` just now.
        async fn online(&self, id: &str, addr: &str) {
            let peer = self.rs.pm.get_or(id).await;
            let mut w = peer.write().await;
            w.socket_addr = addr.parse().unwrap();
            w.last_reg_time = Instant::now();
        }

        /// What hbbs sends to B over UDP.
        async fn to_b(&mut self) -> (RendezvousMessage, SocketAddr) {
            let Data::Msg(msg, addr) = timeout(3000, self.rx.recv()).await.unwrap().unwrap();
            (*msg, addr)
        }
    }

    /// The next message other than the server's KeyExchange offer (`get_next_nonkeyexchange_msg`).
    async fn recv(conn: &mut FramedStream) -> RendezvousMessage {
        loop {
            let bytes = conn.next_timeout(3000).await.unwrap().unwrap();
            let msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
            if !matches!(msg.union, Some(rendezvous_message::Union::KeyExchange(_))) {
                return msg;
            }
        }
    }

    fn mangle(addr: &str) -> Bytes {
        AddrMangle::encode(addr.parse().unwrap()).into()
    }

    fn punch_request(id: &str) -> RendezvousMessage {
        let mut msg = RendezvousMessage::new();
        msg.set_punch_hole_request(PunchHoleRequest {
            id: id.to_owned(),
            nat_type: NatType::ASYMMETRIC.into(),
            token: "token".to_owned(),
            version: "1.4.2".to_owned(),
            udp_port: 1234,
            socket_addr_v6: mangle("[2001:db8::a]:40001"),
            webrtc_sdp_offer: "offer".to_owned(),
            ..Default::default()
        });
        msg
    }

    /// B answers over a fresh connection in the clear, without reading (as clients do).
    async fn b_sends(h: &Harness, msg: RendezvousMessage) -> SocketAddr {
        let stream = TcpStream::connect(h.addr).await.unwrap();
        let local = stream.local_addr().unwrap();
        let mut conn = FramedStream::from(stream, local);
        conn.send(&msg).await.unwrap();
        // Keep it open until the server has read it.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            drop(conn);
        });
        local
    }

    #[hbb_common::tokio::test]
    async fn key_exchange_then_messages() {
        let h = harness(true, None).await;
        for client in [Client::Plain, Client::V0, Client::V1] {
            let mut conn = h.connect(client).await;
            assert_eq!(conn.is_secured(), client != Client::Plain);
            let mut msg = RendezvousMessage::new();
            msg.set_test_nat_request(TestNatRequest::new());
            conn.send(&msg).await.unwrap();
            let Some(rendezvous_message::Union::TestNatResponse(res)) = recv(&mut conn).await.union
            else {
                panic!("{client:?}: expected TestNatResponse");
            };
            assert_eq!(res.port, conn.local_addr().port() as i32, "{client:?}");
            // Unknown peer: the failure comes back on the same (encrypted or plain) stream.
            let mut conn = h.connect(client).await;
            conn.send(&punch_request("nobody")).await.unwrap();
            let Some(rendezvous_message::Union::PunchHoleResponse(res)) = recv(&mut conn).await.union
            else {
                panic!("{client:?}: expected PunchHoleResponse");
            };
            assert_eq!(res.failure, punch_hole_response::Failure::ID_NOT_EXIST.into());
        }
    }

    #[hbb_common::tokio::test]
    async fn no_private_key_no_offer() {
        let h = harness(false, None).await;
        let mut conn = h.connect(Client::Plain).await;
        let mut msg = RendezvousMessage::new();
        msg.set_test_nat_request(TestNatRequest::new());
        conn.send(&msg).await.unwrap();
        // The first frame is the answer itself.
        let bytes = conn.next_timeout(3000).await.unwrap().unwrap();
        let msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
        assert!(matches!(
            msg.union,
            Some(rendezvous_message::Union::TestNatResponse(_))
        ));
    }

    #[hbb_common::tokio::test]
    async fn punch_hole_forwards_v6_both_ways() {
        let mut h = harness(true, None).await;
        h.online("B1", "8.8.8.8:5000").await;
        for client in [Client::Plain, Client::V0, Client::V1] {
            let mut a = h.connect(client).await;
            a.send(&punch_request("B1")).await.unwrap();
            let (msg, to) = h.to_b().await;
            assert_eq!(to, "8.8.8.8:5000".parse().unwrap());
            let Some(rendezvous_message::Union::PunchHole(ph)) = msg.union else {
                panic!("{client:?}: expected PunchHole");
            };
            assert_eq!(AddrMangle::decode(&ph.socket_addr), a.local_addr());
            assert_eq!(ph.socket_addr_v6, mangle("[2001:db8::a]:40001"));
            assert!(!ph.force_relay);
            assert_eq!(ph.nat_type, NatType::ASYMMETRIC.into());
            assert_eq!(ph.relay_server, RELAY);
            // Not forwarded: UDP punching and WebRTC.
            assert_eq!(ph.udp_port, 0);
            assert!(ph.webrtc_sdp_offer.is_empty());

            let mut sent = RendezvousMessage::new();
            sent.set_punch_hole_sent(PunchHoleSent {
                socket_addr: ph.socket_addr.clone(),
                id: "B1".to_owned(),
                relay_server: RELAY.to_owned(),
                nat_type: NatType::ASYMMETRIC.into(),
                version: "1.4.2".to_owned(),
                upnp_port: 7,
                socket_addr_v6: mangle("[2001:db8::b]:40002"),
                webrtc_sdp_answer: "answer".to_owned(),
                ..Default::default()
            });
            let b_addr = b_sends(&h, sent).await;
            let Some(rendezvous_message::Union::PunchHoleResponse(res)) = recv(&mut a).await.union
            else {
                panic!("{client:?}: expected PunchHoleResponse");
            };
            assert_eq!(AddrMangle::decode(&res.socket_addr), b_addr);
            assert_eq!(res.socket_addr_v6, mangle("[2001:db8::b]:40002"));
            assert_eq!(res.upnp_port, 7);
            assert_eq!(res.relay_server, RELAY);
            assert!(!res.pk.is_empty());
        }
    }

    #[hbb_common::tokio::test]
    async fn forced_relay_clears_v6() {
        // A (loopback) inside the mask, B outside: hbbs forces the relay.
        let mut h = harness(true, Some("127.0.0.0/8".parse().unwrap())).await;
        h.online("B1", "8.8.8.8:5000").await;
        let mut a = h.connect(Client::V1).await;
        a.send(&punch_request("B1")).await.unwrap();
        let (msg, _) = h.to_b().await;
        let Some(rendezvous_message::Union::PunchHole(ph)) = msg.union else {
            panic!("expected PunchHole");
        };
        assert!(ph.socket_addr_v6.is_empty());
        assert!(ph.force_relay);
        assert_eq!(ph.nat_type, NatType::SYMMETRIC.into());
        assert_eq!(ph.relay_server, RELAY);
    }

    #[hbb_common::tokio::test]
    async fn fetch_local_addr_forwards_v6() {
        // Same public IP as A: B is asked for its local address.
        let mut h = harness(true, None).await;
        h.online("B1", "127.0.0.1:5000").await;
        let mut a = h.connect(Client::V1).await;
        a.send(&punch_request("B1")).await.unwrap();
        let (msg, _) = h.to_b().await;
        let Some(rendezvous_message::Union::FetchLocalAddr(fla)) = msg.union else {
            panic!("expected FetchLocalAddr");
        };
        assert_eq!(fla.socket_addr_v6, mangle("[2001:db8::a]:40001"));
        assert_eq!(fla.relay_server, RELAY);

        let mut la = RendezvousMessage::new();
        la.set_local_addr(LocalAddr {
            socket_addr: fla.socket_addr.clone(),
            local_addr: mangle("192.168.1.2:21118"),
            relay_server: RELAY.to_owned(),
            id: "B1".to_owned(),
            version: "1.4.2".to_owned(),
            socket_addr_v6: mangle("[2001:db8::b]:40002"),
            ..Default::default()
        });
        b_sends(&h, la).await;
        let Some(rendezvous_message::Union::PunchHoleResponse(res)) = recv(&mut a).await.union else {
            panic!("expected PunchHoleResponse");
        };
        assert!(res.is_local());
        assert_eq!(AddrMangle::decode(&res.socket_addr), "192.168.1.2:21118".parse().unwrap());
        assert_eq!(res.socket_addr_v6, mangle("[2001:db8::b]:40002"));
        // An upstream client sends no candidates: none in the response either.
        assert!(res.leapgate_local_addrs.is_empty());
    }

    #[hbb_common::tokio::test]
    async fn local_addr_relays_lan_candidates() {
        let mut h = harness(true, None).await;
        h.online("B1", "127.0.0.1:5000").await;
        let mut a = h.connect(Client::V1).await;
        a.send(&punch_request("B1")).await.unwrap();
        let (msg, _) = h.to_b().await;
        let Some(rendezvous_message::Union::FetchLocalAddr(fla)) = msg.union else {
            panic!("expected FetchLocalAddr");
        };

        // 10 candidates, one of them 19 bytes long: it is dropped and the first 8 of the rest
        // arrive as sent (a v6 address, 18 bytes, is the longest kept).
        let mut sent: Vec<Bytes> = (1..=9)
            .map(|i| mangle(&format!("192.168.1.{i}:21118")))
            .collect();
        sent.insert(1, Bytes::from(vec![1u8; MAX_MANGLED_ADDR + 1]));
        sent[2] = mangle("[fd00::2]:21118");
        assert_eq!(sent[2].len(), MAX_MANGLED_ADDR);
        let mut la = RendezvousMessage::new();
        la.set_local_addr(LocalAddr {
            socket_addr: fla.socket_addr.clone(),
            local_addr: sent[0].clone(),
            id: "B1".to_owned(),
            version: "1.4.2".to_owned(),
            leapgate_local_addrs: sent.clone(),
            ..Default::default()
        });
        b_sends(&h, la).await;
        let Some(rendezvous_message::Union::PunchHoleResponse(res)) = recv(&mut a).await.union else {
            panic!("expected PunchHoleResponse");
        };
        assert!(res.is_local());
        assert_eq!(res.socket_addr, sent[0]);
        let mut expected = sent.clone();
        expected.remove(1);
        expected.truncate(MAX_LAN_CANDIDATES);
        assert_eq!(res.leapgate_local_addrs, expected);
    }

    #[test]
    fn ws_forwarded_headers_only_from_loopback() {
        let mut headers = tungstenite::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.9".parse().unwrap());
        let direct: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        assert_eq!(ws_client_addr(direct, &headers), direct);
        let mapped: SocketAddr = "[::ffff:198.51.100.1]:5000".parse().unwrap();
        assert_eq!(ws_client_addr(mapped, &headers), mapped);
        for proxy in ["127.0.0.1:5000", "[::1]:5000", "[::ffff:127.0.0.1]:5000"] {
            assert_eq!(
                ws_client_addr(proxy.parse().unwrap(), &headers),
                "203.0.113.9:0".parse().unwrap(),
                "{proxy}"
            );
        }
        headers.insert("X-Real-IP", "2001:db8::1".parse().unwrap());
        assert_eq!(
            ws_client_addr("127.0.0.1:5000".parse().unwrap(), &headers),
            "[2001:db8::1]:0".parse().unwrap()
        );
        assert_eq!(
            ws_client_addr("127.0.0.1:5000".parse().unwrap(), &Default::default()),
            "127.0.0.1:5000".parse().unwrap()
        );
    }

    #[hbb_common::tokio::test]
    async fn console_commands_use_the_router() {
        let h = harness(true, None).await;
        assert!(h.rs.check_cmd("rs").await.contains(RELAY));
        // Applied synchronously: the very next command already sees the new list.
        assert_eq!(h.rs.check_cmd("rs r1:21117,r2,r1:21117,").await, "");
        let status = h.rs.check_cmd("rs").await;
        assert!(status.contains("r1:21117") && status.contains("r2") && !status.contains(RELAY));
        let test = h.rs.check_cmd("tg 1.1.1.1 ::ffff:2.2.2.2").await;
        assert!(test.contains("r1:21117") || test.contains("r2"), "{test}");
        // aur no longer touches the relay list
        assert_eq!(h.rs.check_cmd("aur N").await, "");
        assert_eq!(h.rs.check_cmd("rs").await, status);
        // Device ids for level two: `-` is none, and none gives level one's output.
        let (rev, _) = h.rs.state.router.routing();
        let probes = serde_json::json!({"routing_rev": rev, "age_s": 0, "rtt": {"r1:21117": 12, "r2": 30}});
        h.rs.state.router.record_probes("dev-b", &probes);
        let test = h.rs.check_cmd("tg 1.1.1.1 2.2.2.2 - dev-b").await;
        assert!(test.contains("(rtt_b)") && test.contains("r1:21117: cost 24.0 [A est ?, B rtt 12ms]"), "{test}");
        let test = h.rs.check_cmd("tg 1.1.1.1 2.2.2.2 - -").await;
        assert!(test.contains("(rr)") && !test.contains("[A "), "{test}");
        assert!(h.rs.check_cmd("rs").await.ends_with("measurements: 1 devices, 1 fresh\n"));
    }

    /// Routing level two through a punch request: `leapgate_from_id` picks A's measurements, and the
    /// record gets the reason and both legs; an overlong `leapgate_from_id` counts as none.
    #[hbb_common::tokio::test]
    async fn punch_request_uses_both_measurements() {
        let mut h = harness(true, None).await;
        let router = &h.rs.state.router;
        let (rev, _) = router.routing();
        // (A round can't be stored under an overlong id; here it is, to tell "ignored" from "not found".)
        let long = format!("devA01{}", "x".repeat(MAX_PEER_ID_LEN));
        for (id, ms) in [("devA01", 15), ("devB01", 25), ("devB02", 35), (long.as_str(), 45)] {
            router.record_probes(id, &serde_json::json!({"routing_rev": rev, "age_s": 0, "rtt": {RELAY: ms}}));
        }
        h.online("devB01", "8.8.8.8:5000").await;
        h.online("devB02", "8.8.4.4:5000").await;
        for (b, from) in [("devB01", "devA01".to_owned()), ("devB02", long.clone())] {
            let mut msg = punch_request(b);
            msg.mut_punch_hole_request().leapgate_from_id = from;
            let mut a = h.connect(Client::V1).await;
            a.send(&msg).await.unwrap();
            let (msg, _) = h.to_b().await;
            assert!(matches!(msg.union, Some(rendezvous_message::Union::PunchHole(_))));
        }
        h.rs.state.tracker.flush().await;
        let rows: Vec<(String, String, Option<f64>, Option<f64>)> =
            sqlx::query_as("select b_id, route_reason, route_a_ms, route_b_ms from conn_attempt order by b_id")
                .fetch_all(&h.rs.state.db)
                .await
                .unwrap();
        assert_eq!(
            rows,
            [
                ("devB01".to_owned(), "rtt".to_owned(), Some(15.0), Some(25.0)),
                // The overlong id is not looked up: only B's measurement (A has no position here).
                ("devB02".to_owned(), "rtt_b".to_owned(), None, Some(35.0)),
            ]
        );
    }

    // ---- Limits on unauthenticated input (review A-1..A-5) ----

    /// The `BytesCodec` header announcing `n` bytes: 1~4 bytes, the low two bits are its length - 1.
    fn frame_head(n: usize) -> Vec<u8> {
        let v = n << 2;
        match n {
            0..=0x3F => vec![v as u8],
            0x40..=0x3FFF => (v as u16 | 1).to_le_bytes().to_vec(),
            0x4000..=0x3F_FFFF => (v as u32 | 2).to_le_bytes()[..3].to_vec(),
            _ => (v as u32 | 3).to_le_bytes().to_vec(),
        }
    }

    /// Panics unless the server closes `stream` within `ms` (whatever it sent before).
    async fn closed_within(stream: &mut TcpStream, ms: u64) {
        let mut buf = Vec::new();
        // Ok at EOF, Err on a reset: closed either way.
        let _ = timeout(ms, stream.read_to_end(&mut buf))
            .await
            .expect("the connection is still open");
    }

    #[hbb_common::tokio::test]
    async fn oversized_frame_closes_the_connection() {
        let h = harness(true, None).await;
        // A big WebRTC offer under the limit is still read and answered.
        let mut conn = h.connect(Client::Plain).await;
        let mut msg = punch_request("nobody");
        msg.mut_punch_hole_request().webrtc_sdp_offer = "o".repeat(MAX_FRAME - 200);
        let len = msg.write_to_bytes().unwrap().len();
        assert!(len <= MAX_FRAME && len > MAX_FRAME - 200, "{len}");
        conn.send(&msg).await.unwrap();
        let Some(rendezvous_message::Union::PunchHoleResponse(res)) = recv(&mut conn).await.union
        else {
            panic!("expected PunchHoleResponse");
        };
        assert_eq!(res.failure, punch_hole_response::Failure::ID_NOT_EXIST.into());
        // One byte over: refused on the header, the connection closes.
        let mut s = TcpStream::connect(h.addr).await.unwrap();
        s.write_all(&frame_head(MAX_FRAME + 1)).await.unwrap();
        closed_within(&mut s, 3000).await;
    }

    /// 21115 for a non-loopback source (from loopback it is the console).
    async fn online_port(h: &Harness) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let rs = h.rs.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                rs.handle_listener2(stream, "198.51.100.7:5000".parse().unwrap())
                    .await;
            }
        });
        addr
    }

    #[hbb_common::tokio::test]
    async fn online_request_frame_and_id_count_limits() {
        let h = harness(true, None).await;
        let port = online_port(&h).await;
        let request_ids = |peers: Vec<String>| {
            let mut msg = RendezvousMessage::new();
            msg.set_online_request(OnlineRequest {
                id: "A12345".to_owned(),
                peers,
                ..Default::default()
            });
            msg
        };
        let request = |n: usize| request_ids(vec!["1".to_owned(); n]);
        let connect = || async move {
            let s = TcpStream::connect(port).await.unwrap();
            let local = s.local_addr().unwrap();
            FramedStream::from(s, local)
        };
        // At the id limit (3 bytes each, well under the frame limit): answered, a bit per id.
        let mut conn = connect().await;
        conn.send(&request(MAX_ONLINE_PEERS)).await.unwrap();
        let Some(rendezvous_message::Union::OnlineResponse(res)) = recv(&mut conn).await.union else {
            panic!("expected OnlineResponse");
        };
        assert_eq!(res.states.len(), MAX_ONLINE_PEERS / 8);
        // A big address book: 6,500 ids of 16 characters, a ~117 KB frame, is answered.
        let ids: Vec<String> = (0..6500).map(|i| format!("id{i:014}")).collect();
        let msg = request_ids(ids);
        let len = msg.write_to_bytes().unwrap().len();
        assert!(len > 112 * 1024 && len <= MAX_ONLINE_FRAME, "{len}");
        let mut conn = connect().await;
        conn.send(&msg).await.unwrap();
        let Some(rendezvous_message::Union::OnlineResponse(res)) = recv(&mut conn).await.union else {
            panic!("expected OnlineResponse");
        };
        assert_eq!(res.states.len(), 6500usize.div_ceil(8));
        // One id more than the limit: dropped without an answer.
        let mut conn = connect().await;
        conn.send(&request(MAX_ONLINE_PEERS + 1)).await.unwrap();
        let next = timeout(3000, conn.next()).await.expect("the connection is still open");
        assert!(next.is_none(), "{next:?}");
        // A frame over the limit closes the connection.
        let mut s = TcpStream::connect(port).await.unwrap();
        s.write_all(&frame_head(MAX_ONLINE_FRAME + 1)).await.unwrap();
        closed_within(&mut s, 3000).await;
    }

    fn register_pk(id: &str, uuid: &[u8], pk: &[u8]) -> BytesMut {
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: uuid.to_vec().into(),
            pk: pk.to_vec().into(),
            ..Default::default()
        });
        BytesMut::from(&msg.write_to_bytes().unwrap()[..])
    }

    async fn peer_rows(h: &Harness, id: &str) -> i64 {
        sqlx::query_scalar("select count(*) from peer where id = ?")
            .bind(id)
            .fetch_one(&h.rs.state.db)
            .await
            .unwrap()
    }

    async fn register_reply(client: &mut FramedSocket) -> Option<register_pk_response::Result> {
        let (bytes, _) = client.next_timeout(500).await?.unwrap();
        match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
            Some(rendezvous_message::Union::RegisterPkResponse(r)) => {
                Some(r.result.enum_value().unwrap())
            }
            other => panic!("{other:?}"),
        }
    }

    #[hbb_common::tokio::test]
    async fn register_pk_needs_a_32_byte_pk_and_a_bounded_uuid() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut client = FramedSocket::new("127.20.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        let pk = [7u8; 32];
        let cases: [(&str, &[u8], &[u8]); 4] = [
            ("pkshort", b"uuid", &pk[..31]),
            ("pklong", b"uuid", &[7u8; 33]),
            ("uuidlong", &[1u8; MAX_REG_UUID_LEN + 1], &pk),
            ("uuidnone", b"", &pk),
        ];
        for (id, uuid, pk) in cases {
            h.rs.handle_udp(&register_pk(id, uuid, pk), from, &mut server, "")
                .await
                .unwrap();
            assert_eq!(register_reply(&mut client).await, None, "{id}: no reply");
            assert!(!h.rs.pm.is_in_memory(id).await, "{id}");
            assert_eq!(peer_rows(&h, id).await, 0, "{id}");
        }
        // At the bounds: registered.
        h.rs.handle_udp(&register_pk("uuidmax", &[1u8; MAX_REG_UUID_LEN], &pk), from, &mut server, "")
            .await
            .unwrap();
        assert_eq!(register_reply(&mut client).await, Some(register_pk_response::Result::OK));
        assert!(h.rs.pm.is_in_memory("uuidmax").await);
        assert_eq!(peer_rows(&h, "uuidmax").await, 1);
    }

    #[hbb_common::tokio::test]
    async fn register_pk_new_ids_capped_per_minute() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let pk = [7u8; 32];
        // 20 new ids from each of 6 sources (under the per-source limit): 120 in all.
        for n in 0..120 {
            let from = format!("127.21.0.{}:9", n / 20 + 1).parse().unwrap();
            h.rs.handle_udp(&register_pk(&format!("newid{n}"), b"uuid", &pk), from, &mut server, "")
                .await
                .unwrap();
        }
        let mut registered = 0;
        for n in 0..120 {
            if h.rs.pm.is_in_memory(&format!("newid{n}")).await {
                registered += 1;
            }
        }
        assert_eq!(registered, NEW_IDS_PER_MIN);
        let (last, over) = (format!("newid{}", NEW_IDS_PER_MIN - 1), format!("newid{NEW_IDS_PER_MIN}"));
        assert!(h.rs.pm.is_in_memory(&last).await && !h.rs.pm.is_in_memory(&over).await);
        assert_eq!(peer_rows(&h, &over).await, 0);
        // Over the cap, ids the server knows still register: one only in the database too.
        h.rs.pm.db.insert_peer("known1", b"uuid", &pk, "{}").await.unwrap();
        let mut client = FramedSocket::new("127.21.0.7:0").await.unwrap();
        let from = client.local_addr().unwrap();
        for id in ["newid0", "known1"] {
            h.rs.handle_udp(&register_pk(id, b"uuid", &pk), from, &mut server, "")
                .await
                .unwrap();
            assert_eq!(register_reply(&mut client).await, Some(register_pk_response::Result::OK), "{id}");
        }
        h.rs.handle_udp(&register_pk("newid200", b"uuid", &pk), from, &mut server, "")
            .await
            .unwrap();
        assert_eq!(register_reply(&mut client).await, None, "a new id is dropped");
    }

    #[hbb_common::tokio::test]
    async fn ip_blocker_counts_an_ipv6_64_as_one_source() {
        let h = harness(true, None).await;
        let addrs: [IpAddr; 2] = ["2001:db8:a1:1::1".parse().unwrap(), "2001:db8:a1:1:ffff::2".parse().unwrap()];
        // Alternating addresses of one /64 share upstream's budget: the first call only creates
        // the entry, then 31 more pass.
        let mut passed = 0;
        while h.rs.check_ip_rate(addrs[passed % 2]).await {
            passed += 1;
            assert!(passed < 100);
        }
        assert_eq!(passed, 32);
        assert!(h.rs.check_ip_rate("2001:db8:a1:2::1".parse().unwrap()).await);
        // An IPv4 client on the dual-stack socket counts as its IPv4 address, not as ::ffff:0:0/64.
        let mapped: IpAddr = "::ffff:198.51.100.21".parse().unwrap();
        assert!(h.rs.check_ip_rate(mapped).await);
        assert!(IP_BLOCKER
            .lock()
            .await
            .contains_key(&"198.51.100.21".parse::<IpAddr>().unwrap()));
    }

    #[hbb_common::tokio::test]
    async fn ip_blocker_id_set_holds_only_new_ids() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut client = FramedSocket::new("127.22.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        let pk = [7u8; 32];
        h.rs.pm.db.insert_peer("setold1", b"uuid", &pk, "{}").await.unwrap();
        for id in ["setnew1", "setold1", "setnew1"] {
            h.rs.handle_udp(&register_pk(id, b"uuid", &pk), from, &mut server, "")
                .await
                .unwrap();
            assert_eq!(register_reply(&mut client).await, Some(register_pk_response::Result::OK), "{id}");
        }
        let lock = IP_BLOCKER.lock().await;
        let ids = &lock[&"127.22.0.1".parse::<IpAddr>().unwrap()].1 .0;
        assert_eq!(ids.len(), 1);
        assert!(ids.contains("setnew1"), "{ids:?}");
    }

    #[test]
    fn ip_blocker_full_lets_new_sources_through_to_the_global_cap() {
        let mut map = IpBlockMap::new();
        let src = |s: &str| s.parse::<IpAddr>().unwrap();
        let (a, b, c) = (src("198.51.100.1"), src("198.51.100.2"), src("198.51.100.3"));
        assert!(ip_rate_ok(&mut map, a, 2) && ip_rate_ok(&mut map, b, 2));
        // Full: a third source gets no entry, so no per-source limits...
        for _ in 0..100 {
            assert!(ip_rate_ok(&mut map, c, 2));
        }
        assert_eq!(map.len(), 2);
        // ...but its new ids still go through the global cap.
        assert_eq!(new_id_ok(&mut map, c, "fullnew1", || false), NewId::GlobalFull);
        assert_eq!(new_id_ok(&mut map, c, "fullnew1", || true), NewId::Allowed);
        assert_eq!(map.len(), 2);
        // With an entry: an id the global cap refuses joins no set...
        assert_eq!(new_id_ok(&mut map, a, "a0", || false), NewId::GlobalFull);
        assert!(map[&a].1 .0.is_empty());
        // ...and the global cap is only asked once the source's day limit passed.
        for i in 0..=IP_NEW_IDS_PER_DAY {
            assert_eq!(new_id_ok(&mut map, a, &format!("a{i}"), || true), NewId::Allowed);
        }
        assert_eq!(
            new_id_ok(&mut map, a, "aover", || panic!("asked the global cap")),
            NewId::SourceFull
        );
        // An id already in the set is not new to the source.
        assert_eq!(new_id_ok(&mut map, a, "a0", || true), NewId::Allowed);
        assert_eq!(map[&a].1 .0.len(), IP_NEW_IDS_PER_DAY + 1);
    }

    #[hbb_common::tokio::test]
    async fn idle_peer_evicted_then_reloaded_from_the_database() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut client = FramedSocket::new("127.23.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        let pk = [9u8; 32];
        let register = |uuid: &'static [u8]| register_pk("evict1", uuid, &pk);
        h.rs.handle_udp(&register(b"uuid-evict"), from, &mut server, "")
            .await
            .unwrap();
        assert_eq!(register_reply(&mut client).await, Some(register_pk_response::Result::OK));
        h.rs.pm.evict_idle(PEER_IDLE_EVICT).await;
        assert!(h.rs.pm.is_in_memory("evict1").await, "registered just now: kept");
        h.rs.pm.evict_idle(Duration::ZERO).await;
        assert!(!h.rs.pm.is_in_memory("evict1").await);
        let peer = h.rs.pm.get("evict1").await.unwrap().expect("reloaded from the database");
        {
            let p = peer.read().await;
            assert_eq!((&p.uuid[..], &p.pk[..]), (&b"uuid-evict"[..], &pk[..]));
            assert_eq!(p.info.ip, from.ip().to_string());
        }
        // Registering again works as before eviction: the same uuid is accepted, another refused.
        h.rs.pm.evict_idle(Duration::ZERO).await;
        h.rs.handle_udp(&register(b"uuid-evict"), from, &mut server, "")
            .await
            .unwrap();
        assert_eq!(register_reply(&mut client).await, Some(register_pk_response::Result::OK));
        h.rs.pm.evict_idle(Duration::ZERO).await;
        h.rs.handle_udp(&register(b"other-uuid"), from, &mut server, "")
            .await
            .unwrap();
        assert_eq!(register_reply(&mut client).await, Some(UUID_MISMATCH));
    }

    /// Review C-22/U-1: with the database failing (the rendezvous pool closed), `RegisterPk` takes
    /// no id over and answers no OK, memory keeps what it had, and nothing is signed.
    #[hbb_common::tokio::test]
    async fn database_errors_change_nothing() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut client = FramedSocket::new("127.24.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        let (pk, pk2) = ([5u8; 32], [6u8; 32]);
        // dbfail1 is only in the database (idle, evicted); dbfail2 is in memory too.
        for id in ["dbfail1", "dbfail2"] {
            h.rs.pm.evict_idle(Duration::ZERO).await;
            h.rs.handle_udp(&register_pk(id, b"uuid-real", &pk), from, &mut server, "")
                .await
                .unwrap();
            assert_eq!(register_reply(&mut client).await, Some(register_pk_response::Result::OK), "{id}");
        }
        assert!(!h.rs.pm.is_in_memory("dbfail1").await && h.rs.pm.is_in_memory("dbfail2").await);
        // `get_pk` reads memory only (review D-15/E-10): with both pools still open, a lookup
        // through either would find dbfail1, load it into memory and sign it.
        assert!(h.rs.get_pk("1.4.2", "dbfail1".to_owned()).await.is_empty());
        assert!(!h.rs.pm.is_in_memory("dbfail1").await);
        h.rs.pm.db.close().await;

        // A known id the lookup cannot confirm, and a new one: dropped, nothing added.
        for (id, uuid) in [("dbfail1", &b"uuid-other"[..]), ("dbfail3", b"uuid-new")] {
            h.rs.handle_udp(&register_pk(id, uuid, &pk2), from, &mut server, "")
                .await
                .unwrap();
            assert_eq!(register_reply(&mut client).await, None, "{id}");
            assert!(!h.rs.pm.is_in_memory(id).await, "{id}");
        }
        // A pk change the database does not take: SERVER_ERROR, memory unchanged.
        h.rs.handle_udp(&register_pk("dbfail2", b"uuid-real", &pk2), from, &mut server, "")
            .await
            .unwrap();
        assert_eq!(
            register_reply(&mut client).await,
            Some(register_pk_response::Result::SERVER_ERROR)
        );
        {
            let p = h.rs.pm.get_in_memory("dbfail2").await.unwrap();
            let p = p.read().await;
            assert_eq!((&p.uuid[..], &p.pk[..]), (&b"uuid-real"[..], &pk[..]));
        }
        // With the database failing dbfail1 is still signed nothing (review C-22); dbfail2, in
        // memory, is signed.
        assert!(h.rs.get_pk("1.4.2", "dbfail1".to_owned()).await.is_empty());
        assert!(!h.rs.get_pk("1.4.2", "dbfail2".to_owned()).await.is_empty());
        // The rows are as registered (read through the API's pool, still open).
        let rows: Vec<(String, Vec<u8>, Vec<u8>)> =
            sqlx::query_as("select id, uuid, pk from peer where id like 'dbfail%' order by id")
                .fetch_all(&h.rs.state.db)
                .await
                .unwrap();
        assert_eq!(
            rows,
            ["dbfail1", "dbfail2"].map(|id| (id.to_owned(), b"uuid-real".to_vec(), pk.to_vec()))
        );
    }

    /// Review D-12: a device that only changed address (same uuid and pk) is registered at the new
    /// one even when the database write fails: OK, memory updated, the row left as it was.
    #[hbb_common::tokio::test]
    async fn ip_change_registers_without_the_database() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut old = FramedSocket::new("127.24.2.1:0").await.unwrap();
        let mut new = FramedSocket::new("127.24.2.2:0").await.unwrap();
        let (from_old, from_new) = (old.local_addr().unwrap(), new.local_addr().unwrap());
        let pk = [4u8; 32];
        h.rs.handle_udp(&register_pk("ipchg1", b"uuid-ipchg", &pk), from_old, &mut server, "")
            .await
            .unwrap();
        assert_eq!(register_reply(&mut old).await, Some(register_pk_response::Result::OK));
        let peer = h.rs.pm.get_in_memory("ipchg1").await.unwrap();
        peer.write().await.last_reg_time = Instant::now() - Duration::from_secs(25);
        h.rs.pm.db.close().await;

        h.rs.handle_udp(&register_pk("ipchg1", b"uuid-ipchg", &pk), from_new, &mut server, "")
            .await
            .unwrap();
        assert_eq!(register_reply(&mut new).await, Some(register_pk_response::Result::OK));
        {
            let p = peer.read().await;
            assert_eq!(p.socket_addr, from_new);
            assert_eq!(p.info.ip, from_new.ip().to_string());
            assert!(p.last_reg_time.elapsed() < Duration::from_secs(5));
        }
        let info: String = sqlx::query_scalar("select info from peer where id = 'ipchg1'")
            .fetch_one(&h.rs.state.db)
            .await
            .unwrap();
        assert!(info.contains(&from_old.ip().to_string()), "{info}");
        // A pk change with the same failing database is still refused, memory unchanged.
        h.rs.handle_udp(&register_pk("ipchg1", b"uuid-ipchg", &[5u8; 32]), from_new, &mut server, "")
            .await
            .unwrap();
        assert_eq!(
            register_reply(&mut new).await,
            Some(register_pk_response::Result::SERVER_ERROR)
        );
        assert_eq!(&peer.read().await.pk[..], &pk[..]);
    }

    /// Review U-1: an id added to the database after the lookup found nothing (the command line, an
    /// import) is not registered under another uuid: the row is loaded and decides the retry.
    #[hbb_common::tokio::test]
    async fn id_added_meanwhile_is_judged_by_its_row() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut client = FramedSocket::new("127.24.1.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        let (pk_row, pk_other) = ([7u8; 32], [8u8; 32]);
        h.rs.pm.insert_new("dupid1").await;
        let info = format!(r#"{{"ip":"{}"}}"#, from.ip());
        h.rs.pm.db.insert_peer("dupid1", b"uuid-row", &pk_row, &info).await.unwrap();
        let cases: [(&[u8], [u8; 32], _); 3] = [
            (b"uuid-other", pk_other, register_pk_response::Result::SERVER_ERROR),
            (b"uuid-other", pk_other, UUID_MISMATCH),
            (b"uuid-row", pk_row, register_pk_response::Result::OK),
        ];
        for (uuid, pk, expected) in cases {
            h.rs.handle_udp(&register_pk("dupid1", uuid, &pk), from, &mut server, "")
                .await
                .unwrap();
            assert_eq!(register_reply(&mut client).await, Some(expected));
        }
    }

    /// Review C-12: `RegisterPk`s for ids not in memory are looked up within a global budget; over
    /// it they are dropped without a reply or a lookup.
    #[hbb_common::tokio::test]
    async fn register_pk_misses_within_the_lookup_budget() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut client = FramedSocket::new("127.25.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        let pk = [9u8; 32];
        h.rs.pm.db.insert_peer("budget1", b"uuid", &pk, "{}").await.unwrap();
        // Empty, and stamped a second ahead: nothing is earned however long this thread pauses
        // (review D-23: `take` earns nothing before `at`).
        h.rs.lookups.tokens = 0.0;
        h.rs.lookups.at = Instant::now() + Duration::from_secs(1);
        h.rs.handle_udp(&register_pk("budget1", b"uuid", &pk), from, &mut server, "")
            .await
            .unwrap();
        assert_eq!(register_reply(&mut client).await, None);
        assert!(!h.rs.pm.is_in_memory("budget1").await);
        h.rs.lookups = LookupBudget::new();
        h.rs.handle_udp(&register_pk("budget1", b"uuid", &pk), from, &mut server, "")
            .await
            .unwrap();
        assert_eq!(register_reply(&mut client).await, Some(register_pk_response::Result::OK));
        // A burst, then `LOOKUPS_PER_SEC`, on a fixed clock.
        let mut b = LookupBudget::new();
        let t0 = b.at;
        assert_eq!((0..2000).filter(|_| b.take_at(t0)).count(), LOOKUP_BURST as usize);
        let t1 = t0 + Duration::from_millis(100);
        assert_eq!((0..2000).filter(|_| b.take_at(t1)).count(), (LOOKUPS_PER_SEC / 10.0) as usize);
    }

    /// Contract 05 §3.2.1: STUN has a bucket of its own, a burst of 1,000 and then 1,000 a second
    /// (the lookup budget keeps its values, above).
    #[test]
    fn stun_budget_is_a_bucket_of_its_own() {
        let mut b = LookupBudget::with(STUN_PER_SEC, STUN_BURST);
        let t0 = b.at;
        assert_eq!((0..3000).filter(|_| b.take_at(t0)).count(), 1000);
        let t1 = t0 + Duration::from_millis(100);
        assert_eq!((0..3000).filter(|_| b.take_at(t1)).count(), 100);
    }

    /// The client's Binding request (contract 05 §2.9.3, the shared vector) at `len` bytes: the
    /// length field follows, PADDING makes up the rest.
    fn stun_request(len: usize) -> BytesMut {
        let mut r = crate::testutil::unhex("000100502112a4420102030400060708090a0b0c0026004c");
        r[2..4].copy_from_slice(&((len - 20) as u16).to_be_bytes());
        r[22..24].copy_from_slice(&((len - 24) as u16).to_be_bytes());
        r.resize(len, 0);
        BytesMut::from(&r[..])
    }

    /// The mapped address (an IPv4 one) and the proof of the answer to `stun_request`.
    async fn stun_reply(client: &mut FramedSocket) -> Option<(SocketAddr, Vec<u8>)> {
        let (b, _) = client.next_timeout(500).await?.unwrap();
        assert_eq!(b[..4], [0x01, 0x01, 0x00, (b.len() - 20) as u8]);
        assert_eq!(b[4..20], crate::testutil::unhex("2112a4420102030400060708090a0b0c")[..]);
        assert_eq!(b[20..26], [0x00u8, 0x20, 0x00, 0x08, 0x00, 0x01]);
        let port = u16::from_be_bytes([b[26], b[27]]) ^ 0x2112;
        let ip: [u8; 4] = std::array::from_fn(|i| b[28 + i] ^ ice_stun::STUN_MAGIC[i]);
        assert_eq!(b[32..36], [0xc1u8, 0xe9, 0x00, 28]);
        Some((SocketAddr::new(Ipv4Addr::from(ip).into(), port), b[36..64].to_vec()))
    }

    /// Contract 05 §6.1: Binding requests of 100 bytes and more are answered with the source's
    /// address and a proof that opens to it; shorter ones, a wrong cookie and an empty bucket get
    /// nothing.
    #[hbb_common::tokio::test]
    async fn stun_binding_requests_are_answered_with_a_proof() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut client = FramedSocket::new("127.30.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        h.rs.handle_udp(&stun_request(100), from, &mut server, "").await.unwrap();
        let (mapped, proof) = stun_reply(&mut client).await.unwrap();
        assert_eq!(mapped, from);
        assert_eq!(ice_stun::open(&proof, crate::common::now()), Some(from));

        h.rs.handle_udp(&stun_request(96), from, &mut server, "").await.unwrap();
        assert_eq!(stun_reply(&mut client).await, None, "under 100 bytes");
        let mut bad = stun_request(100);
        bad[7] ^= 1;
        h.rs.handle_udp(&bad, from, &mut server, "").await.unwrap();
        assert_eq!(stun_reply(&mut client).await, None, "cookie");
        // Empty, and stamped a second ahead: nothing is earned however long this thread pauses.
        h.rs.stun.tokens = 0.0;
        h.rs.stun.at = Instant::now() + Duration::from_secs(1);
        h.rs.handle_udp(&stun_request(100), from, &mut server, "").await.unwrap();
        assert_eq!(stun_reply(&mut client).await, None, "bucket");
    }

    /// Contract 05 §2.8, §3.4.3: on a dual-stack socket an IPv4 source arrives as `::ffff:a.b.c.d`;
    /// the answer goes back to it there and carries (and proves) the plain IPv4 address.
    #[hbb_common::tokio::test]
    async fn stun_maps_v4_mapped_sources_back_to_ipv4() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("[::]:0").await.unwrap();
        let mut client = FramedSocket::new("127.30.0.2:0").await.unwrap();
        let v4 = client.local_addr().unwrap();
        let from: SocketAddr = format!("[::ffff:{}]:{}", v4.ip(), v4.port()).parse().unwrap();
        h.rs.handle_udp(&stun_request(100), from, &mut server, "").await.unwrap();
        let (mapped, proof) = stun_reply(&mut client).await.unwrap();
        assert_eq!(mapped, v4);
        assert_eq!(ice_stun::open(&proof, crate::common::now()), Some(v4));
    }

    /// A listener handing every connection to `handle_listener` as if from `from` (`None`: the real
    /// peer, loopback), with licence key `key`.
    async fn listener_as(h: &Harness, from: Option<SocketAddr>, ws: bool, key: &str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let rs = h.rs.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                rs.handle_listener(stream, from.unwrap_or(peer), &key, ws).await;
            }
        });
        addr
    }

    // ---- ICE signaling (contract 05 §6.1). The session table is one for the process and tests run
    // in parallel: sessions are random, and every test's A comes from a source of its own. ----

    /// B's device key: contract 01's seed, as in the shared vectors (§2.5).
    fn device_keys() -> (sign::PublicKey, sign::SecretKey) {
        sign::keypair_from_seed(&sign::Seed([7; 32]))
    }

    impl Harness {
        /// B online and able to do ICE: its key pinned, a fresh heartbeat from Leapgate 0.3.1.
        async fn online_ice(&self, id: &str, addr: &str, pk: &[u8]) {
            self.online(id, addr).await;
            let peer = self.rs.pm.get_or(id).await;
            let mut w = peer.write().await;
            w.pk = Bytes::copy_from_slice(pk);
            w.pinned = true;
            w.leapgate_hb = Some(LeapgateHb {
                at: Instant::now(),
                leapgate_ver: 3010,
            });
        }
    }

    fn ice_session() -> Vec<u8> {
        sodiumoxide::randombytes::randombytes(16)
    }

    /// A host candidate.
    fn ice_cand(addr: &str) -> Bytes {
        ice_signal::encode(&ice_signal::Candidate {
            kind: 0,
            local_pref: 0xFFFF,
            addr: addr.parse().unwrap(),
        })
        .into()
    }

    fn ice_params(cands: &[&str]) -> LeapgateIceParams {
        LeapgateIceParams {
            ufrag: "AAAAAAAA".to_owned(),
            pwd: "a".repeat(24),
            candidates: cands.iter().map(|c| ice_cand(c)).collect(),
            ..Default::default()
        }
    }

    fn ice_msg(m: leapgate_ice::Union) -> RendezvousMessage {
        let mut msg = RendezvousMessage::new();
        msg.set_leapgate_ice(LeapgateIce {
            ver: 1,
            union: Some(m),
            ..Default::default()
        });
        msg
    }

    fn ice_offer(session: &[u8], id: &str, key: &str, params: LeapgateIceParams) -> RendezvousMessage {
        ice_msg(leapgate_ice::Union::Offer(LeapgateIceOffer {
            session: Bytes::copy_from_slice(session),
            id: id.to_owned(),
            licence_key: key.to_owned(),
            params: MessageField::some(params),
            ..Default::default()
        }))
    }

    fn ice_answer(session: &[u8], params: LeapgateIceParams) -> RendezvousMessage {
        ice_msg(leapgate_ice::Union::Answer(LeapgateIceAnswer {
            session: Bytes::copy_from_slice(session),
            params: MessageField::some(params),
            ..Default::default()
        }))
    }

    async fn recv_ice(conn: &mut FramedStream) -> leapgate_ice::Union {
        let Some(rendezvous_message::Union::LeapgateIce(m)) = recv(conn).await.union else {
            panic!("expected LeapgateIce");
        };
        assert_eq!(m.ver, 1);
        m.union.unwrap()
    }

    /// The connection is closed by the server (at once, not after the read timeout).
    async fn ice_closed(conn: &mut FramedStream) {
        let t = Instant::now();
        assert!(conn.next_timeout(3000).await.is_none(), "a message instead of the close");
        assert!(t.elapsed() < Duration::from_millis(2500), "still open");
    }

    /// Nothing is sent to B within `ms`.
    async fn nothing_to_b(h: &mut Harness, ms: u64) {
        assert!(timeout(ms, h.rx.recv()).await.is_err(), "sent to B");
    }

    /// A FORWARD checked against S's key over B's id and opened with B's device key (§2.5).
    fn open_forward(h: &Harness, msg: RendezvousMessage, b_id: &str) -> LeapgateIceSealed {
        let Some(rendezvous_message::Union::LeapgateIce(m)) = msg.union else {
            panic!("expected LeapgateIce");
        };
        assert_eq!(m.ver, 1);
        let Some(leapgate_ice::Union::Forward(f)) = m.union else {
            panic!("expected forward");
        };
        assert!(f.ts.abs_diff(crate::common::now()) <= 2);
        let mut signed = b"leapgate-ice-offer-v1\0".to_vec();
        signed.extend_from_slice(b_id.as_bytes());
        signed.push(0);
        signed.extend_from_slice(&f.ts.to_be_bytes());
        signed.extend_from_slice(&f.sealed);
        let sig = sign::Signature::from_bytes(&f.sig).unwrap();
        assert!(sign::verify_detached(&sig, &signed, &h.server_pk), "signature");
        let (pk, sk) = device_keys();
        let inner = sodiumoxide::crypto::sealedbox::open(
            &f.sealed,
            &sign::to_curve25519_pk(&pk).unwrap(),
            &sign::to_curve25519_sk(&sk).unwrap(),
        )
        .unwrap();
        LeapgateIceSealed::parse_from_bytes(&inner).unwrap()
    }

    /// A registered OFFER: B gets the FORWARD (encrypted and signed, A's candidates filtered with
    /// A's proofs) and A's connection stays for the answer.
    #[hbb_common::tokio::test]
    async fn ice_offer_is_forwarded_sealed_and_signed() {
        let mut h = harness(true, None).await;
        h.online_ice("B1", "8.8.8.8:5000", &device_keys().0 .0).await;
        let port = listener_as(&h, Some("198.51.100.31:5000".parse().unwrap()), false, "").await;
        let mut a = h.connect_at(port, Client::V1).await;
        let s = ice_session();
        let cands = [
            "192.168.1.10:50000",
            "203.0.113.7:40000",
            "203.0.113.8:40000",
            "198.18.0.1:40000",
            "[2001:db8::1]:40000",
        ];
        let mut offer = ice_offer(&s, "B1", "", ice_params(&cands));
        let proof = ice_stun::seal("203.0.113.7:40000".parse().unwrap(), crate::common::now());
        offer.mut_leapgate_ice().mut_offer().proofs = vec![proof.into()];
        a.send(&offer).await.unwrap();
        let (msg, to) = h.to_b().await;
        assert_eq!(to, "8.8.8.8:5000".parse().unwrap());
        let sealed = open_forward(&h, msg, "B1");
        assert_eq!(sealed.session[..], s[..]);
        // The public IPv4 without a proof and the TUN address are gone; nothing but the
        // parameters crosses (no id, key or proofs).
        let expected = ice_params(&[cands[0], cands[1], cands[4]]);
        assert_eq!(*sealed.params, expected);
        drop(a);
    }

    /// §2.4 step 0: on a connection without the KeyExchange (plain 21116, or 21118) an ICE message
    /// is not answered and the connection is closed.
    #[hbb_common::tokio::test]
    async fn ice_needs_the_key_exchange() {
        use tungstenite::Message;
        let mut h = harness(true, None).await;
        h.online_ice("B1", "8.8.8.8:5000", &device_keys().0 .0).await;
        let offer = ice_offer(&ice_session(), "B1", "", ice_params(&["192.168.1.10:50000"]));
        let mut a = h.connect(Client::Plain).await;
        a.send(&offer).await.unwrap();
        // The server's KeyExchange offer, then the close.
        let first = RendezvousMessage::parse_from_bytes(&a.next_timeout(3000).await.unwrap().unwrap()).unwrap();
        assert!(matches!(first.union, Some(rendezvous_message::Union::KeyExchange(_))));
        ice_closed(&mut a).await;

        let port = listener_as(&h, None, true, "").await;
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{port}/")).await.unwrap();
        ws.send(Message::Binary(offer.write_to_bytes().unwrap().into())).await.unwrap();
        loop {
            match timeout(3000, ws.next()).await.expect("the connection is still open") {
                Some(Ok(Message::Binary(b))) => panic!("answered on 21118: {b:?}"),
                Some(Ok(_)) => continue,
                None | Some(Err(_)) => break,
            }
        }
        nothing_to_b(&mut h, 300).await;
    }

    /// One OFFER on a new connection; the reason of the REJECT that comes back on it, which then
    /// closes.
    async fn ice_rejected(h: &Harness, port: SocketAddr, offer: RendezvousMessage) -> Reason {
        let mut a = h.connect_at(port, Client::V1).await;
        a.send(&offer).await.unwrap();
        let leapgate_ice::Union::Reject(r) = recv_ice(&mut a).await else {
            panic!("expected reject");
        };
        let Some(rendezvous_message::Union::LeapgateIce(m)) = offer.union else { unreachable!() };
        let Some(leapgate_ice::Union::Offer(o)) = m.union else { unreachable!() };
        assert_eq!(r.session, o.session);
        ice_closed(&mut a).await;
        r.reason.enum_value().unwrap()
    }

    /// §2.4 steps 1, 2 and 4, one branch each: nothing goes to B.
    #[hbb_common::tokio::test]
    async fn ice_offer_rejections() {
        let mut h = harness(true, None).await;
        let port = listener_as(&h, Some("198.51.100.32:5000".parse().unwrap()), false, "k").await;
        let pk = device_keys().0 .0;
        for id in ["B-old", "B-unpinned", "B-stale", "B-version", "B-point", "B1"] {
            h.online_ice(id, "8.8.8.8:5000", &pk).await;
        }
        let peer = |id: &'static str| {
            let pm = h.rs.pm.clone();
            async move { pm.get_in_memory(id).await.unwrap() }
        };
        peer("B-old").await.write().await.last_reg_time = Instant::now() - Duration::from_millis(REG_TIMEOUT as u64 + 1000);
        peer("B-unpinned").await.write().await.pinned = false;
        peer("B-stale").await.write().await.leapgate_hb.as_mut().unwrap().at = Instant::now() - Duration::from_secs(181);
        peer("B-version").await.write().await.leapgate_hb.as_mut().unwrap().leapgate_ver = 3009;
        // The small-order identity point: no X25519 key to encrypt to.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        peer("B-point").await.write().await.pk = Bytes::copy_from_slice(&identity);

        let p = || ice_params(&["192.168.1.10:50000"]);
        let offer = |id: &str| ice_offer(&ice_session(), id, "k", p());
        for (id, reason) in [
            ("nobody", Reason::OFFLINE),
            ("B-old", Reason::OFFLINE),
            ("B-unpinned", Reason::UNSUPPORTED),
            ("B-stale", Reason::UNSUPPORTED),
            ("B-version", Reason::UNSUPPORTED),
            ("B-point", Reason::UNSUPPORTED),
        ] {
            assert_eq!(ice_rejected(&h, port, offer(id)).await, reason, "{id}");
        }
        let seventeen: Vec<String> = (1..=17).map(|i| format!("192.168.1.{i}:1")).collect();
        let seventeen: Vec<&str> = seventeen.iter().map(|s| s.as_str()).collect();
        for (what, msg) in [
            ("key", ice_offer(&ice_session(), "B1", "x", p())),
            ("session", ice_offer(&ice_session()[..15], "B1", "k", p())),
            ("candidates", ice_offer(&ice_session(), "B1", "k", ice_params(&seventeen))),
        ] {
            assert_eq!(ice_rejected(&h, port, msg).await, Reason::BAD, "{what}");
        }
        nothing_to_b(&mut h, 300).await;
        // The same B, all well: forwarded.
        let mut a = h.connect_at(port, Client::V1).await;
        a.send(&offer("B1")).await.unwrap();
        assert_eq!(h.to_b().await.1, "8.8.8.8:5000".parse().unwrap());
    }

    /// §2.4 step 3: one side inside the LAN mask, the other not: ICE cannot get round the relay.
    #[hbb_common::tokio::test]
    async fn ice_offer_rejected_on_forced_relay() {
        // A (loopback) inside the mask, B outside.
        let mut h = harness(true, Some("127.0.0.0/8".parse().unwrap())).await;
        h.online_ice("B1", "8.8.8.8:5000", &device_keys().0 .0).await;
        let offer = ice_offer(&ice_session(), "B1", "", ice_params(&["192.168.1.10:50000"]));
        assert_eq!(ice_rejected(&h, h.addr, offer).await, Reason::RELAY);
        nothing_to_b(&mut h, 300).await;
    }

    /// §2.4 step 5: a source holds 8 sessions; the 9th is BUSY, and a closed connection frees its
    /// place. A session in use on another connection is BAD and leaves that one alone.
    #[hbb_common::tokio::test]
    async fn ice_sessions_per_source() {
        let mut h = harness(true, None).await;
        h.online_ice("B1", "8.8.8.8:5000", &device_keys().0 .0).await;
        let port = listener_as(&h, Some("198.51.100.33:5000".parse().unwrap()), false, "").await;
        let other = listener_as(&h, Some("198.51.100.34:5000".parse().unwrap()), false, "").await;
        let p = || ice_params(&["192.168.1.10:50000"]);
        let mut held = Vec::new();
        for _ in 0..8 {
            let s = ice_session();
            let mut a = h.connect_at(port, Client::V1).await;
            a.send(&ice_offer(&s, "B1", "", p())).await.unwrap();
            h.to_b().await;
            held.push((a, s));
        }
        let busy = ice_offer(&ice_session(), "B1", "", p());
        assert_eq!(ice_rejected(&h, port, busy).await, Reason::BUSY);
        let in_use = ice_offer(&held[0].1, "B1", "", p());
        assert_eq!(ice_rejected(&h, other, in_use).await, Reason::BAD);
        assert_eq!(ICE_SESSIONS.lock().unwrap().peek_unanswered(&held[0].1[..].try_into().unwrap()).as_deref(), Some("B1"));
        nothing_to_b(&mut h, 300).await;

        drop(held.pop());
        let t = Instant::now();
        loop {
            let mut a = h.connect_at(port, Client::V1).await;
            a.send(&ice_offer(&ice_session(), "B1", "", p())).await.unwrap();
            match recv_or_forward(&mut h, &mut a).await {
                None => break,
                Some(reason) => assert_eq!(reason, Reason::BUSY),
            }
            assert!(t.elapsed() < Duration::from_secs(3), "the closed connection's place is still taken");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// After an OFFER: `None` when B got a FORWARD, or the reason A was rejected with.
    async fn recv_or_forward(h: &mut Harness, a: &mut FramedStream) -> Option<Reason> {
        tokio::select! {
            m = h.rx.recv() => {
                m.unwrap();
                None
            }
            m = recv_ice(a) => {
                let leapgate_ice::Union::Reject(r) = m else { panic!("expected reject") };
                Some(r.reason.enum_value().unwrap())
            }
        }
    }

    /// §2.3 ②: the same OFFER again on the connection sends the cached FORWARD, byte for byte, to
    /// the current address of the B it was registered for, whatever id the resend names; once
    /// only. Another session on the connection is ignored.
    #[hbb_common::tokio::test]
    async fn ice_offer_resend() {
        let mut h = harness(true, None).await;
        let pk = device_keys().0 .0;
        h.online_ice("B1", "8.8.8.8:5000", &pk).await;
        let port = listener_as(&h, Some("198.51.100.35:5000".parse().unwrap()), false, "").await;
        let mut a = h.connect_at(port, Client::V1).await;
        let offer = ice_offer(&ice_session(), "B1", "", ice_params(&["192.168.1.10:50000"]));
        a.send(&offer).await.unwrap();
        let (first, to) = h.to_b().await;
        assert_eq!(to, "8.8.8.8:5000".parse().unwrap());
        // B registers again from elsewhere; the resend names another device that is online.
        h.online("B1", "8.8.4.4:6000").await;
        h.online("B2", "1.1.1.1:7000").await;
        a.send(&ice_offer(&ice_session(), "B1", "", ice_params(&["192.168.1.11:50000"]))).await.unwrap();
        let mut to_b2 = offer.clone();
        to_b2.mut_leapgate_ice().mut_offer().id = "B2".to_owned();
        a.send(&to_b2).await.unwrap();
        let (second, to) = h.to_b().await;
        assert_eq!(to, "8.8.4.4:6000".parse().unwrap());
        assert_eq!(second.write_to_bytes().unwrap(), first.write_to_bytes().unwrap());
        a.send(&offer).await.unwrap();
        nothing_to_b(&mut h, 300).await;
        assert!(a.next_timeout(300).await.is_none(), "nothing for A either");
    }

    /// One registered session from a source of the test's own: A's connection and the session.
    async fn ice_registered(h: &mut Harness, from: &str) -> (FramedStream, Vec<u8>) {
        h.online_ice("B1", "8.8.8.8:5000", &device_keys().0 .0).await;
        let port = listener_as(h, Some(from.parse().unwrap()), false, "").await;
        let mut a = h.connect_at(port, Client::V1).await;
        let s = ice_session();
        a.send(&ice_offer(&s, "B1", "", ice_params(&["192.168.1.10:50000"]))).await.unwrap();
        h.to_b().await;
        (a, s)
    }

    fn session_key(s: &[u8]) -> [u8; 16] {
        s.try_into().unwrap()
    }

    /// §2.3 ④: B's ANSWER, on a connection of B's own, reaches A with B's candidates filtered by
    /// B's proofs (a public IPv4 with one stays, one without goes) and B's `IdPk` signed by S;
    /// B's connection is closed. The session stays, answered, until A's connection ends; a second
    /// ANSWER and one for an unknown session are ignored.
    #[hbb_common::tokio::test]
    async fn ice_answer_reaches_a_with_the_signed_pk() {
        let mut h = harness(true, None).await;
        let (mut a, s) = ice_registered(&mut h, "198.51.100.36:5000").await;
        let cands = ["10.0.0.2:1", "203.0.113.9:2", "[fd00::5]:3", "203.0.113.10:4"];
        let mut answer = ice_answer(&s, ice_params(&cands));
        let proof = ice_stun::seal("203.0.113.9:2".parse().unwrap(), crate::common::now());
        answer.mut_leapgate_ice().mut_answer().proofs = vec![proof.into()];
        let mut b = h.connect(Client::V1).await;
        b.send(&answer).await.unwrap();
        let leapgate_ice::Union::Answer(ans) = recv_ice(&mut a).await else {
            panic!("expected answer");
        };
        assert_eq!(ans.session[..], s[..]);
        assert_eq!(*ans.params, ice_params(&cands[..3]));
        assert!(ans.proofs.is_empty());
        let signed = sign::verify(&ans.pk, &h.server_pk).expect("signed by S");
        let id_pk = IdPk::parse_from_bytes(&signed).unwrap();
        assert_eq!((id_pk.id.as_str(), &id_pk.pk[..]), ("B1", &device_keys().0 .0[..]));
        ice_closed(&mut b).await;

        for session in [s.clone(), ice_session()] {
            let mut b = h.connect(Client::V1).await;
            b.send(&ice_answer(&session, ice_params(&cands))).await.unwrap();
            ice_closed(&mut b).await;
        }
        assert!(a.next_timeout(300).await.is_none(), "nothing more for A");
        // Answered, then A closes without a RESULT: abandoned (§3.7).
        drop(a);
        let rows = ice_rows(&h, 1).await;
        assert_eq!(rows, [("198.51.100.36".to_owned(), "B1".to_owned(), "abandoned".to_owned(), None, None)]);
    }

    type IceRow = (String, String, String, Option<i64>, Option<String>);

    /// `ice_result` once it has `n` rows or 3 seconds passed (A's close is handled on its connection
    /// task): A's address, B's id, the outcome, `elapsed_ms`, `local_kind`.
    async fn ice_rows(h: &Harness, n: usize) -> Vec<IceRow> {
        let t = Instant::now();
        loop {
            h.rs.state.tracker.flush().await;
            let rows: Vec<IceRow> =
                sqlx::query_as("select a_ip, b_id, outcome, elapsed_ms, local_kind from ice_result order by id")
                    .fetch_all(&h.rs.state.db)
                    .await
                    .unwrap();
            if rows.len() >= n || t.elapsed() > Duration::from_secs(3) {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// §2.3 ④: a malformed ANSWER (one of another version too), or one for a B no longer in memory
    /// (no pk to sign), rejects A's session and removes it: A's close records nothing.
    #[hbb_common::tokio::test]
    async fn ice_answer_refused() {
        let mut h = harness(true, None).await;
        let mut bad = ice_params(&["10.0.0.2:1"]);
        bad.candidates.push(Bytes::from_static(&[0; 9]));
        let mut v2 = ice_answer(&[0; 16], ice_params(&["10.0.0.2:1"]));
        v2.mut_leapgate_ice().ver = 2;
        for (from, answer) in [("198.51.100.37:5000", ice_answer(&[0; 16], bad)), ("198.51.100.41:5000", v2)] {
            let (mut a, s) = ice_registered(&mut h, from).await;
            let mut answer = answer;
            answer.mut_leapgate_ice().mut_answer().session = Bytes::copy_from_slice(&s);
            let mut b = h.connect(Client::V1).await;
            b.send(&answer).await.unwrap();
            let leapgate_ice::Union::Reject(r) = recv_ice(&mut a).await else {
                panic!("expected reject");
            };
            assert_eq!((r.session[..] == s[..], r.reason.enum_value().unwrap()), (true, Reason::BAD), "{from}");
            assert!(ICE_SESSIONS.lock().unwrap().peek_unanswered(&session_key(&s)).is_none(), "removed");
            ice_closed(&mut b).await;
            drop(a);
        }

        let (mut a, s) = ice_registered(&mut h, "198.51.100.38:5000").await;
        h.rs.pm.remove("B1").await;
        let mut b = h.connect(Client::V1).await;
        b.send(&ice_answer(&s, ice_params(&["10.0.0.2:1"]))).await.unwrap();
        let leapgate_ice::Union::Reject(r) = recv_ice(&mut a).await else {
            panic!("expected reject");
        };
        assert_eq!((r.session[..] == s[..], r.reason.enum_value().unwrap()), (true, Reason::UNSUPPORTED));
        assert!(ICE_SESSIONS.lock().unwrap().peek_unanswered(&session_key(&s)).is_none(), "removed");
        // A closes: a rejected session is not counted as abandoned (an answered one would be, as
        // a row within the 3 seconds `ice_rows` waits for one).
        drop(a);
        assert!(ice_rows(&h, 1).await.is_empty());
    }

    /// §2.3 ⑦, §3.7 (P-A): A's first RESULT for its own session is recorded; one for another
    /// session, one of another version and a second one are ignored, the connection kept; after a
    /// RESULT, A's close records nothing more.
    #[hbb_common::tokio::test]
    async fn ice_result_is_recorded_once() {
        use leapgate_ice_result::Outcome;
        let mut h = harness(true, None).await;
        let (mut a, s) = ice_registered(&mut h, "198.51.100.40:5000").await;
        let result = |session: &[u8], outcome: Outcome| {
            ice_msg(leapgate_ice::Union::Result(LeapgateIceResult {
                session: Bytes::copy_from_slice(session),
                outcome: outcome.into(),
                elapsed_ms: 1234,
                local_kind: leapgate_ice_result::Kind::SRFLX.into(),
                family: 4,
                ..Default::default()
            }))
        };
        let mut v2 = result(&s, Outcome::NO_PAIR);
        v2.mut_leapgate_ice().ver = 2;
        for m in [v2, result(&ice_session(), Outcome::NO_PAIR), result(&s, Outcome::CONNECTED), result(&s, Outcome::NO_PAIR)] {
            a.send(&m).await.unwrap();
        }
        assert!(a.next_timeout(300).await.is_none(), "nothing for A");
        drop(a);
        // The connection task ends: the session is gone, and nothing more is recorded.
        let t = Instant::now();
        while ICE_SESSIONS.lock().unwrap().peek_unanswered(&session_key(&s)).is_some() {
            assert!(t.elapsed() < Duration::from_secs(3), "A's close not handled");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let rows = ice_rows(&h, 1).await;
        let row = ("198.51.100.40".to_owned(), "B1".to_owned(), "connected".to_owned(), Some(1234), Some("srflx".to_owned()));
        assert_eq!(rows, [row]);
    }

    /// §2.3 ⑤: B's REJECT goes to A as it came, and the session is removed.
    #[hbb_common::tokio::test]
    async fn ice_reject_from_b_reaches_a() {
        let mut h = harness(true, None).await;
        let (mut a, s) = ice_registered(&mut h, "198.51.100.39:5000").await;
        let mut b = h.connect(Client::V1).await;
        b.send(&ice_msg(leapgate_ice::Union::Reject(LeapgateIceReject {
            session: Bytes::copy_from_slice(&s),
            reason: Reason::UNSUPPORTED.into(),
            ..Default::default()
        })))
        .await
        .unwrap();
        let leapgate_ice::Union::Reject(r) = recv_ice(&mut a).await else {
            panic!("expected reject");
        };
        assert_eq!((r.session[..] == s[..], r.reason.enum_value().unwrap()), (true, Reason::UNSUPPORTED));
        ice_closed(&mut b).await;
        assert!(ICE_SESSIONS.lock().unwrap().close(&session_key(&s)).is_none(), "removed");
    }

    /// §3.4.2: B's REJECT of another version is ignored, B's connection closed and A's session
    /// left as it was.
    #[hbb_common::tokio::test]
    async fn ice_reject_of_another_version_is_ignored() {
        let mut h = harness(true, None).await;
        let (mut a, s) = ice_registered(&mut h, "198.51.100.42:5000").await;
        let mut reject = ice_msg(leapgate_ice::Union::Reject(LeapgateIceReject {
            session: Bytes::copy_from_slice(&s),
            reason: Reason::UNSUPPORTED.into(),
            ..Default::default()
        }));
        reject.mut_leapgate_ice().ver = 2;
        let mut b = h.connect(Client::V1).await;
        b.send(&reject).await.unwrap();
        ice_closed(&mut b).await;
        assert!(a.next_timeout(300).await.is_none(), "nothing for A");
        assert_eq!(ICE_SESSIONS.lock().unwrap().peek_unanswered(&session_key(&s)).as_deref(), Some("B1"));
    }

    /// Review C-28/C-2: 21118 reads a message of `MAX_FRAME` bytes and closes the connection on a
    /// longer one; a handshake request over `WS_HANDSHAKE_MAX` closes it at once, not after the
    /// 10-second handshake timeout.
    #[hbb_common::tokio::test]
    async fn ws_message_and_handshake_limits() {
        use tungstenite::Message;
        let h = harness(true, None).await;
        let port = listener_as(&h, None, true, "").await;
        let mut msg = punch_request("nobody");
        let mut n = MAX_FRAME - 200;
        let bytes = loop {
            msg.mut_punch_hole_request().webrtc_sdp_offer = "o".repeat(n);
            let bytes = msg.write_to_bytes().unwrap();
            if bytes.len() == MAX_FRAME {
                break bytes;
            }
            n = n + MAX_FRAME - bytes.len();
        };
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{port}/")).await.unwrap();
        ws.send(Message::Binary(bytes.into())).await.unwrap();
        let Ok(Some(Ok(Message::Binary(reply)))) = timeout(3000, ws.next()).await else {
            panic!("no answer to a MAX_FRAME message");
        };
        let Some(rendezvous_message::Union::PunchHoleResponse(res)) =
            RendezvousMessage::parse_from_bytes(&reply).unwrap().union
        else {
            panic!("expected PunchHoleResponse");
        };
        assert_eq!(res.failure, punch_hole_response::Failure::ID_NOT_EXIST.into());

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{port}/")).await.unwrap();
        let _ = ws.send(Message::Binary(vec![0u8; MAX_FRAME + 1].into())).await;
        loop {
            match timeout(3000, ws.next()).await.expect("the connection is still open") {
                Some(Ok(Message::Binary(b))) => panic!("answered an oversized message: {b:?}"),
                Some(Ok(_)) => continue,
                None | Some(Err(_)) => break,
            }
        }

        let mut s = TcpStream::connect(port).await.unwrap();
        let head = format!("GET / HTTP/1.1\r\nHost: x\r\nX-Pad: {}", "a".repeat(WS_HANDSHAKE_MAX));
        let _ = s.write_all(head.as_bytes()).await;
        closed_within(&mut s, 3000).await;
    }

    /// Review C-13: a connection's `RequestRelay`s are forwarded with their strings cut and without
    /// the licence key, up to `MAX_RELAY_REQUESTS`; the next one closes the connection.
    #[hbb_common::tokio::test]
    async fn relay_requests_cut_and_capped() {
        let mut h = harness(false, None).await;
        h.online("B1", "8.8.8.8:5000").await;
        let mut msg = RendezvousMessage::new();
        msg.set_request_relay(RequestRelay {
            id: "B1".to_owned(),
            uuid: "u".repeat(1000),
            token: "t".repeat(1000),
            relay_server: "r".repeat(1000),
            licence_key: "k".repeat(1000),
            switch_code: "s".repeat(1000),
            secure: true,
            ..Default::default()
        });
        let bytes = msg.write_to_bytes().unwrap();
        let mut s = TcpStream::connect(h.addr).await.unwrap();
        let local = s.local_addr().unwrap();
        for i in 0..MAX_RELAY_REQUESTS {
            s.write_all(&frame_head(bytes.len())).await.unwrap();
            s.write_all(&bytes).await.unwrap();
            let (msg, to) = h.to_b().await;
            assert_eq!(to, "8.8.8.8:5000".parse().unwrap());
            let Some(rendezvous_message::Union::RequestRelay(rr)) = msg.union else {
                panic!("#{i}: expected RequestRelay");
            };
            assert_eq!(
                (rr.uuid.len(), rr.token.len(), rr.switch_code.len(), rr.relay_server.len()),
                (MAX_RELAY_TEXT, MAX_RELAY_TEXT, MAX_RELAY_TEXT, MAX_PEER_ID_LEN)
            );
            assert!(rr.licence_key.is_empty() && rr.secure);
            assert_eq!(AddrMangle::decode(&rr.socket_addr), local);
        }
        let mut buf = [0u8; 1];
        assert!(timeout(300, s.read(&mut buf)).await.is_err(), "still open at the limit");
        s.write_all(&frame_head(bytes.len())).await.unwrap();
        s.write_all(&bytes).await.unwrap();
        closed_within(&mut s, 3000).await;
        assert!(h.rx.try_recv().is_err(), "the one over the limit is not forwarded");
    }

    /// Review C-28: `MAX_CONNS_PER_SOURCE` holds where connections come in, on 21116 and 21118:
    /// the next connection from the source is closed before anything is sent.
    #[hbb_common::tokio::test]
    async fn per_source_limit_at_the_listeners() {
        let h = harness(true, None).await;
        for ws in [false, true] {
            let port = listener_as(&h, Some("198.51.100.9:5000".parse().unwrap()), ws, "").await;
            let mut held = Vec::new();
            for _ in 0..MAX_CONNS_PER_SOURCE {
                let mut s = TcpStream::connect(port).await.unwrap();
                let mut buf = [0u8; 1];
                if ws {
                    // Waiting for the handshake: open, silent.
                    assert!(timeout(100, s.read(&mut buf)).await.is_err(), "ws: closed under the limit");
                } else {
                    timeout(3000, s.read_exact(&mut buf)).await.unwrap().unwrap();
                }
                held.push(s);
            }
            let mut s = TcpStream::connect(port).await.unwrap();
            let mut got = Vec::new();
            let _ = timeout(3000, s.read_to_end(&mut got))
                .await
                .expect("the connection over the limit is still open");
            assert!(got.is_empty(), "ws: {ws}: {got:?}");
        }
    }

    /// Review C-28: 21115 takes `MAX_ONLINE_CONNS` connections at a time; over it a connection is
    /// closed without an answer.
    #[hbb_common::tokio::test]
    async fn online_port_connection_limit() {
        assert_eq!(ConnLimits::default().online.available(), MAX_ONLINE_CONNS);
        let conns = ConnLimits {
            online: ConnLimiter::new(1),
            ..Default::default()
        };
        let h = harness_with(true, None, conns).await;
        let port = online_port(&h).await;
        // Holds the slot: the server waits for its request.
        let first = TcpStream::connect(port).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut second = TcpStream::connect(port).await.unwrap();
        closed_within(&mut second, 3000).await;
        drop(first);
        let mut request = RendezvousMessage::new();
        request.set_online_request(OnlineRequest {
            id: "A12345".to_owned(),
            peers: vec!["B1".to_owned()],
            ..Default::default()
        });
        let mut answered = false;
        for _ in 0..30 {
            let s = TcpStream::connect(port).await.unwrap();
            let local = s.local_addr().unwrap();
            let mut conn = FramedStream::from(s, local);
            conn.send(&request).await.unwrap();
            if let Some(Ok(_)) = conn.next_timeout(500).await {
                answered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(answered, "the slot comes back once the first connection ends");
    }

    /// Review C-28: the 5-minute cleanup (`purge_ip_maps`) rules of LEAPGATE.md §6 item 7.
    #[test]
    fn ip_map_cleanup_rules() {
        use std::collections::HashSet;
        let now = Instant::now();
        // Instants this far back exist once the monotonic clock (boot, on Linux) is older.
        let ago = |s: u64| now.checked_sub(Duration::from_secs(s)).unwrap();
        let (minute_over, change_live, change_over) =
            (ago(IP_BLOCK_DUR + 1), ago(IP_CHANGE_DUR_X2 - 1), ago(IP_CHANGE_DUR_X2));
        let src = |n: u8| IpAddr::from([198, 51, 100, n]);
        let ids = |n: usize| (0..n).map(|i| format!("id{i}")).collect::<HashSet<_>>();
        let mut map = IpBlockMap::new();
        map.insert(src(1), ((1, now), (ids(0), now))); // live minute: kept
        map.insert(src(2), ((1, minute_over), (ids(2), now))); // ids of the day: kept
        map.insert(src(3), ((1, minute_over), (ids(0), now))); // neither: dropped
        let mut expected = vec![(src(1), 0), (src(2), 2)];
        if let Some(day_over) = now.checked_sub(Duration::from_secs(DAY_SECONDS + 1)) {
            map.insert(src(4), ((1, minute_over), (ids(2), day_over))); // day over: emptied, dropped
            map.insert(src(5), ((1, now), (ids(2), day_over))); // day over: emptied, kept
            expected.push((src(5), 0));
        } else {
            eprintln!("day window rule skipped: the monotonic clock started less than a day ago");
        }
        retain_live_ip_blocks(&mut map);
        let mut kept: Vec<_> = map.iter().map(|(ip, (_, (ids, _)))| (*ip, ids.len())).collect();
        kept.sort();
        assert_eq!(kept, expected);

        let mut changes = IpChangesMap::new();
        changes.insert("live".to_owned(), (change_live, Default::default()));
        changes.insert("over".to_owned(), (change_over, Default::default()));
        retain_live_ip_changes(&mut changes);
        assert_eq!(changes.keys().collect::<Vec<_>>(), ["live"]);
    }

    #[hbb_common::tokio::test]
    async fn over_the_limit_closed_before_key_exchange() {
        let conns = ConnLimits {
            tcp: ConnLimiter::new(1),
            ..Default::default()
        };
        let h = harness_with(true, None, conns).await;
        let mut buf = [0u8; 1];
        let first = {
            let mut s = TcpStream::connect(h.addr).await.unwrap();
            timeout(3000, s.read_exact(&mut buf)).await.unwrap().unwrap();
            s
        };
        // No offer: closed before any byte (and before the two signatures).
        let mut second = TcpStream::connect(h.addr).await.unwrap();
        let mut got = Vec::new();
        let _ = timeout(3000, second.read_to_end(&mut got))
            .await
            .expect("the connection is still open");
        assert!(got.is_empty(), "{got:?}");
        // The slot comes back once the first connection ends.
        drop(first);
        let mut offered = false;
        for _ in 0..30 {
            let mut s = TcpStream::connect(h.addr).await.unwrap();
            if let Ok(Ok(_)) = timeout(500, s.read_exact(&mut buf)).await {
                offered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(offered);
    }

    /// Pins `id`'s key as a signed report does (database and memory).
    async fn pin(h: &Harness, id: &str) {
        sqlx::query("update peer set pk_pinned_at = 1 where id = ?")
            .bind(id)
            .execute(&h.rs.state.db)
            .await
            .unwrap();
        h.rs.pm.set_pinned(id, true).await;
    }

    async fn peer_row(h: &Harness, id: &str) -> (Vec<u8>, Vec<u8>, Option<i64>) {
        sqlx::query_as("select uuid, pk, pk_pinned_at from peer where id = ?")
            .bind(id)
            .fetch_one(&h.rs.state.db)
            .await
            .unwrap()
    }

    /// Phase 3 contract 01 §3.4: a pinned key takes no other `RegisterPk` (memory refuses it before
    /// the database; with memory not knowing, the database does); the same key from a new IP is fine.
    #[hbb_common::tokio::test]
    async fn pinned_key_refuses_another() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut a = FramedSocket::new("127.26.0.1:0").await.unwrap();
        let mut b = FramedSocket::new("127.26.0.2:0").await.unwrap();
        let (from_a, from_b) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        let (pk, pk2) = ([1u8; 32], [2u8; 32]);
        h.rs.handle_udp(&register_pk("pinned1", b"uuid-pin", &pk), from_a, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::OK));
        pin(&h, "pinned1").await;

        // Same uuid, same IP, another key: OK before the pin, refused now.
        h.rs.handle_udp(&register_pk("pinned1", b"uuid-pin", &pk2), from_a, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(UUID_MISMATCH));
        assert_eq!(peer_row(&h, "pinned1").await.1, pk.to_vec());
        // The pinned key from another address.
        h.rs.handle_udp(&register_pk("pinned1", b"uuid-pin", &pk), from_b, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut b).await, Some(register_pk_response::Result::OK));
        // Memory not knowing of the pin: the database refuses, and memory learns it.
        h.rs.pm.set_pinned("pinned1", false).await;
        h.rs.handle_udp(&register_pk("pinned1", b"uuid-pin", &pk2), from_b, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut b).await, Some(UUID_MISMATCH));
        assert_eq!(peer_row(&h, "pinned1").await.1, pk.to_vec());
        assert!(h.rs.pm.get_in_memory("pinned1").await.unwrap().read().await.pinned);
    }

    /// What `device key reset [--forget]` does to the database (only the command line changes it).
    async fn cli_reset(h: &Harness, id: &str, forget: bool) {
        let sql = if forget {
            "delete from peer where id = ?"
        } else {
            "update peer set pk_pinned_at = null where id = ?"
        };
        sqlx::query(sql).bind(id).execute(&h.rs.state.db).await.unwrap();
    }

    /// The command line changes the database, then the console's `kl` brings memory in line with
    /// it; the console itself changes nothing (it is not authenticated). The old `kr`/`kf` are gone.
    #[hbb_common::tokio::test]
    async fn key_reset_then_console_reload() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut a = FramedSocket::new("127.26.1.1:0").await.unwrap();
        let from = a.local_addr().unwrap();
        let (pk, pk2, pk3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        h.rs.handle_udp(&register_pk("reset01", b"uuid-rst", &pk), from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::OK));
        pin(&h, "reset01").await;
        for cmd in ["kr reset01", "kf reset01", "key-forget reset01"] {
            assert_eq!(h.rs.check_cmd(cmd).await, "", "{cmd}");
        }
        assert_eq!(peer_row(&h, "reset01").await.2, Some(1));

        cli_reset(&h, "reset01", false).await;
        let out = h.rs.check_cmd("kl reset01").await;
        assert!(out.contains("reloaded"), "{out}");
        assert_eq!(peer_row(&h, "reset01").await, (b"uuid-rst".to_vec(), pk.to_vec(), None));
        assert!(!h.rs.pm.get_in_memory("reset01").await.unwrap().read().await.pinned);
        // The reinstall (same uuid, same IP, new key) keeps the id.
        h.rs.handle_udp(&register_pk("reset01", b"uuid-rst", &pk2), from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::OK));
        assert_eq!(peer_row(&h, "reset01").await.1, pk2.to_vec());

        pin(&h, "reset01").await;
        cli_reset(&h, "reset01", true).await;
        let out = h.rs.check_cmd("key-reload reset01").await;
        assert!(out.contains("dropped from memory"), "{out}");
        assert!(!h.rs.pm.is_in_memory("reset01").await);
        // Registered again as a new device, with another uuid and key.
        h.rs.handle_udp(&register_pk("reset01", b"uuid-new", &pk3), from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::OK));
        assert_eq!(peer_row(&h, "reset01").await, (b"uuid-new".to_vec(), pk3.to_vec(), None));
        // Memory and database agree: reloading changes nothing.
        assert!(h.rs.check_cmd("kl reset01").await.contains("reloaded"));
        assert_eq!(h.rs.pm.get_in_memory("reset01").await.unwrap().read().await.pk[..], pk3);

        assert!(h.rs.check_cmd("kl nosuch1").await.contains("not in memory"));
        assert!(h.rs.check_cmd("kl").await.contains("needs a device id"));
    }

    /// Review fix: memory is not trusted over the database. An unpinning made without the console
    /// takes effect at the next registration with another key (the entry is reloaded first); a row
    /// deleted without the console drops the stale entry (SERVER_ERROR), and the next round
    /// registers the id as new.
    #[hbb_common::tokio::test]
    async fn registration_reloads_a_pinned_entry() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut a = FramedSocket::new("127.26.2.1:0").await.unwrap();
        let from = a.local_addr().unwrap();
        let (pk, pk2, pk3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        h.rs.handle_udp(&register_pk("reload1", b"uuid-rl", &pk), from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::OK));
        pin(&h, "reload1").await;
        cli_reset(&h, "reload1", false).await;
        assert!(h.rs.pm.get_in_memory("reload1").await.unwrap().read().await.pinned, "memory still pinned");
        h.rs.handle_udp(&register_pk("reload1", b"uuid-rl", &pk2), from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::OK));
        assert_eq!(peer_row(&h, "reload1").await.1, pk2.to_vec());

        // Pinned again, then the row deleted behind the server's back.
        pin(&h, "reload1").await;
        cli_reset(&h, "reload1", true).await;
        h.rs.handle_udp(&register_pk("reload1", b"uuid-new", &pk3), from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::SERVER_ERROR));
        assert!(!h.rs.pm.is_in_memory("reload1").await);
        h.rs.handle_udp(&register_pk("reload1", b"uuid-new", &pk3), from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::OK));
        assert_eq!(peer_row(&h, "reload1").await, (b"uuid-new".to_vec(), pk3.to_vec(), None));
    }

    /// Review C-12 kept: the reload of a pinned entry is a database read on `io_loop`, within the
    /// global lookup budget; over it the packet is dropped unanswered, with no read.
    #[hbb_common::tokio::test]
    async fn pinned_key_check_within_the_lookup_budget() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut a = FramedSocket::new("127.26.4.1:0").await.unwrap();
        let from = a.local_addr().unwrap();
        h.rs.handle_udp(&register_pk("pbudget", b"uuid-pb", &[1u8; 32]), from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::OK));
        pin(&h, "pbudget").await;
        // Row deleted, entry kept: a read would find no row, drop the entry and answer SERVER_ERROR.
        cli_reset(&h, "pbudget", true).await;
        h.rs.lookups.tokens = 0.0;
        h.rs.lookups.at = Instant::now() + Duration::from_secs(1);
        let other = register_pk("pbudget", b"uuid-pb", &[2u8; 32]);
        h.rs.handle_udp(&other, from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, None);
        assert!(h.rs.pm.is_in_memory("pbudget").await, "no read happened");
        h.rs.lookups = LookupBudget::new();
        h.rs.handle_udp(&other, from, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut a).await, Some(register_pk_response::Result::SERVER_ERROR));
        assert!(!h.rs.pm.is_in_memory("pbudget").await);
    }

    /// Review fix: a new address of a device whose row is gone is not answered OK (that entry
    /// would keep answering OK without a row): SERVER_ERROR, the entry dropped, and the next round
    /// registers it as new.
    #[hbb_common::tokio::test]
    async fn ip_change_of_a_deleted_row() {
        let mut h = harness(true, None).await;
        let mut server = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let mut old = FramedSocket::new("127.26.3.1:0").await.unwrap();
        let mut new = FramedSocket::new("127.26.3.2:0").await.unwrap();
        let (from_old, from_new) = (old.local_addr().unwrap(), new.local_addr().unwrap());
        let pk = [4u8; 32];
        h.rs.handle_udp(&register_pk("gone01", b"uuid-gone", &pk), from_old, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut old).await, Some(register_pk_response::Result::OK));
        cli_reset(&h, "gone01", true).await;
        h.rs.handle_udp(&register_pk("gone01", b"uuid-gone", &pk), from_new, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut new).await, Some(register_pk_response::Result::SERVER_ERROR));
        assert!(!h.rs.pm.is_in_memory("gone01").await);
        h.rs.handle_udp(&register_pk("gone01", b"uuid-gone", &pk), from_new, &mut server, "").await.unwrap();
        assert_eq!(register_reply(&mut new).await, Some(register_pk_response::Result::OK));
        assert_eq!(peer_rows(&h, "gone01").await, 1);
    }
}
