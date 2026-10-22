use crate::common::*;
use crate::conn_tracker::{
    PunchRequest, RelayRequest, RelayResponseInfo, Reply, ReplyKind, Signal,
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
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
}

const REG_TIMEOUT: i64 = 30_000;
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;
enum Sink {
    /// With the sending half of the cipher once the client completed the KeyExchange.
    TcpStream(TcpStreamSink, Option<Encrypt>),
    Ws(WsSink),
}
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);

// Store punch hole requests
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
    sk: Option<sign::SecretKey>,
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    pm: PeerMap,
    tx: Sender,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
    state: AppState,
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
        let db = crate::database::open(&crate::database::db_url()).await?;
        let cfg = crate::config::Config::from_args()?;
        let api_listen = cfg.api.listen_addr(port)?;
        let state = AppState::new(
            db,
            cfg,
            std::path::Path::new(crate::crypto::SECRET_KEY_FILE),
            key.clone(),
            sk.clone(),
        )?;
        let pm = state.pm.clone();
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        let mut socket = create_udp_listener(bind_addr, port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
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
                sk,
                mask,
                local_ip,
            }),
            state: state.clone(),
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
        loop {
            tokio::select! {
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
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
                    if rk.uuid.is_empty() || rk.pk.is_empty() {
                        return Ok(());
                    }
                    let id = rk.id;
                    let ip = addr.ip().to_string();
                    if id.len() < 6 || id.len() > MAX_PEER_ID_LEN {
                        return send_rk_res(socket, addr, UUID_MISMATCH).await;
                    } else if !self.check_ip_blocker(&ip, &id).await {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    let peer = self.pm.get_or(&id).await;
                    let (changed, ip_changed) = {
                        let peer = peer.read().await;
                        if peer.uuid.is_empty() {
                            (true, false)
                        } else {
                            if peer.uuid == rk.uuid {
                                if peer.info.ip != ip && peer.pk != rk.pk {
                                    log::warn!(
                                        "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                                        id,
                                        ip,
                                        rk.pk,
                                        peer.info.ip,
                                        peer.pk,
                                    );
                                    drop(peer);
                                    return send_rk_res(socket, addr, UUID_MISMATCH).await;
                                }
                            } else {
                                log::warn!(
                                    "Peer {} uuid mismatch: {:?} vs {:?}",
                                    id,
                                    rk.uuid,
                                    peer.uuid
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
                    if changed {
                        self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await;
                    }
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: register_pk_response::Result::OK.into(),
                        ..Default::default()
                    });
                    socket.send(&msg_out, addr).await?
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

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
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
                    });
                    if let Some(peer) = peer {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
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
                _ => {}
            }
        }
        false
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
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
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
        };
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed from {} for peer {} - invalid key", addr, ph.id);
            self.state.tracker.on_punch_request(track);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
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
                    b_id: &id,
                    a_token: &ph.token,
                    conn_type: ph.conn_type.value(),
                })
                .await;
            let mut relay_server = route.relay;
            let forced_relay = ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan);
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
            // udp_port and the WebRTC offer are not forwarded (PORTA.md §6.2)
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
            self.tx.send(Data::Msg(msg.into(), addr))?;
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
        self.tx.send(Data::Msg(
            msg.into(),
            match to_addr {
                Some(addr) => addr,
                None => addr,
            },
        ))?;
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&self, relay_servers: &str) {
        self.state
            .router
            .set_configured(crate::config::parse_relay_list(relay_servers));
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "geo-update(gu)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    res = self.state.router.status_text();
                }
            }
            Some("geo-update" | "gu") => {
                res = self.state.router.geo_update().await;
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
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
                                res = self.state.router.test(a, b.to_canonical()).await;
                            }
                        } else {
                            res = self.state.router.test(a, a).await;
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
                        stream.write(res.as_bytes()).await.ok();
                    }
                }
            });
            return;
        }
        let stream = FramedStream::from(stream, addr);
        tokio::spawn(async move {
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
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
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
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
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
        if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let callback = |req: &Request, response: Response| {
                addr = ws_client_addr(addr, req.headers());
                Ok(response)
            };
            let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
            let (a, mut b) = ws_stream.split();
            sink = Some(Sink::Ws(a));
            while let Ok(Some(Ok(msg))) = timeout(30_000, b.next()).await {
                if let tungstenite::Message::Binary(bytes) = msg {
                    if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                        break;
                    }
                }
            }
        } else {
            let (mut a, mut b) = Framed::new(stream, BytesCodec::new()).split();
            // KeyExchange (note 02 §6.2): offer first; the client's first frame either answers
            // it or is a plaintext message from a client that skips the offer.
            let mut offer = None;
            if let Some(sk) = &self.inner.sk {
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
                if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                    break;
                }
            }
        }
        if sink.is_none() {
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
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
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
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
/// IP-based limits (PORTA.md §6.5a).
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
            // the oldest half is evicted and the newest kept
            assert_eq!(lock.front().unwrap().to_id, format!("peer{}", max % 31));
            assert_eq!(lock.back().unwrap().to_id, format!("peer{}", (max * 2 - 1) % 31));
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
        let app = crate::testutil::app().await;
        app.state.router.set_configured(vec![RELAY.to_owned()]);
        let (server_pk, sk) = sign::gen_keypair();
        let (tx, rx) = mpsc::unbounded_channel();
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
                sk: with_sk.then_some(sk),
            }),
            state: app.state.clone(),
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
            let stream = TcpStream::connect(self.addr).await.unwrap();
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
            match timeout(3000, self.rx.recv()).await.unwrap().unwrap() {
                Data::Msg(msg, addr) => (*msg, addr),
                other => panic!("unexpected {other:?}"),
            }
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
        h.rs.parse_relay_servers(" r1:21117, r2 ,r1:21117,");
        let status = h.rs.check_cmd("rs").await;
        assert!(status.contains("r1:21117") && status.contains("r2") && !status.contains(RELAY));
        let test = h.rs.check_cmd("tg 1.1.1.1 ::ffff:2.2.2.2").await;
        assert!(test.contains("r1:21117") || test.contains("r2"), "{test}");
        // aur no longer touches the relay list
        assert_eq!(h.rs.check_cmd("aur N").await, "");
        assert_eq!(h.rs.check_cmd("rs").await, status);
    }
}
