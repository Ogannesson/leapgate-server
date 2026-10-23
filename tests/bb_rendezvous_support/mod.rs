//! bb_rendezvous 的黑盒测试辅助：起真实的 leapgate-server 进程，模拟控制端 A（TCP / WebSocket）
//! 和被控端 B（UDP 注册）。只依据 LEAPGATE.md、笔记 02/06 和上游客户端代码
//! （`rustdesk/src/common.rs` 的 `key_exchange`、`rendezvous_mediator.rs`），不依赖服务端实现。
#![allow(dead_code)]

use hbb_common::{
    bytes::Bytes,
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{FramedStream, KxTranscript},
    tokio,
    udp::FramedSocket,
    AddrMangle,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

/// 控制端 A 的源地址。和 B 用不同的回环地址：同一公网 IP 会走 `FetchLocalAddr`（局域网分支，
/// 笔记 02 §4.1），而不是 `PunchHole`。Linux 上整个 127/8 都在 lo 上。
pub const A_IP: &str = "127.0.0.2";
/// 被控端 B 的源地址（UDP 注册和回 `PunchHoleSent` 的 TCP 连接）。
pub const B_IP: &str = "127.0.0.3";
/// 每份 leapgate.toml 都要带：不在测试里下载 GeoIP 库。
pub const GEO_OFF: &str = "[geo]\nauto_update = false\n";
/// A 报的客户端版本（非空才会给 `PunchHoleResponse.pk` 签名，笔记 02 §6.1）。
pub const VERSION: &str = "1.4.2";

/// 一台运行中的 leapgate-server，Drop 时杀掉进程；测试失败时把服务日志尾部打到 stderr。
pub struct Server {
    child: Child,
    dir: tempfile::TempDir,
    /// `-p`：会合端口 P。API 在 P-2，NAT 测试/控制台在 P-1，WebSocket 在 P+2。
    pub port: u16,
    /// `id_ed25519.pub` 的内容：`licence_key` 要等于它，KeyExchange 的签名用它验。
    pub key: String,
}

impl Server {
    /// 在临时工作目录里起服务：写 `leapgate.toml`，设 `TEST_HBBS=no`，等端口和 `GET /` 就绪。
    pub async fn start(leapgate_toml: &str, envs: &[(&str, &str)]) -> Server {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("leapgate.toml"), leapgate_toml).unwrap();
        let port = free_port_block();
        let log = std::fs::File::create(dir.path().join("server.log")).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_leapgate-server"));
        cmd.current_dir(dir.path())
            .args(["-p", &port.to_string()])
            .env("TEST_HBBS", "no")
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let child = cmd.spawn().unwrap();
        let mut server = Server {
            child,
            dir,
            port,
            key: String::new(),
        };
        server.wait_ready().await;
        server
    }

    async fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("leapgate-server 提前退出：{status}");
            }
            let key = std::fs::read_to_string(self.dir.path().join("id_ed25519.pub"))
                .unwrap_or_default();
            let tcp_up = tokio::net::TcpStream::connect(self.addr()).await.is_ok();
            let api_up = match http.get(self.api_url("/")).send().await {
                Ok(resp) => resp.status() == 200,
                Err(_) => false,
            };
            if !key.trim().is_empty() && tcp_up && api_up {
                self.key = key.trim().to_owned();
                return;
            }
            assert!(Instant::now() < deadline, "leapgate-server 30 秒内没有就绪");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// 21116 对应的会合地址（TCP 和 UDP 同一个端口）。
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    pub fn ws_url(&self, host: &str) -> String {
        format!("ws://{host}:{}/", self.port + 2)
    }

    pub fn api_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port - 2)
    }

    pub fn pk(&self) -> sign::PublicKey {
        let raw = base64::decode(&self.key).unwrap();
        sign::PublicKey(raw.try_into().expect("服务端公钥不是 32 字节"))
    }

    /// 服务到目前为止的日志（stdout 和 stderr）。
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("server.log")).unwrap_or_default()
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.path().join("db_v2.sqlite3")
    }

    /// 直接打开服务的 SQLite（`DB_URL` 默认 `./db_v2.sqlite3`，LEAPGATE.md §4.1）造数据、查结果。
    pub async fn db(&self) -> SqlitePool {
        let opts = SqliteConnectOptions::new()
            .filename(self.db_path())
            .busy_timeout(Duration::from_secs(5));
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap()
    }

    /// 起好 A 的 TCP 连接并按 `kx` 完成（或不做）KeyExchange。
    pub async fn connect_a(&self, from: &str, kx: Kx) -> FramedStream {
        let mut s = connect_tcp(self.addr(), from).await;
        if kx != Kx::Plain {
            client_key_exchange(&mut s, &self.pk(), kx).await;
        }
        s
    }

    /// 一条带正确 `licence_key` 的 `PunchHoleRequest`（字段见笔记 02 §4.1 阶段 1）。
    pub fn punch_request(&self, b_id: &str) -> PunchHoleRequest {
        PunchHoleRequest {
            id: b_id.to_owned(),
            nat_type: NatType::ASYMMETRIC.into(),
            licence_key: self.key.clone(),
            version: VERSION.to_owned(),
            ..Default::default()
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        if std::thread::panicking() {
            let log = std::fs::read_to_string(self.dir.path().join("server.log")).unwrap_or_default();
            let lines: Vec<&str> = log.lines().collect();
            let tail = &lines[lines.len().saturating_sub(120)..];
            eprintln!("---- leapgate-server 日志（最后 {} 行）----\n{}", tail.len(), tail.join("\n"));
        }
    }
}

static USED_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());

/// 随机挑一个高端口 P，确认 P-2、P-1、P、P+2（TCP）和 P（UDP）都空闲。
/// 同一测试进程里并行的测试不会挑到重叠的端口组。
pub fn free_port_block() -> u16 {
    loop {
        // 20000~32699：避开 Linux 的临时端口段（32768~60999）。测试发起的连接从那里取本地端口，
        // 可能在这里检查完、服务端还没绑定之间占掉其中一个。
        let p = 20000 + (hbb_common::rand::random::<u16>() % 12700);
        let mut used = USED_PORTS.lock().unwrap();
        if used.iter().any(|u| u.abs_diff(p) <= 4) {
            continue;
        }
        let tcp_free = [p - 2, p - 1, p, p + 2]
            .iter()
            .all(|q| std::net::TcpListener::bind(("0.0.0.0", *q)).is_ok());
        if tcp_free && std::net::UdpSocket::bind(("0.0.0.0", p)).is_ok() {
            used.push(p);
            return p;
        }
    }
}

pub async fn connect_tcp(server: SocketAddr, from: &str) -> FramedStream {
    FramedStream::new(server, Some(format!("{from}:0").parse().unwrap()), 3000)
        .await
        .unwrap()
}

/// A 一侧 KeyExchange 的做法。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kx {
    /// 老客户端：不握手，直接发明文。
    Plain,
    /// 版本前的客户端：回 `version = 0`，一个密钥两个方向共用（`Encrypt::new`）。
    V0,
    /// 新客户端：回 `kx_version_for(服务端版本)`，按握手记录拆成两个方向的密钥。
    V1,
}

/// 读服务端连上后先发的 `KeyExchange`（LEAPGATE.md §6.1），按客户端 `key_exchange` 的规则验签：
/// `keys` 只有一个，用服务端公钥验得过，里面是 32 字节临时公钥。
pub async fn read_server_kx(s: &mut FramedStream, pk: &sign::PublicKey) -> (KeyExchange, [u8; 32]) {
    let bytes = s
        .next_timeout(5000)
        .await
        .expect("服务端没有先发 KeyExchange")
        .unwrap();
    let msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union else {
        panic!("服务端先发的不是 KeyExchange：{msg:?}");
    };
    assert_eq!(ex.keys.len(), 1, "服务端的 KeyExchange 只能带一个签名的临时公钥");
    let eph = sign::verify(&ex.keys[0], pk).expect("KeyExchange 的签名用 id_ed25519.pub 验不过");
    let eph: [u8; 32] = eph.try_into().expect("临时公钥不是 32 字节");
    (ex, eph)
}

/// 客户端一侧的握手，照抄 `rustdesk/src/common.rs` `key_exchange` + `create_symmetric_key_msg`。
pub async fn client_key_exchange(s: &mut FramedStream, pk: &sign::PublicKey, kx: Kx) {
    let (ex, their_pk) = read_server_kx(s, pk).await;
    let (our_pk, our_sk) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed = box_::seal(&key.0, &nonce, &box_::PublicKey(their_pk), &our_sk);
    let picked = match kx {
        Kx::V1 => hbb_common::tcp::kx_version_for(ex.version),
        _ => 0,
    };
    let mut msg = RendezvousMessage::new();
    msg.set_key_exchange(KeyExchange {
        keys: vec![our_pk.0.to_vec().into(), sealed.into()],
        version: picked,
        ..Default::default()
    });
    s.send(&msg).await.unwrap();
    if picked == 0 {
        s.set_key(key);
    } else {
        s.set_key_split(
            key,
            true,
            &KxTranscript {
                initiator_pk: &our_pk.0,
                responder_pk: &their_pk,
                advertised: ex.version,
                picked,
            },
        )
        .unwrap();
    }
}

pub async fn send(s: &mut FramedStream, msg: &RendezvousMessage) {
    s.send(msg).await.unwrap();
}

/// 读下一条非 KeyExchange 的消息（和客户端 `get_next_nonkeyexchange_msg` 一样跳过 KeyExchange）。
pub async fn recv(s: &mut FramedStream, ms: u64) -> RendezvousMessage {
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
        let bytes = s
            .next_timeout(left.max(1))
            .await
            .expect("等服务端回包超时或连接被关")
            .expect("读回包出错（加密信道上解密失败？）");
        let msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
        if !matches!(msg.union, Some(rendezvous_message::Union::KeyExchange(_))) {
            return msg;
        }
    }
}

pub fn msg_punch_request(ph: PunchHoleRequest) -> RendezvousMessage {
    let mut m = RendezvousMessage::new();
    m.set_punch_hole_request(ph);
    m
}

/// 客户端怎么编 `socket_addr_v6`：`AddrMangle::encode(v6 地址)`，18 字节。
pub fn v6(addr: &str) -> Bytes {
    AddrMangle::encode(addr.parse().unwrap()).into()
}

/// `AddrMangle` 编码的地址解出来，`::ffff:a.b.c.d` 规范成 IPv4。
pub fn decode_ip(bytes: &[u8]) -> (IpAddr, u16) {
    let addr = hbb_common::try_into_v4(AddrMangle::decode(bytes));
    (addr.ip(), addr.port())
}

/// 被控端 B：UDP 注册（`RegisterPk` + `RegisterPeer`，笔记 02 §2.2、§2.3），收服务端经 UDP
/// 转来的 `PunchHole` / `FetchLocalAddr`，用新开的 TCP 连接回应（笔记 02 §4.1 阶段 2）。
pub struct PeerB {
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub ip: String,
    sock: FramedSocket,
    server: SocketAddr,
}

impl PeerB {
    pub async fn register(server: &Server, id: &str, ip: &str) -> PeerB {
        let sock = FramedSocket::new(format!("{ip}:0")).await.unwrap();
        let mut b = PeerB {
            id: id.to_owned(),
            uuid: hbb_common::rand::random::<[u8; 16]>().to_vec(),
            pk: sign::gen_keypair().0 .0.to_vec(),
            ip: ip.to_owned(),
            sock,
            server: server.addr(),
        };
        let mut m = RendezvousMessage::new();
        m.set_register_pk(RegisterPk {
            id: b.id.clone(),
            uuid: b.uuid.clone().into(),
            pk: b.pk.clone().into(),
            ..Default::default()
        });
        b.sock.send(&m, b.server).await.unwrap();
        loop {
            let msg = b.next(5000).await.expect("RegisterPk 没有回包");
            if let Some(rendezvous_message::Union::RegisterPkResponse(r)) = msg.union {
                assert_eq!(
                    r.result.enum_value(),
                    Ok(register_pk_response::Result::OK),
                    "RegisterPk 被拒"
                );
                break;
            }
        }
        b.refresh().await;
        b
    }

    /// 心跳：发 `RegisterPeer`，等 `RegisterPeerResponse`（在线判定 30 秒，笔记 02 §2.5）。
    pub async fn refresh(&mut self) {
        let mut m = RendezvousMessage::new();
        m.set_register_peer(RegisterPeer {
            id: self.id.clone(),
            ..Default::default()
        });
        self.sock.send(&m, self.server).await.unwrap();
        loop {
            let msg = self.next(5000).await.expect("RegisterPeer 没有回包");
            if let Some(rendezvous_message::Union::RegisterPeerResponse(r)) = msg.union {
                assert!(!r.request_pk, "已注册的 B 心跳不应被要求重发 pk");
                return;
            }
        }
    }

    async fn next(&mut self, ms: u64) -> Option<RendezvousMessage> {
        let (bytes, _) = self.sock.next_timeout(ms).await?.ok()?;
        RendezvousMessage::parse_from_bytes(&bytes).ok()
    }

    /// 等服务端转来的打洞信令，跳过注册回包。
    pub async fn recv_signal(&mut self, ms: u64) -> rendezvous_message::Union {
        let deadline = Instant::now() + Duration::from_millis(ms);
        loop {
            let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
            let msg = self
                .next(left.max(1))
                .await
                .expect("B 没有在 UDP 上收到打洞信令");
            match msg.union {
                Some(rendezvous_message::Union::RegisterPeerResponse(_))
                | Some(rendezvous_message::Union::RegisterPkResponse(_))
                | Some(rendezvous_message::Union::ConfigureUpdate(_))
                | None => continue,
                Some(u) => return u,
            }
        }
    }

    /// 等一条 `PunchHole`（不是 `FetchLocalAddr`）。
    pub async fn recv_punch_hole(&mut self, ms: u64) -> PunchHole {
        match self.recv_signal(ms).await {
            rendezvous_message::Union::PunchHole(ph) => ph,
            other => panic!("B 收到的不是 PunchHole：{other:?}"),
        }
    }

    /// 像客户端那样新开一条 TCP 连接，明文发一条消息（只发不读，服务端先发的 KeyExchange 不理）。
    /// 返回连接，调用方在 A 收到回包前保持它不断开。
    pub async fn reply_tcp(&self, msg: &RendezvousMessage) -> FramedStream {
        let mut s = connect_tcp(self.server, &self.ip).await;
        s.send(msg).await.unwrap();
        s
    }
}

/// 一个假中继：在 127.0.0.1 上监听、accept 后立刻断开（健康检查只做 TCP 建连，LEAPGATE.md §7）。
pub struct FakeRelay {
    pub host: String,
    port: u16,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl FakeRelay {
    pub async fn start() -> FakeRelay {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        FakeRelay {
            host: format!("127.0.0.1:{port}"),
            port,
            task: Some(Self::serve(listener)),
        }
    }

    fn serve(listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        })
    }

    /// 关掉监听（之后建连被拒）。
    pub async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            task.await.ok();
        }
    }

    /// 在原端口重新监听。
    pub async fn restart(&mut self) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", self.port))
            .await
            .unwrap();
        self.task = Some(Self::serve(listener));
    }
}

/// `[[relay]]` 一节。
pub fn relay_toml(host: &str, weight: f64, lat_lon: Option<(f64, f64)>) -> String {
    let mut s = format!("[[relay]]\nhost = \"{host}\"\nweight = {weight:?}\n");
    if let Some((lat, lon)) = lat_lon {
        s += &format!("lat = {lat:?}\nlon = {lon:?}\n");
    }
    s
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub fn now_secs() -> i64 {
    now_ms() / 1000
}

/// 不重复的设备 id（≥ 6 位，RegisterPk 的要求，笔记 02 §2.3）。
pub fn unique_id(prefix: &str) -> String {
    static SEEN: Mutex<Option<HashSet<u32>>> = Mutex::new(None);
    let mut seen = SEEN.lock().unwrap();
    let seen = seen.get_or_insert_with(HashSet::new);
    loop {
        let n = 100_000_000 + hbb_common::rand::random::<u32>() % 900_000_000;
        if seen.insert(n) {
            return format!("{prefix}{n}");
        }
    }
}
