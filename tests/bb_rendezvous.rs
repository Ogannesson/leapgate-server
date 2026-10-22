//! 会合协议与路由的黑盒测试：起真实的 porta-server 进程，在回环地址上模拟控制端 A 和被控端 B。
//! 依据 PORTA.md §6（会合）、§7（路由）、§8（结果记录），笔记 02、06，以及上游客户端代码；
//! 不看服务端实现。下文"§6.1""§6.2"指 PORTA.md §6 的第 1、2 条，"§6.5a"指第 5a 条。
//! 现阶段各模块还没实现，除 `harness_server_starts_and_serves_index` 外大多会失败，这是预期的。

mod bb_rendezvous_support;

use bb_rendezvous_support::*;
use hbb_common::{
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::sign,
    tokio,
};
use sqlx::Row;
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// 进程管理和请求发送本身是对的：骨架已有的 `GET /` 说明页（PORTA.md §9.4）能取到，
/// 21116 在监听，`id_ed25519.pub` 已生成（`Server::start` 等的就是这三样）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harness_server_starts_and_serves_index() {
    let server = Server::start(GEO_OFF, &[]).await;
    let resp = reqwest::get(server.api_url("/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Porta"), "说明页里应有服务名 Porta");
    assert_eq!(server.pk().0.len(), 32);
}

/// 测试辅助自检：本文件客户端一侧的握手（`client_key_exchange`）对一个按笔记 02 §6.2 草图
/// 写的进程内服务端替身（照客户端测试 `rendezvous_stub` + `signed_key_exchange`）v0、v1 都能通、
/// 能互发加密消息。保证下面 KeyExchange 测试失败时是服务端的问题，不是辅助代码的问题。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harness_client_kx_matches_reference_server() {
    use hbb_common::{
        sodiumoxide::crypto::box_,
        tcp::{Encrypt, FramedStream, KxTranscript, KX_PARAMS_DOMAIN},
    };
    for kx in [Kx::V0, Kx::V1] {
        let (pk, sk) = sign::gen_keypair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stub = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let mut s = FramedStream::from(stream, peer);
            let (mut eph_pk, eph_sk) = box_::gen_keypair();
            eph_pk.0[31] |= 0x80;
            let params = KxParams {
                pk: eph_pk.0.to_vec().into(),
                version: 1,
                ..Default::default()
            };
            let mut payload = KX_PARAMS_DOMAIN.to_vec();
            payload.extend_from_slice(&params.write_to_bytes().unwrap());
            let mut msg = RendezvousMessage::new();
            msg.set_key_exchange(KeyExchange {
                keys: vec![sign::sign(&eph_pk.0, &sk).into()],
                version: 1,
                signed_params: sign::sign(&payload, &sk).into(),
                ..Default::default()
            });
            s.send(&msg).await.unwrap();
            let reply = RendezvousMessage::parse_from_bytes(&s.next().await.unwrap().unwrap()).unwrap();
            let Some(rendezvous_message::Union::KeyExchange(ex)) = reply.union else {
                panic!("替身期待客户端的 KeyExchange");
            };
            assert_eq!(ex.keys.len(), 2);
            let shared = Encrypt::decode(&ex.keys[1], &ex.keys[0], &eph_sk).unwrap();
            if ex.version >= 1 {
                let t = KxTranscript {
                    initiator_pk: &ex.keys[0],
                    responder_pk: &eph_pk.0,
                    advertised: 1,
                    picked: ex.version,
                };
                s.set_key_split(shared, false, &t).unwrap();
            } else {
                s.set_key(shared);
            }
            let req = RendezvousMessage::parse_from_bytes(&s.next().await.unwrap().unwrap()).unwrap();
            let Some(rendezvous_message::Union::TestNatRequest(nat)) = req.union else {
                panic!("替身期待加密的 TestNatRequest");
            };
            let mut msg = RendezvousMessage::new();
            msg.set_test_nat_response(TestNatResponse {
                port: nat.serial,
                ..Default::default()
            });
            s.send(&msg).await.unwrap();
            ex.version
        });
        let mut c = connect_tcp(addr, "127.0.0.1").await;
        client_key_exchange(&mut c, &pk, kx).await;
        let mut msg = RendezvousMessage::new();
        msg.set_test_nat_request(TestNatRequest {
            serial: 7,
            ..Default::default()
        });
        send(&mut c, &msg).await;
        let Some(rendezvous_message::Union::TestNatResponse(nat)) = recv(&mut c, 5000).await.union
        else {
            panic!("{kx:?}：期待加密的 TestNatResponse");
        };
        assert_eq!(nat.port, 7);
        let picked = stub.await.unwrap();
        assert_eq!(picked, if kx == Kx::V1 { 1 } else { 0 }, "{kx:?}");
    }
}

// ---------------------------------------------------------------- KeyExchange（PORTA.md §6.1）

/// §6.1、笔记 02 §6.2 步骤 1：21116/TCP 连上后服务端先发 v1 的 KeyExchange：
/// 签名的临时公钥（最高位置 1）、`version = 1`、`signed_params` = 签过名的
/// `KX_PARAMS_DOMAIN ++ KxParams{pk, version}`，两处签名都用 `id_ed25519.pub` 验得过
/// （验法照客户端 `key_exchange`）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kx_server_sends_signed_v1_first() {
    let server = Server::start(GEO_OFF, &[]).await;
    let mut s = connect_tcp(server.addr(), A_IP).await;
    let (ex, eph) = read_server_kx(&mut s, &server.pk()).await;
    assert_eq!(ex.version, 1, "§6.1 要求 v1");
    assert_ne!(eph[31] & 0x80, 0, "v1 的临时公钥最高位要置 1（笔记 02 §6.2）");
    let signed = sign::verify(&ex.signed_params, &server.pk()).expect("signed_params 验签失败");
    let params = signed
        .strip_prefix(hbb_common::tcp::KX_PARAMS_DOMAIN)
        .expect("signed_params 缺 KX_PARAMS_DOMAIN 前缀");
    let params = KxParams::parse_from_bytes(params).unwrap();
    assert_eq!(&params.pk[..], &eph[..], "KxParams.pk 要等于签名的临时公钥");
    assert_eq!(params.version, ex.version);
}

/// §6.1：第一帧是 `KeyExchange` 且 `keys.len()==2` 就建立加密，之后收发都加解密；v0（回
/// `version=0`，`Encrypt::new`）和 v1（`Encrypt::new_split`）都要通。加密信道上发
/// `PunchHoleRequest`（目标 id 不存在），要收到加密的 `PunchHoleResponse{ID_NOT_EXIST}`
/// （原版行为，笔记 02 §4.1）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kx_v0_and_v1_then_encrypted_request() {
    let server = Server::start(GEO_OFF, &[]).await;
    for kx in [Kx::V0, Kx::V1] {
        let mut a = server.connect_a(A_IP, kx).await;
        assert!(a.is_secured());
        let ph = server.punch_request(&unique_id(""));
        send(&mut a, &msg_punch_request(ph)).await;
        let msg = recv(&mut a, 5000).await;
        let Some(rendezvous_message::Union::PunchHoleResponse(resp)) = msg.union else {
            panic!("{kx:?}：期待 PunchHoleResponse，收到 {msg:?}");
        };
        assert_eq!(
            resp.failure.enum_value(),
            Ok(punch_hole_response::Failure::ID_NOT_EXIST),
            "{kx:?}"
        );
    }
}

/// §6.1：第一帧不是 `KeyExchange` 就按明文处理——不握手直接发明文的老客户端照常可用。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kx_plain_legacy_client_still_works() {
    let server = Server::start(GEO_OFF, &[]).await;
    let mut a = server.connect_a(A_IP, Kx::Plain).await;
    let ph = server.punch_request(&unique_id(""));
    send(&mut a, &msg_punch_request(ph)).await;
    let msg = recv(&mut a, 5000).await;
    let Some(rendezvous_message::Union::PunchHoleResponse(resp)) = msg.union else {
        panic!("期待 PunchHoleResponse，收到 {msg:?}");
    };
    assert_eq!(
        resp.failure.enum_value(),
        Ok(punch_hole_response::Failure::ID_NOT_EXIST)
    );
    // 明文连接上错的 licence_key 照旧回 LICENSE_MISMATCH（原版行为，笔记 02 §6.1）。
    let mut ph = server.punch_request(&unique_id(""));
    ph.licence_key = "wrong".to_owned();
    let mut a = server.connect_a(A_IP, Kx::Plain).await;
    send(&mut a, &msg_punch_request(ph)).await;
    let Some(rendezvous_message::Union::PunchHoleResponse(resp)) = recv(&mut a, 5000).await.union
    else {
        panic!("期待 PunchHoleResponse");
    };
    assert_eq!(
        resp.failure.enum_value(),
        Ok(punch_hole_response::Failure::LICENSE_MISMATCH)
    );
}

/// §6.1：21118（WebSocket）不做 KeyExchange，服务端也不先发；明文请求照常应答。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_does_not_send_key_exchange() {
    use hbb_common::futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let server = Server::start(GEO_OFF, &[]).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(server.ws_url("127.0.0.1"))
        .await
        .unwrap();
    // 连上后 1.5 秒内服务端什么都不该发。
    let first = tokio::time::timeout(Duration::from_millis(1500), ws.next()).await;
    assert!(first.is_err(), "21118 不该先发任何消息，收到 {first:?}");
    let ph = server.punch_request(&unique_id(""));
    let bytes = msg_punch_request(ph).write_to_bytes().unwrap();
    ws.send(Message::binary(bytes)).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("21118 没有回包")
        .expect("连接被关")
        .unwrap();
    let Message::Binary(bytes) = reply else {
        panic!("期待二进制帧，收到 {reply:?}");
    };
    let msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::PunchHoleResponse(resp)) = msg.union else {
        panic!("21118 的第一条消息应是 PunchHoleResponse（不是 KeyExchange），收到 {msg:?}");
    };
    assert_eq!(
        resp.failure.enum_value(),
        Ok(punch_hole_response::Failure::ID_NOT_EXIST)
    );
}

// ---------------------------------------------------------------- 打洞信令（PORTA.md §6.2）

/// §6.2、笔记 02 §6.5 的表：
/// - `PunchHoleRequest` → `PunchHole`：补 `socket_addr_v6`（A 的）、`force_relay`；
///   `relay_server` 是路由选出的中继（只配了一台，必然是它）；不转发 `udp_port`。
/// - `PunchHoleSent` → `PunchHoleResponse`：补 `socket_addr_v6`（B 的）、`upnp_port`。
/// B 用明文临时 TCP 连接回应（笔记 02 §6.2）。A 依次用明文、v0、v1 各走一遍：明文先测，转发本身
/// 的错误不会被 KeyExchange 的错误盖住；加密的两遍验证回给 A 的包经 `tcp_punch` 里带加密器的
/// 写半边发出（§6.1 "Sink 改型"）。
/// 其余字段按原版：`socket_addr` 是对方的地址，`pk` 是服务端签的 `IdPk{B id, B pk}`。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn punch_hole_forwards_v6_and_relay() {
    let relay = FakeRelay::start().await;
    let toml = format!("{GEO_OFF}{}", relay_toml(&relay.host, 1.0, None));
    let server = Server::start(&toml, &[]).await;
    let mut b = PeerB::register(&server, &unique_id(""), B_IP).await;

    let a_v6 = v6("[2001:db8::a]:40001");
    let b_v6 = v6("[2001:db8::b]:40002");
    for kx in [Kx::Plain, Kx::V0, Kx::V1] {
        b.refresh().await;
        let mut a = server.connect_a(A_IP, kx).await;
        let mut ph = server.punch_request(&b.id);
        ph.socket_addr_v6 = a_v6.clone();
        ph.udp_port = 5555;
        send(&mut a, &msg_punch_request(ph)).await;

        let hole = b.recv_punch_hole(5000).await;
        assert_eq!(&hole.socket_addr_v6[..], &a_v6[..], "{kx:?}：A 的 v6 地址要转给 B");
        assert_eq!(hole.relay_server, relay.host, "{kx:?}");
        assert_eq!(hole.udp_port, 0, "{kx:?}：第一期不转发 udp_port");
        assert!(!hole.force_relay, "{kx:?}");
        assert_eq!(hole.nat_type.enum_value(), Ok(NatType::ASYMMETRIC), "{kx:?}");
        assert_eq!(
            decode_ip(&hole.socket_addr),
            (ip(A_IP), a.local_addr().port()),
            "{kx:?}"
        );

        let mut sent = RendezvousMessage::new();
        sent.set_punch_hole_sent(PunchHoleSent {
            socket_addr: hole.socket_addr.clone(),
            id: b.id.clone(),
            relay_server: hole.relay_server.clone(),
            nat_type: NatType::ASYMMETRIC.into(),
            version: VERSION.to_owned(),
            socket_addr_v6: b_v6.clone(),
            upnp_port: 31234,
            ..Default::default()
        });
        let b_conn = b.reply_tcp(&sent).await;

        let msg = recv(&mut a, 5000).await;
        let Some(rendezvous_message::Union::PunchHoleResponse(resp)) = msg.union else {
            panic!("{kx:?}：A 期待 PunchHoleResponse，收到 {msg:?}");
        };
        assert_eq!(&resp.socket_addr_v6[..], &b_v6[..], "{kx:?}：B 的 v6 地址要转给 A");
        assert_eq!(resp.upnp_port, 31234, "{kx:?}：PunchHoleResponse 要补 upnp_port");
        assert_eq!(resp.relay_server, relay.host, "{kx:?}");
        assert_eq!(
            decode_ip(&resp.socket_addr),
            (ip(B_IP), b_conn.local_addr().port()),
            "{kx:?}"
        );
        let id_pk = sign::verify(&resp.pk, &server.pk()).expect("PunchHoleResponse.pk 验签失败");
        let id_pk = IdPk::parse_from_bytes(&id_pk).unwrap();
        assert_eq!(id_pk.id, b.id);
        assert_eq!(&id_pk.pk[..], &b.pk[..]);
    }

    // A 自己要求中继（`force_relay`）时照转给 B（§6.2 补 `PunchHole.force_relay`）。
    b.refresh().await;
    let mut a = server.connect_a(A_IP, Kx::Plain).await;
    let mut ph = server.punch_request(&b.id);
    ph.force_relay = true;
    send(&mut a, &msg_punch_request(ph)).await;
    let hole = b.recv_punch_hole(5000).await;
    assert!(hole.force_relay, "A 的 force_relay 要转给 B");
}

/// §6.2、笔记 02 §6.5 的表，局域网分支（A、B 公网 IP 相同 → `FetchLocalAddr`，笔记 02 §4.1）：
/// `FetchLocalAddr` 补 A 的 `socket_addr_v6`；B 回 `LocalAddr` 后 A 收到的
/// `PunchHoleResponse{is_local}` 补 B 的 `socket_addr_v6`。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lan_signaling_forwards_v6() {
    let relay = FakeRelay::start().await;
    let toml = format!("{GEO_OFF}{}", relay_toml(&relay.host, 1.0, None));
    let server = Server::start(&toml, &[]).await;
    let mut b = PeerB::register(&server, &unique_id(""), B_IP).await;

    let a_v6 = v6("[2001:db8::a]:40001");
    let b_v6 = v6("[2001:db8::b]:40002");
    // A 和 B 同一个源 IP。
    let mut a = server.connect_a(B_IP, Kx::Plain).await;
    let mut ph = server.punch_request(&b.id);
    ph.socket_addr_v6 = a_v6.clone();
    send(&mut a, &msg_punch_request(ph)).await;

    let fla = match b.recv_signal(5000).await {
        rendezvous_message::Union::FetchLocalAddr(fla) => fla,
        other => panic!("同 IP 时 B 应收到 FetchLocalAddr，收到 {other:?}"),
    };
    assert_eq!(&fla.socket_addr_v6[..], &a_v6[..], "A 的 v6 地址要转给 B");
    assert_eq!(fla.relay_server, relay.host);

    let local = v6("[2001:db8::c]:21118");
    let mut la = RendezvousMessage::new();
    la.set_local_addr(LocalAddr {
        socket_addr: fla.socket_addr.clone(),
        local_addr: local.clone(),
        relay_server: fla.relay_server.clone(),
        id: b.id.clone(),
        version: VERSION.to_owned(),
        socket_addr_v6: b_v6.clone(),
        ..Default::default()
    });
    let _b_conn = b.reply_tcp(&la).await;

    let msg = recv(&mut a, 5000).await;
    let Some(rendezvous_message::Union::PunchHoleResponse(resp)) = msg.union else {
        panic!("A 期待 PunchHoleResponse，收到 {msg:?}");
    };
    assert!(resp.is_local());
    assert_eq!(&resp.socket_addr[..], &local[..]);
    assert_eq!(&resp.socket_addr_v6[..], &b_v6[..], "B 的 v6 地址要转给 A");
}

/// §6.2、笔记 02 §6.4：hbbs 强制中继（`ALWAYS_USE_RELAY=Y`）时，转给 B 的 `PunchHole`
/// 清空 v6 地址、置 `force_relay`（原版还会把 `nat_type` 改成 SYMMETRIC）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn always_use_relay_clears_v6_and_forces_relay() {
    let relay = FakeRelay::start().await;
    let toml = format!("{GEO_OFF}{}", relay_toml(&relay.host, 1.0, None));
    let server = Server::start(&toml, &[("ALWAYS_USE_RELAY", "Y")]).await;
    let mut b = PeerB::register(&server, &unique_id(""), B_IP).await;

    let mut a = server.connect_a(A_IP, Kx::Plain).await;
    let mut ph = server.punch_request(&b.id);
    ph.socket_addr_v6 = v6("[2001:db8::a]:40001");
    send(&mut a, &msg_punch_request(ph)).await;

    let hole = b.recv_punch_hole(5000).await;
    assert!(hole.socket_addr_v6.is_empty(), "强制中继时不能转发 v6 地址");
    assert!(hole.force_relay, "强制中继时要置 force_relay");
    assert_eq!(hole.nat_type.enum_value(), Ok(NatType::SYMMETRIC));
    assert_eq!(hole.relay_server, relay.host);
}

// ---------------------------------------------------------------- 路由（PORTA.md §7）

/// 发一次打洞请求，返回 B 收到的 `PunchHole.relay_server`（路由的选择）。
async fn select_once(server: &Server, b: &mut PeerB) -> String {
    b.refresh().await;
    let mut a = server.connect_a(A_IP, Kx::Plain).await;
    send(&mut a, &msg_punch_request(server.punch_request(&b.id))).await;
    b.recv_punch_hole(5000).await.relay_server
}

/// §7 回退：没有 GeoIP 库、也没配 `server_location` 时，回环来源地址的位置未知（"server_location
/// 没写的字段视为未知"），中继也没有位置；双方位置都未知 → 在全部候选里轮询（权重不参与）。
/// 两台都健康的中继应严格交替出现。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_round_robin_without_geo() {
    let r1 = FakeRelay::start().await;
    let r2 = FakeRelay::start().await;
    let toml = format!(
        "{GEO_OFF}{}{}",
        relay_toml(&r1.host, 1.0, None),
        relay_toml(&r2.host, 5.0, None)
    );
    let server = Server::start(&toml, &[]).await;
    let mut b = PeerB::register(&server, &unique_id(""), B_IP).await;
    let mut picks = Vec::new();
    for _ in 0..4 {
        picks.push(select_once(&server, &mut b).await);
    }
    for p in &picks {
        assert!(*p == r1.host || *p == r2.host, "选了配置之外的中继：{p}");
    }
    for w in picks.windows(2) {
        assert_ne!(w[0], w[1], "轮询应交替：{picks:?}");
    }
}

/// 两台都配了位置覆盖的中继：R1 在 (0,10)、权重 1；R2 在 (0,1)、权重 20。
/// A、B 都是回环地址 → 按 `server_location` (0,0) 算（§7、笔记 06 §5.2）。
/// 代价（§7、笔记 06 §4，k=2）：R1 = (22.2+22.2)×1 ≈ 44；R2 = (2.2+2.2)×20 ≈ 89 → 选 R1
/// （不乘权重的话 R2 更近，所以这也验证了权重确实参与）。
fn geo_toml(r1: &str, r2: &str) -> String {
    format!(
        "{GEO_OFF}server_location = {{ lat = 0.0, lon = 0.0 }}\n{}{}",
        relay_toml(r1, 1.0, Some((0.0, 10.0))),
        relay_toml(r2, 20.0, Some((0.0, 1.0)))
    )
}

/// §7 代价排序 + 固定中继：`device_policy.relay_pin` 写库后下一次请求立即用它（每次按 `b_id`
/// 查库、不缓存，不重启），而且不看健康状态（这里的固定中继根本解析不了）；清成 `''` 后回到按代价选。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_geo_weight_and_pin() {
    let r1 = FakeRelay::start().await;
    let r2 = FakeRelay::start().await;
    let server = Server::start(&geo_toml(&r1.host, &r2.host), &[]).await;
    let mut b = PeerB::register(&server, &unique_id(""), B_IP).await;
    for _ in 0..3 {
        assert_eq!(select_once(&server, &mut b).await, r1.host, "按代价应选 R1");
    }

    let db = server.db().await;
    let pinned = "pinned.invalid:21117";
    sqlx::query("insert into device_policy(device_id, relay_pin) values(?, ?)")
        .bind(&b.id)
        .bind(pinned)
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(select_once(&server, &mut b).await, pinned, "relay_pin 写库后应立即生效");
    assert_eq!(select_once(&server, &mut b).await, pinned);

    sqlx::query("update device_policy set relay_pin = '' where device_id = ?")
        .bind(&b.id)
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(select_once(&server, &mut b).await, r1.host, "relay_pin 清空后回到按代价选");
}

/// §7 健康检查：每 3 秒对每台中继 TCP 建连（3 秒超时），只有可达的进候选。停掉 R1 的监听后
/// 几轮内不再选它（改选 R2）；在原端口恢复监听后又回到 R1（"恢复后自动回到候选里"，§5）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_health_check_drops_dead_relay() {
    let mut r1 = FakeRelay::start().await;
    let r2 = FakeRelay::start().await;
    let server = Server::start(&geo_toml(&r1.host, &r2.host), &[]).await;
    let mut b = PeerB::register(&server, &unique_id(""), B_IP).await;
    assert_eq!(select_once(&server, &mut b).await, r1.host);

    r1.stop().await;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let pick = select_once(&server, &mut b).await;
        if pick == r2.host {
            break;
        }
        assert_eq!(pick, r1.host);
        assert!(Instant::now() < deadline, "R1 停掉 15 秒后仍被选中");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    r1.restart().await;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let pick = select_once(&server, &mut b).await;
        if pick == r1.host {
            break;
        }
        assert_eq!(pick, r2.host);
        assert!(Instant::now() < deadline, "R1 恢复 15 秒后仍没回到候选");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

// ---------------------------------------------------------------- 结果记录（PORTA.md §8）

/// §8、笔记 02 §4.4：hbbs 直接回失败的请求（目标离线 → `fail_offline`，id 不存在 →
/// `fail_id_not_exist`）定稿为 `outcome = 'rejected'`。离线的 B = `peer` 表里有、内存里不在线。
/// 带令牌的那条，`a_user` = `user.name`、`a_device_id` = `token.device_id`（后台反查）；
/// 不带令牌的两者都是 NULL。其余列：`a_ip` 规范成 IPv4（§3），`via='tcp'`，`started_at` 是毫秒。
/// 定稿时机契约没写死（每 5 秒扫一次），这里最多等 50 秒。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conn_attempt_records_rejected() {
    let server = Server::start(GEO_OFF, &[]).await;
    let db = server.db().await;
    let offline_id = unique_id("");
    let missing_id = unique_id("");
    sqlx::query("insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)")
        .bind(hbb_common::rand::random::<[u8; 16]>().to_vec())
        .bind(&offline_id)
        .bind(hbb_common::rand::random::<[u8; 16]>().to_vec())
        .bind(sign::gen_keypair().0 .0.to_vec())
        .bind(r#"{"ip":""}"#)
        .execute(&db)
        .await
        .unwrap();
    let now = now_secs();
    let user_id = sqlx::query("insert into user(name, created_at, updated_at) values('alice', ?, ?)")
        .bind(now)
        .bind(now)
        .execute(&db)
        .await
        .unwrap()
        .last_insert_rowid();
    let token = "bb-rendezvous-token-0123456789";
    let token_hash: String = <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    sqlx::query(
        "insert into token(token_hash, user_id, device_id, created_at, last_used_at) values(?, ?, '987654321', ?, ?)",
    )
    .bind(&token_hash)
    .bind(user_id)
    .bind(now)
    .bind(now)
    .execute(&db)
    .await
    .unwrap();

    let t0 = now_ms();
    // 离线目标：带令牌（登录过）的请求。用明文发，免得 KeyExchange 的问题盖住记录的问题。
    let mut a1 = server.connect_a(A_IP, Kx::Plain).await;
    let mut ph = server.punch_request(&offline_id);
    ph.token = token.to_owned();
    ph.conn_type = ConnType::FILE_TRANSFER.into();
    ph.socket_addr_v6 = v6("[2001:db8::a]:40001");
    send(&mut a1, &msg_punch_request(ph)).await;
    let Some(rendezvous_message::Union::PunchHoleResponse(resp)) = recv(&mut a1, 5000).await.union
    else {
        panic!("期待 PunchHoleResponse");
    };
    assert_eq!(resp.failure.enum_value(), Ok(punch_hole_response::Failure::OFFLINE));
    // 不存在的目标：未登录的老客户端。
    let mut a2 = server.connect_a(A_IP, Kx::Plain).await;
    send(&mut a2, &msg_punch_request(server.punch_request(&missing_id))).await;
    let Some(rendezvous_message::Union::PunchHoleResponse(resp)) = recv(&mut a2, 5000).await.union
    else {
        panic!("期待 PunchHoleResponse");
    };
    assert_eq!(resp.failure.enum_value(), Ok(punch_hole_response::Failure::ID_NOT_EXIST));
    let t1 = now_ms();

    let deadline = Instant::now() + Duration::from_secs(50);
    let rows = loop {
        let rows = sqlx::query(
            "select * from conn_attempt where b_id in (?, ?) and outcome is not null order by b_id",
        )
        .bind(&offline_id)
        .bind(&missing_id)
        .fetch_all(&db)
        .await
        .unwrap();
        if rows.len() >= 2 {
            break rows;
        }
        assert!(Instant::now() < deadline, "50 秒内 conn_attempt 没有定稿两条 rejected：{}", rows.len());
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    assert_eq!(rows.len(), 2, "每次请求一行");
    for row in &rows {
        let b_id: String = row.get("b_id");
        let (signal, port, user, device, conn_type, has_v6) = if b_id == offline_id {
            (
                "fail_offline",
                a1.local_addr().port(),
                Some("alice".to_owned()),
                Some("987654321".to_owned()),
                1,
                1,
            )
        } else {
            ("fail_id_not_exist", a2.local_addr().port(), None, None, 0, 0)
        };
        assert_eq!(row.get::<String, _>("outcome"), "rejected", "{b_id}");
        assert_eq!(row.get::<String, _>("signal"), signal);
        assert_eq!(row.get::<String, _>("a_ip"), A_IP, "a_ip 要规范成 IPv4");
        assert_eq!(row.get::<i64, _>("a_port"), port as i64);
        assert_eq!(row.get::<String, _>("via"), "tcp");
        assert_eq!(row.get::<Option<String>, _>("a_user"), user);
        assert_eq!(row.get::<Option<String>, _>("a_device_id"), device);
        assert_eq!(row.get::<Option<String>, _>("a_version").as_deref(), Some(VERSION));
        assert_eq!(row.get::<i64, _>("conn_type"), conn_type);
        assert_eq!(row.get::<i64, _>("a_nat_type"), 1);
        assert_eq!(row.get::<i64, _>("a_force_relay"), 0);
        assert_eq!(row.get::<i64, _>("a_has_v6"), has_v6);
        assert_eq!(row.get::<i64, _>("server_forced_relay"), 0);
        let started: i64 = row.get("started_at");
        assert!(
            (t0 - 1000..=t1 + 1000).contains(&started),
            "started_at 应是毫秒：{started} 不在 [{t0}, {t1}]"
        );
        assert!(row.get::<Option<i64>, _>("finalized_at").is_some());
    }
}

// ---------------------------------------------------------------- 21118 来源 IP（PORTA.md §6.5a）

/// 经 21118 发一次打洞请求（带 `X-Real-IP`），返回 B 收到的 `PunchHole.socket_addr` 里的 A 地址。
async fn ws_punch_seen_by_b(server: &Server, b: &mut PeerB, host: &str, real_ip: &str) -> IpAddr {
    use hbb_common::futures::SinkExt;
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};
    b.refresh().await;
    let mut req = server.ws_url(host).into_client_request().unwrap();
    req.headers_mut()
        .insert("X-Real-IP", HeaderValue::from_str(real_ip).unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let bytes = msg_punch_request(server.punch_request(&b.id))
        .write_to_bytes()
        .unwrap();
    ws.send(Message::binary(bytes)).await.unwrap();
    let hole = b.recv_punch_hole(5000).await;
    drop(ws);
    decode_ip(&hole.socket_addr).0
}

/// §6.5a：21118 只在 TCP 对端是回环地址时才信任 `X-Real-IP`，否则用 TCP 对端地址。
/// 观察点：B 收到的 `PunchHole.socket_addr` 就是服务端认定的 A 地址。
/// 非回环对端用本机的非回环地址连自己；本机没有这种地址时注明跳过这一半。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_x_real_ip_trusted_only_from_loopback() {
    let relay = FakeRelay::start().await;
    let toml = format!("{GEO_OFF}{}", relay_toml(&relay.host, 1.0, None));
    let server = Server::start(&toml, &[]).await;
    let mut b = PeerB::register(&server, &unique_id(""), B_IP).await;
    let spoofed = "203.0.113.9";

    let seen = ws_punch_seen_by_b(&server, &mut b, "127.0.0.1", spoofed).await;
    assert_eq!(seen, ip(spoofed), "回环来源（同机反代）的 X-Real-IP 要信任");

    let local = match local_ip_address::local_ip() {
        Ok(addr) if !addr.is_loopback() => addr,
        other => {
            eprintln!("跳过非回环来源的一半：本机没有非回环地址（{other:?}）");
            return;
        }
    };
    let seen = ws_punch_seen_by_b(&server, &mut b, &local.to_string(), spoofed).await;
    assert_eq!(seen, local, "直连 21118 时伪造的 X-Real-IP 不能被信任，应使用 TCP 对端地址");
}

// ---------------------------------------------------------------- 资源上限（PORTA.md §6 第 8 条）

/// 21116 的帧上限 16 KB：带 8 KB WebRTC offer 的 `PunchHoleRequest` 照常应答；
/// 帧头声明 20 KB 的帧一到，连接就被断开。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_is_disconnected() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = Server::start(GEO_OFF, &[]).await;
    let mut a = server.connect_a(A_IP, Kx::Plain).await;
    let mut ph = server.punch_request(&unique_id(""));
    ph.webrtc_sdp_offer = "o".repeat(8 * 1024);
    send(&mut a, &msg_punch_request(ph)).await;
    let Some(rendezvous_message::Union::PunchHoleResponse(resp)) = recv(&mut a, 5000).await.union
    else {
        panic!("期待 PunchHoleResponse");
    };
    assert_eq!(
        resp.failure.enum_value(),
        Ok(punch_hole_response::Failure::ID_NOT_EXIST)
    );

    let mut s = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    // 20 KB 要 3 字节帧头：长度左移 2 位，低 2 位是帧头字节数 - 1（客户端 `BytesCodec`）。
    let n: u32 = 20 * 1024;
    s.write_all(&((n << 2) | 2).to_le_bytes()[..3]).await.unwrap();
    // 服务端可能已经断开，后面的数据写不进去也没关系。
    let _ = s.write_all(&[0u8; 1024]).await;
    let mut buf = Vec::new();
    let res = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    assert!(res.is_ok(), "超过帧上限的连接 5 秒内没有被断开");
}

/// 21118 连上后不做 WebSocket 握手：约 10 秒后被服务端关掉（握手超时），不会一直占着连接。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_without_handshake_times_out() {
    use tokio::io::AsyncReadExt;
    let server = Server::start(GEO_OFF, &[]).await;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", server.port + 2))
        .await
        .unwrap();
    let started = Instant::now();
    let mut buf = Vec::new();
    let res = tokio::time::timeout(Duration::from_secs(20), s.read_to_end(&mut buf)).await;
    assert!(res.is_ok(), "不握手的 WebSocket 连接 20 秒后还没被断开");
    let waited = started.elapsed();
    assert!(waited >= Duration::from_secs(8), "握手超时应约 10 秒，实际 {waited:?}");
    assert!(buf.is_empty(), "服务端不该发任何数据：{buf:?}");
}

/// 审查 C-1/C-7/C-8：未认证、每个包都能触发的日志每分钟最多一行，攻击者给的 id 截断后才进日志
/// （PORTA.md §6 第 7 条）。
/// - 21116 上许可证不符的 `PunchHoleRequest`：一条连接连发 300 条，每条 id 约 16 KB；
/// - 别的地址替一台在线设备发 `RegisterPeer`（"IP change"）：连发 2000 个。回环来源不算换 IP，
///   要用本机的非回环地址；没有时注明跳过这一半。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_floods_log_once_a_minute() {
    let server = Server::start(GEO_OFF, &[]).await;
    let mut a = server.connect_a(A_IP, Kx::Plain).await;
    for _ in 0..300 {
        let mut ph = server.punch_request(&"x".repeat(16_000));
        ph.licence_key = String::new();
        send(&mut a, &msg_punch_request(ph)).await;
    }

    let local = match local_ip_address::local_ip() {
        Ok(addr) if !addr.is_loopback() => Some(addr),
        other => {
            eprintln!("跳过 IP change 的一半：本机没有非回环地址（{other:?}）");
            None
        }
    };
    if let Some(local) = local {
        let b = PeerB::register(&server, &unique_id(""), B_IP).await;
        let mut sock = hbb_common::udp::FramedSocket::new(format!("{local}:0")).await.unwrap();
        let mut m = RendezvousMessage::new();
        m.set_register_peer(RegisterPeer {
            id: b.id.clone(),
            ..Default::default()
        });
        for i in 0..2000 {
            sock.send(&m, std::net::SocketAddr::new(local, server.port)).await.unwrap();
            if i % 100 == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let log = server.log();
    let auth: Vec<&str> = log.lines().filter(|l| l.contains("Authentication failed")).collect();
    assert_eq!(auth.len(), 1, "{auth:?}");
    assert!(auth[0].len() < 1024 && auth[0].contains("(16000 bytes)"), "{}", auth[0]);
    if local.is_some() {
        let n = log.lines().filter(|l| l.contains("IP change of")).count();
        assert_eq!(n, 1, "IP change 行数");
    }
}

// ---------------------------------------------------------------- 会合不等 API（PORTA.md §4.1）

/// UDP 发一条 `RegisterPk`，返回结果（`timeout_ms` 内没回包为 None）和耗时。
async fn register_pk_from(
    server: &Server,
    from: &str,
    id: &str,
    uuid: &[u8],
    timeout_ms: u64,
) -> (Option<register_pk_response::Result>, Duration) {
    let mut sock = hbb_common::udp::FramedSocket::new(format!("{from}:0")).await.unwrap();
    let mut m = RendezvousMessage::new();
    m.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: uuid.to_vec().into(),
        pk: sign::gen_keypair().0 .0.to_vec().into(),
        ..Default::default()
    });
    let t = Instant::now();
    sock.send(&m, server.addr()).await.unwrap();
    while let Some(Ok((bytes, _))) = sock.next_timeout(timeout_ms).await {
        if let Ok(RendezvousMessage {
            union: Some(rendezvous_message::Union::RegisterPkResponse(r)),
            ..
        }) = RendezvousMessage::parse_from_bytes(&bytes)
        {
            return (r.result.enum_value().ok(), t.elapsed());
        }
    }
    (None, t.elapsed())
}

/// 在线设备 L 的一次 `RegisterPeer` 往返；`timeout_ms` 内没回包为 None。
async fn register_peer_rtt(sock: &mut hbb_common::udp::FramedSocket, server: &Server, id: &str, timeout_ms: u64) -> Option<Duration> {
    let mut m = RendezvousMessage::new();
    m.set_register_peer(RegisterPeer {
        id: id.to_owned(),
        ..Default::default()
    });
    let t = Instant::now();
    sock.send(&m, server.addr()).await.unwrap();
    while let Some(Ok((bytes, _))) = sock.next_timeout(timeout_ms).await {
        if let Ok(RendezvousMessage {
            union: Some(rendezvous_message::Union::RegisterPeerResponse(_)),
            ..
        }) = RendezvousMessage::parse_from_bytes(&bytes)
        {
            return Some(t.elapsed());
        }
    }
    None
}

/// 21116 新连接收到第一个字节（KeyExchange offer）要多久；`timeout_ms` 内没收到为 None。
async fn first_byte(server: &Server, timeout_ms: u64) -> Option<Duration> {
    use tokio::io::AsyncReadExt;
    let t = Instant::now();
    let mut s = tokio::net::TcpStream::connect(server.addr()).await.ok()?;
    let mut b = [0u8; 1];
    match tokio::time::timeout(Duration::from_millis(timeout_ms), s.read_exact(&mut b)).await {
        Ok(Ok(_)) => Some(t.elapsed()),
        _ => None,
    }
}

/// 审查 C-21：未认证的 `/api/audit/alarm` 被几百个并发连接灌着（每条两次写库）时，新 id 的
/// `RegisterPk` 不能让会合主循环跟着等库：同时到的 `RegisterPeer` 回包、21116 新连接的首字节
/// 都要在几十毫秒内。会合用自己的小连接池，不和 API 排同一个队（PORTA.md §4.1）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_write_flood_does_not_stall_rendezvous() {
    const FLOODERS: usize = 400;
    // 库放在磁盘上（target/tmp）：/tmp 常是 tmpfs，提交不落盘，等库的时间看不出来。
    let disk = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let db_url = disk.path().join("db_v2.sqlite3");
    let server = std::sync::Arc::new(
        Server::start(GEO_OFF, &[("DB_URL", db_url.to_str().unwrap())]).await,
    );
    // 攻击者先免认证注册一台假设备 X，uuid 就对得上；L 是一台正常在线的设备。
    let x = PeerB::register(&server, &unique_id(""), B_IP).await;
    let l_id = unique_id("");
    let l = PeerB::register(&server, &l_id, "127.0.0.4").await;
    let mut l_sock = hbb_common::udp::FramedSocket::new("127.0.0.4:0").await.unwrap();
    drop(l);
    // 换了端口、IP 不变：照常刷新在线。
    register_peer_rtt(&mut l_sock, &server, &l_id, 5000).await.expect("L 的心跳没有回包");

    let body = format!(
        r#"{{"id":"{}","uuid":"{}","typ":0,"info":"x"}}"#,
        x.id,
        base64::encode(&x.uuid)
    );
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(FLOODERS)
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();
    let mut flood = Vec::new();
    for _ in 0..FLOODERS {
        let (http, url, body, stop, sent) = (
            http.clone(),
            server.api_url("/api/audit/alarm"),
            body.clone(),
            stop.clone(),
            sent.clone(),
        );
        flood.push(tokio::spawn(async move {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = http
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(body.clone())
                    .send()
                    .await;
                sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let flood_start = (Instant::now(), sent.load(std::sync::atomic::Ordering::Relaxed));

    let mut worst = Duration::ZERO;
    let mut lines = Vec::new();
    for i in 0..10 {
        // 新 id 的 RegisterPk（每次换来源，远低于每来源限额），20 ms 后测 L 的心跳和 21116。
        let pk_task = {
            let server = server.clone();
            tokio::spawn(async move {
                register_pk_from(&server, &format!("127.0.1.{}", i + 1), &unique_id(""), b"uuid-c21", 40_000).await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (peer, fb) = tokio::join!(
            register_peer_rtt(&mut l_sock, &server, &l_id, 40_000),
            first_byte(&server, 40_000)
        );
        let (res, pk_rtt) = pk_task.await.unwrap();
        let line = format!(
            "#{i}: RegisterPk {res:?} {pk_rtt:?}, RegisterPeer {peer:?}, 21116 首字节 {fb:?}"
        );
        eprintln!("{line}");
        lines.push(line);
        worst = worst
            .max(peer.unwrap_or(Duration::MAX))
            .max(fb.unwrap_or(Duration::MAX));
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (t0, n0) = flood_start;
    let rate = (sent.load(std::sync::atomic::Ordering::Relaxed) - n0) as f64 / t0.elapsed().as_secs_f64();
    eprintln!("alarm 洪水约 {rate:.0} req/s；RegisterPeer / 21116 最坏 {worst:?}");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for f in flood {
        f.abort();
    }
    assert!(
        worst < Duration::from_millis(100),
        "API 洪水拖住了会合主循环：最坏 {worst:?}\n{}",
        lines.join("\n")
    );
}
