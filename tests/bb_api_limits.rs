//! 黑盒测试：21114 的连接保护（审查 C-9）：连接总数和每来源上限、请求头超时、整请求超时、
//! 按路由的请求体上限、慢读者断开、`/api/ab/peers` 的每用户名额。每个测试起一个真实的 porta-server
//! 进程（见 `bb_api_support`），用裸 TCP 看服务端什么时候关连接、回什么。
//!
//! 常量照实现的取值（src/api/listen.rs、src/api/mod.rs、src/api/ab.rs）：总数 512、每来源 32、
//! 请求头 10 秒、整请求 20 秒（上报类 10 秒）、读写无进度 30 秒；登录等接口请求体 16 KB，
//! `DELETE /api/ab/peer` 2 MB；`/api/ab/peers` 每个用户同时最多 2 页。
//! 写下限（慢慢读的客户端）要服务端发送缓冲小才测得出，回环上内核会把它涨到几 MB，所以在
//! src/api/listen.rs 的单元测试里测。

mod bb_api_support;

use bb_api_support::*;
use hbb_common::tokio;
use serde_json::Value;
use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream},
    thread,
    time::{Duration, Instant},
};

const MAX_CONNS: usize = 512;
const MAX_CONNS_PER_SOURCE: usize = 32;

fn api_addr(s: &Server) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], s.port - 2))
}

/// 在 `wait` 内等服务端关掉连接（读到 EOF 或被重置）；到时还开着返回 false。读到数据算测试失败。
fn closed_within(stream: &mut TcpStream, wait: Duration) -> bool {
    stream.set_read_timeout(Some(wait)).unwrap();
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(0) => true,
        Ok(n) => panic!("unexpected data: {:?}", String::from_utf8_lossy(&buf[..n])),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => false,
        Err(_) => true,
    }
}

/// 不阻塞地看一眼：连接还开着（没有 EOF、没被重置、也没有数据）。
fn still_open(stream: &TcpStream) -> bool {
    stream.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 1];
    let open = matches!(stream.peek(&mut buf), Err(e) if e.kind() == ErrorKind::WouldBlock);
    stream.set_nonblocking(false).unwrap();
    open
}

/// 读一个 HTTP/1.1 响应（按 Content-Length），返回 (状态码, body)。
fn read_response(stream: &mut TcpStream) -> (u16, Vec<u8>) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
            let status: u16 = head[9..12].parse().unwrap();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse().unwrap());
            if data.len() >= end + 4 + len {
                return (status, data[end + 4..end + 4 + len].to_vec());
            }
        }
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed mid-response: {:?}", String::from_utf8_lossy(&data));
        data.extend_from_slice(&buf[..n]);
    }
}

fn get_root(stream: &mut TcpStream) -> u16 {
    stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    read_response(stream).0
}

/// 等服务端把前一个测试步骤关掉的连接收尾（许可在服务端读到 EOF 后才归还）。
async fn settle() {
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
async fn connections_over_the_per_source_cap_are_closed() {
    let Some(ip) = non_loopback_ip() else {
        eprintln!("no non-loopback address on this host; skipped");
        return;
    };
    let s = Server::start().await;
    let addr = SocketAddr::new(ip, s.port - 2);
    settle().await;
    // 这些连接什么都不发：要在 10 秒的请求头超时之前做完。
    let mut held: Vec<TcpStream> = (0..MAX_CONNS_PER_SOURCE).map(|_| TcpStream::connect(addr).unwrap()).collect();
    let mut extra = TcpStream::connect(addr).unwrap();
    assert!(closed_within(&mut extra, Duration::from_secs(3)), "connection N+1 from one source must be closed");
    assert!(held.iter().all(still_open), "the first N connections stay open");
    // 回环来源（同机反代）不计每来源，照常服务。
    let mut lo = TcpStream::connect(api_addr(&s)).unwrap();
    assert_eq!(get_root(&mut lo), 200);
    // 名额还回来后同一来源又能连上。
    drop(held.pop());
    settle().await;
    let mut again = TcpStream::connect(addr).unwrap();
    assert_eq!(get_root(&mut again), 200);
}

#[tokio::test]
async fn connections_over_the_total_cap_are_closed() {
    let s = Server::start().await;
    settle().await;
    let addr = api_addr(&s);
    let mut held: Vec<TcpStream> = (0..MAX_CONNS).map(|_| TcpStream::connect(addr).unwrap()).collect();
    let mut extra = TcpStream::connect(addr).unwrap();
    assert!(closed_within(&mut extra, Duration::from_secs(3)), "connection {} must be closed", MAX_CONNS + 1);
    assert!(held.iter().all(still_open), "the first {MAX_CONNS} connections stay open");
    drop(held.pop());
    settle().await;
    let mut again = TcpStream::connect(addr).unwrap();
    assert_eq!(get_root(&mut again), 200);
}

#[tokio::test]
async fn connections_without_a_request_head_are_closed_after_10s() {
    let s = Server::start().await;
    let addr = api_addr(&s);
    let silent = TcpStream::connect(addr).unwrap();
    let mut half = TcpStream::connect(addr).unwrap();
    half.write_all(b"POST /api/login HTTP/1.1\r\nHost: x\r\n").unwrap();
    // keep-alive：一次请求之后空闲，下一个请求头同样要在 10 秒内到。
    let mut idle = TcpStream::connect(addr).unwrap();
    assert_eq!(get_root(&mut idle), 200);
    let start = Instant::now();
    let waits: Vec<_> = [("silent", silent), ("half head", half), ("idle keep-alive", idle)]
        .into_iter()
        .map(|(name, mut stream)| {
            thread::spawn(move || {
                assert!(closed_within(&mut stream, Duration::from_secs(20)), "{name}: still open after 20 s");
                (name, start.elapsed())
            })
        })
        .collect();
    for w in waits {
        let (name, took) = w.join().unwrap();
        assert!(
            (Duration::from_secs(9)..Duration::from_secs(14)).contains(&took),
            "{name}: closed after {took:?}, expected about 10 s"
        );
    }
}

#[tokio::test]
async fn a_request_head_over_16kb_gets_431() {
    let s = Server::start().await;
    let mut stream = TcpStream::connect(api_addr(&s)).unwrap();
    write!(stream, "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: {}\r\n\r\n", "a".repeat(16 * 1024)).unwrap();
    assert_eq!(read_response(&mut stream).0, 431);
    // 正常大小的请求头照常服务（真实的请求头不到 2 KB）。
    let mut stream = TcpStream::connect(api_addr(&s)).unwrap();
    write!(stream, "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: {}\r\n\r\n", "a".repeat(8 * 1024)).unwrap();
    assert_eq!(read_response(&mut stream).0, 200);
}

#[tokio::test]
async fn bodies_over_the_route_limit_get_413() {
    let s = Server::start().await;
    let uid = s.create_user("alice", "pw", false).await;
    let token = s.issue_token(uid).await;
    let r = s.post("/api/login", None, &" ".repeat(16 * 1024 + 1)).await;
    assert_eq!(r.status, 413, "{:?}", r.text());
    r.assert_error_body();
    let r = s.post("/api/ab/personal", Some(&token), "").await;
    let guid = r.json()["guid"].as_str().unwrap().to_owned();
    let r = s.request("PUT", &format!("/api/ab/peer/update/{guid}"), Some(&token), Some(&" ".repeat(64 * 1024 + 1)), &[]).await;
    assert_eq!(r.status, 413, "{:?}", r.text());
    // 上游客户端一次删除把全部 id 放进一个数组：满簿 5000 个最长的 id 约 1.3 MB，要能过。
    let ids: Vec<String> = (0..5000).map(|i| format!("{i:0>253}")).collect();
    let body = serde_json::to_string(&ids).unwrap();
    assert!(body.len() > 1 << 20);
    let r = s.request("DELETE", &format!("/api/ab/peer/{guid}"), Some(&token), Some(&body), &[]).await;
    assert_eq!((r.status, r.body.len()), (200, 0), "{:?}", r.text());
}

#[tokio::test]
async fn a_body_trickling_in_gets_the_internal_error_answer_in_time() {
    let s = Server::start().await;
    let uid = s.create_user("alice", "pw", false).await;
    let token = s.issue_token(uid).await;
    let addr = api_addr(&s);
    // §9.1：审计和 currentUser 的内部错误回 200 + {"error"}，其他接口回 400 + {"error"}。
    // §9.4：上报类（心跳、sysinfo、审计）10 秒，要在客户端 Rust 侧的 12 秒 HTTP 超时之前答复；其余 20 秒。
    let cases = [
        ("/api/login", None, 400, 20),
        ("/api/audit/conn", None, 200, 10),
        ("/api/heartbeat", None, 400, 10),
        ("/api/currentUser", Some(token), 200, 20),
    ];
    let start = Instant::now();
    let runs: Vec<_> = cases
        .into_iter()
        .map(|(path, token, want, secs)| {
            thread::spawn(move || {
                let mut stream = TcpStream::connect(addr).unwrap();
                let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
                write!(stream, "POST {path} HTTP/1.1\r\nHost: x\r\n{auth}Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{{")
                    .unwrap();
                // 每 4 秒一个字节：一直有进展，不触发读写无进度超时，只有整请求超时能结束它。
                stream.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
                let mut first = [0u8; 1];
                loop {
                    match stream.peek(&mut first) {
                        Ok(_) => break,
                        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                            assert!(start.elapsed() < Duration::from_secs(40), "{path}: no answer");
                            stream.write_all(b" ").unwrap();
                        }
                        Err(e) => panic!("{path}: {e}"),
                    }
                }
                let took = start.elapsed();
                let (status, body) = read_response(&mut stream);
                (path, want, secs, status, body, took)
            })
        })
        .collect();
    for run in runs {
        let (path, want, secs, status, body, took) = run.join().unwrap();
        assert_eq!(status, want, "{path}: {:?}", String::from_utf8_lossy(&body));
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), serde_json::json!({"error": "Request timeout"}), "{path}");
        assert!(
            (Duration::from_secs(secs - 1)..Duration::from_secs(secs + 5)).contains(&took),
            "{path}: answered after {took:?}, expected about {secs} s"
        );
    }
}

/// 一页约 12 MB（1000 条、每条约 12 KB）：大于服务端发送缓冲加客户端的小接收窗口，不读就一直写不完。
async fn fill_big_page(s: &Server, guid: &str) {
    s.exec(&format!(
        "with recursive n(i) as (select 1 union all select i + 1 from n where i < 1000)
         insert into ab_peer(ab_guid, id, data, tags, created_at, updated_at)
         select '{guid}', 'p' || i, '{{\"note\":\"' || hex(randomblob(6000)) || '\"}}', '[]', 0, 0 from n"
    ))
    .await;
}

/// 用接收缓冲只有几 KB 的新连接请求一页，读到响应头就不再读，把连接交回去（一直占着这一页）。
async fn hold_page(addr: SocketAddr, request: &str) -> TcpStream {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut stream = socket.connect(addr).await.unwrap().into_std().unwrap();
    stream.set_nonblocking(false).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut head = vec![0u8; 1024];
    stream.read_exact(&mut head).unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    stream
}

fn page_request(guid: &str, token: &str, page_size: u32) -> String {
    format!(
        "POST /api/ab/peers?current=1&pageSize={page_size}&ab={guid} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n"
    )
}

/// §12.1：同一个用户同时最多 2 页在组装或发送中，第 3 页排队，排队计入整请求 20 秒超时；
/// 别的用户不受影响（审查 D-4：一个慢读的用户不能占满所有人的名额）。
#[tokio::test]
async fn a_users_third_page_waits_within_the_request_timeout() {
    let s = Server::start().await;
    let alice = s.issue_token(s.create_user("alice", "pw", false).await).await;
    let bob = s.issue_token(s.create_user("bob", "pw", false).await).await;
    let alice_book = s.post("/api/ab/personal", Some(&alice), "").await.json()["guid"].as_str().unwrap().to_owned();
    let bob_book = s.post("/api/ab/personal", Some(&bob), "").await.json()["guid"].as_str().unwrap().to_owned();
    fill_big_page(&s, &alice_book).await;
    let addr = api_addr(&s);
    // 两页都发不完：读写无进度 30 秒后才断开，下面的步骤都在这之前做完。
    let held = [hold_page(addr, &page_request(&alice_book, &alice, 1000)).await, hold_page(addr, &page_request(&alice_book, &alice, 1000)).await];
    let start = Instant::now();
    let r = s.post(&format!("/api/ab/peers?current=1&pageSize=100&ab={bob_book}"), Some(&bob), "").await;
    assert_eq!((r.status, r.json()["total"].as_i64()), (200, Some(0)), "{:?}", r.text());
    assert!(start.elapsed() < Duration::from_secs(3), "bob waited {:?}", start.elapsed());
    let request = page_request(&alice_book, &alice, 1);
    let third = thread::spawn(move || {
        let start = Instant::now();
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let (status, body) = read_response(&mut stream);
        (status, body, start.elapsed())
    });
    let (status, body, took) = third.join().unwrap();
    assert_eq!(status, 400, "{:?}", String::from_utf8_lossy(&body));
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), serde_json::json!({"error": "Request timeout"}));
    assert!((Duration::from_secs(19)..Duration::from_secs(26)).contains(&took), "answered after {took:?}");
    // 连接一断，名额跟着归还，alice 又能取页。
    drop(held);
    settle().await;
    let r = s.post(&format!("/api/ab/peers?current=1&pageSize=1&ab={alice_book}"), Some(&alice), "").await;
    assert_eq!((r.status, r.json()["total"].as_i64()), (200, Some(1000)), "{:?}", r.text());
}

/// `DELETE /api/ab/peer` 的数组边读边数（审查 D-16）：2 MB 上限内塞约 70 万个元素的请求，读到第 5001 个
/// 就回 400，不展开成整个列表（原先每个这样的请求约占 50 MB）。看进程的内存峰值：几个并发的这种请求
/// 只多占请求体本身那么多。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_huge_peer_delete_array_is_refused_without_amplifying_memory() {
    let s = Server::start().await;
    let token = s.issue_token(s.create_user("alice", "pw", false).await).await;
    let guid = s.post("/api/ab/personal", Some(&token), "").await.json()["guid"].as_str().unwrap().to_owned();
    let path = format!("/api/ab/peer/{guid}");
    let huge = format!("[{}\"\"]", "\"\",".repeat((2 << 20) / 3 - 1));
    assert!(huge.len() <= 2 << 20, "{}", huge.len());
    let r = s.request("DELETE", &path, Some(&token), Some("[]"), &[]).await;
    assert_eq!((r.status, r.body.len()), (200, 0), "{:?}", r.text());
    let before = s.peak_rss_kb();
    let rs = hbb_common::futures::future::join_all((0..4).map(|_| s.request("DELETE", &path, Some(&token), Some(&huge), &[]))).await;
    let grew = s.peak_rss_kb() - before;
    for r in rs {
        assert_eq!(r.status, 400, "{:?}", r.text());
        let msg = r.json()["error"].as_str().unwrap().to_owned();
        assert!(msg.contains("too many peer ids"), "{msg}");
    }
    eprintln!("peak RSS grew by {grew} KB");
    assert!(grew < 24 * 1024, "peak RSS grew by {grew} KB for 4 requests of 2 MB");
}

#[tokio::test]
async fn a_client_that_stops_reading_is_dropped_after_30s() {
    let s = Server::start().await;
    let uid = s.create_user("alice", "pw", false).await;
    let token = s.issue_token(uid).await;
    let r = s.post("/api/ab/personal", Some(&token), "").await;
    let guid = r.json()["guid"].as_str().unwrap().to_owned();
    // 一页约 12 MB：大于服务端发送缓冲上限（tcp_wmem 默认最多 4 MB）加客户端的小接收窗口，
    // 写不完时 hyper 停在写响应，请求头超时不会生效，只有读写无进度超时能断开它。
    s.exec(&format!(
        "with recursive n(i) as (select 1 union all select i + 1 from n where i < 1000)
         insert into ab_peer(ab_guid, id, data, tags, created_at, updated_at)
         select '{guid}', 'p' || i, '{{\"note\":\"' || hex(randomblob(6000)) || '\"}}', '[]', 0, 0 from n"
    ))
    .await;
    let addr = api_addr(&s);
    let request = format!(
        "POST /api/ab/peers?current=1&pageSize=1000&ab={guid} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n"
    );
    let mut readers = Vec::new();
    for pause in [Duration::from_secs(12), Duration::from_secs(40)] {
        // 连接前把接收缓冲定成几 KB，窗口不会自动涨。
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let stream = socket.connect(addr).await.unwrap().into_std().unwrap();
        stream.set_nonblocking(false).unwrap();
        let request = request.clone();
        readers.push(thread::spawn(move || {
            let mut stream = stream;
            stream.write_all(request.as_bytes()).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut data = vec![0u8; 1024];
            stream.read_exact(&mut data).unwrap();
            let head = String::from_utf8_lossy(&data).to_ascii_lowercase();
            assert!(head.starts_with("http/1.1 200"), "{head}");
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map(|v| v.trim().parse().unwrap())
                .unwrap();
            let end = data.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let total = len + end;
            thread::sleep(pause);
            let mut buf = vec![0u8; 1 << 16];
            let mut got = data.len();
            while got < total {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got += n,
                }
            }
            (pause, got, total)
        }));
    }
    for r in readers {
        let (pause, got, total) = r.join().unwrap();
        assert!(total > 8 << 20, "page of {total} bytes is too small for this test");
        if pause < Duration::from_secs(30) {
            assert_eq!(got, total, "paused {pause:?}: the whole page must still arrive");
        } else {
            assert!(got < total, "paused {pause:?}: got all {total} bytes, the connection was not dropped");
        }
    }
}
