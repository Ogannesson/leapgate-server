//! The API port's accept loop (review C-9): connection caps, a request head timeout, a socket
//! no-progress timeout and a write floor. Not `axum::serve`: it gives hyper no timer, so hyper's default 30-second
//! head timeout never fires (hyper `common/time.rs` `Time::check` drops a default timeout without a
//! timer; checked: a connection that sends half a head stays open), and it has no connection cap.
//! The request timeout and the body limits live in the router (`super::router`).

use crate::conn_limit::{ConnLimiter, ConnPermit};
use axum::{extract::ConnectInfo, http::Request, Router};
use hbb_common::{
    log, throttled_log,
    tokio::{
        self,
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::{TcpListener, TcpStream},
        time::{Instant, Sleep},
    },
};
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tower::ServiceExt as _;

// Fixed, not configurable. Sized for a personal deployment (tens of devices).
/// Concurrent connections in all, besides `conn_limit::MAX_CONNS_PER_SOURCE` per source (loopback
/// excepted) as on the rendezvous ports. A client holds one or two at a time (reports and the
/// address book go through its HTTP client's pool), so this covers a few hundred devices. Behind a
/// reverse proxy on this host (the recommended setup) every client arrives from loopback and counts
/// only here. The connections alone hold 512 × (`MAX_BUF` + socket and task) ≈ 15 MB; a request
/// adds its body while handled, up to its route's limit (16 KB for most, 2 MB for
/// `DELETE /api/ab/peer`, `super::router`), and an `/api/ab/peers` page holds its own (bounded by
/// `ab::MAX_PAGES`).
const MAX_CONNS: usize = 512;
/// Time to receive a request head, from the start of the connection or the end of the previous
/// response (hyper restarts it for every head, so it is also the keep-alive idle timeout). A real
/// head is a single packet.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// One request from its head to the response head, the body included; then an internal-error
/// answer (`super::request_timeout`). Below `IO_IDLE_TIMEOUT`: hyper keeps a read pending to see the
/// peer close while a handler runs, so a slow handler must get its answer out before the socket
/// timeout drops the connection without one (the client would then try its TCP fallback).
/// The largest body (2 MB, `DELETE /api/ab/peer`) arrives in it at 100 KB/s; the client's Flutter
/// side, which sends the address book requests, waits 30 s.
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// `REQUEST_TIMEOUT` for the device reports (`super::is_report`: heartbeat, sysinfo, audit). The
/// client sends those from its Rust side, which gives up after 12 s, connecting and the TLS
/// handshake included (rustdesk `src/common.rs` `post_request_`); an answer after that is never
/// read, the client tries its TCP fallback on 21116 instead (which Porta closes), and over HTTPS a
/// client that has not yet cached its TLS setting resends the request up to 4 times. Bodies are at
/// most 64 KB.
pub(super) const REPORT_TIMEOUT: Duration = Duration::from_secs(10);
/// A read or write pending this long with no byte moved either way drops the connection. The
/// response body is written after `REQUEST_TIMEOUT` is over; without this a client that stops
/// reading holds it (an `/api/ab/peers` page is MBs) until it disconnects.
const IO_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Write floor (review D-4/D-18), for a client that reads, but slowly: from the first write the
/// socket holds up (its send buffer full) until the next request is read, the bytes written must
/// keep up with this rate once `IO_IDLE_TIMEOUT` of grace is over, else the connection drops.
/// `IO_IDLE_TIMEOUT` alone does not bound it: the kernel takes a write whenever a third of the
/// send buffer is free, and over the Internet that buffer stays at tens of KB for a client that
/// keeps its window small, so reading a few KB every 30 s held an `/api/ab/peers` page (MBs) and
/// its slot for hours. 32 KB/s (256 kbit/s) is far below what a remote desktop needs; a real page
/// (100 rows, tens of KB) goes into the socket buffers at once and never meets it. A page of
/// S bytes is then sent within 30 s + S / 32 KB/s (18 MB, 1000 of the largest rows: ~10 min),
/// twice that at worst: bytes read while a response is being written restart the count, and
/// hyper reads at most once before that response is written out. Checked here, not in the
/// response body: hyper stops asking the body for frames while its write buffer is full.
const MIN_WRITE_RATE: u64 = 32 * 1024;
/// hyper's per-connection read buffer cap, i.e. the largest request head (hyper's default is about
/// 400 KB: 200 MB over `MAX_CONNS`). Real heads are under 2 KB; a larger one gets 431.
const MAX_BUF: usize = 16 * 1024;

/// Serves `app` on `listener`; returns only if the runtime goes away.
pub(super) async fn serve(listener: TcpListener, app: Router) {
    let limiter = ConnLimiter::new(MAX_CONNS);
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            // As axum's `handle_accept_error`: a reset belongs to one connection; anything else
            // (EMFILE when out of descriptors) is logged and retried a second later.
            Err(err) => {
                if !matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
                ) {
                    log::error!("API accept error: {err}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        let Some(permit) = limiter.try_acquire(addr.ip()) else {
            throttled_log!(Duration::from_secs(60), warn, "API: too many connections, closed one from {}", addr);
            continue;
        };
        let service = app.clone().map_request(move |mut req: Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo(addr));
            req
        });
        let io = TokioIo::new(Guarded::new(stream, permit));
        tokio::spawn(async move {
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .max_buf_size(MAX_BUF)
                .serve_connection(io, TowerToHyperService::new(service));
            if let Err(err) = conn.await {
                log::debug!("API connection from {addr}: {err}");
            }
        });
    }
}

/// The accepted socket with its connection slot, the `IO_IDLE_TIMEOUT` deadline, pushed back
/// whenever a byte moves, and the `MIN_WRITE_RATE` floor; an operation still pending past either
/// fails with `TimedOut`.
struct Guarded {
    io: TcpStream,
    idle: Pin<Box<Sleep>>,
    /// Since the first write held up after the last read, and the bytes written since.
    behind: Option<(Instant, u64)>,
    /// When the bytes written in `behind` fall below `MIN_WRITE_RATE`.
    slow: Pin<Box<Sleep>>,
    _permit: ConnPermit,
}

impl Guarded {
    fn new(io: TcpStream, permit: ConnPermit) -> Self {
        Self {
            io,
            idle: Box::pin(tokio::time::sleep(IO_IDLE_TIMEOUT)),
            behind: None,
            slow: Box::pin(tokio::time::sleep(IO_IDLE_TIMEOUT)),
            _permit: permit,
        }
    }

    fn moved(&mut self) {
        self.idle.as_mut().reset(Instant::now() + IO_IDLE_TIMEOUT);
    }

    /// For an operation that returned `Pending`.
    fn stalled<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        match self.idle.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::ErrorKind::TimedOut.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn wrote(&mut self, cx: &mut Context<'_>, res: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
        match res {
            Poll::Pending => {
                let (since, sent) = *self.behind.get_or_insert((Instant::now(), 0));
                let due = since + IO_IDLE_TIMEOUT + Duration::from_millis(sent * 1000 / MIN_WRITE_RATE);
                if self.slow.deadline() != due {
                    self.slow.as_mut().reset(due);
                }
                if self.slow.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
                }
                self.stalled(cx)
            }
            Poll::Ready(Ok(n)) if n > 0 => {
                self.moved();
                if let Some((_, sent)) = &mut self.behind {
                    *sent += n as u64;
                }
                Poll::Ready(Ok(n))
            }
            ready => ready,
        }
    }
}

impl AsyncRead for Guarded {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Pending => this.stalled(cx),
            ready => {
                if buf.filled().len() > before {
                    this.moved();
                    // The next request: its response starts a new count.
                    this.behind = None;
                }
                ready
            }
        }
    }
}

impl AsyncWrite for Guarded {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.io).poll_write(cx, buf);
        this.wrote(cx, res)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.io).poll_write_vectored(cx, bufs);
        this.wrote(cx, res)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use hbb_common::tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpSocket,
    };
    use std::net::SocketAddr;

    /// Sends `request` on a new connection with a small receive buffer and reads the response at
    /// about `rate` bytes/s, a quarter-second's worth at a time; returns (bytes read, response
    /// length, when the reading ended).
    async fn read_at(addr: SocketAddr, request: String, rate: usize) -> (usize, usize, Duration) {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let mut stream = socket.connect(addr).await.unwrap();
        let start = Instant::now();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut data = Vec::new();
        let mut total = usize::MAX;
        let mut buf = vec![0u8; rate / 4];
        while data.len() < total {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let want = buf.len().min(total - data.len());
            let mut tick = 0;
            while tick < want {
                match stream.read(&mut buf[tick..want]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => tick += n,
                }
            }
            data.extend_from_slice(&buf[..tick]);
            if tick < want {
                break;
            }
            if total == usize::MAX {
                if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                    assert!(head.starts_with("http/1.1 200"), "{head}");
                    let len: usize =
                        head.lines().find_map(|l| l.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                    total = end + 4 + len;
                }
            }
        }
        (data.len(), total, start.elapsed())
    }

    /// A client that keeps reading, but below `MIN_WRITE_RATE`, is dropped by the write floor
    /// (bytes move every quarter second, so `IO_IDLE_TIMEOUT` never fires), and its
    /// `/api/ab/peers` slots go back; a client above the rate gets its whole page. The server's
    /// send buffer is kept small, as it stays over the Internet for a client with a small window
    /// (on loopback the kernel grows it to MBs, which takes a write only every ~1 MB read).
    #[tokio::test]
    async fn a_slow_reader_is_dropped_and_its_page_slots_go_back() {
        let t = testutil::app().await;
        let (_, token) = testutil::create_user(&t.state.db, "alice", "", false).await;
        let (_, _, body) = testutil::send(&t.app, "POST", "/api/ab/personal", Some(&token), "").await;
        let book = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["guid"].as_str().unwrap().to_owned();
        // About 1.4 MB.
        sqlx::query(
            "with recursive n(i) as (select 1 union all select i + 1 from n where i < 200)
             insert into ab_peer(ab_guid, id, data, created_at, updated_at)
             select ?, 'p' || i, json_object('note', hex(randomblob(3500))), 0, 0 from n",
        )
        .bind(&book)
        .execute(&t.state.db)
        .await
        .unwrap();
        // Accepted sockets inherit the listener's send buffer size.
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(4096).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(16).unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, t.app.clone()));
        let request = format!(
            "POST /api/ab/peers?current=1&pageSize=1000&ab={book} HTTP/1.1\r\nHost: x\r\n\
             Authorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n"
        );
        let slow = tokio::spawn(read_at(addr, request.clone(), 4 * 1024));
        let fast = tokio::spawn(read_at(addr, request, 96 * 1024));
        let (got, total, took) = fast.await.unwrap();
        assert!(total > 1 << 20, "page of {total} bytes");
        assert_eq!(got, total, "above the floor: the whole page, in {took:?}");
        let (got, total, took) = slow.await.unwrap();
        assert!(got < total, "below the floor: got the whole page in {took:?}");
        // Behind from the start, at 4 of the 32 KB/s: due at 30 s × 32 / (32 − 4) ≈ 34 s.
        assert!((Duration::from_secs(31)..Duration::from_secs(42)).contains(&took), "dropped after {took:?}");
        // The page's memory and slots go with the connection.
        let start = Instant::now();
        while t.state.ab_pages.free() != (crate::api::ab::MAX_PAGES, 0) {
            assert!(start.elapsed() < Duration::from_secs(5), "{:?}", t.state.ab_pages.free());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
