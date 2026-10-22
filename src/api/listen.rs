//! The API port's accept loop (review C-9): connection caps, a request head timeout and a socket
//! no-progress timeout. Not `axum::serve`: it gives hyper no timer, so hyper's default 30-second
//! head timeout never fires (hyper `common/time.rs` `Time::check` drops a default timeout without a
//! timer; checked: a connection that sends half a head stays open), and it has no connection cap.
//! The request timeout and the body limits live in the router (`super::router`).

use crate::conn_tracker::source_key;
use axum::{extract::ConnectInfo, http::Request, Router};
use hbb_common::{
    log, throttled_log,
    tokio::{
        self,
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::{TcpListener, TcpStream},
        sync::{OwnedSemaphorePermit, Semaphore},
        time::{Instant, Sleep},
    },
};
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tower::ServiceExt as _;

// Fixed, not configurable. Sized for a personal deployment (tens of devices).
/// Concurrent connections in all. A client holds one or two at a time (reports and the address
/// book go through its HTTP client's pool), so this covers a few hundred devices. Behind a reverse
/// proxy on this host (the recommended setup) every client arrives from loopback and counts only
/// here. Worst case held: 512 × (`MAX_BUF` + socket and task) ≈ 15 MB.
const MAX_CONNS: usize = 512;
/// Concurrent connections per source (an IPv4 address or an IPv6 /64), loopback excepted: a
/// company NAT with a dozen machines fits. Same as on the rendezvous ports.
const MAX_CONNS_PER_SOURCE: usize = 32;
/// Time to receive a request head, from the start of the connection or the end of the previous
/// response (hyper restarts it for every head, so it is also the keep-alive idle timeout). A real
/// head is a single packet.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// One request from its head to the response head, the body included; then an internal-error
/// answer (`super::request_timeout`). Below `IO_IDLE_TIMEOUT`: hyper keeps a read pending to see the
/// peer close while a handler runs, so a slow handler must get its answer out before the socket
/// timeout drops the connection without one (the client would then wait out its TCP fallback).
/// The largest body (2 MB, `DELETE /api/ab/peer`) arrives in it at 100 KB/s.
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// A read or write pending this long with no byte moved either way drops the connection. The
/// response body is written after `REQUEST_TIMEOUT` is over; without this a client that stops
/// reading holds it (an `/api/ab/peers` page is MBs) until it disconnects.
const IO_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// hyper's per-connection read buffer cap, i.e. the largest request head (hyper's default is about
/// 400 KB: 200 MB over `MAX_CONNS`). Real heads are under 2 KB; a larger one gets 431.
const MAX_BUF: usize = 16 * 1024;

/// Serves `app` on `listener`; returns only if the runtime goes away.
pub(super) async fn serve(listener: TcpListener, app: Router) {
    let limiter = Limiter::new(MAX_CONNS);
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

/// Open connections: at most `total` in all and `MAX_CONNS_PER_SOURCE` per source. A loopback peer
/// only counts toward the total (a reverse proxy on this host carries every client).
struct Limiter {
    total: Arc<Semaphore>,
    sources: SourceCounts,
}

/// Open connections per source; a source's key goes with its last connection.
type SourceCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// Held for the life of one connection; gives its slots back when dropped.
struct Permit {
    _total: OwnedSemaphorePermit,
    source: Option<(IpAddr, SourceCounts)>,
}

impl Limiter {
    fn new(total: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total)),
            sources: Default::default(),
        }
    }

    fn try_acquire(&self, ip: IpAddr) -> Option<Permit> {
        let total = self.total.clone().try_acquire_owned().ok()?;
        let ip = ip.to_canonical();
        if ip.is_loopback() {
            return Some(Permit {
                _total: total,
                source: None,
            });
        }
        let key = source_key(ip);
        let mut sources = self.sources.lock().unwrap();
        let n = sources.entry(key).or_insert(0);
        if *n >= MAX_CONNS_PER_SOURCE {
            return None;
        }
        *n += 1;
        Some(Permit {
            _total: total,
            source: Some((key, self.sources.clone())),
        })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some((key, sources)) = &self.source {
            let mut sources = sources.lock().unwrap();
            if let Some(n) = sources.get_mut(key) {
                *n -= 1;
                if *n == 0 {
                    sources.remove(key);
                }
            }
        }
    }
}

/// The accepted socket with its connection slot and the `IO_IDLE_TIMEOUT` deadline, pushed back
/// whenever a byte moves; an operation still pending past it fails with `TimedOut`.
struct Guarded {
    io: TcpStream,
    idle: Pin<Box<Sleep>>,
    _permit: Permit,
}

impl Guarded {
    fn new(io: TcpStream, permit: Permit) -> Self {
        Self {
            io,
            idle: Box::pin(tokio::time::sleep(IO_IDLE_TIMEOUT)),
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
            Poll::Pending => self.stalled(cx),
            Poll::Ready(Ok(n)) if n > 0 => {
                self.moved();
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

    #[test]
    fn limiter_counts_per_source_and_total() {
        let l = Limiter::new(MAX_CONNS_PER_SOURCE + 2);
        let a: [IpAddr; 2] = ["2001:db8:c::1".parse().unwrap(), "2001:db8:c:0:1::1".parse().unwrap()];
        let mut held: Vec<_> = (0..MAX_CONNS_PER_SOURCE).map(|i| l.try_acquire(a[i % 2]).unwrap()).collect();
        assert!(l.try_acquire(a[0]).is_none(), "connection N+1 from one /64");
        // Other sources fit up to the total; loopback only counts toward the total.
        let b = l.try_acquire("::ffff:198.51.100.1".parse().unwrap()).unwrap();
        let lo = l.try_acquire("127.0.0.1".parse().unwrap()).unwrap();
        assert!(l.try_acquire("::1".parse().unwrap()).is_none(), "total reached");
        drop((b, lo));
        held.pop();
        assert!(l.try_acquire(a[1]).is_some(), "a slot freed by the source");
        drop(held);
        assert!(l.sources.lock().unwrap().is_empty(), "keys go with their last connection");
    }
}
