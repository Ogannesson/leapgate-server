//! Concurrent connection caps on one listening port, shared by the rendezvous ports (review A-4)
//! and the API port (review C-9): at most `total` in all and at most `MAX_CONNS_PER_SOURCE` per
//! source (an IPv4 address or an IPv6 /64, `source_key`). A loopback peer only counts toward the
//! total: a reverse proxy on the same host carries every client.

use crate::conn_tracker::source_key;
use hbb_common::tokio::sync::{OwnedSemaphorePermit, Semaphore};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

/// Concurrent connections per source and port; tens, so a company NAT with many machines fits.
pub(crate) const MAX_CONNS_PER_SOURCE: usize = 32;

#[derive(Clone)]
pub(crate) struct ConnLimiter {
    total: Arc<Semaphore>,
    sources: SourceCounts,
}

/// Open connections per source; a source's key goes with its last connection.
type SourceCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// Held for the life of one connection; gives its slots back when dropped.
pub(crate) struct ConnPermit {
    _total: OwnedSemaphorePermit,
    source: Option<(IpAddr, SourceCounts)>,
}

impl ConnLimiter {
    pub(crate) fn new(total: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total)),
            sources: Default::default(),
        }
    }

    /// A slot for a connection from `ip`, or `None` over either cap.
    pub(crate) fn try_acquire(&self, ip: IpAddr) -> Option<ConnPermit> {
        let total = self.total.clone().try_acquire_owned().ok()?;
        let ip = ip.to_canonical();
        if ip.is_loopback() {
            return Some(ConnPermit {
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
        Some(ConnPermit {
            _total: total,
            source: Some((key, self.sources.clone())),
        })
    }

    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.total.available_permits()
    }
}

impl Drop for ConnPermit {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_source_and_total() {
        let l = ConnLimiter::new(MAX_CONNS_PER_SOURCE + 2);
        let a: [IpAddr; 2] = ["2001:db8:c::1".parse().unwrap(), "2001:db8:c:0:1::1".parse().unwrap()];
        let mut held: Vec<_> = (0..MAX_CONNS_PER_SOURCE).map(|i| l.try_acquire(a[i % 2]).unwrap()).collect();
        assert!(l.try_acquire(a[0]).is_none(), "connection N+1 from one /64");
        // Other sources fit up to the total; loopback only counts toward the total.
        let b = l.try_acquire("::ffff:198.51.100.1".parse().unwrap()).unwrap();
        let lo = l.try_acquire("127.0.0.1".parse().unwrap()).unwrap();
        assert!(l.try_acquire("198.51.100.2".parse().unwrap()).is_none(), "total");
        assert!(l.try_acquire("::1".parse().unwrap()).is_none(), "total, loopback too");
        drop((b, lo));
        held.pop();
        assert!(l.try_acquire(a[1]).is_some(), "a slot comes back when its connection ends");
        drop(held);
        assert!(l.sources.lock().unwrap().is_empty(), "a source's key goes with its last connection");
        assert_eq!(l.available(), MAX_CONNS_PER_SOURCE + 2);
    }
}
