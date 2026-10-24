//! Routing level two (LEAPGATE.md §7): each Leapgate device's latest round of relay measurements, as its
//! signed heartbeat reported it (`probes`, phase 3 contract 02 §2.2). Memory only, by device id.

use hbb_common::log;
use serde::Deserialize as _;
use serde_derive::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Devices kept (as many as `device` rows); a new one beyond replaces an expired, else the oldest.
pub(crate) const MAX_MEASURED: usize = 10_000;
/// A round older than this is not used.
pub(crate) const MEASURE_TTL: Duration = Duration::from_secs(15 * 60);
/// `probes.age_s` above this drops the round (the client stops reporting it by then).
const MAX_AGE_S: u64 = 900;
/// Accepted connect times in ms; others leave that relay unknown.
const RTT_MS: std::ops::RangeInclusive<i64> = 1..=10_000;

/// One relay as measured by one device.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Leg {
    /// Not in the round, or an unusable entry.
    Unknown,
    /// Fastest of the round's connects, ms.
    Rtt(u16),
    /// No connect succeeded.
    Down,
}

/// One device's latest round. `legs` follows the relay list of `rev` (its first 32).
struct Measured {
    rev: i64,
    /// When the round ended: received − `age_s`.
    at: Instant,
    legs: Vec<Leg>,
}

/// `probes` of the Leapgate heartbeat; a shape error drops the round.
#[derive(Deserialize)]
struct Probes {
    routing_rev: i64,
    age_s: u64,
    #[serde(default)]
    rtt: HashMap<String, i64>,
    #[serde(default)]
    down: HashSet<String>,
}

#[derive(Default)]
pub(crate) struct Measurements(Mutex<HashMap<String, Measured>>);

impl Measurements {
    /// Stores `probes` as `id`'s latest round when it is for list `rev` and at most `MAX_AGE_S`
    /// old; `hosts` is that list (first 32). A key must be one of `hosts` verbatim and an rtt in
    /// `RTT_MS`, else that relay stays unknown. `id` is the verified one (at most 253 bytes).
    pub fn record(&self, id: &str, probes: &serde_json::Value, hosts: &[&str], rev: i64, now: Instant) {
        let Ok(p) = Probes::deserialize(probes) else {
            log::trace!("probes of {id:?}: bad shape");
            return;
        };
        if p.routing_rev != rev || p.age_s > MAX_AGE_S {
            log::trace!("probes of {id:?}: rev {} age {}s, dropped", p.routing_rev, p.age_s);
            return;
        }
        // Before the monotonic clock's start: not representable, so not usable either.
        let Some(at) = now.checked_sub(Duration::from_secs(p.age_s)) else {
            return;
        };
        let legs = hosts
            .iter()
            .map(|h| match p.rtt.get(*h) {
                Some(ms) if RTT_MS.contains(ms) => Leg::Rtt(*ms as u16),
                _ if p.down.contains(*h) => Leg::Down,
                _ => Leg::Unknown,
            })
            .collect();
        let mut map = self.0.lock().unwrap();
        if map.len() >= MAX_MEASURED && !map.contains_key(id) {
            map.retain(|_, m| now.saturating_duration_since(m.at) <= MEASURE_TTL);
            if map.len() >= MAX_MEASURED {
                if let Some(oldest) = map.iter().min_by_key(|(_, m)| m.at).map(|(k, _)| k.clone()) {
                    map.remove(&oldest);
                }
            }
        }
        map.insert(id.to_owned(), Measured { rev, at, legs });
    }

    /// Drops `id`'s round: its heartbeat carried no `probes`, so it has no valid round now.
    pub fn forget(&self, id: &str) {
        self.0.lock().unwrap().remove(id);
    }

    /// The usable rounds of A and B (one lock): for list `rev` and not older than `MEASURE_TTL`.
    /// An empty id has none.
    pub fn pair(&self, a: &str, b: &str, rev: i64, now: Instant) -> (Option<Vec<Leg>>, Option<Vec<Leg>>) {
        let map = self.0.lock().unwrap();
        let get = |id: &str| {
            (!id.is_empty())
                .then(|| map.get(id))
                .flatten()
                .filter(|m| m.rev == rev && now.saturating_duration_since(m.at) <= MEASURE_TTL)
                .map(|m| m.legs.clone())
        };
        (get(a), get(b))
    }

    /// Devices with a round, and how many of those are usable now (`relay status`).
    pub fn counts(&self, rev: i64, now: Instant) -> (usize, usize) {
        let map = self.0.lock().unwrap();
        let fresh = map
            .values()
            .filter(|m| m.rev == rev && now.saturating_duration_since(m.at) <= MEASURE_TTL)
            .count();
        (map.len(), fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOSTS: [&str; 3] = ["r1.example:21117", "r2.example", "r3.example:21117"];

    fn one(m: &Measurements, id: &str, now: Instant) -> Option<Vec<Leg>> {
        m.pair(id, "", 7, now).0
    }

    #[test]
    fn record_and_read() {
        let m = Measurements::default();
        let now = Instant::now() + Duration::from_secs(3600);
        let p = json!({"routing_rev": 7, "age_s": 42,
                       "rtt": {"r1.example:21117": 23, "r2.example": 10_000, "r9.example": 5},
                       "down": ["r3.example:21117", "r8.example"]});
        m.record("dev1", &p, &HOSTS, 7, now);
        assert_eq!(one(&m, "dev1", now), Some(vec![Leg::Rtt(23), Leg::Rtt(10_000), Leg::Down]));
        // Not verbatim, out of range, missing: unknown.
        let p = json!({"routing_rev": 7, "age_s": 0,
                       "rtt": {"r1.example": 23, "r2.example": 0, "r3.example:21117": 10_001}});
        m.record("dev2", &p, &HOSTS, 7, now);
        assert_eq!(one(&m, "dev2", now), Some(vec![Leg::Unknown; 3]));
        m.record("dev3", &json!({"routing_rev": 7, "age_s": 0, "rtt": {"r2.example": -5}}), &HOSTS, 7, now);
        assert_eq!(one(&m, "dev3", now), Some(vec![Leg::Unknown; 3]));
        // An empty id never has a round; B is looked up the same way.
        assert_eq!(m.pair("", "dev1", 7, now), (None, Some(vec![Leg::Rtt(23), Leg::Rtt(10_000), Leg::Down])));
        // A newer round replaces the old one.
        m.record("dev1", &json!({"routing_rev": 7, "age_s": 1, "down": HOSTS}), &HOSTS, 7, now);
        assert_eq!(one(&m, "dev1", now), Some(vec![Leg::Down; 3]));
        assert_eq!(m.counts(7, now), (3, 3));
    }

    #[test]
    fn dropped_rounds() {
        let m = Measurements::default();
        let now = Instant::now() + Duration::from_secs(3600);
        let good = json!({"routing_rev": 7, "age_s": 0, "rtt": {"r2.example": 9}});
        m.record("keep", &good, &HOSTS, 7, now);
        // A dropped round neither shows nor replaces the device's previous one.
        let prev = json!({"routing_rev": 7, "age_s": 0, "down": HOSTS});
        m.record("bad", &prev, &HOSTS, 7, now);
        for bad in [
            json!({"routing_rev": 6, "age_s": 0, "rtt": {"r2.example": 9}}),
            json!({"routing_rev": 7, "age_s": 901, "rtt": {"r2.example": 9}}),
            json!({"routing_rev": 7, "age_s": -1}),
            json!({"routing_rev": 7}),
            json!({"routing_rev": 7, "age_s": 0, "rtt": {"r2.example": "9"}}),
            json!({"routing_rev": 7, "age_s": 0, "rtt": {"r2.example": 9.5}}),
            json!({"routing_rev": 7, "age_s": 0, "rtt": [9]}),
            json!({"routing_rev": 7, "age_s": 0, "down": "r1.example:21117"}),
            json!("not an object"),
            json!(null),
        ] {
            m.record("bad", &bad, &HOSTS, 7, now);
            assert_eq!(one(&m, "bad", now), Some(vec![Leg::Down; 3]), "{bad}");
        }
        // The other entry is untouched; age 900 is still accepted.
        assert_eq!(one(&m, "keep", now), Some(vec![Leg::Unknown, Leg::Rtt(9), Leg::Unknown]));
        m.record("edge", &json!({"routing_rev": 7, "age_s": 900}), &HOSTS, 7, now);
        assert!(one(&m, "edge", now).is_some());
    }

    #[test]
    fn expiry_and_list_changes() {
        let m = Measurements::default();
        let now = Instant::now() + Duration::from_secs(3600);
        m.record("dev", &json!({"routing_rev": 7, "age_s": 60}), &HOSTS, 7, now);
        // 15 minutes after the round ended (not after it was received) it is gone.
        let ended = now - Duration::from_secs(60);
        assert!(one(&m, "dev", ended + MEASURE_TTL).is_some());
        assert_eq!(one(&m, "dev", ended + MEASURE_TTL + Duration::from_secs(1)), None);
        // Another list: the round is for the old one.
        assert_eq!(m.pair("dev", "", 8, now).0, None);
        assert_eq!(m.counts(8, now), (1, 0));
    }

    #[test]
    fn full_table_evicts_expired_then_oldest() {
        let m = Measurements::default();
        let base = Instant::now() + Duration::from_secs(3600);
        let p = |age: u64| json!({"routing_rev": 7, "age_s": age});
        // Two expired by `now`, the rest fresh; "old" is the oldest fresh one.
        let now = base + MEASURE_TTL;
        m.record("exp1", &p(0), &HOSTS, 7, base - Duration::from_secs(10));
        m.record("exp2", &p(0), &HOSTS, 7, base - Duration::from_secs(5));
        m.record("old", &p(0), &HOSTS, 7, base + Duration::from_secs(1));
        for i in 3..MAX_MEASURED {
            m.record(&format!("d{i}"), &p(0), &HOSTS, 7, now);
        }
        assert_eq!(m.counts(7, now), (MAX_MEASURED, MAX_MEASURED - 2));
        // Full: the expired ones go first, the oldest fresh one stays.
        m.record("new1", &p(0), &HOSTS, 7, now);
        assert_eq!(m.counts(7, now), (MAX_MEASURED - 1, MAX_MEASURED - 1));
        assert!(one(&m, "old", now).is_some());
        m.record("new2", &p(0), &HOSTS, 7, now);
        assert_eq!(m.counts(7, now).0, MAX_MEASURED);
        // Nothing expired: the oldest goes.
        m.record("new3", &p(0), &HOSTS, 7, now);
        assert_eq!(m.counts(7, now).0, MAX_MEASURED);
        assert_eq!(one(&m, "old", now), None);
        assert!(one(&m, "new3", now).is_some());
        // An id already there is overwritten, nothing evicted.
        m.record("new3", &p(5), &HOSTS, 7, now);
        assert_eq!(m.counts(7, now).0, MAX_MEASURED);
        assert!(one(&m, "d3", now).is_some());
    }
}
