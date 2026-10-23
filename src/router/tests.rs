use super::*;
use cost::GeoRecord;
use std::collections::HashMap;

/// Positions by IP, standing in for the mmdb files.
struct FakeGeo(HashMap<IpAddr, GeoRecord>);

impl Locate for FakeGeo {
    fn locate(&self, ip: IpAddr) -> Option<GeoRecord> {
        self.0.get(&ip).cloned()
    }
}

fn rec(lat: f64, lon: f64, country: &str, asn: u32) -> GeoRecord {
    GeoRecord {
        lat: Some(lat),
        lon: Some(lon),
        country: Some(country.to_owned()),
        asn: Some(asn),
    }
}

const BEIJING: (f64, f64) = (39.9042, 116.4074);
const SHANGHAI: (f64, f64) = (31.2304, 121.4737);
const HONGKONG: (f64, f64) = (22.3193, 114.1694);
const FRANKFURT: (f64, f64) = (50.1109, 8.6821);

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Clients: Beijing telecom, Shanghai unicom, Frankfurt, Shanghai telecom; anything else is unknown.
fn fake_geo() -> FakeGeo {
    FakeGeo(HashMap::from([
        (ip("1.0.0.1"), rec(BEIJING.0, BEIJING.1, "CN", 4134)),
        (ip("1.0.0.2"), rec(SHANGHAI.0, SHANGHAI.1, "CN", 4837)),
        (ip("1.0.0.3"), rec(FRANKFURT.0, FRANKFURT.1, "DE", 3320)),
        (ip("1.0.0.4"), rec(SHANGHAI.0, SHANGHAI.1, "CN", 4812)),
    ]))
}

/// A port on 127.0.0.1 nothing listens on (connect is refused at once).
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A relay with a closed port and its whole position given in the configuration.
fn relay(pos: (f64, f64), country: &str, carrier: &str) -> RelayConfig {
    RelayConfig {
        lat: Some(pos.0),
        lon: Some(pos.1),
        country: Some(country.to_owned()),
        carrier: Some(carrier.to_owned()),
        ..RelayConfig::new(format!("127.0.0.1:{}", closed_port()))
    }
}

async fn router(relays: Vec<RelayConfig>) -> (tempfile::TempDir, Arc<Router>) {
    let (dir, db) = crate::testutil::pool().await;
    let mut cfg = Config::default();
    cfg.relay = relays;
    cfg.geo.server_location = Some(crate::config::Location {
        lat: SHANGHAI.0,
        lon: SHANGHAI.1,
        country: "CN".to_owned(),
        carrier: "cn-unicom".to_owned(),
    });
    let r = Arc::new(Router::new(db, Arc::new(cfg)));
    r.set_geo(Box::new(fake_geo()), geo::GeoInfo::default());
    (dir, r)
}

fn q<'a>(a: &str, b: &str, b_id: &'a str) -> RouteQuery<'a> {
    RouteQuery {
        a_ip: ip(a),
        b_ip: ip(b),
        a_id: "",
        b_id,
        a_token: "",
        conn_type: 0,
    }
}

async fn pick(r: &Router, a: &str, b: &str) -> RouteDecision {
    r.select(&q(a, b, "")).await
}

#[tokio::test]
async fn empty_list_gives_empty_relay() {
    let (_dir, r) = router(vec![]).await;
    r.health_round().await;
    assert_eq!(
        pick(&r, "1.0.0.1", "1.0.0.2").await,
        RouteDecision { relay: String::new(), reason: "none", a_ms: None, b_ms: None }
    );
}

#[tokio::test]
async fn geo_cost_and_fallbacks() {
    let bj = relay(BEIJING, "CN", "cn-telecom");
    let sh = relay(SHANGHAI, "CN", "cn-unicom");
    let mut hk = relay(HONGKONG, "HK", "AS9304");
    hk.weight = 0.5;
    let (bjh, shh, hkh) = (bj.host.clone(), sh.host.clone(), hk.host.clone());
    let (_dir, r) = router(vec![bj, sh, hk]).await;
    // Every connect fails: the reachable set stays as loaded, positions come from the overrides.
    r.health_round().await;

    // A Beijing telecom, B Shanghai telecom: bj 0 + 21.3 = 21.3; sh (21.3 + 10) + (0 + 10) = 41.3
    // (cross-carrier, CN 10 ms per leg); hk ((39.3 + 30) + (24.6 + 30)) × 0.5 ≈ 62.
    let d = pick(&r, "1.0.0.1", "1.0.0.4").await;
    assert_eq!((d.relay.as_str(), d.reason), (bjh.as_str(), "geo"));
    // Both in Shanghai on unicom: sh.
    assert_eq!(pick(&r, "1.0.0.2", "1.0.0.2").await.relay, shh);
    // Only A located: 2 × rtt(A, R) × weight.
    let d = pick(&r, "1.0.0.2", "9.9.9.9").await;
    assert_eq!((d.relay.as_str(), d.reason), (shh.as_str(), "geo_a"));
    let d = pick(&r, "9.9.9.9", "1.0.0.1").await;
    assert_eq!((d.relay.as_str(), d.reason), (bjh.as_str(), "geo_b"));
    // Private source: the server's position (Shanghai unicom); 100.64/10 is unknown.
    let d = pick(&r, "192.168.1.10", "100.64.0.1").await;
    assert_eq!((d.relay.as_str(), d.reason), (shh.as_str(), "geo_a"));
    // Frankfurt ↔ Frankfurt: bj 2 × (155.8 + 30) ≈ 372, hk 2 × (183 + 30) × 0.5 ≈ 213: weight 0.5 wins.
    assert_eq!(pick(&r, "1.0.0.3", "1.0.0.3").await.relay, hkh);
    // Both unknown: round-robin over all candidates.
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..3 {
        let d = pick(&r, "9.9.9.9", "100.64.0.1").await;
        assert_eq!(d.reason, "rr");
        seen.push(d.relay);
    }
    seen.sort();
    let mut all = vec![bjh.clone(), shh.clone(), hkh.clone()];
    all.sort();
    assert_eq!(seen, all);

    // Geo legs (before the weight) come with the decision: bj 0 + 21.3.
    let d = pick(&r, "1.0.0.1", "1.0.0.4").await;
    assert_eq!(d.a_ms, Some(0.0));
    assert!((d.b_ms.unwrap() - 21.3).abs() < 0.1, "{d:?}");
    let d = pick(&r, "1.0.0.2", "9.9.9.9").await;
    assert_eq!((d.a_ms, d.b_ms), (Some(0.0), None));
    assert_eq!(pick(&r, "9.9.9.9", "100.64.0.1").await.a_ms, None, "round-robin has no legs");

    let text = r.test(ip("::ffff:1.0.0.1"), ip("1.0.0.4"), "", "").await;
    assert!(text.starts_with("A 1.0.0.1: CN/cn-telecom (39.90,116.41)\nB 1.0.0.4: CN/cn-telecom (31.23,121.47)\n"), "{text}");
    assert!(text.contains(&format!("relay: {bjh:?} (geo)\n  {bjh}: cost 21.")), "{text}");
    assert!(text.contains(&format!("  {shh}: cost 41.")), "{text}");
    assert!(text.contains(&format!("  {hkh}: cost ")), "{text}");
}

#[tokio::test]
async fn weight_and_unlocated_relays() {
    let mut bj = relay(BEIJING, "CN", "cn-telecom");
    bj.weight = 10.0;
    let sh = relay(SHANGHAI, "CN", "cn-unicom");
    // No overrides and nothing in the database for 127.0.0.1: no position.
    let nowhere = RelayConfig::new(format!("127.0.0.1:{}", closed_port()));
    let (shh, nwh) = (sh.host.clone(), nowhere.host.clone());
    let (_dir, r) = router(vec![bj, sh, nowhere]).await;
    r.health_round().await;
    // Beijing telecom ↔ Shanghai telecom: bj 21.3 × 10 = 213 loses to sh 41.3; the relay without a
    // position takes no part.
    for _ in 0..3 {
        let d = pick(&r, "1.0.0.1", "1.0.0.4").await;
        assert_eq!((d.relay.as_str(), d.reason), (shh.as_str(), "geo"));
    }
    // When no candidate has a position, round-robin over all of them.
    r.set_configured(vec![nwh.clone()]);
    r.health_round().await;
    let d = pick(&r, "1.0.0.1", "1.0.0.2").await;
    assert_eq!((d.relay.as_str(), d.reason), (nwh.as_str(), "rr"));
    assert!(r.status_text().contains(&format!("{nwh} weight=1 reachable=yes last=failed location=?/? (?)\n")));
}

#[tokio::test]
async fn fixed_relay() {
    let sh = relay(SHANGHAI, "CN", "cn-unicom");
    let (_dir, r) = router(vec![sh.clone()]).await;
    sqlx::query("insert into device_policy(device_id, relay_pin) values('b1', 'pinned.example:21117'), ('b2', '')")
        .execute(&r.db)
        .await
        .unwrap();
    // The pin wins whatever the list and health say.
    let d = r.select(&q("1.0.0.1", "1.0.0.1", "b1")).await;
    assert_eq!(
        d,
        RouteDecision { relay: "pinned.example:21117".to_owned(), reason: "fixed", a_ms: None, b_ms: None }
    );
    // An empty pin, a device without a row, and an empty b_id (RelayResponse, `tg`) select normally.
    for b_id in ["b2", "b3", ""] {
        assert_eq!(r.select(&q("1.0.0.1", "1.0.0.1", b_id)).await.relay, sh.host);
    }
    // Written by `device pin-relay`: applies to the next call, no cache.
    sqlx::query("update device_policy set relay_pin = 'other:21117' where device_id = 'b1'")
        .execute(&r.db)
        .await
        .unwrap();
    assert_eq!(r.select(&q("1.0.0.1", "1.0.0.1", "b1")).await.relay, "other:21117");
}

#[tokio::test]
async fn health_check() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let down = format!("127.0.0.1:{}", closed_port());
    // Far away but reachable vs. close but down.
    let mut far = relay(FRANKFURT, "DE", "AS3320");
    far.host = up.clone();
    let mut near = relay(BEIJING, "CN", "cn-telecom");
    near.host = down.clone();
    let (_dir, r) = router(vec![far, near]).await;
    // Before the first round every relay is a candidate.
    assert_eq!(pick(&r, "1.0.0.1", "1.0.0.1").await.relay, down);
    assert!(r.status_text().contains("last=pending"));

    r.health_round().await;
    assert_eq!(pick(&r, "1.0.0.1", "1.0.0.1").await.relay, up);
    let status = r.status_text();
    assert!(status.contains(&format!("{up} weight=1 reachable=yes last=")), "{status}");
    assert!(status.contains("ms location=DE/AS3320 (50.11,8.68) (override: lat,lon,country,carrier)"), "{status}");
    assert!(status.contains(&format!("{down} weight=1 reachable=no last=failed")), "{status}");
    let text = r.test(ip("1.0.0.1"), ip("1.0.0.1"), "", "").await;
    assert!(text.contains(&format!("  {down}: unreachable")), "{text}");

    // All fail: the previous reachable set stays.
    drop(listener);
    r.health_round().await;
    assert_eq!(pick(&r, "1.0.0.1", "1.0.0.1").await.relay, up);
    assert!(r.status_text().contains(&format!("{up} weight=1 reachable=yes last=failed")));

    // `rs` replacement: everything reachable again until the next round; file settings are kept.
    r.set_configured(vec![down.clone(), "new.example".to_owned()]);
    let status = r.status_text();
    assert!(status.contains(&format!("{down} weight=1 reachable=yes last=pending")), "{status}");
    assert!(status.contains("new.example weight=1 reachable=yes last=pending location=?/? (?)\n"), "{status}");
}

#[tokio::test]
async fn relay_position_from_database() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let mut partial = RelayConfig::new(format!("127.0.0.1:{}", closed_port()));
    partial.country = Some("JP".to_owned());
    let unresolvable = RelayConfig::new("relay.invalid:21117".to_owned());
    let (_dir, r) = router(vec![RelayConfig::new(host.clone()), partial, unresolvable]).await;
    let mut db = fake_geo();
    db.0.insert(ip("127.0.0.1"), rec(HONGKONG.0, HONGKONG.1, "HK", 4809));
    r.set_geo(Box::new(db), geo::GeoInfo::default());
    r.health_round().await;
    {
        let relays = r.relays.read().unwrap();
        let l = &relays.list;
        assert_eq!(l[0].loc.pos, Some(HONGKONG));
        assert_eq!(l[0].loc.carrier.as_deref(), Some("cn-telecom"));
        assert!(l[0].loc_done);
        // Overridden field kept, the rest from the database.
        assert_eq!(l[1].loc.country.as_deref(), Some("JP"));
        assert_eq!(l[1].loc.pos, Some(HONGKONG));
        // Unresolvable: no position, tried again next round.
        assert_eq!(l[2].loc, Loc::default());
        assert!(!l[2].loc_done);
    }
    // A database swap recomputes positions in the next round.
    r.set_geo(Box::new(FakeGeo(HashMap::new())), geo::GeoInfo::default());
    assert!(!r.relays.read().unwrap().list[0].loc_done);
    r.health_round().await;
    let relays = r.relays.read().unwrap();
    assert_eq!(relays.list[0].loc, Loc::default());
    assert!(!relays.list[0].loc_done);
}

#[tokio::test]
async fn stale_round_is_discarded() {
    // TEST-NET-1 is not routed: the connect hangs until the timeout.
    let (_dir, r) = router(vec![RelayConfig::new("192.0.2.1:21117".to_owned())]).await;
    // A round that started before a replacement must not write into the new list.
    let r2 = r.clone();
    let round = tokio::spawn(async move { r2.health_round().await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    r.set_configured(vec!["x.example".to_owned()]);
    round.await.unwrap();
    let relays = r.relays.read().unwrap();
    assert_eq!(relays.list[0].last, None);
}

#[tokio::test]
async fn routing_rev_follows_the_list() {
    let (_dir, r) = router(vec![RelayConfig::new("r1:21117".to_owned()), RelayConfig::new("r2".to_owned())]).await;
    let (rev, hosts) = r.routing();
    assert_eq!(hosts, ["r1:21117", "r2"]);
    assert!(rev > 0);
    // The same configuration gives the same rev (across restarts).
    let (_dir2, r2) = router(vec![RelayConfig::new("r1:21117".to_owned()), RelayConfig::new("r2".to_owned())]).await;
    assert_eq!(r2.routing().0, rev);
    // `rs` with another list changes it; the same hosts again give the same rev.
    r.set_configured(vec!["r2".to_owned(), "r1:21117".to_owned()]);
    assert_ne!(r.routing().0, rev);
    r.set_configured(vec!["r1:21117".to_owned(), "r2".to_owned()]);
    assert_eq!(r.routing().0, rev);
    // The interval is part of it: the bare host hash is not the rev.
    assert_ne!(rev, crate::strategy::digest_rev(b"r1:21117\nr2"));
    // No relay: an empty list, its rev is not 0.
    r.set_configured(vec![]);
    let (rev0, hosts) = r.routing();
    assert!(hosts.is_empty() && rev0 > 0 && rev0 != rev);
    // Over 32 relays: only the first 32 are measured, and only they make the rev.
    let many: Vec<String> = (0..40).map(|i| format!("r{i}")).collect();
    r.set_configured(many.clone());
    let (rev40, hosts) = r.routing();
    assert_eq!(hosts, many[..MAX_PROBED]);
    r.set_configured(many[..MAX_PROBED].to_vec());
    assert_eq!(r.routing().0, rev40);
}

/// Level two through `select`: A's and B's measurements replace the estimates, `a_ms`/`b_ms` are the
/// chosen relay's legs; another list's round is not used.
#[tokio::test]
async fn measurements_replace_estimates() {
    let bj = relay(BEIJING, "CN", "cn-telecom");
    let sh = relay(SHANGHAI, "CN", "cn-unicom");
    let (bjh, shh) = (bj.host.clone(), sh.host.clone());
    let (_dir, r) = router(vec![bj, sh]).await;
    r.health_round().await;
    let (rev, _) = r.routing();
    let probes = |rtt: serde_json::Value| serde_json::json!({"routing_rev": rev, "age_s": 3, "rtt": rtt});
    let query = |a_id: &'static str, b_id: &'static str| RouteQuery {
        a_id,
        ..q("1.0.0.1", "1.0.0.4", b_id)
    };
    // By geo bj wins (21.3 vs 41.3).
    assert_eq!(r.select(&query("A1", "B1")).await.relay, bjh);
    r.record_probes("A1", &probes(serde_json::json!({&bjh: 80, &shh: 20})));
    let d = r.select(&query("A1", "B1")).await;
    assert_eq!((d.relay.as_str(), d.reason), (shh.as_str(), "rtt_a"));
    assert_eq!(d.a_ms, Some(20.0));
    assert!((d.b_ms.unwrap() - 10.0).abs() < 1e-9, "B's estimate to sh: cross-carrier 10 ms");
    r.record_probes("B1", &probes(serde_json::json!({&bjh: 5, &shh: 90})));
    let d = r.select(&query("A1", "B1")).await;
    assert_eq!((d.relay.as_str(), d.reason, d.a_ms, d.b_ms), (bjh.as_str(), "rtt", Some(80.0), Some(5.0)));
    // B alone (A not identified, as with an original client).
    let d = r.select(&query("", "B1")).await;
    assert_eq!((d.relay.as_str(), d.reason), (bjh.as_str(), "rtt_b"));
    // The fixed relay still comes first.
    sqlx::query("insert into device_policy(device_id, relay_pin) values('B1', 'pinned:21117')")
        .execute(&r.db)
        .await
        .unwrap();
    assert_eq!(r.select(&query("A1", "B1")).await.reason, "fixed");

    let status = r.status_text();
    assert!(status.ends_with("measurements: 2 devices, 2 fresh\n"), "{status}");
    let text = r.test(ip("1.0.0.1"), ip("1.0.0.4"), "A1", "B1").await;
    assert!(text.contains(&format!("relay: {bjh:?} (rtt)\n")), "{text}");
    assert!(text.contains(&format!("  {bjh}: cost 85.0 [A rtt 80ms, B rtt 5ms]\n")), "{text}");
    assert!(text.contains(&format!("  {shh}: cost 110.0 [A rtt 20ms, B rtt 90ms]\n")), "{text}");
    let text = r.test(ip("1.0.0.1"), ip("1.0.0.4"), "A1", "").await;
    assert!(text.contains(&format!("  {bjh}: cost 101.3 [A rtt 80ms, B est 21.3ms]\n")), "{text}");
    // Without ids the output is level one's.
    let text = r.test(ip("1.0.0.1"), ip("1.0.0.4"), "", "").await;
    assert!(text.contains(&format!("relay: {bjh:?} (geo)\n  {bjh}: cost 21.3\n")), "{text}");
    // A measured down: out of the pair, shown as such.
    r.record_probes("A1", &serde_json::json!({"routing_rev": rev, "age_s": 0, "rtt": {&shh: 20}, "down": [&bjh]}));
    let text = r.test(ip("1.0.0.1"), ip("1.0.0.4"), "A1", "B1").await;
    assert!(text.contains(&format!("relay: {shh:?} (rtt)\n")), "{text}");
    assert!(text.contains(&format!("  {bjh}: no cost (measured down) [A down, B rtt 5ms]\n")), "{text}");

    // `rs` replaces the list: the rounds were for the old one, so they are not used.
    r.set_configured(vec![bjh.clone(), shh.clone(), "r3".to_owned()]);
    let d = r.decide(ip("1.0.0.1"), ip("1.0.0.4"), "A1", "B1").decision;
    assert!(d.reason.starts_with("geo"), "{d:?}");
    assert!(r.status_text().ends_with("measurements: 2 devices, 0 fresh\n"));
    // A round for an old rev is dropped.
    r.record_probes("A1", &probes(serde_json::json!({&bjh: 1, &shh: 1, "r3": 1})));
    assert!(r.status_text().ends_with("measurements: 2 devices, 0 fresh\n"));
}

/// MaxMind DB encoding (https://maxmind.github.io/MaxMind-DB/): a control byte (type, size), then the payload.
fn mm_field(ty: u8, size: usize, payload: &[u8]) -> Vec<u8> {
    assert!(size < 29);
    let mut out = if ty <= 7 { vec![ty << 5 | size as u8] } else { vec![size as u8, ty - 7] };
    out.extend_from_slice(payload);
    out
}

fn mm_str(s: &str) -> Vec<u8> {
    mm_field(2, s.len(), s.as_bytes())
}

fn mm_double(v: f64) -> Vec<u8> {
    mm_field(3, 8, &v.to_be_bytes())
}

/// Unsigned integer of type `ty` (5 uint16, 6 uint32, 9 uint64), big-endian without leading zeros.
fn mm_uint(ty: u8, v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    mm_field(ty, 8 - skip, &bytes[skip..])
}

fn mm_map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = mm_field(7, entries.len(), &[]);
    for (k, v) in entries {
        out.extend(mm_str(k));
        out.extend_from_slice(v);
    }
    out
}

/// A minimal IPv4 MaxMind DB: one search tree node whose two 24-bit records both point at `data`, so
/// every address has that record.
fn mmdb(database_type: &str, data: &[u8]) -> Vec<u8> {
    // Data pointers are node_count + 16 + offset.
    let mut out = [17u32, 17].iter().flat_map(|p| p.to_be_bytes()[1..].to_vec()).collect::<Vec<u8>>();
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(data);
    out.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
    out.extend(mm_map(&[
        ("binary_format_major_version", mm_uint(5, 2)),
        ("binary_format_minor_version", mm_uint(5, 0)),
        ("build_epoch", mm_uint(9, 1_700_000_000)),
        ("database_type", mm_str(database_type)),
        ("description", mm_map(&[])),
        ("ip_version", mm_uint(5, 4)),
        ("languages", mm_field(11, 0, &[])),
        ("node_count", mm_uint(6, 1)),
        ("record_size", mm_uint(5, 24)),
    ]));
    out
}

/// A city database placing every address at (`lat`, `lon`) in `country`.
fn city_mmdb(lat: f64, lon: f64, country: &str) -> Vec<u8> {
    let data = mm_map(&[
        ("country", mm_map(&[("iso_code", mm_str(country))])),
        ("location", mm_map(&[("latitude", mm_double(lat)), ("longitude", mm_double(lon))])),
    ]);
    mmdb("Test-City", &data)
}

/// An ASN database putting every address in `asn`.
fn asn_mmdb(asn: u32) -> Vec<u8> {
    mmdb("Test-ASN", &mm_map(&[("autonomous_system_number", mm_uint(6, asn.into()))]))
}

#[tokio::test]
async fn start_removes_old_months() {
    // Review C-11: months a hot swap could not delete, or that `geo update` left, go at the next start.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    for (name, data) in [
        ("dbip-city-lite-2026-09.mmdb", city_mmdb(1.0, 2.0, "CN")),
        ("dbip-city-lite-2026-10.mmdb", city_mmdb(1.0, 2.0, "CN")),
        ("dbip-asn-lite-2026-08.mmdb", asn_mmdb(4837)),
        ("dbip-asn-lite-2026-10.mmdb", asn_mmdb(4837)),
        ("dbip-asn-lite-2026-11.mmdb.part", vec![0]),
        ("GeoLite2-City.mmdb", vec![0]),
    ] {
        std::fs::write(dir.join(name), data).unwrap();
    }
    let (_db_dir, db) = crate::testutil::pool().await;
    let mut cfg = Config::default();
    cfg.geo.dir = dir.to_string_lossy().into_owned();
    cfg.geo.auto_update = false;
    let r = Arc::new(Router::new(db, Arc::new(cfg)));
    r.spawn_tasks();
    let loaded = r.geo_snapshot().unwrap();
    assert_eq!(loaded.info.months, Some((geo::Ym::new(2026, 10), geo::Ym::new(2026, 10))));
    assert_eq!(loaded.db.locate(ip("8.8.8.8")).unwrap().asn, Some(4837));
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["GeoLite2-City.mmdb", "dbip-asn-lite-2026-10.mmdb", "dbip-city-lite-2026-10.mmdb"]);
}

#[cfg(unix)]
#[test]
fn manual_files_are_mapped_from_a_private_copy() {
    // Review C-4/C-15: overwriting a manual file in place (cp, curl -o) must not touch what is mapped.
    // Without the copy, the reads below would hit pages past the shrunken file's end: SIGBUS.
    // Review R2-5: the copies go to a directory of the server's own; geo.dir may be read-only
    // (geoipupdate's root-owned directory, a :ro mount) and is never written to.
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let (dir, copies) = (tmp.path().join("geoip"), tmp.path().join("copies"));
    std::fs::create_dir(&dir).unwrap();
    let cfg = GeoConfig {
        dir: dir.to_string_lossy().into_owned(),
        source: GeoSource::Manual,
        ..Default::default()
    };
    let (city, asn) = (dir.join("GeoLite2-City.mmdb"), dir.join("GeoLite2-ASN.mmdb"));
    std::fs::write(&city, city_mmdb(1.0, 2.0, "CN")).unwrap();
    std::fs::write(&asn, asn_mmdb(4837)).unwrap();
    let names = |d: &Path| {
        let mut v: Vec<String> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    let files = ["GeoLite2-ASN.mmdb", "GeoLite2-City.mmdb"];
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let (db, info) = geo::load_copying(&cfg, &copies).unwrap();
    assert_eq!(info.city, city, "reported under the operator's name");
    assert_eq!(names(&copies), files);
    // std::fs::write truncates and rewrites the same inode, like cp.
    std::fs::write(&city, b"x").unwrap();
    std::fs::write(&asn, b"x").unwrap();
    let rec = db.locate(ip("8.8.8.8")).unwrap();
    assert_eq!((rec.lat, rec.country.as_deref(), rec.asn), (Some(1.0), Some("CN"), Some(4837)));
    // A broken update fails to load and leaves the loaded databases alone.
    assert!(geo::load_copying(&cfg, &copies).is_err());
    assert_eq!(db.locate(ip("8.8.8.8")).unwrap().asn, Some(4837));
    // The next good file is copied again; the old mapping still reads the old data.
    std::fs::write(&city, city_mmdb(3.0, 4.0, "DE")).unwrap();
    std::fs::write(&asn, asn_mmdb(3320)).unwrap();
    let (db2, _) = geo::load_copying(&cfg, &copies).unwrap();
    assert_eq!(db2.locate(ip("8.8.8.8")).unwrap().country.as_deref(), Some("DE"));
    assert_eq!(db.locate(ip("8.8.8.8")).unwrap().country.as_deref(), Some("CN"));

    // `geo lookup` reads the files into memory: also unaffected by in-place writes.
    let full = Config {
        geo: cfg.clone(),
        ..Default::default()
    };
    let out = geo_lookup(&full, ip("8.8.8.8")).unwrap();
    assert!(out.contains("country DE") && out.contains("AS3320"), "{out}");
    let (mem, _) = geo::load_in_memory(&cfg).unwrap();
    std::fs::write(&city, b"x").unwrap();
    assert_eq!(mem.locate(ip("8.8.8.8")).unwrap().country.as_deref(), Some("DE"));

    // geo.dir was never written to, and no temporary files are left.
    assert_eq!(names(&dir), files);
    assert_eq!(names(&copies), files);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Downloads the real DB-IP Lite files (about 65 MB). Run by hand:
/// `cargo test --lib router::tests::real_dbip_download -- --ignored --nocapture`
#[tokio::test]
#[ignore]
async fn real_dbip_download() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = GeoConfig {
        dir: tmp.path().to_string_lossy().into_owned(),
        ..Default::default()
    };
    let started = std::time::Instant::now();
    let msg = geo_download(&cfg).await.unwrap();
    println!("{msg} in {:.1?}", started.elapsed());
    for e in std::fs::read_dir(tmp.path()).unwrap() {
        let e = e.unwrap();
        println!("{} {} bytes", e.file_name().to_string_lossy(), e.metadata().unwrap().len());
    }
    // Up to date now; no *.part left behind.
    assert_eq!(geo_download(&cfg).await.unwrap(), "DB-IP files are up to date");
    assert!(!std::fs::read_dir(tmp.path())
        .unwrap()
        .any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".part")));
    let full = Config {
        geo: cfg.clone(),
        ..Default::default()
    };
    for addr in ["8.8.8.8", "1.1.1.1", "202.96.128.86", "221.5.88.88", "211.136.192.6", "2408:8000::1", "23.95.2.214"] {
        print!("{}", geo_lookup(&full, ip(addr)).unwrap());
    }
    // The server path: load, then select with the real files.
    let (db, info) = geo::load(&cfg).unwrap();
    println!("loaded {info}");
    let telecom = db.locate(ip("202.96.128.86")).unwrap();
    assert_eq!(telecom.country.as_deref(), Some("CN"));
}
