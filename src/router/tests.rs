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
        RouteDecision { relay: String::new(), reason: "none" }
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

    let text = r.test(ip("::ffff:1.0.0.1"), ip("1.0.0.4")).await;
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
    assert_eq!(d, RouteDecision { relay: "pinned.example:21117".to_owned(), reason: "fixed" });
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
    let text = r.test(ip("1.0.0.1"), ip("1.0.0.1")).await;
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
    for addr in ["8.8.8.8", "1.1.1.1", "202.96.128.86", "221.5.88.88", "211.136.192.6", "2408:8000::1", "23.95.2.214"] {
        print!("{}", geo_lookup(&cfg, ip(addr)).unwrap());
    }
    // The server path: load, then select with the real files.
    let (db, info) = geo::load(&cfg).unwrap();
    println!("loaded {info}");
    let telecom = db.locate(ip("202.96.128.86")).unwrap();
    assert_eq!(telecom.country.as_deref(), Some("CN"));
}
