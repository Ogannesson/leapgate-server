//! Cost model of routing level one (PORTA.md §7, note 06 §4 and §5.2). Pure functions over positions,
//! so every branch can be tested with fake data behind [`Locate`].

use crate::config::{Location, RelayConfig, RoutingConfig};
use std::{collections::BTreeMap, net::IpAddr};

/// What the IP database knows about one address.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct GeoRecord {
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub country: Option<String>,
    pub asn: Option<u32>,
}

/// IP database lookups (the mmdb files in production, a map in tests).
pub(crate) trait Locate: Send + Sync {
    /// `None` when the database has no record for `ip`.
    fn locate(&self, ip: IpAddr) -> Option<GeoRecord>;
}

/// Where one end (client or relay) is; every field may be unknown.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Loc {
    /// (latitude, longitude)
    pub pos: Option<(f64, f64)>,
    /// ISO 3166-1 alpha-2.
    pub country: Option<String>,
    /// Carrier group key: a group name from the table, or `AS<n>`.
    pub carrier: Option<String>,
}

/// Main ASNs of China's three carriers (note 06 §4.2: an ASN ownership table, not a latency table).
/// Checked 2026-10-22 against PeeringDB (https://www.peeringdb.com/api/net?asn__in=…: 4134, 4809, 4816,
/// 23724, 4808, 4837, 9929, 17621, 17816, 9808, 24444, 24547, 56046) and bgp.he.net
/// (https://bgp.he.net/AS<n>: 4811, 4812, 17638, 58466, 134774, 9800, 17622, 17623, 9394, 24400, 24445,
/// 38019, 56040, 56041, 56042, 56044, 56047, 56048). AS17638 is China Telecom Tianjin, not Unicom.
/// AS9394 (China TieTong) belongs to China Mobile. International arms (CMHK 9231, CMI 58453,
/// China Unicom Global 10099) are left out: they serve other countries, where these groups don't apply.
const BUILTIN_CARRIERS: &[(u32, &str)] = &[
    (4134, "cn-telecom"),   // China Telecom backbone (ChinaNet, 163)
    (4809, "cn-telecom"),   // China Telecom CN2
    (4811, "cn-telecom"),   // China Telecom (Group)
    (4812, "cn-telecom"),   // China Telecom (Group), Shanghai
    (4816, "cn-telecom"),   // China Telecom (Group)
    (17638, "cn-telecom"),  // Tianjin provincial net of CT
    (23724, "cn-telecom"),  // IDC, China Telecommunications Corporation
    (58466, "cn-telecom"),  // CHINANET Guangdong province network
    (134774, "cn-telecom"), // CHINANET Guangdong Shenzhen MAN
    (4808, "cn-unicom"),    // China Unicom Beijing
    (4837, "cn-unicom"),    // China Unicom backbone (China169)
    (9800, "cn-unicom"),    // CHINA UNICOM
    (9929, "cn-unicom"),    // China Unicom Industrial Internet Backbone
    (17621, "cn-unicom"),   // China Unicom Shanghai
    (17622, "cn-unicom"),   // China Unicom Guangzhou
    (17623, "cn-unicom"),   // China Unicom Shenzhen
    (17816, "cn-unicom"),   // China169 Guangzhou
    (9394, "cn-mobile"),    // China TieTong
    (9808, "cn-mobile"),    // China Mobile (CMNET)
    (24400, "cn-mobile"),   // Shanghai Mobile
    (24444, "cn-mobile"),   // Shandong Mobile
    (24445, "cn-mobile"),   // Henan Mobile
    (24547, "cn-mobile"),   // Hebei Mobile
    (38019, "cn-mobile"),   // Tianjin Mobile
    (56040, "cn-mobile"),   // China Mobile
    (56041, "cn-mobile"),   // China Mobile
    (56042, "cn-mobile"),   // China Mobile
    (56044, "cn-mobile"),   // China Mobile
    (56046, "cn-mobile"),   // Jiangsu Mobile
    (56047, "cn-mobile"),   // China Mobile
    (56048, "cn-mobile"),   // China Mobile, Beijing
];

/// ASN → carrier group: the built-in table plus `[routing.carriers]` (which wins on the same ASN).
pub(crate) struct Carriers(BTreeMap<u32, String>);

impl Carriers {
    pub fn new(extra: &BTreeMap<u32, String>) -> Self {
        let mut map: BTreeMap<u32, String> = BUILTIN_CARRIERS
            .iter()
            .map(|(asn, group)| (*asn, (*group).to_owned()))
            .collect();
        map.extend(extra.iter().map(|(asn, group)| (*asn, group.clone())));
        Self(map)
    }

    /// The group name, or `AS<n>` (so equal ASNs are the same group).
    pub fn group(&self, asn: u32) -> String {
        self.0.get(&asn).cloned().unwrap_or_else(|| format!("AS{asn}"))
    }

    /// A configured `carrier` as a group key: `AS<n>` goes through [`Self::group`], so `AS4837`
    /// and a client in AS4837 are both `cn-unicom`; anything else is a group name already.
    fn key(&self, carrier: String) -> String {
        match carrier.strip_prefix("AS").and_then(|n| n.parse().ok()) {
            Some(asn) => self.group(asn),
            None => carrier,
        }
    }
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_owned())
}

fn from_record(rec: GeoRecord, carriers: &Carriers) -> Loc {
    Loc {
        pos: rec.lat.zip(rec.lon),
        country: rec.country.filter(|c| !c.is_empty()),
        carrier: rec.asn.map(|asn| carriers.group(asn)),
    }
}

/// Private, loopback, link-local or ULA: the client reached us through a private network.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            v6.is_loopback() || s0 & 0xffc0 == 0xfe80 || s0 & 0xfe00 == 0xfc00
        }
    }
}

/// 100.64/10: carrier-grade NAT or a tailnet; the peer may be anywhere.
fn is_shared(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64)
}

/// A client's position: private sources take `server_location` (its empty fields stay unknown),
/// 100.64/10 is unknown, anything else is looked up.
pub(crate) fn client_loc(
    ip: IpAddr,
    geo: Option<&dyn Locate>,
    carriers: &Carriers,
    server: Option<&Location>,
) -> Loc {
    let ip = ip.to_canonical();
    if is_private(ip) {
        return server
            .map(|s| Loc {
                pos: Some((s.lat, s.lon)),
                country: non_empty(&s.country),
                carrier: non_empty(&s.carrier).map(|c| carriers.key(c)),
            })
            .unwrap_or_default();
    }
    if is_shared(ip) {
        return Loc::default();
    }
    geo.and_then(|g| g.locate(ip))
        .map(|rec| from_record(rec, carriers))
        .unwrap_or_default()
}

fn override_str(s: &Option<String>) -> Option<String> {
    s.as_deref().and_then(non_empty)
}

/// Whether some field of the relay's position is not set in `[[relay]]` (so the database is needed).
pub(crate) fn needs_lookup(r: &RelayConfig) -> bool {
    r.lat.is_none() || r.lon.is_none() || override_str(&r.country).is_none() || override_str(&r.carrier).is_none()
}

/// A relay's position: each `[[relay]]` field overrides the database's (empty strings don't).
pub(crate) fn relay_loc(r: &RelayConfig, rec: Option<GeoRecord>, carriers: &Carriers) -> Loc {
    let rec = rec.unwrap_or_default();
    Loc {
        pos: r.lat.or(rec.lat).zip(r.lon.or(rec.lon)),
        country: override_str(&r.country).or(rec.country.filter(|c| !c.is_empty())),
        carrier: override_str(&r.carrier)
            .map(|c| carriers.key(c))
            .or(rec.asn.map(|asn| carriers.group(asn))),
    }
}

/// Great-circle distance in km (haversine, R = 6371 km).
pub(crate) fn distance_km((lat1, lon1): (f64, f64), (lat2, lon2): (f64, f64)) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = p2 - p1;
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * 6371.0 * a.sqrt().min(1.0).asin()
}

/// Per-leg penalty: cross-carrier only within one country (that country's override, else the global
/// value; nothing when either group is unknown or the relay is multi-line BGP); cross-border takes the
/// larger override of the two countries, else the global value; nothing when either country is unknown.
pub(crate) fn penalty(routing: &RoutingConfig, x: &Loc, r: &Loc, multi_bgp: bool) -> f64 {
    let (Some(cx), Some(cr)) = (&x.country, &r.country) else {
        return 0.0;
    };
    if cx == cr {
        return match (&x.carrier, &r.carrier) {
            (Some(gx), Some(gr)) if gx != gr && !multi_bgp => routing
                .country
                .get(cx)
                .and_then(|o| o.cross_carrier_ms)
                .unwrap_or(routing.cross_carrier_ms),
            _ => 0.0,
        };
    }
    let o = |c: &String| routing.country.get(c).and_then(|o| o.cross_border_ms);
    match (o(cx), o(cr)) {
        (Some(a), Some(b)) => a.max(b),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => routing.cross_border_ms,
    }
}

/// Estimated RTT of one leg in ms; `None` when either position is unknown.
pub(crate) fn leg_rtt(routing: &RoutingConfig, x: &Loc, r: &Loc, multi_bgp: bool) -> Option<f64> {
    let d = distance_km(x.pos?, r.pos?);
    Some(d * 2.0 * routing.detour / 200.0 + penalty(routing, x, r, multi_bgp))
}

/// One candidate relay as the cost model sees it.
pub(crate) struct Candidate<'a> {
    pub loc: &'a Loc,
    pub weight: f64,
    pub multi_bgp: bool,
}

/// Costs of the candidates and the basis used: `"geo"` (both ends located), `"geo_a"` / `"geo_b"`
/// (only A / only B located: `2 × rtt(known, R) × weight`). `None` when neither end is located.
/// A candidate without a position gets no cost.
pub(crate) fn score(
    routing: &RoutingConfig,
    a: &Loc,
    b: &Loc,
    cands: &[Candidate<'_>],
) -> Option<(&'static str, Vec<Option<f64>>)> {
    let basis = match (a.pos.is_some(), b.pos.is_some()) {
        (true, true) => "geo",
        (true, false) => "geo_a",
        (false, true) => "geo_b",
        (false, false) => return None,
    };
    let costs = cands
        .iter()
        .map(|c| {
            let ra = leg_rtt(routing, a, c.loc, c.multi_bgp);
            let rb = leg_rtt(routing, b, c.loc, c.multi_bgp);
            let sum = match (ra, rb) {
                (Some(ra), Some(rb)) => ra + rb,
                (Some(r), None) | (None, Some(r)) => 2.0 * r,
                (None, None) => return None,
            };
            Some(sum * c.weight)
        })
        .collect();
    Some((basis, costs))
}

/// Index of the lowest cost (the first one on ties); `None` when nothing has a cost.
pub(crate) fn pick(costs: &[Option<f64>]) -> Option<usize> {
    costs
        .iter()
        .enumerate()
        .filter_map(|(i, c)| c.map(|c| (i, c)))
        .min_by(|x, y| x.1.total_cmp(&y.1))
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, CountryPenalty};

    fn loc(lat: f64, lon: f64, country: &str, carrier: &str) -> Loc {
        Loc {
            pos: Some((lat, lon)),
            country: non_empty(country),
            carrier: non_empty(carrier),
        }
    }

    #[test]
    fn distance() {
        // Beijing ↔ Shanghai ≈ 1067 km (note 06 §4.1).
        let d = distance_km((39.9042, 116.4074), (31.2304, 121.4737));
        assert!((d - 1067.0).abs() < 10.0, "{d}");
        assert_eq!(distance_km((10.0, 20.0), (10.0, 20.0)), 0.0);
    }

    #[test]
    fn penalties() {
        let routing = Config::default().routing;
        let tel = loc(0.0, 0.0, "CN", "cn-telecom");
        let uni = loc(0.0, 0.0, "CN", "cn-unicom");
        let cn_unknown = loc(0.0, 0.0, "CN", "");
        let hk = loc(0.0, 0.0, "HK", "AS9304");
        let us = loc(0.0, 0.0, "US", "AS7922");
        let jp = loc(0.0, 0.0, "JP", "AS2516");
        let nowhere = loc(0.0, 0.0, "", "");
        // Built-in CN: 10 ms cross-carrier, 30 ms cross-border.
        assert_eq!(penalty(&routing, &tel, &uni, false), 10.0);
        assert_eq!(penalty(&routing, &tel, &tel, false), 0.0);
        assert_eq!(penalty(&routing, &tel, &uni, true), 0.0, "multi-line BGP relay");
        assert_eq!(penalty(&routing, &tel, &cn_unknown, false), 0.0, "unknown group");
        assert_eq!(penalty(&routing, &tel, &hk, false), 30.0);
        assert_eq!(penalty(&routing, &hk, &tel, true), 30.0, "multi_bgp doesn't skip cross-border");
        assert_eq!(penalty(&routing, &us, &jp, false), 0.0, "global default");
        assert_eq!(penalty(&routing, &tel, &nowhere, false), 0.0, "unknown country");

        let mut routing = routing;
        routing.cross_carrier_ms = 3.0;
        routing.cross_border_ms = 7.0;
        routing.country.insert(
            "JP".to_owned(),
            CountryPenalty {
                cross_carrier_ms: None,
                cross_border_ms: Some(50.0),
            },
        );
        let us2 = loc(0.0, 0.0, "US", "AS701");
        assert_eq!(penalty(&routing, &us, &us2, false), 3.0, "no override: global cross-carrier");
        assert_eq!(penalty(&routing, &us, &hk, false), 7.0, "no override: global cross-border");
        assert_eq!(penalty(&routing, &us, &jp, false), 50.0, "one override");
        assert_eq!(penalty(&routing, &jp, &tel, false), 50.0, "larger of two overrides");
        assert_eq!(penalty(&routing, &hk, &tel, false), 30.0);
        // JP has no cross-carrier override: the global value applies.
        let jp2 = loc(0.0, 0.0, "JP", "AS4713");
        assert_eq!(penalty(&routing, &jp, &jp2, false), 3.0);
    }

    #[test]
    fn rtt_and_score() {
        let routing = Config::default().routing;
        let a = loc(39.9042, 116.4074, "CN", "cn-telecom"); // Beijing
        let b = loc(31.2304, 121.4737, "CN", "cn-unicom"); // Shanghai
        let r = loc(31.2304, 121.4737, "CN", "cn-unicom");
        let ab = leg_rtt(&routing, &a, &r, false).unwrap();
        // ≈ 1067 km × 2 × 2 / 200 + 10 ms cross-carrier.
        assert!((ab - 31.3).abs() < 0.5, "{ab}");
        assert_eq!(leg_rtt(&routing, &b, &r, false), Some(0.0));
        assert_eq!(leg_rtt(&routing, &Loc::default(), &r, false), None);

        let none = Loc::default();
        let cands = [
            Candidate { loc: &r, weight: 2.0, multi_bgp: false },
            Candidate { loc: &none, weight: 1.0, multi_bgp: false },
        ];
        let (basis, costs) = score(&routing, &a, &b, &cands).unwrap();
        assert_eq!(basis, "geo");
        assert!((costs[0].unwrap() - ab * 2.0).abs() < 1e-9);
        assert_eq!(costs[1], None, "relay without position takes no part");
        let (basis, costs) = score(&routing, &a, &none, &cands).unwrap();
        assert_eq!(basis, "geo_a");
        assert!((costs[0].unwrap() - 2.0 * ab * 2.0).abs() < 1e-9);
        assert_eq!(score(&routing, &none, &b, &cands).unwrap().0, "geo_b");
        assert!(score(&routing, &none, &none, &cands).is_none());

        assert_eq!(pick(&[None, Some(3.0), Some(1.0), Some(1.0)]), Some(2));
        assert_eq!(pick(&[None, None]), None);
    }

    struct Fake;
    impl Locate for Fake {
        fn locate(&self, ip: IpAddr) -> Option<GeoRecord> {
            (ip == IpAddr::from([1, 2, 3, 4])).then(|| GeoRecord {
                lat: Some(1.0),
                lon: Some(2.0),
                country: Some("CN".to_owned()),
                asn: Some(4837),
            })
        }
    }

    #[test]
    fn client_positions() {
        let carriers = Carriers::new(&BTreeMap::from([(4837, "mine".to_owned()), (64512, "x".to_owned())]));
        assert_eq!(carriers.group(4134), "cn-telecom");
        assert_eq!(carriers.group(4837), "mine", "configured entries win");
        assert_eq!(carriers.group(13335), "AS13335");
        let server = Location {
            lat: 29.5,
            lon: 106.5,
            country: "CN".to_owned(),
            carrier: String::new(),
        };
        let geo: Option<&dyn Locate> = Some(&Fake);
        // Public address: looked up (also through a v4-mapped v6 address).
        let public = client_loc("::ffff:1.2.3.4".parse().unwrap(), geo, &carriers, Some(&server));
        assert_eq!(public, loc(1.0, 2.0, "CN", "mine"));
        assert_eq!(client_loc("5.6.7.8".parse().unwrap(), geo, &carriers, None), Loc::default());
        assert_eq!(client_loc("1.2.3.4".parse().unwrap(), None, &carriers, None), Loc::default());
        // Private, loopback, link-local, ULA: the server's position, empty fields unknown.
        for ip in ["192.168.1.2", "10.0.0.1", "127.0.0.1", "169.254.1.1", "::1", "fe80::1", "fd00::1"] {
            let l = client_loc(ip.parse().unwrap(), geo, &carriers, Some(&server));
            assert_eq!(l, loc(29.5, 106.5, "CN", ""), "{ip}");
            assert_eq!(client_loc(ip.parse().unwrap(), geo, &carriers, None), Loc::default());
        }
        // 100.64/10 is unknown even with a server position.
        assert_eq!(client_loc("100.100.1.1".parse().unwrap(), geo, &carriers, Some(&server)), Loc::default());
    }

    #[test]
    fn relay_overrides() {
        let carriers = Carriers::new(&BTreeMap::new());
        let rec = GeoRecord {
            lat: Some(1.0),
            lon: Some(2.0),
            country: Some("CN".to_owned()),
            asn: Some(4134),
        };
        let mut r = RelayConfig::new("r".to_owned());
        assert!(needs_lookup(&r));
        assert_eq!(relay_loc(&r, Some(rec.clone()), &carriers), loc(1.0, 2.0, "CN", "cn-telecom"));
        assert_eq!(relay_loc(&r, None, &carriers), Loc::default());
        r.lat = Some(22.3);
        r.country = Some(String::new()); // empty: not an override
        r.carrier = Some("AS9304".to_owned());
        assert_eq!(relay_loc(&r, Some(rec), &carriers), loc(22.3, 2.0, "CN", "AS9304"));
        assert_eq!(relay_loc(&r, None, &carriers).pos, None, "lon still unknown");
        r.lon = Some(114.2);
        r.country = Some("HK".to_owned());
        assert!(!needs_lookup(&r));
        assert_eq!(relay_loc(&r, None, &carriers), loc(22.3, 114.2, "HK", "AS9304"));
    }

    #[test]
    fn configured_asn_carriers_are_groups() {
        // Review C-10: `carrier = "AS4837"` is the same group as a client in AS4837.
        let routing = Config::default().routing;
        let carriers = Carriers::new(&BTreeMap::from([(64512, "mine".to_owned())]));
        let mut r = RelayConfig::new("r".to_owned());
        (r.lat, r.lon, r.country) = (Some(1.0), Some(2.0), Some("CN".to_owned()));
        let client = client_loc("1.2.3.4".parse().unwrap(), Some(&Fake), &carriers, None);
        for (carrier, group) in [
            ("AS4837", "cn-unicom"),
            ("AS64512", "mine"),
            ("AS13335", "AS13335"),
            ("cn-unicom", "cn-unicom"),
            ("ASx", "ASx"),
        ] {
            r.carrier = Some(carrier.to_owned());
            assert_eq!(relay_loc(&r, None, &carriers).carrier.as_deref(), Some(group), "{carrier}");
        }
        r.carrier = Some("AS4837".to_owned());
        assert_eq!(penalty(&routing, &client, &relay_loc(&r, None, &carriers), false), 0.0);
        let server = Location {
            lat: 1.0,
            lon: 2.0,
            country: "CN".to_owned(),
            carrier: "AS4134".to_owned(),
        };
        let private = client_loc("10.0.0.1".parse().unwrap(), None, &carriers, Some(&server));
        assert_eq!(private.carrier.as_deref(), Some("cn-telecom"));
    }
}
