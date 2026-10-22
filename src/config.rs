//! `porta.toml`: Porta's own structured configuration (PORTA.md §5).
//! hbbs' original arguments (`-p`, `-k`, `-r`, `DB_URL`, `.env`, ...) are unchanged and read via `get_arg`.

use hbb_common::{anyhow::Context, ResultType};
use serde_derive::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, path::Path};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub api: ApiConfig,
    pub geo: GeoConfig,
    pub routing: RoutingConfig,
    /// Effective relay list: `[[relay]]` from the file, or `-r` (weight 1) when the file has none.
    pub relay: Vec<RelayConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    /// `""` (default) = `0.0.0.0:{port-2}`, matching how clients derive the API address.
    #[serde(deserialize_with = "de_listen")]
    pub listen: Option<SocketAddr>,
    /// Public source of this deployment, linked from `GET /` (AGPL-3.0 §13). Deployment-specific,
    /// so it is configured rather than built in.
    pub source_url: String,
}

impl ApiConfig {
    /// The address to listen on; `port` is hbbs' `-p`.
    pub fn listen_addr(&self, port: i32) -> ResultType<SocketAddr> {
        match self.listen {
            Some(addr) => Ok(addr),
            None => {
                let port = u16::try_from(port - 2).context("Invalid port for the API")?;
                Ok(SocketAddr::from(([0, 0, 0, 0], port)))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoSource {
    /// Download DB-IP Lite automatically.
    Dbip,
    /// Only read the files already in `dir` (MaxMind goes this way).
    Manual,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoConfig {
    /// Directory holding the mmdb files, relative to the working directory.
    pub dir: String,
    pub source: GeoSource,
    /// Relative to `dir`; only used with `source = "manual"` (dbip uses `dbip-{city,asn}-lite-YYYY-MM.mmdb`).
    pub city_file: String,
    pub asn_file: String,
    pub auto_update: bool,
    /// Position used for private source addresses (note 06 §5.2).
    pub server_location: Option<Location>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub lat: f64,
    pub lon: f64,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub carrier: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    /// Detour factor k: rtt_ms = km × 2 × k / 200.
    pub detour: f64,
    /// Same country, different carrier group (per leg).
    pub cross_carrier_ms: f64,
    /// One end in the country, the other abroad (per leg).
    pub cross_border_ms: f64,
    /// Per-country overrides; a missing field falls back to the global value above.
    /// The built-in `CN` entry is always present (fields the file leaves out keep the built-in value).
    pub country: BTreeMap<String, CountryPenalty>,
    /// ASN → carrier group, added on top of the router's built-in table.
    #[serde(deserialize_with = "de_carriers")]
    pub carriers: BTreeMap<u32, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CountryPenalty {
    pub cross_carrier_ms: Option<f64>,
    pub cross_border_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Sent to clients as is.
    pub host: String,
    /// Cost multiplier.
    #[serde(default = "default_weight")]
    pub weight: f64,
    /// Multi-line BGP site: never counted as cross-carrier.
    #[serde(default)]
    pub multi_bgp: bool,
    /// Optional overrides of the position looked up from the IP database.
    #[serde(default)]
    pub lat: Option<f64>,
    #[serde(default)]
    pub lon: Option<f64>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub carrier: Option<String>,
}

fn default_weight() -> f64 {
    1.0
}

impl RelayConfig {
    pub fn new(host: String) -> Self {
        Self {
            host,
            weight: default_weight(),
            multi_bgp: false,
            lat: None,
            lon: None,
            country: None,
            carrier: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut cfg = Self {
            api: Default::default(),
            geo: Default::default(),
            routing: Default::default(),
            relay: Vec::new(),
        };
        cfg.apply_builtin();
        cfg
    }
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            dir: "geoip".to_owned(),
            source: GeoSource::Dbip,
            // geoipupdate's file names.
            city_file: "GeoLite2-City.mmdb".to_owned(),
            asn_file: "GeoLite2-ASN.mmdb".to_owned(),
            auto_update: true,
            server_location: None,
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            detour: 2.0,
            cross_carrier_ms: 0.0,
            cross_border_ms: 0.0,
            country: BTreeMap::new(),
            carriers: BTreeMap::new(),
        }
    }
}

/// Built-in per-country penalties (note 06 §4.2).
fn builtin_countries() -> [(&'static str, CountryPenalty); 1] {
    [(
        "CN",
        CountryPenalty {
            cross_carrier_ms: Some(10.0),
            cross_border_ms: Some(30.0),
        },
    )]
}

/// A comma-separated relay list (`-r`, console `rs a,b,c`): trimmed, without empty or duplicate
/// entries. No DNS check, unlike upstream's `get_servers`.
pub fn parse_relay_list(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for host in s.split(',').map(str::trim).filter(|h| !h.is_empty()) {
        if !out.iter().any(|h| h == host) {
            out.push(host.to_owned());
        }
    }
    out
}

fn de_listen<'de, D>(d: D) -> Result<Option<SocketAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::{de::Error, Deserialize};
    let s = String::deserialize(d)?;
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse()
        .map(Some)
        .map_err(|_| D::Error::custom(format!("api.listen: '{s}' is not an ip:port address")))
}

fn de_carriers<'de, D>(d: D) -> Result<BTreeMap<u32, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::{de::Error, Deserialize};
    // TOML keys are strings; the ASN must be a number.
    BTreeMap::<String, String>::deserialize(d)?
        .into_iter()
        .map(|(k, v)| {
            k.trim()
                .parse::<u32>()
                .map(|asn| (asn, v))
                .map_err(|_| D::Error::custom(format!("routing.carriers: ASN '{k}' is not a number")))
        })
        .collect()
}

impl Config {
    /// Reads `--porta-config` (default `porta.toml`) and `-r`.
    pub fn from_args() -> ResultType<Self> {
        let path = crate::common::get_arg_or("porta-config", "porta.toml".to_owned());
        Self::load(Path::new(&path), &crate::common::get_arg("relay-servers"))
    }

    /// A missing file means all defaults. `relay_servers` is the `-r` list, used when the file has no `[[relay]]`.
    pub fn load(path: &Path, relay_servers: &str) -> ResultType<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => Some(text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(err).with_context(|| format!("Failed to read {}", path.display()))
            }
        };
        let mut cfg = match text {
            Some(text) => Self::parse(&text).with_context(|| format!("Invalid {}", path.display()))?,
            None => Self::default(),
        };
        // Only empty and duplicate entries are dropped; no DNS check (the health check judges reachability).
        let mut seen = std::collections::HashSet::new();
        cfg.relay.retain(|r| !r.host.trim().is_empty() && seen.insert(r.host.clone()));
        if cfg.relay.is_empty() {
            cfg.relay = parse_relay_list(relay_servers)
                .into_iter()
                .map(RelayConfig::new)
                .collect();
        }
        Ok(cfg)
    }

    fn parse(text: &str) -> ResultType<Self> {
        let mut cfg: Self = toml::from_str(text)?;
        cfg.apply_builtin();
        Ok(cfg)
    }

    fn apply_builtin(&mut self) {
        for (code, builtin) in builtin_countries() {
            let entry = self.routing.country.entry(code.to_owned()).or_default();
            entry.cross_carrier_ms = entry.cross_carrier_ms.or(builtin.cross_carrier_ms);
            entry.cross_border_ms = entry.cross_border_ms.or(builtin.cross_border_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_uses_defaults_and_cli_relays() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(
            &dir.path().join("porta.toml"),
            "a.example:21117, b.example,,a.example:21117",
        )
        .unwrap();
        assert_eq!(cfg.api.listen, None);
        assert_eq!(cfg.api.listen_addr(21116).unwrap(), "0.0.0.0:21114".parse().unwrap());
        assert_eq!(cfg.api.listen_addr(30000).unwrap(), "0.0.0.0:29998".parse().unwrap());
        assert_eq!(cfg.geo.dir, "geoip");
        assert_eq!(cfg.geo.source, GeoSource::Dbip);
        assert_eq!(cfg.geo.city_file, "GeoLite2-City.mmdb");
        assert_eq!(cfg.geo.asn_file, "GeoLite2-ASN.mmdb");
        assert!(cfg.geo.auto_update);
        assert_eq!(cfg.routing.detour, 2.0);
        assert_eq!(
            cfg.routing.country["CN"],
            CountryPenalty {
                cross_carrier_ms: Some(10.0),
                cross_border_ms: Some(30.0)
            }
        );
        assert_eq!(
            cfg.relay,
            vec![
                RelayConfig::new("a.example:21117".to_owned()),
                RelayConfig::new("b.example".to_owned())
            ]
        );
    }

    #[test]
    fn full_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("porta.toml");
        std::fs::write(
            &path,
            r#"
[api]
listen = "127.0.0.1:8080"

[geo]
dir = "/var/lib/geo"
source = "manual"
city_file = "City.mmdb"
auto_update = false
server_location = { lat = 29.5, lon = 106.5, country = "CN", carrier = "cn-unicom" }

[routing]
detour = 1.8
cross_carrier_ms = 5
[routing.country.CN]
cross_border_ms = 50
[routing.country.US]
cross_carrier_ms = 3
[routing.carriers]
4134 = "cn-telecom"

[[relay]]
host = "r1.example:21117"
weight = 2.5
multi_bgp = true
lat = 22.3
lon = 114.2
country = "HK"

[[relay]]
host = "r2.example"

[[relay]]
host = "r2.example"
weight = 9.0

[[relay]]
host = ""
"#,
        )
        .unwrap();
        let cfg = Config::load(&path, "ignored.example").unwrap();
        assert_eq!(cfg.api.listen_addr(21116).unwrap(), "127.0.0.1:8080".parse().unwrap());
        assert_eq!(cfg.geo.source, GeoSource::Manual);
        assert_eq!(cfg.geo.city_file, "City.mmdb");
        assert_eq!(cfg.geo.asn_file, "GeoLite2-ASN.mmdb");
        assert!(!cfg.geo.auto_update);
        assert_eq!(cfg.geo.server_location.as_ref().unwrap().carrier, "cn-unicom");
        assert_eq!(cfg.routing.detour, 1.8);
        assert_eq!(cfg.routing.cross_carrier_ms, 5.0);
        assert_eq!(cfg.routing.cross_border_ms, 0.0);
        // The file overrides one CN field; the other keeps the built-in value.
        assert_eq!(cfg.routing.country["CN"].cross_border_ms, Some(50.0));
        assert_eq!(cfg.routing.country["CN"].cross_carrier_ms, Some(10.0));
        assert_eq!(cfg.routing.country["US"].cross_carrier_ms, Some(3.0));
        assert_eq!(cfg.routing.country["US"].cross_border_ms, None);
        assert_eq!(cfg.routing.carriers[&4134], "cn-telecom");
        assert_eq!(cfg.relay.len(), 2);
        assert_eq!(cfg.relay[0].weight, 2.5);
        assert!(cfg.relay[0].multi_bgp);
        assert_eq!(cfg.relay[0].country.as_deref(), Some("HK"));
        assert_eq!(cfg.relay[1], RelayConfig::new("r2.example".to_owned()));
    }

    #[test]
    fn relay_list() {
        assert_eq!(parse_relay_list(" a , b,,a, "), vec!["a".to_owned(), "b".to_owned()]);
        assert!(parse_relay_list("").is_empty());
        // Empty listen is the default.
        assert_eq!(Config::parse("[api]\nlisten = \"\"").unwrap().api.listen, None);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Config::parse("[api]\nlisten = \"nope\"").is_err());
        assert!(Config::parse("[routing.carriers]\nabc = \"x\"").is_err());
        assert!(Config::parse("[geo]\nsource = \"ipinfo\"").is_err());
        // Typos are reported instead of silently ignored.
        assert!(Config::parse("[routing]\ndetuor = 2.0").is_err());
    }
}
