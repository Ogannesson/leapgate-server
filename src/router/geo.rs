//! GeoIP files (LEAPGATE.md §7, note 06 §1~§3): finding, opening and checking the mmdb files, the DB-IP
//! Lite download, and the cleanup rules.

use super::cost::{GeoRecord, Locate};
use crate::config::{GeoConfig, GeoSource};
use hbb_common::{anyhow::anyhow, bail, chrono, log, tokio, ResultType};
use maxminddb::{geoip2, Mmap, Reader};
use std::{
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

/// A database month (`YYYY-MM` in DB-IP file names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Ym {
    y: i32,
    m: u32,
}

impl Ym {
    pub fn new(y: i32, m: u32) -> Self {
        Self { y, m }
    }

    /// The current UTC month (DB-IP publishes on the 1st, about 06:30 UTC).
    pub fn now_utc() -> Self {
        use chrono::Datelike;
        let now = chrono::Utc::now();
        Self::new(now.year(), now.month())
    }

    pub fn prev(self) -> Self {
        if self.m == 1 {
            Self::new(self.y - 1, 12)
        } else {
            Self::new(self.y, self.m - 1)
        }
    }

    fn parse(s: &str) -> Option<Self> {
        let (y, m) = s.split_once('-')?;
        if y.len() != 4 || m.len() != 2 {
            return None;
        }
        let (y, m) = (y.parse().ok()?, m.parse().ok()?);
        (1..=12).contains(&m).then(|| Self::new(y, m))
    }
}

impl fmt::Display for Ym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}", self.y, self.m)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    City,
    Asn,
}

impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Kind::City => "dbip-city-lite-",
            Kind::Asn => "dbip-asn-lite-",
        }
    }

    /// `dbip-{city,asn}-lite-YYYY-MM.mmdb`
    fn file_name(self, ym: Ym) -> String {
        format!("{}{ym}.mmdb", self.prefix())
    }

    fn url(self, ym: Ym) -> String {
        format!("https://download.db-ip.com/free/{}.gz", self.file_name(ym))
    }

    fn of(self, months: (Ym, Ym)) -> Ym {
        match self {
            Kind::City => months.0,
            Kind::Asn => months.1,
        }
    }
}

/// The two opened databases: mapped (server), or read into memory (`geo lookup`, see [`load_in_memory`]).
pub(crate) struct GeoDb<S: AsRef<[u8]> = Mmap> {
    city: Reader<S>,
    asn: Reader<S>,
}

impl<S: AsRef<[u8]> + Send + Sync> Locate for GeoDb<S> {
    fn locate(&self, ip: IpAddr) -> Option<GeoRecord> {
        let city = self.city.lookup(ip).and_then(|r| r.decode::<geoip2::City>()).ok().flatten();
        let asn = self.asn.lookup(ip).and_then(|r| r.decode::<geoip2::Asn>()).ok().flatten();
        if city.is_none() && asn.is_none() {
            return None;
        }
        let mut rec = GeoRecord::default();
        if let Some(c) = city {
            rec.lat = c.location.latitude;
            rec.lon = c.location.longitude;
            rec.country = c.country.iso_code.map(str::to_owned);
        }
        rec.asn = asn.and_then(|a| a.autonomous_system_number);
        Some(rec)
    }
}

impl<S: AsRef<[u8]>> GeoDb<S> {
    /// AS organization, for `geo lookup` only (the cost model never matches on names).
    pub fn asn_org(&self, ip: IpAddr) -> Option<String> {
        let asn = self.asn.lookup(ip).and_then(|r| r.decode::<geoip2::Asn>()).ok().flatten()?;
        asn.autonomous_system_organization.map(str::to_owned)
    }
}

/// Which files are loaded.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct GeoInfo {
    pub city: PathBuf,
    pub asn: PathBuf,
    /// dbip: the months of the city and asn files.
    pub months: Option<(Ym, Ym)>,
    /// manual: modification times when loaded.
    pub mtimes: (Option<SystemTime>, Option<SystemTime>),
}

impl fmt::Display for GeoInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} + {}", self.city.display(), self.asn.display())
    }
}

/// The IP addresses checked after opening a database (note 06 §3.3).
const PROBES: [IpAddr; 2] = [IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))];

fn open(path: &Path) -> ResultType<Reader<Mmap>> {
    // SAFETY: the files we map are only replaced by renaming a new file over them, never modified in
    // place: our DB-IP downloads, and for manual files our private copies (`private_copy`).
    unsafe { Reader::open_mmap(path) }.map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// Reads a whole file into memory: nothing is mapped, so whatever happens to the file later cannot
/// affect what was read.
fn read(path: &Path) -> ResultType<Reader<Vec<u8>>> {
    Reader::open_readfile(path).map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// Where the server keeps its private copies of manual files: `.leapgate-geoip/` in its working
/// directory, next to the database and the key files. That is writable even when `geo.dir` is not
/// (geoipupdate's root-owned directory, a read-only mount). Fixed, not configurable.
pub(crate) const COPY_DIR: &str = ".leapgate-geoip";

/// `source = "manual"` on the server: operators may update a file in place (cp, curl -o), and a
/// mapped file that shrinks under us kills the process with SIGBUS. So we map a copy,
/// `<copies>/<file name>`, made on every load under a temporary name and renamed into place. Only the
/// server writes there (`geo lookup` reads into memory), and its loads are serialized.
fn private_copy(path: &Path, copies: &Path) -> ResultType<PathBuf> {
    let Some(name) = path.file_name() else {
        bail!("{}: not a file path", path.display());
    };
    let copy = copies.join(name);
    let part = copies.join(format!("{}.part", name.to_string_lossy()));
    let res = std::fs::create_dir_all(copies)
        .and_then(|_| std::fs::copy(path, &part))
        .and_then(|_| std::fs::rename(&part, &copy));
    if let Err(e) = res {
        std::fs::remove_file(&part).ok();
        bail!("{}: copy to {}: {e}", path.display(), copy.display());
    }
    Ok(copy)
}

/// Opens a city database and checks it.
fn open_city(path: &Path) -> ResultType<Reader<Mmap>> {
    check_city(path, open(path)?)
}

/// Checks an opened city database (`path` names it in errors): type contains "City", and a probe has
/// a position and country.
fn check_city<S: AsRef<[u8]>>(path: &Path, r: Reader<S>) -> ResultType<Reader<S>> {
    let ty = &r.metadata().database_type;
    if !ty.contains("City") {
        bail!("{}: database type '{ty}' is not a city database", path.display());
    }
    let ok = PROBES.iter().any(|ip| {
        matches!(
            r.lookup(*ip).and_then(|l| l.decode::<geoip2::City>()),
            Ok(Some(c)) if c.location.latitude.is_some() && c.location.longitude.is_some()
                && c.country.iso_code.is_some_and(|cc| !cc.is_empty())
        )
    });
    if !ok {
        bail!("{}: no position for the probe addresses", path.display());
    }
    Ok(r)
}

/// Opens an ASN database and checks it.
fn open_asn(path: &Path) -> ResultType<Reader<Mmap>> {
    check_asn(path, open(path)?)
}

/// Checks an opened ASN database (`path` names it in errors): type contains "ASN", and 8.8.8.8 has
/// an ASN.
fn check_asn<S: AsRef<[u8]>>(path: &Path, r: Reader<S>) -> ResultType<Reader<S>> {
    let ty = &r.metadata().database_type;
    if !ty.contains("ASN") {
        bail!("{}: database type '{ty}' is not an ASN database", path.display());
    }
    let ok = matches!(
        r.lookup(PROBES[0]).and_then(|l| l.decode::<geoip2::Asn>()),
        Ok(Some(a)) if a.autonomous_system_number.is_some()
    );
    if !ok {
        bail!("{}: no ASN for the probe address", path.display());
    }
    Ok(r)
}

/// `dbip-{kind}-lite-YYYY-MM.mmdb` files in `dir`, newest first.
pub(crate) fn dbip_files(dir: &Path, kind: Kind) -> Vec<(Ym, PathBuf)> {
    let mut out: Vec<(Ym, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let ym = name.to_str()?.strip_prefix(kind.prefix())?.strip_suffix(".mmdb")?;
            Some((Ym::parse(ym)?, e.path()))
        })
        .collect();
    out.sort_by(|a, b| b.0.cmp(&a.0));
    out
}

/// The newest file of `kind` that opens and passes the checks; broken ones are logged and skipped.
fn open_newest<S: AsRef<[u8]>>(
    dir: &Path,
    kind: Kind,
    open: impl Fn(&Path) -> ResultType<Reader<S>>,
) -> ResultType<(Ym, PathBuf, Reader<S>)> {
    for (ym, path) in dbip_files(dir, kind) {
        let opened = open(&path).and_then(|r| match kind {
            Kind::City => check_city(&path, r),
            Kind::Asn => check_asn(&path, r),
        });
        match opened {
            Ok(r) => return Ok((ym, path, r)),
            Err(e) => log::error!("GeoIP: {e}"),
        }
    }
    bail!("no usable {}YYYY-MM.mmdb in {}", kind.prefix(), dir.display())
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// `source = "manual"`: the two configured files and their modification times.
pub(crate) fn manual_paths(cfg: &GeoConfig) -> (PathBuf, PathBuf) {
    let dir = Path::new(&cfg.dir);
    (dir.join(&cfg.city_file), dir.join(&cfg.asn_file))
}

pub(crate) fn manual_mtimes(cfg: &GeoConfig) -> (Option<SystemTime>, Option<SystemTime>) {
    let (city, asn) = manual_paths(cfg);
    (mtime(&city), mtime(&asn))
}

/// Finds and maps the databases (server; also `geo update` in the command line, which only needs the
/// months): dbip maps the newest month of each kind, manual maps private copies of the configured
/// files in [`COPY_DIR`] (see [`private_copy`]). Both files are required.
pub(crate) fn load(cfg: &GeoConfig) -> ResultType<(GeoDb, GeoInfo)> {
    load_copying(cfg, Path::new(COPY_DIR))
}

/// [`load`], with the private copies of manual files in `copies`.
pub(super) fn load_copying(cfg: &GeoConfig, copies: &Path) -> ResultType<(GeoDb, GeoInfo)> {
    match cfg.source {
        GeoSource::Dbip => load_with(cfg, open),
        GeoSource::Manual => load_with(cfg, |path| open(&private_copy(path, copies)?)),
    }
}

/// `geo lookup` with `source = "manual"`: the same files as [`load`], read into memory, so the
/// command writes nothing (not even private copies). A short-lived process can afford the memory.
pub(crate) fn load_in_memory(cfg: &GeoConfig) -> ResultType<(GeoDb<Vec<u8>>, GeoInfo)> {
    load_with(cfg, read)
}

/// Finds the files (dbip: the newest month of each kind; manual: the configured files), opens them
/// with `open` and checks them.
fn load_with<S: AsRef<[u8]>>(
    cfg: &GeoConfig,
    open: impl Fn(&Path) -> ResultType<Reader<S>>,
) -> ResultType<(GeoDb<S>, GeoInfo)> {
    match cfg.source {
        GeoSource::Dbip => {
            let dir = Path::new(&cfg.dir);
            let (cm, city_path, city) = open_newest(dir, Kind::City, &open)?;
            let (am, asn_path, asn) = open_newest(dir, Kind::Asn, &open)?;
            let info = GeoInfo {
                city: city_path,
                asn: asn_path,
                months: Some((cm, am)),
                mtimes: (None, None),
            };
            Ok((GeoDb { city, asn }, info))
        }
        GeoSource::Manual => {
            let (city_path, asn_path) = manual_paths(cfg);
            let mtimes = manual_mtimes(cfg);
            let db = GeoDb {
                city: check_city(&city_path, open(&city_path)?)?,
                asn: check_asn(&asn_path, open(&asn_path)?)?,
            };
            let info = GeoInfo {
                city: city_path,
                asn: asn_path,
                months: None,
                mtimes,
            };
            Ok((db, info))
        }
    }
}

/// Server start: removes leftover `*.part` files.
pub(crate) fn remove_parts(dir: &Path) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy().ends_with(".part") {
            if let Err(err) = std::fs::remove_file(e.path()) {
                log::warn!("GeoIP: failed to remove {}: {err}", e.path().display());
            }
        }
    }
}

/// At server start and after a hot swap: removes the DB-IP files of other months than the loaded ones.
/// Failures are ignored (Windows refuses while a file is mapped); the next start tries again.
pub(crate) fn remove_old_months(dir: &Path, keep: &GeoInfo) {
    for kind in [Kind::City, Kind::Asn] {
        for (_, path) in dbip_files(dir, kind) {
            if path != keep.city && path != keep.asn {
                std::fs::remove_file(&path).ok();
            }
        }
    }
}

/// The kinds to download for month `target` given the loaded months (all of them when nothing is loaded).
pub(crate) fn plan(have: Option<(Ym, Ym)>, target: Ym) -> Vec<Kind> {
    [Kind::City, Kind::Asn]
        .into_iter()
        .filter(|k| have.map_or(true, |h| k.of(h) < target))
        .collect()
}

/// When this month is a 404: fetch last month only when nothing is loaded or the loaded files are
/// older than last month; otherwise keep them and retry tomorrow.
pub(crate) fn may_fall_back(want: Ym, have: Option<(Ym, Ym)>) -> bool {
    have.map_or(true, |(c, a)| c.min(a) < want.prev())
}

/// Result of one update check.
pub(crate) enum Update {
    UpToDate,
    /// This month is not published yet (404) and the loaded files are recent enough.
    NotPublished(Ym),
    Updated(GeoDb, GeoInfo),
}

/// DB-IP update check (note 06 §3.2): want = this UTC month; download the kinds older than want, falling
/// back to last month on a 404 (see [`may_fall_back`]); check, rename into place, open the new pair.
/// Leaves no `*.part` behind and never touches the loaded files on failure. Removing old months is
/// up to the caller (the server only).
pub(crate) async fn update_dbip(dir: &Path, have: Option<(Ym, Ym)>) -> ResultType<Update> {
    let want = Ym::now_utc();
    let mut target = want;
    let kinds = loop {
        let kinds = plan(have, target);
        if kinds.is_empty() {
            return Ok(Update::UpToDate);
        }
        match fetch(dir, &kinds, target).await? {
            true => break kinds,
            false if target == want && may_fall_back(want, have) => {
                log::info!("GeoIP: DB-IP {want} not published yet, trying {}", want.prev());
                target = want.prev();
            }
            false => return Ok(Update::NotPublished(target)),
        }
    };
    let month = |kind: Kind| match have {
        Some(h) if !kinds.contains(&kind) => kind.of(h),
        _ => target,
    };
    let (cm, am) = (month(Kind::City), month(Kind::Asn));
    let (city_path, asn_path) = (dir.join(Kind::City.file_name(cm)), dir.join(Kind::Asn.file_name(am)));
    let db = GeoDb {
        city: open_city(&city_path)?,
        asn: open_asn(&asn_path)?,
    };
    let info = GeoInfo {
        city: city_path,
        asn: asn_path,
        months: Some((cm, am)),
        mtimes: (None, None),
    };
    Ok(Update::Updated(db, info))
}

/// Temporary files of one kind: the download and the unpacked database.
fn part_paths(dir: &Path, kind: Kind, ym: Ym) -> (PathBuf, PathBuf) {
    let name = kind.file_name(ym);
    (dir.join(format!("{name}.gz.part")), dir.join(format!("{name}.part")))
}

/// Downloads, unpacks and checks every kind into `*.part`, then renames them all into place.
/// `Ok(false)`: month `ym` is not published (404). Any failure removes this run's `*.part` files.
async fn fetch(dir: &Path, kinds: &[Kind], ym: Ym) -> ResultType<bool> {
    std::fs::create_dir_all(dir)?;
    let mut res = fetch_parts(dir, kinds, ym).await;
    if let Ok(true) = res {
        for &kind in kinds {
            if let Err(e) = std::fs::rename(part_paths(dir, kind, ym).1, dir.join(kind.file_name(ym))) {
                res = Err(e.into());
                break;
            }
        }
    }
    for &kind in kinds {
        let (gz, mmdb) = part_paths(dir, kind, ym);
        std::fs::remove_file(gz).ok();
        std::fs::remove_file(mmdb).ok();
    }
    res
}

async fn fetch_parts(dir: &Path, kinds: &[Kind], ym: Ym) -> ResultType<bool> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(600))
        .build()?;
    for &kind in kinds {
        let (gz, mmdb) = part_paths(dir, kind, ym);
        let started = std::time::Instant::now();
        let Some(size) = download(&client, &kind.url(ym), &gz).await? else {
            return Ok(false);
        };
        tokio::task::spawn_blocking(move || -> ResultType<()> {
            gunzip(&gz, &mmdb)?;
            match kind {
                Kind::City => open_city(&mmdb).map(drop),
                Kind::Asn => open_asn(&mmdb).map(drop),
            }
        })
        .await??;
        log::info!(
            "GeoIP: downloaded {}.gz ({size} bytes) in {:.1?}",
            kind.file_name(ym),
            started.elapsed()
        );
    }
    Ok(true)
}

/// Streams the response into `to`; returns the size, `None` on 404.
async fn download(client: &reqwest::Client, url: &str, to: &Path) -> ResultType<Option<u64>> {
    use tokio::io::AsyncWriteExt;
    let mut resp = client.get(url).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        bail!("GET {url}: HTTP {}", resp.status());
    }
    let mut file = tokio::fs::File::create(to).await?;
    let mut size = 0u64;
    while let Some(chunk) = resp.chunk().await? {
        file.write_all(&chunk).await?;
        size += chunk.len() as u64;
    }
    file.flush().await?;
    Ok(Some(size))
}

/// Unpacks a gzip file to the end, so flate2 checks the trailer's CRC32 and length.
fn gunzip(from: &Path, to: &Path) -> ResultType<()> {
    let mut input = flate2::read::GzDecoder::new(std::io::BufReader::new(std::fs::File::open(from)?));
    let mut output = std::fs::File::create(to)?;
    std::io::copy(&mut input, &mut output).map_err(|e| anyhow!("{}: {e}", from.display()))?;
    output.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn months() {
        let m = Ym::new(2026, 10);
        assert_eq!(m.to_string(), "2026-10");
        assert_eq!(m.prev(), Ym::new(2026, 9));
        assert_eq!(Ym::new(2026, 1).prev(), Ym::new(2025, 12));
        assert!(Ym::new(2025, 12) < Ym::new(2026, 1));
        assert_eq!(Ym::parse("2026-03"), Some(Ym::new(2026, 3)));
        for bad in ["2026-13", "2026-3", "26-03", "2026_03", "abcd-ef"] {
            assert_eq!(Ym::parse(bad), None, "{bad}");
        }
        assert_eq!(
            Kind::City.url(m),
            "https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz"
        );
        assert_eq!(Kind::Asn.file_name(m), "dbip-asn-lite-2026-10.mmdb");
    }

    #[test]
    fn update_rules() {
        let (oct, sep, aug) = (Ym::new(2026, 10), Ym::new(2026, 9), Ym::new(2026, 8));
        assert_eq!(plan(None, oct), vec![Kind::City, Kind::Asn]);
        assert_eq!(plan(Some((oct, oct)), oct), vec![]);
        assert_eq!(plan(Some((oct, sep)), oct), vec![Kind::Asn]);
        assert_eq!(plan(Some((sep, sep)), oct), vec![Kind::City, Kind::Asn]);
        // This month 404: last month only when nothing is loaded or the files are older than it.
        assert!(may_fall_back(oct, None));
        assert!(!may_fall_back(oct, Some((sep, sep))));
        assert!(may_fall_back(oct, Some((sep, aug))));
        assert!(may_fall_back(oct, Some((aug, aug))));
        assert!(may_fall_back(Ym::new(2026, 1), Some((Ym::new(2025, 11), Ym::new(2025, 12)))));
    }

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn file_selection_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for n in [
            "dbip-city-lite-2026-09.mmdb",
            "dbip-city-lite-2026-10.mmdb",
            "dbip-city-lite-2025-12.mmdb",
            "dbip-city-lite-2026-11.mmdb.part",
            "dbip-city-lite-2026-11.mmdb.gz.part",
            "dbip-asn-lite-2026-08.mmdb",
            "dbip-city-lite-latest.mmdb",
            "GeoLite2-City.mmdb",
        ] {
            touch(dir, n);
        }
        let city = dbip_files(dir, Kind::City);
        let months: Vec<String> = city.iter().map(|(m, _)| m.to_string()).collect();
        assert_eq!(months, ["2026-10", "2026-09", "2025-12"]);
        assert_eq!(city[0].1, dir.join("dbip-city-lite-2026-10.mmdb"));
        assert_eq!(dbip_files(dir, Kind::Asn).len(), 1);
        assert!(dbip_files(&dir.join("missing"), Kind::Asn).is_empty());
        // Not real databases: nothing loads, and the files stay.
        let cfg = GeoConfig {
            dir: dir.to_string_lossy().into_owned(),
            ..Default::default()
        };
        assert!(load(&cfg).is_err());

        remove_parts(dir);
        assert!(!names(dir).iter().any(|n| n.ends_with(".part")));
        let keep = GeoInfo {
            city: dir.join("dbip-city-lite-2026-09.mmdb"),
            asn: dir.join("dbip-asn-lite-2026-08.mmdb"),
            ..Default::default()
        };
        remove_old_months(dir, &keep);
        assert_eq!(
            names(dir),
            [
                "GeoLite2-City.mmdb",
                "dbip-asn-lite-2026-08.mmdb",
                "dbip-city-lite-2026-09.mmdb",
                "dbip-city-lite-latest.mmdb"
            ]
        );
    }

    #[test]
    fn manual_files() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = GeoConfig {
            dir: tmp.path().to_string_lossy().into_owned(),
            source: GeoSource::Manual,
            ..Default::default()
        };
        let copies = tmp.path().join("copies");
        assert_eq!(manual_mtimes(&cfg), (None, None));
        assert!(load_copying(&cfg, &copies).is_err());
        assert!(load_in_memory(&cfg).is_err());
        touch(tmp.path(), "GeoLite2-City.mmdb");
        let (city, asn) = manual_mtimes(&cfg);
        assert!(city.is_some() && asn.is_none());
        // Present but not a database: rejected.
        touch(tmp.path(), "GeoLite2-ASN.mmdb");
        assert!(load_copying(&cfg, &copies).is_err());
        assert!(load_in_memory(&cfg).is_err());
    }
}
