//! STUN for the self-built ICE (phase 3 contract 05 §2.8, §2.9.3, §3.2): Binding requests on
//! 21116/UDP are answered with the source's address (XOR-MAPPED-ADDRESS) and a proof that this
//! process saw it (`LEAPGATE-PROOF`), which public IPv4 candidates must carry. Hand-written, no STUN
//! library: only Binding requests are recognised, no attribute of a request is read, and the only
//! message sent is a Binding success response, always shorter than the request (§2.9.3).

use once_cell::sync::Lazy;
use sodiumoxide::{crypto::auth, utils::memcmp};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Bytes 4..8 of every STUN message (RFC 8489).
pub(crate) const STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
/// Shorter requests get no answer: the longest response (an IPv6 source) is 96 bytes and STUN
/// lengths are multiples of 4, so from 100 bytes on the answer is always smaller (§2.9.3).
const STUN_MIN_REQUEST: usize = 100;
const HEADER_LEN: usize = 20;
const BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
const BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
const ATTR_XOR_MAPPED: u16 = 0x0020;
const ATTR_LEAPGATE_PROOF: u16 = 0xC1E9;
const ATTR_FINGERPRINT: u16 = 0x8028;
const FINGERPRINT_XOR: u32 = 0x5354_554E;

const PROOF_VER: u8 = 1;
const PROOF_TTL_SECS: u64 = 30;
const PROOF_MAC_LEN: usize = 16;
/// Random per process, only in memory: a restart voids the proofs of the few connections being set
/// up at that moment (§2.8).
static PROOF_KEY: Lazy<auth::Key> = Lazy::new(auth::gen_key);

/// `bytes` is one whole UDP datagram. Only a Binding request gives its transaction id: type 00 01,
/// the magic cookie, a length field that is a multiple of 4 and accounts for the datagram exactly,
/// and at least `STUN_MIN_REQUEST` bytes. Attributes are not looked at (PADDING only makes up the
/// length).
pub fn parse_binding_request(bytes: &[u8]) -> Option<[u8; 12]> {
    if bytes.len() < STUN_MIN_REQUEST || bytes[..2] != BINDING_REQUEST || bytes[4..8] != STUN_MAGIC {
        return None;
    }
    let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if len % 4 != 0 || HEADER_LEN + len != bytes.len() {
        return None;
    }
    bytes[8..HEADER_LEN].try_into().ok()
}

/// Binding success response (0x0101) with the request's transaction id: XOR-MAPPED-ADDRESS,
/// LEAPGATE-PROOF, FINGERPRINT. `source` is already normalized (no `::ffff:` form) and `proof` is
/// `seal`'s output for it.
pub fn binding_response(txid: &[u8; 12], source: SocketAddr, proof: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(&BINDING_SUCCESS);
    m.extend_from_slice(&[0, 0]);
    m.extend_from_slice(&STUN_MAGIC);
    m.extend_from_slice(txid);
    push_attr(&mut m, ATTR_XOR_MAPPED, &xor_mapped_address(txid, source));
    push_attr(&mut m, ATTR_LEAPGATE_PROOF, proof);
    // The length already counts FINGERPRINT when its CRC is taken (RFC 8489 §14.7).
    let len = (m.len() + 8 - HEADER_LEN) as u16;
    m[2..4].copy_from_slice(&len.to_be_bytes());
    let crc = fingerprint(&m);
    push_attr(&mut m, ATTR_FINGERPRINT, &crc.to_be_bytes());
    m
}

/// Values here are 4, 8, 20, 28 or 40 bytes: no padding needed.
fn push_attr(m: &mut Vec<u8>, kind: u16, value: &[u8]) {
    m.extend_from_slice(&kind.to_be_bytes());
    m.extend_from_slice(&(value.len() as u16).to_be_bytes());
    m.extend_from_slice(value);
}

/// The value of XOR-MAPPED-ADDRESS (RFC 8489 §14.2): the port XOR the cookie's top 16 bits, an IPv4
/// address XOR the cookie, an IPv6 address XOR the cookie and the transaction id.
fn xor_mapped_address(txid: &[u8; 12], addr: SocketAddr) -> Vec<u8> {
    let port = addr.port() ^ 0x2112;
    let mut key = STUN_MAGIC.to_vec();
    key.extend_from_slice(txid);
    let (family, ip) = match addr.ip() {
        IpAddr::V4(ip) => (1, ip.octets().to_vec()),
        IpAddr::V6(ip) => (2, ip.octets().to_vec()),
    };
    let mut v = vec![0, family];
    v.extend_from_slice(&port.to_be_bytes());
    v.extend(ip.iter().zip(&key).map(|(a, k)| a ^ k));
    v
}

/// CRC-32 (ISO-HDLC, zlib's) of everything before the FINGERPRINT attribute, XOR 0x5354554E.
fn fingerprint(before: &[u8]) -> u32 {
    crc32fast::hash(before) ^ FINGERPRINT_XOR
}

/// version(1) ‖ ts(u32 big-endian) ‖ family(1, 4|6) ‖ address(4|16) ‖ port(u16 big-endian) ‖ the
/// first 16 bytes of `crypto_auth` over the rest. `addr` is already normalized by the caller.
pub fn seal(addr: SocketAddr, now: u64) -> Vec<u8> {
    seal_with(&PROOF_KEY, addr, now)
}

/// The address in a proof this process issued within `PROOF_TTL_SECS` and whose MAC matches;
/// `None` for anything else.
#[allow(dead_code)] // read by the OFFER/ANSWER checks (contract 05 §3.3), in the next commit
pub fn open(proof: &[u8], now: u64) -> Option<SocketAddr> {
    open_with(&PROOF_KEY, proof, now)
}

fn seal_with(key: &auth::Key, addr: SocketAddr, now: u64) -> Vec<u8> {
    let mut p = vec![PROOF_VER];
    p.extend_from_slice(&(now as u32).to_be_bytes());
    match addr.ip() {
        IpAddr::V4(ip) => {
            p.push(4);
            p.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            p.push(6);
            p.extend_from_slice(&ip.octets());
        }
    }
    p.extend_from_slice(&addr.port().to_be_bytes());
    let tag = auth::authenticate(&p, key);
    p.extend_from_slice(&tag.0[..PROOF_MAC_LEN]);
    p
}

/// Length and family first (no MAC for a malformed one), then the MAC in constant time (a truncated
/// tag, so not `auth::verify`), then version and age, then the address.
fn open_with(key: &auth::Key, proof: &[u8], now: u64) -> Option<SocketAddr> {
    let ip_len = match (proof.len(), proof.get(5)) {
        (28, Some(4)) => 4,
        (40, Some(6)) => 16,
        _ => return None,
    };
    let (body, mac) = proof.split_at(proof.len() - PROOF_MAC_LEN);
    if !memcmp(&auth::authenticate(body, key).0[..PROOF_MAC_LEN], mac) {
        return None;
    }
    let ts = u32::from_be_bytes(body[1..5].try_into().ok()?) as u64;
    if body[0] != PROOF_VER || ts > now || ts < now.saturating_sub(PROOF_TTL_SECS) {
        return None;
    }
    let ip: IpAddr = if ip_len == 4 {
        Ipv4Addr::from(<[u8; 4]>::try_from(&body[6..10]).ok()?).into()
    } else {
        Ipv6Addr::from(<[u8; 16]>::try_from(&body[6..22]).ok()?).into()
    };
    let port = u16::from_be_bytes([body[6 + ip_len], body[7 + ip_len]]);
    if port == 0 || ip.is_unspecified() {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unhex;

    // The vectors the client's tests share (contract 05 §2.8, §2.9.3), byte for byte.
    const TS: u64 = 1761200000;
    const PROOF_V4: &str = "0168f9c78004cb0071079c4019f16eb06b0d075a34e2cabc1d3347bd";
    const PROOF_V6: &str = "0168f9c7800620010db80000000000000000000000079c40e7e3d0fa91fc4de0f67431fb376d3ada";
    const TXID: &str = "0102030400060708090a0b0c";
    const REQUEST_HEAD: &str = "000100502112a4420102030400060708090a0b0c0026004c";
    const RESPONSE_V4: &str = "010100342112a4420102030400060708090a0b0c002000080001bd52ea12d545c1e9001c0168f9c78004cb0071079c4019f16eb06b0d075a34e2cabc1d3347bd802800044a994370";

    // RFC 5769 §2.2 and §2.3 (the byte arrays of `stun_codec` 0.3.5's own tests).
    const RFC5769_V4: &str = "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96";
    const RFC5769_V6: &str = "010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c";

    fn mac_key() -> auth::Key {
        auth::Key([5u8; 32])
    }

    fn request() -> Vec<u8> {
        let mut r = unhex(REQUEST_HEAD);
        r.resize(100, 0);
        r
    }

    fn txid() -> [u8; 12] {
        unhex(TXID).try_into().unwrap()
    }

    #[test]
    fn proof_vectors() {
        let v4: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::7]:40000".parse().unwrap();
        assert_eq!(seal_with(&mac_key(), v4, TS), unhex(PROOF_V4));
        assert_eq!(seal_with(&mac_key(), v6, TS), unhex(PROOF_V6));
        assert_eq!(open_with(&mac_key(), &unhex(PROOF_V4), TS), Some(v4));
        assert_eq!(open_with(&mac_key(), &unhex(PROOF_V6), TS), Some(v6));
    }

    #[test]
    fn proof_opens_only_unchanged_fresh_and_ours() {
        let now = crate::common::now();
        for addr in ["198.51.100.9:1", "[2001:db8::1:2]:65535"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let p = seal(addr, now);
            assert_eq!(open(&p, now), Some(addr));
            // Any byte: version, ts, family, address, port, MAC.
            for i in 0..p.len() {
                let mut q = p.clone();
                q[i] ^= 0x01;
                assert_eq!(open(&q, now), None, "{addr} byte {i}");
            }
            assert_eq!(open(&p, now + PROOF_TTL_SECS), Some(addr));
            assert_eq!(open(&p, now + PROOF_TTL_SECS + 1), None, "too old");
            assert_eq!(open(&p, now - 1), None, "from the future");
            // Another key (another process, or before a restart).
            assert_eq!(open_with(&mac_key(), &p, now), None);
        }
        for len in [0, 27, 29, 41] {
            assert_eq!(open(&vec![PROOF_VER; len], now), None, "{len}");
        }
        // A sealed unspecified address or port 0 does not open.
        for addr in ["0.0.0.0:5", "1.2.3.4:0", "[::]:5"] {
            assert_eq!(open(&seal(addr.parse().unwrap(), now), now), None, "{addr}");
        }
    }

    #[test]
    fn binding_request_is_recognised_strictly() {
        assert_eq!(parse_binding_request(&request()), Some(txid()));
        // Longer requests are fine as long as the length field accounts for them.
        let mut long = request();
        long.extend_from_slice(&[0; 4]);
        long[2..4].copy_from_slice(&84u16.to_be_bytes());
        assert_eq!(parse_binding_request(&long), Some(txid()));
        // The longest valid request under the threshold: 96 bytes, length 76.
        let mut short = request();
        short.truncate(96);
        short[2..4].copy_from_slice(&76u16.to_be_bytes());
        assert_eq!(parse_binding_request(&short), None);
        let cases: [(&str, fn(&mut Vec<u8>)); 7] = [
            ("indication", |r| r[..2].copy_from_slice(&[0x00, 0x11])),
            ("success response", |r| r[..2].copy_from_slice(&[0x01, 0x01])),
            ("error response", |r| r[..2].copy_from_slice(&[0x01, 0x11])),
            ("another method", |r| r[..2].copy_from_slice(&[0x00, 0x03])),
            ("magic", |r| r[7] ^= 1),
            ("length not a multiple of 4", |r| {
                r.push(0);
                r[2..4].copy_from_slice(&81u16.to_be_bytes());
            }),
            ("length not the datagram's", |r| r[2..4].copy_from_slice(&84u16.to_be_bytes())),
        ];
        for (what, change) in cases {
            let mut r = request();
            change(&mut r);
            assert_eq!(parse_binding_request(&r), None, "{what}");
        }
    }

    #[test]
    fn binding_response_vector() {
        let resp = binding_response(&txid(), "203.0.113.7:40000".parse().unwrap(), &unhex(PROOF_V4));
        assert_eq!(resp, unhex(RESPONSE_V4));
    }

    /// The threshold from the responses this encoder actually builds, not from the contract's
    /// length table: every answer is strictly shorter than the request (with the IP and UDP headers
    /// too, which are the same on both), and `STUN_MIN_REQUEST` is the shortest valid STUN length
    /// above the longest answer.
    #[test]
    fn responses_are_shorter_than_requests() {
        let now = crate::common::now();
        let lens: Vec<usize> = ["203.0.113.7:40000", "[2001:db8::7]:40000"]
            .iter()
            .map(|a| {
                let a: SocketAddr = a.parse().unwrap();
                binding_response(&txid(), a, &seal(a, now)).len()
            })
            .collect();
        let longest = *lens.iter().max().unwrap();
        for &len in &lens {
            assert!(len < STUN_MIN_REQUEST, "{lens:?}");
            assert_eq!((len - HEADER_LEN) % 4, 0, "{lens:?}");
        }
        let shortest_above = HEADER_LEN + ((longest - HEADER_LEN) / 4 + 1) * 4;
        assert_eq!(STUN_MIN_REQUEST, shortest_above, "{lens:?}");
        assert_eq!(request().len(), STUN_MIN_REQUEST);
    }

    #[test]
    fn rfc5769_xor_mapped_address_and_fingerprint() {
        for (hex, addr, xor_at) in [
            (RFC5769_V4, "192.0.2.1:32853", 40),
            (RFC5769_V6, "[2001:db8:1234:5678:11:2233:4455:6677]:32853", 40),
        ] {
            let msg = unhex(hex);
            let txid: [u8; 12] = msg[8..20].try_into().unwrap();
            let xor = xor_mapped_address(&txid, addr.parse().unwrap());
            assert_eq!(msg[xor_at - 4..xor_at], [0x00, 0x20, 0x00, xor.len() as u8], "{addr}");
            assert_eq!(&msg[xor_at..xor_at + xor.len()], &xor[..], "{addr}");
            let (before, crc) = msg.split_at(msg.len() - 4);
            assert_eq!(fingerprint(&before[..before.len() - 4]).to_be_bytes(), crc, "{addr}");
        }
    }
}
