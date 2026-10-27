//! Signaling of the self-built ICE (phase 3 contract 05 §2.3~§2.7, §3.3): candidates and their
//! filter, the session table, and the FORWARD that S sends B (encrypted to B's device key, then
//! signed with the rendezvous key). Pure logic for the connection tasks of `rendezvous_server`: no
//! database, no `await`.

use crate::conn_tracker::source_key;
use crate::peer::{LeapgateHb, MAX_PEER_ID_LEN};
use crate::ice_stun;
use hbb_common::{
    bytes::Bytes,
    protobuf::{EnumOrUnknown, Message as _, MessageField},
    rendezvous_proto::*,
};
use sodiumoxide::crypto::{sealedbox, sign};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub(crate) use leapgate_ice_reject::Reason;

/// `LeapgateIce.ver`.
pub const ICE_VER: u32 = 1;
const SESSION_LEN: usize = 16;
/// Domain of the FORWARD signature: unlike every other thing the rendezvous key signs (§2.5).
const OFFER_DOMAIN: &[u8] = b"leapgate-ice-offer-v1\0";
const MAX_CANDIDATES: usize = 16;
const MAX_PROOFS: usize = 16;
/// Global IPv6 candidates without a proof kept per message, as many as upstream's IPv6 punching
/// forwards self-reported (§2.8).
const MAX_UNPROVEN_V6: usize = 2;
const UFRAG_LEN: std::ops::RangeInclusive<usize> = 4..=32;
const PWD_LEN: std::ops::RangeInclusive<usize> = 22..=64;
/// `get_version_number("0.3.1")`: the first `libs/leapgate` with ICE (§2.12).
const ICE_MIN_LEAPGATE_VER: u32 = 3010;
/// Sessions in the table per source (`source_key`), answered ones included (§2.4 step 5).
const ICE_SESSIONS_PER_SOURCE: u8 = 8;
/// FORWARDs per session: the first and one resend (§2.3 ②).
const ICE_OFFER_SENDS: u8 = 2;

/// One candidate (§2.6). `kind` 0 = host, 1 = srflx.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Candidate {
    pub kind: u8,
    pub local_pref: u16,
    pub addr: SocketAddr,
}

/// The whole message is malformed.
#[derive(Debug, PartialEq)]
pub struct Bad;

/// type(1) ‖ local preference(2) ‖ family(1) ‖ address(4|16) ‖ port(2), big-endian: 10 bytes with
/// family 4 or 22 with family 6, type 0/1, a port; anything else is `None`.
pub fn decode(b: &[u8]) -> Option<Candidate> {
    let ip: IpAddr = match (b.len(), b.get(3)) {
        (10, Some(4)) => Ipv4Addr::from(<[u8; 4]>::try_from(&b[4..8]).ok()?).into(),
        (22, Some(6)) => Ipv6Addr::from(<[u8; 16]>::try_from(&b[4..20]).ok()?).into(),
        _ => return None,
    };
    let port = u16::from_be_bytes([b[b.len() - 2], b[b.len() - 1]]);
    if b[0] > 1 || port == 0 {
        return None;
    }
    Some(Candidate {
        kind: b[0],
        local_pref: u16::from_be_bytes([b[1], b[2]]),
        addr: SocketAddr::new(ip, port),
    })
}

pub fn encode(c: &Candidate) -> Vec<u8> {
    let mut b = vec![c.kind];
    b.extend_from_slice(&c.local_pref.to_be_bytes());
    match c.addr.ip() {
        IpAddr::V4(ip) => {
            b.push(4);
            b.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            b.push(6);
            b.extend_from_slice(&ip.octets());
        }
    }
    b.extend_from_slice(&c.addr.port().to_be_bytes());
    b
}

#[derive(PartialEq)]
enum Class {
    Private4,
    Ula,
    Global6,
    Public4,
    Drop,
}

/// The address classes of §2.7. `198.18.0.0/15` and `fdfe:dcba:9876::/48` are the default ranges
/// of mihomo-like TUNs, `100.64.0.0/10` CGNAT's and Tailscale's.
fn class(ip: IpAddr) -> Class {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            match o {
                [10, ..] => Class::Private4,
                [172, b, ..] if b & 0xF0 == 16 => Class::Private4,
                [192, 168, ..] => Class::Private4,
                [0 | 127, ..] | [169, 254, ..] | [198, 18 | 19, ..] => Class::Drop,
                [100, b, ..] if b & 0xC0 == 64 => Class::Drop,
                [a, ..] if a >= 224 => Class::Drop,
                _ => Class::Public4,
            }
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if s[..3] == [0xfdfe, 0xdcba, 0x9876] {
                Class::Drop
            } else if s[0] & 0xFE00 == 0xFC00 {
                Class::Ula
            } else if s[0] & 0xE000 == 0x2000 {
                Class::Global6
            } else {
                Class::Drop
            }
        }
    }
}

/// §2.7: `proofs` is `Some` with the addresses of the proofs that opened (S), `None` without proofs
/// (clients). More than `MAX_CANDIDATES` or one that does not decode is `Bad`; the dropped classes
/// go; with proofs, a public IPv4 needs one and only the first `MAX_UNPROVEN_V6` global IPv6
/// without one stay; of one address only the first stays; the order is kept.
pub fn filter(cands: &[Bytes], proofs: Option<&[SocketAddr]>) -> Result<Vec<Candidate>, Bad> {
    if cands.len() > MAX_CANDIDATES {
        return Err(Bad);
    }
    let decoded = cands.iter().map(|b| decode(b)).collect::<Option<Vec<_>>>().ok_or(Bad)?;
    let mut unproven_v6 = 0;
    let mut out: Vec<Candidate> = Vec::new();
    for c in decoded {
        let keep = match (class(c.addr.ip()), proofs) {
            (Class::Drop, _) => false,
            (Class::Private4 | Class::Ula, _) | (_, None) => true,
            (class, Some(proofs)) => {
                let proven = proofs.contains(&c.addr);
                match class {
                    Class::Public4 => proven,
                    _ if proven => true,
                    _ => {
                        unproven_v6 += 1;
                        unproven_v6 <= MAX_UNPROVEN_V6
                    }
                }
            }
        };
        if keep && !out.iter().any(|o| o.addr == c.addr) {
            out.push(c);
        }
    }
    Ok(out)
}

fn ice_chars(s: &str, len: std::ops::RangeInclusive<usize>) -> bool {
    len.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// One side's parameters as S passes them on (§2.3 ①): ufrag, pwd, at most `MAX_PROOFS` proofs
/// and the candidates filtered with the proofs that open.
fn check_params(p: &LeapgateIceParams, proofs: &[Bytes], now: u64) -> Result<LeapgateIceParams, Bad> {
    if !ice_chars(&p.ufrag, UFRAG_LEN) || !ice_chars(&p.pwd, PWD_LEN) || proofs.len() > MAX_PROOFS {
        return Err(Bad);
    }
    let opened: Vec<SocketAddr> = proofs.iter().filter_map(|p| ice_stun::open(p, now)).collect();
    Ok(LeapgateIceParams {
        ufrag: p.ufrag.clone(),
        pwd: p.pwd.clone(),
        candidates: filter(&p.candidates, Some(&opened))?
            .iter()
            .map(|c| encode(c).into())
            .collect(),
        ..Default::default()
    })
}

/// §2.4 step 1 for an OFFER: the session and A's filtered parameters, or `Bad`. `key` is S's
/// licence key: when set, the OFFER's must equal it (as for punch requests).
pub fn check_offer(
    ver: u32,
    o: &LeapgateIceOffer,
    key: &str,
    now: u64,
) -> Result<([u8; 16], LeapgateIceParams), Bad> {
    let session: [u8; SESSION_LEN] = o.session.as_ref().try_into().map_err(|_| Bad)?;
    if ver != ICE_VER
        || o.id.is_empty()
        || o.id.len() > MAX_PEER_ID_LEN
        // the id goes into the signed message 0x00-separated (§2.5)
        || o.id.as_bytes().contains(&0)
        || (!key.is_empty() && o.licence_key != key)
    {
        return Err(Bad);
    }
    Ok((session, check_params(o.params.get_or_default(), &o.proofs, now)?))
}

/// §2.3 ④ for B's ANSWER: B's filtered parameters, or `Bad`.
pub fn check_answer(ver: u32, a: &LeapgateIceAnswer, now: u64) -> Result<LeapgateIceParams, Bad> {
    if ver != ICE_VER {
        return Err(Bad);
    }
    check_params(a.params.get_or_default(), &a.proofs, now)
}

/// §2.4 step 4 as far as the peer entry tells: a fresh signed heartbeat from a Leapgate with ICE,
/// and a pinned key to encrypt to (an unpinned one may be anybody's who registered B's id first).
pub fn b_supports_ice(pinned: bool, hb: Option<&LeapgateHb>) -> bool {
    pinned
        && hb.is_some_and(|hb| hb.at.elapsed() < crate::peer::LEAPGATE_HB_FRESH && hb.leapgate_ver >= ICE_MIN_LEAPGATE_VER)
}

/// The punch path's forced relay (`ALWAYS_USE_RELAY`, or one side inside the LAN mask and the other
/// not), shared with ICE so the two cannot drift apart (§2.4 step 3).
pub fn forced_relay(always: bool, a_is_lan: bool, b_is_lan: bool) -> bool {
    always || (a_is_lan ^ b_is_lan)
}

/// What the FORWARD signature covers: `OFFER_DOMAIN` ‖ B's id ‖ 0x00 ‖ ts (u64 big-endian) ‖
/// sealed.
fn offer_msg(b_id: &str, ts: u64, sealed: &[u8]) -> Vec<u8> {
    let mut m = OFFER_DOMAIN.to_vec();
    m.extend_from_slice(b_id.as_bytes());
    m.push(0);
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(sealed);
    m
}

/// The FORWARD for B (§2.5): `{session, A's params}` sealed to B's device key converted to X25519,
/// then signed with the rendezvous key. `None` when `b_pk` is no valid Ed25519 point: never sent in
/// the clear.
pub fn forward(
    sk: &sign::SecretKey,
    b_id: &str,
    b_pk: &[u8],
    session: &[u8; 16],
    params: LeapgateIceParams,
    ts: u64,
) -> Option<RendezvousMessage> {
    let x_pk = sign::to_curve25519_pk(&sign::PublicKey::from_slice(b_pk)?).ok()?;
    let inner = LeapgateIceSealed {
        session: Bytes::copy_from_slice(session),
        params: MessageField::some(params),
        ..Default::default()
    }
    .write_to_bytes()
    .ok()?;
    let sealed = sealedbox::seal(&inner, &x_pk);
    let sig = sign::sign_detached(&offer_msg(b_id, ts, &sealed), sk);
    let mut m = LeapgateIce::new();
    m.set_forward(LeapgateIceForward {
        ts,
        sealed: sealed.into(),
        sig: Bytes::copy_from_slice(&sig.to_bytes()),
        ..Default::default()
    });
    Some(wrap(m))
}

fn wrap(mut m: LeapgateIce) -> RendezvousMessage {
    m.ver = ICE_VER;
    let mut msg = RendezvousMessage::new();
    msg.set_leapgate_ice(m);
    msg
}

pub fn reject(session: Bytes, reason: EnumOrUnknown<Reason>) -> RendezvousMessage {
    let mut m = LeapgateIce::new();
    m.set_reject(LeapgateIceReject {
        session,
        reason,
        ..Default::default()
    });
    wrap(m)
}

/// The ANSWER for A: B's filtered parameters and B's `IdPk` signed by S (as `PunchHoleResponse.pk`).
pub fn answer(session: Bytes, params: LeapgateIceParams, pk: Bytes) -> RendezvousMessage {
    let mut m = LeapgateIce::new();
    m.set_answer(LeapgateIceAnswer {
        session,
        params: MessageField::some(params),
        pk,
        ..Default::default()
    });
    wrap(m)
}

// The names of §2.13, shared by the logs and the `ice_result` table (§3.7).

/// `ice_result.outcome` of a session registered and not refused whose connection ended without a
/// RESULT: cancelled by the race, or A went away. Not a RESULT value.
pub const ABANDONED: &str = "abandoned";

/// `unknown` comes only from a sender off the protocol (the zero value, or a number not in the enum).
pub fn outcome_name(o: EnumOrUnknown<leapgate_ice_result::Outcome>) -> &'static str {
    use leapgate_ice_result::Outcome;
    match o.enum_value() {
        Ok(Outcome::CONNECTED) => "connected",
        Ok(Outcome::NO_ANSWER) => "no_answer",
        Ok(Outcome::BAD_ANSWER) => "bad_answer",
        Ok(Outcome::NO_PAIR) => "no_pair",
        Ok(Outcome::KCP_FAILED) => "kcp_failed",
        Ok(Outcome::SECURE_FAILED) => "secure_failed",
        Ok(Outcome::UNKNOWN) | Err(_) => "unknown",
    }
}

/// `None` for a number not in the enum.
pub fn kind_name(k: EnumOrUnknown<leapgate_ice_result::Kind>) -> Option<&'static str> {
    use leapgate_ice_result::Kind;
    Some(match k.enum_value().ok()? {
        Kind::HOST => "host",
        Kind::SRFLX => "srflx",
        Kind::PRFLX => "prflx",
    })
}

/// `None` for a number not in the enum.
pub fn net_name(n: EnumOrUnknown<leapgate_ice_result::Net>) -> Option<&'static str> {
    use leapgate_ice_result::Net;
    Some(match n.enum_value().ok()? {
        Net::ETHERNET => "ethernet",
        Net::WLAN => "wlan",
        Net::OTHER => "other",
    })
}

struct Entry<S> {
    /// A's sink; taken to send the answer or a reject.
    sink: Option<S>,
    /// Sent again as it is on a resend.
    forward: RendezvousMessage,
    /// The OFFER's B: where a resend goes, whose pk the answer carries.
    b_id: String,
    /// The address of A's signaling connection, normalized.
    a_ip: IpAddr,
    sends: u8,
    answered: bool,
    /// A reported a RESULT (only the first counts).
    result: bool,
}

/// The sessions of A's signaling connections (§2.3, §3.3.2), generic over the sink so it can be
/// tested on its own. One per connection at most, removed when the connection ends: no expiry and
/// no overall cap (21116's connection limit is one).
pub struct Sessions<S> {
    map: HashMap<[u8; 16], Entry<S>>,
    per_source: HashMap<IpAddr, u8>,
}

pub enum Refused {
    /// → `REJECT{BAD}`
    Duplicate,
    /// → `REJECT{BUSY}`
    Busy,
}

impl<S> Sessions<S> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            per_source: HashMap::new(),
        }
    }

    /// Registers a session for A at `a_ip` (`try_into_v4` of the connection's address, as
    /// `conn_attempt` has it): refused when it is in the table already or A's source (`source_key`
    /// of the address, a `::ffff:a.b.c.d` normalized here too: a dual-stack 21116 gives every IPv4
    /// client one) holds `ICE_SESSIONS_PER_SOURCE`. Takes `sink` on success only: on a refusal the
    /// caller still has it to reject with.
    pub fn register(
        &mut self,
        session: [u8; 16],
        sink: &mut Option<S>,
        forward: RendezvousMessage,
        b_id: String,
        a_ip: IpAddr,
    ) -> Result<(), Refused> {
        if self.map.contains_key(&session) {
            return Err(Refused::Duplicate);
        }
        let a_ip = a_ip.to_canonical();
        let n = self.per_source.entry(source_key(a_ip)).or_default();
        if *n >= ICE_SESSIONS_PER_SOURCE {
            return Err(Refused::Busy);
        }
        *n += 1;
        self.map.insert(
            session,
            Entry {
                sink: sink.take(),
                forward,
                b_id,
                a_ip,
                sends: 1,
                answered: false,
                result: false,
            },
        );
        Ok(())
    }

    /// The cached FORWARD again, with the registered B's id, while unanswered and under
    /// `ICE_OFFER_SENDS`.
    pub fn resend(&mut self, session: &[u8; 16]) -> Option<(RendezvousMessage, String)> {
        let e = self.map.get_mut(session).filter(|e| !e.answered && e.sends < ICE_OFFER_SENDS)?;
        e.sends += 1;
        Some((e.forward.clone(), e.b_id.clone()))
    }

    /// The registered B's id while unanswered.
    pub fn peek_unanswered(&self, session: &[u8; 16]) -> Option<String> {
        self.map.get(session).filter(|e| !e.answered).map(|e| e.b_id.clone())
    }

    /// A's sink for the answer, once: the entry stays, answered, until A's connection ends.
    pub fn take_sink_for_answer(&mut self, session: &[u8; 16]) -> Option<S> {
        let e = self.map.get_mut(session).filter(|e| !e.answered)?;
        e.answered = true;
        e.sink.take()
    }

    /// Removes an unanswered session (B's reject, a malformed answer, no pk for B) and gives A's
    /// sink to reject with. Not counted as abandoned later.
    pub fn drop_for_reject(&mut self, session: &[u8; 16]) -> Option<S> {
        if !self.map.get(session)?.answered {
            self.remove(session).and_then(|e| e.sink)
        } else {
            None
        }
    }

    /// The first RESULT for a session: A's address and B's id.
    pub fn mark_result(&mut self, session: &[u8; 16]) -> Option<(IpAddr, String)> {
        let e = self.map.get_mut(session).filter(|e| !e.result)?;
        e.result = true;
        Some((e.a_ip, e.b_id.clone()))
    }

    /// A's connection ended: removes its session, if still there, giving A's address, B's id and
    /// whether no RESULT came (an abandoned one).
    pub fn close(&mut self, session: &[u8; 16]) -> Option<(IpAddr, String, bool)> {
        self.remove(session).map(|e| (e.a_ip, e.b_id, !e.result))
    }

    fn remove(&mut self, session: &[u8; 16]) -> Option<Entry<S>> {
        let e = self.map.remove(session)?;
        let key = source_key(e.a_ip);
        if let Some(n) = self.per_source.get_mut(&key) {
            *n -= 1;
            if *n == 0 {
                self.per_source.remove(&key);
            }
        }
        Some(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unhex;
    use std::time::{Duration, Instant};

    // The vectors the client's tests share (contract 05 §2.5, §2.6), byte for byte.
    const C1: &str = "00ffff04c0a8010ac350";
    const C2: &str = "0112340620010db80000000000000000000000010d96";
    const DEVICE_PK: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const SERVER_PK: &str = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
    const DEVICE_X25519_PK: &str = "761d88ec830413919dfe9d4d1d56f17e653c8c994082df5b137b90a0ae6edf74";
    const INNER: &str = "0a10000102030405060708090a0b0c0d0e0f12300a08414141414141414112186161616161616161616161616161616161616161616161611a0a00ffff04c0a8010ac350";
    const SEALED: &str = "1efed8033c4fda7f2ea111068b846a64b9a565c0b24066caad74b4732359b22f1d7cc65bd678b90b11713c25a1acd7fa6e9538b2a54243c19945b13903847822b07aa74c37ac203c5ce2895a753a382fca93611ac14f51be9c6419edb6e4f385ad937c842331da56c74127100cf8ecf84dd61e5e";
    const MSG_HEAD: &str = "6c656170676174652d6963652d6f666665722d763100313233343536373839000000000068f9c780";
    const SIG: &str = "af0420c4ff56072b64aa67109baad18b6559c124895c2fc2fffab0f1eea75fde2652d4c0039a4be24ded171ae09174005b34e41415374da44704cd9f746fd90b";
    const TS: u64 = 1761200000;

    fn keys(seed: u8) -> (sign::PublicKey, sign::SecretKey) {
        sign::keypair_from_seed(&sign::Seed([seed; 32]))
    }

    fn cand(kind: u8, pref: u16, addr: &str) -> Candidate {
        Candidate {
            kind,
            local_pref: pref,
            addr: addr.parse().unwrap(),
        }
    }

    fn wire(cs: &[Candidate]) -> Vec<Bytes> {
        cs.iter().map(|c| encode(c).into()).collect()
    }

    #[test]
    fn candidate_vectors_round_trip() {
        for (hex, c) in [(C1, cand(0, 0xFFFF, "192.168.1.10:50000")), (C2, cand(1, 0x1234, "[2001:db8::1]:3478"))] {
            assert_eq!(encode(&c), unhex(hex));
            assert_eq!(decode(&unhex(hex)), Some(c));
        }
    }

    #[test]
    fn malformed_candidates_are_bad() {
        let c1 = unhex(C1);
        let c2 = unhex(C2);
        let mut bad = Vec::new();
        bad.push(c1[..9].to_vec()); // short
        bad.push([&c1[..], &[0]].concat()); // long
        let mut x = c1.clone();
        x[3] = 6; // family 6 in 10 bytes
        bad.push(x);
        let mut x = c2.clone();
        x[3] = 4; // family 4 in 22 bytes
        bad.push(x);
        let mut x = c1.clone();
        x[0] = 2; // no such type
        bad.push(x);
        let mut x = c1.clone();
        x[8..].copy_from_slice(&[0, 0]); // port 0
        bad.push(x);
        bad.push(Vec::new());
        for b in bad {
            assert_eq!(decode(&b), None, "{b:02x?}");
            assert_eq!(filter(&[c1.clone().into(), b.clone().into()], None), Err(Bad), "{b:02x?}");
        }
        let seventeen = vec![Bytes::from(c1.clone()); MAX_CANDIDATES + 1];
        assert_eq!(filter(&seventeen, None), Err(Bad));
        assert_eq!(filter(&seventeen[1..], None).unwrap().len(), 1);
    }

    #[test]
    fn filter_with_proofs() {
        let public4 = cand(1, 1, "203.0.113.7:40000");
        let other4 = cand(1, 2, "203.0.113.8:40000");
        let v6 = |i: u16| cand(0, i, &format!("[2001:db8::{i:x}]:40000"));
        let kept = [
            cand(0, 1, "10.1.2.3:1"),
            cand(0, 2, "172.16.0.1:1"),
            cand(0, 3, "172.31.255.1:1"),
            cand(0, 4, "192.168.1.10:50000"),
            cand(0, 5, "[fd00::1]:1"),
            cand(0, 6, "[fc00::1]:1"),
        ];
        let dropped = [
            cand(0, 1, "0.1.2.3:1"),
            cand(0, 1, "127.0.0.1:1"),
            cand(0, 1, "169.254.1.1:1"),
            cand(0, 1, "100.64.0.1:1"),
            cand(0, 1, "100.127.255.1:1"),
            cand(0, 1, "198.18.0.1:1"),
            cand(0, 1, "198.19.255.1:1"),
            cand(0, 1, "224.0.0.1:1"),
            cand(0, 1, "255.255.255.255:1"),
            cand(0, 1, "[fdfe:dcba:9876::1]:1"),
            cand(0, 1, "[::1]:1"),
            cand(0, 1, "[fe80::1]:1"),
            cand(0, 1, "[ff02::1]:1"),
            cand(0, 1, "[::ffff:192.168.1.1]:1"),
            cand(0, 1, "[4000::1]:1"),
        ];
        // Neighbours of the ranges are not in them.
        for c in [cand(0, 1, "172.15.0.1:1"), cand(0, 1, "172.32.0.1:1"), cand(0, 1, "100.128.0.1:1"), cand(0, 1, "198.20.0.1:1")] {
            assert_eq!(filter(&wire(&[c]), Some(&[][..])).unwrap(), Vec::new(), "{:?}: public, no proof", c.addr);
            assert_eq!(filter(&wire(&[c]), Some(&[c.addr][..])).unwrap(), [c]);
        }

        // At most 16 to a message: the dropped classes on their own.
        assert_eq!(filter(&wire(&dropped), Some(&[][..])).unwrap(), Vec::new());
        assert_eq!(filter(&wire(&dropped), None).unwrap(), Vec::new());
        let mut sent: Vec<Candidate> = vec![dropped[5], dropped[9]];
        sent.extend(kept);
        sent.extend([public4, other4, v6(1), v6(2), v6(3), v6(4)]);
        // Proved: public4 and the third IPv6, which then does not count against the unproven two.
        let proofs = [public4.addr, v6(3).addr];
        let out = filter(&wire(&sent), Some(&proofs[..])).unwrap();
        let mut expected = kept.to_vec();
        expected.extend([public4, v6(1), v6(2), v6(3)]);
        assert_eq!(out, expected);

        // Without proofs (clients): only the dropped classes go.
        let mut expected = kept.to_vec();
        expected.extend([public4, other4, v6(1), v6(2), v6(3), v6(4)]);
        assert_eq!(filter(&wire(&sent), None).unwrap(), expected);

        // One address: the first only, whatever the type.
        let dup = [cand(0, 9, "192.168.1.10:50000"), cand(1, 8, "192.168.1.10:50000"), cand(0, 7, "192.168.1.10:50001")];
        assert_eq!(filter(&wire(&dup), Some(&[][..])).unwrap(), [dup[0], dup[2]]);
    }

    fn offer(session: Vec<u8>, cands: Vec<Bytes>) -> LeapgateIceOffer {
        LeapgateIceOffer {
            session: session.into(),
            id: "123456789".to_owned(),
            licence_key: "k".to_owned(),
            params: MessageField::some(LeapgateIceParams {
                ufrag: "AAAAAAAA".to_owned(),
                pwd: "a".repeat(24),
                candidates: cands,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn offer_checks() {
        let now = crate::common::now();
        let ok = offer(vec![1; 16], vec![unhex(C1).into()]);
        let (session, params) = check_offer(1, &ok, "k", now).unwrap();
        assert_eq!((session, &params.candidates[..]), ([1; 16], &[Bytes::from(unhex(C1))][..]));
        assert!(check_offer(1, &ok, "", now).is_ok());
        let bad = |f: &dyn Fn(&mut LeapgateIceOffer)| {
            let mut o = ok.clone();
            f(&mut o);
            check_offer(1, &o, "k", now).map(|_| ())
        };
        assert_eq!(check_offer(2, &ok, "k", now).map(|_| ()), Err(Bad), "ver");
        assert_eq!(check_offer(1, &ok, "other", now).map(|_| ()), Err(Bad), "key");
        assert_eq!(bad(&|o| o.session = vec![1; 15].into()), Err(Bad));
        assert_eq!(bad(&|o| o.session = vec![1; 17].into()), Err(Bad));
        assert_eq!(bad(&|o| o.id.clear()), Err(Bad));
        assert_eq!(bad(&|o| o.id = "1".repeat(MAX_PEER_ID_LEN + 1)), Err(Bad));
        assert_eq!(bad(&|o| o.id = "1".repeat(MAX_PEER_ID_LEN)), Ok(()));
        assert_eq!(bad(&|o| o.id = "12\0".to_owned()), Err(Bad));
        assert_eq!(bad(&|o| o.params.clear()), Err(Bad));
        assert_eq!(bad(&|o| o.params.mut_or_insert_default().ufrag = "AAA".to_owned()), Err(Bad));
        assert_eq!(bad(&|o| o.params.mut_or_insert_default().ufrag = "A".repeat(32)), Ok(()));
        assert_eq!(bad(&|o| o.params.mut_or_insert_default().ufrag = "A".repeat(33)), Err(Bad));
        assert_eq!(bad(&|o| o.params.mut_or_insert_default().ufrag = "AAAA-AAA".to_owned()), Err(Bad));
        assert_eq!(bad(&|o| o.params.mut_or_insert_default().pwd = "a+/9".repeat(5) + "a"), Err(Bad));
        assert_eq!(bad(&|o| o.params.mut_or_insert_default().pwd = "a+/9".repeat(5) + "aa"), Ok(()));
        assert_eq!(bad(&|o| o.params.mut_or_insert_default().pwd = "a".repeat(65)), Err(Bad));
        assert_eq!(bad(&|o| o.params.mut_or_insert_default().candidates = vec![unhex(C1).into(); 17]), Err(Bad));
        assert_eq!(bad(&|o| o.proofs = vec![Bytes::new(); MAX_PROOFS]), Ok(()));
        assert_eq!(bad(&|o| o.proofs = vec![Bytes::new(); MAX_PROOFS + 1]), Err(Bad));
    }

    /// A public IPv4 candidate stays with a proof S issued for it, not with one for another
    /// address or none.
    #[test]
    fn offer_proofs_open_with_the_process_key() {
        let now = crate::common::now();
        let a: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let mut o = offer(vec![1; 16], wire(&[cand(1, 1, "203.0.113.7:40000")]));
        assert!(check_offer(1, &o, "k", now).unwrap().1.candidates.is_empty());
        o.proofs = vec![ice_stun::seal("203.0.113.8:40000".parse().unwrap(), now).into()];
        assert!(check_offer(1, &o, "k", now).unwrap().1.candidates.is_empty());
        o.proofs.push(ice_stun::seal(a, now).into());
        assert_eq!(check_offer(1, &o, "k", now).unwrap().1.candidates.len(), 1);
    }

    #[test]
    fn forward_vectors() {
        let (dev_pk, dev_sk) = keys(7);
        let (srv_pk, srv_sk) = keys(9);
        assert_eq!(dev_pk.0[..], unhex(DEVICE_PK)[..]);
        assert_eq!(srv_pk.0[..], unhex(SERVER_PK)[..]);
        let x_pk = sign::to_curve25519_pk(&dev_pk).unwrap();
        assert_eq!(x_pk.0[..], unhex(DEVICE_X25519_PK)[..]);
        let x_sk = sign::to_curve25519_sk(&dev_sk).unwrap();

        // The inner plaintext as S serializes it.
        let session: [u8; 16] = std::array::from_fn(|i| i as u8);
        let inner = LeapgateIceSealed {
            session: Bytes::copy_from_slice(&session),
            params: MessageField::some(LeapgateIceParams {
                ufrag: "AAAAAAAA".to_owned(),
                pwd: "a".repeat(24),
                candidates: vec![unhex(C1).into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(inner.write_to_bytes().unwrap(), unhex(INNER));
        // The fixed sealed box opens with the device key; the signature over it is S's, byte for
        // byte.
        let sealed = unhex(SEALED);
        assert_eq!(sealedbox::open(&sealed, &x_pk, &x_sk).unwrap(), unhex(INNER));
        let msg = offer_msg("123456789", TS, &sealed);
        assert_eq!((msg.len(), &msg[..40]), (156, &unhex(MSG_HEAD)[..]));
        assert_eq!(sign::sign_detached(&msg, &srv_sk).to_bytes()[..], unhex(SIG)[..]);
        // Not an `IdPk`, whatever is signed after the domain (§2.5).
        assert!(IdPk::parse_from_bytes(&msg).is_err());

        // A fresh FORWARD: verified with S's key over B's id, opened with B's.
        let fwd = forward(&srv_sk, "123456789", &dev_pk.0, &session, inner.params.unwrap(), TS).unwrap();
        let Some(rendezvous_message::Union::LeapgateIce(m)) = fwd.union else { panic!() };
        assert_eq!(m.ver, 1);
        let Some(leapgate_ice::Union::Forward(f)) = m.union else { panic!() };
        assert_eq!((f.ts, f.sealed.len()), (TS, unhex(INNER).len() + 48));
        let sig = sign::Signature::from_bytes(&f.sig).unwrap();
        assert!(sign::verify_detached(&sig, &offer_msg("123456789", TS, &f.sealed), &srv_pk));
        assert!(!sign::verify_detached(&sig, &offer_msg("123456788", TS, &f.sealed), &srv_pk));
        assert_eq!(sealedbox::open(&f.sealed, &x_pk, &x_sk).unwrap(), unhex(INNER));
    }

    /// A key that is no valid point is never encrypted to (§2.5): the small-order identity point,
    /// and a wrong length.
    #[test]
    fn forward_refuses_invalid_device_keys() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(sign::to_curve25519_pk(&sign::PublicKey(identity)).is_err());
        let (_, sk) = keys(9);
        for pk in [&identity[..], &[7u8; 31][..], &[][..]] {
            assert!(forward(&sk, "B", pk, &[0; 16], Default::default(), TS).is_none());
        }
    }

    #[test]
    fn forced_relay_is_the_punch_rule() {
        for always in [false, true] {
            for a in [false, true] {
                for b in [false, true] {
                    assert_eq!(forced_relay(always, a, b), always || a != b);
                }
            }
        }
    }

    #[test]
    fn heartbeat_freshness_version_and_pin() {
        let hb = |age: u64, ver: u32| LeapgateHb {
            at: Instant::now().checked_sub(Duration::from_secs(age)).unwrap(),
            leapgate_ver: ver,
            exit: false,
        };
        assert!(b_supports_ice(true, Some(&hb(0, ICE_MIN_LEAPGATE_VER))));
        assert!(b_supports_ice(true, Some(&hb(170, 4000))));
        assert!(!b_supports_ice(false, Some(&hb(0, ICE_MIN_LEAPGATE_VER))));
        assert!(!b_supports_ice(true, Some(&hb(181, ICE_MIN_LEAPGATE_VER))));
        assert!(!b_supports_ice(true, Some(&hb(0, ICE_MIN_LEAPGATE_VER - 1))));
        assert!(!b_supports_ice(true, None));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn sessions_per_source_and_duplicates() {
        let mut t: Sessions<u32> = Sessions::new();
        let fwd = RendezvousMessage::new;
        for i in 0..ICE_SESSIONS_PER_SOURCE {
            let mut sink = Some(i as u32);
            assert!(t.register([i; 16], &mut sink, fwd(), "B".into(), ip("::ffff:203.0.113.1")).is_ok());
            assert_eq!(sink, None, "taken");
        }
        let mut sink = Some(99);
        assert!(matches!(t.register([100; 16], &mut sink, fwd(), "B".into(), ip("203.0.113.1")), Err(Refused::Busy)));
        assert_eq!(sink, Some(99), "left with the caller");
        // Another IPv4 source, mapped or not, has its own; an IPv6 /64 is one source.
        assert!(t.register([101; 16], &mut sink, fwd(), "B".into(), ip("::ffff:203.0.113.2")).is_ok());
        for i in 0..ICE_SESSIONS_PER_SOURCE {
            let mut sink = Some(0);
            let a = ip(&format!("2001:db8::{}", i + 1));
            assert!(t.register([110 + i; 16], &mut sink, fwd(), "B".into(), a).is_ok());
        }
        let mut sink = Some(0);
        assert!(matches!(t.register([120; 16], &mut sink, fwd(), "B".into(), ip("2001:db8::ffff")), Err(Refused::Busy)));
        assert!(t.register([120; 16], &mut sink, fwd(), "B".into(), ip("2001:db8:0:1::1")).is_ok());

        // The same session again: refused, the first one untouched.
        let mut sink = Some(7);
        assert!(matches!(t.register([101; 16], &mut sink, fwd(), "C".into(), ip("198.51.100.1")), Err(Refused::Duplicate)));
        assert_eq!(sink, Some(7));
        assert_eq!(t.peek_unanswered(&[101; 16]).as_deref(), Some("B"));
        assert_eq!(t.take_sink_for_answer(&[101; 16]), Some(99));
        assert_eq!(t.per_source.get(&ip("198.51.100.1")), None);
    }

    #[test]
    fn sessions_lifecycle() {
        let mut t: Sessions<u32> = Sessions::new();
        let a = ip("::ffff:203.0.113.1");
        let mut fwd = RendezvousMessage::new();
        fwd.set_leapgate_ice(LeapgateIce { ver: 1, ..Default::default() });
        for s in 1..=3u8 {
            assert!(t.register([s; 16], &mut Some(s as u32), fwd.clone(), format!("B{s}"), a).is_ok());
        }
        let count = |t: &Sessions<u32>| t.per_source.get(&ip("203.0.113.1")).copied().unwrap_or(0);
        assert_eq!(count(&t), 3);

        // One resend, of the cached FORWARD, with the registered B.
        assert_eq!(t.resend(&[1; 16]), Some((fwd.clone(), "B1".to_owned())));
        assert_eq!(t.resend(&[1; 16]), None);
        assert_eq!(t.resend(&[9; 16]), None);

        // Answered: nothing more for it but RESULT and close; the sink went once.
        assert_eq!(t.take_sink_for_answer(&[1; 16]), Some(1));
        assert_eq!(t.peek_unanswered(&[1; 16]), None);
        assert_eq!(t.take_sink_for_answer(&[1; 16]), None);
        assert_eq!(t.drop_for_reject(&[1; 16]), None);
        assert_eq!(t.resend(&[2; 16]), Some((fwd, "B2".to_owned())));
        assert_eq!(count(&t), 3, "answered entries count");

        // RESULT: the first only; closed after it, not abandoned.
        assert_eq!(t.mark_result(&[1; 16]), Some((ip("203.0.113.1"), "B1".to_owned())));
        assert_eq!(t.mark_result(&[1; 16]), None);
        assert_eq!(t.close(&[1; 16]), Some((ip("203.0.113.1"), "B1".to_owned(), false)));
        // Closed without one: abandoned.
        assert_eq!(t.close(&[2; 16]), Some((ip("203.0.113.1"), "B2".to_owned(), true)));
        // Rejected: removed, the sink given back; closing it later finds nothing.
        assert_eq!(t.drop_for_reject(&[3; 16]), Some(3));
        assert_eq!(t.close(&[3; 16]), None);
        assert_eq!(t.close(&[1; 16]), None);
        assert_eq!(count(&t), 0);
        assert!(t.per_source.is_empty() && t.map.is_empty());
    }

    /// §2.3 ②: an answered session is not sent again, with a send still left.
    #[test]
    fn resend_refused_once_answered() {
        let mut t: Sessions<u32> = Sessions::new();
        let mut fwd = RendezvousMessage::new();
        fwd.set_leapgate_ice(LeapgateIce { ver: 1, ..Default::default() });
        assert!(t.register([7; 16], &mut Some(7), fwd, "B7".to_owned(), ip("203.0.113.9")).is_ok());
        assert_eq!(t.take_sink_for_answer(&[7; 16]), Some(7));
        assert_eq!(t.resend(&[7; 16]), None);
    }
}
