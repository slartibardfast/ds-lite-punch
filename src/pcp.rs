//! PCP (RFC 6887) and NAT-PMP (RFC 6886) on their shared port.
//!
//! The fourth admission path (call/0025): a LAN-only listener on UDP 5351
//! carrying both protocols, as the design's own implementation notes specify
//! (plan/0004 section 7). Only the codec lives here; the admission itself
//! rides the same slot engine as the UPnP facade and the observation arm, so
//! a mapping created in this dialect is indistinguishable from one created by
//! `AddPortMapping` except in the wire format it is described with.
//!
//! Two things in this file are transcribed from the RFCs and are worth the
//! reader's attention because both were checked against the source text rather
//! than recalled:
//!
//! * The result codes. The implementation notes carried a compressed sketch
//!   ("0 to 8, plus CANNOT_PROVIDE_EXTERNAL_PORT = 9") and told the
//!   implementer to verify the numerics. RFC 6887 section 7.4 numbers them
//!   0..13, with `NO_RESOURCES` at 8 and `UNSUPP_PROTOCOL` at 9, so the
//!   sketch's ninth entry is `UNSUPP_PROTOCOL` and the external-port refusal
//!   is 11. The RFC's numbering is what ships; the milestone's results record
//!   notes the divergence.
//! * The divergence channel. The notes said a learned tuple "follows in an
//!   ANNOUNCE". An ANNOUNCE response has no opcode-specific payload at all
//!   (RFC 6887 section 14.1.1), so it cannot carry a tuple. The place the
//!   truth goes is the MAP response's assigned external port and address,
//!   which is what this codec builds; a mapping whose discovery is still in
//!   flight is dropped, and the client's own retransmission (the protocol's
//!   only recovery mechanism) brings it back once the tuple is known.
//!
//! The client's identity comes from the datagram's source address, compared
//! with the header's client field (section 8.2: a mismatch is
//! `ADDRESS_MISMATCH`). A request is only ever served on the LAN side; the
//! listener binds the LAN address and never the wildcard.

use crate::slot::UpsertOutcome;
use std::net::Ipv4Addr;

/// The one port both protocols share (RFC 6887 section 6).
pub const PORT: u16 = 5351;
/// PCP version this server speaks.
pub const VERSION: u8 = 2;
/// The longest mapping lifetime this server grants, in seconds. It bounds how
/// stale a client's idea of its own tuple can be after a re-key: the client's
/// refresh is what reports the new one.
pub const MAX_LIFETIME: u32 = 600;
/// NAT-PMP has no lifetime negotiation beyond the client's request, and the
/// specification recommends this figure; the mapping's own lease is what
/// actually expires it.
pub const NPMP_LIFETIME: u32 = 7200;
/// RFC 6887 section 8.2: a request longer than this is malformed.
pub const MAX_MSG: usize = 1100;
/// The shortest legal PCP request is the common header alone.
pub const HEADER: usize = 24;
/// MAP and PEER opcode-specific data, request side.
pub const OPCODE_DATA: usize = 36;

pub const OP_ANNOUNCE: u8 = 0;
pub const OP_MAP: u8 = 1;
pub const OP_PEER: u8 = 2;

/// RFC 6887 section 7.4, verbatim numbering.
pub mod rc {
    pub const SUCCESS: u8 = 0;
    pub const UNSUPP_VERSION: u8 = 1;
    pub const NOT_AUTHORIZED: u8 = 2;
    pub const MALFORMED_REQUEST: u8 = 3;
    pub const UNSUPP_OPCODE: u8 = 4;
    pub const UNSUPP_OPTION: u8 = 5;
    pub const MALFORMED_OPTION: u8 = 6;
    pub const NETWORK_FAILURE: u8 = 7;
    pub const NO_RESOURCES: u8 = 8;
    pub const UNSUPP_PROTOCOL: u8 = 9;
    pub const USER_EX_QUOTA: u8 = 10;
    pub const CANNOT_PROVIDE_EXTERNAL: u8 = 11;
    pub const ADDRESS_MISMATCH: u8 = 12;
    pub const EXCESSIVE_REMOTE_PEERS: u8 = 13;
}

/// RFC 6886 section 3.5.
pub mod np {
    pub const SUCCESS: u8 = 0;
    pub const UNSUPP_VERSION: u8 = 1;
    pub const NOT_AUTHORIZED: u8 = 2;
    pub const NETWORK_FAILURE: u8 = 3;
    pub const NO_RESOURCES: u8 = 4;
    pub const UNSUPP_OPCODE: u8 = 5;

    /// NAT-PMP opcodes: a public-address request, and the two mapping forms.
    pub const OP_PUBLIC: u8 = 0;
    pub const OP_MAP_UDP: u8 = 1;
    pub const OP_MAP_TCP: u8 = 2;
    /// Responses carry the request's opcode with this bit set.
    pub const RESP: u8 = 0x80;
}

/// What the admission path answers a MAP with, or the reason it answers
/// nothing yet.
pub enum MapAnswer {
    /// Drop the datagram: discovery for this mapping has not completed. The
    /// client's own retransmission is the recovery the protocol provides.
    Drop,
    /// Answer with this result code, lifetime and assigned tuple.
    Answer {
        code: u8,
        lifetime: u32,
        ext_port: u16,
        ext_ip: Ipv4Addr,
    },
}

/// The option codes this server reads (RFC 6887 section 13).
pub const OPT_THIRD_PARTY: u8 = 1;
pub const OPT_PREFER_FAILURE: u8 = 2;
pub const OPT_FILTER: u8 = 3;
/// Option lengths, in octets, excluding padding.
pub const OPT_THIRD_PARTY_LEN: u16 = 16;
pub const OPT_FILTER_LEN: u16 = 20;

/// Read the IPv4 address a field carries. RFC 6887 section 5 puts an IPv4
/// address in the IPv4-mapped IPv6 form; a field that is not that form reads
/// as the unspecified address, which the caller's comparison then refuses.
fn unmapped(a: &[u8]) -> Ipv4Addr {
    if a.len() < 16 || a[10] != 0xff || a[11] != 0xff || a[..10].iter().any(|b| *b != 0) {
        return Ipv4Addr::UNSPECIFIED;
    }
    Ipv4Addr::new(a[12], a[13], a[14], a[15])
}

/// The mapped form this server answers with.
fn mapped(ip: Ipv4Addr) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[10] = 0xff;
    a[11] = 0xff;
    a[12..16].copy_from_slice(&ip.octets());
    a
}

/// A response's common header (RFC 6887 section 7.2): twenty-four octets,
/// the R bit set, the reserved fields zero.
fn resp_header(opcode: u8, code: u8, lifetime: u32, epoch: u32) -> Vec<u8> {
    let mut b = vec![VERSION, opcode | 0x80, 0, code];
    b.extend_from_slice(&lifetime.to_be_bytes());
    b.extend_from_slice(&epoch.to_be_bytes());
    b.extend_from_slice(&[0u8; 12]);
    b
}

/// One MAP or PEER response body: the request's nonce, protocol and internal
/// port come back, and the assigned external port and address are ours.
fn resp_body(nonce: &[u8; 12], proto: u8, int_port: u16, ext_port: u16, ext_ip: Ipv4Addr) -> Vec<u8> {
    let mut b = nonce.to_vec();
    b.push(proto);
    b.extend_from_slice(&[0u8; 3]);
    b.extend_from_slice(&int_port.to_be_bytes());
    b.extend_from_slice(&ext_port.to_be_bytes());
    b.extend_from_slice(&mapped(ext_ip));
    b
}

/// Walk the options that follow the opcode data. `map` is the request being
/// built; options that belong to another opcode are ignored, and an unknown
/// option refuses the request only when it is marked mandatory (the option
/// code's top bit clear).
fn read_options(buf: &[u8], from: usize, map: &mut MapReq) -> Result<(), Refusal> {
    let mut i = from;
    while i + 4 <= buf.len() {
        let code = buf[i];
        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let vstart = i + 4;
        let vend = vstart + len;
        if vend > buf.len() {
            return Err(Refusal::Code {
                opcode: OP_MAP,
                code: rc::MALFORMED_OPTION,
            });
        }
        let val = &buf[vstart..vend];
        match code & 0x7f {
            OPT_THIRD_PARTY if len as u16 == OPT_THIRD_PARTY_LEN => {
                map.third_party = Some(unmapped(val));
            }
            OPT_PREFER_FAILURE if len == 0 => map.prefer_failure = true,
            OPT_FILTER if len as u16 == OPT_FILTER_LEN => {
                if val[1] == 0 {
                    // a zero prefix length is "no filter", and removes the
                    // ones already asked for (RFC 6887 section 13.3)
                    map.filters.clear();
                } else {
                    map.filters.push(Filter {
                        prefix_len: val[1],
                        peer_port: u16::from_be_bytes([val[2], val[3]]),
                        peer_ip: unmapped(&val[4..20]),
                    });
                }
            }
            OPT_THIRD_PARTY | OPT_PREFER_FAILURE | OPT_FILTER => {
                return Err(Refusal::Code {
                    opcode: OP_MAP,
                    code: rc::MALFORMED_OPTION,
                });
            }
            _ if code & 0x80 == 0 => {
                return Err(Refusal::Code {
                    opcode: OP_MAP,
                    code: rc::UNSUPP_OPTION,
                });
            }
            _ => {}
        }
        i = vstart + ((len + 3) & !3);
    }
    if i != buf.len() {
        return Err(Refusal::Code {
            opcode: OP_MAP,
            code: rc::MALFORMED_REQUEST,
        });
    }
    Ok(())
}

/// A refused request: either silence, or an error response with this result
/// code and the request's opcode echoed (RFC 6887 section 8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Drop the datagram without answering.
    Silent,
    /// Answer with an error response.
    Code { opcode: u8, code: u8 },
}

/// One filter a MAP request asked for (RFC 6887 section 13.3). A prefix
/// length of zero means "no filter" and clears the ones already asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Filter {
    pub prefix_len: u8,
    pub peer_port: u16,
    pub peer_ip: Ipv4Addr,
}

/// A MAP request, reduced to what admission needs.
#[derive(Clone, Debug, PartialEq)]
pub struct MapReq {
    pub lifetime: u32,
    pub nonce: [u8; 12],
    pub proto: u8,
    pub int_port: u16,
    pub sug_ext_port: u16,
    pub sug_ext_ip: Ipv4Addr,
    pub prefer_failure: bool,
    pub third_party: Option<Ipv4Addr>,
    pub filters: Vec<Filter>,
}

/// A PEER request (RFC 6887 section 12). Addressed, never filtered: this
/// server's filtering is endpoint-independent, so a peer request's only
/// meaning here is "confirm the mapping that already carries this flow".
#[derive(Clone, Debug, PartialEq)]
pub struct PeerReq {
    pub lifetime: u32,
    pub nonce: [u8; 12],
    pub proto: u8,
    pub int_port: u16,
    pub peer_port: u16,
    pub peer_ip: Ipv4Addr,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Req {
    Announce,
    Map(MapReq),
    Peer(PeerReq),
}

/// Parse one PCP request. `src` is the source address of the datagram that
/// carried it, which section 8.2 compares against the header's client field.
pub fn parse_pcp(buf: &[u8], src: Ipv4Addr) -> Result<Req, Refusal> {
    if buf.len() < 2 {
        return Err(Refusal::Silent);
    }
    let version = buf[0];
    let opcode = buf[1] & 0x7f;
    if buf[1] & 0x80 != 0 {
        // a response arriving at the server: silence, never a reply loop
        return Err(Refusal::Silent);
    }
    if version != VERSION {
        return Err(Refusal::Code {
            opcode,
            code: rc::UNSUPP_VERSION,
        });
    }
    if buf.len() < HEADER {
        return Err(Refusal::Silent);
    }
    if buf.len() > MAX_MSG || buf.len() % 4 != 0 {
        return Err(Refusal::Code {
            opcode,
            code: rc::MALFORMED_REQUEST,
        });
    }
    if unmapped(&buf[8..24]) != src {
        return Err(Refusal::Code {
            opcode,
            code: rc::ADDRESS_MISMATCH,
        });
    }
    let lifetime = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    match opcode {
        OP_ANNOUNCE => Ok(Req::Announce),
        OP_MAP | OP_PEER => {
            let peer = opcode == OP_PEER;
            let need = HEADER + OPCODE_DATA + if peer { 20 } else { 0 };
            if buf.len() < need {
                return Err(Refusal::Code {
                    opcode,
                    code: rc::MALFORMED_REQUEST,
                });
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&buf[24..36]);
            let proto = buf[36];
            let int_port = u16::from_be_bytes([buf[40], buf[41]]);
            if peer {
                return Ok(Req::Peer(PeerReq {
                    lifetime,
                    nonce,
                    proto,
                    int_port,
                    peer_port: u16::from_be_bytes([buf[60], buf[61]]),
                    peer_ip: unmapped(&buf[64..80]),
                }));
            }
            let mut map = MapReq {
                lifetime,
                nonce,
                proto,
                int_port,
                sug_ext_port: u16::from_be_bytes([buf[42], buf[43]]),
                sug_ext_ip: unmapped(&buf[44..60]),
                prefer_failure: false,
                third_party: None,
                filters: Vec::new(),
            };
            // the zero port is legal only as the delete form
            if int_port == 0 && lifetime != 0 {
                return Err(Refusal::Code {
                    opcode,
                    code: rc::MALFORMED_REQUEST,
                });
            }
            read_options(buf, HEADER + OPCODE_DATA, &mut map)?;
            Ok(Req::Map(map))
        }
        _ => Err(Refusal::Code {
            opcode,
            code: rc::UNSUPP_OPCODE,
        }),
    }
}

/// A MAP response (RFC 6887 section 11.1, response side): the client's nonce,
/// protocol and internal port come back, and the assigned external port and
/// address are the server's.
pub fn build_map_response(
    req: &MapReq,
    epoch: u32,
    code: u8,
    lifetime: u32,
    ext_port: u16,
    ext_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut out = resp_header(OP_MAP, code, lifetime, epoch);
    out.extend_from_slice(&resp_body(&req.nonce, req.proto, req.int_port, ext_port, ext_ip));
    out
}

/// A PEER response: the same layout as MAP's (RFC 6887 section 12.1).
pub fn build_peer_response(
    req: &PeerReq,
    epoch: u32,
    code: u8,
    lifetime: u32,
    ext_port: u16,
    ext_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut out = resp_header(OP_PEER, code, lifetime, epoch);
    out.extend_from_slice(&resp_body(&req.nonce, req.proto, req.int_port, ext_port, ext_ip));
    out
}

/// An ANNOUNCE response has no opcode-specific payload: the header alone
/// (RFC 6887 section 14.1.1).
pub fn build_announce_response(epoch: u32) -> Vec<u8> {
    resp_header(OP_ANNOUNCE, rc::SUCCESS, 0, epoch)
}

/// An error response for a request that could not be acted on: the request's
/// own payload comes back (RFC 6887 section 8.2's error-response rule) with
/// the response fields set.
pub fn build_error(req: &[u8], code: u8, epoch: u32) -> Vec<u8> {
    let keep = req.len().min(MAX_MSG);
    let mut out = req[..keep].to_vec();
    out.resize((keep + 3) & !3, 0);
    out[0] = VERSION;
    out[1] = (out[1] & 0x7f) | 0x80;
    out[2] = 0;
    out[3] = code;
    out[4..8].copy_from_slice(&error_lifetime(code).to_be_bytes());
    out[8..12].copy_from_slice(&epoch.to_be_bytes());
    if out.len() >= HEADER {
        // a request that did not parse: its client field comes back in the
        // reserved field so the client can still match the answer to its own
        // request (RFC 6887 section 7.2)
        let mut field = [0u8; 12];
        field.copy_from_slice(&out[12..24]);
        out[12..24].copy_from_slice(&field);
    }
    out
}

/// The lifetime an error response advertises: the RFC recommends thirty
/// seconds for its short-lifetime codes and thirty minutes for the rest.
pub fn error_lifetime(code: u8) -> u32 {
    match code {
        rc::NETWORK_FAILURE | rc::NO_RESOURCES | rc::USER_EX_QUOTA => 30,
        // CANNOT_PROVIDE_EXTERNAL's lifetime "depends on the reason"; ours is
        // structural (the uplink's own NAT owns the external port), so it is
        // the long figure: retrying will not change the answer
        _ => 1800,
    }
}

/// The lifetime a grant answers with, bounded by what the hold can maintain.
/// A zero request is the delete form and stays zero.
pub fn lifetime_cap(requested: u32, cap: u32) -> u32 {
    if requested == 0 {
        0
    } else {
        requested.min(cap)
    }
}

/// The result code an admission outcome answers with.
pub fn outcome_code(o: &UpsertOutcome) -> u8 {
    match o {
        UpsertOutcome::Granted { .. } | UpsertOutcome::Refreshed { .. } => rc::SUCCESS,
        UpsertOutcome::UserQuotaExceeded => rc::USER_EX_QUOTA,
        UpsertOutcome::TableFull => rc::NO_RESOURCES,
    }
}

/// Which protocol a datagram on the shared port belongs to. The first octet
/// is the discriminator (a PCP request is version 2, a NAT-PMP request
/// version 0); anything else is resolved by length, because a NAT-PMP
/// version error and a PCP version-negotiation both start with an
/// unrecognised octet and differ in the shape of what follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sniff {
    Pcp,
    Npmp,
    Unknown,
}

pub fn sniff(buf: &[u8]) -> Sniff {
    match buf.first() {
        None => Sniff::Unknown,
        Some(&0) => Sniff::Npmp,
        Some(&VERSION) => Sniff::Pcp,
        // An unrecognised version octet. A PCP request is at least a common
        // header long; a NAT-PMP request is twelve octets at most, so the
        // length is what separates a future PCP version (answered with
        // UNSUPP_VERSION) from a NAT-PMP version error.
        Some(_) if buf.len() >= HEADER => Sniff::Pcp,
        Some(_) => Sniff::Npmp,
    }
}

/// A NAT-PMP request (RFC 6886 section 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NpmpReq {
    PublicAddress,
    Map {
        op: u8,
        int_port: u16,
        sug_ext_port: u16,
        lifetime: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NpmpErr {
    Silent,
    Code(u8),
}

/// Parse one NAT-PMP request.
pub fn parse_npmp(buf: &[u8]) -> Result<NpmpReq, NpmpErr> {
    if buf.len() < 2 {
        return Err(NpmpErr::Silent);
    }
    let op = buf[1];
    if op & np::RESP != 0 {
        return Err(NpmpErr::Silent);
    }
    if buf[0] != 0 {
        return Err(NpmpErr::Code(np::UNSUPP_VERSION));
    }
    match op {
        np::OP_PUBLIC => Ok(NpmpReq::PublicAddress),
        np::OP_MAP_UDP | np::OP_MAP_TCP => {
            if buf.len() < 12 {
                return Err(NpmpErr::Silent);
            }
            Ok(NpmpReq::Map {
                op,
                int_port: u16::from_be_bytes([buf[4], buf[5]]),
                sug_ext_port: u16::from_be_bytes([buf[6], buf[7]]),
                lifetime: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            })
        }
        _ => Err(NpmpErr::Code(np::UNSUPP_OPCODE)),
    }
}

/// A NAT-PMP mapping response (RFC 6886 section 3.3).
pub fn build_npmp_map(
    op: u8,
    code: u8,
    epoch: u32,
    int_port: u16,
    ext_port: u16,
    lifetime: u32,
) -> Vec<u8> {
    let mut b = vec![0u8, op | np::RESP];
    b.extend_from_slice(&u16::from(code).to_be_bytes());
    b.extend_from_slice(&epoch.to_be_bytes());
    b.extend_from_slice(&int_port.to_be_bytes());
    b.extend_from_slice(&ext_port.to_be_bytes());
    b.extend_from_slice(&lifetime.to_be_bytes());
    b
}

/// A NAT-PMP public-address response (RFC 6886 section 3.2).
pub fn build_npmp_public(code: u8, epoch: u32, ip: Ipv4Addr) -> Vec<u8> {
    let mut b = vec![0u8, np::OP_PUBLIC | np::RESP];
    b.extend_from_slice(&u16::from(code).to_be_bytes());
    b.extend_from_slice(&epoch.to_be_bytes());
    b.extend_from_slice(&ip.octets());
    b
}

/// The version-error response: the short form, with the opcode zeroed
/// (RFC 6886 section 3.5's own diagram).
pub fn build_npmp_version_error(epoch: u32) -> Vec<u8> {
    let mut b = vec![0u8, np::OP_PUBLIC];
    b.extend_from_slice(&u16::from(np::UNSUPP_VERSION).to_be_bytes());
    b.extend_from_slice(&epoch.to_be_bytes());
    b
}

/// The unsupported-opcode response: the request itself comes back with the
/// response bit set and the result code 5 (RFC 6886 section 3.5).
pub fn build_npmp_echo(req: &[u8], epoch: u32) -> Vec<u8> {
    if req.len() < 12 {
        // no room for a result code in the request's own shape: the short
        // public-address form carries it
        return build_npmp_public(np::UNSUPP_OPCODE, epoch, Ipv4Addr::UNSPECIFIED);
    }
    let mut out = req[..12].to_vec();
    out[1] |= np::RESP;
    out[2] = 0;
    out[3] = np::UNSUPP_OPCODE;
    out[4..8].copy_from_slice(&epoch.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 21, 50);
    const SUG: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

    fn mapped(ip: Ipv4Addr) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[10] = 0xff;
        a[11] = 0xff;
        a[12..16].copy_from_slice(&ip.octets());
        a
    }

    fn header(opcode: u8, lifetime: u32, client: Ipv4Addr, body: &[u8]) -> Vec<u8> {
        let mut b = vec![VERSION, opcode];
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&lifetime.to_be_bytes());
        b.extend_from_slice(&mapped(client));
        b.extend_from_slice(body);
        b
    }

    /// The MAP opcode-specific data, request side (RFC 6887 section 11.1).
    fn map_body(proto: u8, int_port: u16, sug_port: u16, sug_ip: Ipv4Addr) -> Vec<u8> {
        let mut b = vec![0xAB; 12];
        b.push(proto);
        b.extend_from_slice(&[0u8; 3]);
        b.extend_from_slice(&int_port.to_be_bytes());
        b.extend_from_slice(&sug_port.to_be_bytes());
        b.extend_from_slice(&mapped(sug_ip));
        b
    }

    fn opt(code: u8, data: &[u8]) -> Vec<u8> {
        let mut b = vec![code, 0];
        b.extend_from_slice(&(data.len() as u16).to_be_bytes());
        b.extend_from_slice(data);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    fn map_req(lifetime: u32, proto: u8, int_port: u16, sug_port: u16, sug_ip: Ipv4Addr) -> Vec<u8> {
        header(OP_MAP, lifetime, CLIENT, &map_body(proto, int_port, sug_port, sug_ip))
    }

    // ---- PCP parsing ----

    #[test]
    fn parse_map_reads_every_field() {
        let buf = map_req(120, 17, 3074, 3074, SUG);
        let req = parse_pcp(&buf, CLIENT).expect("a well-formed MAP parses");
        let Req::Map(m) = req else { panic!("not a MAP") };
        assert_eq!(m.lifetime, 120);
        assert_eq!(m.proto, 17);
        assert_eq!(m.int_port, 3074);
        assert_eq!(m.sug_ext_port, 3074);
        assert_eq!(m.sug_ext_ip, SUG);
        assert_eq!(m.nonce, [0xAB; 12]);
        assert!(!m.prefer_failure);
        assert!(m.third_party.is_none());
        assert!(m.filters.is_empty());
    }

    #[test]
    fn parse_announce_has_no_opcode_data() {
        let buf = header(OP_ANNOUNCE, 0, CLIENT, &[]);
        assert_eq!(parse_pcp(&buf, CLIENT), Ok(Req::Announce));
        // lifetime is ignored on reception (section 14.1.1)
        let buf = header(OP_ANNOUNCE, 9, CLIENT, &[]);
        assert_eq!(parse_pcp(&buf, CLIENT), Ok(Req::Announce));
    }

    #[test]
    fn parse_peer_reads_the_remote_peer() {
        let mut body = map_body(17, 3074, 0, Ipv4Addr::UNSPECIFIED);
        body.extend_from_slice(&19302u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&mapped(SUG));
        let buf = header(OP_PEER, 120, CLIENT, &body);
        let Req::Peer(p) = parse_pcp(&buf, CLIENT).expect("a PEER parses") else {
            panic!("not a PEER")
        };
        assert_eq!(p.proto, 17);
        assert_eq!(p.int_port, 3074);
        assert_eq!(p.peer_port, 19302);
        assert_eq!(p.peer_ip, SUG);
        assert_eq!(p.lifetime, 120);
    }

    #[test]
    fn options_are_read_where_they_mean_something() {
        let mut buf = map_req(120, 17, 3074, 3074, SUG);
        buf.extend_from_slice(&opt(OPT_THIRD_PARTY, &mapped(Ipv4Addr::new(192, 168, 21, 60))));
        buf.extend_from_slice(&opt(OPT_PREFER_FAILURE, &[]));
        let Req::Map(m) = parse_pcp(&buf, CLIENT).expect("options parse") else {
            panic!("not a MAP")
        };
        assert_eq!(m.third_party, Some(Ipv4Addr::new(192, 168, 21, 60)));
        assert!(m.prefer_failure);
    }

    #[test]
    fn filter_options_accumulate_and_a_zero_prefix_clears_them() {
        let mut f1 = vec![0u8];
        f1.push(32); // a full-length prefix
        f1.extend_from_slice(&3074u16.to_be_bytes());
        f1.extend_from_slice(&mapped(SUG));
        let mut buf = map_req(120, 17, 3074, 0, Ipv4Addr::UNSPECIFIED);
        buf.extend_from_slice(&opt(OPT_FILTER, &f1));
        let Req::Map(m) = parse_pcp(&buf, CLIENT).expect("a filter parses") else {
            panic!("not a MAP")
        };
        assert_eq!(m.filters.len(), 1);
        assert_eq!(m.filters[0].prefix_len, 32);
        assert_eq!(m.filters[0].peer_port, 3074);
        assert_eq!(m.filters[0].peer_ip, SUG);

        // a zero prefix length means "no filter" and removes the earlier one
        let mut clear = vec![0u8, 0];
        clear.extend_from_slice(&0u16.to_be_bytes());
        clear.extend_from_slice(&mapped(Ipv4Addr::UNSPECIFIED));
        let mut buf = map_req(120, 17, 3074, 0, Ipv4Addr::UNSPECIFIED);
        buf.extend_from_slice(&opt(OPT_FILTER, &f1));
        buf.extend_from_slice(&opt(OPT_FILTER, &clear));
        let Req::Map(m) = parse_pcp(&buf, CLIENT).expect("a clearing filter parses") else {
            panic!("not a MAP")
        };
        assert!(m.filters.is_empty(), "prefix zero clears the set");
    }

    // ---- PCP refusals ----

    #[test]
    fn a_short_datagram_is_silently_dropped() {
        assert_eq!(parse_pcp(&[], CLIENT), Err(Refusal::Silent));
        assert_eq!(parse_pcp(&[VERSION], CLIENT), Err(Refusal::Silent));
        // version 2 but shorter than the common header: silence, not an error
        let mut short = map_req(120, 17, 3074, 3074, SUG);
        short.truncate(23);
        assert_eq!(parse_pcp(&short, CLIENT), Err(Refusal::Silent));
    }

    #[test]
    fn a_response_is_silently_dropped() {
        let mut buf = map_req(120, 17, 3074, 3074, SUG);
        buf[1] |= 0x80; // the R bit
        assert_eq!(parse_pcp(&buf, CLIENT), Err(Refusal::Silent));
    }

    #[test]
    fn a_future_version_earns_an_unsupported_version_response() {
        let mut buf = map_req(120, 17, 3074, 3074, SUG);
        buf[0] = 3;
        assert_eq!(
            parse_pcp(&buf, CLIENT),
            Err(Refusal::Code {
                opcode: OP_MAP,
                code: rc::UNSUPP_VERSION
            })
        );
    }

    #[test]
    fn a_foreign_source_address_is_an_address_mismatch() {
        let buf = map_req(120, 17, 3074, 3074, SUG);
        assert_eq!(
            parse_pcp(&buf, Ipv4Addr::new(192, 168, 21, 51)),
            Err(Refusal::Code {
                opcode: OP_MAP,
                code: rc::ADDRESS_MISMATCH
            })
        );
    }

    #[test]
    fn a_length_the_rfc_forbids_is_malformed() {
        // not a multiple of four
        let mut buf = map_req(120, 17, 3074, 3074, SUG);
        buf.push(0);
        assert_eq!(
            parse_pcp(&buf, CLIENT),
            Err(Refusal::Code {
                opcode: OP_MAP,
                code: rc::MALFORMED_REQUEST
            })
        );
        // longer than the maximum
        let mut big = map_req(120, 17, 3074, 3074, SUG);
        big.resize(MAX_MSG + 4, 0);
        assert_eq!(
            parse_pcp(&big, CLIENT),
            Err(Refusal::Code {
                opcode: OP_MAP,
                code: rc::MALFORMED_REQUEST
            })
        );
        // too short for the opcode it claims
        let mut short = map_req(120, 17, 3074, 3074, SUG);
        short.truncate(40);
        assert_eq!(
            parse_pcp(&short, CLIENT),
            Err(Refusal::Code {
                opcode: OP_MAP,
                code: rc::MALFORMED_REQUEST
            })
        );
    }

    #[test]
    fn an_unknown_opcode_is_refused_not_misparsed() {
        let buf = header(5, 120, CLIENT, &[0u8; 36]);
        assert_eq!(
            parse_pcp(&buf, CLIENT),
            Err(Refusal::Code {
                opcode: 5,
                code: rc::UNSUPP_OPCODE
            })
        );
    }

    #[test]
    fn a_ragged_option_is_a_malformed_option() {
        // FILTER announcing twenty octets with only four present
        let mut buf = map_req(120, 17, 3074, 3074, SUG);
        buf.extend_from_slice(&[OPT_FILTER, 0, 0, 20, 0, 0, 0, 0]);
        assert_eq!(
            parse_pcp(&buf, CLIENT),
            Err(Refusal::Code {
                opcode: OP_MAP,
                code: rc::MALFORMED_OPTION
            })
        );
    }

    #[test]
    fn an_unknown_mandatory_option_is_refused() {
        // the top bit clear means mandatory to process; 100 is nobody's
        let buf = {
            let mut b = map_req(120, 17, 3074, 3074, SUG);
            b.extend_from_slice(&opt(100, &[]));
            b
        };
        assert_eq!(
            parse_pcp(&buf, CLIENT),
            Err(Refusal::Code {
                opcode: OP_MAP,
                code: rc::UNSUPP_OPTION
            })
        );
        // with the top bit set it is optional, and is ignored
        let buf = {
            let mut b = map_req(120, 17, 3074, 3074, SUG);
            b.extend_from_slice(&opt(100 | 0x80, &[]));
            b
        };
        assert!(matches!(parse_pcp(&buf, CLIENT), Ok(Req::Map(_))));
    }

    #[test]
    fn a_map_must_name_a_port_unless_it_is_deleting() {
        // internal port zero with a non-zero lifetime is not a mapping
        let buf = map_req(120, 17, 0, 0, Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            parse_pcp(&buf, CLIENT),
            Err(Refusal::Code {
                opcode: OP_MAP,
                code: rc::MALFORMED_REQUEST
            })
        );
        // with a zero lifetime it is the delete-everything form, and parses
        let buf = map_req(0, 17, 0, 0, Ipv4Addr::UNSPECIFIED);
        assert!(matches!(parse_pcp(&buf, CLIENT), Ok(Req::Map(_))));
    }

    #[test]
    fn the_protocol_field_is_read_as_sent() {
        // admission decides what to do with it; the codec reports it
        let Req::Map(m) = parse_pcp(&map_req(120, 6, 3074, 0, Ipv4Addr::UNSPECIFIED), CLIENT)
            .expect("a TCP MAP parses")
        else {
            panic!("not a MAP")
        };
        assert_eq!(m.proto, 6);
    }

    // ---- PCP responses ----

    #[test]
    fn a_map_response_carries_the_request_back_and_the_assigned_tuple() {
        let req = MapReq {
            lifetime: 120,
            nonce: [0xAB; 12],
            proto: 17,
            int_port: 3074,
            sug_ext_port: 3074,
            sug_ext_ip: SUG,
            prefer_failure: false,
            third_party: None,
            filters: Vec::new(),
        };
        let out = build_map_response(&req, 41, rc::SUCCESS, 120, 40222, SUG);
        assert_eq!(out.len(), HEADER + OPCODE_DATA);
        assert_eq!(out[0], VERSION);
        assert_eq!(out[1], OP_MAP | 0x80, "the R bit marks a response");
        assert_eq!(out[2], 0, "reserved");
        assert_eq!(out[3], rc::SUCCESS);
        assert_eq!(u32::from_be_bytes([out[4], out[5], out[6], out[7]]), 120);
        assert_eq!(u32::from_be_bytes([out[8], out[9], out[10], out[11]]), 41);
        assert_eq!(&out[12..24], &[0u8; 12], "the reserved field is zero");
        assert_eq!(&out[24..36], &[0xAB; 12], "the nonce comes back");
        assert_eq!(out[36], 17);
        assert_eq!(&out[37..40], &[0u8; 3]);
        assert_eq!(u16::from_be_bytes([out[40], out[41]]), 3074);
        assert_eq!(u16::from_be_bytes([out[42], out[43]]), 40222);
        assert_eq!(&out[44..54], &[0u8; 10], "an IPv4 address is mapped");
        assert_eq!(&out[54..56], &[0xff, 0xff]);
        assert_eq!(&out[56..60], &SUG.octets());
    }

    #[test]
    fn an_error_map_response_copies_the_suggestion_back() {
        let req = MapReq {
            lifetime: 120,
            nonce: [0x11; 12],
            proto: 17,
            int_port: 3074,
            sug_ext_port: 3074,
            sug_ext_ip: SUG,
            prefer_failure: true,
            third_party: None,
            filters: Vec::new(),
        };
        let out = build_map_response(&req, 41, rc::CANNOT_PROVIDE_EXTERNAL, 30, 3074, SUG);
        assert_eq!(out[3], rc::CANNOT_PROVIDE_EXTERNAL);
        assert_eq!(u16::from_be_bytes([out[42], out[43]]), 3074);
        assert_eq!(&out[56..60], &SUG.octets());
    }

    #[test]
    fn an_announce_response_is_the_header_alone() {
        let out = build_announce_response(41);
        assert_eq!(out.len(), HEADER);
        assert_eq!(out[1], OP_ANNOUNCE | 0x80);
        assert_eq!(out[3], rc::SUCCESS);
        assert_eq!(u32::from_be_bytes([out[4], out[5], out[6], out[7]]), 0);
        assert_eq!(u32::from_be_bytes([out[8], out[9], out[10], out[11]]), 41);
    }

    #[test]
    fn a_peer_response_keeps_the_map_layout() {
        let req = PeerReq {
            lifetime: 120,
            nonce: [0x22; 12],
            proto: 17,
            int_port: 3074,
            peer_port: 19302,
            peer_ip: SUG,
        };
        let out = build_peer_response(&req, 41, rc::SUCCESS, 120, 40222, SUG);
        assert_eq!(out.len(), HEADER + OPCODE_DATA);
        assert_eq!(out[1], OP_PEER | 0x80);
        assert_eq!(&out[24..36], &[0x22; 12]);
        assert_eq!(u16::from_be_bytes([out[42], out[43]]), 40222);
    }

    #[test]
    fn an_error_response_carries_the_request_and_the_code() {
        let req = map_req(120, 17, 3074, 3074, SUG);
        let out = build_error(&req, rc::MALFORMED_REQUEST, 41);
        assert_eq!(out.len(), req.len());
        assert_eq!(out[0], VERSION);
        assert_eq!(out[1], OP_MAP | 0x80);
        assert_eq!(out[3], rc::MALFORMED_REQUEST);
        assert_eq!(
            u32::from_be_bytes([out[4], out[5], out[6], out[7]]),
            error_lifetime(rc::MALFORMED_REQUEST)
        );
        assert_eq!(u32::from_be_bytes([out[8], out[9], out[10], out[11]]), 41);
        // the payload comes back verbatim so the client can match the answer
        assert_eq!(&out[24..], &req[24..]);
        // and the client's own field comes back in the reserved field, which
        // is how a request that did not parse is still correlated
        assert_eq!(&out[12..24], &req[12..24]);
        // and a long message is cut at the maximum the RFC allows
        let mut big = req.clone();
        big.resize(MAX_MSG + 8, 0);
        assert_eq!(build_error(&big, rc::MALFORMED_REQUEST, 41).len(), MAX_MSG);
    }

    #[test]
    fn the_short_lifetime_errors_answer_with_the_short_figure() {
        for code in [
            rc::NETWORK_FAILURE,
            rc::NO_RESOURCES,
            rc::USER_EX_QUOTA,
        ] {
            assert_eq!(error_lifetime(code), 30, "code {}", code);
        }
        for code in [
            rc::MALFORMED_REQUEST,
            rc::UNSUPP_OPCODE,
            rc::NOT_AUTHORIZED,
            rc::CANNOT_PROVIDE_EXTERNAL,
        ] {
            assert_eq!(error_lifetime(code), 1800, "code {}", code);
        }
    }

    #[test]
    fn a_granted_lifetime_is_bounded_by_its_dialect() {
        // PCP: the hold's ceiling. NAT-PMP: the figure its own spec
        // recommends, which is what a legacy client expects to read back.
        assert_eq!(lifetime_cap(0, MAX_LIFETIME), 0, "a zero request is a delete");
        assert_eq!(lifetime_cap(120, MAX_LIFETIME), 120);
        assert_eq!(lifetime_cap(MAX_LIFETIME, MAX_LIFETIME), MAX_LIFETIME);
        assert_eq!(lifetime_cap(7200, MAX_LIFETIME), MAX_LIFETIME);
        assert_eq!(lifetime_cap(7200, NPMP_LIFETIME), NPMP_LIFETIME);
        assert_eq!(lifetime_cap(0, NPMP_LIFETIME), 0);
    }

    #[test]
    fn an_admission_outcome_maps_to_a_result_code() {
        assert_eq!(outcome_code(&UpsertOutcome::Granted { bind_port: 30000 }), rc::SUCCESS);
        assert_eq!(outcome_code(&UpsertOutcome::Refreshed { bind_port: 30000 }), rc::SUCCESS);
        assert_eq!(outcome_code(&UpsertOutcome::UserQuotaExceeded), rc::USER_EX_QUOTA);
        assert_eq!(outcome_code(&UpsertOutcome::TableFull), rc::NO_RESOURCES);
    }

    // ---- the shared port ----

    #[test]
    fn the_shared_port_is_disambiguated_by_version_and_length() {
        assert_eq!(sniff(&map_req(120, 17, 3074, 3074, SUG)), Sniff::Pcp);
        assert_eq!(sniff(&[0u8; 12]), Sniff::Npmp);
        assert_eq!(sniff(&[0u8, 1]), Sniff::Npmp);
        // an unrecognised version: a PCP request is at least a header long
        let mut pcp = map_req(120, 17, 3074, 3074, SUG);
        pcp[0] = 7;
        assert_eq!(sniff(&pcp), Sniff::Pcp, "long enough to be PCP's");
        assert_eq!(sniff(&[7u8, 1, 0, 0]), Sniff::Npmp, "short enough to be NAT-PMP's");
        assert_eq!(sniff(&[]), Sniff::Unknown);
    }

    // ---- NAT-PMP ----

    #[test]
    fn a_natpmp_map_request_parses() {
        let buf = [
            0u8, np::OP_MAP_UDP, 0, 0, 0x0c, 0x02, 0x0c, 0x02, 0x00, 0x00, 0x1c, 0x20,
        ];
        assert_eq!(
            parse_npmp(&buf),
            Ok(NpmpReq::Map {
                op: np::OP_MAP_UDP,
                int_port: 3074,
                sug_ext_port: 3074,
                lifetime: 7200,
            })
        );
    }

    #[test]
    fn a_natpmp_public_address_request_is_two_octets() {
        assert_eq!(parse_npmp(&[0u8, np::OP_PUBLIC]), Ok(NpmpReq::PublicAddress));
        assert_eq!(parse_npmp(&[0u8]), Err(NpmpErr::Silent));
    }

    #[test]
    fn a_natpmp_version_error_is_the_rfc_diagram() {
        assert_eq!(
            parse_npmp(&[1u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(NpmpErr::Code(np::UNSUPP_VERSION))
        );
        // the specification's own diagram for this one: eight octets, OP zero
        // (the result code, not the response bit, is what marks it an error)
        let out = build_npmp_version_error(41);
        assert_eq!(out.len(), 8);
        assert_eq!(out[0], 0);
        assert_eq!(out[1], np::OP_PUBLIC);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), u16::from(np::UNSUPP_VERSION));
        assert_eq!(u32::from_be_bytes([out[4], out[5], out[6], out[7]]), 41);
    }

    #[test]
    fn a_natpmp_response_is_the_short_form() {
        assert_eq!(parse_npmp(&[0u8, np::OP_PUBLIC | np::RESP, 0, 0]), Err(NpmpErr::Silent));
        let out = build_npmp_public(np::SUCCESS, 41, SUG);
        assert_eq!(out.len(), 12);
        assert_eq!(out[1], np::OP_PUBLIC | np::RESP);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 0);
        assert_eq!(&out[8..12], &SUG.octets());

        let out = build_npmp_map(np::OP_MAP_UDP, np::SUCCESS, 41, 3074, 40222, NPMP_LIFETIME);
        assert_eq!(out.len(), 16);
        assert_eq!(out[1], np::OP_MAP_UDP | np::RESP);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 0);
        assert_eq!(u32::from_be_bytes([out[4], out[5], out[6], out[7]]), 41);
        assert_eq!(u16::from_be_bytes([out[8], out[9]]), 3074);
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 40222);
        assert_eq!(u32::from_be_bytes([out[12], out[13], out[14], out[15]]), NPMP_LIFETIME);
    }

    #[test]
    fn an_unknown_natpmp_opcode_comes_back_unsupported() {
        let buf = [0u8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_npmp(&buf), Err(NpmpErr::Code(np::UNSUPP_OPCODE)));
        let out = build_npmp_echo(&buf, 41);
        assert_eq!(out.len(), buf.len());
        assert_eq!(out[1], 9 | np::RESP, "the request's opcode with the response bit");
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), u16::from(np::UNSUPP_OPCODE));
        assert_eq!(u32::from_be_bytes([out[4], out[5], out[6], out[7]]), 41);
        // a two-octet unknown opcode has nowhere to put a code: the short
        // form answers it
        let out = build_npmp_echo(&[0u8, 9], 41);
        assert_eq!(out.len(), 12);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), u16::from(np::UNSUPP_OPCODE));
    }
}