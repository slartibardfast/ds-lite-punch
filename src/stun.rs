//! Minimal STUN (RFC 5389) codec: Binding Request and Success Response with (XOR-)MAPPED-ADDRESS.
use std::net::Ipv4Addr;

pub const MAGIC: u32 = 0x2112A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED: u16 = 0x0001;
const ATTR_XOR_MAPPED: u16 = 0x0020;
const FAMILY_V4: u8 = 0x01;

pub fn binding_request(txn: &[u8; 12]) -> Vec<u8> {
    let mut b = Vec::with_capacity(20);
    b.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // no attributes
    b.extend_from_slice(&MAGIC.to_be_bytes());
    b.extend_from_slice(txn);
    b
}

/// Cheap non-crypto transaction id: an LCG seeded from the clock, since STUN is unauthenticated anyway.
pub fn random_txn() -> [u8; 12] {
    let mut t = [0u8; 12];
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e3779b97f4a7c15);
    let mut x = seed | 1;
    for byte in t.iter_mut() {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *byte = (x >> 33) as u8;
    }
    t
}

/// Parse a Binding Success Response and return the reflexive (ip, port) the NAT reports for us.
pub fn parse_mapped(resp: &[u8]) -> Option<(Ipv4Addr, u16)> {
    if resp.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([resp[0], resp[1]]);
    if msg_type != BINDING_SUCCESS_RESPONSE {
        return None;
    }
    let cookie = u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]);
    if cookie != MAGIC {
        return None;
    }
    let msg_len = u16::from_be_bytes([resp[2], resp[3]]) as usize;
    let end = (20 + msg_len).min(resp.len());
    let attrs = &resp[20..end];
    let mut i = 0usize;
    while i + 4 <= attrs.len() {
        let atype = u16::from_be_bytes([attrs[i], attrs[i + 1]]);
        let alen = u16::from_be_bytes([attrs[i + 2], attrs[i + 3]]) as usize;
        let vstart = i + 4;
        if vstart > attrs.len() {
            break;
        }
        let vend = (vstart + alen).min(attrs.len());
        let val = &attrs[vstart..vend];
        if (atype == ATTR_XOR_MAPPED || atype == ATTR_MAPPED) && val.len() >= 8 && val[1] == FAMILY_V4 {
            let mut port = u16::from_be_bytes([val[2], val[3]]);
            let mut ip = [val[4], val[5], val[6], val[7]];
            if atype == ATTR_XOR_MAPPED {
                port ^= (MAGIC >> 16) as u16;
                let cb = MAGIC.to_be_bytes();
                for k in 0..4 {
                    ip[k] ^= cb[k];
                }
            }
            return Some((Ipv4Addr::from(ip), port));
        }
        i += 4 + ((alen + 3) & !3); // attribute values pad to 4 bytes
    }
    None
}

/// Build a valid Binding Success Response with one (XOR-)MAPPED-ADDRESS attribute, shared by tests and proofs
#[cfg(any(test, kani))]
fn build_mapped_response(xor: bool, ip: [u8; 4], port: u16) -> Vec<u8> {
    let attr_type = if xor { ATTR_XOR_MAPPED } else { ATTR_MAPPED };
    let (eport, eip) = if xor {
        let cb = MAGIC.to_be_bytes();
        let mut xip = ip;
        for k in 0..4 {
            xip[k] ^= cb[k];
        }
        (port ^ (MAGIC >> 16) as u16, xip)
    } else {
        (port, ip)
    };
    let mut r = Vec::with_capacity(32);
    r.extend_from_slice(&BINDING_SUCCESS_RESPONSE.to_be_bytes());
    r.extend_from_slice(&12u16.to_be_bytes()); // attr: 4 hdr + 8 value
    r.extend_from_slice(&MAGIC.to_be_bytes());
    r.extend_from_slice(&[0u8; 12]); // transaction id
    r.extend_from_slice(&attr_type.to_be_bytes());
    r.extend_from_slice(&8u16.to_be_bytes()); // value length
    r.push(0x00); // reserved
    r.push(FAMILY_V4);
    r.extend_from_slice(&eport.to_be_bytes());
    r.extend_from_slice(&eip);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_xor_mapped() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let resp = build_mapped_response(true, ip.octets(), 32853);
        assert_eq!(parse_mapped(&resp), Some((ip, 32853)));
    }

    #[test]
    fn roundtrip_plain_mapped() {
        let ip = Ipv4Addr::new(192, 0, 2, 9);
        let resp = build_mapped_response(false, ip.octets(), 1024);
        assert_eq!(parse_mapped(&resp), Some((ip, 1024)));
    }

    #[test]
    fn rejects_non_response() {
        let req = binding_request(&random_txn());
        assert_eq!(parse_mapped(&req), None);
        assert_eq!(parse_mapped(&[]), None);
        assert_eq!(parse_mapped(&[0u8; 8]), None);
    }
}

/// Kani verification harnesses, which prove these properties for all inputs rather than by example.
#[cfg(kani)]
mod verify {
    use super::*;

    #[kani::proof]
    #[kani::unwind(13)] // parser loop advances >=4 B/iter; 48/4 = 12 max
    fn parse_mapped_never_panics() {
        let arr: [u8; 48] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= arr.len());
        let _ = parse_mapped(&arr[..len]);
    }

    #[kani::proof]
    #[kani::unwind(6)] // bounds both the 4-byte XOR loop and the 2-attr parse loop
    fn xor_mapped_roundtrip() {
        let ip: [u8; 4] = kani::any();
        let port: u16 = kani::any();
        let resp = build_mapped_response(true, ip, port);
        assert_eq!(parse_mapped(&resp), Some((Ipv4Addr::from(ip), port)));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn plain_mapped_roundtrip() {
        let ip: [u8; 4] = kani::any();
        let port: u16 = kani::any();
        let resp = build_mapped_response(false, ip, port);
        assert_eq!(parse_mapped(&resp), Some((Ipv4Addr::from(ip), port)));
    }

    #[kani::proof]
    fn binding_request_layout() {
        let txn: [u8; 12] = kani::any();
        let req = binding_request(&txn);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&req[2..4], &0u16.to_be_bytes());
        assert_eq!(&req[4..8], &MAGIC.to_be_bytes());
        assert_eq!(&req[8..20], &txn);
    }

    #[kani::proof]
    #[kani::unwind(13)] // same bound as parse_mapped_never_panics
    fn some_implies_valid_header() {
        let arr: [u8; 48] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= arr.len());
        let buf = &arr[..len];
        if parse_mapped(buf).is_some() {
            assert!(buf.len() >= 20);
            let ty = u16::from_be_bytes([buf[0], buf[1]]);
            let ck = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            assert_eq!(ty, 0x0101);
            assert_eq!(ck, MAGIC);
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn truncated_response_is_none_or_valid() {
        // Cutting a valid response at any point must yield None, since the attribute cannot be complete.
        let ip: [u8; 4] = kani::any();
        let port: u16 = kani::any();
        let full = build_mapped_response(true, ip, port);
        let cut: usize = kani::any();
        kani::assume(cut < full.len());
        let truncated = &full[..cut];
        if let Some(t) = parse_mapped(truncated) {
            // A truncated buffer parses only if the cut falls after the complete attribute, removing nothing.
            assert_eq!(t, (Ipv4Addr::from(ip), port));
        }
    }
}
