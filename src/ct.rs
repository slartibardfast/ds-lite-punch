//! Netlink conntrack deletion, which this kernel refuses with EINVAL; the self-pin replaced it, and --ct-probe re-bisects it.
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use crate::publish::{emitln};

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u8 = 2;
const NFNETLINK_V0: u8 = 0;
const AF_INET: u8 = 2;
const NLMSG_ERROR: u16 = 2;
const UDP: u8 = 17;

// nf_conntrack.h CTA_* attribute ids (nested under CTA_TUPLE_ORIG).
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 3;
const CTA_PROTO_DST_PORT: u16 = 4;
const CTA_TUPLE_ORIG: u16 = 1;
/// Top-level zone attribute (ctattr_type: CTA_ZONE = 23).
const CTA_ZONE: u16 = 23;

/// Append an NLA attribute: length (4 + data), type, payload, padded to four bytes.
fn put_attr(buf: &mut Vec<u8>, ty: u16, data: &[u8], nested: bool) {
    let nty = if nested { ty | 0x8000 } else { ty };
    buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&nty.to_ne_bytes());
    buf.extend_from_slice(data);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

/// Build a delete message from the encodings the bisect varies.
#[allow(clippy::too_many_arguments)]
fn build_msg(
    family: u8,
    nested: bool,
    dir_reply: bool,
    a: (Ipv4Addr, u16),
    b: (Ipv4Addr, u16),
    with_zone: bool,
) -> Vec<u8> {
    let (src, dst) = if dir_reply { (b, a) } else { (a, b) };
    let mut ip = Vec::new();
    put_attr(&mut ip, CTA_IP_V4_SRC, &src.0.octets(), false);
    put_attr(&mut ip, CTA_IP_V4_DST, &dst.0.octets(), false);
    let mut proto = Vec::new();
    put_attr(&mut proto, CTA_PROTO_NUM, &[UDP], false);
    put_attr(&mut proto, CTA_PROTO_SRC_PORT, &src.1.to_be_bytes(), false);
    put_attr(&mut proto, CTA_PROTO_DST_PORT, &dst.1.to_be_bytes(), false);
    let mut tuple = Vec::new();
    put_attr(&mut tuple, CTA_TUPLE_IP, &ip, nested);
    put_attr(&mut tuple, CTA_TUPLE_PROTO, &proto, nested);
    let mut attrs = Vec::new();
    put_attr(&mut attrs, CTA_TUPLE_ORIG, &tuple, nested);
    if with_zone {
        put_attr(&mut attrs, CTA_ZONE, &0u16.to_be_bytes(), false);
    }

    let total = 16 + 4 + attrs.len();
    let mut req = vec![0u8; total];
    req[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
    let nl_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE as u16;
    req[4..6].copy_from_slice(&nl_type.to_ne_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());
    req[16] = family;
    req[17] = NFNETLINK_V0;
    req[20..].copy_from_slice(&attrs);
    req
}

/// Build the CT_DELETE request for the observed flow's original tuple. Dead code: the self-pin replaced it.
#[allow(dead_code)]
pub fn build_del_msg(
    host: Ipv4Addr,
    host_port: u16,
    peer: Ipv4Addr,
    peer_port: u16,
) -> Vec<u8> {
    build_msg(
        AF_INET,
        true,
        false,
        (host, host_port),
        (peer, peer_port),
        false,
    )
}

/// Send one delete request: Ok(0) deleted, Ok(-2) already gone, other negatives are errno, Err is the request failing.
fn ct_delete(cmd: &[u8]) -> std::io::Result<i32> {
    let fd: RawFd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let bind_r = unsafe {
        let mut local: libc::sockaddr_nl = std::mem::zeroed();
        local.nl_family = libc::AF_NETLINK as u16;
        libc::bind(
            fd,
            &local as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bind_r != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    let sent = unsafe { libc::send(fd, cmd.as_ptr() as *const libc::c_void, cmd.len(), 0) };
    if sent < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut code = 0;
    let pr = unsafe { libc::poll(&mut pfd, 1, 1000) };
    if pr > 0 {
        let mut buf = [0u8; 4096];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n >= 20 {
            let nl_type = u16::from_ne_bytes([buf[4], buf[5]]);
            if nl_type == NLMSG_ERROR {
                code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            }
        }
    }
    unsafe { libc::close(fd) };
    Ok(code)
}

/// Delete the observed flow's conntrack entry, best effort: a caller warns and never fails. Dead code.
#[allow(dead_code)]
pub fn del_orig(
    host: Ipv4Addr,
    host_port: u16,
    peer: Ipv4Addr,
    peer_port: u16,
) -> std::io::Result<()> {
    let code = ct_delete(&build_del_msg(host, host_port, peer, peer_port))?;
    match code {
        e if e == 0 || e == -libc::ENOENT => Ok(()),
        other => Err(std::io::Error::from_raw_os_error(other.unsigned_abs() as i32)),
    }
}

/// The --ct-probe bisect: create an entry from a fresh socket, try every encoding, print each acknowledgement code.
pub fn self_test() {
    use std::io::Write as _;
    let sock = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            emitln!("ct-probe: bind failed: {}", e);
            return;
        }
    };
    let hp = sock.local_addr().unwrap().port();
    // egress route on the router: default via eth1 → src 192.168.0.21
    let peer = (Ipv4Addr::new(1, 1, 1, 1), 9u16);
    let nat = (Ipv4Addr::new(192, 168, 0, 21), hp);
    let dst = std::net::SocketAddrV4::new(peer.0, peer.1);
    if let Err(e) = sock.send_to(b"x", dst) {
        emitln!("ct-probe: send failed: {}", e);
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut stdout = std::io::stdout();
    let _ = writeln!(
        &mut stdout,
        "ct-probe: entry ({},{}) -> ({},{}) created",
        nat.0, nat.1, peer.0, peer.1
    );
    let mut winners = Vec::new();
    let mut seen = 0u32; // re-create when a variant actually deleted
    for family in [AF_INET, 0u8] {
        for nested in [true, false] {
            for reply in [false, true] {
                for zone in [false, true] {
                    if seen > 0 {
                        let _ = sock.send_to(b"x", dst);
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                    let msg = build_msg(family, nested, reply, nat, peer, zone);
                    let code = ct_delete(&msg).unwrap_or(i32::MIN);
                    let label = format!(
                        "fam={} nested={} dir={} zone={}: code {}",
                        family,
                        nested,
                        if reply { "REPLY" } else { "ORIG" },
                        zone,
                        code
                    );
                    let _ = writeln!(&mut stdout, "  {}", label);
                    if code == 0 {
                        winners.push(label);
                        seen += 1;
                    }
                }
            }
        }
    }
    for w in &winners {
        let _ = writeln!(&mut stdout, "ct-probe: WORKING: {}", w);
    }
    let _ = writeln!(&mut stdout, "ct-probe: done (deleting variants: {})", winners.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn del_msg_wire_shape() {
        let m = build_del_msg(
            Ipv4Addr::new(192, 168, 21, 1),
            41077,
            Ipv4Addr::new(74, 125, 250, 129),
            19302,
        );
        // nlmsghdr: len, type CT_DELETE, flags REQUEST|ACK, seq 1
        assert_eq!(m.len() as u32, u32::from_ne_bytes(m[0..4].try_into().unwrap()));
        assert_eq!(
            u16::from_ne_bytes([m[4], m[5]]),
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE as u16
        );
        assert_eq!(u16::from_ne_bytes([m[6], m[7]]), NLM_F_REQUEST | NLM_F_ACK);
        // nfgenmsg: family AF_INET, version 0
        assert_eq!(m[16], AF_INET);
        assert_eq!(m[17], NFNETLINK_V0);
        // The tuple bytes are big-endian: original-tuple header, IP header, then the source octets.
        assert_eq!(&m[32..36], &[192, 168, 21, 1], "src ip octets");
        assert_eq!(&m[40..44], &[74, 125, 250, 129], "dst ip octets");
        // ports big-endian
        assert!(
            m.windows(2).any(|w| w == &[0xa0, 0x75]), // 41077 = 0xA075 big-endian
            "htons(41077) = 0xa0 0x75 must appear in the message"
        );
        assert!(
            m.windows(2).any(|w| w == &[0x4b, 0x66]), // 19302 = 0x4B66 big-endian
            "htons(19302) = 0x4b 0x66 must appear in the message"
        );
        assert!(!m.windows(2).any(|w| w == &[0x75, 0xa0]), "no host-order port");
    }

    #[test]
    fn dump_hex() {
        let m = build_del_msg(
            Ipv4Addr::new(192, 168, 21, 1),
            41077,
            Ipv4Addr::new(74, 125, 250, 129),
            19302,
        );
        let hex: String = m.iter().map(|b| format!("{:02x}", b)).collect();
        emitln!("MY  len {} hex {}", m.len(), hex);
    }
}