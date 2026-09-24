//! Source-preserving UDP forward: an `IP_TRANSPARENT` socket bound to the peer's (ip, port).
use std::io;
use std::net::SocketAddrV4;

const IP_TRANSPARENT: libc::c_int = 19;

pub fn forward(pkt: &[u8], peer: SocketAddrV4, target: SocketAddrV4) -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_TRANSPARENT,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let peer_addr = to_sockaddr_in(peer);
        if libc::bind(
            fd,
            &peer_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let target_addr = to_sockaddr_in(target);
        let n = libc::sendto(
            fd,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &target_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::close(fd);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn to_sockaddr_in(a: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: a.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*a.ip()).to_be(),
        },
        sin_zero: [0; 8],
    }
}
