//! TCP slot datapath: the listener splices AFTR-forwarded connections, and a STUN link keeps the mapping.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::publish::Publisher;
use crate::stun;
use crate::vote::{VoteDecision, VoteState};

/// Keepalive interval for a TCP slot, strictly under the on-box 120 s silent-death bound.
pub const TCP_KEEPALIVE_SECS: u64 = 60;

/// The mapping's connection state: Live while a STUN-over-TCP connection is up, Dead once it errored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionState {
    Live,
    Dead,
}

impl ConnectionState {
    pub fn is_live(&self) -> bool {
        *self == ConnectionState::Live
    }

    /// A connection error kills the live mapping.
    pub fn on_error(&mut self) {
        if *self == ConnectionState::Live {
            *self = ConnectionState::Dead;
        }
    }

    /// Re-establishment restores the mapping.
    pub fn on_established(&mut self) {
        *self = ConnectionState::Live;
    }
}

/// Binds wildcard, so the connection can own the slot's tuple while the listener still queues its SYNs.
pub async fn bind_pin(r: u16) -> io::Result<TcpListener> {
    let sock = tokio::net::TcpSocket::new_v4()?;
    sock.set_reuseaddr(true)?;
    sock.bind(std::net::SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        r,
    )))?;
    sock.listen(128)
}

/// Accepts each AFTR-forwarded connection on the slot's mapping and splices it to the target.
pub async fn run_tcp_slot(listener: TcpListener, target: SocketAddrV4) {
    loop {
        match listener.accept().await {
            Ok((peer, _)) => {
                tokio::spawn(splice(peer, target));
            }
            Err(_) => continue,
        }
    }
}

/// One dial per accept; the copy dominates, and a failed dial closes the peer.
async fn splice(mut peer: TcpStream, target: SocketAddrV4) {
    match TcpStream::connect(target).await {
        Ok(mut upstream) => {
            let _ = tokio::io::copy_bidirectional(&mut peer, &mut upstream).await;
        }
        Err(_) => {}
    }
}

/// Opens the STUN connection from an ephemeral port the relay's own snat_map folds to the slot's tuple.
async fn connection_round(
    bind_ip: Ipv4Addr,
    r: u16,
    server: SocketAddrV4,
) -> io::Result<((Ipv4Addr, u16), TcpStream, u16)> {
    let sock = tokio::net::TcpSocket::new_v4()?;
    sock.set_reuseaddr(true)?;
    sock.bind(std::net::SocketAddr::V4(SocketAddrV4::new(bind_ip, 0)))?;
    let local_port = sock.local_addr()?.port();
    crate::nft::add_pin(bind_ip, local_port, r).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("connection fold pin: {e}"))
    })?;
    let mut conn = sock
        .connect(std::net::SocketAddr::V4(server))
        .await?;
    let txn = stun::random_txn();
    conn.write_all(&stun::binding_request(&txn)).await?;
    let mut buf = [0u8; 2048];
    let n = conn.read(&mut buf).await?;
    let tuple = stun::parse_mapped(&buf[..n])
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "connection STUN: no mapped tuple"))?;
    Ok((tuple, conn, local_port))
}

/// Refreshes the held connection each interval and re-establishes on error, rotating servers.
pub async fn run_connection(
    bind_ip: Ipv4Addr,
    r: u16,
    servers: Vec<SocketAddrV4>,
    vote: Arc<Mutex<VoteState>>,
    publisher: Arc<Publisher>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(TCP_KEEPALIVE_SECS));
    let mut state = ConnectionState::Dead;
    let mut conn: Option<TcpStream> = None;
    let mut last_local: Option<u16> = None;
    let mut server_idx = 0usize;
    loop {
        interval.tick().await;
        if state.is_live() && conn.is_some() {
            // Refresh the held connection: the STUN traffic re-arms the AFTR idle timer.
            let Some(c) = conn.as_mut() else {
                continue;
            };
            let txn = stun::random_txn();
            let mut buf = [0u8; 2048];
            let result = async {
                c.write_all(&stun::binding_request(&txn)).await?;
                let n = c.read(&mut buf).await?;
                stun::parse_mapped(&buf[..n])
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "connection refresh: no mapped"))
            }
            .await;
            match result {
                Ok(tuple) => {
                    let mut v = vote.lock().await;
                    if let VoteDecision::Churn(t) = v.observe(server_idx, tuple) {
                        publisher.publish_slot(r, t.0, t.1);
                    }
                }
                Err(_) => {
                    state.on_error();
                    conn = None;
                }
            }
        } else {
            // Dead: re-establish next interval, rotating servers, after deleting the previous fold.
            state.on_error();
            conn = None;
            if let Some(lp) = last_local.take() {
                let _ = crate::nft::del_pin(bind_ip, lp);
            }
            server_idx = (server_idx + 1) % servers.len();
            match connection_round(bind_ip, r, servers[server_idx]).await {
                Ok((tuple, c, lp)) => {
                    conn = Some(c);
                    last_local = Some(lp);
                    state.on_established();
                    let mut v = vote.lock().await;
                    if let VoteDecision::Churn(t) = v.observe(server_idx, tuple) {
                        publisher.publish_slot(r, t.0, t.1);
                    }
                }
                Err(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_state_transitions() {
        let mut h = ConnectionState::Dead;
        assert!(!h.is_live());
        h.on_established();
        assert!(h.is_live());
        h.on_error();
        assert!(!h.is_live());
        h.on_error(); // error from Dead is idempotent
        assert!(!h.is_live());
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn cadence_under_bound() {
        // The harness asserts the interval is non-zero and strictly under the 120 s bound.
        assert!(TCP_KEEPALIVE_SECS < 120);
        assert!(TCP_KEEPALIVE_SECS > 0);
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn holder_cycles_through_both_states_without_unknown() {
        // The harness drives three alternating transitions and asserts the state each one leaves.
        let mut h = ConnectionState::Dead;
        for i in 0..3 {
            if i % 2 == 0 {
                h.on_established();
            } else {
                h.on_error();
            }
            assert!(match h {
                ConnectionState::Live => i % 2 == 0,
                ConnectionState::Dead => i % 2 == 1,
            });
        }
    }
}