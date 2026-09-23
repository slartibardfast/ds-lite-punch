//! TCP slot datapath (call/0017). A listener on the slot's pin tuple
//! accepts AFTR-forwarded inbound connections and splices them to the
//! slot target. A persistent STUN-over-TCP connection from the same tuple
//! keeps the mapping alive at an interval under the C3 bound: an
//! idle AFTR TCP mapping survives 120 s of silence and dies by 300 s
//! (results/RESULTS-2026-09-13-c3.md), so the connection refreshes at a
//! interval strictly under the lower bound. The connection's XOR-MAPPED is
//! the slot's external TCP tuple, published per slot on churn. The
//! connection lifecycle is the Kani-proven state machine. The fw4 TCP input
//! accept is mandatory for the splice: the box drops forwarded TCP NEW
//! silently (the C3 finding).

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

/// Keepalive interval for a TCP slot, strictly under the C3 silent-death
/// lower bound (120 s). See the Kani proof `cadence_under_bound`.
pub const TCP_KEEPALIVE_SECS: u64 = 60;

// ---- connection lifecycle (the Kani-provable part) ----

/// The mapping's connection state machine. Live means a live STUN-over-TCP
/// connection from the pin tuple, hence a live AFTR TCP mapping; Dead
/// means the connection errored (RST or silent expiry) and the mapping
/// is re-establishing on the next interval.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionState {
    Live,
    Dead,
}

impl ConnectionState {
    pub fn is_live(&self) -> bool {
        *self == ConnectionState::Live
    }

    /// A connection error kills the live mapping: Dead.
    pub fn on_error(&mut self) {
        if *self == ConnectionState::Live {
            *self = ConnectionState::Dead;
        }
    }

    /// Re-establishment restores the mapping: Live.
    pub fn on_established(&mut self) {
        *self = ConnectionState::Live;
    }
}

// ---- runtime ----

/// Bind the slot's TCP pin. The listener binds WILDCARD: the connection must
/// own the specific (ip, R) tuple to originate the outbound flow that
/// creates and maintains the AFTR mapping, and a specific bind beside a
/// specific listener is EADDRINUSE under every SO_REUSE* combination
/// (verified on this kernel 2026-09-13: reuseaddr+reuseaddr refused,
/// reuseport+reuseport misroutes inbound SYNs into the non-listening
/// connection, reuseport-listener + reuseaddr-connection refuses the connection).
/// The specific-vs-wildcard bind is SO_REUSEADDR's classic exception:
/// no REUSEPORT group exists, so inbound SYNs (dst the slot's tuple)
/// reach this listener's accept queue, the connection's established replies
/// reach it, and eth1-scoping of inbound is enforced by the nft input
/// accept, not by the bind.
pub async fn bind_pin(r: u16) -> io::Result<TcpListener> {
    let sock = tokio::net::TcpSocket::new_v4()?;
    sock.set_reuseaddr(true)?;
    sock.bind(std::net::SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        r,
    )))?;
    sock.listen(128)
}

/// The accept loop: each inbound connection (the AFTR forwarding a peer
/// SYN through the slot's TCP mapping) is spliced to the slot target.
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

/// Bidirectional copy between the accepted peer and the slot target.
/// Kernel-dominated (copy_bidirectional); the lifecycle around it is
/// minimal: one dial per accept, dial failure closes the peer, copy end
/// closes both.
async fn splice(mut peer: TcpStream, target: SocketAddrV4) {
    match TcpStream::connect(target).await {
        Ok(mut upstream) => {
            let _ = tokio::io::copy_bidirectional(&mut peer, &mut upstream).await;
        }
        Err(_) => {}
    }
}

/// One connection round: open the STUN-over-TCP connection and read the
/// observed external tuple. The connection originates from an EPHEMERAL
/// local port folded to the slot's tuple by the relay's own nft snat_map
/// (add_pin below): the AFTR's mapping is created for (bind_ip, r)
/// without a second socket ever binding that tuple, which this kernel
/// refuses beside the wildcard listener (verified 2026-09-13 across all
/// SO_REUSE* combinations). The fold element is cleaned up on
/// re-establish; the connection is returned to be held.
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

/// The connection task: at each interval, refresh the persistent connection
/// (the STUN traffic re-arms the AFTR idle timer) and publish the
/// observed tuple on churn; on connection error, drop it and re-establish
/// on the next interval, rotating servers.
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
            // Refresh the held connection: the STUN traffic re-arms the
            // AFTR idle timer.
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
            // Dead: re-establish on the next interval, rotating servers.
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
        // C3: an idle AFTR TCP mapping survives 120 s of silence and
        // dies by 300 s on the measured node/session. The connection refresh
        // interval must sit strictly under the silent-death lower bound so
        // a reachable mapping is refreshed before the AFTR can expire it.
        assert!(TCP_KEEPALIVE_SECS < 120);
        assert!(TCP_KEEPALIVE_SECS > 0);
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn holder_cycles_through_both_states_without_unknown() {
        // Reachability: the two-state machine cycles Held -> Dead (error)
        // and Dead -> Held (re-establish) with no other state; a sequence
        // of error/established transitions alternates strictly.
        let mut h = ConnectionState::Dead;
        for i in 0..3 {
            if i % 2 == 0 {
                h.on_established();
            } else {
                h.on_error();
            }
            // The state is always one of the two variants; Held after an
            // established, Dead after an error.
            assert!(match h {
                ConnectionState::Live => i % 2 == 0,
                ConnectionState::Dead => i % 2 == 1,
            });
        }
    }
}