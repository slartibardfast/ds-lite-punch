//! The observation refresh engine: it claims flows, spawns a shadow keepalive per flow, and releases them.
use crate::cdc::Cdc;
use crate::forward;
use crate::nft;
use crate::publish::Publisher;
use crate::slot::LeaseTable;
use crate::stun;
use crate::vote::VoteState;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use crate::publish::{emiteln};

/// Engine interval: 2 s, well under the AFTR's 5 to 10 s idle timeout.
pub const TICK: Duration = Duration::from_secs(2);
/// Ticks an entry must be missing from the CDC with no inbound before the flow is presumed dead.
pub const DEFAULT_GRACE_TICKS: u32 = 3;

/// Why a flow's keepalive ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// A static or lease slot has claimed the inner tuple.
    OwnedBySlot,
    /// The entry is gone from the CDC with no inbound within the grace: the flow is dead.
    Stale,
    /// The device stopped answering on the LAN, so a keepalive releases nothing anyone uses.
    DeviceGone,
}

/// The claim gate: never an owned tuple, and never past the refresh budget.
pub fn claim_allowed(
    bind: (Ipv4Addr, u16),
    owned: &[(Ipv4Addr, u16)],
    active: usize,
    max_refresh_attempts: u32,
) -> bool {
    !owned.contains(&bind) && (active as u64) < (max_refresh_attempts as u64)
}

/// The exit decision from the missing-tick and silence counters.
pub fn exit_due(
    missing_ticks: u32,
    grace_ticks: u32,
    ticks_since_inbound: u32,
    owned_now: bool,
) -> Option<ExitReason> {
    if owned_now {
        return Some(ExitReason::OwnedBySlot);
    }
    if missing_ticks >= grace_ticks && ticks_since_inbound >= grace_ticks {
        return Some(ExitReason::Stale);
    }
    None
}

/// The pin, unpin and accept operations a claim performs; tests inject no-ops.
pub trait PinOps: Send + Sync {
    fn add(&self, host: Ipv4Addr, host_port: u16, r: u16) -> std::io::Result<()>;
    fn del(&self, host: Ipv4Addr, host_port: u16);
    /// Per-port input accept: fw4 would drop an inbound datagram that no established flow covers.
    fn accept(&self, r: u16) -> std::io::Result<()>;
    fn unaccept(&self, r: u16);
}

pub struct NftPins;

impl PinOps for NftPins {
    /// Installs only the shadow's self-pin; the device's own pin is a separate call.
    fn add(&self, _host: Ipv4Addr, _host_port: u16, r: u16) -> std::io::Result<()> {
        nft::add_pin(nft::NAT_ADDR, r, r)
    }
    /// Removes a self-pin only, guarded by the NAT address; a device-key element is not ours to take away.
    fn del(&self, host: Ipv4Addr, host_port: u16) {
        if host == nft::NAT_ADDR {
            let _ = nft::del_pin(host, host_port);
        }
    }
    fn accept(&self, r: u16) -> std::io::Result<()> {
        nft::add_input_accept(r, false)
    }
    fn unaccept(&self, r: u16) {
        let _ = nft::del_input_accept(r, false);
    }
}

/// One refreshed flow.
struct ObsSlot {
    host: Ipv4Addr,
    host_port: u16,
    bind_tuple: (Ipv4Addr, u16),
    external: Option<(Ipv4Addr, u16)>,
    /// The per-flow vote, so the report carries the decision as well as the learned tuple.
    vote: Arc<Mutex<VoteState>>,
    /// Wall-clock second this flow was last seen live.
    last_seen_unix: u64,
    /// The device's own packet count for this tuple, as the connection table last reported it.
    dev_pkts: u64,
    /// Consecutive ticks with neither the device nor a peer touching the tuple.
    quiet_ticks: u32,
    /// Consecutive failed LAN probes for this slot's device.
    dev_misses: u8,
    missing_ticks: u32,
    ticks_since_inbound: u32,
    /// inbound counter value the engine last saw (task bumps on forward)
    last_inbound_seen: u64,
    stop: Arc<AtomicBool>,
    inbound_ts: Arc<AtomicU64>,
    external_arc: Arc<Mutex<Option<(Ipv4Addr, u16)>>>,
}

pub struct ObservationEngine {
    cdc: Box<dyn Cdc>,
    owned: Vec<(Ipv4Addr, u16)>,
    max_refresh_attempts: u32,
    grace_ticks: u32,
    servers: Vec<SocketAddrV4>,
    publisher: Arc<Publisher>,
    pins: Arc<dyn PinOps>,
    slots: Vec<ObsSlot>,
    /// The devices this arm may act for; an empty list leaves it the admission it already had.
    pub allow: Vec<Ipv4Addr>,
    /// Whether the arm holds and promotes, or only reports.
    pub hold: bool,
    /// Tuples already reported in log-only mode, so the line appears once per flow rather than per tick.
    reported: std::collections::HashSet<(Ipv4Addr, u16)>,
    /// The live lease table, when this arm runs beside the facade: the tuples an allocation holds, read live.
    pub alloc: Option<Arc<Mutex<LeaseTable>>>,
    /// The address the slots bind, so their tuples can be named.
    pub bind_ip: Ipv4Addr,
    /// Ticks since start, for the probe throttle and its round robin.
    ticks: u64,
    /// Which slot the next device probe looks at.
    probe_cursor: usize,
    /// The per-device hold cap.
    per_host: u32,
    /// Candidates not yet held, with the device's last packet count and its quiet ticks.
    young: std::collections::HashMap<(Ipv4Addr, u16), (u64, u32)>,
}

impl ObservationEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cdc: Box<dyn Cdc>,
        owned: Vec<(Ipv4Addr, u16)>,
        max_refresh_attempts: u32,
        grace_ticks: u32,
        servers: Vec<SocketAddrV4>,
        publisher: Arc<Publisher>,
        pins: Arc<dyn PinOps>,
    ) -> Self {
        ObservationEngine {
            cdc,
            owned,
            max_refresh_attempts,
            grace_ticks,
            servers,
            publisher,
            pins,
            slots: Vec::new(),
            allow: Vec::new(),
            hold: true,
            reported: std::collections::HashSet::new(),
            alloc: None,
            bind_ip: Ipv4Addr::UNSPECIFIED,
            ticks: 0,
            probe_cursor: 0,
            per_host: 4,
            young: std::collections::HashMap::new(),
        }
    }

    pub fn name(&self) -> &'static str {
        self.cdc.name()
    }

    pub async fn run(mut self) {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            self.tick().await;
        }
    }

    /// The tuples an allocation holds now: the static snapshot plus any grant made since.
    async fn owned_now(&self) -> Vec<(Ipv4Addr, u16)> {
        let mut owned = self.owned.clone();
        if let Some(t) = &self.alloc {
            for s in t.lock().await.slots() {
                owned.push((self.bind_ip, s.bind_port));
            }
        }
        owned
    }

    async fn tick(&mut self) {
        let owned = self.owned_now().await;
        let live: Vec<crate::cdc::Candidate> = self.cdc.tick();

        // An empty allowlist keeps the predicate's admission; a set one narrows the arm to the named devices.
        let live: Vec<crate::cdc::Candidate> = if self.allow.is_empty() {
            live
        } else {
            live.into_iter()
                .filter(|c| crate::keepalive::allowed(&self.allow, c.host))
                .collect()
        };
        if !self.hold {
            self.report_only(&live);
            return;
        }
        // The report set follows the live set in either mode, so a gone tuple keeps no place in it.
        self.reported.retain(|t| live.iter().any(|c| c.bind_tuple == *t));

        // Per-slot bookkeeping: a CDC entry resets the miss counter, and an inbound change resets silence.
        for s in self.slots.iter_mut() {
            s.missing_ticks = if live.iter().any(|c| c.bind_tuple == s.bind_tuple) {
                0
            } else {
                s.missing_ticks.saturating_add(1)
            };
            let ts = s.inbound_ts.load(Ordering::Relaxed);
            if ts != s.last_inbound_seen {
                s.last_inbound_seen = ts;
                s.ticks_since_inbound = 0;
            } else {
                s.ticks_since_inbound = s.ticks_since_inbound.saturating_add(1);
            }
            // Once the shadow sees a STUN reply, record the flow's live external tuple.
            if live.iter().any(|c| c.bind_tuple == s.bind_tuple) {
                s.last_seen_unix = unix_now();
            }
            let seen = *s.external_arc.lock().await;
            if let Some(t) = observe_report(s.external, seen) {
                s.external = Some(t);
                // Report the vote's decision beside the tuple it learned, so the two cannot disagree.
                let decision = s.vote.lock().await.observe(0, t);
                self.publisher.log_transition(
                    "observed-tuple",
                    &format!("{}:{} -> {}:{} ({:?})", s.host, s.host_port, t.0, t.1, decision),
                );
            }
        }

        // Claims: fresh candidates only, through the owned-tuple and budget gate.
        for c in &live {
            if self.slots.iter().any(|s| s.bind_tuple == c.bind_tuple) {
                continue; // already refreshed
            }
            let (_, quiet) = self
                .young
                .get(&c.bind_tuple)
                .copied()
                .unwrap_or((c.host_port as u64, 0));
            if quiet < KEEPALIVE_AFTER_TICKS {
                // the device is still refreshing this flow, so it needs nothing
                continue;
            }
            if !host_budget_ok(c.host, &self.slots, self.per_host) {
                // one device's churn cannot spend another device's capacity
                continue;
            }
            if !claim_allowed(c.bind_tuple, &owned, self.slots.len(), self.max_refresh_attempts) {
                // A tuple a slot holds is refused rather than captured, and the refusal is reported.
                if owned.contains(&c.bind_tuple) && self.reported.insert(c.bind_tuple) {
                    self.publisher.log_transition(
                        "collision-reported",
                        &format!(
                            "{}:{} shares tuple {} with a slot that holds it",
                            c.host, c.host_port, c.bind_tuple.1
                        ),
                    );
                }
                continue;
            }
            let bind = SocketAddr::V4(SocketAddrV4::new(c.bind_tuple.0, c.bind_tuple.1));
            let sock = match UdpSocket::bind(bind).await {
                Ok(s) => s,
                Err(e) => {
                    emiteln!("warn: shadow bind {} failed: {}", bind, e);
                    continue;
                }
            };
            // Self-pin: the keepalive must egress as (NAT, R_nat), or the kernel NAPT's it elsewhere.
            if let Err(e) = self.pins.add(c.bind_tuple.0, c.bind_tuple.1, c.bind_tuple.1) {
                emiteln!("warn: shadow self-pin {} failed: {}", c.bind_tuple.1, e);
                drop(sock);
                continue;
            }
            if let Err(e) = self.pins.add(c.host, c.host_port, c.bind_tuple.1) {
                emiteln!(
                    "warn: shadow pin {}:{} -> {} failed: {}",
                    c.host, c.host_port, c.bind_tuple.1, e
                );
                let _ = self.pins.del(c.bind_tuple.0, c.bind_tuple.1);
                drop(sock);
                continue;
            }
            if let Err(e) = self.pins.accept(c.bind_tuple.1) {
                emiteln!("warn: shadow accept {} failed: {}", c.bind_tuple.1, e);
                let _ = self.pins.del(c.host, c.host_port);
                let _ = self.pins.del(c.bind_tuple.0, c.bind_tuple.1);
                drop(sock);
                continue;
            }
            let stop = Arc::new(AtomicBool::new(false));
            let inbound_ts = Arc::new(AtomicU64::new(unix_now()));
            let vote = Arc::new(Mutex::new(VoteState::new()));
            let external = Arc::new(Mutex::new(None));
            spawn_shadow(
                sock,
                c.host,
                c.host_port,
                self.servers.clone(),
                stop.clone(),
                inbound_ts.clone(),
                external.clone(),
            );
            self.publisher.log_transition(
                "refresh",
                &format!(
                    "claim {}:{} -> {}:{} -> {} (cdc {})",
                    c.host,
                    c.host_port,
                    c.peer.0,
                    c.peer.1,
                    c.bind_tuple.1,
                    self.cdc.name()
                ),
            );
            self.slots.push(ObsSlot {
                host: c.host,
                host_port: c.host_port,
                bind_tuple: c.bind_tuple,
                external: None,
                vote,
                last_seen_unix: unix_now(),
                dev_pkts: 0,
                quiet_ticks: 0,
                dev_misses: 0,
                missing_ticks: 0,
                ticks_since_inbound: 0,
                last_inbound_seen: inbound_ts.load(Ordering::Relaxed),
                stop,
                inbound_ts,
                external_arc: external,
            });
        }

        // Liveness pass: only the device's packets or a peer's inbound keep a hold alive, never our writes.
        self.ticks += 1;
        // Age the young: the device's packets reset quiet, so only a flow it stopped refreshing is held.
        if !live.is_empty() {
            let proc_text = std::fs::read_to_string("/proc/net/nf_conntrack").ok();
            for c in live.iter() {
                let pkts = proc_text
                    .as_deref()
                    .map(|t| device_packets(t, c.bind_tuple, c.host))
                    .unwrap_or(0);
                let e = self.young.entry(c.bind_tuple).or_insert((pkts, 0));
                if pkts > e.0 {
                    e.0 = pkts;
                    e.1 = 0;
                } else {
                    let (last, quiet) = (e.0, e.1);
                    *e = (last.max(pkts), quiet.saturating_add(1));
                }
            }
            let live_set: std::collections::HashSet<(Ipv4Addr, u16)> =
                live.iter().map(|c| c.bind_tuple).collect();
            self.young.retain(|t, _| live_set.contains(t));
        }
        if !self.slots.is_empty() {
            let proc_text = std::fs::read_to_string("/proc/net/nf_conntrack").ok();
            for s in self.slots.iter_mut() {
                let dev_now = proc_text
                    .as_deref()
                    .map(|t| device_packets(t, s.bind_tuple, s.host))
                    .unwrap_or(s.dev_pkts);
                let device_active = dev_now > s.dev_pkts;
                s.dev_pkts = dev_now;
                let peer_active = s.ticks_since_inbound == 0;
                if device_active || peer_active {
                    s.quiet_ticks = 0;
                } else {
                    s.quiet_ticks = s.quiet_ticks.saturating_add(1);
                }
            }
            // One device probe per throttle window, round robin, so a tick never blocks on two.
            if self.ticks % PROBE_EVERY_TICKS == 0 {
                if self.probe_cursor >= self.slots.len() {
                    self.probe_cursor = 0;
                }
                if let Some(s) = self.slots.get_mut(self.probe_cursor) {
                    let host = s.host;
                    if crate::presence::device_up(host) {
                        for s in self.slots.iter_mut().filter(|s| s.host == host) {
                            s.dev_misses = 0;
                        }
                    } else {
                        for s in self.slots.iter_mut().filter(|s| s.host == host) {
                            s.dev_misses = s.dev_misses.saturating_add(1);
                        }
                    }
                }
                self.probe_cursor = self.probe_cursor.saturating_add(1);
            }
        }

        // Exit pass: held-by-slot is instant, and stale needs the entry gone and no inbound, both past grace.
        let mut i = 0;
        while i < self.slots.len() {
            let (t, missing, since_inbound, stop) = {
                let s = &self.slots[i];
                (
                    s.bind_tuple,
                    s.missing_ticks,
                    s.ticks_since_inbound,
                    s.stop.clone(),
                )
            };
            let owned_now = owned.contains(&t);
            let (quiet, misses) = {
                let s = &self.slots[i];
                (s.quiet_ticks, s.dev_misses)
            };
            let reason = release_reason(
                owned_now,
                misses,
                quiet,
                missing,
                since_inbound,
                LONG_QUIET_TICKS,
            );
            if let Some(r) = reason {
                stop.store(true, Ordering::Relaxed);
                let gone = self.slots.swap_remove(i);
                let _ = self.pins.del(gone.host, gone.host_port);
                let _ = self.pins.del(gone.bind_tuple.0, gone.bind_tuple.1); // self-pin
                self.pins.unaccept(gone.bind_tuple.1);
                let silent_s = unix_now().saturating_sub(gone.last_seen_unix);
                self.publisher.log_transition(
                    "refresh-exit",
                    &format!(
                        "{}:{} (reason {:?}, last seen {}s ago)",
                        gone.host, gone.host_port, r, silent_s
                    ),
                );
                continue;
            }
            i += 1;
        }
    }
}

/// Whether the observed tuple is worth reporting: the first look, or a tuple that has moved.
fn observe_report(
    prev: Option<(Ipv4Addr, u16)>,
    now: Option<(Ipv4Addr, u16)>,
) -> Option<(Ipv4Addr, u16)> {
    match now {
        Some(t) if prev != Some(t) => Some(t),
        _ => None,
    }
}

/// Ticks a flow must be quiet before it is held, so one the device still refreshes is never claimed.
const KEEPALIVE_AFTER_TICKS: u32 = 3;
/// Ticks both sides must leave a hold alone before the backstop releases it.
const LONG_QUIET_TICKS: u32 = 150;
/// Consecutive failed LAN probes before a keepalive is released as abandoned.
const DEV_MISSES_TO_RELEASE: u8 = 3;
/// Probe one slot's device every this many ticks, so a tick blocks on one probe at most.
const PROBE_EVERY_TICKS: u64 = 3;

/// The one place a keepalive's end is decided; pure, so the policy is testable without a clock.
fn release_reason(
    owned_now: bool,
    misses: u8,
    quiet: u32,
    missing: u32,
    since_inbound: u32,
    long_quiet: u32,
) -> Option<ExitReason> {
    if owned_now {
        return Some(ExitReason::OwnedBySlot);
    }
    if misses >= DEV_MISSES_TO_RELEASE {
        return Some(ExitReason::DeviceGone);
    }
    match exit_due(missing, long_quiet, since_inbound, false) {
        Some(r) => Some(r),
        None if quiet >= long_quiet => Some(ExitReason::Stale),
        None => None,
    }
}

/// Sums the table entries on a tuple whose origin is the device, so our own writes cannot vouch for liveness.
fn device_packets(proc_text: &str, bind: (Ipv4Addr, u16), host: Ipv4Addr) -> u64 {
    proc_text
        .lines()
        .filter_map(crate::obs::parse_line)
        .filter(|e| e.nat_src() == bind && e.orig_src == host)
        .map(|e| e.orig_packets)
        .sum()
}

/// A device's own hold budget: one device's churn cannot spend another's capacity.
fn host_budget_ok(host: Ipv4Addr, slots: &[ObsSlot], per_host: u32) -> bool {
    let mine = slots.iter().filter(|s| s.host == host).count() as u64;
    mine < per_host as u64
}

/// The log-only stage: reports each named device's live flow once and touches nothing.
impl ObservationEngine {
    fn report_only(&mut self, live: &[crate::cdc::Candidate]) {
        self.reported
            .retain(|t| live.iter().any(|c| c.bind_tuple == *t));
        for c in live {
            if self.reported.insert(c.bind_tuple) {
                self.publisher.log_transition(
                    "observe",
                    &format!(
                        "{}:{} -> {} (cdc {}, would hold)",
                        c.host, c.host_port, c.bind_tuple.1, self.cdc.name()
                    ),
                );
            }
        }
    }
}

/// The per-flow shadow task: a keepalive each tick, and inbound datagrams forwarded to the host:port.
fn spawn_shadow(
    sock: UdpSocket,
    host: Ipv4Addr,
    host_port: u16,
    servers: Vec<SocketAddrV4>,
    stop: Arc<AtomicBool>,
    inbound_ts: Arc<AtomicU64>,
    external: Arc<Mutex<Option<(Ipv4Addr, u16)>>>,
) {
    tokio::spawn(async move {
        let target = SocketAddrV4::new(host, host_port);
        let mut cursor = 0usize;
        let mut ticker = tokio::time::interval(Duration::from_secs(2));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut buf = vec![0u8; 2048];
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if !servers.is_empty() {
                        // Stick to one server: a second flow from this port gets NAPT'd onto another tuple.
                        let server = servers[cursor % servers.len()];
                        let txn = stun::random_txn();
                        let req = stun::binding_request(&txn);
                        if let Err(e) = sock.send_to(&req, server).await {
                            emiteln!("warn: shadow keepalive {} failed: {}", server, e);
                            cursor = cursor.wrapping_add(1);
                        }
                    }
                }
                r = sock.recv_from(&mut buf) => match r {
                    Ok((n, src)) => {
                        let pkt = &buf[..n];
                        let SocketAddr::V4(v4) = src else { continue };
                        if servers.iter().any(|s| *s == v4) {
                            // a STUN reply carries the flow's live external tuple.
                            if let Some(t) = stun::parse_mapped(pkt) {
                                *external.lock().await = Some(t);
                            }
                        } else {
                            // a peer datagram is promoted to the observed host:port.
                            match forward::forward(pkt, v4, target) {
                                Ok(()) => {
                                    inbound_ts.store(unix_now(), Ordering::Relaxed);
                                }
                                Err(e) => emiteln!(
                                    "warn: shadow forward {} -> {} failed: {}",
                                    v4, target, e
                                ),
                            }
                        }
                    }
                    Err(e) => emiteln!("warn: shadow recv: {}", e),
                },
            }
        }
    });
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeCdc {
        cands: Vec<crate::cdc::Candidate>,
    }
    impl Cdc for FakeCdc {
        fn tick(&mut self) -> Vec<crate::cdc::Candidate> {
            self.cands.clone()
        }
        fn name(&self) -> &'static str {
            "fake"
        }
    }

    struct NopPins;
    impl PinOps for NopPins {
        fn add(&self, _h: Ipv4Addr, _p: u16, _r: u16) -> std::io::Result<()> {
            Ok(())
        }
        fn del(&self, _h: Ipv4Addr, _p: u16) {}
        fn accept(&self, _r: u16) -> std::io::Result<()> {
            Ok(())
        }
        fn unaccept(&self, _r: u16) {}
    }

    /// Ticks until a candidate has been quiet long enough to be held.
    async fn age(e: &mut ObservationEngine, ticks: usize) {
        for _ in 0..ticks {
            e.tick().await;
        }
    }

    fn cand(bind: (Ipv4Addr, u16), host: Ipv4Addr, hp: u16) -> crate::cdc::Candidate {
        crate::cdc::Candidate {
            bind_tuple: bind,
            host,
            host_port: hp,
            peer: (Ipv4Addr::new(8, 8, 8, 8), 53),
        }
    }

    fn engine(cdc: Box<dyn Cdc>, owned: Vec<(Ipv4Addr, u16)>, max: u32, grace: u32) -> ObservationEngine {
        ObservationEngine::new(
            cdc,
            owned,
            max,
            grace,
            Vec::new(),
            Arc::new(Publisher::with_watch("/tmp/dslp-test", tokio::sync::watch::channel(Ipv4Addr::UNSPECIFIED).0)),
            Arc::new(NopPins),
        )
    }

    // Loopback NAT for tests: the engine binds whatever the CDC reports.
    const LO: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 21, 50);

    #[tokio::test]
    async fn claims_live_candidate_once() {
        // distinct ports per test: a shadow task holds its socket for the test's runtime.
        let c = cand((LO, 54322), HOST, 54322);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c] }), Vec::new(), 8, 3);
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1);
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await; // same candidate again: no duplicate claim
        assert_eq!(e.slots.len(), 1);
        assert_eq!(e.slots[0].missing_ticks, 0);
    }

    #[tokio::test]
    async fn budget_limits_claims() {
        let c1 = cand((LO, 54324), HOST, 54324);
        let c2 = cand((LO, 54325), HOST, 54325);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c1, c2] }), Vec::new(), 1, 3);
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1, "budget 1 blocks the second claim");
    }

    #[tokio::test]
    async fn held_candidate_not_claimed() {
        let c = cand((LO, 54326), HOST, 54326);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c] }), vec![(LO, 54326)], 8, 3);
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert!(e.slots.is_empty(), "I1: owned tuple never claimed");
    }

    #[tokio::test]
    async fn a_quiet_hold_is_kept_not_released() {
        // An entry gone from the CDC with no inbound is what a lobby looks like, so it is kept.
        let h = HOST;
        let mut e = engine(
            Box::new(FakeCdc { cands: vec![cand((LO, 54360), h, 54360)] }),
            Vec::new(),
            8,
            3,
        );
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1, "the flow is held");
        {
            let s = &mut e.slots[0];
            s.missing_ticks = 99;
            s.ticks_since_inbound = 99;
            s.quiet_ticks = 4;
            s.dev_misses = 0;
        }
        e.tick().await;
        assert_eq!(e.slots.len(), 1, "quiet is what the keepalive is for");
    }

    #[tokio::test]
    async fn a_device_outside_the_allowlist_is_never_claimed() {
        // The arm acts for named devices only: a flow outside the list is not held, however live it is.
        let named = Ipv4Addr::new(192, 168, 21, 68);
        let other = Ipv4Addr::new(192, 168, 21, 59);
        let mut e = engine(Box::new(FakeCdc {
            cands: vec![
                cand((LO, 54340), named, 54340),
                cand((LO, 54341), other, 54341),
            ],
        }), Vec::new(), 8, 3);
        e.allow = vec![named];
        e.hold = true;
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1, "only the named device's flow is held");
        assert_eq!(e.slots[0].host, named);
    }

    #[tokio::test]
    async fn the_log_only_stage_holds_nothing() {
        // Log-only: the arm reports what it would act on and touches nothing.
        let named = Ipv4Addr::new(192, 168, 21, 68);
        let mut e = engine(Box::new(FakeCdc {
            cands: vec![cand((LO, 54342), named, 54342)],
        }), Vec::new(), 8, 3);
        e.allow = vec![named];
        e.hold = false;
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert!(e.slots.is_empty(), "log-only: nothing claimed");
        assert!(e.reported.contains(&(LO, 54342)), "but it is reported");
        // a device outside the list is not even reported
        assert!(!e.reported.contains(&(LO, 54343)));
    }

    #[test]
    fn liveness_is_the_device_s_packets_and_never_our_own() {
        // The tuple is (192.168.0.21, 3074); the device is the console.
        let bind = (Ipv4Addr::new(192, 168, 0, 21), 3074);
        let host = Ipv4Addr::new(192, 168, 21, 138);
        // the console's own store to a peer: origin is the console
        let dev = "ipv4 2 udp 17 180 src=192.168.21.138 dst=185.34.107.129 sport=3074 dport=3074 \
                   packets=9 bytes=540 src=185.34.107.129 dst=192.168.0.21 sport=3074 dport=3074 \
                   packets=2 bytes=90 mark=0 zone=0 use=2";
        // our shadow's keepalive: NAT side the same, origin the NAT address
        let ours = "ipv4 2 udp 17 300 src=192.168.0.21 dst=162.159.207.0 sport=3074 dport=3478 \
                    packets=41 bytes=1968 src=162.159.207.0 dst=192.168.0.21 sport=3478 dport=3074 \
                    packets=41 bytes=2460 [ASSURED] mark=0 zone=0 use=2";
        assert_eq!(device_packets(dev, bind, host), 9, "the device's own count");
        assert_eq!(device_packets(ours, bind, host), 0, "our writes are not the device");
        assert_eq!(device_packets(&format!("{}\n{}", dev, ours), bind, host), 9);
        // a peer's datagram arriving (orig from the peer) is not the device
        let peer = "ipv4 2 udp 17 25 src=170.9.238.141 dst=192.168.0.21 sport=39897 dport=3074 \
                    packets=1 bytes=37 src=192.168.21.138 dst=170.9.238.141 sport=3074 dport=39897 \
                    packets=0 bytes=0 mark=0 zone=0 use=2";
        assert_eq!(device_packets(peer, bind, host), 0);
    }

    #[test]
    fn a_quiet_hold_is_kept_and_a_gone_device_is_not() {
        // Quiet is what a keepalive is for, so only a gone device, a slot's claim or the backstop ends it.
        let long = 150;
        assert_eq!(release_reason(false, 0, 5, 9, 9, long), None, "quiet is kept");
        assert_eq!(
            release_reason(false, 3, 1, 1, 1, long),
            Some(ExitReason::DeviceGone),
            "an absent device releases its holds"
        );
        assert_eq!(
            release_reason(true, 0, 9, 9, 9, long),
            Some(ExitReason::OwnedBySlot),
            "a slot's claim takes the tuple"
        );
        assert_eq!(
            release_reason(false, 0, long, long, long, long),
            Some(ExitReason::Stale),
            "both sides silent for the long window is the backstop"
        );
        // and the short grace of the old rule no longer ends anything
        assert_eq!(release_reason(false, 0, 3, 3, 3, long), None);
    }


    #[tokio::test]
    async fn a_device_s_budget_is_its_own() {
        let c = Ipv4Addr::new(192, 168, 21, 138);
        let other = Ipv4Addr::new(192, 168, 21, 68);
        let mut e = engine(
            Box::new(FakeCdc { cands: vec![cand((LO, 54410), c, 54410)] }),
            Vec::new(),
            8,
            3,
        );
        e.per_host = 1;
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1, "a lone flow from a named device is held");
        // a second flow from the same device is refused by that device's own cap
        let mut e2 = engine(
            Box::new(FakeCdc {
                cands: vec![cand((LO, 54411), c, 54411), cand((LO, 54412), c, 54412)],
            }),
            Vec::new(),
            8,
            3,
        );
        e2.per_host = 1;
        age(&mut e2, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert_eq!(e2.slots.len(), 1, "one device's churn spends its own budget");
        // another device still has its own capacity
        let mut e3 = engine(
            Box::new(FakeCdc {
                cands: vec![cand((LO, 54413), c, 54413), cand((LO, 54414), other, 54414)],
            }),
            Vec::new(),
            8,
            3,
        );
        e3.per_host = 1;
        age(&mut e3, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert_eq!(e3.slots.len(), 2, "each device has its own capacity");
    }

    #[test]
    fn a_report_is_per_observation_not_once_per_flow() {
        // A re-key matters most: the AFTR can move the tuple under a held flow, so every change is reported.
        let a = ("203.0.113.1".parse().unwrap(), 40001);
        let b = ("203.0.113.1".parse().unwrap(), 40002);
        assert_eq!(observe_report(None, Some(a)), Some(a), "the first look is reported");
        assert_eq!(observe_report(Some(a), Some(a)), None, "unchanged is not an event");
        assert_eq!(observe_report(Some(a), Some(b)), Some(b), "a re-key is reported");
        assert_eq!(observe_report(Some(a), None), None, "silence reports nothing");
    }

    #[tokio::test]
    async fn an_allocated_tuple_is_never_captured() {
        // The claim gate reads the live table, so a slot's tuple never has two local owners.
        let c = Ipv4Addr::new(192, 168, 21, 68);
        let mut t = crate::slot::LeaseTable::new(
            crate::slot::PortAllocator::new(30000, 30009).unwrap(),
            4,
            2,
        );
        assert_eq!(
            t.upsert_pcp(crate::slot::Proto::Udp, 3074, c, 600, 1_800_000_000, c, 3074),
            crate::slot::UpsertOutcome::Granted { bind_port: 30000 }
        );
        let mut e = engine(
            Box::new(FakeCdc {
                cands: vec![cand((LO, 30000), c, 30000)],
            }),
            Vec::new(),
            8,
            3,
        );
        e.alloc = Some(Arc::new(Mutex::new(t)));
        e.bind_ip = LO;
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert!(e.slots.is_empty(), "an allocation's tuple is not this arm's");
    }

    #[tokio::test]
    async fn slot_claimed_by_connection_exits() {
        let c = cand((LO, 54328), HOST, 54328);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c] }), Vec::new(), 8, 3);
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1);
        e.owned.push((LO, 54328)); // a static/lease slot claims the tuple
        age(&mut e, KEEPALIVE_AFTER_TICKS as usize + 1).await;
        assert!(e.slots.is_empty(), "I1: engine exits once a slot holds the tuple");
    }
}

#[cfg(kani)]
mod verify {
    use super::*;

    fn any_ip() -> Ipv4Addr {
        Ipv4Addr::from(kani::any::<[u8; 4]>())
    }

    #[kani::proof]
    fn claim_allowed_is_budget_and_held_safe() {
        let bind = (any_ip(), kani::any::<u16>());
        let h0 = (any_ip(), kani::any::<u16>());
        let h1 = (any_ip(), kani::any::<u16>());
        let owned = [h0, h1];
        let active: usize = kani::any();
        let max: u32 = kani::any();
        if claim_allowed(bind, &owned, active, max) {
            assert!(!owned.contains(&bind), "claim never takes an owned tuple");
            assert!((active as u64) < (max as u64), "claim never exceeds budget");
        }
    }

    #[kani::proof]
    fn exit_due_matches_conditions() {
        let missing: u32 = kani::any();
        let grace: u32 = kani::any();
        let idle: u32 = kani::any();
        let owned_now: bool = kani::any();
        match exit_due(missing, grace, idle, owned_now) {
            Some(ExitReason::OwnedBySlot) => assert!(owned_now),
            Some(ExitReason::Stale) => {
                assert!(!owned_now);
                assert!(missing >= grace, "stale requires the entry gone past grace");
                assert!(idle >= grace, "stale requires inbound silence past grace");
            }
            None => assert!(!owned_now && (missing < grace || idle < grace)),
        }
    }
}