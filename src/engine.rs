//! Observation rescue engine (brief v2, Phase G — G3–G5 runtime).
//!
//! One tokio task per rescued flow, mirroring `run_slot` (same one-poll-loop
//! shape, tokio DECIDED): the engine's 2 s tick drives *lifecycle* (claim /
//! budget / exit) from the selected `Cdc` backend; each claimed flow gets a
//! spawned task owning its shadow socket — keepalive tick + recv loop in the
//! task, decisions in the engine.
//!
//! Rescue sequence (G3, exact order):
//!   (b) bind shadow socket (NAT addr, R_nat) — C5 PASS, shadow-bind proven;
//!   (c) install the SELF-PIN `(NAT, R_nat) -> (NAT, R_nat)` — the shadow
//!       keepalive flows must egress as `(NAT, R_nat)` to refresh the
//!       observed AFTR mapping. Without it the kernel NAPT's them to a
//!       fresh ephemeral port the moment the observed conntrack entry lives
//!       (measured 41077 → 1024 on-box 2026-09-02) and the rescue refreshes
//!       the WRONG mapping. An explicit (addr, port) snat via the map
//!       bypasses that remap; the entry-delete alternative was bisected
//!       (CT_DELETE, all encodings) and rejected EINVAL by this 6.12
//!       ImmortalWrt kernel — see ct.rs;
//!   (d) add pin element (host, host_port) → R_nat — host wake-up flows
//!       land on the same AFTR inner tuple;
//!   (e) input accept for R_nat (B4-parallel — a promotion datagram is a
//!       NEW inbound flow fw4's `ct state established` won't cover);
//!   (f) STUN keepalive from the shadow socket every tick — EIM refreshes
//!       the flow's mapping, the peer receives nothing;
//!   (g) record the flow's XOR-MAPPED-ADDRESS on any STUN reply (free
//!       per-flow observability);
//!   (h) inbound datagram → forward P1-style to (host, host_port) with the
//!       peer source preserved — G4 promotion; conntrack never touched.
//!
//! Exit (G5): the inner tuple got claimed by a static/lease slot (I1 —
//! instant teardown) | the entry is absent from the CDC for `grace_ticks`
//! AND no inbound for `grace_ticks` (flow presumed dead). On exit: stop the
//! task (socket closes), delete the pin element, drop the record. (Pin
//! deletion can change the console's external tuple — acceptable only at
//! exit, flow presumed dead.)
use crate::cdc::Cdc;
use crate::forward;
use crate::nft;
use crate::publish::Publisher;
use crate::stun;
use crate::vote::VoteState;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Engine cadence. 2 s « 5–10 s AFTR TTL (I3).
pub const TICK: Duration = Duration::from_secs(2);
/// G5 grace in ticks: entry gone from the CDC ∧ no inbound for this long →
/// flow presumed dead. Default 3 ticks (~6 s after the conntrack entry died,
/// which itself lags host silence by the kernel UDP timeouts).
pub const DEFAULT_GRACE_TICKS: u32 = 3;

/// G5 exit reasons — Copy enum (Kani-friendly).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// A static/lease slot claims the inner tuple (I1).
    HeldBySlot,
    /// Entry gone from the CDC and no inbound within grace — flow dead.
    Stale,
}

/// I1 + G2 budget gate before claiming a candidate. Pure; Kani-proven.
pub fn claim_allowed(
    bind: (Ipv4Addr, u16),
    held: &[(Ipv4Addr, u16)],
    active: usize,
    max_rescues: u32,
) -> bool {
    !held.contains(&bind) && (active as u64) < (max_rescues as u64)
}

/// G5 exit decision. Pure; Kani-proven (the exit state machine).
pub fn exit_due(
    missing_ticks: u32,
    grace_ticks: u32,
    ticks_since_inbound: u32,
    held_now: bool,
) -> Option<ExitReason> {
    if held_now {
        return Some(ExitReason::HeldBySlot);
    }
    if missing_ticks >= grace_ticks && ticks_since_inbound >= grace_ticks {
        return Some(ExitReason::Stale);
    }
    None
}

/// Pin/unpin + forward-path accept operations — real impl drives nft; tests
/// inject no-ops. The accept is B4-parallel: inbound to a rescued tuple that
/// is NOT part of an established flow (the promotion datagram) would be
/// rejected by fw4's `ct state established` input policy without a per-port
/// accept (slot accepts exist the same way; observation shadows install
/// theirs per claim).
pub trait PinOps: Send + Sync {
    fn add(&self, host: Ipv4Addr, host_port: u16, r: u16) -> std::io::Result<()>;
    fn del(&self, host: Ipv4Addr, host_port: u16);
    fn accept(&self, r: u16) -> std::io::Result<()>;
    fn unaccept(&self, r: u16);
}

pub struct NftPins;

impl PinOps for NftPins {
    fn add(&self, host: Ipv4Addr, host_port: u16, r: u16) -> std::io::Result<()> {
        nft::add_pin(host, host_port, r)
    }
    fn del(&self, host: Ipv4Addr, host_port: u16) {
        let _ = nft::del_pin(host, host_port);
    }
    fn accept(&self, r: u16) -> std::io::Result<()> {
        nft::add_input_accept(r, false)
    }
    fn unaccept(&self, r: u16) {
        let _ = nft::del_input_accept(r, false);
    }
}

/// One rescued flow.
struct ObsSlot {
    host: Ipv4Addr,
    host_port: u16,
    bind_tuple: (Ipv4Addr, u16),
    external: Option<(Ipv4Addr, u16)>,
    /// The per-flow vote, so the report carries the decision the daemon
    /// actually made rather than only the tuple it learned. The shadow keeps
    /// one server (concurrent flows from one source port are NAPT'd
    /// elsewhere), so a lone report can only be Stable or the first Churn.
    vote: Arc<Mutex<VoteState>>,
    /// Wall-clock second this flow was last seen live.
    last_seen_unix: u64,
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
    held: Vec<(Ipv4Addr, u16)>,
    max_rescues: u32,
    grace_ticks: u32,
    servers: Vec<SocketAddrV4>,
    publisher: Arc<Publisher>,
    pins: Arc<dyn PinOps>,
    slots: Vec<ObsSlot>,
    /// The devices this arm may act for (call/0025): the allowlist is
    /// admission for maintenance, and everything outside it is untouched.
    /// Set by the daemon from its configuration; empty leaves the arm the
    /// admission it already had.
    pub allow: Vec<Ipv4Addr>,
    /// Whether the arm holds (claims, keeps alive, promotes) or only reports.
    /// The log-only stage is how the allowlist is read against the AFTR's
    /// real behaviour before a device is held.
    pub hold: bool,
    /// Tuples already reported in log-only mode, so the line appears once per
    /// flow rather than once per tick.
    reported: std::collections::HashSet<(Ipv4Addr, u16)>,
}

impl ObservationEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cdc: Box<dyn Cdc>,
        held: Vec<(Ipv4Addr, u16)>,
        max_rescues: u32,
        grace_ticks: u32,
        servers: Vec<SocketAddrV4>,
        publisher: Arc<Publisher>,
        pins: Arc<dyn PinOps>,
    ) -> Self {
        ObservationEngine {
            cdc,
            held,
            max_rescues,
            grace_ticks,
            servers,
            publisher,
            pins,
            slots: Vec::new(),
            allow: Vec::new(),
            hold: true,
            reported: std::collections::HashSet::new(),
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

    async fn tick(&mut self) {
        let live: Vec<crate::cdc::Candidate> = self.cdc.tick();

        // The admission (call/0025): a configured allowlist narrows this arm
        // to the named devices, and an empty one leaves it the admission it
        // already had (the G2 predicate in cdc.rs), so a deployment that
        // never names a device keeps the behaviour it was verified with.
        let live: Vec<crate::cdc::Candidate> = if self.allow.is_empty() {
            live
        } else {
            live.into_iter()
                .filter(|c| crate::hold::allowed(&self.allow, c.host))
                .collect()
        };
        if !self.hold {
            self.report_only(&live);
            return;
        }

        // Per-slot bookkeeping: an entry reported by the CDC resets its miss
        // counter; a task inbound (counter change) resets inbound silence.
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
            // G3e: once the shadow socket sees a STUN reply, record the
            // flow's live external tuple.
            if live.iter().any(|c| c.bind_tuple == s.bind_tuple) {
                s.last_seen_unix = unix_now();
            }
            if s.external.is_none() {
                if let Some(t) = *s.external_arc.lock().await {
                    s.external = Some(t);
                    // The decision the flow's own vote made, reported beside
                    // the tuple it learned, so the log and the client's view
                    // cannot disagree about what happened.
                    let decision = s.vote.lock().await.observe(0, t);
                    self.publisher.log_transition(
                        "observed-tuple",
                        &format!(
                            "{}:{} -> {}:{} ({:?})",
                            s.host, s.host_port, t.0, t.1, decision
                        ),
                    );
                }
            }
        }

        // Claims (G3): fresh candidates only, through the I1 + budget gate.
        for c in &live {
            if self.slots.iter().any(|s| s.bind_tuple == c.bind_tuple) {
                continue; // already rescued
            }
            if !claim_allowed(c.bind_tuple, &self.held, self.slots.len(), self.max_rescues) {
                continue;
            }
            let bind = SocketAddr::V4(SocketAddrV4::new(c.bind_tuple.0, c.bind_tuple.1));
            let sock = match UdpSocket::bind(bind).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("warn: shadow bind {} failed: {}", bind, e);
                    continue;
                }
            };
            // G3(c): self-pin — the shadow's keepalive traffic must egress
            // as (NAT, R_nat) or the kernel NAPT's it elsewhere and the
            // rescue refreshes the wrong mapping (measured 41077 → 1024).
            if let Err(e) = self.pins.add(c.bind_tuple.0, c.bind_tuple.1, c.bind_tuple.1) {
                eprintln!("warn: shadow self-pin {} failed: {}", c.bind_tuple.1, e);
                drop(sock);
                continue;
            }
            if let Err(e) = self.pins.add(c.host, c.host_port, c.bind_tuple.1) {
                eprintln!(
                    "warn: shadow pin {}:{} -> {} failed: {}",
                    c.host, c.host_port, c.bind_tuple.1, e
                );
                let _ = self.pins.del(c.bind_tuple.0, c.bind_tuple.1);
                drop(sock);
                continue;
            }
            if let Err(e) = self.pins.accept(c.bind_tuple.1) {
                eprintln!("warn: shadow accept {} failed: {}", c.bind_tuple.1, e);
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
                "rescue",
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
                missing_ticks: 0,
                ticks_since_inbound: 0,
                last_inbound_seen: inbound_ts.load(Ordering::Relaxed),
                stop,
                inbound_ts,
                external_arc: external,
            });
        }

        // Exit pass (G5). Held-by-slot is instant (I1); stale needs the
        // entry gone ∧ no inbound, both past grace.
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
            let held_now = self.held.contains(&t);
            let reason = exit_due(missing, self.grace_ticks, since_inbound, held_now);
            if let Some(r) = reason {
                stop.store(true, Ordering::Relaxed);
                let gone = self.slots.swap_remove(i);
                let _ = self.pins.del(gone.host, gone.host_port);
                let _ = self.pins.del(gone.bind_tuple.0, gone.bind_tuple.1); // self-pin
                self.pins.unaccept(gone.bind_tuple.1);
                let silent_s = unix_now().saturating_sub(gone.last_seen_unix);
                self.publisher.log_transition(
                    "rescue-exit",
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

/// The log-only stage: report every named device's live flow once, and touch
/// nothing. It exists so the allowlist can be read against the AFTR's real
/// behaviour before any device is held (plan/0009's first rollout stage).
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

/// The per-flow shadow task: keepalive every tick from the bound tuple
/// (G3d — EIM refreshes the flow's mapping, peer sees nothing), inbound
/// datagrams forwarded P1-style to the observed host:port (G4 promotion,
/// source preserved, conntrack untouched).
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
                        // Stick to one server (relay pattern): concurrent
                        // flows from one source port get NAPT'd by the
                        // kernel (measured 41077 → 1024), which would
                        // refresh the wrong tuple. Rotate only on failure.
                        let server = servers[cursor % servers.len()];
                        let txn = stun::random_txn();
                        let req = stun::binding_request(&txn);
                        if let Err(e) = sock.send_to(&req, server).await {
                            eprintln!("warn: shadow keepalive {} failed: {}", server, e);
                            cursor = cursor.wrapping_add(1);
                        }
                    }
                }
                r = sock.recv_from(&mut buf) => match r {
                    Ok((n, src)) => {
                        let pkt = &buf[..n];
                        let SocketAddr::V4(v4) = src else { continue };
                        if servers.iter().any(|s| *s == v4) {
                            // STUN reply → the flow's live external tuple.
                            if let Some(t) = stun::parse_mapped(pkt) {
                                *external.lock().await = Some(t);
                            }
                        } else {
                            // Peer datagram → promotion (G4).
                            match forward::forward(pkt, v4, target) {
                                Ok(()) => {
                                    inbound_ts.store(unix_now(), Ordering::Relaxed);
                                }
                                Err(e) => eprintln!(
                                    "warn: shadow forward {} -> {} failed: {}",
                                    v4, target, e
                                ),
                            }
                        }
                    }
                    Err(e) => eprintln!("warn: shadow recv: {}", e),
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

    fn cand(bind: (Ipv4Addr, u16), host: Ipv4Addr, hp: u16) -> crate::cdc::Candidate {
        crate::cdc::Candidate {
            bind_tuple: bind,
            host,
            host_port: hp,
            peer: (Ipv4Addr::new(8, 8, 8, 8), 53),
        }
    }

    fn engine(cdc: Box<dyn Cdc>, held: Vec<(Ipv4Addr, u16)>, max: u32, grace: u32) -> ObservationEngine {
        ObservationEngine::new(
            cdc,
            held,
            max,
            grace,
            Vec::new(),
            Arc::new(Publisher::with_watch("/tmp/dslp-test", tokio::sync::watch::channel(Ipv4Addr::UNSPECIFIED).0)),
            Arc::new(NopPins),
        )
    }

    // Loopback NAT for tests: the engine binds whatever the CDC reports
    // (real CDC yields 192.168.0.21 — the hub-LAN NAT addr on-box).
    const LO: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 21, 50);

    #[tokio::test]
    async fn claims_live_candidate_once() {
        // distinct ports across tests: shadow tasks hold their sockets for
        // the test's runtime, and cargo runs tests in parallel
        let c = cand((LO, 54322), HOST, 54322);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c] }), Vec::new(), 8, 3);
        e.tick().await;
        assert_eq!(e.slots.len(), 1);
        e.tick().await; // same candidate again: no duplicate claim
        assert_eq!(e.slots.len(), 1);
        assert_eq!(e.slots[0].missing_ticks, 0);
    }

    #[tokio::test]
    async fn budget_limits_claims() {
        let c1 = cand((LO, 54324), HOST, 54324);
        let c2 = cand((LO, 54325), HOST, 54325);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c1, c2] }), Vec::new(), 1, 3);
        e.tick().await;
        assert_eq!(e.slots.len(), 1, "budget 1 blocks the second claim");
    }

    #[tokio::test]
    async fn held_candidate_not_claimed() {
        let c = cand((LO, 54326), HOST, 54326);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c] }), vec![(LO, 54326)], 8, 3);
        e.tick().await;
        assert!(e.slots.is_empty(), "I1: held tuple never claimed");
    }

    #[tokio::test]
    async fn stale_flow_exits_after_grace() {
        let c = cand((LO, 54327), HOST, 54327);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c] }), Vec::new(), 8, 1);
        e.tick().await; // claim
        assert_eq!(e.slots.len(), 1);
        e.cdc = Box::new(FakeCdc { cands: vec![] });
        e.tick().await; // entry gone; no inbound ever -> stale past grace
        assert!(e.slots.is_empty(), "G5: stale flow exits");
    }

    // ---- the allowlist and the hold (call/0025, plan/0009 #snoop) ----

    #[tokio::test]
    async fn a_device_outside_the_allowlist_is_never_claimed() {
        // The arm's whole point is that it acts for named devices only: a
        // flow whose origin is not on the list is not held, however live it
        // is, and no write is ever made for it.
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
        e.tick().await;
        assert_eq!(e.slots.len(), 1, "only the named device's flow is held");
        assert_eq!(e.slots[0].host, named);
    }

    #[tokio::test]
    async fn the_log_only_stage_holds_nothing() {
        // plan/0009's first rollout stage: the arm reports what it would act
        // on and touches nothing, so the log can be read against the AFTR's
        // real behaviour before any device is held.
        let named = Ipv4Addr::new(192, 168, 21, 68);
        let mut e = engine(Box::new(FakeCdc {
            cands: vec![cand((LO, 54342), named, 54342)],
        }), Vec::new(), 8, 3);
        e.allow = vec![named];
        e.hold = false;
        e.tick().await;
        assert!(e.slots.is_empty(), "log-only: nothing claimed");
        assert!(e.reported.contains(&(LO, 54342)), "but it is reported");
        // a device outside the list is not even reported
        assert!(!e.reported.contains(&(LO, 54343)));
    }

    #[tokio::test]
    async fn slot_claimed_by_holder_exits() {
        let c = cand((LO, 54328), HOST, 54328);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c] }), Vec::new(), 8, 3);
        e.tick().await;
        assert_eq!(e.slots.len(), 1);
        e.held.push((LO, 54328)); // a static/lease slot claims the tuple
        e.tick().await;
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
        let held = [h0, h1];
        let active: usize = kani::any();
        let max: u32 = kani::any();
        if claim_allowed(bind, &held, active, max) {
            assert!(!held.contains(&bind), "claim never lands on a held tuple");
            assert!((active as u64) < (max as u64), "claim never exceeds budget");
        }
    }

    #[kani::proof]
    fn exit_due_matches_conditions() {
        let missing: u32 = kani::any();
        let grace: u32 = kani::any();
        let idle: u32 = kani::any();
        let held_now: bool = kani::any();
        match exit_due(missing, grace, idle, held_now) {
            Some(ExitReason::HeldBySlot) => assert!(held_now),
            Some(ExitReason::Stale) => {
                assert!(!held_now);
                assert!(missing >= grace, "stale requires the entry gone past grace");
                assert!(idle >= grace, "stale requires inbound silence past grace");
            }
            None => assert!(!held_now && (missing < grace || idle < grace)),
        }
    }
}