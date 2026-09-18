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
    /// The device itself stopped answering on the LAN (call/0029): a hold
    /// for a device that is off or asleep releases nothing anyone uses.
    DeviceGone,
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
    /// Pin the shadow's own egress, never the device's key. The shadow binds
    /// the device's tuple, so what it needs is for its own keepalives to
    /// leave as that tuple: a pin on the *device's* (client, port) key would
    /// instead drag the device's own traffic onto our port, and a console
    /// whose game flows then egress on two different external tuples is
    /// scored Strict or Moderate. call/0014 settled this, and the port a
    /// device keeps by preservation is the tuple the shadow mirrors.
    fn add(&self, _host: Ipv4Addr, _host_port: u16, r: u16) -> std::io::Result<()> {
        nft::add_pin(nft::NAT_ADDR, r, r)
    }
    /// Only ever a self-pin. A device-key element is not ours to remove with
    /// the tuple gone; those are cleaned once by hand when the arm stops
    /// installing them.
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
    /// The device's own packet count for this tuple, as the connection table
    /// last reported it. Our own writes are not the device's, and they are
    /// what used to keep this arm believing a flow was alive: the delta over
    /// this counter is the liveness signal that cannot be self-fulfilled.
    dev_pkts: u64,
    /// Consecutive ticks with neither the device nor a peer touching the
    /// tuple.
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
    /// The lease table, when this arm runs beside the facade: the tuples an
    /// allocation holds, read live. The frozen list a start-up snapshot gives
    /// cannot see a grant that happened since, and a slot's tuple is not this
    /// arm's to capture (call/0027 R1).
    pub alloc: Option<Arc<Mutex<LeaseTable>>>,
    /// The address the slots bind, so their tuples can be named.
    pub bind_ip: Ipv4Addr,
    /// Ticks since start, for the probe throttle and its round robin.
    ticks: u64,
    /// Which slot the next device probe looks at.
    probe_cursor: usize,
    /// The per-device hold cap.
    per_host: u32,
    /// Candidates not yet held, with the device's last packet count and how
    /// many ticks it has been quiet. A flow is claimed when it has been quiet
    /// long enough to need us, which is what keeps a device's capacity for
    /// the mappings that matter.
    young: std::collections::HashMap<(Ipv4Addr, u16), (u64, u32)>,
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

    /// The tuples an allocation holds right now: the static snapshot plus
    /// whatever the lease table has granted since (call/0027 R1).
    async fn held_now(&self) -> Vec<(Ipv4Addr, u16)> {
        let mut held = self.held.clone();
        if let Some(t) = &self.alloc {
            for s in t.lock().await.slots() {
                held.push((self.bind_ip, s.bind_port));
            }
        }
        held
    }

    async fn tick(&mut self) {
        let held = self.held_now().await;
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
        // The report set follows the live set in either mode, so a tuple that
        // is long gone cannot keep its place in it.
        self.reported.retain(|t| live.iter().any(|c| c.bind_tuple == *t));

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
            let seen = *s.external_arc.lock().await;
            if let Some(t) = observe_report(s.external, seen) {
                s.external = Some(t);
                // The decision the flow's own vote made, reported beside the
                // tuple it learned, so the log and the client's view cannot
                // disagree about what happened.
                let decision = s.vote.lock().await.observe(0, t);
                self.publisher.log_transition(
                    "observed-tuple",
                    &format!("{}:{} -> {}:{} ({:?})", s.host, s.host_port, t.0, t.1, decision),
                );
            }
        }

        // Claims (G3): fresh candidates only, through the I1 + budget gate.
        for c in &live {
            if self.slots.iter().any(|s| s.bind_tuple == c.bind_tuple) {
                continue; // already rescued
            }
            let (_, quiet) = self
                .young
                .get(&c.bind_tuple)
                .copied()
                .unwrap_or((c.host_port as u64, 0));
            if quiet < HOLD_AFTER_TICKS {
                // the device is still refreshing this flow: it needs nothing
                continue;
            }
            if !host_budget_ok(c.host, &self.slots, self.per_host) {
                // one device's churn cannot spend another device's capacity
                continue;
            }
            if !claim_allowed(c.bind_tuple, &held, self.slots.len(), self.max_rescues) {
                // R5: a tuple a slot holds is refused rather than captured,
                // and the refusal is reported. A device's flow on a slot's
                // tuple is the late collision (call/0028), and the log is
                // where it becomes visible; the device keeps the inbound.
                if held.contains(&c.bind_tuple) && self.reported.insert(c.bind_tuple) {
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
            // G3(c): self-pin — the shadow's keepalive traffic must egress
            // as (NAT, R_nat) or the kernel NAPT's it elsewhere and the
            // rescue refreshes the wrong mapping (measured 41077 → 1024).
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

        // Liveness pass: what keeps a hold alive is the device or a peer,
        // never our own writes. The device's own packet count comes from the
        // connection table (our egress appears there with the NAT address as
        // its origin, so it cannot be mistaken for the device's), and a peer
        // probe is what the shadow timestamps as inbound.
        self.ticks += 1;
        // Age the young: a candidate's own device packets reset its quiet
        // count, so only a flow the device has stopped refreshing becomes a
        // hold candidate.
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
            // One device probe per throttle window, round robin across the
            // holds so a tick never blocks on more than one ping.
            if self.ticks % PROBE_EVERY_TICKS == 0 {
                if self.probe_cursor >= self.slots.len() {
                    self.probe_cursor = 0;
                }
                if let Some(s) = self.slots.get_mut(self.probe_cursor) {
                    let host = s.host;
                    if device_up(host) {
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
            let held_now = held.contains(&t);
            let (quiet, misses) = {
                let s = &self.slots[i];
                (s.quiet_ticks, s.dev_misses)
            };
            let reason = release_reason(
                held_now,
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

/// Whether a flow's observation is worth reporting, and with which tuple:
/// the first look, or a tuple that has moved since the last one. The daemon
/// reports the tuple as often as it changes, so a re-key appears in the log
/// beside its decision rather than being invisible (#snoop, call/0027 R5).
fn observe_report(
    prev: Option<(Ipv4Addr, u16)>,
    now: Option<(Ipv4Addr, u16)>,
) -> Option<(Ipv4Addr, u16)> {
    match now {
        Some(t) if prev != Some(t) => Some(t),
        _ => None,
    }
}

/// A candidate is claimed only once its device has been quiet this long: a
/// flow the device is refreshing needs nothing from us, and claiming it would
/// spend the device's own capacity on churn (call/0029). Five to ten seconds
/// is well inside the uplink's measured reaping window, so the hold starts
/// before the mapping can lapse.
const HOLD_AFTER_TICKS: u32 = 3;
/// A hold is released when both sides have left it alone this long. Generous
/// on purpose: a lobby is silence, and silence is what the hold is for, so
/// this is a backstop behind the device-presence probe rather than a
/// liveness rule.
const LONG_QUIET_TICKS: u32 = 150;
/// Consecutive failed LAN probes before a hold is released as abandoned.
const DEV_MISSES_TO_RELEASE: u8 = 3;
/// Probe one slot's device every this many ticks, so the tick never blocks
/// on more than one probe.
const PROBE_EVERY_TICKS: u64 = 3;

/// Is the device on the LAN? The neighbour table is the instrument, not the
/// echo. A console that drops ICMP still answers ARP, and a device that is
/// off leaves FAILED or INCOMPLETE behind (measured on the router: the
/// Switch present with a MAC and no ICMP, the PS3 absent with no ARP at all).
/// An ICMP echo is used only as a trigger, to make the kernel settle an entry
/// we cannot read, and never as the answer.
///
/// A probe that cannot run answers "up": a broken instrument must never
/// release a live hold.
fn device_up(ip: Ipv4Addr) -> bool {
    let s = ip.to_string();
    let first = neigh_state(&s).unwrap_or_default();
    if first.trim().is_empty() {
        let _ = std::process::Command::new("ping")
            .args(["-c", "1", "-W", "1", &s])
            .output();
        let second = neigh_state(&s).unwrap_or_default();
        if second.trim().is_empty() {
            return true;
        }
        return neigh_answers(&second);
    }
    neigh_answers(&first)
}

/// `ip neigh show <ip>`, as text. None means the probe itself could not run.
fn neigh_state(ip: &str) -> Option<String> {
    std::process::Command::new("ip")
        .args(["neigh", "show", ip])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Whether a neighbour listing says the device answered on the LAN. A listing
/// with a link-layer address means it did, whatever the state; FAILED or
/// INCOMPLETE means a probe went unanswered; anything else counts as present,
/// so a failure of this instrument never releases a live hold.
fn neigh_answers(listing: &str) -> bool {
    let l = listing.trim();
    if l.is_empty() {
        return true;
    }
    if l.contains("FAILED") || l.contains("INCOMPLETE") {
        return false;
    }
    true
}

/// The one place a hold's end is decided. A hold yields to a slot, ends when
/// its device stops answering on the LAN, and otherwise ends only when both
/// sides have left the tuple alone for the long window: going quiet is what a
/// hold is for, so quiet is never by itself a reason to release one
/// (call/0029). Pure, so the policy is testable without a clock.
fn release_reason(
    held_now: bool,
    misses: u8,
    quiet: u32,
    missing: u32,
    since_inbound: u32,
    long_quiet: u32,
) -> Option<ExitReason> {
    if held_now {
        return Some(ExitReason::HeldBySlot);
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

/// The device's own packet count for a tuple: the connection table's entries
/// whose NAT side is that tuple and whose origin is the device. A game
/// talking to several peers is several entries on one tuple, so this is a
/// sum, and our own writes to the same tuple carry the NAT address as their
/// origin and are therefore counted out. That exclusion is the whole point:
/// a liveness signal our own keepalives can satisfy proves nothing
/// (call/0029).
fn device_packets(proc_text: &str, bind: (Ipv4Addr, u16), host: Ipv4Addr) -> u64 {
    proc_text
        .lines()
        .filter_map(crate::obs::parse_line)
        .filter(|e| e.nat_src() == bind && e.orig_src == host)
        .map(|e| e.orig_packets)
        .sum()
}

/// Per-device budget: one device's churn must not spend another's capacity.
/// Pure; the caller passes the holds grouped by host.
fn host_budget_ok(host: Ipv4Addr, slots: &[ObsSlot], per_host: u32) -> bool {
    let mine = slots.iter().filter(|s| s.host == host).count() as u64;
    mine < per_host as u64
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

    /// Tick until a candidate has been quiet long enough to be held: the arm
    /// holds what a device has stopped refreshing, so a fresh flow needs a
    /// few ticks before it is old enough, and a flow the device keeps
    /// refreshing is never claimed at all.
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
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1);
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await; // same candidate again: no duplicate claim
        assert_eq!(e.slots.len(), 1);
        assert_eq!(e.slots[0].missing_ticks, 0);
    }

    #[tokio::test]
    async fn budget_limits_claims() {
        let c1 = cand((LO, 54324), HOST, 54324);
        let c2 = cand((LO, 54325), HOST, 54325);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c1, c2] }), Vec::new(), 1, 3);
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1, "budget 1 blocks the second claim");
    }

    #[tokio::test]
    async fn held_candidate_not_claimed() {
        let c = cand((LO, 54326), HOST, 54326);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c] }), vec![(LO, 54326)], 8, 3);
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
        assert!(e.slots.is_empty(), "I1: held tuple never claimed");
    }

    #[tokio::test]
    async fn a_quiet_hold_is_kept_not_released() {
        // The rule this milestone changed: an entry gone from the change data
        // capture with no inbound is what a lobby looks like, and it is the
        // state a hold exists to survive. The old rule released on exactly
        // those two counters.
        let h = HOST;
        let mut e = engine(
            Box::new(FakeCdc { cands: vec![cand((LO, 54360), h, 54360)] }),
            Vec::new(),
            8,
            3,
        );
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1, "the flow is held");
        {
            let s = &mut e.slots[0];
            s.missing_ticks = 99;
            s.ticks_since_inbound = 99;
            s.quiet_ticks = 4;
            s.dev_misses = 0;
        }
        e.tick().await;
        assert_eq!(e.slots.len(), 1, "quiet is what the hold is for");
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
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
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
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
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
        // Quiet is what a hold is for: neither the device nor a peer touching
        // the tuple is the normal case for a lobby, and it must not end the
        // hold. Only the device's disappearance, a slot's claim, or the long
        // backstop does.
        let long = 150;
        assert_eq!(release_reason(false, 0, 5, 9, 9, long), None, "quiet is kept");
        assert_eq!(
            release_reason(false, 3, 1, 1, 1, long),
            Some(ExitReason::DeviceGone),
            "an absent device releases its holds"
        );
        assert_eq!(
            release_reason(true, 0, 9, 9, 9, long),
            Some(ExitReason::HeldBySlot),
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

    #[test]
    fn the_neighbour_table_is_the_presence_signal() {
        // Measured shapes from the router: the Switch present with a MAC and
        // dropping ICMP, the PS3 absent and answering no ARP at all.
        assert!(neigh_answers("192.168.21.68 dev br-lan lladdr 80:d2:e5:6d:d1:00 DELAY"));
        assert!(neigh_answers("192.168.21.68 dev br-lan lladdr 80:d2:e5:6d:d1:00 STALE"));
        assert!(!neigh_answers("192.168.21.138 dev br-lan FAILED"));
        assert!(!neigh_answers("192.168.21.138 dev br-lan INCOMPLETE"));
        // a failure of the instrument is not evidence the device is gone
        assert!(neigh_answers(""));
        assert!(neigh_answers("something we do not understand"));
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
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1, "a lone flow from a named device is held");
        // a second flow from the same device is refused by that device's own
        // cap, which is the point: the churn cannot spend another's capacity
        let mut e2 = engine(
            Box::new(FakeCdc {
                cands: vec![cand((LO, 54411), c, 54411), cand((LO, 54412), c, 54412)],
            }),
            Vec::new(),
            8,
            3,
        );
        e2.per_host = 1;
        age(&mut e2, HOLD_AFTER_TICKS as usize + 1).await;
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
        age(&mut e3, HOLD_AFTER_TICKS as usize + 1).await;
        assert_eq!(e3.slots.len(), 2, "each device has its own capacity");
    }

    #[test]
    fn a_report_is_per_observation_not_once_per_flow() {
        // #snoop wants the learned tuple, the last-seen stamp and the
        // decision per observation, so the log carries a flow's tuple
        // history rather than only its first value. A re-key is the case
        // that matters: the AFTR can move the tuple under a held flow, and a
        // change that is not reported is what call/0027 R5 forbids.
        let a = ("203.0.113.1".parse().unwrap(), 40001);
        let b = ("203.0.113.1".parse().unwrap(), 40002);
        assert_eq!(observe_report(None, Some(a)), Some(a), "the first look is reported");
        assert_eq!(observe_report(Some(a), Some(a)), None, "unchanged is not an event");
        assert_eq!(observe_report(Some(a), Some(b)), Some(b), "a re-key is reported");
        assert_eq!(observe_report(Some(a), None), None, "silence reports nothing");
    }

    #[tokio::test]
    async fn an_allocated_tuple_is_never_captured() {
        // call/0027 R1 from this arm's side. The snapshot it starts with
        // cannot see a grant that happened since, so the claim gate reads the
        // live table: a slot's tuple belongs to the slot, and a shadow socket
        // on it would be two local owners of one inner tuple.
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
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
        assert!(e.slots.is_empty(), "an allocation's tuple is not this arm's");
    }

    #[tokio::test]
    async fn slot_claimed_by_holder_exits() {
        let c = cand((LO, 54328), HOST, 54328);
        let mut e = engine(Box::new(FakeCdc { cands: vec![c] }), Vec::new(), 8, 3);
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
        assert_eq!(e.slots.len(), 1);
        e.held.push((LO, 54328)); // a static/lease slot claims the tuple
        age(&mut e, HOLD_AFTER_TICKS as usize + 1).await;
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