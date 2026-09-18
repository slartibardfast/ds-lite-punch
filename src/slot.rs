//! Slot engine core: deterministic per-mapping state, lease table with two
//! lookup indices (PCP key / UPnP key), fixed-port-range allocator, epoch
//! and lease persistence.
//!
//! All table logic is pure over small `Vec`s (max `--max-slots`, default 32)
//! so Kani can prove it; the runtime layer (sockets, nft, STUN) lives in
//! `main.rs` and the facade modules. Linear scans are deliberate: at ≤32
//! slots they are nanoseconds, and they keep the proof surface simple.
//!
//! Invariants (Kani-checked):
//!   - one slot per distinct (client, int_port); two indices never diverge;
//!   - bind ports are unique and drawn from [lo, hi] (allocator);
//!   - delete returns the port to the allocator; respawn-restore re-allocates
//!     the exact same ports;
//!   - epoch never decreases for a fixed `created_unix` and restarts near 0
//!     after a simulated reboot (tmpfs loss).
//!
//! Interim `dead_code` allowance (p2-slot-engine): consumers land
//! incrementally — nft element calls (B4), persistence (B6), GC timer (B9),
//! PCP/UPnP facades (D/E). Remove this allow when the B10 merge gate runs
//! `cargo build -D warnings`.
#![allow(dead_code)]
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

// ---- protocol ----

/// UDP and TCP. TCP was structurally refused until C3 measured the AFTR
/// TCP mapping idle lifetime (results/RESULTS-2026-09-13-c3.md); the
/// refusal is lifted by call/0017.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    pub fn code(self) -> u8 {
        match self {
            Proto::Udp => 17, // IANA UDP, on the wire in PCP/NAT-PMP
            Proto::Tcp => 6,  // IANA TCP
        }
    }
}

// ---- leases ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeaseKind {
    Static,
    Granted,
}

/// A mapping grant. `expires_at_unix` is wall-clock seconds (0 = none for
/// Static). Kept as plain integers — not `Instant` — so expiry/GC arithmetic
/// is Kani-provable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lease {
    Static,
    Granted {
        client: Ipv4Addr,
        int_port: u16,
        granted_lifetime: u32,
        expires_at_unix: u64,
    },
}

impl Lease {
    pub fn kind(&self) -> LeaseKind {
        match self {
            Lease::Static => LeaseKind::Static,
            Lease::Granted { .. } => LeaseKind::Granted,
        }
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        match self {
            Lease::Static => false,
            Lease::Granted { expires_at_unix, .. } => now_unix >= *expires_at_unix,
        }
    }
}

// ---- slot ----

#[derive(Clone, Copy, Debug)]
pub struct Slot {
    /// Deterministic bind port R — the CGNAT-facing inner tuple port.
    pub bind_port: u16,
    pub proto: Proto,
    pub target: Ipv4Addr,
    pub target_port: u16,
    pub lease: Lease,
    /// STUN stagger offset in ms (see B5); 0 for the single-slot baseline.
    pub phase_ms: u32,
    /// Wall-clock seconds of last inbound traffic (0 = none seen yet).
    pub last_activity_unix: u64,
}

impl Slot {
    pub fn is_static(&self) -> bool {
        matches!(self.lease, Lease::Static)
    }

    /// PCP key: (proto, internal port, client). Slots without a client (Static)
    /// are not addressable by PCP.
    pub fn pcp_key(&self) -> Option<(Proto, u16, Ipv4Addr)> {
        match self.lease {
            Lease::Granted { client, int_port, .. } => Some((self.proto, int_port, client)),
            Lease::Static => None,
        }
    }

    pub fn client(&self) -> Option<Ipv4Addr> {
        match self.lease {
            Lease::Granted { client, .. } => Some(client),
            Lease::Static => None,
        }
    }
}

// ---- port allocator ----

/// Fixed-range allocator over `[lo, hi]`. Lowest free port first → respawn
/// restores are deterministic. The *used* set is a sorted `Vec` (≤
/// `--max-slots` entries): at that bound linear membership is nanoseconds,
/// and arrays/slices are what the Kani proofs can model — a `BTreeSet`
/// stalled the solver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortAllocator {
    pub lo: u16,
    pub hi: u16,
}

impl PortAllocator {
    pub fn new(lo: u16, hi: u16) -> Option<Self> {
        if lo == 0 || hi < lo {
            return None;
        }
        Some(PortAllocator { lo, hi })
    }

    /// Allocate the first free port in [lo,hi] not present in `used`
    /// (sorted, unique). Returns None when the range is exhausted.
    pub fn allocate(&self, used: &[u16]) -> Option<u16> {
        for port in self.lo..=self.hi {
            if !used.contains(&port) {
                return Some(port);
            }
        }
        None
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.lo && port <= self.hi
    }
}

// ---- lease table ----

/// Result of a MAP/AddPortMapping upsert. Mirrors the facade result codes
/// (0 = success path).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpsertOutcome {
    Granted { bind_port: u16 },
    Refreshed { bind_port: u16 },
    UserQuotaExceeded,
    TableFull,
}

/// The slot table. `slots` is the single source of truth; the two lookup
/// indices are derived views kept in sync by the mutation operations.
#[derive(Clone, Debug)]
pub struct LeaseTable {
    slots: Vec<Slot>,
    allocator: PortAllocator,
    max_slots: usize,
    max_maps_per_client: u16,
    /// Ports a live flow already holds: the punch collision rule (call/0027).
    /// A tuple the change-data-capture shows live belongs to whoever punched
    /// it, so the allocator MUST NOT put a slot on it. Sorted and unique, and
    /// replaced on every refresh rather than accumulated, so a tuple that
    /// goes quiet stops reserving its port.
    avoid: Vec<u16>,
}

impl LeaseTable {
    pub fn new(allocator: PortAllocator, max_slots: usize, max_maps_per_client: u16) -> Self {
        LeaseTable {
            slots: Vec::with_capacity(max_slots), // pre-reserved: no realloc in proofs
            allocator,
            max_slots,
            max_maps_per_client,
            avoid: Vec::new(),
        }
    }

    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    pub fn max_slots(&self) -> usize {
        self.max_slots
    }

    pub fn allocator(&self) -> PortAllocator {
        self.allocator
    }

    /// First free port in [lo,hi] scanning live slots directly — no
    /// intermediate collection, so Kani only sees iteration over arrays.
    /// The first bind port neither this table nor a live punch holds: the
    /// allocation's probe before it claims (call/0027 R3). A port a live flow
    /// already uses is not available, because the AFTR keys its mapping on
    /// the inner tuple and two local owners of one tuple share one inbound
    /// path.
    fn find_free_bind_port(&self) -> Option<u16> {
        for port in self.allocator.lo..=self.allocator.hi {
            if self.avoid.contains(&port) {
                continue;
            }
            if !self.slots.iter().any(|s| s.bind_port == port) {
                return Some(port);
            }
        }
        None
    }

    /// Replace the live-tuple reservation. Callers pass the ports of the
    /// post-NAT tuples the change-data-capture currently shows, which is the
    /// same liveness the observation arm reads, so both mechanisms cannot
    /// disagree about what is in use (call/0027 R2/R3).
    pub fn avoid_ports(&mut self, live: &[u16]) {
        self.avoid = live
            .iter()
            .copied()
            .filter(|p| self.allocator.contains(*p))
            .collect();
        self.avoid.sort_unstable();
        self.avoid.dedup();
    }

    /// The bind ports a device's flow has taken: call/0028's signature, a
    /// connection entry whose NAT side is one of our tuples while its origin
    /// is a br-lan host. The slot's own punch egresses from the NAT address
    /// and an outside peer's datagram carries the peer's source, so neither
    /// reads as a collision; a device's flow does, because that flow is the
    /// incumbent (call/0027 R2) and the port is not ours to take back.
    ///
    /// The addresses are the daemon's constants, the same ones the
    /// observation arm's predicate uses, so both mechanisms read one world.
    pub fn collided(&self, proc_text: &str) -> Vec<u16> {
        let ctx = crate::obs::brlan_ctx();
        let mut out: Vec<u16> = Vec::new();
        for line in proc_text.lines() {
            let Some(e) = crate::obs::parse_line(line) else {
                continue;
            };
            let (nat, port) = e.nat_src();
            if nat != ctx.vm_nat || !ctx.is_brlan(e.orig_src) {
                continue;
            }
            // A static is the operator's configuration (call/0030), so a
            // device's flow on a static's port is reported and the port is
            // left where the config put it: moving it would diverge the
            // running state from the config that produced it. A granted
            // lease is the daemon's, and R4 yields it.
            if self
                .slots
                .iter()
                .any(|s| s.bind_port == port && !s.is_static())
                && !out.contains(&port)
            {
                out.push(port);
            }
        }
        out.sort_unstable();
        out
    }

    /// R4: yield a port a device's flow has taken. The slot keeps its client,
    /// its internal port and the label the client asked for; it takes a port
    /// the probe leaves free, and the caller re-establishes the datapath on
    /// the new one and reports the substitution (R5). `None` means the range
    /// had nowhere to go, and the slot keeps what it has.
    pub fn move_bind_port(&mut self, old: u16) -> Option<u16> {
        let idx = self.slots.iter().position(|s| s.bind_port == old)?;
        // the old port's tuple is a device's now, so the probe must not hand
        // it back to us
        if !self.avoid.contains(&old) {
            self.avoid.push(old);
            self.avoid.sort_unstable();
        }
        let new = self.find_free_bind_port()?;
        self.slots[idx].bind_port = new;
        Some(new)
    }

    /// Put a lease back where it was when a move could not be completed. The
    /// port it came from stays in the probe's view, because a device's flow
    /// holds it now.
    pub fn restore_bind_port(&mut self, from: u16, to: u16) {
        if let Some(s) = self.slots.iter_mut().find(|s| s.bind_port == from) {
            s.bind_port = to;
        }
    }

    /// What the rule is currently steering around, for the log (R5).
    pub fn reserved_ports(&self) -> Vec<u16> {
        self.avoid.clone()
    }

    /// The ports the probe skipped on the way to `chosen`: live tuples below
    /// the port it took, which are the ones the rule actually decided. Empty
    /// means the choice was free and no collision was in play.
    pub fn avoid_steering(&self, chosen: u16) -> Vec<u16> {
        self.avoid
            .iter()
            .copied()
            .filter(|p| *p < chosen && !self.slots.iter().any(|s| s.bind_port == *p))
            .collect()
    }

    // -- indices --

    pub fn by_bind_port(&self, port: u16) -> Option<&Slot> {
        self.slots.iter().find(|s| s.bind_port == port)
    }

    /// PCP index: (proto, int_port, client) -> slot.
    pub fn by_pcp_key(&self, proto: Proto, int_port: u16, client: Ipv4Addr) -> Option<&Slot> {
        self.slots
            .iter()
            .find(|s| s.pcp_key() == Some((proto, int_port, client)))
    }

    /// UPnP index: (bookkeeping ext port, proto) -> slot.
    pub fn by_upnp_key(&self, ext_port: u16, proto: Proto) -> Option<&Slot> {
        // Bookkeeping external port == bind port for UPnP grants: the AFTR's
        // real external port is discovered via STUN and reported separately
        // (E3 GetExternalIPAddress / D4). The UPnP control point key is the
        // port it requested; we treat R as that key so delete/enumerate are
        // unambiguous and unique.
        self.slots.iter().find(|s| s.bind_port == ext_port && s.proto == proto)
    }

    // -- allocation counts --

    pub fn count_for_client(&self, client: Ipv4Addr) -> usize {
        self.slots
            .iter()
            .filter(|s| s.client() == Some(client))
            .count()
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_full(&self) -> bool {
        self.slots.len() >= self.max_slots
    }

    // -- mutations --

    /// Insert or refresh a PCP-keyed lease. Returns the slot's bind port.
    /// Errors: quota / capacity / TCP. Never duplicates a (client,int_port).
    pub fn upsert_pcp(
        &mut self,
        proto: Proto,
        int_port: u16,
        client: Ipv4Addr,
        granted_lifetime: u32,
        now_unix: u64,
        target: Ipv4Addr,
        target_port: u16,
    ) -> UpsertOutcome {
        if let Some(idx) = self.index_of_key(proto, int_port, client) {
            // refresh: extend expiry, keep R and target. The client is
            // provably present (it just sent Add): stamp last-seen too.
            self.slots[idx].lease = Lease::Granted {
                client,
                int_port,
                granted_lifetime,
                expires_at_unix: now_unix.saturating_add(granted_lifetime as u64),
            };
            self.slots[idx].last_activity_unix = now_unix;
            return UpsertOutcome::Refreshed {
                bind_port: self.slots[idx].bind_port,
            };
        }
        if self.count_for_client(client) >= usize::from(self.max_maps_per_client) {
            return UpsertOutcome::UserQuotaExceeded;
        }
        if self.is_full() {
            return UpsertOutcome::TableFull;
        }
        let bind_port = match self.find_free_bind_port() {
            Some(p) => p,
            None => return UpsertOutcome::TableFull,
        };
        self.slots.push(Slot {
            bind_port,
            proto,
            target,
            target_port,
            lease: Lease::Granted {
                client,
                int_port,
                granted_lifetime,
                expires_at_unix: now_unix.saturating_add(granted_lifetime as u64),
            },
            phase_ms: 0, // assigned by the runtime stager
            last_activity_unix: now_unix, // the grant is the first-seen signal
        });
        UpsertOutcome::Granted { bind_port }
    }

    /// Insert a static lease from config (`--static-map R=ip:port`).
    /// Statics are UDP by definition: the classic relay datapath. A TCP
    /// pin arrives via the grant path (call/0017).
    ///
    /// Error is a `Copy` enum, not `String`: the Kani proofs exercise
    /// `restore`/`insert_static` and must not model heap allocation in the
    /// error paths; messages are formatted at the call site.
    pub fn insert_static(
        &mut self,
        bind_port: u16,
        target: Ipv4Addr,
        target_port: u16,
    ) -> Result<u16, StaticMapErr> {
        if !self.allocator.contains(bind_port) {
            return Err(StaticMapErr::OutOfRange { port: bind_port });
        }
        if self.by_bind_port(bind_port).is_some() {
            return Err(StaticMapErr::InUse { port: bind_port });
        }
        self.slots.push(Slot {
            bind_port,
            proto: Proto::Udp,
            target,
            target_port,
            lease: Lease::Static,
            phase_ms: 0,
            last_activity_unix: 0,
        });
        Ok(bind_port)
    }

    fn index_of_key(&self, proto: Proto, int_port: u16, client: Ipv4Addr) -> Option<usize> {
        self.slots.iter().position(|s| s.pcp_key() == Some((proto, int_port, client)))
    }

    /// Remove a lease by UPnP key (bookkeeping ext port == bind port).
    /// Returns the freed bind port, or None if absent.
    ///
    /// `swap_remove` (not `remove`): slot order is semantically irrelevant
    /// — every lookup is key-driven and facades sort at enumeration — and a
    /// single-element copy is what the Kani proofs can model (a tail memmove
    /// stalls the solver).
    pub fn delete_by_ext_port(&mut self, ext_port: u16) -> Option<u16> {
        let idx = self.slots.iter().position(|s| s.bind_port == ext_port)?;
        let port = self.slots[idx].bind_port;
        self.slots.swap_remove(idx);
        Some(port)
    }

    pub fn delete_by_bind_port(&mut self, bind_port: u16) -> Option<u16> {
        self.delete_by_ext_port(bind_port)
    }

    /// GC scan: drop leases expired for `grace` seconds past expiry with no
    /// inbound activity. Static leases are never GC'd. Returns freed ports.
    pub fn gc(&mut self, now_unix: u64, grace_secs: u64) -> Vec<u16> {
        let cutoff_with_activity = now_unix.saturating_sub(grace_secs);
        let mut freed = Vec::new();
        let mut keep = Vec::with_capacity(self.slots.len());
        for s in self.slots.drain(..) {
            let expired = s.lease.is_expired(now_unix);
            let beyond_grace = match &s.lease {
                Lease::Granted { expires_at_unix, .. } => {
                    now_unix.saturating_sub(*expires_at_unix) > grace_secs
                }
                Lease::Static => false,
            };
            let busy = s.last_activity_unix >= cutoff_with_activity;
            if s.is_static() || !expired || !beyond_grace || busy {
                keep.push(s);
            } else {
                freed.push(s.bind_port);
            }
        }
        self.slots = keep;
        freed
    }

    /// The lease policy's last-seen stamp, rate-limited: the datapath can
    /// fire many times a second, so one write per slot per
    /// `min_interval_secs` is plenty of clock resolution for a 24 h policy.
    pub fn stamp_activity_if_stale(
        &mut self,
        bind_port: u16,
        now_unix: u64,
        min_interval_secs: u64,
    ) {
        let Some(s) = self.slots.iter_mut().find(|s| s.bind_port == bind_port) else {
            return;
        };
        if now_unix.saturating_sub(s.last_activity_unix) >= min_interval_secs {
            s.last_activity_unix = now_unix;
        }
    }

    /// Backstop sweep of the lease policy: reap UDP grants whose client
    /// has shown no activity (datapath or control) for `backstop_secs`,
    /// whatever the pool state. Statics never reap. TCP grants are out of
    /// the lease policy entirely: a live TCP splice can be control-silent,
    /// so reaping on the control clock would break a live session (the
    /// AFTR already reaps an idle TCP mapping at the C3 bound). Returns
    /// the freed bind ports.
    pub fn gc_idle(&mut self, now_unix: u64, backstop_secs: u64) -> Vec<u16> {
        let cutoff = now_unix.saturating_sub(backstop_secs);
        let mut freed = Vec::new();
        let mut keep = Vec::with_capacity(self.slots.len());
        for s in self.slots.drain(..) {
            let idle = matches!(&s.lease, Lease::Granted { .. })
                && s.proto == Proto::Udp
                && s.last_activity_unix < cutoff;
            if idle {
                freed.push(s.bind_port);
            } else {
                keep.push(s);
            }
        }
        self.slots = keep;
        freed
    }

    /// The pressure-eviction candidate: the longest-idle UDP grant of a
    /// client OTHER than `requester`, idle past `grace`. The requesting
    /// client's own grants are never evicted (its live mappings stay).
    /// Returns the slot identity the caller needs to tear it down.
    pub fn evict_idle_client(
        &self,
        now_unix: u64,
        grace_secs: u64,
        requester: Ipv4Addr,
    ) -> Option<(u16, Ipv4Addr, u16, Proto)> {
        let cutoff = now_unix.saturating_sub(grace_secs);
        let mut best: Option<(u64, u16, Ipv4Addr, u16)> = None; // (idle, bind, client, int)
        for s in &self.slots {
            let Lease::Granted { client, int_port, .. } = &s.lease else {
                continue;
            };
            if *client == requester || s.proto != Proto::Udp {
                continue;
            }
            if s.last_activity_unix >= cutoff {
                continue;
            }
            let idle = now_unix.saturating_sub(s.last_activity_unix);
            if best.is_none_or(|(b, ..)| idle > b) {
                best = Some((idle, s.bind_port, *client, *int_port));
            }
        }
        best.map(|(_, bind, client, int_port)| (bind, client, int_port, Proto::Udp))
    }

    /// Build the table from persisted lease records after a respawn
    /// (B8). Re-allocates the exact same bind ports; static leases come from
    /// config; granted leases are re-bound with their remaining lifetime.
    /// Returns at most one error naming the first malformed record.
    pub fn restore(
        &mut self,
        static_maps: &[(u16, Ipv4Addr, u16)],
        granted_records: &[GrantedRecord],
        now_unix: u64,
    ) -> Result<(), StaticMapErr> {
        // Static first (config is authoritative; refuses collisions).
        for &(bind_port, ip, port) in static_maps {
            self.insert_static(bind_port, ip, port)?;
        }
        for rec in granted_records {
            if !self.allocator.contains(rec.bind_port) {
                return Err(StaticMapErr::OutOfRange { port: rec.bind_port });
            }
            if self.by_bind_port(rec.bind_port).is_some() {
                return Err(StaticMapErr::InUse { port: rec.bind_port });
            }
            let remaining = rec.expires_at_unix.saturating_sub(now_unix);
            let lifetime = rec.granted_lifetime;
            let expires_at_unix = now_unix.saturating_add(remaining.clamp(1, lifetime as u64));
            self.slots.push(Slot {
                bind_port: rec.bind_port,
                proto: rec.proto,
                target: rec.target,
                target_port: rec.target_port,
                lease: Lease::Granted {
                    client: rec.client,
                    int_port: rec.int_port,
                    granted_lifetime: lifetime,
                    expires_at_unix,
                },
                phase_ms: 0,
                // a restored grant counts as freshly active: never insta-reap
                // a mapping that survived a respawn (the last-seen clock is
                // not persisted; a restart resets it conservatively)
                last_activity_unix: now_unix,
            });
        }
        Ok(())
    }
}

/// Persisted granted lease (leases.tsv row), restored after respawn.
#[derive(Clone, Copy, Debug)]
pub struct GrantedRecord {
    pub bind_port: u16,
    pub proto: Proto,
    pub client: Ipv4Addr,
    pub int_port: u16,
    pub target: Ipv4Addr,
    pub target_port: u16,
    pub granted_lifetime: u32,
    pub expires_at_unix: u64,
}

/// Static-map / restore rejection reason. `Copy`, never carries heap — the
/// Kani proofs walk these error paths.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StaticMapErr {
    /// Bind port outside [slot_lo, slot_hi].
    OutOfRange { port: u16 },
    /// Bind port already held by another slot.
    InUse { port: u16 },
}

// ---- epoch ----

/// PCP ANNOUNCE epoch (B7): seconds since the lease table was first created.
/// Persisted so respawn continues the epoch; reboot restarts near 0 — which
/// is correct, because a reboot killed every CGNAT mapping.
#[derive(Clone, Copy, Debug)]
pub struct Epoch {
    pub created_unix: u64,
}

impl Epoch {
    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn new(created_unix: u64) -> Self {
        Epoch { created_unix }
    }

    pub fn epoch_at(&self, now_unix: u64) -> u32 {
        now_unix.saturating_sub(self.created_unix).min(u32::MAX as u64) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn table() -> LeaseTable {
        LeaseTable::new(PortAllocator::new(30000, 30003).unwrap(), 4, 2)
    }

    #[test]
    fn stamp_rate_limits_and_upsert_seeds_activity() {
        // The lease policy's clock: a grant starts seen at its own
        // creation, and the rate-limited stamp only advances it.
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 50);
        let g = t.upsert_pcp(Proto::Udp, 3478, c, 300, NOW, c, 3478);
        let port = match g {
            UpsertOutcome::Granted { bind_port } => bind_port,
            _ => panic!("must grant"),
        };
        assert_eq!(
            t.by_bind_port(port).unwrap().last_activity_unix,
            NOW,
            "a grant is its own first-seen"
        );
        // a refresh re-stamps (the client is provably present)
        t.upsert_pcp(Proto::Udp, 3478, c, 300, NOW + 50, c, 3478);
        assert_eq!(t.by_bind_port(port).unwrap().last_activity_unix, NOW + 50);
        // rate limit: within the window the stamp does not advance
        t.stamp_activity_if_stale(port, NOW + 60, 15);
        assert_eq!(t.by_bind_port(port).unwrap().last_activity_unix, NOW + 50);
        // past the window it does
        t.stamp_activity_if_stale(port, NOW + 70, 15);
        assert_eq!(t.by_bind_port(port).unwrap().last_activity_unix, NOW + 70);
    }

    #[test]
    fn gc_idle_reaps_only_silent_udp_grants() {
        let mut t = table();
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let b = Ipv4Addr::new(192, 168, 21, 51);
        // a static lease: never reaped
        assert!(t.insert_static(30000, a, 9999).is_ok());
        // an idle UDP grant (silent for 8 days)
        let g1 = t.upsert_pcp(Proto::Udp, 3478, a, 300, NOW - 700_000, a, 3478);
        let p1 = match g1 {
            UpsertOutcome::Granted { bind_port } => bind_port,
            _ => panic!("grant 1"),
        };
        t.stamp_activity_if_stale(p1, NOW - 700_000, 0);
        // a recent UDP grant (stamped 1 h ago): kept
        let g2 = t.upsert_pcp(Proto::Udp, 3479, a, 300, NOW - 3600, a, 3479);
        let p2 = match g2 {
            UpsertOutcome::Granted { bind_port } => bind_port,
            _ => panic!("grant 2"),
        };
        // an idle TCP grant: outside the lease policy, kept
        let g3 = t.upsert_pcp(Proto::Tcp, 80, b, 300, NOW - 700_000, b, 80);
        let p3 = match g3 {
            UpsertOutcome::Granted { bind_port } => bind_port,
            _ => panic!("grant 3"),
        };
        t.stamp_activity_if_stale(p3, NOW - 700_000, 0);
        let freed = t.gc_idle(NOW, 604_800);
        assert_eq!(freed, vec![p1], "only the silent UDP grant reaps");
        assert!(t.by_bind_port(30000).is_some(), "static kept");
        assert!(t.by_bind_port(p2).is_some(), "recent grant kept");
        assert!(t.by_bind_port(p3).is_some(), "TCP grant kept");
    }

    #[test]
    fn evict_idle_client_picks_longest_idle_other_client() {
        let mut t = LeaseTable::new(PortAllocator::new(30000, 30009).unwrap(), 8, 4);
        let requester = Ipv4Addr::new(192, 168, 21, 50);
        let other = Ipv4Addr::new(192, 168, 21, 51);
        // the requester's own idle grant: never a candidate
        let g_self = t.upsert_pcp(Proto::Udp, 1000, requester, 300, NOW - 700_000, requester, 1000);
        let p_self = match g_self {
            UpsertOutcome::Granted { bind_port } => bind_port,
            _ => panic!("self grant"),
        };
        t.stamp_activity_if_stale(p_self, NOW - 700_000, 0);
        // another client, idle 30 h (past the 24 h grace)
        let g_a = t.upsert_pcp(Proto::Udp, 1001, other, 300, NOW - 100_000, other, 1001);
        let p_a = match g_a {
            UpsertOutcome::Granted { bind_port } => bind_port,
            _ => panic!("other grant"),
        };
        t.stamp_activity_if_stale(p_a, NOW - 100_000, 0);
        // a third client idle 8 days: the longest
        let third = Ipv4Addr::new(192, 168, 21, 52);
        let g_b = t.upsert_pcp(Proto::Udp, 1002, third, 300, NOW - 700_000, third, 1002);
        let p_b = match g_b {
            UpsertOutcome::Granted { bind_port } => bind_port,
            _ => panic!("third grant"),
        };
        t.stamp_activity_if_stale(p_b, NOW - 700_000, 0);
        // a TCP grant of another client: outside the policy
        let g_t = t.upsert_pcp(Proto::Tcp, 80, Ipv4Addr::new(192, 168, 21, 53), 300, NOW - 700_000, Ipv4Addr::new(192, 168, 21, 53), 80);
        let p_t = match g_t {
            UpsertOutcome::Granted { bind_port } => bind_port,
            _ => panic!("tcp grant"),
        };
        t.stamp_activity_if_stale(p_t, NOW - 700_000, 0);
        let got = t.evict_idle_client(NOW, 86_400, requester);
        assert_eq!(got, Some((p_b, third, 1002, Proto::Udp)), "longest-idle other-client UDP");
        assert!(got != Some((p_self, requester, 1000, Proto::Udp)), "requester never evicted");
    }

    #[test]
    fn restore_counts_grants_freshly_active() {
        // a respawned grant must never be insta-reaped by the backstop:
        // restore seeds last-seen = now (the clock is not persisted).
        let mut t = table();
        t.restore(
            &[],
            &[GrantedRecord {
                bind_port: 30000,
                proto: Proto::Udp,
                client: Ipv4Addr::new(192, 168, 21, 50),
                int_port: 3478,
                target: Ipv4Addr::new(192, 168, 21, 50),
                target_port: 3478,
                granted_lifetime: 300,
                expires_at_unix: NOW + 300,
            }],
            NOW,
        )
        .expect("restore ok");
        assert_eq!(
            t.by_bind_port(30000).unwrap().last_activity_unix,
            NOW,
            "restored grant starts seen at restore"
        );
        assert!(
            t.gc_idle(NOW, 604_800).is_empty(),
            "backstop must not reap a just-restored grant"
        );
    }

    #[test]
    fn allocator_lowest_free() {
        let a = PortAllocator::new(30000, 30002).unwrap();
        let mut used: Vec<u16> = vec![30000, 30002];
        used.sort_unstable();
        assert_eq!(a.allocate(&used), Some(30001));
        used.push(30001);
        used.sort_unstable();
        assert_eq!(a.allocate(&used), None);
    }

    #[test]
    fn upsert_grants_then_refreshes_same_r() {
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 50);
        let g = t.upsert_pcp(Proto::Udp, 3478, c, 300, NOW, c, 3478);
        let (port, outcome) = match g {
            UpsertOutcome::Granted { bind_port } => (bind_port, "granted"),
            _ => panic!("first upsert must grant"),
        };
        assert_eq!(outcome, "granted");
        assert_eq!(t.len(), 1);
        let r = t.upsert_pcp(Proto::Udp, 3478, c, 300, NOW + 100, c, 3478);
        match r {
            UpsertOutcome::Refreshed { bind_port } => assert_eq!(bind_port, port),
            _ => panic!("second upsert must refresh"),
        }
        assert_eq!(t.len(), 1, "refresh must not duplicate");
    }

    #[test]
    fn quota_and_capacity() {
        let mut t = table();
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let b = Ipv4Addr::new(192, 168, 21, 51);
        assert!(matches!(
            t.upsert_pcp(Proto::Udp, 1000, a, 60, NOW, a, 1000),
            UpsertOutcome::Granted { .. }
        ));
        assert!(matches!(
            t.upsert_pcp(Proto::Udp, 1001, a, 60, NOW, a, 1001),
            UpsertOutcome::Granted { .. }
        ));
        assert_eq!(
            t.upsert_pcp(Proto::Udp, 1002, a, 60, NOW, a, 1002),
            UpsertOutcome::UserQuotaExceeded
        );
        // full table: two more distinct clients -> table full
        assert!(matches!(
            t.upsert_pcp(Proto::Udp, 2000, b, 60, NOW, b, 2000),
            UpsertOutcome::Granted { .. }
        ));
        let c = Ipv4Addr::new(192, 168, 21, 52);
        assert!(matches!(
            t.upsert_pcp(Proto::Udp, 3000, c, 60, NOW, c, 3000),
            UpsertOutcome::Granted { .. }
        ));
        assert_eq!(
            t.upsert_pcp(Proto::Udp, 4000, c, 60, NOW, c, 4000),
            UpsertOutcome::TableFull
        );
    }

    #[test]
    fn tcp_grant_and_udp_share_the_table_proto_dimension() {
        // C3 unlocked TCP grants (call/0017): the same (client, int_port)
        // across protocols yields distinct slots with their own bind
        // ports, matching the AFTR's per-protocol external ports.
        assert_eq!(Proto::Udp.code(), 17);
        assert_eq!(Proto::Tcp.code(), 6);
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 50);
        assert!(matches!(
            t.upsert_pcp(Proto::Tcp, 3478, c, 300, NOW, c, 3478),
            UpsertOutcome::Granted { .. }
        ));
        let g = t.upsert_pcp(Proto::Udp, 3478, c, 300, NOW, c, 3478);
        match g {
            UpsertOutcome::Granted { bind_port } => {
                let s = t.by_bind_port(bind_port).unwrap();
                assert_eq!(s.proto, Proto::Udp);
            }
            _ => panic!("UDP grant expected"),
        }
        let tcp_slot = t
            .slots()
            .iter()
            .find(|s| s.proto == Proto::Tcp)
            .expect("a TCP slot exists");
        assert_eq!(tcp_slot.pcp_key(), Some((Proto::Tcp, 3478, c)));
    }

    #[test]
    fn delete_frees_port() {
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 50);
        let UpsertOutcome::Granted { bind_port } =
            t.upsert_pcp(Proto::Udp, 3478, c, 300, NOW, c, 3478)
        else {
            panic!()
        };
        assert_eq!(t.delete_by_ext_port(bind_port), Some(bind_port));
        assert_eq!(t.len(), 0);
        // port is reusable
        let g2 = t.upsert_pcp(Proto::Udp, 3478, c, 300, NOW, c, 3478);
        match g2 {
            UpsertOutcome::Granted { bind_port: p2 } => assert_eq!(p2, bind_port),
            _ => panic!("reuse must succeed"),
        }
    }

    #[test]
    fn gc_frees_only_expired_unbusy_grants() {
        let mut t = table();
        let a = Ipv4Addr::new(192, 168, 21, 50);
        // static lease survives GC
        t.insert_static(30003, a, 1).unwrap();
        let UpsertOutcome::Granted { bind_port } =
            t.upsert_pcp(Proto::Udp, 3478, a, 60, NOW, a, 3478)
        else {
            panic!()
        };
        // GC at NOW+100: lease (expires NOW+60) is past expiry and past the
        // 30 s grace; activity at NOW+90 is inside the grace window -> keep.
        let idx = t.slots.iter().position(|s| s.bind_port == bind_port).unwrap();
        t.slots[idx].last_activity_unix = NOW + 90;
        let freed = t.gc(NOW + 100, 30);
        assert!(freed.is_empty(), "busy slot must survive: {:?}", freed);
        // same slot, now idle -> freed; static slot survives.
        let idx = t.slots.iter().position(|s| s.bind_port == bind_port).unwrap();
        t.slots[idx].last_activity_unix = 0;
        let freed = t.gc(NOW + 100, 30);
        assert_eq!(freed, vec![bind_port]);
        assert!(t.by_bind_port(30003).is_some(), "static must never GC");
    }

    #[test]
    fn restore_is_deterministic() {
        let mut t = table();
        let a = Ipv4Addr::new(192, 168, 21, 50);
        t.upsert_pcp(Proto::Udp, 3478, a, 300, NOW, a, 3478);
        let slots: Vec<Slot> = t.slots().to_vec();
        let records: Vec<GrantedRecord> = slots
            .iter()
            .filter_map(|s| match s.lease {
                Lease::Granted { client, int_port, granted_lifetime, expires_at_unix } => {
                    Some(GrantedRecord {
                        bind_port: s.bind_port,
                        proto: s.proto,
                        client,
                        int_port,
                        target: s.target,
                        target_port: s.target_port,
                        granted_lifetime,
                        expires_at_unix,
                    })
                }
                Lease::Static => None,
            })
            .collect();

        let mut t2 = table();
        t2.restore(&[], &records, NOW + 100).unwrap();
        assert_eq!(t2.len(), 1);
        let s = t2.slots()[0];
        assert_eq!(s.bind_port, slots[0].bind_port);
        assert_eq!(s.lease, slots[0].lease);
        // collision refused
        let mut t3 = table();
        t3.insert_static(slots[0].bind_port, a, 1).unwrap();
        assert!(t3.restore(&[], &records, NOW + 100).is_err());
    }

    #[test]
    fn epoch_never_decreases_and_restarts() {
        let e = Epoch::new(1_700_000_000);
        assert_eq!(e.epoch_at(1_700_000_000), 0);
        assert!(e.epoch_at(1_700_000_100) >= e.epoch_at(1_700_000_050));
        // reboot: new created_unix -> small epoch again
        let rebooted = Epoch::new(1_800_000_000);
        let r1 = rebooted.epoch_at(1_800_000_010);
        let r2 = e.epoch_at(1_800_000_010);
        assert!(r1 < r2, "restart must reset epoch below the continuous one");
    }

    // ---- the punch collision rules (call/0027) ----

    fn candidate(ip: &str, port: u16) -> (Ipv4Addr, u16) {
        (ip.parse().unwrap(), port)
    }

    #[test]
    fn a_live_punch_reserves_its_port_from_allocation() {
        // R2/R3: the incumbent keeps the tuple, and the allocator probes
        // before it claims. Slot 30000 is live from a punch nobody allocated,
        // so a fresh grant takes the next free port instead of sharing a
        // tuple the AFTR would then key as one mapping.
        let mut t = table();
        t.avoid_ports(&[30000]);
        let c = Ipv4Addr::new(192, 168, 21, 68);
        let g = t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478);
        assert_eq!(g, UpsertOutcome::Granted { bind_port: 30001 });
        // and the choice is reportable: the ports the rule steered around,
        // below the one it took
        assert_eq!(t.avoid_steering(30001), vec![30000]);
    }

    #[test]
    fn a_renewal_keeps_its_port_even_when_the_probe_would_avoid_it() {
        // R4's neighbour: a refresh allocates nothing. The slot's own punch
        // puts its tuple in the live set, so a renewal must not read that
        // set as a reason to move.
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 68);
        assert_eq!(
            t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478),
            UpsertOutcome::Granted { bind_port: 30000 }
        );
        t.avoid_ports(&[30000]);
        assert_eq!(
            t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW + 30, c, 3478),
            UpsertOutcome::Refreshed { bind_port: 30000 },
            "a renewal holds the port it already has"
        );
    }

    #[test]
    fn the_reservation_follows_the_live_set_and_is_not_a_leak() {
        // The set is replaced, never accumulated: a tuple that goes quiet
        // stops being reserved, so a port cannot be lost to a flow that is
        // gone. (One refresh, one set.)
        let mut t = table();
        t.avoid_ports(&[30000]);
        t.avoid_ports(&[]);
        let c = Ipv4Addr::new(192, 168, 21, 68);
        assert_eq!(
            t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478),
            UpsertOutcome::Granted { bind_port: 30000 },
            "nothing is live now, so the lowest port is free again"
        );
    }

    #[test]
    fn steering_ignores_what_the_range_cannot_allocate() {
        // A live tuple outside the slot range costs nothing and is not
        // reported as a decision: the allocator never considered it.
        let mut t = table();
        t.avoid_ports(&[12345, 30002]);
        let c = Ipv4Addr::new(192, 168, 21, 68);
        let g = t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478);
        assert_eq!(g, UpsertOutcome::Granted { bind_port: 30000 });
        assert!(t.avoid_steering(30000).is_empty(), "nothing was skipped");
        // with the low ports live, the third port is the first free one and
        // the two it skipped are named
        let mut t = table();
        t.avoid_ports(&[30000, 30001]);
        assert_eq!(
            t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478),
            UpsertOutcome::Granted { bind_port: 30002 }
        );
        assert_eq!(t.avoid_steering(30002), vec![30000, 30001]);
    }

    #[test]
    fn a_client_outside_the_allowlist_is_not_a_collision() {
        // R7 stated as a test: the probe knows tuples, not identities. A
        // live tuple is reserved whatever its origin, and its owner is not
        // thereby admitted to anything.
        let mut t = table();
        t.avoid_ports(&[candidate("192.168.21.59", 30000).1]);
        assert_eq!(t.avoid_steering(30001), vec![30000]);
        assert_eq!(t.reserved_ports(), vec![30000]);
    }

    // ---- R4: the late collision (call/0027, call/0028) ----

    /// A device's flow on a leased tuple, in the shape the router prints it:
    /// its pre-NAT origin is the device, and the NAT side is the bind port.
    fn device_flow(host: &str, sport: u16) -> String {
        format!(
            "ipv4     2 udp      17 100 src={} dst=8.8.8.8 sport={} dport=53 packets=1 bytes=92 \
             src=8.8.8.8 dst=192.168.0.21 sport=53 dport={} packets=1 bytes=60 mark=0 zone=0 use=2",
            host, sport, sport
        )
    }

    #[test]
    fn a_device_flow_on_a_leased_tuple_is_a_collision() {
        // The signature call/0028 names: a connection entry whose NAT side is
        // our bind tuple and whose origin is a device.
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 68);
        assert_eq!(
            t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478),
            UpsertOutcome::Granted { bind_port: 30000 }
        );
        let text = device_flow("192.168.21.68", 30000);
        assert_eq!(t.collided(&text), vec![30000]);
    }

    #[test]
    fn a_static_is_the_operators_and_is_never_the_slot_that_moves() {
        // call/0030: a static mapping is the operator's configuration, and
        // the same rule that releases a console's mapping leaves the
        // configured relay alone. A device's flow that lands on a static's
        // port is still a collision, and the log is where it becomes
        // visible, but the port is not the daemon's to take: yielding it
        // would put the operator's own relay on a port they never chose, and
        // the running state would diverge from the config that produced it.
        let mut t = table();
        assert!(t
            .insert_static(30002, Ipv4Addr::new(192, 168, 21, 12), 40000)
            .is_ok());
        let text = device_flow("192.168.21.68", 30002);
        assert!(
            t.collided(&text).is_empty(),
            "a static's port is the operator's, not a lease the yield may move"
        );
    }

    #[test]
    fn the_slots_own_punch_is_not_a_collision() {
        // A slot's keepalive egresses from (NAT, R) itself: the origin is the
        // NAT address, not a device, and that is the flow we own.
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 68);
        t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478);
        let own = "ipv4     2 udp      17 100 src=192.168.0.21 dst=162.159.207.0 sport=30000 dport=3478 packets=41 bytes=1968 src=162.159.207.0 dst=192.168.0.21 sport=3478 dport=30000 packets=41 bytes=2460 [ASSURED] mark=0 zone=0 use=2";
        assert!(t.collided(own).is_empty(), "our own punch is not a collision");
    }

    #[test]
    fn an_outside_peer_on_the_tuple_is_not_a_collision() {
        // An external prober's datagram reaches the same tuple and must not
        // make the slot move: the incumbent rule is about a device's flow,
        // not about who is knocking.
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 68);
        t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478);
        let peer = "ipv4     2 udp      17 25 src=170.9.238.141 dst=192.168.0.21 sport=39897 dport=30000 packets=1 bytes=37 [UNREPLIED] src=192.168.21.68 dst=170.9.238.141 sport=30000 dport=39897 packets=0 bytes=0 mark=0 zone=0 use=2";
        assert!(t.collided(peer).is_empty(), "a peer is not a device's flow");
    }

    #[test]
    fn a_device_flow_on_an_unleased_port_is_not_ours_to_move() {
        // R7: a punch nobody allocated is left to its owner, and the table
        // only speaks for the ports it holds.
        let t = table();
        assert!(t.collided(&device_flow("192.168.21.68", 30000)).is_empty());
    }

    #[test]
    fn a_yield_takes_a_free_port_and_keeps_the_label() {
        // R4: the slot moves, the client's label does not, and the lease's
        // client and internal port are untouched.
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 68);
        t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478);
        // the colliding tuple is live, so the probe must steer past it
        t.avoid_ports(&[30000]);
        assert_eq!(t.move_bind_port(30000), Some(30001));
        let s = t.by_bind_port(30001).expect("the slot moved");
        assert_eq!(s.pcp_key(), Some((Proto::Udp, 3478, c)), "key and label intact");
        // and the old port is free again for the next allocation
        assert!(t.by_bind_port(30000).is_none());
    }

    #[test]
    fn a_failed_yield_can_be_put_back() {
        // The caller moves the lease first and establishes the datapath after,
        // so a failure needs the row back where it was: the old port stays in
        // the probe's view either way, since a device's flow holds it.
        let mut t = table();
        let c = Ipv4Addr::new(192, 168, 21, 68);
        t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478);
        assert_eq!(t.move_bind_port(30000), Some(30001));
        t.restore_bind_port(30001, 30000);
        assert_eq!(t.by_bind_port(30000).map(|s| s.pcp_key()), Some(Some((Proto::Udp, 3478, c))));
        assert!(t.reserved_ports().contains(&30000), "the taken port stays avoided");
    }

    #[test]
    fn a_yield_with_nowhere_to_go_reports_and_leaves_it() {
        // The range is a budget: when it is full the slot stays where it is
        // and says so, which is R5's report rather than a silent failure.
        let mut t = LeaseTable::new(PortAllocator::new(30000, 30001).unwrap(), 4, 2);
        let c = Ipv4Addr::new(192, 168, 21, 68);
        t.upsert_pcp(Proto::Udp, 3478, c, 600, NOW, c, 3478);
        t.upsert_pcp(Proto::Udp, 3479, c, 600, NOW, c, 3479);
        t.avoid_ports(&[30000, 30001]);
        assert_eq!(t.move_bind_port(30000), None);
        assert!(t.by_bind_port(30000).is_some(), "it keeps what it has");
    }
}

/// Kani proofs: lease-table invariants and exact-inverse/edge arithmetic.
#[cfg(kani)]
mod verify {
    use super::*;

    fn alloc_ok() -> PortAllocator {
        PortAllocator::new(30000, 30009).unwrap()
    }

    #[kani::proof]
    fn allocator_never_double_allocates() {
        // Concrete small range: the allocate loop has a fixed bound; Kani
        // explores membership, not range arithmetic.
        let a = PortAllocator { lo: 30001, hi: 30004 };
        // Fixed-size symbolic used-set, sentinel-padded: entries are either
        // in-range or 0 (inert, since lo >= 1). No counters, no dynamic
        // array writes — just element reads, which CBMC handles cheaply.
        let used: [u16; 4] = kani::any();
        for p in used.iter() {
            kani::assume(*p == 0 || a.contains(*p));
        }
        if let Some(p) = a.allocate(&used) {
            assert!(!used.contains(&p), "allocate must return an unused port");
        }
    }

    #[kani::proof]
    fn allocator_none_only_when_exhausted() {
        // Concrete full used-set: None is reachable and provably only then.
        let a = PortAllocator { lo: 30000, hi: 30002 };
        let used = [30000u16, 30001, 30002];
        assert_eq!(a.allocate(&used), None);
        // One free slot left -> Some(that slot)
        assert_eq!(a.allocate(&used[..2]), Some(30002));
    }

    #[kani::proof]
    fn allocator_returns_in_range() {
        let a = PortAllocator { lo: 30001, hi: 30004 };
        let used: [u16; 4] = kani::any();
        for p in used.iter() {
            kani::assume(*p == 0 || a.contains(*p));
        }
        if let Some(p) = a.allocate(&used) {
            assert!(a.contains(p), "allocated port must be inside the range");
        }
    }

    #[kani::proof]
    #[kani::unwind(8)] // max_slots assumed <= 7 below
    fn upsert_unique_key_never_duplicates() {
        // I1 core: same (proto, int_port, client) key never yields a second
        // holder. Symbolic in the key dimensions; time/life concrete (the
        // property does not depend on them and symbolic u64 inflated the
        // Vec-push state space).
        let mut t = LeaseTable::new(alloc_ok(), 7, 4);
        let octets: [u8; 4] = kani::any(); // Ipv4Addr is not kani::Arbitrary
        let c = Ipv4Addr::from(octets);
        let ip: u16 = kani::any();
        let r1 = t.upsert_pcp(Proto::Udp, ip, c, 300, 1_000, c, ip);
        let n1 = t.len();
        let r2 = t.upsert_pcp(Proto::Udp, ip, c, 300, 1_001, c, ip);
        // Fresh key on an empty table always grants; the same key always
        // refreshes (the key check precedes quota/capacity).
        let UpsertOutcome::Granted { bind_port: p1 } = r1 else {
            panic!("first upsert must grant on an empty table");
        };
        let UpsertOutcome::Refreshed { bind_port: p2 } = r2 else {
            panic!("second upsert of the same key must refresh, never re-grant");
        };
        assert_eq!(p1, p2, "refresh must keep the same R");
        assert_eq!(t.len(), n1, "same key must not grow the table");
        // And the index agrees: exactly one slot addresses this key.
        let slot = t.by_pcp_key(Proto::Udp, ip, c);
        assert!(slot.is_some() && slot.unwrap().bind_port == p1);
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn delete_removes_only_target_slot() {
        // Delete semantics: removing ext_port p1 leaves every other slot
        // intact and frees the port for reuse. Concrete ports (the property
        // is about the delete operation, not the port values).
        let mut t = LeaseTable::new(alloc_ok(), 8, 4);
        let c = Ipv4Addr::new(192, 168, 21, 50);
        let UpsertOutcome::Granted { bind_port: p1 } =
            t.upsert_pcp(Proto::Udp, 1000, c, 60, 0, c, 1000)
        else {
            panic!()
        };
        let UpsertOutcome::Granted { bind_port: p2 } =
            t.upsert_pcp(Proto::Udp, 1001, c, 60, 0, c, 1001)
        else {
            panic!()
        };
        assert_ne!(p1, p2);
        let n = t.len();
        assert_eq!(t.delete_by_ext_port(p1), Some(p1));
        assert_eq!(t.len(), n - 1);
        assert!(t.by_bind_port(p2).is_some(), "other slot must survive");
        assert!(t.by_bind_port(p1).is_none(), "deleted slot must be gone");
        // freed port is immediately reusable
        let r3 = t.upsert_pcp(Proto::Udp, 1002, c, 60, 0, c, 1002);
        match r3 {
            UpsertOutcome::Granted { bind_port: p3 } => assert_eq!(p3, p1, "port must be reused lowest-first"),
            _ => panic!("reuse must grant"),
        }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn restore_rebinds_exact_port() {
        // B8: respawn restore re-binds the exact same R. Single record —
        // multi-record ordering is unit-tested (restore_is_deterministic);
        // the proof owns the mechanical guarantee per record, symbolically
        // in the record's port so both in-range and out-of-range bind ports
        // are explored.
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let port: u16 = kani::any();
        kani::assume(port <= 30009); // alloc_ok() hi bound
        let rec = GrantedRecord {
            bind_port: port,
            proto: Proto::Udp,
            client: a,
            int_port: 1000,
            target: a,
            target_port: 1000,
            granted_lifetime: 300,
            expires_at_unix: 400,
        };
        let mut t = LeaseTable::new(alloc_ok(), 8, 4);
        // in-range -> rebind exact; out-of-range -> OutOfRange error
        match t.restore(&[], &[rec], 150) {
            Ok(()) => {
                assert_eq!(t.slots().len(), 1);
                assert!(t.allocator().contains(port));
                assert_eq!(t.slots()[0].bind_port, port);
            }
            Err(StaticMapErr::OutOfRange { port: p }) => {
                assert_eq!(p, port);
                assert!(!t.allocator().contains(port));
                assert_eq!(t.slots().len(), 0);
            }
            Err(_) => panic!("only OutOfRange is reachable for an empty table"),
        }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn restore_rejects_collision() {
        // A static map already holding the port must make restore refuse the
        // granted record rather than double-allocate.
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let mut t = LeaseTable::new(alloc_ok(), 8, 4);
        assert!(t.insert_static(30005, a, 4444).is_ok());
        let rec = GrantedRecord {
            bind_port: 30005,
            proto: Proto::Udp,
            client: a,
            int_port: 1000,
            target: a,
            target_port: 1000,
            granted_lifetime: 300,
            expires_at_unix: 400,
        };
        let r = t.restore(&[(30005, a, 4444)], &[rec], 150);
        assert!(matches!(r, Err(StaticMapErr::InUse { port: 30005 })));
        assert_eq!(t.slots().len(), 1, "static slot remains, no duplicate");
    }

    #[kani::proof]
    fn epoch_monotonic_and_bounded() {
        let created: u64 = kani::any();
        let n1: u64 = kani::any();
        let n2: u64 = kani::any();
        kani::assume(n2 >= n1);
        let e = Epoch::new(created);
        assert!(e.epoch_at(n2) >= e.epoch_at(n1), "epoch must be monotone in now");
        // epoch is u32 by construction (saturating_sub caps at u32::MAX)
    }

    #[kani::proof]
    fn lease_expiry_matches_definition() {
        let now: u64 = kani::any();
        let exp: u64 = kani::any();
        let l = Lease::Granted {
            client: Ipv4Addr::new(192, 168, 21, 50),
            int_port: 3478,
            granted_lifetime: 60,
            expires_at_unix: exp,
        };
        assert_eq!(l.is_expired(now), now >= exp, "expiry is exactly now>=expiry");
        assert!(!Lease::Static.is_expired(now), "static never expires");
    }
}
