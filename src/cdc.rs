//! G1 change-data-capture (brief v2 §10.1, DECIDED 2026-09-01).
//!
//! One `Cdc` trait, three backends, one contract: *live bidirectional UDP
//! candidates with shadow-bind tuples at ≤2 s cadence*.
//!
//!   (a) nft `flow_obs` dynamic-set mirror  — primary. Gating test PASSED
//!       2026-09-02: a filter-postrouting observer at priority 110 (> fw4
//!       srcnat 100) records post-NAT tuples, so elements ARE the
//!       shadow-bind tuples `(192.168.0.21, R_nat)` directly.
//!   (b) Aya TC hook on br-lan              — performance tier (first-class,
//!       not an escalation; BTF confirmed on-box). Not wired yet.
//!   (c) `/proc/net/nf_conntrack` polling   — fallback (`--cdc proc`;
//!       David: "I don't like 1, keep it as a fallback").
//!
//! Both the nft mirror and the proc read feed the same Kani-proven `obs`
//! predicate; the mirror's 15 s kernel expiry is the silence detector, the
//! proc table provides identity (host, host_port) for fresh tuples.
use crate::obs::{scan, ObsCtx, RefreshCandidate};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use crate::publish::{emiteln};

/// One live candidate: the shadow-bind tuple (`bind_tuple`, alias of
/// `obs::RefreshCandidate`) + the br-lan flow origin (`host`/`host_port`,
/// the pin key).
pub type Candidate = RefreshCandidate;

/// br-lan prefix (hosts eligible for refresh) and the hub-LAN NAT address
/// flows egress from — defaults matching `obs::brlan_ctx`.
pub const BR_LAN: (Ipv4Addr, u8) = (Ipv4Addr::new(192, 168, 21, 0), 24);
pub const VM_NAT: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 21);
pub const PROC_PATH: &str = "/proc/net/nf_conntrack";

/// Backend selector (`--cdc`). Kani-irrelevant; startup-decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdcKind {
    Proc,
    Nft,
    Aya,
}

/// The backends are used behind an `Arc` inside a spawned task, and the
/// engine now reads the lease table across an await while it holds one, so
/// the trait carries both bounds the runtime needs.
pub trait Cdc: Send + Sync {
    /// Live candidates this tick. Cheap by contract: capped at the refresh
    /// budget, no blocking beyond a kernel table read, 2 s cadence.
    fn tick(&mut self) -> Vec<Candidate>;
    fn name(&self) -> &'static str;
}

/// `/proc/net/nf_conntrack` polling backend (G1 fallback).
pub struct ProcCdc {
    /// The allowlist: the admission for a flow the device itself has not
    /// been answered on (call/0029).
    allowed: Vec<Ipv4Addr>,
    path: String,
    brlan: (Ipv4Addr, u8),
    vm_nat: Ipv4Addr,
    owned: Vec<(Ipv4Addr, u16)>,
    max_refresh_attempts: u32,
}

impl ProcCdc {
    /// held = inner tuples static/lease slots own (I1: never capture one).
    pub fn new(owned: Vec<(Ipv4Addr, u16)>, max_refresh_attempts: u32, allowed: Vec<Ipv4Addr>) -> Self {
        ProcCdc {
            path: PROC_PATH.to_string(),
            brlan: BR_LAN,
            vm_nat: VM_NAT,
            owned,
            max_refresh_attempts,
            allowed,
        }
    }
}

impl Cdc for ProcCdc {
    fn tick(&mut self) -> Vec<Candidate> {
        let f = match std::fs::read_to_string(&self.path) {
            Ok(f) => f,
            Err(e) => {
                emiteln!("warn: cdc(proc): {}: {}", self.path, e);
                return Vec::new();
            }
        };
        let ctx = ObsCtx {
            brlan: self.brlan,
            vm_nat: self.vm_nat,
            allowed: &self.allowed,
            owned: &self.owned,
            max_refresh_attempts: self.max_refresh_attempts,
            refresh_attempts_so_far: 0,
        };
        scan(&f, &ctx)
    }

    fn name(&self) -> &'static str {
        "proc"
    }
}

/// nft `flow_obs` mirror backend (G1 primary; gating test PASSED
/// 2026-09-02). The mirror carries the shadow-bind tuples `(192.168.0.21,
/// R_nat)` directly (post-NAT, port-preserving) with a 15 s kernel expiry —
/// the silence detector. Identity (host, host_port — the pin key and the
/// promotion target) is not in the mirror: it is resolved once per fresh
/// tuple from a `/proc` scan, then cached until the mirror evicts the tuple.
/// Steady state does zero proc reads.
pub struct NftCdc {
    known: HashMap<(Ipv4Addr, u16), Candidate>,
    owned: Vec<(Ipv4Addr, u16)>,
    max_refresh_attempts: u32,
    /// The allowlist, as for the proc backend.
    allowed: Vec<Ipv4Addr>,
}

impl NftCdc {
    pub fn new(owned: Vec<(Ipv4Addr, u16)>, max_refresh_attempts: u32, allowed: Vec<Ipv4Addr>) -> Self {
        NftCdc {
            known: HashMap::new(),
            owned,
            max_refresh_attempts,
            allowed,
        }
    }
}

impl Cdc for NftCdc {
    fn tick(&mut self) -> Vec<Candidate> {
        let live = match crate::nft::list_flow_obs() {
            Ok(l) => l,
            Err(e) => {
                emiteln!("warn: cdc(nft): list flow_obs failed: {}", e);
                return Vec::new();
            }
        };
        let proc_text = if live.iter().any(|t| !self.known.contains_key(t)) {
            std::fs::read_to_string(PROC_PATH).ok()
        } else {
            None // steady state: every live tuple already has an identity
        };
        reconcile(
            &live,
            proc_text.as_deref(),
            &mut self.known,
            &self.owned,
            self.max_refresh_attempts,
            &self.allowed,
        )
    }

    fn name(&self) -> &'static str {
        "nft"
    }
}

/// Pure reconcile: given the live mirror tuples and (optionally) a proc
/// snapshot, return the live candidates — resolving + caching identity for
/// tuples not yet known, pruning evicted ones. Unit-tested with real list-
/// set output and proc lines (Kani non-goal, like the rest of the CLI
/// boundary).
fn reconcile(
    live: &[(Ipv4Addr, u16)],
    proc_text: Option<&str>,
    known: &mut HashMap<(Ipv4Addr, u16), Candidate>,
    owned: &[(Ipv4Addr, u16)],
    max_refresh_attempts: u32,
    allowed: &[Ipv4Addr],
) -> Vec<Candidate> {
    let fresh: Vec<(Ipv4Addr, u16)> = live
        .iter()
        .copied()
        .filter(|t| !known.contains_key(t))
        .collect();
    if !fresh.is_empty() {
        if let Some(f) = proc_text {
            let ctx = ObsCtx {
                brlan: BR_LAN,
                vm_nat: VM_NAT,
                owned,
                max_refresh_attempts,
                allowed,
                refresh_attempts_so_far: 0,
            };
            for c in scan(f, &ctx) {
                if fresh.contains(&c.bind_tuple) {
                    known.insert(c.bind_tuple, c);
                }
            }
        }
    }
    known.retain(|t, _| live.contains(t));
    live.iter().filter_map(|t| known.get(t).copied()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real line captured on the router (2026-08-31): a br-lan container UDP
    // flow egressing the VM line — same shape as obs.rs's GOOD fixture.
    const GOOD: &str = "ipv4     2 udp      17 56 src=192.168.21.10 dst=8.8.8.8 sport=54322 dport=53 packets=1 bytes=92 [UNREPLIED] src=8.8.8.8 dst=192.168.0.21 sport=53 dport=54322 packets=0 bytes=0 mark=0 zone=0 use=2";

    /// Make the flow bidirectional ([ASSURED], reply packets > 0).
    fn replied(g: &str) -> String {
        g.replace("[UNREPLIED]", "")
            .replace("packets=0 bytes=0 mark=", "[ASSURED] packets=3 bytes=210 mark=")
    }

    fn temp_table(name: &str, body: &str) -> String {
        let dir = std::env::temp_dir().join(format!("dslp-cdc-{}-{}", std::process::id(), name));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("nf_conntrack");
        std::fs::write(&p, body).unwrap();
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn proc_tick_yields_live_candidates() {
        let path = temp_table("one", &format!("{}\n", replied(GOOD)));
        let mut cdc = ProcCdc {
            path,
            brlan: BR_LAN,
            vm_nat: VM_NAT,
            owned: Vec::new(),
            max_refresh_attempts: 8,
            allowed: Vec::new(),
        };
        let cands = cdc.tick();
        assert_eq!(cdc.name(), "proc");
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].bind_tuple, (VM_NAT, 54322));
        assert_eq!(cands[0].host, Ipv4Addr::new(192, 168, 21, 10));
        assert_eq!(cands[0].host_port, 54322);
    }

    #[test]
    fn proc_tick_filters_held_tuples() {
        let path = temp_table("owned", &format!("{}\n", replied(GOOD)));
        let mut cdc = ProcCdc {
            path,
            brlan: BR_LAN,
            vm_nat: VM_NAT,
            owned: vec![(VM_NAT, 54322)],
            max_refresh_attempts: 8,
            allowed: Vec::new(),
        };
        assert!(cdc.tick().is_empty(), "I1: owned tuple never surfaces");
    }

    #[test]
    fn proc_tick_caps_at_budget() {
        let mut table = String::new();
        for port in [54322u16, 50011, 50023] {
            table.push_str(&replied(&GOOD.replace("54322", &port.to_string())));
            table.push('\n');
        }
        let path = temp_table("cap", &table);
        let mut cdc = ProcCdc {
            path,
            brlan: BR_LAN,
            vm_nat: VM_NAT,
            owned: Vec::new(),
            max_refresh_attempts: 2,
            allowed: Vec::new(),
        };
        assert_eq!(cdc.tick().len(), 2, "scan caps at the refresh budget");
    }

    #[test]
    fn missing_proc_file_is_empty_tick() {
        let mut cdc = ProcCdc {
            path: "/nonexistent/nf_conntrack".to_string(),
            brlan: BR_LAN,
            vm_nat: VM_NAT,
            owned: Vec::new(),
            max_refresh_attempts: 8,
            allowed: Vec::new(),
        };
        assert!(cdc.tick().is_empty(), "unreadable table -> empty tick, not panic");
    }

    // --- nft mirror backend (reconcile) ---

    fn mirror_live() -> Vec<(Ipv4Addr, u16)> {
        vec![(VM_NAT, 54322)]
    }

    fn proc_fixture() -> String {
        // the replied VM-line flow fixture from the obs tests, as a table
        let good = "ipv4     2 udp      17 56 src=192.168.21.10 dst=8.8.8.8 sport=54322 dport=53 packets=1 bytes=92 [UNREPLIED] src=8.8.8.8 dst=192.168.0.21 sport=53 dport=54322 packets=0 bytes=0 mark=0 zone=0 use=2";
        format!(
            "{}\n",
            good.replace("[UNREPLIED]", "")
                .replace("packets=0 bytes=0 mark=", "[ASSURED] packets=3 bytes=210 mark=")
        )
    }

    #[test]
    fn reconcile_resolves_then_caches() {
        let mut known = HashMap::new();
        let live = mirror_live();
        // first tick: fresh tuple, resolved via the proc snapshot
        let mut out = reconcile(&live, Some(&proc_fixture()), &mut known, &[], 8, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].bind_tuple, (VM_NAT, 54322));
        assert_eq!(out[0].host, Ipv4Addr::new(192, 168, 21, 10));
        assert_eq!(out[0].host_port, 54322);
        assert_eq!(out[0].peer, (Ipv4Addr::new(8, 8, 8, 8), 53));
        // steady state: no proc read needed, cached identity served
        out = reconcile(&live, None, &mut known, &[], 8, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].host, Ipv4Addr::new(192, 168, 21, 10));
    }

    #[test]
    fn reconcile_prunes_evicted_tuples() {
        let mut known = HashMap::new();
        let live = mirror_live();
        assert_eq!(reconcile(&live, Some(&proc_fixture()), &mut known, &[], 8, &[]).len(), 1);
        // mirror loses the flow (15 s element expiry is the silence
        // detector): nothing live -> nothing returned, cache pruned
        let out = reconcile(&[], None, &mut known, &[], 8, &[]);
        assert!(out.is_empty());
        assert!(known.is_empty());
    }

    #[test]
    fn reconcile_skips_held_and_unresolvable() {
        let mut known = HashMap::new();
        let live = mirror_live();
        // held: the I1 predicate drops it during identity resolution
        let out = reconcile(&live, Some(&proc_fixture()), &mut known, &[(VM_NAT, 54322)], 8, &[]);
        assert!(out.is_empty());
        // unresolvable: proc tuple absent from the snapshot -> no identity
        let mut known = HashMap::new();
        let out = reconcile(&live, Some("ipv4     2 tcp       6 50 src=9.9.9.9 dst=1.1.1.1 sport=1 dport=1 packets=1 bytes=1 src=1.1.1.1 dst=9.9.9.9 sport=1 dport=1 packets=0 bytes=0 mark=0 zone=0 use=2\n"), &mut known, &[], 8, &[]);
        assert!(out.is_empty());
        assert!(known.is_empty());
    }

    #[test]
    fn reconcile_budget_caps_resolution() {
        let mut known = HashMap::new();
        let live = vec![(VM_NAT, 54322), (VM_NAT, 50011)];
        // two live tuples, budget 1: only the first gets an identity
        let mut table = String::new();
        for port in [54322u16, 50011] {
            let good = proc_fixture().replace("54322", &port.to_string());
            table.push_str(&good);
            table.push('\n');
        }
        let out = reconcile(&live, Some(&table), &mut known, &[], 1, &[]);
        assert_eq!(out.len(), 1, "budget caps how many fresh tuples resolve");
    }
}