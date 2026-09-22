//! Observation refresh engine (brief v2, Phase G) — G1/G2/G9.
//!
//! G1 CDC: `/proc/net/nf_conntrack` polling. C4 measured (2026-08-31): on
//! this ImmortalWrt 6.12.35 build, netlink conntrack events DO NOT reach
//! userspace (CT_GET dump works, event multicast silent even with
//! nf_conntrack_events=1) — so the change-data-capture for observing
//! flows is a poll of the proc table: existence, [UNREPLIED]/[ASSURED],
//! and the reply-direction tuple (which reveals the post-NAT router-side
//! source the shadow socket must bind).
//!
//! G2 policy predicate (console-agnostic, Kani truth table):
//!   proto UDP
//!   && src ∈ br-lan prefix
//!   && dst off-LAN (not br-lan, not hub-LAN, not loopback/private-local)
//!   && flow is bidirectional (reply seen — a peer cares about this flow)
//!   && flow egresses the VM line (reply dst == the hub-LAN NAT address:
//!      only flows through the AFTR have a CGNAT mapping to refresh; vdsl4
//!      flows are directly routable and need nothing)
//!   && inner tuple (NAT addr, reply dport) not owned by a static/lease
//!      slot (I1 — observation never captures an owned tuple)
//!   && refreshes for this flow < --max-refresh-attempts
//! No hostname/MAC/port allowlists — review rejects any.
//!
//! G9: the predicate's truth table is Kani-proven. Parsing itself is
//! numeric (no heap in the decision path); the parse→entry→evaluate chain
//! is unit-tested against real proc lines captured on the router.
//!
//! `dead_code` allowance (p2-slot-engine, Phase G): the parse + predicate
//! layer feeds the engine via `cdc::ProcCdc` → `scan`, but the evidence
//! fields (orig_dport, unreplied, assured) are consumed only by tests and
//! the G8 wire-shaping logs, so they stay untouched in the shipped binary.
//! Do not remove this allowance without consuming those fields.
#![allow(dead_code)]
use std::net::Ipv4Addr;

/// Parsed one line of /proc/net/nf_conntrack.
/// Field layout (6.12):
///   ipv4 2 <proto> <number> <timeout_left> \
///   src=A dst=B sport=N dport=M packets=.. bytes=.. [UNREPLIED]/[ASSURED] \
///   src=C dst=D sport=N dport=M packets=.. bytes=.. mark=0 zone=0 use=K
///
/// The *reply* direction's dst/dport is the router-side post-NAT source
/// tuple for that flow (what packets coming back arrive as) — the shadow
/// socket binds exactly that (I2). Parsed after NAT via the reply side,
/// because conntrack's orig side shows the pre-NAT LAN tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtEntry {
    pub proto: u8, // 17 = UDP, 6 = TCP, 1 = ICMP
    pub timeout_left: u32,
    pub orig_src: Ipv4Addr,
    pub orig_sport: u16,
    pub orig_dst: Ipv4Addr,
    pub orig_dport: u16,
    pub orig_packets: u64,
    pub orig_bytes: u64,
    pub reply_src: Ipv4Addr,
    pub reply_sport: u16,
    pub reply_dst: Ipv4Addr,
    pub reply_dport: u16,
    pub reply_packets: u64,
    pub reply_bytes: u64,
    pub unreplied: bool,
    pub assured: bool,
}

impl CtEntry {
    pub fn is_udp(&self) -> bool {
        self.proto == 17
    }

    /// Router-side post-NAT source tuple for this flow (what the shadow
    /// socket binds): reply-direction *dst* + *dport*. The reply tuple in
    /// /proc/net/nf_conntrack is src=<peer> dst=<router NAT addr>
    /// sport=<peer port> dport=<router NAT port> — the NAT'd local side is
    /// (dst, dport).
    pub fn nat_src(&self) -> (Ipv4Addr, u16) {
        (self.reply_dst, self.reply_dport)
    }

    /// Boolean: the reply direction has carried packets (bidirectional —
    /// this is the flow a peer actually cares about).
    pub fn has_seen_reply(&self) -> bool {
        self.reply_packets > 0
    }
}

/// Immutable decision context. `'a` borrows the owned-tuple slice so the
/// runtime can hand a live slot list per scan (the engine owns the slab;
/// the Kani harnesses use `'static` const arrays).
#[derive(Clone, Copy, Debug)]
pub struct ObsCtx<'a> {
    /// The allowlist (call/0025). A named device's flow is admitted on its
    /// own outbound tuple: the mapping a console's NAT type depends on is the one
    /// its own packets create, and once it goes quiet only our writes can
    /// keep it alive, so an unanswered flow is exactly the one that needs us
    /// (call/0029). An unnamed flow keeps the reply requirement, where the
    /// heuristic is all there is to go on.
    pub allowed: &'a [Ipv4Addr],
    /// br-lan prefix (hosts eligible for refresh). Default 192.168.21.0/24.
    pub brlan: (Ipv4Addr, u8),
    /// hub-LAN NAT address — only flows egressing the VM line (AFTR) have
    /// a CGNAT mapping to refresh.
    pub vm_nat: Ipv4Addr,
    /// Inner tuples already owned by static/lease slots (I1).
    pub owned: &'a [(Ipv4Addr, u16)],
    /// per-flow refresh budget
    pub max_refresh_attempts: u32,
    /// number of refreshes so far for the candidate flow
    pub refresh_attempts_so_far: u32,
}

impl<'a> ObsCtx<'a> {
    pub fn is_brlan(&self, a: Ipv4Addr) -> bool {
        let (net, bits) = self.brlan;
        let mask: u32 = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        (u32::from(a) & mask) == (u32::from(net) & mask)
    }

    pub fn is_private_local(&self, a: Ipv4Addr) -> bool {
        let v = u32::from(a);
        // 10/8, 172.16/12, 192.168/16, 127/8, 0/8 — nothing a peer needs to
        // reach, and dst in these would be a LAN or self-address.
        (v & 0xff00_0000) == 0x0a00_0000
            || (v & 0xfff0_0000) == 0xac10_0000
            || (v & 0xffff_0000) == 0xc0a8_0000
            || (v & 0xff00_0000) == 0x7f00_0000
    }

    pub fn is_owned(&self, tuple: (Ipv4Addr, u16)) -> bool {
        self.owned.iter().any(|h| *h == tuple)
    }
}

/// G2 predicate. Pure; Kani-provable.
pub fn should_refresh(e: &CtEntry, ctx: &ObsCtx<'_>) -> bool {
    if !e.is_udp() {
        return false;
    }
    if !ctx.is_brlan(e.orig_src) {
        return false;
    }
    if ctx.is_private_local(e.orig_dst) {
        return false; // off-LAN requirement: dst must be a routable public
    }
    // Bidirectional, or named: a peer must be able to care about this flow,
    // and for a named device our own writes are what let it care at all.
    if !e.has_seen_reply() && !ctx.allowed.contains(&e.orig_src) {
        return false;
    }
    // VM line only: the reply's destination is the hub-LAN NAT address,
    // so the flow crossed the AFTR and has a CGNAT mapping to refresh.
    if e.reply_dst != ctx.vm_nat {
        return false;
    }
    // I1: never capture a tuple a static/lease slot holds.
    if ctx.is_owned(e.nat_src()) {
        return false;
    }
    if ctx.refresh_attempts_so_far >= ctx.max_refresh_attempts {
        return false;
    }
    true
}

/// A flow the observation engine has decided to refresh. The shadow socket
/// binds `nat_src` = (192.168.0.21, R_nat) and STUN-keepalives it; a pin
/// element `(orig_src, orig_sport) -> R_nat` goes in after C5 (shadow-bind
/// proven) so all future traffic from that host port shares the tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshCandidate {
    /// inner tuple the shadow socket will bind — the flow's post-NAT
    /// (source, port) as the AFTR sees it
    pub bind_tuple: (Ipv4Addr, u16),
    /// br-lan host + port the pin must anchor (orig direction, pre-NAT)
    pub host: Ipv4Addr,
    pub host_port: u16,
    /// Peer side of the observed flow (reply src) — the other half of the
    /// conntrack orig tuple the claim deletes (netlink CT_DELETE, see
    /// engine.rs: without the delete the kernel NAPT's the shadow
    /// keepalives to an ephemeral port and the refresh targets the wrong
    /// tuple; measured 41077 → 1024 on-box, 2026-09-02).
    pub peer: (Ipv4Addr, u16),
}

/// Scan `/proc/net/nf_conntrack` and collect eligible refresh candidates.
/// Returns candidates in stable (line) order. Never allocates per line
/// beyond the return list.
pub fn scan(f: &str, ctx: &ObsCtx<'_>) -> Vec<RefreshCandidate> {
    let mut out = Vec::new();
    let mut refreshes = 0u32;
    for line in f.lines() {
        let Some(e) = parse_line(line) else {
            continue;
        };
        let mut c = *ctx;
        c.refresh_attempts_so_far = refreshes;
        if should_refresh(&e, &c) {
            out.push(RefreshCandidate {
                bind_tuple: e.nat_src(),
                host: e.orig_src,
                host_port: e.orig_sport,
                peer: (e.reply_src, e.reply_sport),
            });
            refreshes += 1;
            if refreshes >= ctx.max_refresh_attempts {
                break;
            }
        }
    }
    out
}

/// Find `key=` in a whitespace-tokenized conntrack line section and return
/// the value. No allocation.
fn kv_at<'a>(fields: &'a [&str], key: &str) -> Option<&'a str> {
    fields.iter().find_map(|f| {
        let (k, v) = f.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// Parse one /proc/net/nf_conntrack line. Returns None on any malformed
/// field (never panics). Only the fields the engine needs are extracted.
pub fn parse_line(line: &str) -> Option<CtEntry> {
    let t: Vec<&str> = line.split_whitespace().collect();
    if t.len() < 16 {
        return None;
    }
    // t[0]=family t[1]=2 t[2]=proto-name t[3]=proto-number t[4]=timeout
    let proto: u8 = t.get(3)?.parse().ok()?;
    let timeout_left: u32 = t.get(4)?.parse().ok()?;

    let orig = &t[5..];
    let orig_src: Ipv4Addr = kv_at(orig, "src")?.parse().ok()?;
    let orig_dst: Ipv4Addr = kv_at(orig, "dst")?.parse().ok()?;
    let orig_sport: u16 = kv_at(orig, "sport")?.parse().ok()?;
    let orig_packets: u64 = kv_at(orig, "packets")?.parse().ok()?;
    let orig_bytes: u64 = kv_at(orig, "bytes")?.parse().ok()?;

    // Reply side: after the orig window (which ends at the [flags] token,
    // position of the second "src=" token in the whole line).
    let reply_off = (t.iter().enumerate().filter(|(_, f)| f.starts_with("src=")).nth(1))
        .map(|(i, _)| i)
        .unwrap_or(t.len());
    let reply = &t[reply_off..];
    let reply_src: Ipv4Addr = kv_at(reply, "src")?.parse().ok()?;
    let reply_sport: u16 = kv_at(reply, "sport")?.parse().ok()?; // peer side port
    let reply_dst: Ipv4Addr = kv_at(reply, "dst")?.parse().ok()?;
    let reply_dport: u16 = kv_at(reply, "dport")?.parse().ok()?; // NAT side port
    let reply_packets: u64 = kv_at(reply, "packets")?.parse().ok()?;
    let reply_bytes: u64 = kv_at(reply, "bytes")?.parse().ok()?;

    let unreplied = line.contains("[UNREPLIED]");
    let assured = line.contains("[ASSURED]");

    Some(CtEntry {
        proto,
        timeout_left,
        orig_src,
        orig_sport,
        orig_dst,
        orig_dport: 0,
        orig_packets,
        orig_bytes,
        reply_src,
        reply_sport,
        reply_dst,
        reply_dport,
        reply_packets,
        reply_bytes,
        unreplied,
        assured,
    })
}

pub fn brlan_ctx() -> ObsCtx<'static> {
    ObsCtx {
        brlan: (Ipv4Addr::new(192, 168, 21, 0), 24),
        vm_nat: Ipv4Addr::new(192, 168, 0, 21),
        owned: &[],
        max_refresh_attempts: 8,
        allowed: &[],
        refresh_attempts_so_far: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real line captured on the router (2026-08-31): a br-lan container
    // UDP flow egressing the VM line via the relay pin.
    const GOOD: &str = "ipv4     2 udp      17 56 src=192.168.21.10 dst=8.8.8.8 sport=54322 dport=53 packets=1 bytes=92 [UNREPLIED] src=8.8.8.8 dst=192.168.0.21 sport=53 dport=54322 packets=0 bytes=0 mark=0 zone=0 use=2";

    #[test]
    fn parses_good_line() {
        let e = parse_line(GOOD).expect("parse");
        assert_eq!(e.proto, 17);
        assert_eq!(e.orig_src, Ipv4Addr::new(192, 168, 21, 10));
        assert_eq!(e.orig_dst, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(e.reply_src, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(e.reply_sport, 53); // peer side port
        assert_eq!(e.reply_dst, Ipv4Addr::new(192, 168, 0, 21));
        assert_eq!(e.reply_dport, 54322); // post-NAT port the shadow binds
        assert!(e.unreplied);
        assert!(!e.assured);
        assert!(!e.has_seen_reply());
    }

    #[test]
    fn an_unreplied_flow_from_a_named_device_is_refreshed() {
        // call/0029: the mapping a console's NAT type depends on is the one its
        // own packets create, and its flows to game peers are frequently
        // unanswered. A named device is admitted on that tuple; an unnamed
        // one is not.
        let l = GOOD;
        let e = parse_line(l).expect("fixture parses");
        assert!(e.unreplied, "the fixture is the unanswered case");
        let host = e.orig_src;
        let named = [host];
        let ctx = ObsCtx {
            allowed: &named,
            ..brlan_ctx()
        };
        assert!(should_refresh(&e, &ctx), "a named device is admitted unanswered");
        assert!(
            !should_refresh(&e, &brlan_ctx()),
            "without the list the reply requirement stands"
        );
    }

    #[test]
    fn an_unreplied_flow_from_an_unnamed_device_is_not_refreshed() {
        let e = parse_line(GOOD).unwrap();
        // no reply seen → predicate false (wait for a reply; mapping matters
        // to a peer)
        assert!(!should_refresh(&e, &brlan_ctx()));
    }

    fn replied_line() -> String {
        // same flow, now bidirectional ([ASSURED], reply packets > 0)
        GOOD.replace("[UNREPLIED]", "").replace(
            "packets=0 bytes=0 mark=",
            "[ASSURED] packets=3 bytes=210 mark=",
        )
    }

    #[test]
    fn replied_vm_line_flow_is_refreshed() {
        let line = replied_line();
        let e = parse_line(&line).unwrap();
        assert!(e.has_seen_reply());
        assert!(e.assured);
        assert!(should_refresh(&e, &brlan_ctx()));
    }

    #[test]
    fn vdsl4_flow_not_refreshed() {
        // reply dst = the vdsl4 public IP (not the VM NAT): no AFTR mapping
        let line = GOOD
            .replace("dst=192.168.0.21", "dst=84.203.115.61")
            .replace("[UNREPLIED]", "")
            .replace("packets=0 bytes=0 mark=", "[ASSURED] packets=3 bytes=210 mark=");
        let e = parse_line(&line).unwrap();
        assert!(!should_refresh(&e, &brlan_ctx()));
    }

    #[test]
    fn tcp_flow_not_refreshed() {
        // TCP is out of scope until C3 measured.
        let line = GOOD
            .replace("udp      17", "tcp       6")
            .replace("packets=0 bytes=0 mark=", "[ASSURED] packets=3 bytes=210 mark=");
        let e = parse_line(&line).unwrap();
        assert!(!e.is_udp());
        assert!(!should_refresh(&e, &brlan_ctx()));
    }

    #[test]
    fn dest_off_lan_required() {
        // dst in a private block → not a peer-reachable flow
        let line = GOOD
            .replace("dst=8.8.8.8", "dst=10.1.2.3")
            .replace("[UNREPLIED]", "")
            .replace("packets=0 bytes=0 mark=", "[ASSURED] packets=3 bytes=210 mark=");
        let e = parse_line(&line).unwrap();
        assert!(!should_refresh(&e, &brlan_ctx()));
    }

    #[test]
    fn owned_tuple_never_refreshed() {
        // I1: a lease/static slot already holds (192.168.0.21, 54322)
        let line = replied_line();
        let e = parse_line(&line).unwrap();
        let mut ctx = brlan_ctx();
        const OWNED: [(Ipv4Addr, u16); 1] = [(Ipv4Addr::new(192, 168, 0, 21), 54322)];
        ctx.owned = &OWNED;
        assert!(!should_refresh(&e, &ctx));
    }

    #[test]
    fn refresh_budget_respected() {
        let line = replied_line();
        let e = parse_line(&line).unwrap();
        let mut ctx = brlan_ctx();
        ctx.max_refresh_attempts = 8;
        ctx.refresh_attempts_so_far = 8;
        assert!(!should_refresh(&e, &ctx));
        ctx.refresh_attempts_so_far = 7;
        assert!(should_refresh(&e, &ctx));
    }

    #[test]
    fn malformed_line_never_panics() {
        for bad in ["", "short", "ipv4 2 udp 17", "src=x dst=y"] {
            assert!(parse_line(bad).is_none());
        }
    }

    #[test]
    fn scan_collects_only_eligible() {
        // 3 lines: eligible VM-line UDP (ASSURED), vdsl4 UDP (skip), TCP (skip)
        let good = replied_line();
        let vdsl4 = GOOD
            .replace("dst=192.168.0.21", "dst=84.203.115.61")
            .replace("[UNREPLIED]", "")
            .replace("packets=0 bytes=0 mark=", "[ASSURED] packets=3 bytes=210 mark=");
        let tcp = GOOD
            .replace("udp      17", "tcp       6")
            .replace("packets=0 bytes=0 mark=", "[ASSURED] packets=3 bytes=210 mark=");
        let table = format!("{}\n{}\n{}", good, vdsl4, tcp);
        let ctx = brlan_ctx();
        let found = scan(&table, &ctx);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host, Ipv4Addr::new(192, 168, 21, 10));
        assert_eq!(found[0].host_port, 54322);
        assert_eq!(found[0].bind_tuple, (Ipv4Addr::new(192, 168, 0, 21), 54322));
    }

    #[test]
    fn scan_respects_global_budget() {
        // two eligible lines but max_refresh_attempts=1 -> only the first is taken
        let good = replied_line();
        let mut ctx = brlan_ctx();
        ctx.max_refresh_attempts = 1;
        let found = scan(&format!("{}\n{}", good, good), &ctx);
        assert_eq!(found.len(), 1);
    }
}

#[cfg(kani)]
mod verify {
    use super::*;

    fn any_entry() -> CtEntry {
        // build an entry with symbolic UDP fields; a few fields pinned so
        // the tree stays small
        CtEntry {
            proto: 17,
            timeout_left: kani::any(),
            orig_src: Ipv4Addr::from(kani::any::<[u8; 4]>()),
            orig_sport: 0,
            orig_dst: Ipv4Addr::from(kani::any::<[u8; 4]>()),
            orig_dport: 0,
            orig_packets: kani::any(),
            orig_bytes: kani::any(),
            reply_src: Ipv4Addr::from(kani::any::<[u8; 4]>()),
            reply_sport: kani::any(),
            reply_dst: Ipv4Addr::from(kani::any::<[u8; 4]>()),
            reply_dport: kani::any(),
            reply_packets: kani::any(),
            reply_bytes: kani::any(),
            unreplied: false,
            assured: true,
        }
    }

    const BR: (Ipv4Addr, u8) = (Ipv4Addr::new(192, 168, 21, 0), 24);
    const NAT: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 21);
    const OWNED: [(Ipv4Addr, u16); 0] = [];

    #[kani::proof]
    fn predicate_requires_udp() {
        let mut e = any_entry();
        let ctx = ObsCtx {
            brlan: BR,
            vm_nat: NAT,
            owned: &OWNED,
            max_refresh_attempts: 8,
            refresh_attempts_so_far: 0,
        };
        // force UDP-ness off symbolically
        e.proto = kani::any();
        if e.proto != 17 {
            assert!(!should_refresh(&e, &ctx), "non-UDP must never refresh");
        }
    }

    #[kani::proof]
    fn predicate_requires_brlan_source() {
        let e = any_entry();
        let ctx = ObsCtx {
            brlan: BR,
            vm_nat: NAT,
            owned: &OWNED,
            max_refresh_attempts: 8,
            refresh_attempts_so_far: 0,
        };
        if should_refresh(&e, &ctx) {
            assert!(ctx.is_brlan(e.orig_src), "refresh implies br-lan src");
        }
    }

    #[kani::proof]
    fn predicate_requires_reply_and_vm_line() {
        let e = any_entry();
        let ctx = ObsCtx {
            brlan: BR,
            vm_nat: NAT,
            owned: &OWNED,
            max_refresh_attempts: 8,
            refresh_attempts_so_far: 0,
        };
        if should_refresh(&e, &ctx) {
            assert!(e.has_seen_reply(), "refresh implies bidirectional");
            assert_eq!(e.reply_dst, NAT, "refresh implies VM-line egress");
        }
    }

    #[kani::proof]
    fn predicate_respects_budget_exact() {
        let e = any_entry();
        let mut ctx = ObsCtx {
            brlan: BR,
            vm_nat: NAT,
            owned: &OWNED,
            max_refresh_attempts: 8,
            refresh_attempts_so_far: 0,
        };
        ctx.refresh_attempts_so_far = 8;
        assert!(!should_refresh(&e, &ctx), "budget exhausted -> never refresh");
    }

    #[kani::proof]
    fn held_never_refreshed() {
        let e = any_entry();
        const OWNED1: [(Ipv4Addr, u16); 1] = [(NAT, 54322)];
        let ctx = ObsCtx {
            brlan: BR,
            vm_nat: NAT,
            held: &OWNED1,
            max_refresh_attempts: 8,
            refresh_attempts_so_far: 0,
        };
        let tuple = e.nat_src();
        if tuple == (NAT, 54322) {
            assert!(!should_refresh(&e, &ctx), "I1: owned tuple never refreshed");
        }
    }
}