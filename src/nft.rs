//! nft datapath for ds-lite-punch — fixed rule set installed ONCE, dynamic
//! state only in named-map *elements* (brief B4). Slot create/delete =
//! element add/delete, atomic, no rule re-parsing mid-flight.
//!
//! Structure:
//!   table ip dslp {
//!     map snat_map { type ipv4_addr . inet_service : ipv4_addr . inet_service; }
//!                       // key (client ip, client port) -> value (NAT addr, R)
//!     chain postrouting { type nat hook postrouting priority -150; }  // BEFORE fw4 srcnat (-100)
//!   }
//!   rule: oifname "eth1" meta l4proto udp snat to ip saddr . udp sport map @snat_map
//!
//! priority -150 matters (brief delta: P1's SNAT is the proven mechanism;
//! running before fw4's masquerade means the map matches the *pre-NAT*
//! (client_ip, client_port) and fixes the translation to (192.168.0.21, R)
//! for that connection; everything else falls through to fw4 untouched).
//! The nat-hook floor is -200 EXCLUSIVE — `-200` itself is rejected by nft
//! (validated on-box, nftables 1.1.1), so -150 is used (must also stay below
//! fw4's srcnat at -100).
//!
//! `meta l4proto udp` (not bare `udp`) is used deliberately: bare `udp`
//! followed by the map-snat statement parses ambiguously on nftables 1.1.1.
//!
//! All ops go through the `nft` CLI (`Command`), like P1's `ip route
//! replace` for STUN host routes. Not Kani-modelable (external process);
//! covered on-box by A1/B10.3. Failure mode: any error is returned, never
//! panics, and calls happen only from the admission path (facade grant /
//! revoke / GC) — a failed element add refuses the grant upstream.
//!
//! Teardown functions (`del_pin`, `remove_ruleset`) are the B8/B9 revoke and
//! stop paths — referenced from the binder below so the crate stays
//! warning-free at every phase gate, and re-exported for the deploy script.
#![allow(dead_code)] // del_pin / remove_ruleset consumed by B8/B9 revoke paths
use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use crate::publish::emiteln;

/// The NAT address every pinned console flow egresses as: the hub-LAN
/// address the relay sockets bind. Matches the `--bind` default in main.rs.
pub const NAT_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 21);

fn run(args: &[&str]) -> io::Result<()> {
    let status = Command::new("nft").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("nft {} -> {}", args.join(" "), status),
        ))
    }
}

/// Run a multi-statement nft script (`nft -f -`) as ONE atomic batch: a
/// single subprocess per transaction instead of one per statement. A
/// failing statement aborts the whole batch, so the datapath state is
/// all-or-nothing (the facade grant/revoke use this; the fixed-startup
/// ruleset stays per-statement for its fine-grained idempotency).
pub fn run_script(script: &str) -> io::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "nft -f - stdin unavailable"))?
        .write_all(script.as_bytes())?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("nft batch -> {}", status),
        ))
    }
}

/// Install the conntrack timeout policy for the allowlist (call/0025,
/// plan/0009 #allowlist). The chain and both objects are removed first and
/// re-added, so the address list in force is exactly the allowlist's: a
/// startup that changes the list changes the rules, and a failure leaves no
/// policy at all, which is the safe direction (every flow keeps the router's
/// own timeouts and the WAN half of the keepalive is the daemon's own writes).
pub fn apply_hold(list: &[Ipv4Addr]) -> io::Result<()> {
    remove_hold();
    if list.is_empty() {
        return Ok(());
    }
    run_script(&crate::keepalive::ruleset(list))
}

/// Remove the policy: the selection chain first, then the two objects.
/// Best-effort by design — the daemon's table dies with the process (the
/// stop path deletes `table ip dslp` wholesale), so a failure here leaves
/// nothing that outlives the daemon.
pub fn remove_hold() {
    let _ = run_script(&crate::keepalive::teardown());
}

/// Whether the policy is in the live table, for the startup log: the parse
/// after the apply is the evidence that the policy is in force, not the exit
/// status of the batch that installed it.
pub fn hold_in_force() -> bool {
    let Ok(out) = Command::new("nft")
        .args(["list", "table", "ip", "dslp"])
        .output()
    else {
        return false;
    };
    crate::keepalive::present(&String::from_utf8_lossy(&out.stdout))
}

/// The daemon's accept sets, inside fw4's table: a slot's inbound accept is an
/// *element* of the set its protocol uses, and the two rules that accept the
/// sets are installed once.
///
/// This is a fix, not a style. `delete rule` by expression is refused by this
/// nft ("syntax error, unexpected iifname, expecting handle"), so a per-port
/// rule could only be removed by a handle read out of
/// `nft -a list chain inet fw4 input` — the listing the libnftables segfaults
/// come from — and a delete that failed left the rule installed: two accept
/// rules from earlier daemons were still on the test router, one of them for a
/// protocol this build does not enable. An element is addressed by key, so
/// nothing in the datapath needs a handle, and both sets are emptied when the
/// daemon installs them, so no port outlives the process that wanted it.
pub const ACCEPT_SET_UDP: &str = "dslp_ports_udp";
pub const ACCEPT_SET_TCP: &str = "dslp_ports_tcp";

fn accept_set(tcp: bool) -> &'static str {
    if tcp {
        ACCEPT_SET_TCP
    } else {
        ACCEPT_SET_UDP
    }
}

/// One element operation on the set, as argv: the verb and the key.
fn accept_element(verb: &str, r: u16, tcp: bool) -> Vec<String> {
    vec![
        verb.into(),
        "element".into(),
        "inet".into(),
        "fw4".into(),
        accept_set(tcp).into(),
        format!("{{ {} }}", r),
    ]
}

/// The two rules that accept the sets, one per protocol. One definition, so
/// the rules the daemon installs are the rules it checks for. They carry no
/// comment, which is also what keeps the legacy sweep below off them.
fn accept_rule_text() -> [String; 2] {
    [
        format!("iifname \"eth1\" udp dport @{} accept", ACCEPT_SET_UDP),
        format!("iifname \"eth1\" tcp dport @{} accept", ACCEPT_SET_TCP),
    ]
}

/// Handles of the per-port accept rules an older daemon installed: the lines
/// whose comment names this daemon. The sets' own rules carry no such
/// comment, so the sweep can never take them.
fn legacy_rule_handles(listing: &str) -> Vec<u64> {
    listing
        .lines()
        .filter(|l| l.contains("dslitepunch"))
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|t| t.parse::<u64>().ok())
        .collect()
}

/// The set of slot ports that have an inbound translation, one per protocol,
/// and the map that carries each port to the client tuple that owns it.
pub const INBOUND_SET_UDP: &str = "dslp_in_udp";
pub const INBOUND_SET_TCP: &str = "dslp_in_tcp";
pub const INBOUND_MAP_UDP: &str = "dslp_dnat_udp";
pub const INBOUND_MAP_TCP: &str = "dslp_dnat_tcp";

fn inbound_set(tcp: bool) -> &'static str {
    if tcp {
        INBOUND_SET_TCP
    } else {
        INBOUND_SET_UDP
    }
}

fn inbound_map(tcp: bool) -> &'static str {
    if tcp {
        INBOUND_MAP_TCP
    } else {
        INBOUND_MAP_UDP
    }
}

/// The prerouting rule that sends an arrival at a slot port to the client that
/// owns it. `dnat`, and never `snat`, which is the whole point: the client's
/// own egress keeps its own port (call/0014 measured what the other choice
/// costs a console), and the arrival is translated at ingress instead.
pub fn inbound_rule_text(tcp: bool) -> String {
    let proto = if tcp { "tcp" } else { "udp" };
    format!(
        "iifname \"eth1\" {} dport @{} dnat ip to {} dport map @{}",
        proto,
        inbound_set(tcp),
        proto,
        inbound_map(tcp)
    )
}

/// The argv that installs the prerouting chain. Its own function because the
/// first deployment of this design left it out, and the failure was total:
/// the rule could not be added to a chain that did not exist, the install
/// returned an error, and the daemon refused to run rather than run blind.
fn inbound_chain_argv() -> Vec<String> {
    vec![
        "add".into(),
        "chain".into(),
        "ip".into(),
        "dslp".into(),
        "prerouting".into(),
        "{ type nat hook prerouting priority -150 ; policy accept ; }".into(),
    ]
}

/// Install the inbound sets, maps, chain and rules. Idempotent, and the sets
/// are emptied like the accept sets: a restart re-grants every lease it
/// restored, and a port no lease owns must not survive the process that
/// wanted it.
pub fn ensure_inbound() -> io::Result<()> {
    let argv = inbound_chain_argv();
    let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let _ = run(&refs); // EEXIST when the chain is already there
    let mut listing = String::new();
    if let Ok(o) = Command::new("nft")
        .args(["list", "chain", "ip", "dslp", "prerouting"])
        .output()
    {
        listing = String::from_utf8_lossy(&o.stdout).into_owned();
    }
    for tcp in [false, true] {
        let _ = run(&[
            "add",
            "set",
            "ip",
            "dslp",
            inbound_set(tcp),
            "{ type inet_service ; size 65535 ; }",
        ]);
        let _ = run(&[
            "add",
            "map",
            "ip",
            "dslp",
            inbound_map(tcp),
            "{ type inet_service : ipv4_addr . inet_service ; size 65535 ; }",
        ]);
        let text = inbound_rule_text(tcp);
        if !listing.contains(&text) {
            run(&["add", "rule", "ip", "dslp", "prerouting", &text])?;
        }
        let _ = run(&["flush", "set", "ip", "dslp", inbound_set(tcp)]);
    }
    Ok(())
}

/// The ports a set currently holds. Pure, so the read-back after a revoke is
/// testable away from the box.
pub fn parse_port_set(text: &str) -> Vec<u16> {
    let Some(pos) = text.find("elements = {") else {
        return Vec::new();
    };
    let rest = &text[pos + "elements = {".len()..];
    rest.split(&[',', '}'][..])
        .filter_map(|t| t.split_whitespace().next())
        .filter_map(|t| t.parse::<u16>().ok())
        .collect()
}

/// Whether a port still has an inbound translation. The revoke's own
/// read-back: a leftover would deliver another client's traffic.
pub fn inbound_set_has(bind_port: u16, tcp: bool) -> bool {
    let Ok(out) = Command::new("nft")
        .args(["list", "set", "ip", "dslp", inbound_set(tcp)])
        .output()
    else {
        return false;
    };
    parse_port_set(&String::from_utf8_lossy(&out.stdout)).contains(&bind_port)
}

/// Grant a slot's datapath: the port is accepted on eth1 and translated at
/// ingress to the client that asked for it.
///
/// The client's own tuple is deliberately not pinned into `snat_map`. That
/// pin made the client's traffic egress through the slot's port, so one game
/// held two external tuples at once: some flows on its own preserved port and
/// some on the relay's, which is what a console scores as Strict or Moderate.
/// Measured live on the router, with a console in game: 14,740 packets of one
/// flow egressing on the slot's port while its siblings kept their own.
/// call/0014 settled this: the console's value story is organic, "works
/// alongside, not enabled by" the relay.
///
/// The pin was also the only thing that mapped an arrival at the slot port
/// back to the client, through that flow's conntrack entry, so removing it
/// silently broke inbound delivery for every lease whose client had no pinned
/// flow. Measured on 2026-09-20: a lease's arrival reached eth1 and never
/// reached the client's socket. The ingress translation is what replaces it:
/// egress untouched, ingress mapped.
pub fn grant_datapath(client: Ipv4Addr, int_port: u16, bind_port: u16, tcp: bool) -> io::Result<()> {
    let script = format!(
        "add element ip dslp {} {{ {} }}\n\
         add element ip dslp {} {{ {} : {} . {} }}\n",
        inbound_set(tcp),
        bind_port,
        inbound_map(tcp),
        bind_port,
        client,
        int_port
    );
    run_script(&script)?;
    add_input_accept(bind_port, tcp)
}

/// The statements that revoke a slot's datapath. Each stands alone: the
/// elements are deleted one by one, because a batch is all-or-nothing and the
/// element that is already absent used to cancel the rest of the revoke.
///
/// There is no `snat_map` statement here, and that is deliberate: the grant
/// installs an ingress translation and no pin, so a pin delete can only ever
/// fail. It used to log an error on every revoke while the design never
/// created what it deleted (measured on the router on 2026-09-20: 54 error
/// lines in one session). The paths that do pin, the arm's self-pin and the
/// statics, remove their own with `del_pin`.
pub fn revoke_statements(bind_port: u16, tcp: bool) -> Vec<String> {
    vec![
        format!("delete element ip dslp {} {{ {} }}", inbound_set(tcp), bind_port),
        format!("delete element ip dslp {} {{ {} }}", inbound_map(tcp), bind_port),
        format!("delete element inet fw4 {} {{ {} }}", accept_set(tcp), bind_port),
    ]
}

/// Revoke a slot's datapath. Every statement runs on its own and a missing
/// element is not a failure.
///
/// The revoke is read back rather than trusted, because a translation left
/// behind is not litter: the port can be reallocated to another client, and a
/// stale translation would deliver that client's traffic to the wrong host.
///
/// It removes no pin. The facade installs none, so a pin delete could only
/// fail and print nft's own error into the log; the paths that do pin — the
/// arm's self-pin and the TCP connection — remove their own with `del_pin`. This
/// was the last of the log's error lines, measured on the router on
/// 2026-09-20: three of them at 21:58, one per expired lease.
pub fn revoke_datapath(client: Ipv4Addr, int_port: u16, bind_port: u16, tcp: bool) -> io::Result<()> {
    let _ = (client, int_port);
    for stmt in revoke_statements(bind_port, tcp) {
        let _ = run_script(&format!("{}\n", stmt));
    }
    if inbound_set_has(bind_port, tcp) {
        emiteln!(
            "warn: revoke left the inbound translation for {} in {}",
            bind_port,
            inbound_set(tcp)
        );
    }
    Ok(())
}

/// Install the fixed ruleset. Idempotent: table creation is a no-op when
/// present (`nft` errors are tolerated for the create steps).
pub fn ensure_ruleset() -> io::Result<()> {
    let _ = run(&["add", "table", "ip", "dslp"]);
    // map + chain are re-created only on first install; ignore EEXIST
    let _ = run(&[
        "add", "map", "ip", "dslp", "snat_map",
        "{ type ipv4_addr . inet_service : ipv4_addr . inet_service ; }",
    ]);
    let _ = run(&[
        "add", "chain", "ip", "dslp", "postrouting",
        "{ type nat hook postrouting priority -150 ; policy accept ; }",
    ]);
    // one fixed rule per protocol, guarded so re-installs don't duplicate
    if !has_rule(false)? {
        run(&[
            "add", "rule", "ip", "dslp", "postrouting",
            "oifname", "\"eth1\"", "meta", "l4proto", "udp",
            "snat", "to", "ip", "saddr", ".", "udp", "sport", "map", "@snat_map",
        ])?;
    }
    if !has_rule(true)? {
        run(&[
            "add", "rule", "ip", "dslp", "postrouting",
            "oifname", "\"eth1\"", "meta", "l4proto", "tcp",
            "snat", "to", "ip", "saddr", ".", "tcp", "sport", "map", "@snat_map",
        ])?;
    }
    ensure_accept_sets()?;
    ensure_inbound()?;
    Ok(())
}

/// Install the accept sets and their two rules, empty both sets, and take away
/// any per-port rule an older daemon left behind. Idempotent. The listing is
/// read once, for the two questions it can answer — is the accept rule already
/// there, and is there legacy litter — and never for the datapath, which is
/// what keeps a handle out of every per-slot operation.
pub fn ensure_accept_sets() -> io::Result<()> {
    let listing = Command::new("nft")
        .args(["list", "chain", "inet", "fw4", "input"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    for text in accept_rule_text() {
        let tcp = text.contains(ACCEPT_SET_TCP);
        let _ = run(&[
            "add",
            "set",
            "inet",
            "fw4",
            accept_set(tcp),
            "{ type inet_service ; size 65535 ; }",
        ]);
        // With no listing there is no way to know whether the rule is already
        // installed, and a duplicate accept changes nothing about which
        // packets pass: leave it alone rather than add a second rule.
        let present = listing
            .as_deref()
            .map(|l| l.contains(&text))
            .unwrap_or(true);
        if !present {
            run(&["add", "rule", "inet", "fw4", "input", &text])?;
        }
        // a restart must not inherit the last run's accepted ports
        let _ = run(&["flush", "set", "inet", "fw4", accept_set(tcp)]);
    }
    if let Some(l) = listing.as_deref() {
        for h in legacy_rule_handles(l) {
            let _ = run(&[
                "delete",
                "rule",
                "inet",
                "fw4",
                "input",
                "handle",
                &h.to_string(),
            ]);
        }
    }
    Ok(())
}

fn has_rule(tcp: bool) -> io::Result<bool> {
    let out = Command::new("nft")
        .args(["list", "chain", "ip", "dslp", "postrouting"])
        .output()?;
    let needle = if tcp {
        "tcp sport map @snat_map"
    } else {
        "udp sport map @snat_map"
    };
    Ok(String::from_utf8_lossy(&out.stdout).contains(needle))
}

// ---------------------------------------------------------------------------
// G1 CDC mirror (`flow_obs`) — the observation engine's primary backend.
//
// A filter-hook postrouting chain at priority 110 (AFTER fw4 srcnat @ 100 —
// the default `srcnat` priority, NOT -100 as an earlier brief draft assumed)
// records every UDP flow egressing eth1 into a 15 s-expiry set. Gating test
// PASSED (2026-09-02, on-box): the observer sees the post-NAT source — fw4's
// eth1 NAT is a fixed `snat ip to 192.168.0.21` (port-preserving), so the
// elements are the shadow-bind tuples `(192.168.0.21, R_nat)` directly and
// no CT_GET assist is needed. The 15 s element timeout is the kernel-side
// silence detector (G1 design: the CDC's timeout, not a userspace budget).
//
// Installed only when `--observation` is on (separate from `ensure_ruleset`
// so the production daemon's ruleset stays byte-identical to today).

/// The observer chain runs after fw4's srcnat (100) — strictly greater.
pub const FLOW_OBS_PRIORITY: i32 = 110;

pub fn ensure_flow_obs() -> io::Result<()> {
    // set create is a no-op when present
    let _ = run(&[
        "add", "set", "ip", "dslp", "flow_obs",
        "{ type ipv4_addr . inet_service ; flags timeout ; timeout 15s ; }",
    ]);
    if !has_flow_obs_chain()? {
        run(&[
            "add", "chain", "ip", "dslp", "cdc",
            &format!("{{ type filter hook postrouting priority {} ; policy accept ; }}", FLOW_OBS_PRIORITY),
        ])?;
    }
    if !has_flow_obs_rule()? {
        // `update`, not `add`: a keepalive re-matching an EXISTING element
        // must refresh its 15 s timeout. `add` is insert-only — the element
        // dies on schedule regardless of traffic (measured on-box
        // 2026-09-02: keepalives flowed at 2 s while the element still
        // expired and the engine Stale-exited).
        run(&[
            "add", "rule", "ip", "dslp", "cdc",
            "oifname", "\"eth1\"", "meta", "l4proto", "udp",
            "update", "@flow_obs", "{ ip saddr . udp sport }",
        ])?;
    }
    Ok(())
}

fn has_flow_obs_chain() -> io::Result<bool> {
    let out = Command::new("nft").args(["list", "chain", "ip", "dslp", "cdc"]).output()?;
    Ok(!out.stdout.is_empty())
}

fn has_flow_obs_rule() -> io::Result<bool> {
    let out = Command::new("nft").args(["list", "chain", "ip", "dslp", "cdc"]).output()?;
    // content-aware: an old `add @flow_obs` rule must not block the
    // `update @flow_obs` replacement.
    Ok(String::from_utf8_lossy(&out.stdout).contains("update @flow_obs"))
}

/// Live mirror elements: the current post-NAT `(ip, port)` tuples of eth1
/// UDP flows. Empty result on any nft failure (caller logs).
pub fn list_flow_obs() -> io::Result<Vec<(Ipv4Addr, u16)>> {
    let out = Command::new("nft").args(["list", "set", "ip", "dslp", "flow_obs"]).output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("nft list set flow_obs -> {}", out.status),
        ));
    }
    Ok(parse_flow_obs(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `nft list set` output into element tuples. Pure; unit-tested
/// against real shapes (with/without `expires`, no elements). Hand-rolled,
/// tiny — Kani non-goal, like the rest of the CLI boundary.
pub fn parse_flow_obs(text: &str) -> Vec<(Ipv4Addr, u16)> {
    let mut out = Vec::new();
    let Some(pos) = text.find("elements = {") else {
        return out;
    };
    let rest = &text[pos + "elements = {".len()..];
    for tok in rest.split(',') {
        let t: Vec<&str> = tok.split_whitespace().collect();
        if t.len() < 3 {
            continue;
        }
        if let (Ok(ip), Ok(port)) = (t[0].parse::<Ipv4Addr>(), t[2].parse::<u16>()) {
            out.push((ip, port));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The carrier-probe counter (call/0033) — the watcher's observation point.
// ---------------------------------------------------------------------------

/// The named counter the watcher reads. One definition, so the rule the
/// daemon installs and the counter it reads cannot drift apart.
pub const CARRIER_COUNTER: &str = "carrier_probe";

/// The rule that counts a marked probe, for one chain. The chain decides how
/// much the rule can say about the port.
///
/// In the input chain the arrival is still addressed to the slot's bind port, so
/// the rule matches that port through the accept set, which sits beside it in
/// this table because a set reference is table-scoped.
///
/// In the forward chain the destination port is the client's already, because
/// the ingress translation has rewritten it. Measured on the router on
/// 2026-09-21: with a port match there the counter stayed at zero while the
/// marked datagram arrived, and the translation had moved the packet to the
/// client's port before the hook. The mark alone is the probe's identity, so the
/// forward rule asks for eth1 and the mark.
///
/// The protocol is named `meta l4proto udp` there, and that spelling is load
/// bearing: a bare `udp` before a payload expression makes nft expect a UDP
/// header field and refuse the rule outright — "syntax error, unexpected @,
/// expecting length or checksum or sport or dport" — so the rule was never
/// installed and the watch counted nothing through two releases.
///
/// The counter's name is written in quotes, and that is the second load-bearing
/// spelling here. nft lists the rule it stored as
/// `counter name "carrier_probe"`, quotes included, so a rule the daemon spells
/// without them is never found in the listing: the install reads the chain,
/// concludes its rule is missing, and inserts another copy. Measured on the
/// router on 2026-09-23, while the convergence below ran: one duplicate every
/// five seconds, thirty-nine copies after a few minutes. The text this build
/// installs is therefore the text the listing carries, which is the whole point
/// of comparing them.
///
/// Neither rule terminates, and that is deliberate: the probe is a datagram like
/// any other, so the accept and forward rules still decide its fate, and a
/// marked packet gains nothing from being recognised. The payload match is the
/// mark's eight bytes at the start of the transport payload, which for UDP
/// begins at bit 64 of the transport header.
pub fn carrier_probe_rule_text(chain: &str) -> String {
    let mark = format!("@th,64,64 0x{:016x}", crate::carrier::MARK_WORD);
    match chain {
        "forward" => format!(
            "iifname \"eth1\" meta l4proto udp {} counter name \"{}\"",
            mark, CARRIER_COUNTER
        ),
        _ => format!(
            "iifname \"eth1\" udp dport @{} {} counter name \"{}\"",
            ACCEPT_SET_UDP, mark, CARRIER_COUNTER
        ),
    }
}

/// The handles of this chain's rules that name the counter and are not the rule
/// this build means to have exactly once.
///
/// Two kinds are returned, and both are how a watch stops being honest. An older
/// build's rule survives an install that only adds, and a rule that is merely
/// different counts nothing: measured on the router on 2026-09-21, a stale
/// forward rule and two stale input variants survived two releases and the
/// counter stayed at zero while the probes arrived. And a duplicate of the rule
/// itself is what a repair that never verified its own write leaves behind: the
/// convergence of 2026-09-23 inserted one copy per poll because the text it
/// looked for was not the text nft stores, thirty-nine of them in a few minutes.
/// The first rule that is this build's is kept, and every later copy goes.
pub fn carrier_probe_stale_handles(listing: &str, text: &str) -> Vec<u64> {
    let mut kept_this_build = false;
    let mut out = Vec::new();
    for line in listing.lines() {
        if !line.contains(CARRIER_COUNTER) {
            continue;
        }
        let is_this_build = line.contains(text);
        let drop = if is_this_build {
            let duplicate = kept_this_build;
            kept_this_build = true;
            duplicate
        } else {
            true
        };
        if !drop {
            continue;
        }
        if let Some(h) = line
            .rsplit("handle ")
            .next()
            .and_then(|h| h.trim().parse::<u64>().ok())
        {
            out.push(h);
        }
    }
    out
}

/// The chains a counting rule is installed in. Both are real, and which one
/// applies is a property of the datapath rather than of the probe: an arrival
/// whose destination is the router itself traverses the input chain, and the
/// ingress translation sends a slot port's arrival to its client, which
/// traverses the forward chain. Measured on the router on 2026-09-21: with the
/// rule in the input chain alone the marked datagram arrived at the slot port
/// (`170.9.238.141.41001 > 192.168.0.21.40000`) and the counter stayed at zero,
/// because the translation introduced by this same work had already turned the
/// arrival into forwarded traffic.
pub const CARRIER_CHAINS: [&str; 2] = ["input", "forward"];

/// The argv that installs the counting rule in one chain.
///
/// `insert`, not `add`, and that is a fix this rule needed: fw4's chains carry
/// accept rules of their own for the same ports, and a rule appended after an
/// accept is never evaluated for a packet that accept takes. Measured on the
/// box on 2026-09-20: the marked datagram arrived at the slot port while the
/// counter stayed at zero. Inserting puts the count ahead of every decision,
/// and the rule terminates nothing, so the packet's fate is exactly what it
/// was.
fn carrier_probe_rule_argv(chain: &str) -> Vec<String> {
    vec![
        "insert".into(),
        "rule".into(),
        "inet".into(),
        "fw4".into(),
        chain.into(),
        carrier_probe_rule_text(chain),
    ]
}

/// What one chain's listing says about the counting rule.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainRuleState {
    /// The handles of rules that name the counter and are not this build's rule.
    pub stale: Vec<u64>,
    /// Whether this build's rule is absent from the chain.
    pub missing: bool,
}

/// Read one chain's listing into the two facts an install acts on.
///
/// A listing that cannot be read says nothing about the rule, and is left
/// alone: the install would fail on the same read, and the caller reports it.
pub fn carrier_probe_chain_state(listing: Option<&str>, text: &str) -> ChainRuleState {
    match listing {
        Some(l) => ChainRuleState {
            stale: carrier_probe_stale_handles(l, text),
            missing: !l.contains(text),
        },
        None => ChainRuleState {
            stale: Vec::new(),
            missing: false,
        },
    }
}

/// Read one chain of the firewall's table. An error says nothing about the rule
/// in it, which is why the answer is an Option rather than a String.
fn read_carrier_chain(chain: &str) -> Option<String> {
    Command::new("nft")
        .args(["list", "chain", "inet", "fw4", chain])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Install the counter and its rules. Idempotent, and content-aware: a rule is
/// installed only when its chain does not already carry it, so a second call
/// adds nothing and a chain that already counts keeps counting.
///
/// The return says whether this call changed anything, which is what makes a
/// lost rule visible: the rules live in the firewall's tables, and a firewall
/// rebuild takes them with it while leaving the counter object in place, so the
/// reading stays plausible and only the install can tell that the instrument
/// had gone.
pub fn ensure_carrier_probe() -> io::Result<bool> {
    let mut changed = false;
    if run(&["add", "counter", "inet", "fw4", CARRIER_COUNTER]).is_ok() {
        changed = true;
    }
    for chain in CARRIER_CHAINS {
        let text = carrier_probe_rule_text(chain);
        let state = carrier_probe_chain_state(read_carrier_chain(chain).as_deref(), &text);
        for h in state.stale {
            if run(&[
                "delete",
                "rule",
                "inet",
                "fw4",
                chain,
                "handle",
                &h.to_string(),
            ])
            .is_ok()
            {
                changed = true;
            }
        }
        if state.missing {
            let argv = carrier_probe_rule_argv(chain);
            let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            run(&refs)?;
            // The chain is read back, because the chain is the only thing that
            // says whether the rule landed and which text it landed as. The
            // quoting above was found this way: an install that looked for the
            // wrong spelling added a copy a poll while reporting a repair.
            if !read_carrier_chain(chain)
                .map(|l| l.contains(&text))
                .unwrap_or(false)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("the counting rule did not land in the {} chain", chain),
                ));
            }
            changed = true;
        }
    }
    Ok(changed)
}

/// Read the counter's packet count. An error here is the shape a watch that
/// was never installed has, and the caller logs it and keeps watching.
pub fn list_carrier_probe() -> io::Result<u64> {
    let out = Command::new("nft")
        .args(["list", "counter", "inet", "fw4", CARRIER_COUNTER])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("nft list counter {} -> {}", CARRIER_COUNTER, out.status),
        ));
    }
    Ok(parse_carrier_probe(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse the counter's packet count. Pure; a listing with no `packets` line
/// reads as zero. Hand-rolled, tiny — Kani non-goal, like the rest of the
/// CLI boundary.
pub fn parse_carrier_probe(text: &str) -> u64 {
    text.lines()
        .find_map(|l| {
            let mut t = l.split_whitespace();
            while let Some(w) = t.next() {
                if w == "packets" {
                    return t.next().and_then(|n| n.parse::<u64>().ok());
                }
            }
            None
        })
        .unwrap_or(0)
}

/// Pin a console flow: (client_ip, client_port) -> (NAT_ADDR, R).
/// `nft add element ip dslp snat_map { 10.0.0.5 . 3074 : 192.168.0.21 . 30740 }`
///
/// Idempotent for respawn (B8): kernel nft state survives a daemon crash,
/// so re-adding an identical element must succeed; a *conflicting* value
/// for the same key is an error (I1-style split). Implemented by listing
/// the map and matching the exact `key : value` line on EEXIST.
pub fn add_pin(client: Ipv4Addr, client_port: u16, r: u16) -> io::Result<()> {
    let elem = format!("{} . {} : {} . {}", client, client_port, NAT_ADDR, r);
    match run(&[
        "add", "element", "ip", "dslp", "snat_map",
        &format!("{{ {} }}", elem),
    ]) {
        Ok(()) => Ok(()),
        Err(_) => {
            // EEXIST: the kernel keeps nft state across a daemon crash, and
            // this map is the daemon's own, so a stale element for this key
            // is our own mess from a previous run rather than a competing
            // connection. A key maps to one value, and a stale value is worse
            // than any split this used to refuse: it mis-translates the
            // device's traffic to a port the device is not using, which is a
            // console losing its mapping while nothing looks wrong. The
            // element is replaced.
            let _ = del_pin(client, client_port);
            run(&[
                "add", "element", "ip", "dslp", "snat_map",
                &format!("{{ {} }}", elem),
            ])
        }
    }
}

pub fn del_pin(client: Ipv4Addr, client_port: u16) -> io::Result<()> {
    let elem = format!("{} . {}", client, client_port);
    run(&[
        "delete", "element", "ip", "dslp", "snat_map",
        &format!("{{ {} }}", elem),
    ])
}

/// Open the hub-LAN input for one slot's port: the port joins the accept set
/// its protocol uses. Two sets, because the TCP arm is mandatory for the
/// splice (fw4's input chain drops forwarded TCP NEW silently, the C3
/// finding) and one set for both protocols would open a TCP accept for a UDP
/// slot's port. An element addressed by key, so the accept can always be
/// taken away again.
pub fn add_input_accept(r: u16, tcp: bool) -> io::Result<()> {
    let args = accept_element("add", r, tcp);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&refs)
}

/// Close it again: the port leaves the set. Not present is fine, and cannot
/// hide a leftover the way a per-port rule could: an element is addressed by
/// key rather than by a handle read out of `nft -a list`, and the sets are
/// emptied when the daemon installs them.
pub fn del_input_accept(r: u16, tcp: bool) -> io::Result<()> {
    let args = accept_element("delete", r, tcp);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let _ = run(&refs);
    Ok(())
}

/// Remove the ruleset (shutdown / clean restore). Best-effort: the daemon's
/// own table goes wholesale, and the accept sets are emptied, so no port stays
/// open for a process that is not there. The two accept rules stay installed —
/// they accept an empty set, which accepts nothing, and leaving them avoids
/// churn in fw4 on every restart.
pub fn remove_ruleset() {
    let _ = run(&["delete", "table", "ip", "dslp"]);
    for tcp in [false, true] {
        let _ = run(&["flush", "set", "inet", "fw4", accept_set(tcp)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_addr_is_hub_lan() {
        assert_eq!(NAT_ADDR, Ipv4Addr::new(192, 168, 0, 21));
    }

    #[test]
    fn a_slots_accept_is_a_set_element_never_a_rule_handle() {
        // `delete rule` by expression is refused by this nft ("syntax error,
        // unexpected iifname, expecting handle"), so a per-port *rule* could
        // only be removed by a handle read out of `nft -a list chain inet fw4
        // input`, and a delete that failed left the rule installed: two accept
        // rules from earlier daemons were still on the test router. A slot's
        // accept is an *element* of the set its protocol uses, addressed by
        // key.
        assert_eq!(accept_set(false), "dslp_ports_udp");
        assert_eq!(accept_set(true), "dslp_ports_tcp");
        let add = accept_element("add", 40001, false);
        assert_eq!(
            add,
            vec![
                "add",
                "element",
                "inet",
                "fw4",
                "dslp_ports_udp",
                "{ 40001 }"
            ]
        );
        let del = accept_element("delete", 40002, true);
        assert_eq!(
            del,
            vec![
                "delete",
                "element",
                "inet",
                "fw4",
                "dslp_ports_tcp",
                "{ 40002 }"
            ]
        );
        assert!(
            !add.iter().any(|t| t == "rule" || t == "handle" || t == "-a"),
            "an element is not a rule and needs no handle: {:?}",
            add
        );
    }

    #[test]
    fn the_two_protocols_use_two_sets() {
        // One set for both protocols would open a TCP accept for a UDP slot's
        // port; the TCP arm exists for the splice, not for every slot. And the
        // sets' own rules must carry no daemon comment, or the legacy sweep
        // would delete them on the next start.
        assert_ne!(accept_set(false), accept_set(true));
        let rules = accept_rule_text();
        assert_eq!(rules[0], "iifname \"eth1\" udp dport @dslp_ports_udp accept");
        assert_eq!(rules[1], "iifname \"eth1\" tcp dport @dslp_ports_tcp accept");
        assert!(
            !rules.iter().any(|r| r.contains("dslitepunch")),
            "the sweep must never see the sets' own rules: {:?}",
            rules
        );
    }

    #[test]
    fn the_legacy_sweep_takes_only_the_daemons_per_port_rules() {
        // A real listing shape: the sets' two rules, one rule an older daemon
        // left behind, and fw4's own traffic.
        let listing = "\t\tiifname \"eth1\" udp dport @dslp_ports_udp accept\n\
                       \t\tiifname \"eth1\" tcp dport @dslp_ports_tcp accept\n\
                       \t\tiifname \"eth1\" tcp dport 40002 accept comment \"dslitepunch-40002-tcp\" # handle 137\n\
                       \t\tct state established accept\n";
        assert_eq!(legacy_rule_handles(listing), vec![137]);
        assert!(legacy_rule_handles("").is_empty());
        assert!(
            legacy_rule_handles("iifname \"eth1\" udp dport @dslp_ports_udp accept").is_empty()
        );
    }

    #[test]
    fn element_format_roundtrip_helpers() {
        // sanity on the string shapes produced for nft (no nft on CI):
        let client = Ipv4Addr::new(192, 168, 21, 50);
        assert_eq!(
            format!("{} . {}", client, 3074),
            "192.168.21.50 . 3074"
        );
        assert_eq!(
            format!("{} . {} : {} . {}", client, 3074, NAT_ADDR, 30740),
            "192.168.21.50 . 3074 : 192.168.0.21 . 30740"
        );
    }

    #[test]
    fn parse_flow_obs_real_shapes() {
        // live shape captured on the router (2026-09-02, gating test): one
        // element with an `expires` marker
        let live = "table ip dslp {\n\tset flow_obs {\n\t\ttype ipv4_addr . inet_service\n\t\tsize 65535\n\t\ttimeout 15s\n\t\telements = { 192.168.0.21 . 40077 expires 13s498ms }\n\t}\n}\n";
        assert_eq!(
            parse_flow_obs(live),
            vec![(Ipv4Addr::new(192, 168, 0, 21), 40077)]
        );

        // multi-element + trailing closing brace on the last token
        let multi = "elements = { 192.168.0.21 . 40077 expires 2s, 192.168.0.21 . 40078 expires 14s }\n";
        assert_eq!(
            parse_flow_obs(multi),
            vec![
                (Ipv4Addr::new(192, 168, 0, 21), 40077),
                (Ipv4Addr::new(192, 168, 0, 21), 40078),
            ]
        );

        // empty set: no elements line at all
        let empty = "table ip dslp {\n\tset flow_obs {\n\t\ttype ipv4_addr . inet_service\n\t}\n}\n";
        assert!(parse_flow_obs(empty).is_empty());

        // garbage never panics, yields nothing
        assert!(parse_flow_obs("").is_empty());
        assert!(parse_flow_obs("elements = { }").is_empty());
        assert!(parse_flow_obs("elements = { not-an-ip . x }").is_empty());
    }

    #[test]
    fn the_watch_rule_matches_the_mark_and_never_terminates() {
        for chain in CARRIER_CHAINS {
            let text = carrier_probe_rule_text(chain);
            assert!(
                text.contains("@th,64,64"),
                "the mark sits at the transport payload: {}",
                text
            );
            assert!(
                text.contains(&format!("0x{:016x}", crate::carrier::MARK_WORD)),
                "{}",
                text
            );
            assert!(
                text.contains(&format!("counter name \"{}\"", CARRIER_COUNTER)),
                "the text must be the text nft lists, quotes included: {}",
                text
            );
            assert!(
                !text.contains("accept"),
                "recognising a probe grants nothing: {}",
                text
            );
            assert!(
                !text.contains("drop"),
                "recognising a probe grants nothing: {}",
                text
            );
        }
    }

    #[test]
    fn the_input_rule_names_the_slot_port_and_the_forward_rule_cannot() {
        // The arrival reaches the input chain still addressed to the slot's bind
        // port, and the ingress translation rewrites it to the client's port
        // before the forward hook. A port match in the forward rule therefore
        // matches nothing: measured on the router on 2026-09-21, with both rules
        // installed and the marked datagram arriving, the counter stayed at zero
        // until the forward rule stopped asking for the port.
        let input = carrier_probe_rule_text("input");
        assert!(
            input.contains(&format!("dport @{}", ACCEPT_SET_UDP)),
            "{}",
            input
        );
        let forward = carrier_probe_rule_text("forward");
        assert!(
            !forward.contains("dport"),
            "the forward hook sees the client's port, not the slot's: {}",
            forward
        );
        assert!(forward.contains("iifname \"eth1\""));
        assert!(forward.contains("@th,64,64"));
    }

    #[test]
    fn the_forward_rule_names_the_protocol_the_way_nft_accepts() {
        // A bare `udp` before a payload expression is a syntax error, so this
        // rule was never installed and the watch counted nothing. Measured on the
        // router on 2026-09-21: "syntax error, unexpected @, expecting length or
        // checksum or sport or dport", with the counter at zero while the probes
        // arrived.
        let forward = carrier_probe_rule_text("forward");
        assert!(forward.contains("meta l4proto udp"), "{}", forward);
        assert!(
            !forward.contains("\"eth1\" udp @th"),
            "a bare protocol keyword before the payload is refused: {}",
            forward
        );
    }

    #[test]
    fn a_stale_rule_is_named_by_its_handle_and_the_current_one_is_not() {
        let current = carrier_probe_rule_text("forward");
        let listing = format!(
            "\t\tiifname \"eth1\" udp dport @dslp_ports_udp @th,64,64 0x64736c702d707262 counter name \"carrier_probe\" # handle 17665\n\t\t{} # handle 17669\n",
            current
        );
        assert_eq!(carrier_probe_stale_handles(&listing, &current), vec![17665]);
        assert!(carrier_probe_stale_handles("", &current).is_empty());
        assert_eq!(
            carrier_probe_stale_handles(&listing, "nothing matches this").len(),
            2
        );
    }

    #[test]
    fn the_watch_rule_is_evaluated_before_the_accept_rules() {
        let argv = carrier_probe_rule_argv("input");
        assert_eq!(
            argv[0], "insert",
            "an appended rule is never evaluated past an accept: {:?}",
            argv
        );
        assert_eq!(argv[5], carrier_probe_rule_text("input"));
    }

    #[test]
    fn the_watch_counts_in_both_the_input_and_forward_paths() {
        // Measured on the router on 2026-09-21: the ingress translation sends a
        // slot port's arrival to its client, which makes it forwarded traffic, so
        // a counting rule in the input chain alone sees nothing at all. The
        // counter stayed at zero while the marked datagram arrived.
        for chain in CARRIER_CHAINS {
            let argv = carrier_probe_rule_argv(chain);
            assert_eq!(argv[0], "insert", "{:?}", argv);
            assert_eq!(argv[4], chain, "{:?}", argv);
            assert_eq!(argv[5], carrier_probe_rule_text(chain));
        }
        assert!(CARRIER_CHAINS.contains(&"input"));
        assert!(CARRIER_CHAINS.contains(&"forward"));
    }

    #[test]
    fn a_chain_whose_counting_rule_went_is_read_as_missing() {
        // Measured on the router on 2026-09-22: a firewall rebuild left the
        // counter object in place with nothing naming it, so the reading stayed
        // plausible while the count stood still. This is the reading the poll
        // converges on, and the wipe is the case with the object and no rule.
        let text = carrier_probe_rule_text("forward");
        let wiped = "\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n";
        assert_eq!(
            carrier_probe_chain_state(Some(wiped), &text),
            ChainRuleState {
                stale: Vec::new(),
                missing: true
            },
            "an object with no rule naming it is the wipe"
        );

        let installed = format!("\t\t{} # handle 17660\n", text);
        assert_eq!(
            carrier_probe_chain_state(Some(&installed), &text),
            ChainRuleState {
                stale: Vec::new(),
                missing: false
            },
            "the rule this build installs counts as present, read back as nft lists it"
        );

        let older = "\t\tiifname \"eth1\" udp dport 40000 counter name \"carrier_probe\" # handle 17661\n";
        assert_eq!(
            carrier_probe_chain_state(Some(older), &text),
            ChainRuleState {
                stale: vec![17661],
                missing: true
            },
            "an older variant is replaced, and the chain still needs this build's rule"
        );

        // Measured on the router on 2026-09-23: the install looked for a text
        // nft never stores, so every poll added another copy of the rule it
        // already had. Thirty-nine of them sat in the chain. The first copy is
        // kept and every later one goes, so the count comes back to one.
        let duplicated = format!(
            "\t\t{} # handle 21328\n\t\t{} # handle 21330\n\t\t{} # handle 21332\n",
            text, text, text
        );
        assert_eq!(
            carrier_probe_chain_state(Some(&duplicated), &text),
            ChainRuleState {
                stale: vec![21330, 21332],
                missing: false
            },
            "copies of the rule the chain already has are duplicates, not repairs"
        );

        assert_eq!(
            carrier_probe_chain_state(None, &text),
            ChainRuleState {
                stale: Vec::new(),
                missing: false
            },
            "a chain that cannot be read is left alone, and the caller reports the read"
        );
    }

    #[test]
    fn the_inbound_chain_is_installed_before_its_rule() {
        let argv = inbound_chain_argv();
        assert_eq!(argv[0], "add");
        assert_eq!(argv[1], "chain");
        assert_eq!(argv[4], "prerouting");
        assert!(
            argv[5].contains("nat hook prerouting"),
            "the translation needs the nat prerouting hook: {:?}",
            argv
        );
        // and it must run ahead of fw4's own dstnat at the hook's default
        assert!(argv[5].contains("priority -150"), "{:?}", argv);
    }

    #[test]
    fn the_inbound_rule_translates_at_ingress_and_never_at_egress() {
        for tcp in [false, true] {
            let text = inbound_rule_text(tcp);
            let proto = if tcp { "tcp" } else { "udp" };
            assert!(text.contains("dnat"), "{}", text);
            assert!(
                !text.contains("snat"),
                "the client's egress keeps its own port: {}",
                text
            );
            assert!(text.contains(&format!("{} dport @{}", proto, inbound_set(tcp))));
            assert!(text.contains(&format!("map @{}", inbound_map(tcp))));
            assert!(text.contains("iifname \"eth1\""));
        }
    }

    #[test]
    fn a_grant_translates_the_port_to_the_client_that_owns_it() {
        let client = Ipv4Addr::new(192, 168, 21, 11);
        let script = format!(
            "add element ip dslp {} {{ {} }}\nadd element ip dslp {} {{ {} : {} . {} }}\n",
            INBOUND_SET_UDP,
            40002,
            INBOUND_MAP_UDP,
            40002,
            client,
            41010
        );
        assert!(script.contains("dslp_in_udp { 40002 }"));
        assert!(script.contains("dslp_dnat_udp { 40002 : 192.168.21.11 . 41010 }"));
    }

    #[test]
    fn a_revoke_undoes_every_element_on_its_own() {
        let stmts = revoke_statements(40002, false);
        assert_eq!(stmts.len(), 3, "{:?}", stmts);
        // each statement stands alone: a batch is all-or-nothing, and an
        // absent element used to cancel the rest of the revoke
        for s in &stmts {
            assert!(!s.contains('\n'), "one statement per run: {}", s);
            assert!(s.starts_with("delete element "), "{}", s);
        }
        assert!(stmts[0].contains(&format!("{} {{ 40002 }}", INBOUND_SET_UDP)));
        assert!(stmts[1].contains(&format!("{} {{ 40002 }}", INBOUND_MAP_UDP)));
        assert!(stmts[2].contains(&format!("{} {{ 40002 }}", ACCEPT_SET_UDP)));
        // and nothing deletes a pin the grant never installs: that delete
        // failed on every revoke and put an error line in the log
        for s in &stmts {
            assert!(!s.contains("snat_map"), "{}", s);
        }
    }

    #[test]
    fn a_sets_ports_are_parsed_for_the_revoke_readback() {
        let live = "table ip dslp {\n\tset dslp_in_udp {\n\t\ttype inet_service\n\t\telements = { 40002, 40003 }\n\t}\n}\n";
        assert_eq!(parse_port_set(live), vec![40002, 40003]);
        assert!(parse_port_set("").is_empty());
        assert!(parse_port_set("elements = { }").is_empty());
        assert_eq!(parse_port_set("elements = { 40002 }"), vec![40002]);
    }

    #[test]
    fn the_counter_reading_is_parsed_from_a_real_listing() {
        let live = "table inet fw4 {\n\tcounter carrier_probe {\n\t\tpackets 42 bytes 672\n\t}\n}\n";
        assert_eq!(parse_carrier_probe(live), 42);
        assert_eq!(parse_carrier_probe(""), 0);
        assert_eq!(parse_carrier_probe("counter carrier_probe {\n}\n"), 0);
        assert_eq!(parse_carrier_probe("packets not-a-number bytes 1"), 0);
    }
}