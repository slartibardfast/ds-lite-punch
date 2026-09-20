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
/// own timeouts and the WAN half of the hold is the daemon's own writes).
pub fn apply_hold(list: &[Ipv4Addr]) -> io::Result<()> {
    remove_hold();
    if list.is_empty() {
        return Ok(());
    }
    run_script(&crate::hold::ruleset(list))
}

/// Remove the policy: the selection chain first, then the two objects.
/// Best-effort by design — the daemon's table dies with the process (the
/// stop path deletes `table ip dslp` wholesale), so a failure here leaves
/// nothing that outlives the daemon.
pub fn remove_hold() {
    let _ = run_script(&crate::hold::teardown());
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
    crate::hold::present(&String::from_utf8_lossy(&out.stdout))
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

/// Grant a slot's datapath: the port joins the accept set its protocol uses.
/// One element operation, addressed by key, so there is nothing to clean up
/// first and nothing that can be left behind.
pub fn grant_datapath(client: Ipv4Addr, int_port: u16, bind_port: u16, tcp: bool) -> io::Result<()> {
    // The client's own (client, int_port) is deliberately not pinned. That
    // pin made the client's traffic egress through the slot's port, so one
    // game held two external tuples at once: some flows on its own preserved
    // port and some on the relay's, which is what a console scores as Strict
    // or Moderate. Measured live on the router, with a console in game:
    // 14,740 packets of one flow egressing on the slot's port while its
    // siblings kept their own. call/0014 settled this: the console's value
    // story is organic, "works alongside, not enabled by" the relay. The
    // slot's own punch keeps its tuple through its own bound socket, and the
    // inbound path needs nothing of the client's egress.
    let _ = (client, int_port);
    add_input_accept(bind_port, tcp)
}

/// Revoke a slot's datapath: the port leaves its accept set, and the
/// snat_map element goes too for the paths that still pin (the arm's
/// self-pin and the statics).
pub fn revoke_datapath(client: Ipv4Addr, int_port: u16, bind_port: u16, tcp: bool) -> io::Result<()> {
    let script = format!(
        "delete element ip dslp snat_map {{ {} . {} }}\n\
         delete element inet fw4 {} {{ {} }}\n",
        client,
        int_port,
        accept_set(tcp),
        bind_port
    );
    if run_script(&script).is_ok() {
        return Ok(());
    }
    let _ = del_pin(client, int_port);
    let _ = del_input_accept(bind_port, tcp);
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

/// The rule that counts a marked probe arriving at a slot port, in fw4's
/// input chain where the accept sets live: a set reference is table-scoped,
/// so the rule belongs beside `dslp_ports_udp`.
///
/// The rule does not terminate, and that is deliberate: the probe is a
/// datagram like any other, so the accept rules still decide its fate and a
/// marked packet gains nothing from being recognised. The payload match is
/// the mark's eight bytes at the start of the transport payload, which for
/// UDP begins at bit 64 of the transport header.
pub fn carrier_probe_rule_text() -> String {
    format!(
        "iifname \"eth1\" udp dport @{} @th,64,64 0x{:016x} counter name {}",
        ACCEPT_SET_UDP,
        crate::carrier::MARK_WORD,
        CARRIER_COUNTER
    )
}

/// The argv that installs the counting rule.
///
/// `insert`, not `add`, and that is a fix this rule needed: fw4's input chain
/// carries accept rules of its own for the same ports, and a rule appended
/// after an accept is never evaluated for a packet that accept takes. Measured
/// on the box on 2026-09-20: the marked datagram arrived at the slot port
/// (`170.9.238.141.41000 > 192.168.0.21.40000`) while the counter stayed at
/// zero. Inserting puts the count ahead of every decision, and the rule
/// terminates nothing, so the packet's fate is exactly what it was.
fn carrier_probe_rule_argv() -> Vec<String> {
    vec![
        "insert".into(),
        "rule".into(),
        "inet".into(),
        "fw4".into(),
        "input".into(),
        carrier_probe_rule_text(),
    ]
}

/// Install the counter and its rule. Idempotent, and content-aware: the rule
/// is installed only when the chain does not already carry it.
pub fn ensure_carrier_probe() -> io::Result<()> {
    let _ = run(&["add", "counter", "inet", "fw4", CARRIER_COUNTER]);
    let listing = Command::new("nft")
        .args(["list", "chain", "inet", "fw4", "input"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    let text = carrier_probe_rule_text();
    let present = listing
        .as_deref()
        .map(|l| l.contains(&text))
        .unwrap_or(true);
    if !present {
        let argv = carrier_probe_rule_argv();
        let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        run(&refs)?;
    }
    Ok(())
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
            // holder. A key maps to one value, and a stale value is worse
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
        let text = carrier_probe_rule_text();
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
        assert!(text.contains(&format!("counter name {}", CARRIER_COUNTER)));
        assert!(text.contains(&format!("@{}", ACCEPT_SET_UDP)));
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

    #[test]
    fn the_watch_rule_is_evaluated_before_the_accept_rules() {
        let argv = carrier_probe_rule_argv();
        assert_eq!(
            argv[0], "insert",
            "an appended rule is never evaluated past an accept: {:?}",
            argv
        );
        assert_eq!(argv[5], carrier_probe_rule_text());
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