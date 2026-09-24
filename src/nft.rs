//! nft datapath: a fixed rule set installed once, all dynamic state in named-map elements.
#![allow(dead_code)] // del_pin and remove_ruleset are consumed by the revoke and stop paths
use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use crate::publish::emiteln;

/// The NAT address every pinned console flow egresses as, the hub-LAN address the relay sockets bind.
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

/// Run a multi-statement nft script as one atomic batch, so the datapath state is all-or-nothing.
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

/// Install the conntrack timeout policy for the allowlist: both objects are removed and re-added.
pub fn apply_hold(list: &[Ipv4Addr]) -> io::Result<()> {
    remove_hold();
    if list.is_empty() {
        return Ok(());
    }
    run_script(&crate::keepalive::ruleset(list))
}

/// Remove the policy, selection chain first then the two objects; best-effort by design.
pub fn remove_hold() {
    let _ = run_script(&crate::keepalive::teardown());
}

/// Whether the policy is live: the parse after the apply is the evidence, not the batch's exit status.
pub fn hold_in_force() -> bool {
    let Ok(out) = Command::new("nft")
        .args(["list", "table", "ip", "dslp"])
        .output()
    else {
        return false;
    };
    crate::keepalive::present(&String::from_utf8_lossy(&out.stdout))
}

/// The daemon's accept sets: a slot's inbound accept is an element of the set its protocol uses.
pub const ACCEPT_SET_UDP: &str = "dslp_ports_udp";
pub const ACCEPT_SET_TCP: &str = "dslp_ports_tcp";

// two sets, one per protocol: one set for both would accept TCP on a UDP slot's port
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

/// The two rules that accept the sets, one per protocol; the legacy sweep must never see them.
fn accept_rule_text() -> [String; 2] {
    [
        format!("iifname \"eth1\" udp dport @{} accept", ACCEPT_SET_UDP),
        format!("iifname \"eth1\" tcp dport @{} accept", ACCEPT_SET_TCP),
    ]
}

/// Handles of the per-port accept rules an older daemon installed: the lines whose comment names it.
fn legacy_rule_handles(listing: &str) -> Vec<u64> {
    listing
        .lines()
        .filter(|l| l.contains("dslitepunch"))
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|t| t.parse::<u64>().ok())
        .collect()
}

/// The per-protocol sets of ports with an inbound translation, and the maps to their client tuples.
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

/// The prerouting rule that sends an arrival at a slot port to the client that owns it: dnat, never snat.
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

/// The argv that installs the prerouting chain, which must exist before its rule can be added.
fn inbound_chain_argv() -> Vec<String> {
    // -150: the nat hook floor -200 is rejected by nft, and fw4's own translation is at -100
    vec![
        "add".into(),
        "chain".into(),
        "ip".into(),
        "dslp".into(),
        "prerouting".into(),
        "{ type nat hook prerouting priority -150 ; policy accept ; }".into(),
    ]
}

/// Install the inbound sets, maps, chain and rules; idempotent, and the sets are emptied.
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

/// The ports a set currently holds; pure, so the revoke's read-back is testable away from the box.
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

/// Whether a port still has an inbound translation: the revoke reads this back, and a leftover misdelivers.
pub fn inbound_set_has(bind_port: u16, tcp: bool) -> bool {
    let Ok(out) = Command::new("nft")
        .args(["list", "set", "ip", "dslp", inbound_set(tcp)])
        .output()
    else {
        return false;
    };
    parse_port_set(&String::from_utf8_lossy(&out.stdout)).contains(&bind_port)
}

/// Grant a slot's datapath: accept the port on eth1 and translate an ingress arrival to its owning client.
pub fn grant_datapath(client: Ipv4Addr, int_port: u16, bind_port: u16, tcp: bool) -> io::Result<()> {
    // the grant installs no pin: egress keeps the client's port, and ingress is translated instead
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

/// The statements that revoke a slot's datapath; each runs on its own, since a batch is all-or-nothing.
pub fn revoke_statements(bind_port: u16, tcp: bool) -> Vec<String> {
    // no snat_map statement: the grant installs no pin, so a pin delete could only fail
    vec![
        format!("delete element ip dslp {} {{ {} }}", inbound_set(tcp), bind_port),
        format!("delete element ip dslp {} {{ {} }}", inbound_map(tcp), bind_port),
        format!("delete element inet fw4 {} {{ {} }}", accept_set(tcp), bind_port),
    ]
}

/// Revoke a slot's datapath one statement at a time, and read the inbound set back afterwards.
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

/// Install the fixed ruleset; idempotent, since a create step for something present is tolerated.
pub fn ensure_ruleset() -> io::Result<()> {
    let _ = run(&["add", "table", "ip", "dslp"]);
    // map + chain are re-created only on first install; ignore EEXIST
    let _ = run(&[
        "add", "map", "ip", "dslp", "snat_map",
        "{ type ipv4_addr . inet_service : ipv4_addr . inet_service ; }",
    ]);
    // -150: the nat hook floor -200 is rejected by nft, and fw4's own translation is at -100
    let _ = run(&[
        "add", "chain", "ip", "dslp", "postrouting",
        "{ type nat hook postrouting priority -150 ; policy accept ; }",
    ]);
    // one fixed rule per protocol, guarded so re-installs don't duplicate
    if !has_rule(false)? {
        // meta l4proto udp, not bare udp: before the map snat statement bare udp parses ambiguously
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

/// Install the accept sets and their two rules, empty both, and sweep an older daemon's per-port rules.
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
        // With no listing, leave the rule alone: a duplicate accept changes nothing about which packets pass.
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

// The CDC mirror (flow_obs): the observation engine's primary backend, a set of live eth1 UDP flows.

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
        // update, not add: add is insert-only, so an existing element's 15 s timeout would never refresh.
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
    // content-aware: an old add-rule for the mirror must not block the update-rule replacement.
    Ok(String::from_utf8_lossy(&out.stdout).contains("update @flow_obs"))
}

/// Live mirror elements: the post-NAT (ip, port) tuples of eth1 UDP flows; empty on any nft failure.
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

/// Parse nft list set output into element tuples; pure, and hand-rolled up to the CLI boundary.
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

// The carrier-probe counter (call/0033): the watcher's observation point.

/// The named counter the watcher reads, defined once so the rule and the counter read cannot drift.
pub const CARRIER_COUNTER: &str = "carrier_probe";

/// The rule that counts a marked probe in one chain; the chain decides how much it can say about the port.
pub fn carrier_probe_rule_text(chain: &str) -> String {
    // the mark is the eight bytes at bit 64 of the transport header, where a UDP payload starts
    let mark = format!("@th,64,64 0x{:016x}", crate::carrier::MARK_WORD);
    match chain {
        // meta l4proto udp, not bare udp: bare udp before a payload expression is a syntax error
        "forward" => format!(
            // the name is quoted because the install compares this text with the chain listing
            "iifname \"eth1\" meta l4proto udp {} counter name \"{}\"",
            mark, CARRIER_COUNTER
        ),
        // a set reference is table-scoped: the input rule reaches the accept set because both sit in fw4's table
        _ => format!(
            "iifname \"eth1\" udp dport @{} {} counter name \"{}\"",
            ACCEPT_SET_UDP, mark, CARRIER_COUNTER
        ),
    }
}

/// The handles of this chain's rules that name the counter and are not the one copy this build keeps.
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

/// The chains a counting rule is installed in: input for the router's arrival, forward for a translated one.
pub const CARRIER_CHAINS: [&str; 2] = ["input", "forward"];

/// The argv that installs the counting rule with insert: an appended rule is never evaluated past an accept.
fn carrier_probe_rule_argv(chain: &str) -> Vec<String> {
    // the rule terminates nothing: the accept and forward rules still decide the packet's fate
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
pub fn carrier_probe_chain_state(listing: &str, text: &str) -> ChainRuleState {
    ChainRuleState {
        stale: carrier_probe_stale_handles(listing, text),
        missing: !listing.contains(text),
    }
}

/// Whether the named counter is there to read.
fn carrier_counter_reads() -> bool {
    Command::new("nft")
        .args(["list", "counter", "inet", "fw4", CARRIER_COUNTER])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Read one chain of the firewall's table; a chain that cannot be read is an error, never a shrug.
fn read_carrier_chain(chain: &str) -> io::Result<String> {
    let out = Command::new("nft")
        .args(["list", "chain", "inet", "fw4", chain])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("nft list chain inet fw4 {} -> {}", chain, out.status),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Install the counter and its rules; the return says whether this call changed anything.
pub fn ensure_carrier_probe() -> io::Result<bool> {
    let mut changed = false;
    // the counter is created only when absent: adding one that exists reports success and changes nothing
    if !carrier_counter_reads() {
        run(&["add", "counter", "inet", "fw4", CARRIER_COUNTER])?;
        if !carrier_counter_reads() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("the counter {} did not land", CARRIER_COUNTER),
            ));
        }
        changed = true;
    }
    for chain in CARRIER_CHAINS {
        let text = carrier_probe_rule_text(chain);
        let state = carrier_probe_chain_state(&read_carrier_chain(chain)?, &text);
        for h in state.stale {
            run(&[
                "delete",
                "rule",
                "inet",
                "fw4",
                chain,
                "handle",
                &h.to_string(),
            ])?;
            changed = true;
        }
        if state.missing {
            let argv = carrier_probe_rule_argv(chain);
            let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            run(&refs)?;
            // the chain is read back: the listing is the only oracle for whether the rule landed
            if !read_carrier_chain(chain)?.contains(&text) {
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

/// Read the counter's packet count; an error is the shape a watch that was never installed has.
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

/// Parse the counter's packet count; a listing with no packets line reads as zero.
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

/// Pin a console flow as (client_ip, client_port) -> (NAT_ADDR, R) in snat_map.
pub fn add_pin(client: Ipv4Addr, client_port: u16, r: u16) -> io::Result<()> {
    let elem = format!("{} . {} : {} . {}", client, client_port, NAT_ADDR, r);
    match run(&[
        "add", "element", "ip", "dslp", "snat_map",
        &format!("{{ {} }}", elem),
    ]) {
        Ok(()) => Ok(()),
        Err(_) => {
            // the element is replaced: a stale value under this key mis-translates the device's traffic
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

/// Open the hub-LAN input for one slot's port: the port joins the accept set its protocol uses.
pub fn add_input_accept(r: u16, tcp: bool) -> io::Result<()> {
    let args = accept_element("add", r, tcp);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&refs)
}

/// Close it again: the port leaves the set, and not being present is fine.
pub fn del_input_accept(r: u16, tcp: bool) -> io::Result<()> {
    let args = accept_element("delete", r, tcp);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let _ = run(&refs);
    Ok(())
}

/// Remove the ruleset at shutdown: the daemon's table wholesale, and both accept sets emptied.
pub fn remove_ruleset() {
    let _ = run(&["delete", "table", "ip", "dslp"]);
    for tcp in [false, true] {
        // the two accept rules stay installed: they accept an empty set, which accepts nothing
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
        // delete rule by expression is refused by this nft, so a slot's accept is a key-addressed element.
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
        // one set for both protocols would accept TCP on a UDP slot's port.
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
        // A real listing shape: the sets' two rules, one rule an older daemon left, and fw4's own traffic.
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
        // a live shape captured on the router: one element carrying an expires marker
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
        // the input rule can match the slot's port because the ingress translation has not run yet
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
        // a bare protocol keyword before a payload expression is refused, so the rule uses meta l4proto udp
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
        // the ingress translation makes a slot port's arrival forwarded, so the input chain sees nothing
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
        // a firewall rebuild leaves the counter object with no rule naming it, so the count stands still
        let text = carrier_probe_rule_text("forward");
        let wiped = "\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n";
        assert_eq!(
            carrier_probe_chain_state(wiped, &text),
            ChainRuleState {
                stale: Vec::new(),
                missing: true
            },
            "an object with no rule naming it is the wipe"
        );

        let installed = format!("\t\t{} # handle 17660\n", text);
        assert_eq!(
            carrier_probe_chain_state(&installed, &text),
            ChainRuleState {
                stale: Vec::new(),
                missing: false
            },
            "the rule this build installs counts as present, read back as nft lists it"
        );

        let older = "\t\tiifname \"eth1\" udp dport 40000 counter name \"carrier_probe\" # handle 17661\n";
        assert_eq!(
            carrier_probe_chain_state(older, &text),
            ChainRuleState {
                stale: vec![17661],
                missing: true
            },
            "an older variant is replaced, and the chain still needs this build's rule"
        );

        // the first copy of this build's rule is kept; every later copy goes, so the count returns to one
        let duplicated = format!(
            "\t\t{} # handle 21328\n\t\t{} # handle 21330\n\t\t{} # handle 21332\n",
            text, text, text
        );
        assert_eq!(
            carrier_probe_chain_state(&duplicated, &text),
            ChainRuleState {
                stale: vec![21330, 21332],
                missing: false
            },
            "copies of the rule the chain already has are duplicates, not repairs"
        );

        // an unreadable chain returns the error, not a shrug, since silence hid the segfaulting listing
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
        // each statement stands alone: a batch is all-or-nothing, and an absent element cancelled the rest
        for s in &stmts {
            assert!(!s.contains('\n'), "one statement per run: {}", s);
            assert!(s.starts_with("delete element "), "{}", s);
        }
        assert!(stmts[0].contains(&format!("{} {{ 40002 }}", INBOUND_SET_UDP)));
        assert!(stmts[1].contains(&format!("{} {{ 40002 }}", INBOUND_MAP_UDP)));
        assert!(stmts[2].contains(&format!("{} {{ 40002 }}", ACCEPT_SET_UDP)));
        // nothing deletes a pin the grant never installs: that delete failed on every revoke
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