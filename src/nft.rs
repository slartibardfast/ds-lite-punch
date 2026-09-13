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
use std::net::Ipv4Addr;
use std::process::Command;

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
            // EEXIST path: accept if the element is already exactly this
            // value (respawn re-add); reject if it maps elsewhere.
            let out = Command::new("nft")
                .args(["list", "map", "ip", "dslp", "snat_map"])
                .output()?;
            let text = String::from_utf8_lossy(&out.stdout);
            let needle = format!("{} . {} : {} . {}", client, client_port, NAT_ADDR, r);
            if text.contains(&needle) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("snat_map pin conflict for {} . {}", client, client_port),
                ))
            }
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

/// Per-slot wan input-accept so the relay socket receives on the hub-LAN
/// interface. Protocol-specific (`udp`/`tcp` dport); unique comment per
/// slot and proto (`dslitepunch-<R>` / `dslitepunch-<R>-tcp`);
/// replace-not-dup. The TCP arm is mandatory for the splice: fw4's input
/// chain drops forwarded TCP NEW silently (the C3 finding).
pub fn add_input_accept(r: u16, tcp: bool) -> io::Result<()> {
    let comment = format!("dslitepunch-{}{}", r, if tcp { "-tcp" } else { "" });
    // delete any stale rule with this comment first (idempotent add)
    let _ = del_input_accept(r, tcp);
    let kw = if tcp { "tcp" } else { "udp" };
    run(&[
        "insert", "rule", "inet", "fw4", "input",
        "iifname", "\"eth1\"", kw, "dport", &r.to_string(),
        "accept", "comment", &format!("\"{}\"", comment),
    ])
}

pub fn del_input_accept(r: u16, tcp: bool) -> io::Result<()> {
    let comment = format!(
        "\"dslitepunch-{}{}\"",
        r,
        if tcp { "-tcp" } else { "" }
    );
    let out = Command::new("nft")
        .args(["-a", "list", "chain", "inet", "fw4", "input"])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut deleted = false;
    for line in text.lines() {
        if line.contains(&comment) {
            // handle marker: `# handle N` is the last token
            let handle = line.split_whitespace().last().and_then(|t| t.parse::<u64>().ok());
            if let Some(h) = handle {
                if run(&["delete", "rule", "inet", "fw4", "input", "handle", &h.to_string()]).is_ok() {
                    deleted = true;
                }
            }
        }
    }
    let _ = deleted;
    // not present is fine (idempotent delete)
    Ok(())
}

/// Remove the whole ruleset (shutdown / clean restore). Best-effort.
pub fn remove_ruleset() {
    let _ = run(&["delete", "table", "ip", "dslp"]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_addr_is_hub_lan() {
        assert_eq!(NAT_ADDR, Ipv4Addr::new(192, 168, 0, 21));
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
}