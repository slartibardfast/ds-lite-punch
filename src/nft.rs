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

/// The match half of a slot's accept rule: every discriminator, no verb.
/// `insert` builds a rule from it and `delete` removes one by it, so a delete
/// needs no handle and never parses a listing. One definition, so the rule
/// the daemon installs is the rule it can remove.
fn accept_match(bind_port: u16, tcp: bool) -> Vec<String> {
    let kw = if tcp { "tcp" } else { "udp" };
    vec![
        "iifname".into(),
        "\"eth1\"".into(),
        kw.into(),
        "dport".into(),
        bind_port.to_string(),
        "accept".into(),
        "comment".into(),
        format!(
            "\"dslitepunch-{}{}\"",
            bind_port,
            if tcp { "-tcp" } else { "" }
        ),
    ]
}

/// The per-slot accept rule text (shared by the grant batch and the
/// fallback path so the comment and match never drift).
fn accept_rule(bind_port: u16, tcp: bool) -> String {
    format!(
        "insert rule inet fw4 input {}",
        accept_match(bind_port, tcp).join(" ")
    )
}

/// Grant a slot datapath atomically: the snat_map pin and the input-accept
/// in one `nft -f -` batch (one subprocess, all-or-nothing). Falls back to
/// the per-op functions when the batch fails (e.g. the respawn re-add case
/// where `add element` EEXISTs — `add_pin` tolerates that by value check,
/// and `add_input_accept` cleans a stale rule first). The stale-rule edge
/// (same R re-granted after the revoke) is handled by the fallback; a
/// duplicate accept is otherwise unreachable because R reuse only follows
/// a successful revoke.
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
    // All or nothing: the accept rule alone, in one batch, with the per-op
    // path as the fallback for the respawn re-add case.
    let script = format!("{}\n", accept_rule(bind_port, tcp));
    if run_script(&script).is_ok() {
        return Ok(());
    }
    add_input_accept(bind_port, tcp)
}

/// Revoke a slot datapath atomically: element delete plus rule delete (by
/// expression — no handle lookup) in one batch; falls back to the per-op
/// functions.
pub fn revoke_datapath(client: Ipv4Addr, int_port: u16, bind_port: u16, tcp: bool) -> io::Result<()> {
    let script = format!(
        "delete element ip dslp snat_map {{ {} . {} }}\n\
         delete rule inet fw4 input {}\n",
        client,
        int_port,
        accept_match(bind_port, tcp).join(" ")
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

/// Per-slot wan input-accept so the relay socket receives on the hub-LAN
/// interface. Protocol-specific (`udp`/`tcp` dport); unique comment per
/// slot and proto (`dslitepunch-<R>` / `dslitepunch-<R>-tcp`);
/// replace-not-dup. The TCP arm is mandatory for the splice: fw4's input
/// chain drops forwarded TCP NEW silently (the C3 finding).
pub fn add_input_accept(r: u16, tcp: bool) -> io::Result<()> {
    // delete any stale rule with this match first (idempotent add)
    let _ = del_input_accept(r, tcp);
    let mut args: Vec<String> = vec![
        "insert".into(),
        "rule".into(),
        "inet".into(),
        "fw4".into(),
        "input".into(),
    ];
    args.extend(accept_match(r, tcp));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&refs)
}

/// Delete a slot's accept rule by its match expression, never by handle. A
/// handle has to be read out of `nft -a list chain inet fw4 input`, which is
/// both the listing the libnftables segfaults come from and the reason a
/// failed delete leaves the rule behind: two accept rules from earlier
/// daemons are still installed on the test router, one of them for a
/// protocol this build does not enable. A match needs no listing, so the rule
/// the daemon installs is always one it can remove. Not present is fine.
pub fn del_input_accept(r: u16, tcp: bool) -> io::Result<()> {
    let mut args: Vec<String> = vec![
        "delete".into(),
        "rule".into(),
        "inet".into(),
        "fw4".into(),
        "input".into(),
    ];
    args.extend(accept_match(r, tcp));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    // `delete rule` removes the first match. A duplicate can only come from
    // an older daemon, so it is deleted while one remains, bounded so a
    // misbehaving nft can never spin here.
    for _ in 0..4 {
        if run(&refs).is_err() {
            break;
        }
    }
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
    fn a_slots_accept_rule_is_matched_by_expression_never_by_handle() {
        // The delete must not depend on parsing `nft -a list chain inet fw4
        // input`: that listing is the path the libnftables segfaults come
        // from, and a delete that depends on it leaves the rule behind when
        // it fails. Two such rules from earlier daemons are still installed
        // on the test router, one of them for a protocol this build does not
        // even enable. Every discriminator therefore lives in one match, so
        // `delete rule` finds the rule without a handle.
        let udp = accept_match(40001, false);
        assert_eq!(
            udp,
            vec![
                "iifname",
                "\"eth1\"",
                "udp",
                "dport",
                "40001",
                "accept",
                "comment",
                "\"dslitepunch-40001\"",
            ]
        );
        let tcp = accept_match(40002, true);
        assert_eq!(tcp[2], "tcp", "the protocol is in the match");
        assert!(
            tcp[7].contains("-tcp"),
            "the comment is in the match: {:?}",
            tcp[7]
        );
        assert!(
            !udp.iter().any(|t| t == "-a" || t == "list" || t == "handle"),
            "a match is not a listing: {:?}",
            udp
        );
    }

    #[test]
    fn the_insert_and_the_delete_share_one_match() {
        // One definition, so the rule the daemon installs is the rule it can
        // remove: a drift between the two is a rule that can never be
        // deleted, and it stays installed until the router reboots.
        let m = accept_match(40003, false).join(" ");
        assert_eq!(
            accept_rule(40003, false),
            format!("insert rule inet fw4 input {}", m)
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
}