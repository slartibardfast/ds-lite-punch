//! The allowlist admission (call/0025, plan/0009 #allowlist): which devices
//! get the keepalive, and the local ruleset that grants it.
//!
//! Two halves make the keepalive, and neither is sufficient. Locally, the router's
//! own conntrack entry for a quiet device's flow is what the router's NAT
//! needs in order to translate inbound for that device, and it is reaped at
//! `nf_conntrack_udp_timeout` (60 s one-way) today. Remotely, only a datagram
//! from the flow's own post-NAT tuple refreshes the AFTR mapping. This module
//! owns the local half: the policy objects and the chain that selects them.
//!
//! The chain's hook is at mangle priority rather than at raw, and that is a
//! measurement rather than a preference: at a pre-conntrack priority the
//! assignment has no effect on this build, and one hook later it does. Both
//! readings are in this milestone's results record.
//!
//! The policy lives in the daemon's own datapath table (`ip dslp`), beside the
//! named map and the CDC mirror, for one reason: the allowlist drives both
//! halves of the keepalive, so the process that owns the arm owns the policy, and
//! there is no file, table or list that can drift from the daemon's own view
//! of who is admitted. fw4's generator carries no `flush ruleset`, so a
//! firewall reload regenerates fw4's own tables and leaves this one alone --
//! the same fact the deployed snat map already relies on. The alternative
//! (a script include under `/etc/nftables.d`, the pattern the v6 anti-spoof
//! table uses) is the durable form if the policy should outlive the daemon;
//! plan/0009's results record names the exact means.
//!
//! The allowlist grants maintenance and never authority (call/0025): nothing
//! here is readable or writable through UPnP, and no role derives from an
//! entry. The address is the key because the admitted devices are DHCP-pinned;
//! `ether saddr` is bridge-family and unavailable in the family the datapath
//! table uses.

use std::net::Ipv4Addr;

/// The daemon's datapath table: `--static-map` pins, the CDC mirror and this
/// policy share it.
pub const TABLE: &str = "ip dslp";
/// Policy-object names. Both carry the project prefix: nft object names are
/// global to the table, and the table is shared with the rest of the datapath.
pub const UDP_POLICY: &str = "dslp_udp_long";
pub const TCP_POLICY: &str = "dslp_tcp_long";
/// The selection chain. Its hook is measured rather than reasoned about: the
/// same statement at a pre-conntrack raw priority left every entry at the
/// default sixty seconds on this build, and the same statement one hook later
/// attaches the policy to the entry the conntrack hook has just created.
/// Mangle priority sits after conntrack, and fw4's own prerouting chain at the
/// same priority does not interact with this one.
pub const CHAIN: &str = "hold";
/// UDP: five minutes in both directions, against the two-minute floor the
/// mapping requirements set (RFC 4787's UDP mapping lifetime, carried into the
/// carrier-grade requirements). Above the floor on purpose: the cost of a
/// longer entry is one dormant conntrack row.
pub const UDP_POLICY_BODY: &str = "policy = { unreplied : 5m, replied : 5m }";
/// TCP: the established figure RFC 5382 sets (two hours four minutes), which
/// is also what the router's own default already carries.
pub const TCP_POLICY_BODY: &str = "policy = { established : 2h4m }";

/// Parse an allowlist file: one IPv4 address per line, `#` starts a comment,
/// blank lines are ignored. Returns the admitted addresses (in file order,
/// de-duplicated) and the lines that could not be read as an address, so a
/// malformed entry is reported rather than silently dropped.
pub fn parse(text: &str) -> (Vec<Ipv4Addr>, Vec<String>) {
    let mut list = Vec::new();
    let mut bad = Vec::new();
    for raw in text.lines() {
        let code = raw.split('#').next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }
        match code.parse::<Ipv4Addr>() {
            Ok(ip) => {
                if !list.contains(&ip) {
                    list.push(ip);
                }
            }
            Err(_) => bad.push(code.to_string()),
        }
    }
    (list, bad)
}

/// Whether `ip` is admitted for the keepalive. Pure membership: the entry carries
/// no role, so this answer is only ever "maintain this flow", never "trust".
pub fn allowed(list: &[Ipv4Addr], ip: Ipv4Addr) -> bool {
    list.contains(&ip)
}

/// The nft batch that installs the policy for `list`. Empty when the list is
/// empty: no admitted device means no policy object, no chain, and every flow
/// keeps the router's own timeouts.
pub fn ruleset(list: &[Ipv4Addr]) -> String {
    if list.is_empty() {
        return String::new();
    }
    let addrs: Vec<String> = list.iter().map(|ip| ip.to_string()).collect();
    let set = addrs.join(", ");
    format!(
        "table {table} {{\n\
         \tct timeout {udp} {{\n\
         \t\tprotocol udp\n\
         \t\t{UDP_POLICY_BODY}\n\
         \t}}\n\
         \tct timeout {tcp} {{\n\
         \t\tprotocol tcp\n\
         \t\t{TCP_POLICY_BODY}\n\
         \t}}\n\
         \tchain {chain} {{\n\
         \t\ttype filter hook prerouting priority -150; policy accept;\n\
         \t\tip saddr {{ {set} }} meta l4proto udp ct timeout set \"{udp}\"\n\
         \t\tip saddr {{ {set} }} meta l4proto tcp ct timeout set \"{tcp}\"\n\
         \t}}\n\
         }}\n",
        table = TABLE,
        chain = CHAIN,
        udp = UDP_POLICY,
        tcp = TCP_POLICY,
        set = set,
    )
}

/// The nft batch that removes the policy: the chain first (the selection),
/// then the two objects. Idempotent by the caller's tolerance, not here.
pub fn teardown() -> String {
    format!(
        "delete chain {table} {chain}\n\
         delete ct timeout {table} {udp}\n\
         delete ct timeout {table} {tcp}\n",
        table = TABLE,
        chain = CHAIN,
        udp = UDP_POLICY,
        tcp = TCP_POLICY,
    )
}

/// Whether `nft list table ip dslp` output already carries the policy. The
/// install is guarded by this because re-adding an existing `ct timeout`
/// object is an error under `nft -f`, and the batch would then apply nothing.
pub fn present(listed: &str) -> bool {
    listed.contains(&format!("ct timeout {}", UDP_POLICY))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_reads_addresses_and_reports_the_rest() {
        let (list, bad) = parse(
            "# the admitted devices\n\
             \n\
             192.168.21.68   # the switch\n\
             \t192.168.21.138\n\
             192.168.21.68\n\
             not-an-address\n\
             192.168.21.1/24\n",
        );
        // file order, duplicates dropped
        assert_eq!(list, vec![a("192.168.21.68"), a("192.168.21.138")]);
        // both unreadable lines are named back to the caller
        assert_eq!(bad.len(), 2);
        assert!(bad[0].contains("not-an-address"));
        assert!(bad[1].contains("192.168.21.1/24"));
    }

    #[test]
    fn parse_of_an_empty_or_comment_only_file_is_no_list() {
        assert_eq!(parse(""), (Vec::new(), Vec::new()));
        assert_eq!(parse("# nothing here\n\n"), (Vec::new(), Vec::new()));
        // whitespace-only lines are blank, not malformed
        assert_eq!(parse("   \n\t\n"), (Vec::new(), Vec::new()));
    }

    #[test]
    fn allowed_is_membership_alone() {
        let list = vec![a("192.168.21.68")];
        assert!(allowed(&list, a("192.168.21.68")));
        assert!(!allowed(&list, a("192.168.21.69")));
        assert!(!allowed(&[], a("192.168.21.68")), "an empty list admits nobody");
    }

    #[test]
    fn ruleset_carries_both_policies_and_the_admitted_addresses() {
        let rs = ruleset(&[a("192.168.21.68"), a("192.168.21.138")]);
        // the objects
        assert!(rs.contains(&format!("ct timeout {}", UDP_POLICY)), "{}", rs);
        assert!(rs.contains(UDP_POLICY_BODY), "{}", rs);
        assert!(rs.contains(&format!("ct timeout {}", TCP_POLICY)), "{}", rs);
        assert!(rs.contains(TCP_POLICY_BODY), "{}", rs);
        // the keyword this build accepts in an object, and not the one it
        // rejects there; `l4proto` is the selection matcher's, and the split
        // keeps the two apart
        let objects = rs.split(&format!("chain {CHAIN}")).next().unwrap();
        assert!(objects.contains("protocol udp"), "{}", objects);
        assert!(objects.contains("protocol tcp"), "{}", objects);
        assert!(!objects.contains("l4proto"), "object keyword: {}", objects);
        // the selection, as one inline list (the whole batch is regenerated
        // from the allowlist, so a set object would buy nothing)
        assert!(
            rs.contains("ip saddr { 192.168.21.68, 192.168.21.138 } meta l4proto udp ct timeout set"),
            "{}",
            rs
        );
        assert!(
            rs.contains("ip saddr { 192.168.21.68, 192.168.21.138 } meta l4proto tcp ct timeout set"),
            "{}",
            rs
        );
        // The hook is measured, not chosen: `ct timeout set` at a
        // pre-conntrack raw priority has no effect on this build (the entry
        // keeps the default 60 s), while the same statement at mangle
        // priority attaches the policy to the entry the conntrack hook has
        // just created. Both were read back from `/proc/net/nf_conntrack` on
        // the router, 2026-09-18.
        assert!(rs.contains("hook prerouting priority -150"), "{}", rs);
        assert!(!rs.contains("priority raw"), "the hook that does not work: {}", rs);
        // `ether saddr` is bridge-family; the key is the address
        assert!(!rs.contains("ether saddr"), "{}", rs);
    }

    #[test]
    fn ruleset_of_an_empty_allowlist_is_empty() {
        assert_eq!(ruleset(&[]), "", "nobody admitted means no policy at all");
    }

    #[test]
    fn ruleset_is_the_validated_table_block_form() {
        // The shape validated on the router (2026-09-17) is a table block
        // applied with `nft -f`, not a sequence of `nft add` calls: the
        // objects are declared inside the block, exactly as validated. The
        // batch adds; it never deletes anything of its own.
        let rs = ruleset(&[a("192.168.21.68")]);
        assert!(rs.starts_with(&format!("table {} {{\n", TABLE)), "{}", rs);
        assert!(rs.contains(&format!("\tchain {} {{\n", CHAIN)), "{}", rs);
        assert!(!rs.contains("delete"), "install never deletes: {}", rs);
        // the table block is re-entered, not declared fresh: the datapath
        // table (named map, CDC mirror) is already there and stays there
        assert!(!rs.contains("flush"), "install never flushes: {}", rs);
    }

    #[test]
    fn teardown_removes_the_chain_then_the_objects() {
        let t = teardown();
        let (chain_at, udp_at, tcp_at) = (
            t.find(&format!("delete chain ip dslp {}", CHAIN)).expect("chain delete"),
            t.find(&format!("delete ct timeout ip dslp {}", UDP_POLICY)).expect("udp delete"),
            t.find(&format!("delete ct timeout ip dslp {}", TCP_POLICY)).expect("tcp delete"),
        );
        assert!(chain_at < udp_at && chain_at < tcp_at, "selection goes first: {}", t);
    }

    #[test]
    fn present_reads_a_listing() {
        assert!(present(&format!("\tct timeout {} {{\n\t\tprotocol udp\n\t}}\n", UDP_POLICY)));
        assert!(!present("table ip dslp {\n\tmap snat_map {\n\t}\n}\n"));
        assert!(!present(""));
    }
}