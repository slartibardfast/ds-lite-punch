//! The allowlist admission (call/0025): which devices get the keepalive, and the local policy that holds them.

use std::net::Ipv4Addr;

/// The daemon's datapath table, shared by the `--static-map` pins, the CDC mirror and this policy.
pub const TABLE: &str = "ip dslp";
/// Policy-object names carry the project prefix, because nft object names are global to the shared table.
pub const UDP_POLICY: &str = "dslp_udp_long";
pub const TCP_POLICY: &str = "dslp_tcp_long";
/// The selection chain, at prerouting priority -150: a pre-conntrack priority has no effect on this build.
pub const CHAIN: &str = "hold";
/// UDP: five minutes in both directions, against the two-minute floor RFC 4787 sets.
pub const UDP_POLICY_BODY: &str = "policy = { unreplied : 5m, replied : 5m }";
/// TCP: the established figure RFC 5382 sets, two hours four minutes.
pub const TCP_POLICY_BODY: &str = "policy = { established : 2h4m }";

/// Parse an allowlist file: one IPv4 address per line, `#` starts a comment, and an unreadable entry is reported.
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

/// Whether `ip` is admitted for the keepalive: pure membership, since an entry carries no role.
pub fn allowed(list: &[Ipv4Addr], ip: Ipv4Addr) -> bool {
    list.contains(&ip)
}

/// The nft batch that installs the policy for `list`; an empty list installs nothing.
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

/// The nft batch that removes the policy: the chain first, then the two policy objects.
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

/// Whether the listing already carries the policy; a re-added `ct timeout` object is an error under `nft -f`.
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
        // The object carries `protocol`; `meta l4proto` is the selection matcher's keyword.
        let objects = rs.split(&format!("chain {CHAIN}")).next().unwrap();
        assert!(objects.contains("protocol udp"), "{}", objects);
        assert!(objects.contains("protocol tcp"), "{}", objects);
        assert!(!objects.contains("l4proto"), "object keyword: {}", objects);
        // The selection is one inline list, since the whole batch is regenerated from the allowlist.
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
        // The hook is measured: at a pre-conntrack priority the entry keeps the default 60 s on this build.
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
        // The shape validated on the router is one table block applied with `nft -f`.
        let rs = ruleset(&[a("192.168.21.68")]);
        assert!(rs.starts_with(&format!("table {} {{\n", TABLE)), "{}", rs);
        assert!(rs.contains(&format!("\tchain {} {{\n", CHAIN)), "{}", rs);
        assert!(!rs.contains("delete"), "install never deletes: {}", rs);
        // The table block is re-entered, since the named map and the CDC mirror are already there.
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