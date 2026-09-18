//! Is a device on the LAN? One rule, used by everything that holds a mapping
//! for a device: the arm's holds and the facade's leases both need it.
//!
//! The neighbour table is the instrument, not an echo. Measured on the router:
//! a console that drops ICMP still answers ARP, and a device that is off
//! leaves FAILED or INCOMPLETE behind. An ICMP echo is only a trigger, to make
//! the kernel settle an entry we cannot read, and never the answer.
//!
//! A probe that cannot run answers "up": a broken instrument must never
//! release a live mapping.

use std::net::Ipv4Addr;
use std::process::Command;

/// Consecutive misses before a caller treats the device as gone. Two is the
/// default: one miss can be a Wi-Fi blip or a sleeping radio, two in a row is
/// a device that is not answering on the LAN.
pub const MISSES_TO_ABSENT: u8 = 2;

pub fn device_up(ip: Ipv4Addr) -> bool {
    let s = ip.to_string();
    let first = neigh_state(&s).unwrap_or_default();
    if first.trim().is_empty() {
        let _ = Command::new("ping")
            .args(["-c", "1", "-W", "1", &s])
            .output();
        let second = neigh_state(&s).unwrap_or_default();
        if second.trim().is_empty() {
            return true;
        }
        return neigh_answers(&second);
    }
    neigh_answers(&first)
}

/// `ip neigh show <ip>`, as text. None means the probe itself could not run.
fn neigh_state(ip: &str) -> Option<String> {
    Command::new("ip")
        .args(["neigh", "show", ip])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Whether a neighbour listing says the device answered on the LAN. A listing
/// with a link-layer address means it did, whatever the state; FAILED or
/// INCOMPLETE means a probe went unanswered; anything else counts as present,
/// so a failure of this instrument never releases a live mapping.
pub fn neigh_answers(listing: &str) -> bool {
    let l = listing.trim();
    if l.is_empty() {
        return true;
    }
    if l.contains("FAILED") || l.contains("INCOMPLETE") {
        return false;
    }
    true
}

/// The release rule for a mapping that belongs to a client: a requested
/// mapping ends when its client is no longer on the LAN, and never for the
/// client being quiet — a lobby, a paused game and a sleeping screen all look
/// like quiet, and the mapping is exactly what must survive them. A static
/// mapping is the operator's configuration and is never released here.
///
/// Pure, so the policy is testable without a network.
pub fn release_absent(is_static: bool, misses: u8) -> bool {
    !is_static && misses >= MISSES_TO_ABSENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_neighbour_table_is_the_presence_signal() {
        // Measured shapes from the router: the Switch present with a MAC and
        // dropping ICMP, the PS3 absent and answering no ARP at all.
        assert!(neigh_answers("192.168.21.68 dev br-lan lladdr 80:d2:e5:6d:d1:00 DELAY"));
        assert!(neigh_answers("192.168.21.68 dev br-lan lladdr 80:d2:e5:6d:d1:00 STALE"));
        assert!(!neigh_answers("192.168.21.138 dev br-lan FAILED"));
        assert!(!neigh_answers("192.168.21.138 dev br-lan INCOMPLETE"));
        // a failure of the instrument is not evidence the device is gone
        assert!(neigh_answers(""));
        assert!(neigh_answers("something we do not understand"));
    }

    #[test]
    fn a_client_mapping_ends_when_its_client_is_gone_and_never_when_it_is_quiet() {
        // Quiet is not a reason: it is the state a mapping exists to survive.
        assert!(!release_absent(false, 0), "a present client keeps its mapping");
        assert!(!release_absent(false, 1), "one miss is a blip");
        assert!(release_absent(false, 2), "two in a row is a device that is gone");
        // the operator's configuration is never released by presence
        assert!(!release_absent(true, 9), "a static mapping is the operator's");
    }
}