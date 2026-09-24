//! Is a device on the LAN? One rule, used by the arm's holds and the facade's leases alike.

use std::net::Ipv4Addr;
use std::process::Command;

/// Consecutive misses before a caller treats the device as gone: two, because one miss can be a Wi-Fi blip.
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

/// Whether a listing says the device answered: `FAILED` or `INCOMPLETE` means no, anything else present.
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

/// Whether to release a client's mapping: a device past the miss threshold, and never a static or a quiet one.
pub fn release_absent(is_static: bool, misses: u8) -> bool {
    !is_static && misses >= MISSES_TO_ABSENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_neighbour_table_is_the_presence_signal() {
        // Measured shapes: a console that drops ICMP still answers ARP, and a device that is off leaves FAILED.
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