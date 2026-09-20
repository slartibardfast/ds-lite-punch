//! The watcher for the carrier's filtering (call/0033).
//!
//! The daemon cannot send from a foreign address, so a cooperating helper on
//! the external vantage sends a marked datagram to the mapping's learned
//! external tuple. The datapath counts that mark in a named `nft` counter, and
//! this module turns the counter's readings into the two events the decision
//! names: `carrier-probe` when a probe arrived, and `carrier-silent` when
//! three intervals pass with none.
//!
//! The state machine is pure. The caller supplies the epoch and the counter's
//! reading, which keeps the detection arithmetic testable away from the box.

/// The mark the helper puts in the first eight bytes of the datagram's
/// payload. The datapath matches it with `@th,64,64`, and the length is the
/// contract: a shorter or longer mark is a different rule.
pub const MARK: &[u8; 8] = b"dslp-prb";

/// The mark as the 64-bit word the `nft` rule compares against.
pub const MARK_WORD: u64 = u64::from_be_bytes(*MARK);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A probe arrived since the last poll.
    Probe { count: u64 },
    /// No probe was seen for `misses` intervals. `last_seen` is `None` when
    /// the watch has never seen one.
    Silent {
        last_seen: Option<u64>,
        waited: u64,
    },
}

pub struct Watch {
    /// The counter as last read.
    count: u64,
    /// The epoch of the last probe seen, if any.
    last_seen: Option<u64>,
    /// The epoch the watch started, used while no probe has been seen.
    started: u64,
    /// Set while a silence has been reported, cleared by a probe.
    alarmed: bool,
    /// The first poll adopts the counter without calling it an arrival.
    primed: bool,
}

impl Watch {
    pub fn new(now: u64) -> Self {
        Watch {
            count: 0,
            last_seen: None,
            started: now,
            alarmed: false,
            primed: false,
        }
    }

    /// One poll. `count` is the named counter's current reading.
    pub fn poll(&mut self, now: u64, count: u64, interval: u64, misses: u64) -> Vec<Event> {
        if !self.primed {
            self.primed = true;
            self.count = count;
            return Vec::new();
        }
        if count > self.count {
            self.count = count;
            self.last_seen = Some(now);
            self.alarmed = false;
            return vec![Event::Probe { count }];
        }
        let since = self.last_seen.unwrap_or(self.started);
        let waited = now.saturating_sub(since);
        if !self.alarmed && waited >= interval.saturating_mul(misses) {
            self.alarmed = true;
            return vec![Event::Silent {
                last_seen: self.last_seen,
                waited,
            }];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL: u64 = 900;
    const MISSES: u64 = 3;

    #[test]
    fn the_mark_is_eight_bytes_at_the_payload_start() {
        assert_eq!(MARK.len(), 8);
        assert_eq!(MARK_WORD, 0x64736c702d707262);
    }

    #[test]
    fn the_first_poll_primes_the_counter_without_calling_it_an_arrival() {
        let mut w = Watch::new(1000);
        // a counter left over from an earlier run reads as the baseline
        assert!(w.poll(1000, 7, INTERVAL, MISSES).is_empty());
    }

    #[test]
    fn a_rising_counter_is_a_probe() {
        let mut w = Watch::new(0);
        w.poll(0, 0, INTERVAL, MISSES);
        assert_eq!(w.poll(10, 1, INTERVAL, MISSES), vec![Event::Probe { count: 1 }]);
        // the same reading twice is not a second arrival
        assert!(w.poll(20, 1, INTERVAL, MISSES).is_empty());
    }

    #[test]
    fn a_silence_alarms_once_and_a_resumed_probe_clears_it() {
        let mut w = Watch::new(0);
        w.poll(0, 0, INTERVAL, MISSES);
        assert_eq!(w.poll(5, 1, INTERVAL, MISSES), vec![Event::Probe { count: 1 }]);
        // inside the window: nothing
        assert!(w.poll(900, 1, INTERVAL, MISSES).is_empty());
        assert!(w.poll(2699, 1, INTERVAL, MISSES).is_empty());
        // at three intervals since the last probe: the alarm, once
        assert_eq!(
            w.poll(2705, 1, INTERVAL, MISSES),
            vec![Event::Silent { last_seen: Some(5), waited: 2700 }]
        );
        assert!(w.poll(3600, 1, INTERVAL, MISSES).is_empty(), "the alarm is not repeated");
        // a probe resumes the watch and clears the alarm
        assert_eq!(w.poll(3605, 2, INTERVAL, MISSES), vec![Event::Probe { count: 2 }]);
        // and the next silence alarms again
        assert_eq!(
            w.poll(6305, 2, INTERVAL, MISSES),
            vec![Event::Silent { last_seen: Some(3605), waited: 2700 }]
        );
    }

    #[test]
    fn a_watch_that_never_saw_a_probe_alarms_from_its_own_start() {
        let mut w = Watch::new(1000);
        w.poll(1000, 0, INTERVAL, MISSES);
        assert!(w.poll(3000, 0, INTERVAL, MISSES).is_empty());
        assert_eq!(
            w.poll(3700, 0, INTERVAL, MISSES),
            vec![Event::Silent { last_seen: None, waited: 2700 }]
        );
    }

    #[test]
    fn a_short_interval_watches_faster() {
        // the shape the alarm proof runs with
        let mut w = Watch::new(0);
        w.poll(0, 0, 20, 3);
        assert_eq!(w.poll(5, 1, 20, 3), vec![Event::Probe { count: 1 }]);
        assert!(w.poll(60, 1, 20, 3).is_empty());
        assert_eq!(
            w.poll(65, 1, 20, 3),
            vec![Event::Silent { last_seen: Some(5), waited: 60 }]
        );
    }
}