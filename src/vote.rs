//! STUN majority vote: the confirmed tuple is canonical, and it moves only to a value two servers agree on.
#![allow(dead_code)]
use std::net::Ipv4Addr;

/// Max STUN servers the vote tracks; must be >= 2 for the vote to work.
pub const MAX_VOTE_SERVERS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VoteDecision {
    /// Response matched confirmed, or confirmed was already this value: no state change and no publication.
    Stable,
    /// One server reported a value differing from confirmed: mark it suspect and do not republish.
    Disagree(usize),
    /// confirmed moved to a new tuple, or this is the first observation ever: republish.
    Churn((Ipv4Addr, u16)),
}

/// Per-server latest observation, sentinel-slotted (None = not weighed in): no collision bookkeeping.
#[derive(Clone, Debug)]
pub struct VoteState {
    confirmed: Option<(Ipv4Addr, u16)>,
    pend: [Option<(Ipv4Addr, u16)>; MAX_VOTE_SERVERS],
}

impl VoteState {
    pub fn new() -> Self {
        VoteState {
            confirmed: None,
            pend: [None; MAX_VOTE_SERVERS],
        }
    }

    pub fn confirmed(&self) -> Option<(Ipv4Addr, u16)> {
        self.confirmed
    }

    fn clear_pend(&mut self) {
        self.pend = [None; MAX_VOTE_SERVERS];
    }

    /// Record server observing t and return the decision; server must index within MAX_VOTE_SERVERS.
    pub fn observe(&mut self, server: usize, t: (Ipv4Addr, u16)) -> VoteDecision {
        if self.confirmed == Some(t) {
            // Re-seeing the confirmed value heals any transient suspicion.
            self.clear_pend();
            return VoteDecision::Stable;
        }
        if server < MAX_VOTE_SERVERS {
            self.pend[server] = Some(t);
        }
        // Count agreement on `t` across all slots.
        let mut agreeing = 0;
        for slot in self.pend.iter() {
            if *slot == Some(t) {
                agreeing += 1;
            }
        }
        if agreeing >= 2 {
            self.confirmed = Some(t);
            self.clear_pend();
            return VoteDecision::Churn(t);
        }
        // not yet agreed, and this is the very first observation ever, so confirm on one server's word
        if self.confirmed.is_none() {
            self.confirmed = Some(t);
            self.clear_pend();
            return VoteDecision::Churn(t);
        }
        // One disagreement: suspect server, hold `confirmed`.
        VoteDecision::Disagree(server)
    }
}

impl Default for VoteState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const B: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);

    #[test]
    fn first_observation_confirms() {
        let mut v = VoteState::new();
        assert_eq!(v.observe(0, (A, 40000)), VoteDecision::Churn((A, 40000)));
        assert_eq!(v.confirmed(), Some((A, 40000)));
    }

    #[test]
    fn reseeing_confirmed_is_stable() {
        let mut v = VoteState::new();
        v.observe(0, (A, 40000));
        assert_eq!(v.observe(0, (A, 40000)), VoteDecision::Stable);
        assert_eq!(v.confirmed(), Some((A, 40000)));
    }

    #[test]
    fn single_disagreement_holds_confirmed() {
        let mut v = VoteState::new();
        v.observe(0, (A, 40000));
        let d = v.observe(1, (B, 50000));
        assert!(matches!(d, VoteDecision::Disagree(1)));
        assert_eq!(v.confirmed(), Some((A, 40000)), "confirmed must not move on one server");
    }

    #[test]
    fn two_agreeing_servers_churn() {
        let mut v = VoteState::new();
        v.observe(0, (A, 40000));
        assert!(matches!(v.observe(1, (B, 50000)), VoteDecision::Disagree(_)));
        assert_eq!(v.observe(0, (B, 50000)), VoteDecision::Churn((B, 50000)));
        assert_eq!(v.confirmed(), Some((B, 50000)));
    }

    #[test]
    fn transient_disagreement_heals() {
        let mut v = VoteState::new();
        v.observe(0, (A, 40000));
        v.observe(1, (B, 50000)); // disagree
        assert_eq!(v.observe(1, (A, 40000)), VoteDecision::Stable, "re-agree with confirmed clears suspicion");
        assert_eq!(v.confirmed(), Some((A, 40000)));
        // after a heal the old disagreeing server still participates, and must re-report the new value
        assert!(matches!(v.observe(1, (B, 50000)), VoteDecision::Disagree(_)));
    }
}

#[cfg(kani)]
mod verify {
    use super::*;

    fn addr_u8() -> (Ipv4Addr, u16) {
        let o: [u8; 4] = kani::any();
        let p: u16 = kani::any();
        (Ipv4Addr::from(o), p)
    }

    #[kani::proof]
    fn first_observation_always_confirms() {
        let mut v = VoteState::new();
        let t = addr_u8();
        match v.observe(0, t) {
            VoteDecision::Churn(c) => assert_eq!(c, t),
            _ => panic!("first observation must confirm"),
        }
        assert_eq!(v.confirmed(), Some(t));
    }

    #[kani::proof]
    fn reseeing_confirmed_never_churns() {
        let mut v = VoteState::new();
        let t = addr_u8();
        v.observe(0, t);
        assert!(!matches!(v.observe(1, t), VoteDecision::Churn(_)));
        assert_eq!(v.confirmed(), Some(t), "confirmed unchanged");
    }

    #[kani::proof]
    fn single_disagreement_never_churns() {
        let mut v = VoteState::new();
        let t = addr_u8();
        let u = addr_u8();
        kani::assume(t != u);
        v.observe(0, t);
        // only one server has reported, so a differing observation from a single slot must not churn
        assert!(!matches!(v.observe(1, u), VoteDecision::Churn(_)));
        assert_eq!(v.confirmed(), Some(t));
    }

    #[kani::proof]
    fn two_servers_agree_always_churn() {
        let mut v = VoteState::new();
        let old = addr_u8();
        let new = addr_u8();
        kani::assume(old != new);
        v.observe(0, old);
        // server 1 disagrees, server 0 flips -> two agreeing on `new`
        v.observe(1, new);
        let d = v.observe(0, new);
        assert_eq!(d, VoteDecision::Churn(new));
        assert_eq!(v.confirmed(), Some(new));
    }

    #[kani::proof]
    fn confirmed_only_moves_to_observed_value() {
        let mut v = VoteState::new();
        let t = addr_u8();
        let u = addr_u8();
        kani::assume(t != u);
        v.observe(0, t);
        v.observe(1, u); // disagree
        let c = v.confirmed().unwrap();
        assert!(c == t, "after a single disagreement confirmed must stay at the original value");
        // and with a second agreement the move target is exactly the agreed value
        let d = v.observe(0, u);
        match d {
            VoteDecision::Churn(c) => assert_eq!(c, u),
            _ => panic!("two observers on u must churn to u"),
        }
    }
}