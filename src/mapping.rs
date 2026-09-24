//! Shared runtime state and the tuple health machine: healthy, churn, and blind after silent keepalives.
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Instant;

pub struct State {
    pub servers: Vec<SocketAddrV4>,
    pub server_idx: usize,
    pub tuple: Option<(Ipv4Addr, u16)>,
    pub last_response: Option<Instant>,
    pub silent_ticks: u32,
    /// rotate STUN server after this many consecutive silent keepalives
    pub rotate_after: u32,
}

impl State {
    pub fn new(servers: Vec<SocketAddrV4>) -> Self {
        State {
            servers,
            server_idx: 0,
            tuple: None,
            last_response: None,
            silent_ticks: 0,
            rotate_after: 3,
        }
    }

    pub fn current_server(&self) -> SocketAddrV4 {
        self.servers[self.server_idx]
    }

    pub fn is_stun_server(&self, a: SocketAddrV4) -> bool {
        self.servers.contains(&a)
    }

    /// Count a keepalive with no response. Returns true if we rotated servers.
    pub fn note_silence(&mut self) -> bool {
        self.silent_ticks += 1;
        if self.silent_ticks >= self.rotate_after && self.servers.len() > 1 {
            self.server_idx = (self.server_idx + 1) % self.servers.len();
            self.silent_ticks = 0;
            true
        } else {
            false
        }
    }

    /// Record a STUN-observed tuple. Returns true if the tuple changed (churn).
    pub fn note_response(&mut self, t: (Ipv4Addr, u16)) -> bool {
        self.silent_ticks = 0;
        self.last_response = Some(Instant::now());
        let changed = self.tuple != Some(t);
        self.tuple = Some(t);
        changed
    }

    /// Index of a resolved STUN server address, so the vote can attribute an observation to it.
    pub fn server_index(&self, a: SocketAddrV4) -> Option<usize> {
        self.servers.iter().position(|&s| s == a)
    }

    /// Rotate at once on a disagreeing observation; a single server has nowhere to rotate to.
    pub fn mark_suspect(&mut self) -> bool {
        if self.servers.len() > 1 {
            self.server_idx = (self.server_idx + 1) % self.servers.len();
            self.silent_ticks = 0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_server() -> State {
        State::new(vec![SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 3478)])
    }

    #[test]
    fn first_response_is_churn_then_stable() {
        let mut st = one_server();
        assert!(st.note_response((Ipv4Addr::new(203, 0, 113, 9), 5000)));
        assert!(!st.note_response((Ipv4Addr::new(203, 0, 113, 9), 5000)));
        assert!(st.note_response((Ipv4Addr::new(203, 0, 113, 9), 5001)));
    }

    #[test]
    fn response_resets_silence() {
        let mut st = one_server();
        st.note_silence();
        st.note_silence();
        assert_eq!(st.silent_ticks, 2);
        st.note_response((Ipv4Addr::new(203, 0, 113, 9), 5000));
        assert_eq!(st.silent_ticks, 0);
    }

    #[test]
    fn suspect_rotates_immediately() {
        let mut st = State::new(vec![
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 3478),
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 3478),
        ]);
        let first = st.current_server();
        assert!(st.mark_suspect());
        assert_ne!(st.current_server(), first);
        assert_eq!(st.silent_ticks, 0);
    }

    #[test]
    fn single_server_never_suspect_rotates() {
        let mut st = one_server();
        assert!(!st.mark_suspect());
        assert_eq!(st.silent_ticks, 0);
    }
}

/// Kani proofs for the pure parts of the state machine, which carry no `Instant` for Kani to model.
#[cfg(kani)]
mod verify {
    use super::*;

    fn two_servers() -> State {
        State::new(vec![
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 3478),
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 3478),
        ])
    }

    #[kani::proof]
    #[kani::unwind(10)] // loop runs at most threshold-1 <= 7 times
    fn silence_rotates_after_threshold() {
        let mut st = two_servers();
        // rotate_after is a small symbolic threshold (>=1 so progress is real).
        let threshold: u32 = kani::any();
        kani::assume((1..=8).contains(&threshold));
        st.rotate_after = threshold;

        let first = st.current_server();
        // Fewer silences than the threshold: no rotation.
        for _ in 0..threshold.saturating_sub(1) {
            assert!(!st.note_silence());
        }
        assert_eq!(st.current_server(), first);
        // The threshold-th consecutive silence rotates.
        assert!(st.note_silence());
        assert_ne!(st.current_server(), first);
        assert_eq!(st.silent_ticks, 0);
    }

    #[kani::proof]
    #[kani::unwind(20)] // loop runs at most n <= 16 times
    fn single_server_never_rotates() {
        let mut st = State::new(vec![SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 3478)]);
        let threshold: u32 = kani::any();
        kani::assume((1..=8).contains(&threshold));
        st.rotate_after = threshold;
        let only = st.current_server();
        // A single server has nowhere to rotate to, so no threshold ever produces a rotation.
        let n: u32 = kani::any();
        kani::assume(n <= 16);
        for _ in 0..n {
            assert!(!st.note_silence());
        }
        assert_eq!(st.current_server(), only);
    }

    #[kani::proof]
    #[kani::unwind(6)] // len is concretely 2 here
    fn suspect_rotates_within_bounds() {
        // mark_suspect moves at most one step, stays in range and resets silence.
        let mut st = two_servers();
        assert!(st.mark_suspect());
        let servers = st.servers.len();
        assert!(st.server_idx < servers, "server_idx stays in range");
        assert_eq!(st.silent_ticks, 0);
        let mut s1 = State::new(vec![SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 3478)]);
        assert!(!s1.mark_suspect());
        assert_eq!(s1.server_idx, 0);
        assert_eq!(s1.silent_ticks, 0);
    }
}
