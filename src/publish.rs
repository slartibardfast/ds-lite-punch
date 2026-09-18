//! Tuple publication: write the current external tuple to a state file and
//! emit a JSON line (journald) on every change. Downstream (DDNS, dashboards)
//! consumes the file; the daemon never blocks on consumers. When a watch
//! sender is attached (UPnP facade mode), every published tuple also feeds
//! the facade's external-IP state (E3 GetExternalIPAddress + E5 GENA
//! events) — fire-and-forget: the facade runs with the latest value.
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;
use std::net::Ipv4Addr;

use tokio::sync::watch;

/// Take a lock without letting a poisoned one take the process down. The
/// daemon sets `panic = "abort"`, so a panic anywhere is fatal, and a
/// `StdMutex` that a panicking thread held stays poisoned: `.unwrap()` would
/// then abort the daemon on the next request. A failed write must never do
/// that (call/0029), and neither must the lock around the state it writes.
pub fn lock_or_recover<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Print a line without letting a failed write take the process down.
/// `println!` panics when stdout is a broken pipe, and this daemon's stdout is
/// a procd pipe; with `panic = "abort"` set that panic is fatal. Every line
/// this daemon emits goes through here (call/0029).
macro_rules! emitln {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

/// As `emitln`, for stderr.
macro_rules! emiteln {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}

pub(crate) use {emiteln, emitln};

pub struct Publisher {
    dir: String,
    ip_watch: Option<watch::Sender<Ipv4Addr>>,
    /// The learned tuples, held in memory. The file is the record, but a
    /// state directory that cannot be written (a full tmpfs, a read-only
    /// mount) must not cost the daemon its knowledge of its own mappings:
    /// PCP answers a slot from here, and the file is only how a *restored*
    /// slot's tuple is read back after a restart.
    slots: StdMutex<HashMap<u16, (Ipv4Addr, u16)>>,
    /// Whether the state directory last refused a write, so the report is a
    /// transition rather than a line per packet.
    dir_failed: AtomicBool,
}

impl Publisher {
    /// Attach the facade's external-IP watch (UPnP facade mode).
    pub fn with_watch(dir: &str, ip_watch: watch::Sender<Ipv4Addr>) -> Self {
        let _ = fs::create_dir_all(dir);
        Publisher {
            dir: dir.to_string(),
            ip_watch: Some(ip_watch),
            slots: StdMutex::new(HashMap::new()),
            dir_failed: AtomicBool::new(false),
        }
    }

    pub fn publish(&self, ip: Ipv4Addr, port: u16) {
        let path = format!("{}/tuple", self.dir);
        let _ = fs::write(&path, format!("{}:{}\n", ip, port));
        emitln!("{{\"event\":\"tuple\",\"ip\":\"{}\",\"port\":{}}}", ip, port);
    }

    /// Per-slot tuple file (B6/B8): `tuple-<R>` alongside the aggregate
    /// `tuple` file (last writer). Respawn restore reads `tuple-<R>` per
    /// slot; existing consumers keep reading `tuple` unchanged. The facade
    /// watch mirrors the same value for the SOAP/GENA layers.
    pub fn publish_slot(&self, bind_port: u16, ip: Ipv4Addr, port: u16) {
        let path = format!("{}/tuple-{}", self.dir, bind_port);
        // memory first: the answer a client gets must not depend on the
        // state directory accepting a write
        lock_or_recover(&self.slots).insert(bind_port, (ip, port));
        let w = fs::write(&path, format!("{}:{}\n", ip, port));
        self.note_write(&format!("tuple-{}", bind_port), w);
        emitln!(
            "{{\"event\":\"tuple\",\"slot\":{},\"ip\":\"{}\",\"port\":{}}}",
            bind_port, ip, port
        );
        self.publish(ip, port);
        if let Some(tx) = &self.ip_watch {
            let _ = tx.send(ip);
        }
    }

    /// The tuple a slot's discovery learned: memory first, because that is
    /// the live answer, then the file, which is how a restored slot's tuple
    /// comes back after a restart.
    pub fn slot_tuple(&self, bind_port: u16) -> Option<(Ipv4Addr, u16)> {
        if let Some(t) = lock_or_recover(&self.slots).get(&bind_port) {
            return Some(*t);
        }
        let s = fs::read_to_string(format!("{}/tuple-{}", self.dir, bind_port)).ok()?;
        let (ip, port) = s.trim().split_once(':')?;
        Some((ip.parse().ok()?, port.parse().ok()?))
    }

    /// Report a write into the state directory as a transition: the first
    /// failure says so, and the first success after it says so too. The
    /// tables and the tuples live in memory either way, so what this reports
    /// is that the record on disk has stopped keeping up.
    pub fn note_write(&self, what: &str, r: std::io::Result<()>) {
        match r {
            Ok(()) => {
                if self.dir_failed.swap(false, Ordering::Relaxed) {
                    self.log_transition("state-write-recovered", what);
                }
            }
            Err(e) => {
                if !self.dir_failed.swap(true, Ordering::Relaxed) {
                    self.log_transition(
                        "state-write-failed",
                        &format!("{}: {} (state is held in memory)", what, e),
                    );
                }
            }
        }
    }

    /// A mapping's tuple file goes when the mapping does. The file is the
    /// *learned* tuple, so one that outlives its mapping is a lie a client can
    /// act on: a later mapping that lands on the same bind port would be
    /// answered with the dead port. The box found this on 2026-09-17, with
    /// three revoked slots still carrying their old tuples.
    pub fn remove_slot(&self, bind_port: u16) {
        lock_or_recover(&self.slots).remove(&bind_port);
        let _ = fs::remove_file(format!("{}/tuple-{}", self.dir, bind_port));
    }

    pub fn log_transition(&self, event: &str, detail: &str) {
        emitln!("{{\"event\":\"{}\",\"detail\":\"{}\"}}", event, detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The fallback the daemon needs when its state directory will not take a
    /// write: the tuple a client is answered with comes from memory.
    #[test]
    fn a_learned_tuple_is_served_when_the_file_cannot_be_written() {
        // A regular file where the directory would be: create_dir_all cannot
        // make it and every write fails with ENOTDIR, which is the shape a
        // full tmpfs presents to the daemon.
        let blocker = std::env::temp_dir().join(format!("dslp-blocker-{}", std::process::id()));
        let _ = fs::remove_file(&blocker);
        fs::write(&blocker, "not a directory\n").unwrap();
        let dir = format!("{}/state", blocker.to_str().unwrap());
        let (_tx, rx) = watch::channel(Ipv4Addr::LOCALHOST);
        let p = Publisher::with_watch(&dir, _tx);
        assert!(fs::write(format!("{}/probe", dir), "x").is_err(), "the dir is unwritable for the test");
        let _ = rx;
        p.publish_slot(30000, "203.0.113.9".parse().unwrap(), 40001);
        assert_eq!(
            p.slot_tuple(30000),
            Some(("203.0.113.9".parse().unwrap(), 40001)),
            "memory answers even though the record could not be written"
        );
        // and a mapping that never published is simply unknown
        assert_eq!(p.slot_tuple(30001), None);
    }

    /// A poisoned lock must not take the daemon down. `panic = "abort"` makes
    /// any panic fatal, and a `StdMutex` a panicking thread held stays
    /// poisoned, so `.unwrap()` on it would abort the daemon on the next
    /// request — a failed write bringing the service down by construction is
    /// what this rules out (call/0029).
    #[test]
    fn a_poisoned_lock_is_recovered_not_fatal() {
        let m = Arc::new(StdMutex::new(7u32));
        let m2 = Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("a thread dies holding the lock");
        })
        .join();
        assert!(m.is_poisoned(), "the lock is poisoned for the test to mean anything");
        assert_eq!(*lock_or_recover(&m), 7, "the value survives and the lock is taken");
    }

    /// A restored slot's tuple is the one case the file is the source, since
    /// memory starts empty after a restart.
    #[test]
    fn a_restored_slots_tuple_is_read_from_the_file() {
        let dir = std::env::temp_dir().join(format!("dslp-pubfile-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("tuple-30000"), "203.0.113.9:40001\n").unwrap();
        let (tx, _rx) = watch::channel(Ipv4Addr::LOCALHOST);
        let p = Publisher::with_watch(dir.to_str().unwrap(), tx);
        assert_eq!(
            p.slot_tuple(30000),
            Some(("203.0.113.9".parse().unwrap(), 40001))
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
