//! Publish the learned external tuple to a state file, to a JSON line, and to the facade's watch when one is attached.
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;
use std::net::Ipv4Addr;

use tokio::sync::watch;

/// Take a lock that may be poisoned, which `panic = "abort"` would otherwise turn into an abort on the next request.
pub fn lock_or_recover<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Print a line with a write that may fail: `println!` panics on a broken pipe, and `panic = "abort"` makes that fatal.
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
    /// The learned tuples in memory, so a state directory that refuses a write costs no knowledge.
    slots: StdMutex<HashMap<u16, (Ipv4Addr, u16)>>,
    /// Whether the state directory last refused a write, so the report is a transition.
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

    /// Write `tuple-<R>` beside the aggregate `tuple` file, and mirror the value to the facade's watch.
    pub fn publish_slot(&self, bind_port: u16, ip: Ipv4Addr, port: u16) {
        let path = format!("{}/tuple-{}", self.dir, bind_port);
        // The answer a client gets must not depend on the state directory accepting a write.
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

    /// The tuple a slot's discovery learned: memory first, then the file a restart restores it from.
    pub fn slot_tuple(&self, bind_port: u16) -> Option<(Ipv4Addr, u16)> {
        if let Some(t) = lock_or_recover(&self.slots).get(&bind_port) {
            return Some(*t);
        }
        let s = fs::read_to_string(format!("{}/tuple-{}", self.dir, bind_port)).ok()?;
        let (ip, port) = s.trim().split_once(':')?;
        Some((ip.parse().ok()?, port.parse().ok()?))
    }

    /// Report a write into the state directory as a transition, since the tables are in memory either way.
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

    /// Remove a mapping's tuple file with it: a file that outlives its mapping answers a later mapping with a dead port.
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

    /// The tuple a client is answered with comes from memory when the directory refuses a write.
    #[test]
    fn a_learned_tuple_is_served_when_the_file_cannot_be_written() {
        // A regular file where the directory would be: every write fails with ENOTDIR, as a full tmpfs does.
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

    /// A poisoned lock must not take the daemon down: `panic = "abort"` would make `.unwrap()` fatal.
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

    /// A restored slot's tuple is the one case the file is the source, since memory starts empty.
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
