//! Tuple publication: write the current external tuple to a state file and
//! emit a JSON line (journald) on every change. Downstream (DDNS, dashboards)
//! consumes the file; the daemon never blocks on consumers.
use std::fs;
use std::net::Ipv4Addr;

pub struct Publisher {
    dir: String,
}

impl Publisher {
    pub fn new(dir: &str) -> Self {
        let _ = fs::create_dir_all(dir);
        Publisher { dir: dir.to_string() }
    }

    pub fn publish(&self, ip: Ipv4Addr, port: u16) {
        let path = format!("{}/tuple", self.dir);
        let _ = fs::write(&path, format!("{}:{}\n", ip, port));
        println!("{{\"event\":\"tuple\",\"ip\":\"{}\",\"port\":{}}}", ip, port);
    }

    /// Per-slot tuple file (B6/B8): `tuple-<R>` alongside the aggregate
    /// `tuple` file (last writer). Respawn restore reads `tuple-<R>` per
    /// slot; existing consumers keep reading `tuple` unchanged.
    pub fn publish_slot(&self, bind_port: u16, ip: Ipv4Addr, port: u16) {
        let path = format!("{}/tuple-{}", self.dir, bind_port);
        let _ = fs::write(&path, format!("{}:{}\n", ip, port));
        println!(
            "{{\"event\":\"tuple\",\"slot\":{},\"ip\":\"{}\",\"port\":{}}}",
            bind_port, ip, port
        );
        self.publish(ip, port);
    }

    pub fn log_transition(&self, event: &str, detail: &str) {
        println!("{{\"event\":\"{}\",\"detail\":\"{}\"}}", event, detail);
    }
}
