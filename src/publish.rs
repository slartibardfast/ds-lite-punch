//! Tuple publication: write the current external tuple to a state file and
//! emit a JSON line (journald) on every change. Downstream (DDNS, dashboards)
//! consumes the file; the daemon never blocks on consumers. When a watch
//! sender is attached (UPnP facade mode), every published tuple also feeds
//! the facade's external-IP state (E3 GetExternalIPAddress + E5 GENA
//! events) — fire-and-forget: the facade runs with the latest value.
use std::fs;
use std::net::Ipv4Addr;

use tokio::sync::watch;

pub struct Publisher {
    dir: String,
    ip_watch: Option<watch::Sender<Ipv4Addr>>,
}

impl Publisher {
    /// Attach the facade's external-IP watch (UPnP facade mode).
    pub fn with_watch(dir: &str, ip_watch: watch::Sender<Ipv4Addr>) -> Self {
        let _ = fs::create_dir_all(dir);
        Publisher {
            dir: dir.to_string(),
            ip_watch: Some(ip_watch),
        }
    }

    pub fn publish(&self, ip: Ipv4Addr, port: u16) {
        let path = format!("{}/tuple", self.dir);
        let _ = fs::write(&path, format!("{}:{}\n", ip, port));
        println!("{{\"event\":\"tuple\",\"ip\":\"{}\",\"port\":{}}}", ip, port);
    }

    /// Per-slot tuple file (B6/B8): `tuple-<R>` alongside the aggregate
    /// `tuple` file (last writer). Respawn restore reads `tuple-<R>` per
    /// slot; existing consumers keep reading `tuple` unchanged. The facade
    /// watch mirrors the same value for the SOAP/GENA layers.
    pub fn publish_slot(&self, bind_port: u16, ip: Ipv4Addr, port: u16) {
        let path = format!("{}/tuple-{}", self.dir, bind_port);
        let _ = fs::write(&path, format!("{}:{}\n", ip, port));
        println!(
            "{{\"event\":\"tuple\",\"slot\":{},\"ip\":\"{}\",\"port\":{}}}",
            bind_port, ip, port
        );
        self.publish(ip, port);
        if let Some(tx) = &self.ip_watch {
            let _ = tx.send(ip);
        }
    }

    /// A mapping's tuple file goes when the mapping does. The file is the
    /// *learned* tuple, so one that outlives its mapping is a lie a client can
    /// act on: a later mapping that lands on the same bind port would be
    /// answered with the dead port. The box found this on 2026-09-17, with
    /// three revoked slots still carrying their old tuples.
    pub fn remove_slot(&self, bind_port: u16) {
        let _ = fs::remove_file(format!("{}/tuple-{}", self.dir, bind_port));
    }

    pub fn log_transition(&self, event: &str, detail: &str) {
        println!("{{\"event\":\"{}\",\"detail\":\"{}\"}}", event, detail);
    }
}
