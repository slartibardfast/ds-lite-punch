//! Persistence for the slot engine (brief v2, B6/B7/B8): epoch + lease
//! records under `/tmp/dslp/`.
//!
//!   `epoch`      — one line: unix seconds the lease table was first
//!                  created (written on first start; tmpfs survives
//!                  respawn, not reboot — which is exactly right, B7/I5).
//!   `leases.tsv` — one row per slot: R, kind(static|granted), client,
//!                  int_port, bookkeeping_ext_port, granted_lifetime,
//!                  expires_at_unix, created_at_unix. Rewritten on every
//!                  change (small table; atomic via tmpfile+rename).
//!
//! Respawn restore (B8): read `epoch` to continue the PCP ANNOUNCE epoch;
//! read `leases.tsv` to re-bind the exact same Rs before the first STUN
//! round. Grant records that are still valid under the *static* config are
//! reconciled by the caller (`LeaseTable::restore`).
//!
//! Path is fixed at `/tmp/dslp/` per the brief; the runtime dir
//! (`--state-dir`, `/run/ds-lite-punch`) stays for the published tuple.
//!
//! Interim `dead_code` allowance (p2-slot-engine): `read_leases` is the
//! B8 respawn-restore reader, wired in the next phase. Remove the
//! `#![allow(dead_code)]` when B8 lands and the merge-gate build runs
//! `cargo build -D warnings`.
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

pub const DEFAULT_DIR: &str = "/tmp/dslp";

/// Parse `epoch` from disk, creating it with `now` when absent.
/// `now` is provided by the caller (Epoch::now) so tests can pin it.
pub fn load_epoch(dir: &Path, now: u64) -> u64 {
    let path = dir.join("epoch");
    match fs::read_to_string(&path) {
        Ok(s) => s.trim().parse::<u64>().unwrap_or(now),
        Err(_) => {
            let _ = fs::create_dir_all(dir);
            let _ = fs::write(&path, format!("{}\n", now));
            now
        }
    }
}

/// One persisted slot row (mirrors `slot::GrantedRecord` + static marker).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedSlot {
    pub bind_port: u16,
    /// IANA proto code: 17 = UDP, 6 = TCP (the last column; rows without
    /// it are legacy UDP).
    pub proto: u8,
    pub kind: u8, // 0=static, 1=granted
    pub client: Ipv4Addr,
    pub int_port: u16,
    pub bookkeeping_ext_port: u16,
    pub granted_lifetime: u32,
    pub expires_at_unix: u64,
    pub created_at_unix: u64,
}

/// Snapshot the live slot table for persisting (B8 respawn restore; the
/// UPnP facade grants reuse the same projection so respawn re-binds the
/// granted Rs).
pub fn snapshot(table: &[crate::slot::Slot], now_unix: u64) -> Vec<PersistedSlot> {
    table
        .iter()
        .map(|s| match s.lease {
            crate::slot::Lease::Static => PersistedSlot {
                bind_port: s.bind_port,
                proto: s.proto.code(),
                kind: 0,
                client: Ipv4Addr::UNSPECIFIED,
                int_port: 0,
                bookkeeping_ext_port: 0,
                granted_lifetime: 0,
                expires_at_unix: 0,
                created_at_unix: now_unix,
            },
            crate::slot::Lease::Granted {
                client,
                int_port,
                granted_lifetime,
                expires_at_unix,
            } => PersistedSlot {
                bind_port: s.bind_port,
                proto: s.proto.code(),
                kind: 1,
                client,
                int_port,
                bookkeeping_ext_port: 0,
                granted_lifetime,
                expires_at_unix,
                created_at_unix: now_unix,
            },
        })
        .collect()
}

/// Serialize slots to TSV. Deterministic order (by bind_port) so diffs
/// between respawns are stable.
pub fn tsv(slots: &[PersistedSlot]) -> String {
    let mut rows: Vec<&PersistedSlot> = slots.iter().collect();
    rows.sort_by_key(|s| s.bind_port);
    let mut out = String::new();
    for s in rows {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            s.bind_port,
            s.kind,
            s.client,
            s.int_port,
            s.bookkeeping_ext_port,
            s.granted_lifetime,
            s.expires_at_unix,
            s.created_at_unix,
            s.proto
        ));
    }
    out
}

/// Atomically replace `leases.tsv` (tmpfile + rename). Never leaves a
/// half-written file behind a crash.
pub fn write_leases(dir: &Path, slots: &[PersistedSlot]) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let tmp = dir.join("leases.tsv.tmp");
    let final_path = dir.join("leases.tsv");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(tsv(slots).as_bytes())?;
    }
    fs::rename(&tmp, final_path)
}

/// Parse `leases.tsv`. Rows skip malformed lines (return partial list plus
/// the count skipped — the caller decides whether that is fatal; restore
/// semantics in the brief treat a malformed row as a bind failure, so the
/// strictness lives in slot::LeaseTable::restore, not here).
#[allow(dead_code)] // B8 respawn-restore reader
pub fn read_leases(dir: &Path) -> (Vec<PersistedSlot>, usize) {
    let path = dir.join("leases.tsv");
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return (Vec::new(), 0),
    };
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 8 && parts.len() != 9 {
            skipped += 1;
            continue;
        }
        // Proto code is the appended column; rows without it are legacy
        // UDP. A malformed proto column counts as a malformed row.
        let proto: u8 = match parts.get(8) {
            Some(p) => match p.parse::<u8>() {
                Ok(v) if v == 17 || v == 6 => v,
                _ => {
                    skipped += 1;
                    continue;
                }
            },
            None => 17,
        };
        match (
            parts[0].parse::<u16>().ok(),
            parts[1].parse::<u8>().ok(),
            parts[2].parse::<Ipv4Addr>().ok(),
            parts[3].parse::<u16>().ok(),
            parts[4].parse::<u16>().ok(),
            parts[5].parse::<u32>().ok(),
            parts[6].parse::<u64>().ok(),
            parts[7].parse::<u64>().ok(),
        ) {
            (
                Some(bind_port),
                Some(kind),
                Some(client),
                Some(int_port),
                Some(bookkeeping_ext_port),
                Some(granted_lifetime),
                Some(expires_at_unix),
                Some(created_at_unix),
            ) => out.push(PersistedSlot {
                bind_port,
                proto,
                kind,
                client,
                int_port,
                bookkeeping_ext_port,
                granted_lifetime,
                expires_at_unix,
                created_at_unix,
            }),
            _ => skipped += 1,
        }
    }
    (out, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dslp-test-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn epoch_created_then_persists() {
        let d = tmpdir("epoch");
        assert_eq!(load_epoch(&d, 1000), 1000);
        assert_eq!(load_epoch(&d, 9999), 1000, "second load must read the file");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn lease_roundtrip() {
        let d = tmpdir("leases");
        let slots = vec![
            PersistedSlot {
                bind_port: 30001,
                proto: 17,
                kind: 1,
                client: Ipv4Addr::new(192, 168, 21, 50),
                int_port: 3478,
                bookkeeping_ext_port: 0,
                granted_lifetime: 600,
                expires_at_unix: 1_800_000_600,
                created_at_unix: 1_800_000_000,
            },
            PersistedSlot {
                bind_port: 30000,
                proto: 17,
                kind: 0,
                client: Ipv4Addr::new(0, 0, 0, 0),
                int_port: 0,
                bookkeeping_ext_port: 0,
                granted_lifetime: 0,
                expires_at_unix: 0,
                created_at_unix: 1_800_000_000,
            },
        ];
        write_leases(&d, &slots).unwrap();
        let (got, skipped) = read_leases(&d);
        assert_eq!(skipped, 0);
        // tsv sorts by bind_port: 30000 (static) then 30001
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].bind_port, 30000);
        assert_eq!(got[0].kind, 0);
        assert_eq!(got[1].bind_port, 30001);
        assert_eq!(got[1].client, Ipv4Addr::new(192, 168, 21, 50));
        assert_eq!(got[1].granted_lifetime, 600);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn snapshot_projects_static_and_granted_exactly() {
        // Regression (review S6): snapshot is the respawn-restore
        // projection; a field dropped or mis-keyed in the Granted arm
        // (kind flipped, client/int swapped, lifetime zeroed) would ship
        // green and silently kill facade grants on the next respawn.
        let now = 1_800_000_000u64;
        let slots = [
            crate::slot::Slot {
                bind_port: 30000,
                proto: crate::slot::Proto::Udp,
                target: Ipv4Addr::new(192, 168, 0, 21),
                target_port: 30000,
                lease: crate::slot::Lease::Static,
                phase_ms: 0,
                last_activity_unix: 0,
            },
            crate::slot::Slot {
                bind_port: 30001,
                proto: crate::slot::Proto::Tcp,
                target: Ipv4Addr::new(192, 168, 21, 50),
                target_port: 4000,
                lease: crate::slot::Lease::Granted {
                    client: Ipv4Addr::new(192, 168, 21, 50),
                    int_port: 4000,
                    granted_lifetime: 3600,
                    expires_at_unix: now + 3600,
                },
                phase_ms: 0,
                last_activity_unix: 0,
            },
        ];
        let p = snapshot(&slots, now);
        assert_eq!(p.len(), 2);
        // static row: kind 0, zeroed client/int, UDP code
        assert_eq!(p[0].kind, 0);
        assert_eq!(p[0].client, Ipv4Addr::UNSPECIFIED);
        assert_eq!(p[0].int_port, 0);
        assert_eq!(p[0].proto, 17);
        // granted row: kind 1, fields intact, TCP code
        assert_eq!(p[1].kind, 1);
        assert_eq!(p[1].client, Ipv4Addr::new(192, 168, 21, 50));
        assert_eq!(p[1].int_port, 4000);
        assert_eq!(p[1].granted_lifetime, 3600);
        assert_eq!(p[1].expires_at_unix, now + 3600);
        assert_eq!(p[1].proto, 6);
        // the TSV round-trip recovers the granted row for main's kind==1
        // restore filter
        let d = tmpdir("snapshot");
        write_leases(&d, &[p[1].clone()]).unwrap();
        let (got, skipped) = read_leases(&d);
        assert_eq!(skipped, 0);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, 1);
        assert_eq!(got[0].client, p[1].client);
        assert_eq!(got[0].int_port, 4000);
        assert_eq!(got[0].granted_lifetime, 3600);
        assert_eq!(got[0].expires_at_unix, now + 3600);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn malformed_rows_skipped() {
        let d = tmpdir("malformed");
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join("leases.tsv"),
            "not\ta\trow\n30000\t0\t10.0.0.1\t0\t0\t0\t0\t0\nshort\n",
        )
        .unwrap();
        let (got, skipped) = read_leases(&d);
        assert_eq!(got.len(), 1);
        assert_eq!(skipped, 2);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn tsv_output_is_permutation_invariant() {
        // Deterministic serialization: caller order must not change the
        // bytes on disk (rows sort by bind_port). This is the property a
        // future Kani harness would prove, but `format!`/String equality
        // stall the solver — same class as forward.rs's FFI; kept as a
        // unit test instead (recorded in the brief's Kani non-goals).
        let mk = |bind_port: u16, kind: u8| PersistedSlot {
            bind_port,
            proto: 17,
            kind,
            client: Ipv4Addr::new(192, 168, 21, 50),
            int_port: 0,
            bookkeeping_ext_port: 0,
            granted_lifetime: 0,
            expires_at_unix: 0,
            created_at_unix: 0,
        };
        let a = mk(30000, 0);
        let b = mk(30001, 1);
        let ab = tsv(&[a.clone(), b.clone()]);
        let ba = tsv(&[b, a]);
        assert_eq!(ab, ba, "TSV output must not depend on input order");
        assert!(ab.starts_with("30000\t0\t"), "lowest bind port row first");
        // and a re-parse of the serialized form round-trips the ports
        let d = tmpdir("tsvperm");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("leases.tsv"), &ab).unwrap();
        let (got, skipped) = read_leases(&d);
        assert_eq!(skipped, 0);
        let ports: Vec<u16> = got.iter().map(|s| s.bind_port).collect();
        assert_eq!(ports, vec![30000, 30001]);
        let _ = fs::remove_dir_all(&d);
    }
}