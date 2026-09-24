//! The epoch and the lease records, at the fixed path /tmp/dslp, which a restart re-binds its slots from.
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

pub const DEFAULT_DIR: &str = "/tmp/dslp";

/// Parse `epoch`, creating it with `now` when absent; the caller supplies the clock so tests can pin it.
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
    /// IANA protocol code: 17 is UDP, 6 is TCP; a row without the column is legacy UDP.
    pub proto: u8,
    pub kind: u8, // 0=static, 1=granted
    pub client: Ipv4Addr,
    pub int_port: u16,
    pub bookkeeping_ext_port: u16,
    pub granted_lifetime: u32,
    pub expires_at_unix: u64,
    pub created_at_unix: u64,
}

/// Project the live slot table for persisting, so a restart re-binds the same slots.
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

/// Serialize the slots to TSV, ordered by bind port so the bytes are stable across restarts.
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

/// Replace `leases.tsv` atomically, so a crash leaves no half-written file.
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

/// Parse `leases.tsv`: a malformed row is skipped and counted here, and the caller decides what that costs.
#[allow(dead_code)] // B8 respawn-restore reader
/// Replace `upnp.tsv` atomically, and only when the write succeeded: an unconditional rename published an empty file over a good table.
pub fn write_entries(dir: &Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    fs::create_dir_all(dir)?;
    let tmp = dir.join("upnp.tsv.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
    }
    fs::rename(&tmp, dir.join("upnp.tsv"))
}

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
        // The protocol code is the appended column, and a malformed one counts as a malformed row.
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

    #[test]
    fn a_failed_entry_write_cannot_publish_an_empty_record() {
        // A directory where the tmpfile belongs: the create fails, and the table that was there stays there.
        let d = tmpdir("entries");
        fs::create_dir_all(&d).unwrap();
        let good = d.join("upnp.tsv");
        fs::write(&good, "3074\t17\t40002\t...\n").unwrap();
        fs::create_dir_all(d.join("upnp.tsv.tmp")).unwrap();
        let r = write_entries(&d, "something else\n");
        assert!(r.is_err(), "the write is reported, not swallowed");
        assert_eq!(
            fs::read_to_string(&good).unwrap(),
            "3074\t17\t40002\t...\n",
            "the record that was there is untouched"
        );
        // and a directory that can be written publishes the new body
        fs::remove_dir(d.join("upnp.tsv.tmp")).unwrap();
        write_entries(&d, "fresh\n").unwrap();
        assert_eq!(fs::read_to_string(&good).unwrap(), "fresh\n");
        let _ = fs::remove_dir_all(&d);
    }

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
        // A field dropped or mis-keyed in the granted arm would ship green and kill facade grants on the next restart.
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
        // The round trip recovers the granted row for the restore filter.
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
        // Caller order must not change the bytes on disk; a Kani harness would prove it, and `format!` stalls the solver.
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