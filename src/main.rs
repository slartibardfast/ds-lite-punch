//! ds-lite-punch — CGNAT-aware UDP relay for the Virgin Media ds-lite line.
//!
//! One socket bound to (192.168.0.21, R). Two jobs share it:
//!   1. keep the AFTR mapping alive + observe it (STUN keepalive = discovery);
//!   2. forward inbound peer datagrams to the br-lan target, source preserved.
//! See plan/0004-ds-lite-punch/README.md for the full design and the measured
//! CGNAT behavior this is built around (5-10 s idle timeout, EIM+EIF, no
//! source-port preservation).
mod cdc;
mod ct;
mod dp;
mod engine;
mod forward;
mod mapping;
mod nft;
mod obs;
mod persist;
mod publish;
mod slot;
mod stun;
mod tcpslot;
mod upnp;
mod upnpsvc;
mod vote;

use cdc::CdcKind;
use mapping::State;
use nft::{add_input_accept, add_pin, ensure_flow_obs, ensure_ruleset};
use persist::{load_epoch, read_leases, snapshot, write_leases, DEFAULT_DIR};
use publish::Publisher;
use slot::{Epoch, LeaseTable, PortAllocator, StaticMapErr};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};
use upnp::DEFAULT_LAN_IP;
use upnpsvc::UpnpFacade;
use vote::{VoteDecision, VoteState};

/// Format a static-map/restore rejection for logs (the enum stays heap-free
/// in `slot.rs` for the Kani proofs; messages live only at this boundary).
fn fmt_static_err(e: StaticMapErr, lo: u16, hi: u16) -> String {
    match e {
        StaticMapErr::OutOfRange { port } => {
            format!("static bind port {} outside slot range {}-{}", port, lo, hi)
        }
        StaticMapErr::InUse { port } => format!("static bind port {} already in use", port),
    }
}

/// One static mapping R=ip:port (UDP). P1's `--bind`/`--target` pair is sugar
/// for a single entry; `--static-map` is the repeatable form (B3).
#[derive(Clone, Copy, Debug)]
struct StaticMap {
    bind_port: u16,
    target: SocketAddrV4,
}

#[derive(Debug)]
struct Config {
    bind: SocketAddr,
    target: SocketAddrV4,
    static_maps: Vec<StaticMap>,
    stun: Vec<String>,
    interval: Duration,
    gateway: String,
    state_dir: String,
    slot_lo: u16,
    slot_hi: u16,
    max_slots: usize,
    max_maps_per_client: u16,
    gc_grace_factor: u32,
    observation: bool,
    max_rescues: u32,
    cdc: CdcKind,
    // UPnP IGD facade (plan/0007 phase E): br-lan only.
    upnp_enabled: bool,
    upnp_port: u16,
    lan_ip: Ipv4Addr,
    upnp_name: String,
}

fn parse_args() -> Result<Config, String> {
    parse_args_from(std::env::args().collect())
}

/// The parser, with its argv supplied. Kept separate so the multi-instance
/// form can be tested: `--static-map` is repeatable, and until this split the
/// only way to exercise it was to run the binary.
fn parse_args_from(args: Vec<String>) -> Result<Config, String> {
    let mut bind: Option<SocketAddr> = None;
    let mut target: Option<SocketAddrV4> = None;
    let mut static_maps: Vec<StaticMap> = Vec::new();
    let mut stun: Vec<String> = Vec::new();
    let mut interval_s: u64 = 2;
    let mut gateway = "192.168.0.1".to_string();
    let mut state_dir = "/run/ds-lite-punch".to_string();
    let mut slot_range = "30000-39999".to_string();
    let mut max_slots: usize = 32;
    let mut max_maps_per_client: u16 = 16;
    let mut gc_grace_factor: u32 = 3;
    let mut observation = false;
    let mut max_rescues: u32 = 8;
    let mut upnp_enabled = true;
    let mut upnp_port: u16 = upnp::UPNP_DEFAULT_PORT;
    let mut lan_ip = DEFAULT_LAN_IP;
    let mut upnp_name = "ds-lite-punch IGD".to_string();
    // G1 primary = the nft flow_obs mirror (gating test passed 2026-09-02);
    // /proc stays reachable as the fallback (--cdc proc).
    let mut cdc_kind = CdcKind::Nft;

    let mut i = 1;
    while i < args.len() {
        let k = args[i].as_str();
        let v = || {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("missing value for {}", k))
        };
        match k {
            "--bind" => {
                bind = Some(v()?.parse().map_err(|e| format!("--bind: {}", e))?);
                i += 2
            }
            "--target" => {
                target = Some(v()?.parse().map_err(|e| format!("--target: {}", e))?);
                i += 2
            }
            "--static-map" => {
                // R=ip:port — the repeatable multi-instance form (B3)
                let spec = v()?;
                let (r, rest) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("--static-map: expected R=ip:port, got '{}'", spec))?;
                let bind_port: u16 = r
                    .parse()
                    .map_err(|e| format!("--static-map: bad port '{}': {}", r, e))?;
                let target: SocketAddrV4 = rest
                    .parse()
                    .map_err(|e| format!("--static-map: bad target '{}': {}", rest, e))?;
                static_maps.push(StaticMap {
                    bind_port,
                    target,
                });
                i += 2
            }
            "--slot-port-range" => {
                slot_range = v()?;
                i += 2
            }
            "--max-slots" => {
                max_slots = v()?.parse().map_err(|e| format!("--max-slots: {}", e))?;
                i += 2
            }
            "--max-maps-per-client" => {
                max_maps_per_client = v()?.parse().map_err(|e| format!("--max-maps-per-client: {}", e))?;
                i += 2
            }
            "--gc-grace-factor" => {
                gc_grace_factor = v()?.parse().map_err(|e| format!("--gc-grace-factor: {}", e))?;
                i += 2
            }
            "--stun" => {
                stun = v()?.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                i += 2
            }
            "--interval" => {
                interval_s = v()?.parse().map_err(|e| format!("--interval: {}", e))?;
                i += 2
            }
            "--gateway" => {
                gateway = v()?;
                i += 2
            }
            "--state-dir" => {
                state_dir = v()?;
                i += 2
            }
            "--observation" => {
                observation = true;
                i += 1
            }
            "--max-rescues" => {
                max_rescues = v()?.parse().map_err(|e| format!("--max-rescues: {}", e))?;
                i += 2
            }
            "--cdc" => {
                cdc_kind = match v()?.as_str() {
                    "proc" => CdcKind::Proc,
                    "nft" => CdcKind::Nft,
                    "aya" => CdcKind::Aya,
                    other => {
                        return Err(format!(
                            "--cdc: unknown backend '{}' (proc|nft|aya)",
                            other
                        ))
                    }
                };
                i += 2
            }
            "--upnp-port" => {
                upnp_port = v()?.parse().map_err(|e| format!("--upnp-port: {}", e))?;
                i += 2
            }
            "--lan-ip" => {
                lan_ip = v()?.parse().map_err(|e| format!("--lan-ip: {}", e))?;
                i += 2
            }
            "--upnp-name" => {
                upnp_name = v()?;
                i += 2
            }
            "--no-upnp" => {
                upnp_enabled = false;
                i += 1
            }
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            "--ct-probe" => {
                // Diagnostic: bisect the netlink CT_DELETE encoding against
                // a self-created conntrack entry (see ct.rs). Not a daemon
                // flag — exits immediately.
                crate::ct::self_test();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {}", other)),
        }
    }

    // Legacy --bind/--target pair == one static map (P1 semantics).
    match (bind, target) {
        (Some(b), Some(t)) => {
            if !static_maps.is_empty() {
                return Err("--bind/--target cannot be combined with --static-map".to_string());
            }
            static_maps.push(StaticMap {
                bind_port: b.port(),
                target: t,
            });
        }
        (Some(_), None) => return Err("--bind requires --target".to_string()),
        (None, Some(_)) => return Err("--target requires --bind".to_string()),
        (None, None) => {}
    }
    if static_maps.is_empty() {
        return Err(
            "no mappings: use --bind/--target (single) or --static-map R=ip:port (repeatable)"
                .to_string(),
        );
    }

    let mk = || -> Result<(u16, u16), String> {
        let (lo, hi) = slot_range
            .split_once('-')
            .ok_or_else(|| format!("--slot-port-range: expected LO-HI, got '{}'", slot_range))?;
        let lo: u16 = lo.parse().map_err(|e| format!("--slot-port-range lo: {}", e))?;
        let hi: u16 = hi.parse().map_err(|e| format!("--slot-port-range hi: {}", e))?;
        Ok((lo, hi))
    };
    let (slot_lo, slot_hi) = mk()?;
    PortAllocator::new(slot_lo, slot_hi)
        .ok_or_else(|| format!("invalid slot range {}-{}", slot_lo, slot_hi))?;

    let bind = bind.unwrap_or_else(|| SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(192, 168, 0, 21),
        static_maps[0].bind_port,
    )));
    let target = static_maps[0].target;
    if stun.is_empty() {
        stun = vec![
            "stun.l.google.com:19302".to_string(),
            "stun.cloudflare.com:3478".to_string(),
        ];
    }
    Ok(Config {
        bind,
        target,
        static_maps,
        stun,
        interval: Duration::from_secs(interval_s.max(1)),
        gateway,
        state_dir,
        slot_lo,
        slot_hi,
        max_slots,
        max_maps_per_client,
        gc_grace_factor,
        observation,
        max_rescues,
        cdc: cdc_kind,
        upnp_enabled,
        upnp_port,
        lan_ip,
        upnp_name,
    })
}

fn usage() {
    eprintln!(
        "ds-lite-punch --static-map R=ip:port [--static-map ...] \
         [--stun host:port,host:port] [--interval 2] [--gateway 192.168.0.1] \
         [--state-dir /run/ds-lite-punch] [--slot-port-range LO-HI] \
         [--max-slots 32] [--max-maps-per-client 16] \
         [--gc-grace-factor 3] [--observation] [--max-rescues 8] \
         [--cdc proc|nft|aya] \
         [--upnp-port 49152] [--lan-ip 192.168.21.1] [--upnp-name NAME] \
         [--no-upnp]\n\
         Legacy single-map form (P1): --bind 192.168.0.21:R --target ip:port"
    );
}

/// Force each STUN server's IP out the VM line: host route via the hub.
/// Without this the default route (vdsl4, lower metric) wins and STUN maps the
/// wrong NAT. Idempotent (`replace`).
fn add_stun_routes(servers: &[SocketAddrV4], gateway: &str) {
    for s in servers {
        let status = Command::new("ip")
            .args(["route", "replace", &s.ip().to_string(), "via", gateway])
            .status();
        match status {
            Ok(st) if st.success() => {}
            Ok(st) => eprintln!("warn: ip route replace {} via {} -> {}", s.ip(), gateway, st),
            Err(e) => eprintln!("warn: ip route replace failed: {}", e),
        }
    }
}

/// Dedicated table for the relay's tuple-sourced egress (RCA 2026-09-13:
/// the accepted TCP connections' replies and the fold-holder's outbound
/// follow the kernel's output lookup, whose main-table default is the
/// vdsl4 PPPoE, never the eth1 line the AFTR mapping lives on; the AFTR
/// can translate a return path only on that line).
const EGRESS_TABLE: &str = "1001";
const EGRESS_PRIO: &str = "25100";
/// Lease-policy last-seen stamp interval: the datapath can fire many
/// times a second; one write per slot per 15 s is ample resolution for a
/// 24 h grace period.
const LEASE_STAMP_MIN_S: u64 = 15;

/// Force every tuple-sourced egress out the VM line: a policy rule from
/// the bind address into the dedicated table whose default is the hub.
/// Local-destination replies still loop (the local table outranks the
/// rule), so a self-sourced probe can never complete a handshake; the
/// rule exists for genuinely remote peers. Idempotent; the init script
/// removes the rule and flushes the table on stop.
fn add_egress_rule(bind_ip: &SocketAddr, gateway: &str) {
    let from = bind_ip.ip().to_string();
    let _ = Command::new("ip")
        .args([
            "route", "replace", "default", "via", gateway,
            "table", EGRESS_TABLE,
        ])
        .status();
    let status = Command::new("ip")
        .args([
            "rule", "add", "from", &from, "lookup", EGRESS_TABLE,
            "prio", EGRESS_PRIO,
        ])
        .status();
    if let Ok(st) = status {
        if !st.success() {
            eprintln!("warn: ip rule egress {} -> {}", from, st);
        }
    }
}

async fn resolve_stun(hosts: &[String]) -> Vec<SocketAddrV4> {
    let mut out = Vec::new();
    for h in hosts {
        match tokio::net::lookup_host(h).await {
            Ok(addrs) => {
                for a in addrs {
                    if let SocketAddr::V4(v4) = a {
                        out.push(v4);
                        break; // first v4 per host
                    }
                }
            }
            Err(e) => eprintln!("warn: resolve {} failed: {}", h, e),
        }
    }
    out
}

/// The slot keepalive loop. Spawned by the slot's caller (static path and
/// the UPnP facade grant path) so that path owns the JoinHandle and can
/// abort both tasks on teardown.
pub(crate) async fn keepalive_loop(
    sock: Arc<UdpSocket>,
    state: Arc<Mutex<State>>,
    interval: Duration,
    phase_ms: u32,
) {
    // Stagger: slot index i at (i * 2000/N) ms so N slots never burst one
    // STUN server simultaneously.
    if phase_ms > 0 {
        tokio::time::sleep(Duration::from_millis(phase_ms as u64)).await;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let server = state.lock().await.current_server();
        let txn = stun::random_txn();
        let req = stun::binding_request(&txn);
        if let Err(e) = sock.send_to(&req, server).await {
            eprintln!("warn: keepalive send to {} failed: {}", server, e);
        }
        let rotated = state.lock().await.note_silence();
        if rotated {
            eprintln!(
                "keepalive: STUN server unresponsive, rotated to {}",
                state.lock().await.current_server()
            );
        }
    }
}

/// One slot: keepalive task (staggered) + recv loop on its own socket.
/// Byte-identical to v1 core when there is exactly one slot (no stagger:
/// single socket, same forward path). `pub(crate)`: the UPnP facade grants
/// spawn the same datapath for a granted UDP slot.
///
/// The keepalive task is NOT spawned here: the caller spawns it (and owns
/// both JoinHandles) so a facade grant revocation can abort the keepalive
/// too — otherwise the keepalive's own Arc clone would keep the slot socket
/// bound after the recv loop is aborted (the 2026-09-14 leak).
pub(crate) async fn run_slot(
    sock: Arc<UdpSocket>,
    state: Arc<Mutex<State>>,
    table: Arc<Mutex<LeaseTable>>,
    target: SocketAddrV4,
    publisher: Arc<Publisher>,
    bind_port: u16,
) {
    // B6 STUN majority vote: publication happens only when >=2 servers
    // agree on a new tuple; a single disagreeing observation marks the
    // server suspect (rotate) without republishing.
    let vote = Arc::new(Mutex::new(VoteState::new()));

    // recv loop: classify STUN responses vs peer data; forward the latter.
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("warn: recv failed: {}", e);
                continue;
            }
        };
        let pkt = &buf[..n];
        let src_v4 = match src {
            SocketAddr::V4(v4) => v4,
            _ => continue,
        };

        let is_stun_server = state.lock().await.is_stun_server(src_v4);
        if is_stun_server {
            if let Some(tuple) = stun::parse_mapped(pkt) {
                // Health bookkeeping first: any valid response clears
                // silence, regardless of what the vote decides.
                state.lock().await.note_response(tuple);
                let server_idx = state.lock().await.server_index(src_v4);
                let decision = match server_idx {
                    Some(idx) => vote.lock().await.observe(idx, tuple),
                    None => VoteDecision::Stable, // unknown server, ignore
                };
                match decision {
                    VoteDecision::Churn((ip, port)) => {
                        publisher.log_transition(
                            "churn",
                            &format!("slot {} confirmed {}:{}", bind_port, ip, port),
                        );
                        publisher.publish_slot(bind_port, ip, port);
                    }
                    VoteDecision::Disagree(idx) => {
                        let rotated = state.lock().await.mark_suspect();
                        publisher.log_transition(
                            "suspect",
                            &format!(
                                "slot {} STUN server {} disagreed; rotated={}",
                                bind_port, idx, rotated
                            ),
                        );
                    }
                    VoteDecision::Stable => {}
                }
            }
            // STUN packet we can't parse: ignore.
        } else {
            // Peer data reaching the client = the mapping is in use: stamp
            // the last-seen clock (rate-limited) so the lease policy can
            // tell a live session from a ghost.
            {
                let mut t = table.lock().await;
                t.stamp_activity_if_stale(bind_port, Epoch::now(), LEASE_STAMP_MIN_S);
            }
            if let Err(e) = forward::forward(pkt, src_v4, target) {
                eprintln!("warn: forward {} -> {} failed: {}", src_v4, target, e);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {}", e);
            usage();
            std::process::exit(2);
        }
    };

    let servers = resolve_stun(&cfg.stun).await;
    if servers.is_empty() {
        eprintln!("fatal: no STUN servers resolved");
        std::process::exit(1);
    }
    add_stun_routes(&servers, &cfg.gateway);
    add_egress_rule(&cfg.bind, &cfg.gateway);

    // Slot table: built entirely via restore() (B8) so statics are inserted
    // exactly once — config statics are authoritative, persisted granted
    // leases re-bind their exact Rs. Collisions/out-of-range are
    // startup-fatal (config errors, not transient state).
    let allocator = PortAllocator::new(cfg.slot_lo, cfg.slot_hi)
        .expect("slot range validated in parse_args");
    let mut table = LeaseTable::new(allocator, cfg.max_slots, cfg.max_maps_per_client);

    // B6/B7/B8 persistence: epoch survives respawn (tmpfs) and resets on
    // reboot (correct: a reboot killed every CGNAT mapping); leases.tsv
    // snapshots the table so respawn re-binds the same Rs before the
    // first STUN round (deterministic rebind).
    let persist_dir = Path::new(DEFAULT_DIR);
    let _ = load_epoch(persist_dir, Epoch::now());
    let now = Epoch::now();

    // B8 respawn restore: re-bind the exact same Rs before the first STUN
    // round. Config statics are authoritative; granted leases come back
    // from leases.tsv (tmpfs survives a crash, not a reboot — which is the
    // mapping-death alignment). A granted record's target is its own
    // (client, int_port) tuple. A persisted grant whose R collides with a
    // config static is stale (config wins) — dropped, not fatal.
    let static_tuples: Vec<(u16, Ipv4Addr, u16)> = cfg
        .static_maps
        .iter()
        .map(|m| (m.bind_port, *m.target.ip(), m.target.port()))
        .collect();
    let static_rs: Vec<u16> = static_tuples.iter().map(|t| t.0).collect();
    let (persisted, skipped) = read_leases(persist_dir);
    if skipped > 0 {
        eprintln!("warn: {} malformed lease rows ignored", skipped);
    }
    let granted: Vec<slot::GrantedRecord> = persisted
        .iter()
        .filter(|p| p.kind == 1 && !static_rs.contains(&p.bind_port))
        .map(|p| slot::GrantedRecord {
            bind_port: p.bind_port,
            proto: match p.proto {
                6 => slot::Proto::Tcp,
                _ => slot::Proto::Udp,
            },
            client: p.client,
            int_port: p.int_port,
            target: p.client, // granted slot forwards to its own flow
            target_port: p.int_port,
            granted_lifetime: p.granted_lifetime,
            expires_at_unix: p.expires_at_unix,
        })
        .collect();
    if let Err(e) = table.restore(&static_tuples, &granted, now) {
        eprintln!(
            "fatal: lease table restore failed: {}",
            fmt_static_err(e, cfg.slot_lo, cfg.slot_hi)
        );
        std::process::exit(1);
    }

    // Snapshot the whole table (static + granted) back to disk so the
    // respawn cycle is stable. One projection lives in persist::snapshot
    // (the facade's persist() writes through it too); the boot path must
    // not carry a second copy that can drift from it.
    let persisted_snapshot: Vec<persist::PersistedSlot> = snapshot(table.slots(), now);
    if let Err(e) = write_leases(persist_dir, &persisted_snapshot) {
        eprintln!("warn: persist leases failed: {}", e);
    }

    // B9 GC: scan every 60 s; free granted leases expired past
    // (grace_factor x 60 s) with no inbound activity. Statics never GC. In
    // facade mode the UPnP facade's own GC owns the per-slot teardown
    // (nft element delete, task abort, entry removal) so the table-only
    // loop here only runs without the facade.
    // Snapshot the slots before the table is moved into the tasks: pins,
    // accepts and slot tasks are all driven from this frozen set
    // (facade-added leases get their own spawn path in phase E).
    let slots_snapshot: Vec<slot::Slot> = table.slots().to_vec();
    let table = Arc::new(Mutex::new(table));
    if !cfg.upnp_enabled {
        let grace = cfg.gc_grace_factor.saturating_mul(60);
        let gc_table = table.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let now = Epoch::now();
                let freed = gc_table.lock().await.gc(now, grace as u64);
                if !freed.is_empty() {
                    eprintln!(
                        "gc: freed slots {:?} (no refresh, no traffic, past grace)",
                        freed
                    );
                }
            }
        });
    }

    // The tuple watch carries the last published external IP: the facade's
    // GetExternalIPAddress reads it and GENA events fire on its changes.
    // Seeded from the persisted slot-0 tuple file (respawn continuity), so
    // a pre-discovery request is answered from the last known value.
    let (ip_tx, ip_rx) =
        watch::channel(seed_external_ip(&cfg.state_dir, cfg.bind.port()));
    let publisher = Arc::new(Publisher::with_watch(&cfg.state_dir, ip_tx));
    let state = Arc::new(Mutex::new(State::new(servers.clone())));
    let target = cfg.target;

    // B4: install the fixed nft ruleset once, then pin + accept per slot.
    // Pin key is uniform across statics and restored grants: the slot's own
    // (target ip, target port) tuple -> (NAT_ADDR, R) (B4; I2).
    if let Err(e) = ensure_ruleset() {
        eprintln!("fatal: nft ruleset install failed: {}", e);
        std::process::exit(1);
    }
    let bind_ip = match cfg.bind {
        SocketAddr::V4(v4) => *v4.ip(),
        _ => Ipv4Addr::new(192, 168, 0, 21),
    };
    for s in &slots_snapshot {
        if let Err(e) = add_pin(s.target, s.target_port, s.bind_port) {
            eprintln!(
                "fatal: nft add_pin {}:{} -> {} failed: {}",
                s.target, s.target_port, s.bind_port, e
            );
            std::process::exit(1);
        }
        if let Err(e) = add_input_accept(s.bind_port, s.proto == slot::Proto::Tcp) {
            eprintln!("fatal: nft input accept for {} failed: {}", s.bind_port, e);
            std::process::exit(1);
        }
    }

    println!(
        "{{\"event\":\"start\",\"bind\":\"{}\",\"target\":\"{}\",\"stun_servers\":{},\"slots\":{}}}",
        cfg.bind,
        target,
        state.lock().await.servers.len(),
        slots_snapshot.len()
    );

    // Stagger slot i at (i * 2000/N) ms; single-slot keeps no stagger
    // (byte-identical to v1 core): one socket, same keepalive + recv path.
    let n = slots_snapshot.len() as u32;
    let interval = cfg.interval;
    for (i, s) in slots_snapshot.iter().enumerate() {
        // In facade mode, granted leases (respawn-restored from leases.tsv)
        // have their datapath rebuilt and registered in the facade's task
        // map by UpnpFacade::start — the one owner that can tear them down.
        // A second spawn here would double-bind the slot socket and orphan
        // the handles. Statics stay on this path: the facade never tears a
        // static slot down, so main's discarded handles are correct for it.
        if cfg.upnp_enabled && !s.is_static() {
            continue;
        }
        if s.proto == slot::Proto::Tcp {
            // TCP slot datapath (call/0017): listener on the pin tuple
            // with a STUN-over-TCP holder at the C3-sized cadence. The
            // holder publishes the slot's external TCP tuple per-R.
            let listener = match tcpslot::bind_pin(s.bind_port).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!(
                        "fatal: bind tcp slot {}:{} failed: {}",
                        bind_ip, s.bind_port, e
                    );
                    std::process::exit(1);
                }
            };
            let target = SocketAddrV4::new(s.target, s.target_port);
            let publisher = publisher.clone();
            let servers = state.lock().await.servers.clone();
            let vote = Arc::new(Mutex::new(VoteState::new()));
            let bind_port = s.bind_port;
            tokio::spawn(tcpslot::run_tcp_slot(listener, target));
            tokio::spawn(tcpslot::run_holder(
                bind_ip, bind_port, servers, vote, publisher,
            ));
            continue;
        }
        let sock = Arc::new(
            match UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(bind_ip, s.bind_port))).await {
                Ok(sk) => sk,
                Err(e) => {
                    eprintln!("fatal: bind slot {}:{} failed: {}", bind_ip, s.bind_port, e);
                    std::process::exit(1);
                }
            },
        );
        let phase_ms = if n > 1 { i as u32 * 2000 / n } else { 0 };
        let state = Arc::new(Mutex::new(State::new(
            state.lock().await.servers.clone(),
        )));
        let target = SocketAddrV4::new(s.target, s.target_port);
        let publisher = publisher.clone();
        let bind_port = s.bind_port;
        // The keepalive is a sibling task (not spawned inside run_slot):
        // the caller owns both JoinHandles, so a facade grant revocation
        // can abort them together. The static path here never tears a slot
        // down, so the handles are deliberately discarded.
        let ka_sock = sock.clone();
        let ka_state = state.clone();
        tokio::spawn(async move {
            keepalive_loop(ka_sock, ka_state, interval, phase_ms).await
        });
        let table_for_slot = table.clone();
        tokio::spawn(async move {
            run_slot(sock, state, table_for_slot, target, publisher, bind_port).await
        });
    }

    // Phase E: the UPnP IGD facade (plan/0007). SSDP + description docs +
    // SOAP (POST/M-POST) + GENA on br-lan; AddPortMapping grants UDP and
    // TCP slots with real datapaths (the facade spawns a slot's runtime as
    // its own job, per the D/E note above). In facade mode the facade's
    // local GC owns the granted-lease teardown (the table-only GC above is
    // skipped); the tuple watch feeds GetExternalIPAddress and the GENA
    // events.
    let facade = if cfg.upnp_enabled {
        let facade_servers = servers.clone();
        match UpnpFacade::start(
            upnpsvc::UpnpConfig {
                lan_ip: cfg.lan_ip,
                upnp_port: cfg.upnp_port,
                bind_ip,
                state_dir: cfg.state_dir.clone(),
                servers: facade_servers,
                interval: cfg.interval,
                name: cfg.upnp_name.clone(),
                grace_secs: u64::from(cfg.gc_grace_factor.saturating_mul(60)),
            },
            table.clone(),
            publisher.clone(),
            ip_rx,
        )
        .await
        {
            Ok(f) => {
                println!(
                    "{{\"event\":\"upnp\",\"lan\":\"{}:{}\",\"udn\":\"uuid:{}\"}}",
                    cfg.lan_ip,
                    cfg.upnp_port,
                    f.udn()
                );
                Some(f)
            }
            Err(e) => {
                eprintln!("upnp: facade unavailable, continuing without it: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Phase G: observation rescue engine (--observation). The selected CDC
    // produces live candidate flows; the engine claims them with shadow
    // sockets that keep the AFTR mapping alive and forward inbound to the
    // host P1-style (see engine.rs). Default CDC = the nft `flow_obs`
    // mirror (gating test passed 2026-09-02); the `/proc` backend is the
    // fallback; Aya is not wired yet.
    if cfg.observation {
        // I1: inner tuples static/lease slots own — the engine never
        // captures one. (Today the table holds statics only; facade-added
        // leases extend this list in D/E.)
        let held: Vec<(Ipv4Addr, u16)> = slots_snapshot
            .iter()
            .map(|s| (bind_ip, s.bind_port))
            .collect();
        let cdc: Box<dyn cdc::Cdc> = match cfg.cdc {
            cdc::CdcKind::Proc => Box::new(cdc::ProcCdc::new(held.clone(), cfg.max_rescues)),
            cdc::CdcKind::Nft => {
                // The mirror is part of the daemon's ruleset but only when
                // the observation engine is enabled — the production daemon
                // (no --observation) keeps today's byte-identical ruleset.
                if let Err(e) = ensure_flow_obs() {
                    eprintln!("fatal: nft flow_obs mirror install failed: {}", e);
                    std::process::exit(1);
                }
                Box::new(cdc::NftCdc::new(held.clone(), cfg.max_rescues))
            }
            cdc::CdcKind::Aya => {
                eprintln!("fatal: --cdc aya is not built yet");
                std::process::exit(2);
            }
        };
        let servers = state.lock().await.servers.clone();
        let engine = engine::ObservationEngine::new(
            cdc,
            held,
            cfg.max_rescues,
            engine::DEFAULT_GRACE_TICKS,
            servers,
            publisher.clone(),
            Arc::new(engine::NftPins),
        );
        let cdc_name = engine.name();
        tokio::spawn(async move {
            engine.run().await;
        });
        println!(
            "{{\"event\":\"observe\",\"cdc\":\"{}\",\"max_rescues\":{}}}",
            cdc_name, cfg.max_rescues
        );
    }

    // All work happens in spawned tasks; keep main alive. procd sends
    // SIGTERM on stop. In facade mode a handler sends the SSDP byebye
    // NOTIFYs before exiting (the init script's stop() removes the nft
    // ruleset); without the facade the default SIGTERM action applies.
    if let Some(facade) = &facade {
        let f = facade.clone();
        tokio::spawn(async move {
            // Exit only on a received SIGTERM: a registration failure here
            // (the guard's Err arm) must leave the default SIGTERM action
            // in place, never self-terminate moments after boot.
            if let Ok(mut sigterm) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                sigterm.recv().await;
                f.send_byebye().await;
                tokio::time::sleep(Duration::from_millis(150)).await;
                std::process::exit(0);
            }
        });
    }
    std::future::pending::<()>().await;
}

/// Seed the facade's external-IP watch from the persisted tuple files
/// (slot-0's per-slot file first, then the aggregate): the last known
/// value across respawns, so a pre-discovery GetExternalIPAddress is never
/// answered with an unset address.
fn seed_external_ip(state_dir: &str, primary: u16) -> Ipv4Addr {
    let slot_file = format!("{}/tuple-{}", state_dir, primary);
    let agg_file = format!("{}/tuple", state_dir);
    for f in [slot_file, agg_file] {
        if let Ok(s) = std::fs::read_to_string(&f) {
            if let Some((ip, _)) = s.trim().split_once(':') {
                if let Ok(ip) = ip.parse() {
                    return ip;
                }
            }
        }
    }
    Ipv4Addr::UNSPECIFIED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(rest: &[&str]) -> Vec<String> {
        let mut v = vec!["ds-lite-punch".to_string()];
        v.extend(rest.iter().map(|s| s.to_string()));
        v
    }

    /// The multi-instance CLI contract (plan/0004 B3): `--static-map` is
    /// repeatable and order-preserving, the legacy pair is sugar for one entry
    /// and cannot be combined with it, and every malformed shape names itself.
    #[test]
    fn static_map_parse_is_repeatable_and_exclusive() {
        // the repeatable form, in order
        let c = parse_args_from(argv(&[
            "--static-map", "40000=192.168.0.21:40001",
            "--static-map", "41000=192.168.0.22:41001",
        ]))
        .expect("two static maps parse");
        assert_eq!(c.static_maps.len(), 2, "both maps are kept");
        assert_eq!(c.static_maps[0].bind_port, 40000);
        assert_eq!(c.static_maps[0].target.to_string(), "192.168.0.21:40001");
        assert_eq!(c.static_maps[1].bind_port, 41000);
        assert_eq!(c.static_maps[1].target.to_string(), "192.168.0.22:41001");

        // the legacy pair is one entry, and its bind port is the key
        let c = parse_args_from(argv(&["--bind", "192.168.0.21:40000", "--target", "192.168.0.21:40001"]))
            .expect("the legacy pair parses");
        assert_eq!(c.static_maps.len(), 1);
        assert_eq!(c.static_maps[0].bind_port, 40000);

        // ... and cannot be combined with the repeatable form
        let e = parse_args_from(argv(&[
            "--bind", "192.168.0.21:40000", "--target", "192.168.0.21:40001",
            "--static-map", "41000=192.168.0.22:41001",
        ]))
        .expect_err("combining the forms is refused");
        assert!(e.contains("cannot be combined"), "{}", e);

        // each malformed shape is named, not swallowed
        for (args, want) in [
            (vec!["--static-map", "40000"], "expected R=ip:port"),
            (vec!["--static-map", "nope=192.168.0.21:40001"], "bad port"),
            (vec!["--static-map", "40000=not-an-addr"], "bad target"),
            (vec!["--bind", "192.168.0.21:40000"], "--bind requires --target"),
            (vec!["--target", "192.168.0.21:40001"], "--target requires --bind"),
            (vec![], "no mappings"),
        ] {
            let e = parse_args_from(argv(&args)).expect_err("a malformed form is refused");
            assert!(e.contains(want), "for {:?} expected {:?}, got {:?}", args, want, e);
        }
    }

    #[test]
    fn seed_external_ip_prefers_slot_over_aggregate() {
        // Regression (review S6): the seeded GetExternalIPAddress answer
        // depends on the file order and the trim-before-split; a regression
        // here silently answered 501 after every reboot with a stale tuple.
        let d = std::env::temp_dir().join(format!("dslp-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // aggregate only
        std::fs::write(d.join("tuple"), "87.116.31.222:40001\n").unwrap();
        assert_eq!(
            seed_external_ip(d.to_str().unwrap(), 40000),
            "87.116.31.222".parse::<Ipv4Addr>().unwrap()
        );
        // per-slot file wins over the aggregate (it is the fresher record)
        std::fs::write(d.join("tuple-40000"), "87.116.31.223:40001\n").unwrap();
        assert_eq!(
            seed_external_ip(d.to_str().unwrap(), 40000),
            "87.116.31.223".parse::<Ipv4Addr>().unwrap()
        );
        // a trailing-newline-only variant still parses (trim before split)
        std::fs::write(d.join("tuple"), "87.116.31.224:40001").unwrap();
        assert_eq!(
            seed_external_ip(d.to_str().unwrap(), 40001),
            "87.116.31.224".parse::<Ipv4Addr>().unwrap()
        );
        // nothing readable -> UNSPECIFIED
        let missing = std::env::temp_dir().join(format!("dslp-seed-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        std::fs::create_dir_all(&missing).unwrap();
        assert_eq!(seed_external_ip(missing.to_str().unwrap(), 40000), Ipv4Addr::UNSPECIFIED);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&missing);
    }
}
