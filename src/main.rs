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
mod vote;

use cdc::CdcKind;
use mapping::State;
use nft::{add_input_accept, add_pin, ensure_flow_obs, ensure_ruleset};
use persist::{load_epoch, read_leases, write_leases, PersistedSlot, DEFAULT_DIR};
use publish::Publisher;
use slot::{Epoch, LeaseTable, PortAllocator, StaticMapErr};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
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
#[derive(Clone, Copy)]
struct StaticMap {
    bind_port: u16,
    target: SocketAddrV4,
}

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
}

fn parse_args() -> Result<Config, String> {
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
    // G1 primary = the nft flow_obs mirror (gating test passed 2026-09-02);
    // /proc stays reachable as the fallback (--cdc proc).
    let mut cdc_kind = CdcKind::Nft;

    let args: Vec<String> = std::env::args().collect();
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
    })
}

fn usage() {
    eprintln!(
        "ds-lite-punch --static-map R=ip:port [--static-map ...] \
         [--stun host:port,host:port] [--interval 2] [--gateway 192.168.0.1] \
         [--state-dir /run/ds-lite-punch] [--slot-port-range LO-HI] \
         [--max-slots 32] [--max-maps-per-client 16] \
         [--gc-grace-factor 3] [--observation] [--max-rescues 8] \
         [--cdc proc|nft|aya]\n\
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

async fn keepalive_loop(
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
/// single socket, same forward path).
async fn run_slot(
    sock: Arc<UdpSocket>,
    state: Arc<Mutex<State>>,
    target: SocketAddrV4,
    publisher: Arc<Publisher>,
    bind_port: u16,
    interval: Duration,
    phase_ms: u32,
) {
    let ka_sock = sock.clone();
    let ka_state = state.clone();
    tokio::spawn(async move {
        keepalive_loop(ka_sock, ka_state, interval, phase_ms).await;
    });

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
    // respawn cycle is stable.
    let persisted_snapshot: Vec<PersistedSlot> = table
        .slots()
        .iter()
        .map(|s| match s.lease {
            slot::Lease::Static => PersistedSlot {
                bind_port: s.bind_port,
                proto: s.proto.code(),
                kind: 0,
                client: Ipv4Addr::UNSPECIFIED,
                int_port: 0,
                bookkeeping_ext_port: 0,
                granted_lifetime: 0,
                expires_at_unix: 0,
                created_at_unix: now,
            },
            slot::Lease::Granted {
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
                created_at_unix: now,
            },
        })
        .collect();
    if let Err(e) = write_leases(persist_dir, &persisted_snapshot) {
        eprintln!("warn: persist leases failed: {}", e);
    }

    // B9 GC ticker: scan every 60 s; free granted leases expired past
    // (grace_factor x 60 s) with no inbound activity. Statics never GC. The
    // per-slot teardown (element delete, socket close) is owned by the
    // facade layer for granted leases (D/E); today the table only holds
    // statics, so this logs at most. Holds the table lock briefly.
    // Snapshot the slots before the table is moved into the GC task:
    // pins, accepts and slot tasks are all driven from this frozen set
    // (facade-added leases get their own spawn path in D/E).
    let slots_snapshot: Vec<slot::Slot> = table.slots().to_vec();
    {
        let table = Arc::new(tokio::sync::Mutex::new(table));
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
                    eprintln!("gc: freed slots {:?} (no refresh, no traffic, past grace)", freed);
                }
            }
        });
    }

    let publisher = Arc::new(Publisher::new(&cfg.state_dir));
    let state = Arc::new(Mutex::new(State::new(servers)));
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
        tokio::spawn(async move {
            run_slot(sock, state, target, publisher, bind_port, interval, phase_ms).await
        });
    }

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
    // SIGTERM on stop — the daemon makes no graceful-shutdown guarantees;
    // the init script's stop() removes the nft ruleset (B8).
    std::future::pending::<()>().await;
}
