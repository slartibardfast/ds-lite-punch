//! CGNAT-aware UDP relay: one socket per slot keeps the AFTR mapping alive and forwards inbound to br-lan.
mod cdc;
mod ct;
mod dp;
mod engine;
mod forward;
mod keepalive;
mod mapping;
mod nft;
mod obs;
mod pcp;
mod presence;
mod persist;
mod publish;
mod slot;
mod stun;
mod tcpslot;
mod upnp;
mod upnpsvc;
mod vote;
mod carrier;

use cdc::CdcKind;
use mapping::State;
use nft::{ensure_flow_obs, ensure_ruleset};
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
use crate::publish::{emiteln, emitln};

/// Format a static-map/restore rejection; the enum stays heap-free for the Kani proofs.
fn fmt_static_err(e: StaticMapErr, lo: u16, hi: u16) -> String {
    match e {
        StaticMapErr::OutOfRange { port } => {
            format!("static bind port {} outside slot range {}-{}", port, lo, hi)
        }
        StaticMapErr::InUse { port } => format!("static bind port {} already in use", port),
    }
}

/// One static mapping R=ip:port (UDP), from `--static-map` or the legacy pair.
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
    max_refresh_attempts: u32,
    cdc: CdcKind,
    /// The devices the keepalive acts for; empty means nobody.
    allow: Vec<Ipv4Addr>,
    /// Whether the keepalive holds; without `--keepalive` the arm only reports what it would act on.
    hold: bool,
    /// The PCP and NAT-PMP listener on the shared port; opt-in because PCP is private.
    pcp: bool,
    /// Whether the PCP PEER opcode is answered; the filtering here is endpoint-independent.
    pcp_peer: bool,
    // UPnP IGD facade: br-lan only.
    upnp_enabled: bool,
    upnp_port: u16,
    lan_ip: Ipv4Addr,
    upnp_name: String,
    /// The carrier watch: count the marked probe, over this interval, misses and poll cadence.
    carrier_probe: bool,
    carrier_probe_interval: u64,
    carrier_probe_misses: u64,
    carrier_probe_poll: u64,
}

fn parse_args() -> Result<Config, String> {
    parse_args_from(std::env::args().collect())
}

/// The parser with its argv supplied, so the repeatable `--static-map` form is testable.
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
    let mut max_refresh_attempts: u32 = 8;
    let mut allow = Vec::new();
    let mut hold = false;
    let mut pcp = false;
    let mut pcp_peer = false;
    let mut upnp_enabled = true;
    let mut upnp_port: u16 = upnp::UPNP_DEFAULT_PORT;
    let mut lan_ip = DEFAULT_LAN_IP;
    let mut upnp_name = "ds-lite-punch IGD".to_string();
    let mut carrier_probe = false;
    let mut carrier_probe_interval: u64 = 900;
    let mut carrier_probe_misses: u64 = 3;
    let mut carrier_probe_poll: u64 = 5;
    // the nft flow_obs mirror is the default; /proc stays reachable as the fallback
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
                // R=ip:port — the repeatable multi-instance form
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
            "--max-refresh-attempts" => {
                max_refresh_attempts = v()?.parse().map_err(|e| format!("--max-refresh-attempts: {}", e))?;
                i += 2
            }
            "--allowlist" => {
                // one IPv4 address per line, with # comments; read here so a typo fails the start
                let allow_path = v()?;
                let text = std::fs::read_to_string(&allow_path)
                    .map_err(|e| format!("--allowlist {}: {}", allow_path, e))?;
                let (list, bad) = keepalive::parse(&text);
                if !bad.is_empty() {
                    return Err(format!(
                        "--allowlist {}: not an address: {}",
                        allow_path,
                        bad.join(", ")
                    ));
                }
                allow = list;
                i += 2
            }
            "--keepalive" => {
                hold = true;
                i += 1
            }
            "--pcp" => {
                pcp = true;
                i += 1
            }
            "--pcp-peer" => {
                pcp_peer = true;
                i += 1
            }
            "--carrier-probe" => {
                carrier_probe = true;
                i += 1
            }
            "--carrier-probe-interval" => {
                carrier_probe_interval = v()?
                    .parse()
                    .map_err(|e| format!("--carrier-probe-interval: {}", e))?;
                i += 2
            }
            "--carrier-probe-misses" => {
                carrier_probe_misses = v()?
                    .parse()
                    .map_err(|e| format!("--carrier-probe-misses: {}", e))?;
                i += 2
            }
            "--carrier-probe-poll" => {
                carrier_probe_poll = v()?
                    .parse()
                    .map_err(|e| format!("--carrier-probe-poll: {}", e))?;
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
            "-V" | "--version" => {
                // the same value tools/argdoc reads from the manifest, so the two cannot disagree
                emitln!("ds-lite-punch {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--ct-probe" => {
                // diagnostic: bisect the netlink CT_DELETE encoding against a self-created entry, then exit
                crate::ct::self_test();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {}", other)),
        }
    }

    // the legacy --bind/--target pair is one static map
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
        max_refresh_attempts,
        cdc: cdc_kind,
        allow,
        hold,
        pcp,
        pcp_peer,
        upnp_enabled,
        upnp_port,
        lan_ip,
        upnp_name,
        carrier_probe,
        carrier_probe_interval,
        carrier_probe_misses,
        carrier_probe_poll,
    })
}

/// The help text, generated by tools/argdoc; the flag-coverage test holds it to the parser.
const HELP: &str = include_str!("help.txt");

/// Print the help text, without the trailing newline `emitln!` adds.
fn usage() {
    emitln!("{}", HELP.trim_end());
}

/// The rejected-command-line path: stderr, so a procd log keeps the text beside the error.
fn usage_err() {
    emiteln!("{}", HELP.trim_end());
}

/// Force each STUN server's IP out the VM line; the default route would map the wrong NAT.
fn add_stun_routes(servers: &[SocketAddrV4], gateway: &str) {
    for s in servers {
        let status = Command::new("ip")
            .args(["route", "replace", &s.ip().to_string(), "via", gateway])
            .status();
        match status {
            Ok(st) if st.success() => {}
            Ok(st) => emiteln!("warn: ip route replace {} via {} -> {}", s.ip(), gateway, st),
            Err(e) => emiteln!("warn: ip route replace failed: {}", e),
        }
    }
}

/// Dedicated table for the relay's tuple-sourced egress; the main table's default is the wrong line.
const EGRESS_TABLE: &str = "1001";
const EGRESS_PRIO: &str = "25100";
/// The last-seen stamp interval: one write per slot per 15 s, ample for a 24 h grace.
const LEASE_STAMP_MIN_S: u64 = 15;

/// Force tuple-sourced egress out the VM line: a policy rule into the dedicated table.
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
            emiteln!("warn: ip rule egress {} -> {}", from, st);
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
            Err(e) => emiteln!("warn: resolve {} failed: {}", h, e),
        }
    }
    out
}

/// The slot keepalive loop; the caller owns the JoinHandle so a teardown can abort it.
pub(crate) async fn keepalive_loop(
    sock: Arc<UdpSocket>,
    state: Arc<Mutex<State>>,
    interval: Duration,
    phase_ms: u32,
) {
    // stagger slot i at (i * 2000/N) ms so N slots never burst one STUN server at once
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
            emiteln!("warn: keepalive send to {} failed: {}", server, e);
        }
        let rotated = state.lock().await.note_silence();
        if rotated {
            emiteln!(
                "keepalive: STUN server unresponsive, rotated to {}",
                state.lock().await.current_server()
            );
        }
    }
}

/// One slot's recv loop on its own socket; the caller spawns the keepalive and owns both handles.
pub(crate) async fn run_slot(
    sock: Arc<UdpSocket>,
    state: Arc<Mutex<State>>,
    table: Arc<Mutex<LeaseTable>>,
    target: SocketAddrV4,
    publisher: Arc<Publisher>,
    bind_port: u16,
) {
    // STUN majority vote: publication needs two servers to agree; one dissent marks suspect
    let vote = Arc::new(Mutex::new(VoteState::new()));

    // recv loop: classify STUN responses vs peer data; forward the latter.
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                emiteln!("warn: recv failed: {}", e);
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
                // health bookkeeping first: any valid response clears silence, whatever the vote decides
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
            // peer data reaching the client means the mapping is in use: stamp the last-seen clock
            {
                let mut t = table.lock().await;
                t.stamp_activity_if_stale(bind_port, Epoch::now(), LEASE_STAMP_MIN_S);
            }
            if let Err(e) = forward::forward(pkt, src_v4, target) {
                emiteln!("warn: forward {} -> {} failed: {}", src_v4, target, e);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            emiteln!("error: {}", e);
            usage_err();
            std::process::exit(2);
        }
    };

    let servers = resolve_stun(&cfg.stun).await;
    if servers.is_empty() {
        emiteln!("fatal: no STUN servers resolved");
        std::process::exit(1);
    }
    add_stun_routes(&servers, &cfg.gateway);
    add_egress_rule(&cfg.bind, &cfg.gateway);

    // the table is built entirely through restore(), so config statics are inserted exactly once
    let allocator = PortAllocator::new(cfg.slot_lo, cfg.slot_hi)
        .expect("slot range validated in parse_args");
    let mut table = LeaseTable::new(allocator, cfg.max_slots, cfg.max_maps_per_client);

    // the epoch survives a respawn (tmpfs) and resets on a reboot; leases.tsv re-binds the same Rs
    let persist_dir = Path::new(DEFAULT_DIR);
    let _ = load_epoch(persist_dir, Epoch::now());
    let now = Epoch::now();

    // respawn restore re-binds the same Rs before STUN; a grant colliding with a static is dropped
    let static_tuples: Vec<(u16, Ipv4Addr, u16)> = cfg
        .static_maps
        .iter()
        .map(|m| (m.bind_port, *m.target.ip(), m.target.port()))
        .collect();
    let static_rs: Vec<u16> = static_tuples.iter().map(|t| t.0).collect();
    let (persisted, skipped) = read_leases(persist_dir);
    if skipped > 0 {
        emiteln!("warn: {} malformed lease rows ignored", skipped);
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
        emiteln!(
            "fatal: lease table restore failed: {}",
            fmt_static_err(e, cfg.slot_lo, cfg.slot_hi)
        );
        std::process::exit(1);
    }

    // one projection of the table lives in persist::snapshot; the boot path must not keep a second copy
    let persisted_snapshot: Vec<persist::PersistedSlot> = snapshot(table.slots(), now);
    if let Err(e) = write_leases(persist_dir, &persisted_snapshot) {
        emiteln!("warn: persist leases failed: {}", e);
    }

    // GC scans every 60 s for leases expired past grace with no traffic; statics never GC

    // the slot list is frozen before the table moves, because the ruleset and tasks drive from it
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
                    emiteln!(
                        "gc: freed slots {:?} (no refresh, no traffic, past grace)",
                        freed
                    );
                }
            }
        });
    }

    // the tuple watch carries the last published external IP, seeded from the persisted tuple files
    let (ip_tx, ip_rx) =
        watch::channel(seed_external_ip(&cfg.state_dir, cfg.bind.port()));
    let publisher = Arc::new(Publisher::with_watch(&cfg.state_dir, ip_tx));
    let state = Arc::new(Mutex::new(State::new(servers.clone())));
    let target = cfg.target;

    // the ruleset installs once, then each slot gets the ingress translation and the accept, no pin
    if let Err(e) = ensure_ruleset() {
        emiteln!("fatal: nft ruleset install failed: {}", e);
        std::process::exit(1);
    }
    let bind_ip = match cfg.bind {
        SocketAddr::V4(v4) => *v4.ip(),
        _ => Ipv4Addr::new(192, 168, 0, 21),
    };
    // a restored slot gets what a fresh grant installs: the ingress translation and the accept, no pin
    for s in &slots_snapshot {
        if let Err(e) =
            nft::grant_datapath(s.target, s.target_port, s.bind_port, s.proto == slot::Proto::Tcp)
        {
            emiteln!(
                "fatal: nft grant_datapath {}:{} -> {} failed: {}",
                s.target, s.target_port, s.bind_port, e
            );
            std::process::exit(1);
        }
    }

    emitln!(
        "{{\"event\":\"start\",\"bind\":\"{}\",\"target\":\"{}\",\"stun_servers\":{},\"slots\":{}}}",
        cfg.bind,
        target,
        state.lock().await.servers.len(),
        slots_snapshot.len()
    );

    // stagger slot i at (i * 2000/N) ms; a single slot keeps no stagger
    let n = slots_snapshot.len() as u32;
    let interval = cfg.interval;
    for (i, s) in slots_snapshot.iter().enumerate() {
        // in facade mode the facade owns granted leases; a second spawn here would double-bind the socket
        if cfg.upnp_enabled && !s.is_static() {
            continue;
        }
        if s.proto == slot::Proto::Tcp {
            // a TCP slot: a listener on its bind port, and a STUN-over-TCP connection that publishes its tuple
            let listener = match tcpslot::bind_pin(s.bind_port).await {
                Ok(l) => l,
                Err(e) => {
                    emiteln!(
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
            tokio::spawn(tcpslot::run_connection(
                bind_ip, bind_port, servers, vote, publisher,
            ));
            continue;
        }
        let sock = Arc::new(
            match UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(bind_ip, s.bind_port))).await {
                Ok(sk) => sk,
                Err(e) => {
                    emiteln!("fatal: bind slot {}:{} failed: {}", bind_ip, s.bind_port, e);
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
        // the keepalive is a sibling task; the caller owns both handles so a revocation can abort them
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

    // the UPnP IGD facade on br-lan: SSDP, description, SOAP and GENA, and it owns granted leases
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
                emitln!(
                    "{{\"event\":\"upnp\",\"lan\":\"{}:{}\",\"udn\":\"uuid:{}\"}}",
                    cfg.lan_ip,
                    cfg.upnp_port,
                    f.udn()
                );
                Some(f)
            }
            Err(e) => {
                emiteln!("upnp: facade unavailable, continuing without it: {}", e);
                None
            }
        }
    } else {
        None
    };

    // the hold policy for the named devices: installed only when the hold is on, then read back
    if cfg.hold && !cfg.allow.is_empty() {
        match nft::apply_hold(&cfg.allow) {
            Ok(()) => {
                let in_force = nft::hold_in_force();
                emitln!(
                    "{{\"event\":\"hold\",\"devices\":{},\"ruleset_in_force\":{}}}",
                    cfg.allow.len(),
                    in_force
                );
                if !in_force {
                    emiteln!("hold: policy installed but not readable back from table ip dslp");
                }
            }
            Err(e) => emiteln!("hold: policy install failed (flows keep the router timeouts): {}", e),
        }
    }

    // --observation: the engine claims candidate flows with shadow sockets that keep the mapping alive
    if cfg.observation {
        // the engine never captures a tuple a static or lease slot already owns
        let owned: Vec<(Ipv4Addr, u16)> = slots_snapshot
            .iter()
            .map(|s| (bind_ip, s.bind_port))
            .collect();
        let cdc: Box<dyn cdc::Cdc> = match cfg.cdc {
            cdc::CdcKind::Proc => Box::new(cdc::ProcCdc::new(owned.clone(), cfg.max_refresh_attempts, cfg.allow.clone())),
            cdc::CdcKind::Nft => {
                // the flow_obs mirror installs only with --observation, so the default ruleset is unchanged
                if let Err(e) = ensure_flow_obs() {
                    emiteln!("fatal: nft flow_obs mirror install failed: {}", e);
                    std::process::exit(1);
                }
                Box::new(cdc::NftCdc::new(owned.clone(), cfg.max_refresh_attempts, cfg.allow.clone()))
            }
            cdc::CdcKind::Aya => {
                emiteln!("fatal: --cdc aya is not built yet");
                std::process::exit(2);
            }
        };
        let servers = state.lock().await.servers.clone();
        let mut engine = engine::ObservationEngine::new(
            cdc,
            owned,
            cfg.max_refresh_attempts,
            engine::DEFAULT_GRACE_TICKS,
            servers,
            publisher.clone(),
            Arc::new(engine::NftPins),
        );
        // a named device's flows are held; without --keepalive they are only reported
        engine.allow = cfg.allow.clone();
        engine.hold = cfg.hold;
        // the arm reads the live lease table, so a tuple a grant has taken is not one it captures
        engine.alloc = Some(table.clone());
        engine.bind_ip = bind_ip;
        let cdc_name = engine.name();
        tokio::spawn(async move {
            engine.run().await;
        });
        emitln!(
            "{{\"event\":\"observe\",\"cdc\":\"{}\",\"max_refresh_attempts\":{},\"allowed\":{},\"hold\":{}}}",
            cdc_name,
            cfg.max_refresh_attempts,
            cfg.allow.len(),
            cfg.hold
        );
    }

    // the carrier watch counts a cooperating helper's marked probe at the datapath
    if cfg.carrier_probe {
        if let Err(e) = nft::ensure_carrier_probe() {
            emiteln!(
                "warn: carrier watch install failed (nothing will be counted): {}",
                e
            );
        }
        let (interval, misses, poll) = (
            cfg.carrier_probe_interval,
            cfg.carrier_probe_misses,
            cfg.carrier_probe_poll,
        );
        tokio::spawn(async move {
            let epoch = || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            };
            let mut watch = carrier::Watch::new(epoch());
            emitln!(
                "{{\"event\":\"carrier-watch\",\"counter\":\"{}\",\"interval\":{},\"misses\":{},\"poll\":{}}}",
                nft::CARRIER_COUNTER,
                interval,
                misses,
                poll
            );
            let mut tick = tokio::time::interval(Duration::from_secs(poll.max(1)));
            loop {
                tick.tick().await;
                let now = epoch();
                // a firewall rebuild removes the counting rules, so reinstall them on every poll
                match nft::ensure_carrier_probe() {
                    Ok(true) => emitln!(
                        "{{\"event\":\"carrier-watch-reinstalled\",\"counter\":\"{}\",\"epoch\":{}}}",
                        nft::CARRIER_COUNTER,
                        now
                    ),
                    Ok(false) => {}
                    Err(e) => emiteln!("warn: carrier watch reinstall failed: {}", e),
                }
                let count = match nft::list_carrier_probe() {
                    Ok(c) => c,
                    Err(e) => {
                        emiteln!("warn: carrier watch: counter read failed: {}", e);
                        continue;
                    }
                };
                for ev in watch.poll(now, count, interval, misses) {
                    match ev {
                        carrier::Event::Probe { count } => emitln!(
                            "{{\"event\":\"carrier-probe\",\"count\":{},\"epoch\":{}}}",
                            count,
                            now
                        ),
                        carrier::Event::Silent { last_seen, waited } => emitln!(
                            "{{\"event\":\"carrier-silent\",\"last_probe\":{},\"waited\":{},\"epoch\":{}}}",
                            last_seen
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "null".to_string()),
                            waited,
                            now
                        ),
                    }
                }
            }
        });
    }

    // PCP and NAT-PMP on UDP 5351, LAN-only, opt-in, and it needs the facade for its grant machinery
    if cfg.pcp {
        match &facade {
            Some(f) => match tokio::net::UdpSocket::bind(SocketAddrV4::new(cfg.lan_ip, pcp::PORT)).await {
                Ok(sock) => {
                    let f = f.clone();
                    let peer = cfg.pcp_peer;
                    tokio::spawn(async move {
                        f.pcp_serve(sock, peer).await;
                    });
                    emitln!(
                        "{{\"event\":\"pcp\",\"bind\":\"{}:{}\",\"peer\":{}}}",
                        cfg.lan_ip,
                        pcp::PORT,
                        peer
                    );
                }
                Err(e) => {
                    emiteln!("fatal: pcp listener bind {}:{} failed: {}", cfg.lan_ip, pcp::PORT, e);
                    std::process::exit(1);
                }
            },
            None => {
                emiteln!("fatal: --pcp needs the facade (--no-upnp removes it)");
                std::process::exit(2);
            }
        }
    }

    // main stays alive; procd sends SIGTERM, and the facade's handler sends the byebye NOTIFYs first
    if let Some(facade) = &facade {
        let f = facade.clone();
        tokio::spawn(async move {
            // only a received SIGTERM exits: a failed registration must leave the default action in place
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

/// Seed the external-IP watch from the persisted tuple files: the last known value across respawns.
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

    /// Flags this parser takes and the help hides on purpose, because it is a diagnostic.
    const HIDDEN: &[&str] = &["--ct-probe"];

    /// Whether a token is written like a flag.
    fn is_flag_token(t: &str) -> bool {
        if let Some(rest) = t.strip_prefix("--") {
            !rest.is_empty() && rest.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        } else if let Some(rest) = t.strip_prefix('-') {
            rest.len() == 1 && rest.chars().all(|c| c.is_ascii_alphabetic())
        } else {
            false
        }
    }

    /// Every flag-like token in a block of text.
    fn flag_tokens(text: &str) -> std::collections::BTreeSet<String> {
        let cleaned: String = text
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { ' ' })
            .collect();
        cleaned
            .split_whitespace()
            .filter(|t| is_flag_token(t))
            .map(|t| t.to_string())
            .collect()
    }

    /// The flags this file's match arms take, read from the source so a new flag cannot hide.
    fn parser_flags_from_source() -> std::collections::BTreeSet<String> {
        let src = include_str!("main.rs");
        let arms = src.split("#[cfg(test)]").next().unwrap_or(src);
        arms.split('"')
            .skip(1)
            .step_by(2)
            .filter(|t| is_flag_token(t))
            .map(|t| t.to_string())
            .collect()
    }

    /// The CLI check: tools/argdoc's clap definition and this parser are one set of flags.
    #[test]
    fn the_help_names_exactly_the_flags_the_parser_takes() {
        let parser = parser_flags_from_source();
        let named = flag_tokens(HELP);
        for f in &parser {
            assert!(
                named.contains(f) || HIDDEN.contains(&f.as_str()),
                "the parser takes {} and the help does not name it",
                f
            );
        }
        for f in &named {
            assert!(
                parser.contains(f),
                "the help names {}, which this parser does not take",
                f
            );
        }
        assert!(
            named.len() > 25,
            "the help text looks too short to be the generated one: {} flags",
            named.len()
        );
    }

    /// Undo clap_mangen's roff escapes, so the page's text can be read.
    fn roff_text(roff: &str) -> String {
        roff.replace("\\fB", " ")
            .replace("\\fR", " ")
            .replace("\\fI", " ")
            .replace("\\*(Aq", "'")
            .replace("\\-", "-")
    }

    /// The manual page names the same flags as the help, and keeps the appended sections.
    #[test]
    fn the_man_page_names_the_flags_and_keeps_its_appended_sections() {
        let man = roff_text(include_str!("../deploy/man/ds-lite-punch.8"));
        let named = flag_tokens(&man);
        for f in parser_flags_from_source() {
            assert!(
                named.contains(&f) || HIDDEN.contains(&f.as_str()) || f == "-h" || f == "--help",
                "the manual does not name {}",
                f
            );
        }
        for section in ["ENVIRONMENT", "FILES", "LOG EVENTS", "LIMITS", "SEE ALSO"] {
            assert!(
                man.contains(&format!(".SH {}", section)),
                "the manual lost its {} section, so a regeneration dropped it",
                section
            );
        }
        assert!(
            !man.contains(".SH EXTRA"),
            "clap_mangen's EXTRA block is back, and the appended sections already cover it"
        );
        // the name is asserted in the fifth .TH field, where a reader sees it instead of the renderer's
        assert!(
            man.contains("\"\" \"Manual\""),
            "the manual's name is not in the header's fifth .TH field, so a reader \
             sees the renderer's name for the section instead of a neutral one"
        );
    }

    /// The multi-instance CLI contract: `--static-map` is repeatable, and the legacy pair is one entry.
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

    /// The keepalive's flags: the allowlist is validated at parse time, and the switches default off.
    #[test]
    fn the_allowlist_is_parsed_and_named() {
        let d = std::env::temp_dir().join(format!("dslp-allow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let good = d.join("good.allow");
        std::fs::write(&good, "# the consoles\n192.168.21.68\n192.168.21.138\n").unwrap();
        let c = parse_args_from(argv(&[
            "--static-map", "40000=192.168.0.21:40001",
            "--allowlist", good.to_str().unwrap(),
            "--keepalive",
            "--pcp",
            "--pcp-peer",
        ]))
        .expect("an allowlist with two addresses parses");
        assert_eq!(c.allow.len(), 2);
        assert_eq!(c.allow[0], "192.168.21.68".parse::<Ipv4Addr>().unwrap());
        assert!(c.hold && c.pcp && c.pcp_peer, "the switches are read");

        // the defaults: no list, no hold, no listener
        let c = parse_args_from(argv(&["--static-map", "40000=192.168.0.21:40001"]))
            .expect("the plain form parses");
        assert!(c.allow.is_empty() && !c.hold && !c.pcp && !c.pcp_peer);

        // a line that is not an address is refused, and the line is named
        let bad = d.join("bad.allow");
        std::fs::write(&bad, "192.168.21.68\n192.168.21.1/24\n").unwrap();
        let e = parse_args_from(argv(&[
            "--static-map", "40000=192.168.0.21:40001",
            "--allowlist", bad.to_str().unwrap(),
        ]))
        .expect_err("a malformed line is refused");
        assert!(e.contains("192.168.21.1/24"), "{}", e);

        // and an unreadable path is refused at parse time
        let e = parse_args_from(argv(&[
            "--static-map", "40000=192.168.0.21:40001",
            "--allowlist", d.join("absent.allow").to_str().unwrap(),
        ]))
        .expect_err("a missing file is refused");
        assert!(e.contains("absent.allow"), "{}", e);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn seed_external_ip_prefers_slot_over_aggregate() {
        // the seeded answer depends on the file order and the trim-before-split, so both are asserted here
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
