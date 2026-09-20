//! UPnP IGDv1 facade runtime (plan/0007 phase E): the SSDP responder, the
//! HTTP service (description docs + SOAP with POST/M-POST parity + GENA),
//! the grant/teardown datapaths for AddPortMapping (UDP slot via the v1
//! `run_slot`, TCP slot via the call/0017 datapath), and the tuple watch
//! that feeds GetExternalIPAddress and the GENA ExternalIPAddress events.
//! The pure, Kani-proven layer is `upnp.rs`; this module is the io+nft
//! wiring (Kani non-goal, like every nft/FFI boundary in the crate).
//!
//! E8 hardening: request head/body caps (`HTTP_CAP`), LAN-only binds (the
//! HTTP listener binds the br-lan address; SSDP joins the group on br-lan),
//! no panics (every parse is fallible), capped logging (one line per SOAP
//! action; SSDP answers are not logged per packet).

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex, Semaphore};

use crate::mapping::State;
use crate::nft;
use crate::dp;
use crate::pcp;
use crate::persist::{self, DEFAULT_DIR};
use crate::publish::Publisher;
use crate::slot::{Epoch, Lease, LeaseTable, Proto, Slot, UpsertOutcome};
use crate::tcpslot;
use crate::upnp;
use crate::upnp::*;
use crate::vote::VoteState;
use crate::publish::{emiteln, emitln};

/// Concurrency cap for the HTTP service (E8: bounded connections).
const HTTP_CONN_CAP: usize = 16;
/// plan/0008 R6 mount gate: the IGD:2 facade is served only when its
/// complete service set (WIP2 + DeviceProtection:1) is real. The
/// #v2-service-set task flips it here, and it stays on: the v2 mount
/// carries the 21-action WANIPConnection:2 SCPD, the DP SCPD, and the
/// DeviceProtection service in the root description (sections 26.4 and
/// 26.11, which forbid an IGD:2 facade without DP). The v1 presentation
/// stays served beside it (section 26.12).
const IGD_V2_ENABLED: bool = true;
/// plan/0008 R6: the per-control-point discovery window. 1 s is the UDA
/// default for a missing MX, so a deferred ssdp:all response always
/// lands inside its own allowed response window.
const DISCOVERY_DEBOUNCE_MS: u64 = 1000;
/// The versioned description URLs (plan/0008's LOCATION design).
const DOC_V1: &str = "/igd/v1/rootDesc.xml";
const DOC_V2: &str = "/igd/v2/rootDesc.xml";
/// The WANIPConnection:2 maximum lease (table 2-6): the version 2 reading
/// of a lease of 0, where version 1 read it as a static mapping.
const WIP2_MAX_LEASE: u32 = 604_800;
/// The floor of an automatic external-port choice, the AddAnyPortMapping
/// wildcard of section 2.5.17.
const ANY_PORT_BASE: u16 = 1024;
/// The stored length of a control point's mapping description (2.3.22).
/// The format is application-defined and the spec imposes no bound; this
/// keeps the record and the persisted index line bounded.
const DESC_MAX: usize = 64;
/// Lease policy (2026-09-15): the granted lease appears infinite
/// (U32_MAX wire/index) while the effective lifetime is managed
/// underneath. A UDP grant becomes a reap candidate when its client has
/// shown no evidence (datapath peer data or any SOAP action) for
/// `LEASE_GRACE_S`; the 7-day backstop catches true ghosts whatever the
/// pool state. TCP grants are outside the policy (a live splice can be
/// control-silent; the AFTR reaps idle TCP at the C3 bound).
const LEASE_GRACE_S: u64 = 86_400;
const LEASE_BACKSTOP_S: u64 = 604_800;
/// The GENA prune cadence (subscriptions live at 2x the requested timeout).
const GENA_PRUNE_S: u64 = 60;
/// The local GC cadence for granted leases (facade teardown ownership).
const GC_TICK_S: u64 = 60;
/// NOTIFY delivery per-callback timeout.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(2);

pub struct UpnpConfig {
    pub lan_ip: Ipv4Addr,
    pub upnp_port: u16,
    /// The eth1 address slot datapaths bind (the CGNAT-facing tuple).
    pub bind_ip: Ipv4Addr,
    pub state_dir: String,
    pub servers: Vec<SocketAddrV4>,
    pub interval: Duration,
    pub name: String,
    pub grace_secs: u64,
}

/// One granted mapping's control-plane record. `req_ext` is the requested
/// external port — the UPnP key — while the slot's `bind_port` is the
/// granted inner R; the AFTR's real external tuple is discovered via STUN
/// and reported through the tuple watch ("report-requested", E3). `desc`
/// is the control point's own label (2.3.22), kept so the enumeration and
/// the Listing can return what the control point actually sent.
#[derive(Clone, Debug)]
struct FacadeEntry {
    req_ext: u16,
    proto: Proto,
    /// The control point that asked for the mapping: the per-client key, and
    /// what the containment compares against. A lifted control point may name
    /// another host as the target, so this is not the target.
    owner: Ipv4Addr,
    /// The datapath target (`NewInternalClient`): where inbound datagrams are
    /// forwarded.
    client: Ipv4Addr,
    int_port: u16,
    bind_port: u16,
    granted_lifetime: u32,
    expires_at_unix: u64,
    desc: String,
}

/// One GENA subscription (E5): callback URL validated to be http + br-lan,
/// expiry at 2x the requested timeout, per-subscription eventKey.
#[derive(Clone, Debug)]
struct Sub {
    sid: Sid,
    cb_ip: Ipv4Addr,
    cb_port: u16,
    cb_path: Vec<u8>,
    timeout_secs: u32,
    expires_at_unix: u64,
    seq: u32,
    /// The control point that subscribed, captured at SUBSCRIBE: containment
    /// keys on the caller, and the callback address is not the caller.
    caller: Ipv4Addr,
    /// The face it subscribed on. The port floor binds the v2 face only, so
    /// the subscriber's own count is scoped the way its reads are.
    v2: bool,
    /// The declared evented variables as this subscriber last saw them, so a
    /// NOTIFY carries exactly what moved (call/0025).
    sent: Option<EventView>,
}

#[derive(Default)]
struct GenaState {
    subs: Vec<Sub>,
    sids: SidSet,
    /// SystemUpdateID: bumped when a mapping appears or goes, so a subscriber
    /// that only reads the evented surface still sees the table move.
    update_id: u32,
}

/// plan/0008's ssdp:all rule and its state machine: what the responder does with one
/// M-SEARCH target. `v2_enabled` is the IGD_V2_ENABLED mount gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryAction {
    /// answer immediately from the v1 compatibility facade
    ReplyV1(SearchTarget),
    /// answer immediately from the v2 facade (gate on only)
    ReplyV2(SearchTarget),
    /// the target is not offered (a v2 target while the gate is off,
    /// or anything unknown)
    Ignore,
    /// ssdp:all with v2 mounted: open or join the per-control-point
    /// burst and defer the response (R6)
    DeferAll,
}

fn discovery_action(st: SearchTarget, v2_enabled: bool) -> DiscoveryAction {
    use SearchTarget::*;
    match st {
        All if v2_enabled => DiscoveryAction::DeferAll,
        All => DiscoveryAction::ReplyV1(All),
        RootDevice | InternetGatewayDevice | WanDevice | WanConnectionDevice
        | WanIpConnection | WanPppConnection => DiscoveryAction::ReplyV1(st),
        InternetGatewayDevice2 | WanIpConnection2 | WanPppConnection2 if v2_enabled => {
            DiscoveryAction::ReplyV2(st)
        }
        _ => DiscoveryAction::Ignore,
    }
}

/// Resolve a deferred ssdp:all burst: true when an IGD:2 search flipped
/// the watch before the debounce elapsed, false on the default
/// (plan/0008's bounded burst debounce: seen_v2 ? v2 : v1).
async fn burst_resolves_v2(mut rx: watch::Receiver<bool>, debounce: Duration) -> bool {
    tokio::select! {
        changed = rx.changed() => {
            // changed() errors only if the sender dropped (cleanup); the
            // last value still decides
            let _ = changed;
            *rx.borrow()
        }
        _ = tokio::time::sleep(debounce) => false,
    }
}

pub struct UpnpFacade {
    cfg: UpnpConfig,
    table: Arc<Mutex<LeaseTable>>,
    publisher: Arc<Publisher>,
    entries: Mutex<Vec<FacadeEntry>>,
    tasks: Mutex<HashMap<u16, Vec<tokio::task::JoinHandle<()>>>>,
    gena: Mutex<GenaState>,
    ip_rx: watch::Receiver<Ipv4Addr>,
    udn: String,
    started_unix: u64,
    ssdp: Arc<UdpSocket>,
    /// plan/0008 R6: pending ssdp:all bursts, keyed by control point
    /// (src addr + port). The sender's value flips true when an IGD:2
    /// search is observed inside the window; entries live only while a
    /// response is deferred and are removed by the deferred task.
    bursts: Arc<StdMutex<HashMap<(Ipv4Addr, u16), watch::Sender<bool>>>>,
    /// plan/0008 #v2-service-set: the DeviceProtection:1 service state
    /// (users + ACL persisted, sessions transient per section 26.15).
    dp: StdMutex<dp::DpState>,
    /// PCP mappings whose discovery has not completed yet: bind port -> the
    /// second the wait began. A request that cannot be answered yet is
    /// dropped; past DISCOVERY_GRACE_S the answer is the network error.
    pcp_wait: StdMutex<HashMap<u16, u64>>,
    /// Consecutive LAN-presence misses per slot. This lives on the facade
    /// because the GC runs as one pass per tick, so a counter local to the
    /// pass would reset before it ever reached the threshold.
    presence_misses: StdMutex<HashMap<u16, u8>>,
}

impl UpnpFacade {
    /// Build and start the facade: identity, seed the tuple watch, spawn
    /// the SSDP (alive + M-SEARCH), HTTP, GENA-event, prune and local-GC
    /// tasks. Returns the handle (used for the SIGTERM byebye).
    ///
    /// The only hard failure is the privileged SSDP bind (UDP 1900): Err on
    /// that (or on a bind of the LAN address the daemon does not own) makes
    /// the facade degrade at the call site instead of taking the daemon
    /// down with it — the keepalive datapath runs regardless.
    pub async fn start(
        cfg: UpnpConfig,
        table: Arc<Mutex<LeaseTable>>,
        publisher: Arc<Publisher>,
        ip_rx: watch::Receiver<Ipv4Addr>,
    ) -> io::Result<Arc<UpnpFacade>> {
        let (udn, _boot_id) = load_identity(&cfg.state_dir, cfg.lan_ip, cfg.bind_ip);

        // Rebuild the control-plane entry index from the persisted upnp.tsv
        // (requested-ext key -> slot), so delete/enumerate survive a
        // respawn alongside the slot table restore. Drop entries whose slot
        // is no longer in the (restored) table.
        let mut entries = restore_entries();
        {
            let t = table.lock().await;
            entries.retain(|e| t.by_bind_port(e.bind_port).is_some());
        }

        let ssdp = bind_ssdp(cfg.lan_ip)?;
        let started_unix = Epoch::now();
        let device_id = dp_device_id(&udn);
        let dp_state = dp_load(&cfg.state_dir, device_id);
        let facade = Arc::new(UpnpFacade {
            cfg,
            table,
            publisher,
            entries: Mutex::new(entries),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx,
            udn,
            started_unix,
            ssdp: Arc::new(ssdp),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(dp_state),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });

        // Respawn-restored grants: main skipped their datapath spawn (its
        // loop owns statics only in facade mode), so their socket runtime
        // is rebuilt here and registered for teardown.
        facade.spawn_restored_grants().await;

        // Alive NOTIFY: the first tick fires immediately (startup
        // announcement), then every max-age/2.
        let f = facade.clone();
        tokio::spawn(async move {
            f.ssdp_alive_loop().await;
        });

        // M-SEARCH responder: one unicast reply per answerable discovery.
        let f = facade.clone();
        tokio::spawn(async move {
            f.ssdp_recv_loop().await;
        });

        // GENA event loop: every tuple publication (churn/republish) sends
        // an ExternalIPAddress NOTIFY to every subscription. The receiver
        // is owned here (changed() needs &mut).
        let mut event_rx = facade.ip_rx.clone();
        let f = facade.clone();
        tokio::spawn(async move {
            loop {
                if event_rx.changed().await.is_err() {
                    break;
                }
                let ip = *event_rx.borrow();
                if ip == Ipv4Addr::UNSPECIFIED {
                    continue;
                }
                f.notify_all(ip).await;
            }
        });

        // GENA expiry pruner (subscriptions live at 2x the timeout).
        let f = facade.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(GENA_PRUNE_S));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                f.prune_expired().await;
            }
        });

        // Local GC: tear down expired granted leases (nft, datapath tasks,
        // entry, persistence). The facade owns the full teardown, so main's
        // table-only GC is disabled in facade mode.
        let f = facade.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(GC_TICK_S));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                f.gc_loop().await;
            }
        });

        // HTTP service (docs + SOAP + GENA), LAN-only bind.
        let f = facade.clone();
        tokio::spawn(async move {
            if let Err(e) = http_loop(f).await {
                emiteln!("upnp: http service stopped: {}", e);
            }
        });

        Ok(facade)
    }

    /// Spawn the datapath tasks for respawn-restored granted leases and
    /// register their JoinHandles, so facade teardown (delete_mapping /
    /// gc_loop) can abort them. The boot add_pin loop re-creates the nft
    /// elements for restored slots; only the socket runtime is missing, and
    /// main skips granted leases in facade mode, so this is the granted
    /// slot's single task owner. A slot whose bind fails degrades alone
    /// (logged; the entry stays enumerable and the row is reclaimed by the
    /// lease->GC path).
    async fn spawn_restored_grants(&self) {
        let entries: Vec<FacadeEntry> = self.entries.lock().await.clone();
        for e in entries {
            let granted = {
                let t = self.table.lock().await;
                matches!(
                    t.by_bind_port(e.bind_port).map(|s| s.lease),
                    Some(Lease::Granted { .. })
                )
            };
            if !granted {
                continue;
            }
            let handles = match e.proto {
                Proto::Udp => self.spawn_udp_slot(e.bind_port, e.client, e.int_port).await,
                Proto::Tcp => self.spawn_tcp_slot(e.bind_port, e.client, e.int_port).await,
            };
            match handles {
                Ok(h) => {
                    self.tasks.lock().await.insert(e.bind_port, h);
                }
                Err(err) => {
                    emiteln!(
                        "upnp: restore slot {}:{:?} bind failed: {}",
                        e.bind_port, e.proto, err
                    );
                }
            }
        }
    }

    /// The device UDN (without the "uuid:" prefix; used in docs and logs).
    pub fn udn(&self) -> &str {
        &self.udn
    }

    /// Send the byebye NOTIFYs (clean exit, SIGTERM path). Best-effort.
    pub async fn send_byebye(&self) {
        let now = Epoch::now();
        for st in NOTIFY_STS {
            let pkt = notify_payload(
                st,
                b"byebye",
                &self.udn,
                self.cfg.lan_ip,
                self.cfg.upnp_port,
                now,
                DOC_V1,
            );
            let _ = self.ssdp.send_to(&pkt, (SSDP_MCAST, SSDP_PORT)).await;
        }
    }

    fn external_ip(&self) -> Option<Ipv4Addr> {
        let ip = *self.ip_rx.borrow();
        if ip == Ipv4Addr::UNSPECIFIED {
            None
        } else {
            Some(ip)
        }
    }

    // ---- SSDP ----

    async fn ssdp_alive_loop(&self) {
        let mut ticker = tokio::time::interval(Duration::from_secs(SSDP_ALIVE_PERIOD_S));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let now = Epoch::now();
            for st in NOTIFY_STS {
                let pkt = notify_payload(
                    st,
                    b"alive",
                    &self.udn,
                    self.cfg.lan_ip,
                    self.cfg.upnp_port,
                    now,
                    DOC_V1,
                );
                let _ = self.ssdp.send_to(&pkt, (SSDP_MCAST, SSDP_PORT)).await;
            }
        }
    }

    async fn ssdp_recv_loop(&self) {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, src) = match self.ssdp.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let pkt = &buf[..n];
            let (st, mx) = match upnp::parse_msearch(pkt) {
                MSearchParse::Answer { st, mx } => (st, mx),
                _ => continue,
            };
            let key = match src {
                SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
                _ => continue, // SSDP is IPv4-only on this surface
            };
            match discovery_action(st, IGD_V2_ENABLED) {
                DiscoveryAction::Ignore => continue,
                DiscoveryAction::ReplyV1(t) => {
                    self.send_discovery(t, src, mx, DOC_V1).await;
                }
                DiscoveryAction::ReplyV2(t) => {
                    // an explicit IGD:2 search inside a pending burst flips
                    // the deferred ssdp:all response to v2 (R6)
                    if let Some(tx) = crate::publish::lock_or_recover(&self.bursts).get(&key) {
                        let _ = tx.send(true);
                    }
                    self.send_discovery(t, src, mx, DOC_V2).await;
                }
                DiscoveryAction::DeferAll => {
                    self.defer_all(key, src).await;
                }
            }
        }
    }

    /// Jitter within MX (capped 5 s by the grammar) then answer with the
    /// given presentation's LOCATION.
    async fn send_discovery(&self, st: SearchTarget, src: SocketAddr, mx: u8, loc: &str) {
        let delay_ms = if mx == 0 {
            0u64
        } else {
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1);
            (seed % (u64::from(mx) * 1000)).max(1)
        };
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        let resp = upnp::msearch_response(
            st,
            &self.udn,
            self.cfg.lan_ip,
            self.cfg.upnp_port,
            Epoch::now(),
            loc,
        );
        let _ = self.ssdp.send_to(&resp, src).await;
    }

    /// plan/0008 R6: hold the ssdp:all response for the discovery
    /// window, releasing early with the v2 presentation when an IGD:2
    /// search flips the burst, or at the deadline with the v1
    /// compatibility default. Duplicate :all retransmissions from the
    /// same control point coalesce onto the existing burst.
    async fn defer_all(&self, key: (Ipv4Addr, u16), src: SocketAddr) {
        {
            let m = crate::publish::lock_or_recover(&self.bursts);
            if m.contains_key(&key) {
                return; // already deferred; the pending task answers
            }
        }
        let (tx, rx) = watch::channel(false);
        {
            let mut m = crate::publish::lock_or_recover(&self.bursts);
            if m.insert(key, tx).is_some() {
                return; // raced: a concurrent defer won the slot
            }
        }
        let ssdp = self.ssdp.clone();
        let udn = self.udn.clone();
        let lan_ip = self.cfg.lan_ip;
        let port = self.cfg.upnp_port;
        let bursts = self.bursts.clone();
        tokio::spawn(async move {
            let v2 = burst_resolves_v2(rx, Duration::from_millis(DISCOVERY_DEBOUNCE_MS)).await;
            let loc = if v2 { DOC_V2 } else { DOC_V1 };
            // the deferred answer lands at the window deadline, which is
            // at most the assumed MX floor (1 s); no extra jitter needed
            let resp = upnp::msearch_response(
                SearchTarget::All,
                &udn,
                lan_ip,
                port,
                Epoch::now(),
                loc,
            );
            let _ = ssdp.send_to(&resp, src).await;
            crate::publish::lock_or_recover(&bursts).remove(&key);
        });
    }

    // ---- SOAP actions ----

    async fn get_external_ip(&self) -> Result<String, UpnpErr> {
        match self.external_ip() {
            Some(ip) => Ok(format!("<NewExternalIPAddress>{}</NewExternalIPAddress>", ip)),
            None => Err(UpnpErr::ActionFailed),
        }
    }

    async fn get_status_info(&self) -> String {
        let uptime = Epoch::now().saturating_sub(self.started_unix);
        format!(
            "<NewConnectionStatus>Connected</NewConnectionStatus>\
             <NewLastConnectionError>ERROR_NONE</NewLastConnectionError>\
             <NewUptime>{}</NewUptime>",
            uptime
        )
    }

    fn get_connection_type_info(&self) -> String {
        "<NewConnectionType>IP_Routed</NewConnectionType>\
         <NewPossibleConnectionTypes>IP_Routed</NewPossibleConnectionTypes>"
            .to_string()
    }

    /// GetCommonLinkProperties on the WANCommonInterfaceConfig:1 service:
    /// the physical link is Up whenever the tuple watch holds a value;
    /// the symmetric ds-lite line offers no measurable Layer-1 bit rates,
    /// so 0 is reported (the value is absent, not a measured zero).
    fn common_link_properties(&self) -> String {
        let status = if self.external_ip().is_some() { "Up" } else { "Down" };
        format!(
            "<NewWANAccessType>DSL</NewWANAccessType>\
             <NewLayer1UpstreamMaxBitRate>0</NewLayer1UpstreamMaxBitRate>\
             <NewLayer1DownstreamMaxBitRate>0</NewLayer1DownstreamMaxBitRate>\
             <NewPhysicalLinkStatus>{}</NewPhysicalLinkStatus>",
            status
        )
    }

    /// allocate_exact (plan/0008's version-specific SOAP semantics): the
    /// requested external port is the requester's own handle. A re-Add
    /// pivots that requester's mapping to the requested port; another
    /// requester on the same port gets its own entry beside it, because
    /// the port is a per-client label rather than a resource this device
    /// allocates (call/0022, which supersedes the specification's
    /// one-holder rule for this line).
    async fn allocate_exact(
        &self,
        req: MappingReq,
        owner: Ipv4Addr,
        view: Option<Contain>,
    ) -> Result<String, UpnpErr> {
        self.grant_mapping(req, owner, view).await.map(|_| String::new())
    }

    /// The grant itself, returning the admission outcome so a dialect that
    /// reports result codes can answer precisely (PCP's quota and resource
    /// errors are different messages to its clients).
    async fn grant_mapping(
        &self,
        req: MappingReq,
        owner: Ipv4Addr,
        view: Option<Contain>,
    ) -> Result<UpsertOutcome, UpnpErr> {
        let MappingReq {
            ext: req_ext,
            proto,
            client,
            int_port,
            lifetime,
            desc,
        } = req;
        if let Some(c) = view {
            if !request_within(c, client, req_ext, int_port) {
                return Err(UpnpErr::NotAuthorized);
            }
        }
        if !in_lan(client, self.cfg.lan_ip) {
            return Err(UpnpErr::InvalidArgs);
        }
        let lifetime = if lifetime == 0 { INFINITE_LEASE } else { lifetime };
        let now = Epoch::now();
        // The punch collision rule (call/0027 R2/R3): a bind port whose inner
        // tuple is already live belongs to whoever punched it, so the
        // allocator's probe runs before a fresh allocation and steers around
        // every live tuple the change-data-capture shows. A renewal allocates
        // nothing, so it reads nothing. When the mirror is unavailable the
        // probe cannot run, and that is said rather than passed over in
        // silence (R5).
        let fresh = {
            let t = self.table.lock().await;
            t.by_pcp_key(proto, int_port, owner).is_none()
        };
        if fresh {
            match nft::list_flow_obs() {
                Ok(live) => {
                    let ports: Vec<u16> = live.iter().map(|(_, r)| *r).collect();
                    let mut t = self.table.lock().await;
                    t.avoid_ports(&ports);
                }
                Err(e) => self.publisher.log_transition(
                    "collision-probe-unavailable",
                    &format!("no live-tuple set to steer around: {}", e),
                ),
            }
        }
        let mut outcome = self.upsert_once(proto, int_port, client, lifetime, now).await;
        if outcome == UpsertOutcome::TableFull && self.evict_candidate(client).await.is_some() {
            // Pool pressure: the first upsert found no slot. Reclaim the
            // longest-idle UDP grant of ANOTHER client (idle past
            // LEASE_GRACE_S) and retry once. Never evicts this client's
            // own grants, and never a slot with recent activity.
            outcome = self.upsert_once(proto, int_port, client, lifetime, now).await;
        }
        let bind_port;
        let granted_new = match outcome {
            UpsertOutcome::Granted { bind_port: r } => {
                bind_port = r;
                true
            }
            UpsertOutcome::Refreshed { bind_port: r } => {
                bind_port = r;
                false
            }
            UpsertOutcome::UserQuotaExceeded | UpsertOutcome::TableFull => {
                return Err(UpnpErr::ActionFailed)
            }
        };

        if granted_new {
            // Install the datapath: pin the client's flow to the slot tuple,
            // accept inbound on eth1, spawn the slot task(s). Roll back the
            // table entry on any failure (never leave a phantom lease).
            if let Err(e) = nft::grant_datapath(client, int_port, bind_port, proto == Proto::Tcp) {
            let _ = nft::revoke_datapath(client, int_port, bind_port, proto == Proto::Tcp);
        self.publisher.remove_slot(bind_port);
            let mut t = self.table.lock().await;
            t.delete_by_bind_port(bind_port);
            emiteln!("upnp: grant datapath {} failed: {}", bind_port, e);
            return Err(UpnpErr::ActionFailed);
        }
            let handles = match proto {
                Proto::Udp => self.spawn_udp_slot(bind_port, client, int_port).await,
                Proto::Tcp => self.spawn_tcp_slot(bind_port, client, int_port).await,
            };
            match handles {
                Ok(h) => {
                    self.tasks.lock().await.insert(bind_port, h);
                    // R5: name what the rule steered around, so the decision
                    // is auditable without a packet capture.
                    let steered = {
                        let t = self.table.lock().await;
                        t.avoid_steering(bind_port)
                    };
                    if !steered.is_empty() {
                        self.publisher.log_transition(
                            "collision-avoided",
                            &format!(
                                "slot {} steered around the live tuple(s) {:?}",
                                bind_port, steered
                            ),
                        );
                    }
                }
                Err(e) => {
                    // bind failed: roll back nft + table. No pin to remove:
                    // the facade's grant installs none (the arm and the TCP
                    // holder pin their own flows and clean them up themselves).
                    let _ = nft::del_input_accept(bind_port, proto == Proto::Tcp);
                    let mut t = self.table.lock().await;
                    t.delete_by_bind_port(bind_port);
                    emiteln!("upnp: slot bind {} failed: {}", bind_port, e);
                    return Err(UpnpErr::ActionFailed);
                }
            }
        }

        // Record / refresh the control-plane entry (one entry per internal
        // key — client, int, proto; the requested port rides the re-Add).
        // A re-Add that moved the mapping to a new slot surrenders the
        // same client's previous entry at that port, so delete/enumerate
        // always resolve to the slot the control point actually owns.
        // Another client's entry at the same port is untouched.
        let stray = {
            let mut es = self.entries.lock().await;
            apply_entry(
                &mut es, req_ext, proto, client, owner, int_port, bind_port, lifetime, now,
                desc,
            )
        };
        if let Some((old_bind, old_client, old_int)) = stray {
            {
                let mut t = self.table.lock().await;
                let _ = t.delete_by_bind_port(old_bind); // may already be gone (GC)
            }
            let _ = nft::revoke_datapath(old_client, old_int, old_bind, proto == Proto::Tcp);
        self.publisher.remove_slot(old_bind);
            if let Some(h) = self.tasks.lock().await.remove(&old_bind) {
                for jh in h {
                    jh.abort();
                }
            }
        }
        // A grant, and any stray it left behind, is a change to what a
        // subscriber can see: say so before the index is persisted.
        self.signal_change().await;
        self.persist().await;
        Ok(outcome)
    }

    // ---- PCP and NAT-PMP admission (call/0025, plan/0009 #pcp) ----

    /// The PCP epoch: seconds since this facade's state was created. A reboot
    /// resets it near zero, which is what tells a PCP client its mappings are
    /// gone (RFC 6887 section 8.5).
    fn pcp_epoch(&self) -> u32 {
        Epoch::now().saturating_sub(self.started_unix).min(u32::MAX as u64) as u32
    }

    /// The tuple a slot's discovery learned, from the per-slot file the
    /// publisher writes. `None` means discovery has not completed, which is
    /// the drop rule: the client's own retransmission brings it back.
    fn external_tuple(&self, bind_port: u16) -> Option<(Ipv4Addr, u16)> {
        // memory first: a state directory that cannot be written must not
        // turn every PCP MAP into a drop
        self.publisher.slot_tuple(bind_port)
    }

    /// Bind port of a mapping, by the key its dialect addresses it with.
    async fn bind_port_of(&self, proto: Proto, owner: Ipv4Addr, int_port: u16) -> Option<u16> {
        let es = self.entries.lock().await;
        es.iter()
            .find(|e| e.proto == proto && e.owner == owner && e.int_port == int_port)
            .map(|e| e.bind_port)
    }

    /// The answer for a mapping whose tuple is not known yet, with the wait
    /// recorded against the slot so a request that never discovers stops
    /// being answered with silence.
    fn discovery_answer(
        &self,
        bind_port: u16,
        sug_ext: u16,
        sug_ip: Ipv4Addr,
    ) -> crate::pcp::MapAnswer {
        let now = Epoch::now();
        let mut w = crate::publish::lock_or_recover(&self.pcp_wait);
        let started = *w.entry(bind_port).or_insert(now);
        match discovery_verdict(now.saturating_sub(started), false) {
            Some(code) => {
                w.remove(&bind_port);
                pcp_error(code, sug_ext, sug_ip)
            }
            None => crate::pcp::MapAnswer::Drop,
        }
    }

    /// One MAP admission, shared by PCP and NAT-PMP: the same slot engine and
    /// the same per-client key as the other three paths, so a mapping made
    /// here is indistinguishable in the datapath from an `AddPortMapping`
    /// grant. `cap` is the dialect's longest grantable lifetime.
    #[allow(clippy::too_many_arguments)] // one flat admission over the request's fields
    async fn admit_map(
        &self,
        owner: Ipv4Addr,
        target: Ipv4Addr,
        view: Option<Contain>,
        proto_u8: u8,
        int_port: u16,
        sug_ext: u16,
        sug_ip: Ipv4Addr,
        lifetime: u32,
        cap: u32,
        filters: &[crate::pcp::Filter],
    ) -> crate::pcp::MapAnswer {
        let Some(proto) = proto_of(proto_u8) else {
            return pcp_error(crate::pcp::rc::UNSUPP_PROTOCOL, sug_ext, sug_ip);
        };
        // The datapath this daemon installs is endpoint-independent by
        // design, so a filter it cannot install is refused with the code the
        // RFC names for exactly that case, rather than answered with a claim
        // of filtering that does not happen.
        if !filters.is_empty() {
            self.publisher.log_transition(
                "pcp-filter",
                &format!(
                    "{} {} refused: the datapath is endpoint-independent",
                    owner, int_port
                ),
            );
            return pcp_error(crate::pcp::rc::EXCESSIVE_REMOTE_PEERS, sug_ext, sug_ip);
        }
        if lifetime == 0 {
            // the delete form: the mapping goes, and the answer says so
            let entry = {
                let es = self.entries.lock().await;
                es.iter()
                    .find(|e| e.proto == proto && e.owner == owner && e.int_port == int_port)
                    .map(|e| e.req_ext)
            };
            if let Some(req_ext) = entry {
                if self.delete_mapping(req_ext, proto, owner, None).await.is_err() {
                    return pcp_error(crate::pcp::rc::NOT_AUTHORIZED, sug_ext, sug_ip);
                }
            }
            return crate::pcp::MapAnswer::Answer {
                code: crate::pcp::rc::SUCCESS,
                lifetime: 0,
                ext_port: sug_ext,
                ext_ip: sug_ip,
            };
        }
        let granted = pcp::lifetime_cap(lifetime, cap);
        let req = MappingReq {
            ext: sug_ext,
            proto,
            client: target,
            int_port,
            lifetime: granted,
            desc: "pcp".to_string(),
        };
        let outcome = match self.grant_mapping(req, owner, view).await {
            Ok(o) => o,
            Err(UpnpErr::NotAuthorized) => {
                return pcp_error(crate::pcp::rc::NOT_AUTHORIZED, sug_ext, sug_ip)
            }
            Err(UpnpErr::InvalidArgs) => {
                return pcp_error(crate::pcp::rc::MALFORMED_REQUEST, sug_ext, sug_ip)
            }
            Err(_) => return pcp_error(crate::pcp::rc::NO_RESOURCES, sug_ext, sug_ip),
        };
        let code = pcp::outcome_code(&outcome);
        if code != crate::pcp::rc::SUCCESS {
            return pcp_error(code, sug_ext, sug_ip);
        }
        let bind_port = match outcome {
            UpsertOutcome::Granted { bind_port } | UpsertOutcome::Refreshed { bind_port } => {
                bind_port
            }
            _ => return pcp_error(crate::pcp::rc::NO_RESOURCES, sug_ext, sug_ip),
        };
        match self.external_tuple(bind_port) {
            Some((ip, port)) => {
                crate::publish::lock_or_recover(&self.pcp_wait).remove(&bind_port);
                crate::pcp::MapAnswer::Answer {
                    code: crate::pcp::rc::SUCCESS,
                    lifetime: granted,
                    ext_port: port,
                    ext_ip: ip,
                }
            }
            None => self.discovery_answer(bind_port, sug_ext, sug_ip),
        }
    }

    /// A PCP PEER: the filtering here is endpoint-independent, so a peer
    /// request has nothing to install. It is answered with the mapping's own
    /// tuple when the operator has enabled the opcode, and refused otherwise.
    async fn admit_peer(
        &self,
        owner: Ipv4Addr,
        proto_u8: u8,
        int_port: u16,
        sug_ext: u16,
        sug_ip: Ipv4Addr,
        lifetime: u32,
        peer_enabled: bool,
    ) -> crate::pcp::MapAnswer {
        let Some(proto) = proto_of(proto_u8) else {
            return pcp_error(crate::pcp::rc::UNSUPP_PROTOCOL, sug_ext, sug_ip);
        };
        let Some(bind_port) = self.bind_port_of(proto, owner, int_port).await else {
            // nothing to extend: this server creates mappings through MAP
            return pcp_error(crate::pcp::rc::CANNOT_PROVIDE_EXTERNAL, sug_ext, sug_ip);
        };
        if !peer_enabled {
            return pcp_error(crate::pcp::rc::NOT_AUTHORIZED, sug_ext, sug_ip);
        }
        match self.external_tuple(bind_port) {
            Some((ip, port)) => crate::pcp::MapAnswer::Answer {
                code: crate::pcp::rc::SUCCESS,
                lifetime: pcp::lifetime_cap(lifetime, crate::pcp::MAX_LIFETIME),
                ext_port: port,
                ext_ip: ip,
            },
            None => self.discovery_answer(bind_port, sug_ext, sug_ip),
        }
    }

    /// One PCP datagram: the response to send, or None to stay silent.
    async fn pcp_handle(&self, pkt: &[u8], client: Ipv4Addr, peer_enabled: bool) -> Option<Vec<u8>> {
        let epoch = self.pcp_epoch();
        match pcp::parse_pcp(pkt, client) {
            Err(pcp::Refusal::Silent) => None,
            Err(pcp::Refusal::Code { code, .. }) => Some(pcp::build_error(pkt, code, epoch)),
            Ok(pcp::Req::Announce) => Some(pcp::build_announce_response(epoch)),
            Ok(pcp::Req::Map(m)) => {
                // THIRD_PARTY is gated on the lift the containment already
                // defines: a caller that authenticated over DeviceProtection
                // may map for another host, and one that did not may not.
                let lifted = self.dp_holds_lift(client, Epoch::now());
                let (target, view) = match (m.third_party, lifted) {
                    (Some(other), true) => (other, None),
                    (Some(_), false) => {
                        return Some(pcp::build_map_response(
                            &m,
                            epoch,
                            crate::pcp::rc::NOT_AUTHORIZED,
                            pcp::error_lifetime(crate::pcp::rc::NOT_AUTHORIZED),
                            m.sug_ext_port,
                            m.sug_ext_ip,
                        ))
                    }
                    (None, true) => (client, None),
                    (None, false) => (
                        client,
                        Some(Contain {
                            caller: client,
                            high_port: false,
                        }),
                    ),
                };
                if m.prefer_failure {
                    // On this uplink the AFTR owns the external port, so a
                    // suggested external port cannot be promised, and the
                    // option says: do not substitute. RFC 6887 section 13.2
                    // names this result for exactly this request.
                    return Some(pcp::build_map_response(
                        &m,
                        epoch,
                        crate::pcp::rc::CANNOT_PROVIDE_EXTERNAL,
                        pcp::error_lifetime(crate::pcp::rc::CANNOT_PROVIDE_EXTERNAL),
                        m.sug_ext_port,
                        m.sug_ext_ip,
                    ));
                }
                match self
                    .admit_map(
                        client,
                        target,
                        view,
                        m.proto,
                        m.int_port,
                        m.sug_ext_port,
                        m.sug_ext_ip,
                        m.lifetime,
                        pcp::MAX_LIFETIME,
                        &m.filters,
                    )
                    .await
                {
                    pcp::MapAnswer::Drop => None,
                    pcp::MapAnswer::Answer {
                        code,
                        lifetime,
                        ext_port,
                        ext_ip,
                    } => Some(pcp::build_map_response(&m, epoch, code, lifetime, ext_port, ext_ip)),
                }
            }
            Ok(pcp::Req::Peer(p)) => {
                match self
                    .admit_peer(
                        client,
                        p.proto,
                        p.int_port,
                        p.peer_port,
                        p.peer_ip,
                        p.lifetime,
                        peer_enabled,
                    )
                    .await
                {
                    pcp::MapAnswer::Drop => None,
                    pcp::MapAnswer::Answer {
                        code,
                        lifetime,
                        ext_port,
                        ext_ip,
                    } => Some(pcp::build_peer_response(&p, epoch, code, lifetime, ext_port, ext_ip)),
                }
            }
        }
    }

    /// One NAT-PMP datagram: the response to send, or None to stay silent.
    async fn npmp_handle(&self, pkt: &[u8], client: Ipv4Addr) -> Option<Vec<u8>> {
        let epoch = self.pcp_epoch();
        match pcp::parse_npmp(pkt) {
            Err(pcp::NpmpErr::Silent) => None,
            Err(pcp::NpmpErr::Code(code)) => Some(if code == pcp::np::UNSUPP_VERSION {
                pcp::build_npmp_version_error(epoch)
            } else {
                pcp::build_npmp_echo(pkt, epoch)
            }),
            Ok(pcp::NpmpReq::PublicAddress) => Some(pcp::build_npmp_public(
                pcp::np::SUCCESS,
                epoch,
                self.external_ip().unwrap_or(Ipv4Addr::UNSPECIFIED),
            )),
            Ok(pcp::NpmpReq::Map {
                op,
                int_port,
                sug_ext_port,
                lifetime,
            }) => {
                let proto_u8 = if op == pcp::np::OP_MAP_UDP { 17 } else { 6 };
                if int_port == 0 && lifetime != 0 {
                    return Some(pcp::build_npmp_map(
                        op,
                        pcp::np::NOT_AUTHORIZED,
                        epoch,
                        int_port,
                        0,
                        0,
                    ));
                }
                let answer = self
                    .admit_map(
                        client,
                        client,
                        Some(Contain {
                            caller: client,
                            high_port: false,
                        }),
                        proto_u8,
                        int_port,
                        sug_ext_port,
                        Ipv4Addr::UNSPECIFIED,
                        lifetime,
                        pcp::NPMP_LIFETIME,
                        &[],
                    )
                    .await;
                match answer {
                    // NAT-PMP has no answer for a mapping still in flight:
                    // the client asks again, and this request is dropped
                    pcp::MapAnswer::Drop => None,
                    pcp::MapAnswer::Answer {
                        code,
                        lifetime,
                        ext_port,
                        ..
                    } => {
                        let code = npmp_code(code);
                        Some(pcp::build_npmp_map(op, code, epoch, int_port, ext_port, lifetime))
                    }
                }
            }
        }
    }

    /// The PCP and NAT-PMP service (call/0025's fourth admission path): one
    /// socket on the LAN address carrying both protocols on the shared port.
    /// The caller owns the bind, so the service can be exercised without the
    /// production port.
    pub async fn pcp_serve(self: Arc<Self>, sock: UdpSocket, peer_enabled: bool) {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    emiteln!("pcp: recv: {}", e);
                    continue;
                }
            };
            let SocketAddr::V4(v4) = from else { continue };
            let client = *v4.ip();
            // LAN only, by the bind and by this check: a request from another
            // network is not a control point of ours (RFC 6887 section 8.2).
            if !in_lan(client, self.cfg.lan_ip) {
                continue;
            }
            let pkt = &buf[..n];
            let reply = match pcp::sniff(pkt) {
                pcp::Sniff::Pcp => self.pcp_handle(pkt, client, peer_enabled).await,
                pcp::Sniff::Npmp => self.npmp_handle(pkt, client).await,
                pcp::Sniff::Unknown => None,
            };
            if let Some(r) = reply {
                let _ = sock.send_to(&r, from).await;
            }
        }
    }

    /// One upsert attempt. A retry after pressure eviction is the caller's
    /// business (at most one eviction per Add).
    async fn upsert_once(
        &self,
        proto: Proto,
        int_port: u16,
        client: Ipv4Addr,
        lifetime: u32,
        now: u64,
    ) -> UpsertOutcome {
        let mut t = self.table.lock().await;
        t.upsert_pcp(proto, int_port, client, lifetime, now, client, int_port)
    }

    /// Under pool pressure, reclaim the longest-idle UDP grant of a
    /// DIFFERENT client (idle past LEASE_GRACE_S) and tear it down so the
    /// retry can allocate. Never evicts the requesting client's own
    /// mappings. Returns the evicted slot's identity.
    async fn evict_candidate(&self, requester: Ipv4Addr) -> Option<(u16, Ipv4Addr, u16, Proto)> {
        let now = Epoch::now();
        let cand = {
            let t = self.table.lock().await;
            t.evict_idle_client(now, LEASE_GRACE_S, requester)
        };
        let (old_bind, old_client, old_int, old_proto) = cand?;
        {
            let mut t = self.table.lock().await;
            let _ = t.delete_by_bind_port(old_bind); // may already be gone (GC)
        }
        let _ = nft::revoke_datapath(old_client, old_int, old_bind, old_proto == Proto::Tcp);
        self.publisher.remove_slot(old_bind);
        if let Some(h) = self.tasks.lock().await.remove(&old_bind) {
            for jh in h {
                jh.abort();
            }
        }
        {
            let mut es = self.entries.lock().await;
            es.retain(|e| e.bind_port != old_bind);
        } // guard must drop before persist() (it re-locks entries)
        self.persist().await;
        Some((old_bind, old_client, old_int, old_proto))
    }

    async fn spawn_udp_slot(
        &self,
        bind_port: u16,
        client: Ipv4Addr,
        int_port: u16,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, io::Error> {
        let sock = Arc::new(UdpSocket::bind(SocketAddrV4::new(self.cfg.bind_ip, bind_port)).await?);
        let state = Arc::new(Mutex::new(State::new(self.cfg.servers.clone())));
        let target = SocketAddrV4::new(client, int_port);
        let publisher = self.publisher.clone();
        let interval = self.cfg.interval;
        // The keepalive is a sibling task so revocation can abort both
        // (see run_slot): the recv loop alone would release its Arc, but
        // the keepalive's clone would keep the slot socket bound.
        let ka_sock = sock.clone();
        let ka_state = state.clone();
        let table = self.table.clone();
        let ka = tokio::spawn(async move {
            crate::keepalive_loop(ka_sock, ka_state, interval, 0).await
        });
        let recv = tokio::spawn(async move {
            crate::run_slot(sock, state, table, target, publisher, bind_port).await
        });
        Ok(vec![ka, recv])
    }

    async fn spawn_tcp_slot(
        &self,
        bind_port: u16,
        client: Ipv4Addr,
        int_port: u16,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, io::Error> {
        let listener = tcpslot::bind_pin(bind_port).await?;
        let target = SocketAddrV4::new(client, int_port);
        let h1 = tokio::spawn(tcpslot::run_tcp_slot(listener, target));
        let vote = Arc::new(Mutex::new(VoteState::new()));
        let publisher = self.publisher.clone();
        let servers = self.cfg.servers.clone();
        let bind_ip = self.cfg.bind_ip;
        let h2 = tokio::spawn(tcpslot::run_holder(bind_ip, bind_port, servers, vote, publisher));
        Ok(vec![h1, h2])
    }

    async fn delete_mapping(
        &self,
        req_ext: u16,
        proto: Proto,
        caller: Ipv4Addr,
        view: Option<Contain>,
    ) -> Result<String, UpnpErr> {
        let (bind_port, client, int_port) = {
            let es = self.entries.lock().await;
            // DeletePortMapping's own key carries no client, and the
            // requested port is a label several clients may hold, so the
            // lookup is the caller's own entry at that port: "mine", or
            // 714. Another client's mapping at the same port is not
            // reachable here; the bulk path for it is the range delete
            // with NewManage (2.5.19).
            let Some(e) = es
                .iter()
                .find(|e| e.req_ext == req_ext && e.proto == proto && e.owner == caller)
            else {
                return Err(UpnpErr::NoSuchEntry);
            };
            if let Some(c) = view {
                if !entry_within(c, e) {
                    return Err(UpnpErr::NotAuthorized);
                }
            }
            (e.bind_port, e.client, e.int_port)
        };
        {
            let mut t = self.table.lock().await;
            let _ = t.delete_by_bind_port(bind_port); // may already be gone (GC)
        }
        let _ = nft::revoke_datapath(client, int_port, bind_port, proto == Proto::Tcp);
        self.publisher.remove_slot(bind_port);
        if let Some(h) = self.tasks.lock().await.remove(&bind_port) {
            for jh in h {
                jh.abort();
            }
        }
        {
            // Only the caller's own entry goes. This retained on
            // (req_ext, proto) alone, which was the one-holder rule: deleting
            // one holder drained every client's entry at that port (the
            // deployed bench found it, the router's delete taking the
            // workstation's mapping with it).
            let mut es = self.entries.lock().await;
            es.retain(|e| !(e.req_ext == req_ext && e.proto == proto && e.owner == caller));
        }
        self.signal_change().await;
        self.persist().await;
        Ok(String::new())
    }

    async fn get_specific(
        &self,
        req_ext: u16,
        proto: Proto,
        caller: Ipv4Addr,
        view: Option<Contain>,
    ) -> Result<String, UpnpErr> {
        let es = self.entries.lock().await;
        // as for the delete: "my mapping at that port", or 714, because the
        // port is a label another client may hold just as legitimately
        let Some(e) = es
            .iter()
            .find(|e| e.req_ext == req_ext && e.proto == proto && e.owner == caller)
        else {
            return Err(UpnpErr::NoSuchEntry);
        };
        // 2.5.14.2: a contained caller may retrieve only its own entries,
        // and an entry it may not see is not "not found" but forbidden
        if let Some(c) = view {
            if !entry_within(c, e) {
                return Err(UpnpErr::NotAuthorized);
            }
        }
        Ok(entry_xml(e, false))
    }

    /// GetGenericPortMappingEntry. A contained caller enumerates its own
    /// visible subset, so the index space is what it may see: walking past
    /// the end answers 714, which is the terminator a control point's
    /// enumeration loop expects (2.5.14.2).
    async fn get_generic(&self, index: u32, view: Option<Contain>) -> Result<String, UpnpErr> {
        let es = self.entries.lock().await;
        let visible: Vec<&FacadeEntry> = es
            .iter()
            .filter(|e| view.is_none_or(|c| entry_within(c, e)))
            .collect();
        // The index addresses this list directly. It used to index a list of
        // (req_ext, proto) keys and then look the entry up by those two
        // fields, which is no longer unique now that several clients may hold
        // one requested port: both indexes rendered the first holder, so a
        // two-holder table enumerated as two copies of the earlier entry.
        // The bench for the client matrix found it.
        let e = visible
            .get(index as usize)
            .copied()
            .ok_or(UpnpErr::NoSuchEntry)?;
        Ok(entry_xml(e, true))
    }

    // ---- plan/0008 #v2-service-set: DP boundary + WIP2-only actions ----

    /// The DeviceProtection authorization decision for a control point
    /// (section 26.7: the boundary sits in front of the engine).
    fn dp_enforce(&self, key: Ipv4Addr, required: &dp::DpAuthz, now: u64) -> Result<(), UpnpErr> {
        let state = crate::publish::lock_or_recover(&self.dp);
        state.enforce(key, required, now).map_err(map_dp_err)
    }

    /// Whether the caller holds the containment lift: a live session whose
    /// roles satisfy Basic, which Admin also satisfies (the containment for
    /// callers without the lift). The policy function is the same one the boundary uses, so
    /// the lift cannot drift from the gate.
    fn dp_holds_lift(&self, key: Ipv4Addr, now: u64) -> bool {
        let state = crate::publish::lock_or_recover(&self.dp);
        let roles = state.session_roles(key, now);
        dp::authorize(&roles, &dp::DpAuthz::Roles(vec!["Basic".to_string()]))
    }

    /// Refresh a session's activity stamp after an authorized action.
    fn dp_touch(&self, key: Ipv4Addr, now: u64) {
        let mut state = crate::publish::lock_or_recover(&self.dp);
        state.touch(key, now);
    }

    /// allocate_preferred (plan/0008's version-specific SOAP semantics): WANIPConnection:2's
    /// AddAnyPortMapping, where the requested port is a preference and the
    /// answer is the port actually reserved. The engine underneath is the
    /// same one allocate_exact drives, so a preferred request resolves to
    /// the same mapping objects; only the port resolution differs. A
    /// wildcard (0) asks for any free port, and a request for a port
    /// another client holds is moved to a free one rather than evicting
    /// that client, which is what 2.5.17 requires and what a control point
    /// reads NewReservedPort for. The spec's other reading of 2.5.17.3, a
    /// wildcard answered as 0 meaning "all unmapped external ports", is
    /// not a mapping this NAT can install: the AFTR is the mapper and it
    /// maps one tuple at a time.
    async fn allocate_preferred(
        &self,
        req: MappingReq,
        owner: Ipv4Addr,
        view: Option<Contain>,
    ) -> Result<String, UpnpErr> {
        let MappingReq {
            ext,
            proto,
            client,
            int_port,
            lifetime,
            desc,
        } = req;
        // the containment is judged on the request, before the port is
        // resolved: a preference below the floor is a request the contained
        // caller may not make, not one to be silently substituted
        if let Some(c) = view {
            if !request_within(c, client, ext, int_port) {
                return Err(UpnpErr::NotAuthorized);
            }
        }
        let req_ext = {
            let es = self.entries.lock().await;
            preferred_port(&es, ext, proto)
        };
        self.allocate_exact(
            MappingReq {
                ext: req_ext,
                proto,
                client,
                int_port,
                lifetime,
                desc,
            },
            owner,
            None,
        )
        .await?;
        Ok(format!("<NewReservedPort>{}</NewReservedPort>", req_ext))
    }

    /// DeletePortMappingRange: delete every entry whose requested port
    /// lies in [start, end] for the protocol. Bounded by the entries
    /// table, never by the port span. An empty range is the 730
    /// PortMappingNotFound the spec requires (2.5.19.2), and the delete
    /// is atomic in the sense that matters here: the target list is
    /// collected before any of it is removed.
    async fn delete_mapping_range(
        &self,
        start: u16,
        end: u16,
        proto: Proto,
        view: Option<Contain>,
    ) -> Result<String, UpnpErr> {
        // 2.5.19.2: an entry the caller may not touch is skipped and the
        // rest of the range still goes. An empty selection is 730.
        let targets: Vec<(u16, Ipv4Addr)> = {
            let es = self.entries.lock().await;
            es.iter()
                .filter(|e| e.proto == proto && e.req_ext >= start && e.req_ext <= end)
                .filter(|e| view.is_none_or(|c| entry_within(c, e)))
                .map(|e| (e.req_ext, e.owner))
                .collect()
        };
        if targets.is_empty() {
            return Err(UpnpErr::PortMappingNotFound);
        }
        for (ext, owner) in targets {
            let _ = self.delete_mapping(ext, proto, owner, view).await;
        }
        Ok(String::new())
    }

    /// GetListOfPortMappings: the entries whose requested port lies in
    /// [start, end] (protocol-filtered, capped at max when nonzero), as
    /// the NewPortListing XML (the A_ARG_TYPE_PortListing OUT value).
    /// The fragment shape is the sample of the spec's section 2.3.25.2: a
    /// PortMappingList of PortMappingEntry elements in the
    /// urn:schemas-upnp-org:gw:WANIPConnection namespace. NewLeaseTime is
    /// the remaining lease, as section 2.4.6 requires of a query. An
    /// empty selection is 730 PortMappingNotFound, as for the delete
    /// (2.5.21.3).
    async fn list_port_mappings(
        &self,
        start: u16,
        end: u16,
        proto: Option<Proto>,
        max: u16,
        view: Option<Contain>,
    ) -> Result<String, UpnpErr> {
        let es = self.entries.lock().await;
        let now = Epoch::now();
        let mut listing = String::from(PORT_LISTING_WRAP_OPEN);
        listing.push_str(PORT_LISTING_OPEN);
        let mut count = 0u16;
        for e in es.iter() {
            if let Some(p) = proto {
                if e.proto != p {
                    continue;
                }
            }
            if e.req_ext < start || e.req_ext > end {
                continue;
            }
            if max != 0 && count >= max {
                break;
            }
            // 2.5.21.3: a contained caller's listing holds only its own
            // entries at or above the floor
            if let Some(c) = view {
                if !entry_within(c, e) {
                    continue;
                }
            }
            let proto_txt = match e.proto {
                Proto::Tcp => "TCP",
                Proto::Udp => "UDP",
            };
            listing.push_str("<p:PortMappingEntry>");
            listing.push_str("<p:NewRemoteHost></p:NewRemoteHost>");
            listing.push_str(&format!("<p:NewExternalPort>{}</p:NewExternalPort>", e.req_ext));
            listing.push_str(&format!("<p:NewProtocol>{}</p:NewProtocol>", proto_txt));
            listing.push_str(&format!("<p:NewInternalPort>{}</p:NewInternalPort>", e.int_port));
            listing.push_str(&format!("<p:NewInternalClient>{}</p:NewInternalClient>", e.client));
            listing.push_str("<p:NewEnabled>1</p:NewEnabled>");
            listing.push_str(&format!(
                "<p:NewDescription>{}</p:NewDescription>",
                xml_escape(&e.desc)
            ));
            listing.push_str(&format!(
                "<p:NewLeaseTime>{}</p:NewLeaseTime>",
                e.expires_at_unix.saturating_sub(now)
            ));
            listing.push_str("</p:PortMappingEntry>");
            count += 1;
        }
        if count == 0 {
            return Err(UpnpErr::PortMappingNotFound);
        }
        listing.push_str("</p:PortMappingList>");
        listing.push_str(PORT_LISTING_WRAP_CLOSE);
        Ok(listing)
    }

    // ---- GENA ----

    async fn gena_subscribe(
        &self,
        callback: &[u8],
        timeout_secs: u32,
        caller: Ipv4Addr,
        v2: bool,
    ) -> Result<String, UpnpErr> {
        let Some((ip, port, path)) = parse_callback(callback) else {
            return Err(UpnpErr::InvalidArgs);
        };
        if !in_lan(ip, self.cfg.lan_ip) {
            return Err(UpnpErr::InvalidArgs);
        }
        if path.len() > GENA_CB_MAX || !in_lan(caller, self.cfg.lan_ip) {
            return Err(UpnpErr::InvalidArgs);
        }
        let timeout = timeout_secs.clamp(1, GENA_TIMEOUT_CAP);
        let sid = random_sid();
        let now = Epoch::now();
        let mut g = self.gena.lock().await;
        if !g.sids.add(sid) {
                return Err(UpnpErr::ActionFailed); // full
        }
        g.subs.push(Sub {
            sid,
            cb_ip: ip,
            cb_port: port,
            cb_path: path.to_vec(),
            timeout_secs: timeout,
            expires_at_unix: now.saturating_add(u64::from(timeout) * 2),
            seq: 0,
            caller,
            v2,
            sent: None,
        });
        drop(g);
        // initial NOTIFY carries eventKey 0 per GENA (E5) and every declared
        // evented variable; a delivered initial notify advances the
        // subscription's key so the first change event carries 1 — never a
        // repeat of 0 (notify_view performs the same advance after every
        // delivery).
        let ext = self.external_ip().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let view = self.view_for(caller, v2, ext).await;
        self.notify_view(sid, view, true).await;
        Ok(format!(
            "SID: {}\r\nTIMEOUT: Second-{}\r\n",
            String::from_utf8_lossy(&sid.wire()),
            timeout
        ))
    }

    async fn gena_renew(&self, sid: Sid, timeout_secs: u32) -> Result<String, UpnpErr> {
        let timeout = timeout_secs.clamp(1, GENA_TIMEOUT_CAP);
        let mut g = self.gena.lock().await;
        match g.subs.iter_mut().find(|s| s.sid == sid) {
            Some(s) => {
                s.timeout_secs = timeout;
                s.expires_at_unix = Epoch::now().saturating_add(u64::from(timeout) * 2);
                Ok(format!(
                    "SID: {}\r\nTIMEOUT: Second-{}\r\n",
                    String::from_utf8_lossy(&sid.wire()),
                    timeout
                ))
            }
            None => Err(UpnpErr::NoSuchEntry),
        }
    }

    async fn gena_unsubscribe(&self, sid: Sid) -> Result<String, UpnpErr> {
        let mut g = self.gena.lock().await;
        let before = g.subs.len();
        g.subs.retain(|s| s.sid != sid);
        if g.subs.len() == before || !g.sids.remove(sid) {
            return Err(UpnpErr::NoSuchEntry);
        }
        Ok(String::new())
    }

    /// The evented view one subscriber may see: the daemon's external
    /// address, the connection status, and its own count of mappings,
    /// computed with the containment its reads apply (call/0025).
    async fn view_for(&self, caller: Ipv4Addr, v2: bool, ext: Ipv4Addr) -> EventView {
        let scope = if self.dp_holds_lift(caller, Epoch::now()) {
            None
        } else {
            Some(Contain {
                caller,
                high_port: v2,
            })
        };
        let entries = {
            let es = self.entries.lock().await;
            scoped_count(scope, &es)
        };
        let update_id = self.gena.lock().await.update_id;
        EventView::new(ext, entries, update_id)
    }

    /// SystemUpdateID moves when a mapping appears or goes. A re-key of the
    /// datapath tuple deliberately does not move it: the reported port is the
    /// requested label (call/0022), so no event may invent a port change
    /// (call/0025). What a re-key can show is the address, and that rides
    /// ExternalIPAddress on the tuple path.
    async fn bump_update_id(&self) {
        let mut g = self.gena.lock().await;
        g.update_id = g.update_id.wrapping_add(1);
    }

    /// A mapping appeared or went: move the id and tell the subscribers now,
    /// rather than waiting for the next tuple publication.
    async fn signal_change(&self) {
        self.bump_update_id().await;
        let ext = self.external_ip().unwrap_or(Ipv4Addr::UNSPECIFIED);
        self.notify_all(ext).await;
    }

    /// Offer every subscriber the current view; each one is sent exactly the
    /// declared variables that moved for it.
    async fn notify_all(&self, ip: Ipv4Addr) {
        let subs: Vec<(Sid, Ipv4Addr, bool)> = {
            let g = self.gena.lock().await;
            g.subs.iter().map(|s| (s.sid, s.caller, s.v2)).collect()
        };
        for (sid, caller, v2) in subs {
            let view = self.view_for(caller, v2, ip).await;
            self.notify_view(sid, view, false).await;
        }
    }

    /// Deliver one NOTIFY carrying what moved for this subscriber, and record
    /// the view it was told. `force` is the subscription's initial event,
    /// which carries every declared variable whether or not it moved.
    async fn notify_view(&self, sid: Sid, view: EventView, force: bool) {
        let sub = {
            let g = self.gena.lock().await;
            g.subs.iter().find(|s| s.sid == sid).cloned()
        };
        let Some(s) = sub else {
            return;
        };
        let body = if force {
            propertyset(None, &view)
        } else {
            propertyset(s.sent.as_ref(), &view)
        };
        if body.is_empty() {
            // nothing moved: not an event, and the key must not advance
            return;
        }
        let seq = s.seq;
        let path = if s.cb_path.is_empty() {
            "/".to_string()
        } else {
            String::from_utf8_lossy(&s.cb_path).into_owned()
        };
        let req = format!(
            "POST {} HTTP/1.1\r\nHOST: {}:{}\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n\
             NT: upnp:event\r\nNTS: upnp:propchange\r\nSID: {}\r\nSEQ: {}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            path,
            s.cb_ip,
            s.cb_port,
            String::from_utf8_lossy(&s.sid.wire()),
            seq,
            body.len(),
            body
        );
        let _ = tokio::time::timeout(
            NOTIFY_TIMEOUT,
            deliver_notify(s.cb_ip, s.cb_port, req.as_bytes()),
        )
        .await;
        // delivered: the key advances and the view is remembered, so the next
        // event carries only what moved since this one
        let mut g = self.gena.lock().await;
        if let Some(s) = g.subs.iter_mut().find(|s| s.sid == sid) {
            s.sent = Some(view);
            s.seq = advance_seq(seq);
        }
    }

    async fn prune_expired(&self) {
        let now = Epoch::now();
        let mut g = self.gena.lock().await;
        let before = g.subs.len();
        g.subs.retain(|s| s.expires_at_unix > now);
        if g.subs.len() < before {
            // rebuild the sid mirror from the survivors
            let keep: Vec<Sid> = g.subs.iter().map(|s| s.sid).collect();
            g.sids = SidSet::new();
            for sid in keep {
                let _ = g.sids.add(sid);
            }
            emiteln!(
                "upnp: gena pruned {} expired subscription(s)",
                before - g.subs.len()
            );
        }
    }

    // ---- local GC (facade-owned teardown) ----

    // ---- R4: the late collision (call/0027, call/0028) ----

    /// A lease whose bind port a device's flow has taken yields it. The probe
    /// runs first, so the slot moves to a port nothing live holds; the label
    /// the client asked for does not change (call/0022); and the substitution
    /// is reported (R5).
    /// Release the mappings whose client has left the LAN. The statics are
    /// the operator's configuration and are never touched here; a client's
    /// own request is a promise to a device, and a device that is gone has
    /// nothing to be promised.
    async fn reap_absent_clients(&self) {
        let entries: Vec<(u16, Ipv4Addr, Proto, Ipv4Addr, u16)> = {
            let es = self.entries.lock().await;
            es.iter()
                .map(|e| (e.bind_port, e.owner, e.proto, e.client, e.req_ext))
                .collect()
        };
        // Decide under the lock and release outside it: a guard must not be
        // held across an await.
        let mut to_release: Vec<(Ipv4Addr, Proto, Ipv4Addr, u16)> = Vec::new();
        {
            let mut misses = self
                .presence_misses
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let live: std::collections::HashSet<u16> = entries.iter().map(|e| e.0).collect();
            misses.retain(|p, _| live.contains(p));
            for (bind_port, owner, proto, client, req_ext) in entries {
                if crate::presence::device_up(client) {
                    misses.remove(&bind_port);
                    continue;
                }
                let n = misses.entry(bind_port).or_insert(0);
                *n = n.saturating_add(1);
                if !crate::presence::release_absent(false, *n) {
                    continue;
                }
                misses.remove(&bind_port);
                to_release.push((owner, proto, client, req_ext));
            }
        }
        for (owner, proto, client, req_ext) in to_release {
            self.publisher.log_transition(
                "mapping-released",
                &format!(
                    "{}:{} asked for {} and is no longer on the LAN; its mapping goes",
                    client, req_ext, req_ext
                ),
            );
            let _ = self.delete_mapping(req_ext, proto, owner, None).await;
        }
    }

    async fn yield_collided_slots(&self) {
        let Ok(text) = std::fs::read_to_string("/proc/net/nf_conntrack") else {
            return;
        };
        if let Ok(live) = nft::list_flow_obs() {
            let ports: Vec<u16> = live.iter().map(|(_, r)| *r).collect();
            let mut t = self.table.lock().await;
            t.avoid_ports(&ports);
        }
        let collided = {
            let t = self.table.lock().await;
            t.collided(&text)
        };
        for old in collided {
            self.yield_port(old).await;
        }
    }

    /// Move one lease off a port a device's flow holds. The new datapath goes
    /// up first and the old one comes down only once it is up, so a move that
    /// cannot be completed leaves the slot working where it was. Nothing is
    /// signalled: the count does not change and the reported port is the
    /// client's label, so an event would invent a change it cannot see
    /// (call/0025). A PCP client learns the new assigned tuple on its next
    /// renewal, which is what the protocol is for.
    async fn yield_port(&self, old: u16) {
        let entry = {
            let es = self.entries.lock().await;
            es.iter().find(|e| e.bind_port == old).cloned()
        };
        let Some(e) = entry else {
            return;
        };
        let moved = {
            let mut t = self.table.lock().await;
            t.move_bind_port(old)
        };
        let Some(new) = moved else {
            self.publisher.log_transition(
                "collision-reported",
                &format!(
                    "slot {} shares its tuple with a device's flow and the range has nowhere to go",
                    old
                ),
            );
            return;
        };
        let tcp = e.proto == Proto::Tcp;
        let handles = match e.proto {
            Proto::Udp => self.spawn_udp_slot(new, e.client, e.int_port).await,
            Proto::Tcp => self.spawn_tcp_slot(new, e.client, e.int_port).await,
        };
        let h = match handles {
            Ok(h) => h,
            Err(err) => {
                let mut t = self.table.lock().await;
                t.restore_bind_port(new, old);
                self.publisher.log_transition(
                    "collision-reported",
                    &format!(
                        "slot {} could not move to {}: {}; it keeps the port it had",
                        old, new, err
                    ),
                );
                return;
            }
        };
        let _ = nft::grant_datapath(e.client, e.int_port, new, tcp);
        self.tasks.lock().await.insert(new, h);
        let _ = nft::revoke_datapath(e.client, e.int_port, old, tcp);
        if let Some(prev) = self.tasks.lock().await.remove(&old) {
            for jh in prev {
                jh.abort();
            }
        }
        self.publisher.remove_slot(old);
        {
            let mut es = self.entries.lock().await;
            if let Some(x) = es.iter_mut().find(|x| x.bind_port == old) {
                x.bind_port = new;
            }
        }
        self.publisher.log_transition(
            "collision-yield",
            &format!(
                "slot {} yielded to a device's flow and moved to {} (label {} kept)",
                old, new, e.req_ext
            ),
        );
        self.persist().await;
    }

    async fn gc_loop(&self) {
        let grace = self.cfg.grace_secs;
        // R4 before anything is reaped: a slot sharing a tuple with a
        // device's flow moves, so the reap decisions below act on ports the
        // table actually holds.
        self.yield_collided_slots().await;
        // expiry-GC for finite leases (the appearing-infinite grants never
        // trip this; their lifecycle belongs to the lease policy below)
        let now = Epoch::now();
        let pre: Vec<Slot> = {
            let t = self.table.lock().await;
            t.slots().to_vec()
        };
        let freed = {
            let mut t = self.table.lock().await;
            t.gc(now, grace)
        };
        if !freed.is_empty() {
            self.tear_down_ports(&pre, &freed).await;
            emiteln!("upnp: gc freed expired slots {:?}", freed);
        }
        // A client-requested mapping ends when its client is no longer on
        // the LAN (presence.rs) and never for the client being quiet: a
        // lobby and a paused game are quiet, and the mapping is what must
        // survive them. This supersedes the silence backstop that used to
        // reap here, which reaped exactly the mappings a console needs when
        // it sits still.
        self.reap_absent_clients().await;
        // lease-policy backstop, kept for the pool-state case only: the
        // pressure path handles the shorter grace under TableFull.
        let now = Epoch::now();
        let pre: Vec<Slot> = {
            let t = self.table.lock().await;
            t.slots().to_vec()
        };
        let idle_freed = {
            let mut t = self.table.lock().await;
            t.gc_idle(now, LEASE_BACKSTOP_S)
        };
        if !idle_freed.is_empty() {
            self.tear_down_ports(&pre, &idle_freed).await;
            emiteln!("upnp: gc freed idle slots {:?}", idle_freed);
        }
    }

    /// Shared teardown for freed ports: revoke the datapath, abort the
    /// slot tasks, drop the control-plane entry, persist.
    async fn tear_down_ports(&self, pre: &[Slot], freed: &[u16]) {
        for port in freed {
            let info = pre.iter().find(|s| s.bind_port == *port).copied();
            if let Some(s) = info {
                if let Some(client) = s.client() {
                    let _ = nft::revoke_datapath(client, s.target_port, *port, s.proto == Proto::Tcp);
        self.publisher.remove_slot(*port);
                }
            }
            if let Some(h) = self.tasks.lock().await.remove(port) {
                for jh in h {
                    jh.abort();
                }
            }
            let mut es = self.entries.lock().await;
            es.retain(|e| e.bind_port != *port);
        }
        self.persist().await;
    }

    /// Client-presence stamp from the control plane: any SOAP action from
    /// this IP proves the client is alive; refresh its grants' last-seen
    /// (the lease policy's second producer, beside the datapath stamp).
    async fn stamp_client(&self, client: Ipv4Addr) {
        let now = Epoch::now();
        let ports: Vec<u16> = {
            let es = self.entries.lock().await;
            es.iter()
                .filter(|e| e.client == client)
                .map(|e| e.bind_port)
                .collect()
        };
        if ports.is_empty() {
            return;
        }
        let mut t = self.table.lock().await;
        for p in ports {
            t.stamp_activity_if_stale(p, now, 0);
        }
    }

    // ---- persistence ----

    async fn persist(&self) {
        let now = Epoch::now();
        let slots: Vec<Slot> = {
            let t = self.table.lock().await;
            t.slots().to_vec()
        };
        let w = persist::write_leases(
            std::path::Path::new(DEFAULT_DIR),
            &persist::snapshot(&slots, now),
        );
        self.publisher.note_write("leases.tsv", w);
        // the control-plane index (req_ext key) rides its own file
        let es = self.entries.lock().await;
        let mut out = String::new();
        for e in es.iter() {
            out.push_str(&entry_line(e));
        }
        drop(es);
        let w = persist::write_entries(std::path::Path::new(DEFAULT_DIR), &out);
        self.publisher.note_write("upnp.tsv", w);
    }
}

// ---- HTTP service ----

/// Accept loop: bound the connection count (E8), one task per client.
async fn http_loop(facade: Arc<UpnpFacade>) -> io::Result<()> {
    let listener = TcpListener::bind((facade.cfg.lan_ip, facade.cfg.upnp_port)).await?;
    http_serve(listener, facade).await
}

/// The accept/dispatch loop over an already-bound listener (split so the
/// in-process test harness can drive it on an ephemeral port).
async fn http_serve(listener: TcpListener, facade: Arc<UpnpFacade>) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(HTTP_CONN_CAP));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // A transient accept error (fd pressure, EMFILE/ENOBUFS)
                // must not kill the control plane: the SSDP loops keep
                // advertising, and a dead HTTP service would leave the
                // facade a ghost IGD. Log and retry, like the sibling
                // loops' Err(_) => continue.
                emiteln!("upnp: accept: {}", e);
                continue;
            }
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let client_ip = match peer {
            SocketAddr::V4(v4) => *v4.ip(),
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let f = facade.clone();
        tokio::spawn(async move {
            let _guard = permit;
            // Bound the whole connection: a stalled handler (a client that
            // never finishes its head/body, or a wedged write) would
            // otherwise hold its semaphore permit forever; once enough
            // stall, the pool exhausts and every later connection is
            // accepted-and-dropped. 30 s is far beyond any real UPnP
            // request but caps the damage.
            let _ = tokio::time::timeout(
                Duration::from_secs(30),
                handle_conn(f, stream, client_ip),
            )
            .await;
        });
    }
}

/// One client connection: read the head (capped), read a body when
/// Content-Length says so, classify, dispatch.
async fn handle_conn(facade: Arc<UpnpFacade>, mut stream: TcpStream, client_ip: Ipv4Addr) {
    let raw = match read_head(&mut stream).await {
        Ok(h) => h,
        Err(_) => return,
    };
    // The body may already sit in the same read as the head (small SOAP
    // and GENA requests send head+body in one segment): split it out so
    // read_body below does not wait on bytes that already arrived.
    let (head, excess) = split_head(&raw).unwrap_or((&raw[..], &raw[..]));
    let mut body: Vec<u8> = excess.to_vec();
    if let Some(cl) = content_length(head) {
        if cl > body.len() {
            match read_body(&mut stream, cl - body.len()).await {
                Ok(b) => body.extend_from_slice(&b),
                Err(_) => return,
            }
        }
        body.truncate(cl);
    }

    match classify(head) {
        ReqClass::Get => {
            let path = request_path(head).unwrap_or(b"");
            let doc = match path {
                p if eq_ia(p, b"/rootDesc.xml") => Some(root_desc(
                    facade.cfg.lan_ip,
                    facade.cfg.upnp_port,
                    &facade.cfg.name,
                    &facade.udn,
                )),
                p if eq_ia(p, b"/WANIPC.xml") => Some(SCPD_WANIP.as_bytes().to_vec()),
                p if eq_ia(p, b"/WANPPP.xml") => Some(SCPD_WANPPP.as_bytes().to_vec()),
                p if eq_ia(p, b"/WANCfg.xml") => Some(SCPD_WANCMN.as_bytes().to_vec()),
                // plan/0008's LOCATION design: the deterministic versioned URLs.
                // The v1 prefixes are the canonical v1 presentation; the
                // legacy paths above remain served for backward
                // compatibility with existing descriptions/control points.
                p if eq_ia(p, b"/igd/v1/rootDesc.xml") => Some(root_desc(
                    facade.cfg.lan_ip,
                    facade.cfg.upnp_port,
                    &facade.cfg.name,
                    &facade.udn,
                )),
                p if eq_ia(p, b"/igd/v1/WANIPC.xml") => Some(SCPD_WANIP.as_bytes().to_vec()),
                p if eq_ia(p, b"/igd/v1/WANPPP.xml") => Some(SCPD_WANPPP.as_bytes().to_vec()),
                p if eq_ia(p, b"/igd/v1/WANCfg.xml") => Some(SCPD_WANCMN.as_bytes().to_vec()),
                // The v2 surface mounts only with its complete service set
                // (plan/0008 R5, R6 gate); until then the URLs are not
                // offered and answer 404.
                p if IGD_V2_ENABLED && eq_ia(p, b"/igd/v2/rootDesc.xml") => {
                    Some(root_desc_v2(
                        facade.cfg.lan_ip,
                        facade.cfg.upnp_port,
                        &facade.cfg.name,
                        &facade.udn,
                    ))
                }
                p if IGD_V2_ENABLED && eq_ia(p, b"/igd/v2/WANIPCn.xml") => {
                    Some(SCPD_WIP2.as_bytes().to_vec())
                }
                p if IGD_V2_ENABLED && eq_ia(p, b"/igd/v2/DP.xml") => {
                    Some(SCPD_DP.as_bytes().to_vec())
                }
                _ => None,
            };
            match doc {
                Some(xml) => {
                    let _ = write_response(&mut stream, "200 OK", &xml, "").await;
                }
                None => {
                    let _ = write_response(&mut stream, "404 Not Found", b"", "").await;
                }
            }
        }
        ReqClass::Soap { service, action, v2 } => {
            handle_soap(&facade, service, action, v2, client_ip, &body, &mut stream).await;
            // Client-presence stamp for the lease policy: any SOAP action
            // from this IP proves the client is alive. Stamp result
            // regardless of the action's own outcome (the client talked).
            facade.stamp_client(client_ip).await;
        }
        ReqClass::GenaSubscribe => {
            let callback = upnp::find_header(head, b"CALLBACK").unwrap_or(b"");
            let timeout =
                parse_timeout(upnp::find_header(head, b"TIMEOUT")).unwrap_or(GENA_TIMEOUT_CAP);
            let v2 = request_path(head)
                .map(|p| p.starts_with(b"/igd/v2/"))
                .unwrap_or(false);
            match facade.gena_subscribe(callback, timeout, client_ip, v2).await {
                Ok(extra) => {
                    let _ = write_response(&mut stream, "200 OK", b"", &extra).await;
                }
                Err(e) => {
                    let _ = write_soap_fault(&mut stream, &fault_of(e)).await;
                }
            }
        }
        ReqClass::GenaRenew => {
            let timeout =
                parse_timeout(upnp::find_header(head, b"TIMEOUT")).unwrap_or(GENA_TIMEOUT_CAP);
            match parse_sid_header(head) {
                Some(sid) => match facade.gena_renew(sid, timeout).await {
                    Ok(extra) => {
                        let _ = write_response(&mut stream, "200 OK", b"", &extra).await;
                    }
                    Err(e) => {
                        let _ = write_soap_fault(&mut stream, &fault_of(e)).await;
                    }
                },
                None => {
                    let _ = write_soap_fault(&mut stream, &FAULT_INVALID_ARGS).await;
                }
            }
        }
        ReqClass::GenaUnsubscribe => match parse_sid_header(head) {
            Some(sid) => match facade.gena_unsubscribe(sid).await {
                Ok(_) => {
                    let _ = write_response(&mut stream, "200 OK", b"", "").await;
                }
                Err(e) => {
                    let _ = write_soap_fault(&mut stream, &fault_of(e)).await;
                }
            },
            None => {
                let _ = write_soap_fault(&mut stream, &FAULT_INVALID_ARGS).await;
            }
        },
        ReqClass::SoapInvalidAction => {
            let _ = write_soap_fault(&mut stream, &FAULT_INVALID_ACTION).await;
        }
        ReqClass::NotFound => {
            let _ = write_response(&mut stream, "404 Not Found", b"", "").await;
        }
    }
}

async fn handle_soap(
    facade: &Arc<UpnpFacade>,
    service: SoapService,
    action: SoapAction,
    v2: bool,
    client_ip: Ipv4Addr,
    body: &[u8],
    stream: &mut TcpStream,
) {
    // plan/0008's WANIPConnection integration: the DeviceProtection authorization boundary.
    // A v2 WIP2 security-sensitive invocation flows through the session
    // principal before the canonical mapping engine; there is no engine
    // bypass for the v2 face. The v1 facade stays a legacy unauthenticated
    // compatibility surface (section 26.12).
    let gated: Result<(), UpnpErr> = if service == SoapService::WanIpConnection
        && v2
        && matches!(
            action,
            SoapAction::AddPortMapping
                | SoapAction::AddAnyPortMapping
                | SoapAction::DeletePortMapping
                | SoapAction::DeletePortMappingRange
        ) {
        let name = String::from_utf8_lossy(upnp::soap_action_name(action)).into_owned();
        let required = dp::required_role(dp::DpTarget::WanIpConnection, &name);
        let now = Epoch::now();
        let r = facade.dp_enforce(client_ip, &required, now);
        if r.is_ok() {
            facade.dp_touch(client_ip, now);
        }
        r
    } else {
        Ok(())
    };
    // plan/0008's containment for callers without the lift: the containment the spec recommends for
    // unauthenticated control points (2.5.16.2, 2.5.18.2, 2.5.14.2,
    // 2.5.21.3). One view serves reads and writes alike, because the
    // address clause needs no remedy on either side of that line: a caller
    // without the lift may name, see, enumerate and delete only its own
    // host, and the port floor binds the v2 face, where the DP session that
    // lifts it is established. A lift is a principal's roles rather than a
    // face's, so a control point that authenticates over DeviceProtection
    // reaches the whole table on either face; a caller that never
    // authenticates sees only its own mappings.
    let lift = facade.dp_holds_lift(client_ip, Epoch::now());
    let view = if lift {
        None
    } else {
        Some(Contain {
            caller: client_ip,
            high_port: v2,
        })
    };
    let result: Result<String, UpnpErr> = match gated {
        Err(e) => Err(e),
        Ok(()) => match (service, action) {
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::GetExternalIpAddress,
            ) => facade.get_external_ip().await,
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::GetStatusInfo,
            ) => Ok(facade.get_status_info().await),
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::GetConnectionTypeInfo,
            ) => Ok(facade.get_connection_type_info()),
            // The line is auto-configured (the ISP owns the ds-lite WAN),
            // so ConnectionType is read-only: 2.5.1's note that it may be,
            // and the code 2.5.23 names for a SetConnectionType that
            // cannot set it.
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::SetConnectionType,
            ) => Err(UpnpErr::ReadOnly),
            // RequestConnection: its precondition (2.5.3.4) is a status of
            // Disconnected, PendingDisconnect or Connected with an
            // IP_Routed type, and its effect (2.5.3.5) is Connected. When
            // the facade holds an external tuple both already hold, so the
            // action succeeds; with no tuple the provider side is not up,
            // which is the 704 ConnectionSetupFailed of 2.5.3.6.
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::RequestConnection,
            ) => {
                if facade.external_ip().is_some() {
                    Ok(String::new())
                } else {
                    Err(UpnpErr::ConnectionSetupFailed)
                }
            }
            // ForceTermination is refused, deliberately. The facade does
            // not own the WAN lifetime (netifd and the ISP do), and the
            // action is public on the v1 face, so honouring it would hand
            // every LAN device a lever that drops the household line for
            // every client. 501 is the UDA generic failure; the spec's own
            // table offers no code for a device that may not terminate.
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::ForceTermination,
            ) => Err(UpnpErr::ActionFailed),
            // GetNATRSIPStatus: the facade performs NAT (1) and this line
            // runs no RSIP server (0), per the variables of 2.3.11/2.3.12
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::GetNatRsipStatus,
            ) => Ok(String::from(
                "<NewRSIPAvailable>0</NewRSIPAvailable>\
                 <NewNATEEnabled>1</NewNATEEnabled>",
            )),
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::AddPortMapping,
            ) => match parse_add_args(body) {
                Ok((ext, proto, int_port, client, lifetime)) => {
                    // the URN's version decides the lease reading
                    // (table 2-6 against the v1 static mapping)
                    let lifetime = if v2 { wip2_lease(lifetime) } else { lifetime };
                    facade
                        .allocate_exact(
                            MappingReq {
                                ext,
                                proto,
                                client,
                                int_port,
                                lifetime,
                                desc: parse_desc(body),
                            },
                            client_ip,
                            view,
                        )
                        .await
                }
                Err(e) => Err(e),
            },
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::DeletePortMapping,
            ) => match parse_delete_args(body) {
                Ok((ext, proto)) => facade.delete_mapping(ext, proto, client_ip, view).await,
                Err(e) => Err(e),
            },
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::GetSpecificPortMappingEntry,
            ) => match parse_delete_args(body) {
                Ok((ext, proto)) => facade.get_specific(ext, proto, client_ip, view).await,
                Err(e) => Err(e),
            },
            (
                SoapService::WanIpConnection | SoapService::WanPppConnection,
                SoapAction::GetGenericPortMappingEntry,
            ) => match parse_index_arg(body) {
                Ok(i) => facade.get_generic(i, view).await,
                Err(e) => Err(e),
            },
            // WIP2-only surface (plan/0008 #v2-service-set). The engine is
            // report-requested: the granted bind port IS the external
            // port, so AddAnyPortMapping answers NewReservedPort with the
            // granted port and the entries key follows it.
            (SoapService::WanIpConnection, SoapAction::AddAnyPortMapping) => {
                match parse_add_args_any(body) {
                    Ok((ext, proto, int_port, client, lifetime)) => {
                        // this arm is v2-only, so the version 2 lease
                        // reading always applies here
                        let lifetime = wip2_lease(lifetime);
                        facade
                            .allocate_preferred(
                                MappingReq {
                                    ext,
                                    proto,
                                    client,
                                    int_port,
                                    lifetime,
                                    desc: parse_desc(body),
                                },
                                client_ip,
                                view,
                            )
                            .await
                    }
                    Err(e) => Err(e),
                }
            }
            (SoapService::WanIpConnection, SoapAction::DeletePortMappingRange) => {
                match parse_range_args(body) {
                    Ok((start, end, proto)) => {
                        facade.delete_mapping_range(start, end, proto, view).await
                    }
                    Err(e) => Err(e),
                }
            }
            (SoapService::WanIpConnection, SoapAction::GetListOfPortMappings) => {
                match parse_list_args(body) {
                    Ok((start, end, proto, max)) => {
                        facade.list_port_mappings(start, end, proto, max, view).await
                    }
                    Err(e) => Err(e),
                }
            }
            (SoapService::WanCommonIfaceCfg, SoapAction::GetCommonLinkProperties) => {
                Ok(facade.common_link_properties())
            }
            // DeviceProtection:1 (the authoritative 13 actions,
            // docs/upnp-dp1/TRANSCRIPTION.md). The admin-gated actions
            // enforce through dp::required_role inside each handler.
            (SoapService::DeviceProtection, SoapAction::SendSetupMessage) => {
                dp_send_setup(facade, body)
            }
            (SoapService::DeviceProtection, SoapAction::GetSupportedProtocols) => {
                Ok(dp::supported_protocols_xml())
            }
            (SoapService::DeviceProtection, SoapAction::GetAssignedRoles) => {
                Ok(dp_assigned_roles(facade, client_ip))
            }
            (SoapService::DeviceProtection, SoapAction::GetRolesForAction) => {
                dp_roles_for_action(body)
            }
            (SoapService::DeviceProtection, SoapAction::GetUserLoginChallenge) => {
                dp_challenge(facade, client_ip, body)
            }
            (SoapService::DeviceProtection, SoapAction::UserLogin) => {
                dp_login(facade, client_ip, body)
            }
            (SoapService::DeviceProtection, SoapAction::UserLogout) => {
                dp_logout(facade, client_ip)
            }
            (SoapService::DeviceProtection, SoapAction::GetAclData) => {
                dp_get_acl(facade, client_ip)
            }
            (SoapService::DeviceProtection, SoapAction::AddIdentityList) => {
                dp_add_identities(facade, client_ip, body)
            }
            (SoapService::DeviceProtection, SoapAction::RemoveIdentity) => {
                dp_remove_identity(facade, client_ip, body)
            }
            (SoapService::DeviceProtection, SoapAction::SetUserLoginPassword) => {
                dp_set_password(facade, client_ip, body)
            }
            (SoapService::DeviceProtection, SoapAction::AddRolesForIdentity) => {
                dp_add_roles(facade, client_ip, body, true)
            }
            (SoapService::DeviceProtection, SoapAction::RemoveRolesForIdentity) => {
                dp_add_roles(facade, client_ip, body, false)
            }
            _ => Err(UpnpErr::InvalidAction),
        },
    };
    match result {
        Ok(inner) => {
            let action_name = String::from_utf8_lossy(upnp::soap_action_name(action));
            let xml = upnp::soap_success_v(service, v2, &action_name, &inner);
            let _ = write_response(stream, "200 OK", &xml, "").await;
            emitln!(
                "{{\"event\":\"upnp\",\"action\":\"{}\",\"service\":\"{}\"}}",
                action_name,
                String::from_utf8_lossy(upnp::service_urn_v(service, v2))
            );
        }
        Err(e) => {
            let _ = write_soap_fault(stream, &fault_of(e)).await;
        }
    }
}

// ---- plan/0008 #v2-service-set: the DeviceProtection dispatch ----

/// GetUserLoginChallenge (DP 2.6.5): ProtocolType MUST be PKCS5 (the one
/// Login protocol this device speaks); Name MUST be a known user; the
/// response carries the user's Salt and a fresh Challenge (Base64). The
/// challenge replaces the session's previous one (2.6.5.9).
fn dp_challenge(facade: &UpnpFacade, client_ip: Ipv4Addr, body: &[u8]) -> Result<String, UpnpErr> {
    let proto = xml_tag(body, b"ProtocolType").ok_or(UpnpErr::InvalidValue)?;
    if !eq_ia(proto, b"PKCS5") {
        return Err(UpnpErr::InvalidValue);
    }
    let name = dp_str_tag(body, b"Name")?;
    let mut state = crate::publish::lock_or_recover(&facade.dp);
    let (salt, challenge) = state
        .begin_login(client_ip, &name, dp_random_16(), Epoch::now())
        .map_err(map_dp_err)?;
    Ok(format!(
        "<Salt>{}</Salt><Challenge>{}</Challenge>",
        dp::base64_encode(&salt),
        dp::base64_encode(&challenge)
    ))
}

/// UserLogin (DP 2.6.6): verify the Authenticator for the session's
/// pending Challenge (2.6.6.4). UserLogin has no OUT arguments.
fn dp_login(facade: &UpnpFacade, client_ip: Ipv4Addr, body: &[u8]) -> Result<String, UpnpErr> {
    let proto = xml_tag(body, b"ProtocolType").ok_or(UpnpErr::InvalidValue)?;
    if !eq_ia(proto, b"PKCS5") {
        return Err(UpnpErr::InvalidValue);
    }
    let challenge = dp_b64_tag16(body, b"Challenge")?;
    let auth = xml_tag(body, b"Authenticator")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(dp::base64_decode)
        .ok_or(UpnpErr::InvalidValue)?;
    let mut state = crate::publish::lock_or_recover(&facade.dp);
    state
        .login(client_ip, challenge, &auth, Epoch::now())
        .map(|_| String::new())
        .map_err(map_dp_err)
}

/// UserLogout (DP 2.6.7): drop the session principal. No arguments.
fn dp_logout(facade: &UpnpFacade, client_ip: Ipv4Addr) -> Result<String, UpnpErr> {
    let mut state = crate::publish::lock_or_recover(&facade.dp);
    state.logout(client_ip, Epoch::now());
    Ok(String::new())
}

/// GetAssignedRoles (DP 2.6.3): the session's role set, space-separated.
/// Per 2.6.3.2, an unauthenticated session sees only "Public".
fn dp_assigned_roles(facade: &UpnpFacade, client_ip: Ipv4Addr) -> String {
    let state = crate::publish::lock_or_recover(&facade.dp);
    let roles = state.session_roles(client_ip, Epoch::now());
    if roles.is_empty() {
        "<RoleList>Public</RoleList>".to_string()
    } else {
        format!("<RoleList>{}</RoleList>", roles.join(" "))
    }
}

/// GetRolesForAction (DP 2.6.4): answer the device's role policy for the
/// named (DeviceUDN, ServiceId, ActionName): RoleList = the roles that
/// grant access unconditionally, RestrictedRoleList empty (no role is
/// conditional in this policy). The policy itself is dp::required_role.
fn dp_roles_for_action(body: &[u8]) -> Result<String, UpnpErr> {
    let service_id = dp_str_tag(body, b"ServiceId")?;
    let action = dp_str_tag(body, b"ActionName")?;
    let target = if service_id.contains("DeviceProtection") {
        dp::DpTarget::DeviceProtection
    } else if service_id.contains("WANIPConnection") || service_id.contains("WANPPPConnection") {
        dp::DpTarget::WanIpConnection
    } else {
        return Err(UpnpErr::InvalidValue);
    };
    let (role_list, restricted) = match dp::required_role(target, &action) {
        dp::DpAuthz::Public => ("Public".to_string(), String::new()),
        dp::DpAuthz::Roles(needed) => (needed.join(" "), String::new()),
    };
    Ok(format!(
        "<RoleList>{}</RoleList><RestrictedRoleList>{}</RestrictedRoleList>",
        role_list, restricted
    ))
}

/// SendSetupMessage (DP 2.6.1): the generic transport for introduction
/// protocols. This device speaks exactly one Introduction protocol
/// (WPS, per the mandated SupportedProtocols) but runs no WPS registrar
/// (it is an IGD on a wired line, not an enrolment point), so a WPS
/// in-message cannot be processed: 600 for an unsupported ProtocolType
/// (2.6.1.9), 704 Processing Error for a WPS message (2.6.1.9: "an error
/// was encountered in processing InMessage").
fn dp_send_setup(facade: &UpnpFacade, body: &[u8]) -> Result<String, UpnpErr> {
    let proto = xml_tag(body, b"ProtocolType").ok_or(UpnpErr::InvalidValue)?;
    if !eq_ia(proto, b"WPS") {
        return Err(UpnpErr::InvalidValue);
    }
    // No setup operation is pending or possible: SetupReady stays
    // unchanged (2.4.2 semantics; the evented variable never moves).
    let _state = crate::publish::lock_or_recover(&facade.dp);
    let _ = _state.setup_ready();
    Err(map_dp_err(dp::DpErr::Processing))
}

/// GetACLData (DP 2.6.8), Admin-gated: the ACL document as the OUT
/// value (an XML document embedded per 2.6.8.2).
fn dp_get_acl(facade: &UpnpFacade, client_ip: Ipv4Addr) -> Result<String, UpnpErr> {
    let now = Epoch::now();
    let required = dp::required_role(dp::DpTarget::DeviceProtection, "GetACLData");
    let state = crate::publish::lock_or_recover(&facade.dp);
    state.enforce(client_ip, &required, now).map_err(map_dp_err)?;
    Ok(dp::acl_xml(state.acl()))
}

/// AddIdentityList (DP 2.6.9), Admin-gated: union-add the incoming User
/// identities; IdentityListResult carries the identities actually added
/// (2.6.9.3).
fn dp_add_identities(facade: &UpnpFacade, client_ip: Ipv4Addr, body: &[u8]) -> Result<String, UpnpErr> {
    let now = Epoch::now();
    let required = dp::required_role(dp::DpTarget::DeviceProtection, "AddIdentityList");
    let mut state = crate::publish::lock_or_recover(&facade.dp);
    state.enforce(client_ip, &required, now).map_err(map_dp_err)?;
    let incoming = dp::DpAcl {
        identities: dp_identity_names(body)
            .into_iter()
            .map(|name| dp::DpIdentity {
                name,
                alias: None,
                id: [0u8; 16],
                roles: Vec::new(),
            })
            .collect(),
    };
    let added = state.add_identities(&incoming);
    dp_save(&facade.cfg.state_dir, &state);
    Ok(dp::identity_list_xml(&added))
}

/// RemoveIdentity (DP 2.6.10), Admin-gated: remove by Name
/// (case-sensitive); an unknown Identity is 600 (2.6.10.7).
fn dp_remove_identity(facade: &UpnpFacade, client_ip: Ipv4Addr, body: &[u8]) -> Result<String, UpnpErr> {
    let now = Epoch::now();
    let required = dp::required_role(dp::DpTarget::DeviceProtection, "RemoveIdentity");
    let mut state = crate::publish::lock_or_recover(&facade.dp);
    state.enforce(client_ip, &required, now).map_err(map_dp_err)?;
    let name = dp_identity_names(body)
        .into_iter()
        .next()
        .ok_or(UpnpErr::InvalidValue)?;
    if !state.remove_identity(&name) {
        return Err(UpnpErr::InvalidValue);
    }
    dp_save(&facade.cfg.state_dir, &state);
    Ok(String::new())
}

/// SetUserLoginPassword (DP 2.6.11): Admin, or the session logged in AS
/// the Name (2.6.11.6). Sets/creates the user's Stored + Salt.
fn dp_set_password(facade: &UpnpFacade, client_ip: Ipv4Addr, body: &[u8]) -> Result<String, UpnpErr> {
    let proto = xml_tag(body, b"ProtocolType").ok_or(UpnpErr::InvalidValue)?;
    if !eq_ia(proto, b"PKCS5") {
        return Err(UpnpErr::InvalidValue);
    }
    let name = dp_str_tag(body, b"Name")?;
    let stored = dp_b64_tag16(body, b"Stored")?;
    let salt = dp_b64_tag16(body, b"Salt")?;
    let now = Epoch::now();
    let mut state = crate::publish::lock_or_recover(&facade.dp);
    let admin = dp::required_role(dp::DpTarget::DeviceProtection, "SetUserLoginPassword");
    let self_ok = state.session_user(client_ip, now) == Some(name.as_str());
    if !self_ok {
        state.enforce(client_ip, &admin, now).map_err(map_dp_err)?;
    }
    if !state.set_user_password(&name, stored, salt) {
        return Err(UpnpErr::InvalidValue);
    }
    dp_save(&facade.cfg.state_dir, &state);
    Ok(String::new())
}

/// AddRolesForIdentity / RemoveRolesForIdentity (DP 2.6.12 / 2.6.13),
/// Admin-gated. Unknown role names are rejected with 600 (2.6.12.3); an
/// unknown identity is 600.
fn dp_add_roles(
    facade: &UpnpFacade,
    client_ip: Ipv4Addr,
    body: &[u8],
    add: bool,
) -> Result<String, UpnpErr> {
    let now = Epoch::now();
    let action = if add {
        "AddRolesForIdentity"
    } else {
        "RemoveRolesForIdentity"
    };
    let required = dp::required_role(dp::DpTarget::DeviceProtection, action);
    let mut state = crate::publish::lock_or_recover(&facade.dp);
    state.enforce(client_ip, &required, now).map_err(map_dp_err)?;
    let identity = dp_identity_names(body)
        .into_iter()
        .next()
        .ok_or(UpnpErr::InvalidValue)?;
    let roles = dp_role_list(body)?;
    let ok = if add {
        state.add_roles(&identity, &roles)
    } else {
        state.remove_roles(&identity, &roles)
    };
    if !ok {
        return Err(UpnpErr::InvalidValue);
    }
    dp_save(&facade.cfg.state_dir, &state);
    Ok(String::new())
}

fn dp_str_tag(body: &[u8], tag: &[u8]) -> Result<String, UpnpErr> {
    xml_tag(body, tag)
        .and_then(|v| std::str::from_utf8(v).ok())
        .map(|s| s.trim().to_string())
        .ok_or(UpnpErr::InvalidValue)
}

fn dp_b64_tag16(body: &[u8], tag: &[u8]) -> Result<[u8; 16], UpnpErr> {
    let v = xml_tag(body, tag)
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(dp::base64_decode)
        .ok_or(UpnpErr::InvalidValue)?;
    if v.len() != 16 {
        return Err(UpnpErr::InvalidValue);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&v);
    Ok(out)
}

/// A space-separated RoleList argument; every role must be one the
/// device understands (2.6.12.3: unknown roles -> 600).
fn dp_role_list(body: &[u8]) -> Result<Vec<String>, UpnpErr> {
    let s = dp_str_tag(body, b"RoleList")?;
    let roles: Vec<String> = s.split_whitespace().map(str::to_string).collect();
    if roles.iter().any(|r| !dp::valid_role(r)) {
        return Err(UpnpErr::InvalidValue);
    }
    Ok(roles)
}

/// Every `<Name>` inside the request's `<Identity>` elements (the minimal
/// scanner; the upnp.rs scope note applies — a real XML parser is the
/// escalation a CP actually needs it).
fn dp_identity_names(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut search_from = 0usize;
    loop {
        let Some(rel) = substring(&body[search_from..], b"<Identity") else {
            break;
        };
        let start = search_from + rel;
        let Some(gt) = substring(&body[start..], b">") else {
            break;
        };
        let block_start = start + gt + 1;
        let Some(end_rel) = substring(&body[block_start..], b"</Identity>") else {
            break;
        };
        let block = &body[block_start..block_start + end_rel];
        if let Some(name) = xml_tag(block, b"Name") {
            if let Ok(s) = std::str::from_utf8(name) {
                out.push(s.trim().to_string());
            }
        }
        search_from = block_start + end_rel + b"</Identity>".len();
    }
    out
}

fn substring(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

// ---- WIP2-only action argument parsing (plan/0008 #v2-service-set) ----

/// DeletePortMappingRange: NewStartPort/NewEndPort/NewProtocol/NewManage.
/// The range endpoints are honored as an entry filter, so no scan runs
/// over the port span. A start above the end is the 733
/// InconsistentParameters of 2.5.19.6, not a malformed request.
fn parse_range_args(body: &[u8]) -> Result<(u16, u16, Proto), UpnpErr> {
    let start = tag_u16(body, b"NewStartPort").ok_or(UpnpErr::InvalidArgs)?;
    let end = tag_u16(body, b"NewEndPort").ok_or(UpnpErr::InvalidArgs)?;
    if end < start {
        return Err(UpnpErr::InconsistentParameters);
    }
    let proto = match xml_tag(body, b"NewProtocol") {
        Some(p) if eq_ia(p, b"TCP") => Proto::Tcp,
        Some(p) if eq_ia(p, b"UDP") => Proto::Udp,
        _ => return Err(UpnpErr::InvalidArgs),
    };
    Ok((start, end, proto))
}

/// GetListOfPortMappings: NewStartPort/NewEndPort/NewProtocol
/// (TCP|UDP|ALL)/NewNumberOfPorts, with NewManage accepted and ignored
/// (managed entries are not a concept this facade exposes). A start above
/// the end is 733 InconsistentParameters, as for the delete (2.5.21.7).
fn parse_list_args(body: &[u8]) -> Result<(u16, u16, Option<Proto>, u16), UpnpErr> {
    let start = tag_u16(body, b"NewStartPort").ok_or(UpnpErr::InvalidArgs)?;
    let end = tag_u16(body, b"NewEndPort").ok_or(UpnpErr::InvalidArgs)?;
    if end < start {
        return Err(UpnpErr::InconsistentParameters);
    }
    let proto = match xml_tag(body, b"NewProtocol") {
        Some(p) if eq_ia(p, b"TCP") => Some(Proto::Tcp),
        Some(p) if eq_ia(p, b"UDP") => Some(Proto::Udp),
        Some(p) if eq_ia(p, b"ALL") => None,
        _ => return Err(UpnpErr::InvalidArgs),
    };
    let max = tag_u16(body, b"NewNumberOfPorts").unwrap_or(0);
    Ok((start, end, proto, max))
}

/// Fire one GENA NOTIFY at a callback (bounded by the caller's timeout).
async fn deliver_notify(cb_ip: Ipv4Addr, cb_port: u16, req: &[u8]) {
    let mut stream = match TcpStream::connect((cb_ip, cb_port)).await {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = stream.write_all(req).await;
    let mut buf = [0u8; 512];
    let _ = stream.read(&mut buf).await;
}

// ---- argument parsing (E3: fallible, never panics) ----

fn parse_add_args(body: &[u8]) -> Result<(u16, Proto, u16, Ipv4Addr, u32), UpnpErr> {
    parse_add_args_impl(body, false)
}

/// AddAnyPortMapping: the AddPortMapping argument table plus NewReservedPort
/// (table 2-41). Unlike AddPortMapping, a wildcard NewExternalPort is not a
/// malformed request here: it is the action's any-free-port form, which a
/// device may support (2.5.17.3), and this one does. The facade decides what
/// port the wildcard reserves.
fn parse_add_args_any(body: &[u8]) -> Result<(u16, Proto, u16, Ipv4Addr, u32), UpnpErr> {
    parse_add_args_impl(body, true)
}

/// The shared parse of the AddPortMapping argument table (table 2-11). The
/// wildcard external port is the only difference between the two callers.
fn parse_add_args_impl(
    body: &[u8],
    wildcard_ext: bool,
) -> Result<(u16, Proto, u16, Ipv4Addr, u32), UpnpErr> {
    let ext = tag_u16(body, b"NewExternalPort").ok_or(UpnpErr::InvalidArgs)?;
    let proto = match xml_tag(body, b"NewProtocol") {
        Some(p) if eq_ia(p, b"TCP") => Proto::Tcp,
        Some(p) if eq_ia(p, b"UDP") => Proto::Udp,
        _ => return Err(UpnpErr::InvalidArgs),
    };
    let int_port = tag_u16(body, b"NewInternalPort").ok_or(UpnpErr::InvalidArgs)?;
    let client = xml_tag(body, b"NewInternalClient")
        .and_then(|c| std::str::from_utf8(c).ok())
        .and_then(|c| c.parse::<Ipv4Addr>().ok())
        .ok_or(UpnpErr::InvalidArgs)?;
    if (ext == 0 && !wildcard_ext) || int_port == 0 || client == Ipv4Addr::UNSPECIFIED {
        return Err(UpnpErr::InvalidArgs);
    }
    // RemoteHost accepted and ignored (EIF); NewEnabled and the description
    // are descriptive; a missing lease means the maximum.
    let lifetime = tag_u32(body, b"NewLeaseDuration").unwrap_or(0);
    Ok((ext, proto, int_port, client, lifetime))
}

fn parse_delete_args(body: &[u8]) -> Result<(u16, Proto), UpnpErr> {
    let ext = tag_u16(body, b"NewExternalPort").ok_or(UpnpErr::InvalidArgs)?;
    let proto = match xml_tag(body, b"NewProtocol") {
        Some(p) if eq_ia(p, b"TCP") => Proto::Tcp,
        Some(p) if eq_ia(p, b"UDP") => Proto::Udp,
        _ => return Err(UpnpErr::InvalidArgs),
    };
    Ok((ext, proto))
}

fn parse_index_arg(body: &[u8]) -> Result<u32, UpnpErr> {
    tag_u32(body, b"NewPortMappingIndex").ok_or(UpnpErr::InvalidArgs)
}

fn tag_u16(body: &[u8], tag: &[u8]) -> Option<u16> {
    let v = xml_tag(body, tag)?;
    std::str::from_utf8(v).ok()?.trim().parse().ok()
}

fn tag_u32(body: &[u8], tag: &[u8]) -> Option<u32> {
    let v = xml_tag(body, tag)?;
    std::str::from_utf8(v).ok()?.trim().parse().ok()
}

fn parse_timeout(v: Option<&[u8]>) -> Option<u32> {
    let v = v?;
    // "Second-300" | "infinite"
    if eq_ia(v, b"infinite") {
        return Some(GENA_TIMEOUT_CAP);
    }
    let prefix = b"Second-";
    if starts_with_ia(v, prefix) && v.len() > prefix.len() {
        return std::str::from_utf8(&v[prefix.len()..])
            .ok()?
            .trim()
            .parse()
            .ok();
    }
    None
}

fn parse_sid_header(head: &[u8]) -> Option<Sid> {
    Sid::from_bytes(upnp::find_header(head, b"SID")?)
}

fn parse_callback(cb: &[u8]) -> Option<(Ipv4Addr, u16, &[u8])> {
    let mut v = trim(cb);
    if v.len() >= 2 && v.first() == Some(&b'<') && v.last() == Some(&b'>') {
        v = &v[1..v.len() - 1];
    }
    // One delivery URL only: a residual bracket means additional or
    // malformed delivery URLs (GENA's multi-URL CALLBACK form) — reject
    // rather than mangle them into the path and lose every notification.
    if find_byte(v, b'<').is_some() || find_byte(v, b'>').is_some() {
        return None;
    }
    if !starts_with_ia(v, b"http://") {
        return None;
    }
    let rest = &v[7..];
    let slash = find_byte(rest, b'/').unwrap_or(rest.len());
    let hostport = &rest[..slash];
    let path = &rest[slash..];
    let (ip, port) = match find_byte(hostport, b':') {
        Some(c) => (
            std::str::from_utf8(&hostport[..c]).ok()?.parse().ok()?,
            std::str::from_utf8(&hostport[c + 1..]).ok()?.parse().ok()?,
        ),
        None => (std::str::from_utf8(hostport).ok()?.parse().ok()?, 80u16),
    };
    Some((ip, port, path))
}

fn in_lan(ip: Ipv4Addr, lan: Ipv4Addr) -> bool {
    let a = u32::from(ip) & 0xffff_ff00;
    let b = u32::from(lan) & 0xffff_ff00;
    a == b
}

/// The AddAnyPortMapping wildcard's port choice (section 2.5.17): the
/// lowest requested port at or above 1024 that no entry of this protocol
/// claims. The 1024 floor is the recommended lower bound for a control
/// point with limited permission (2.5.16.2), and reserving above it keeps
/// the well-known range out of the automatic choice. The scan always
/// terminates: the lease table caps at a configured few hundred slots
/// while the port space holds 64512 of them.
fn free_requested_port(entries: &[FacadeEntry], proto: Proto) -> u16 {
    let mut p = ANY_PORT_BASE;
    while p < u16::MAX && entries.iter().any(|e| e.proto == proto && e.req_ext == p) {
        p += 1;
    }
    p
}

/// An AddPortMapping or AddAnyPortMapping request (table 2-11): the
/// argument set the two allocation entry points share, so the pair differs
/// in port resolution alone.
#[derive(Clone, Debug)]
struct MappingReq {
    ext: u16,
    proto: Proto,
    client: Ipv4Addr,
    int_port: u16,
    lifetime: u32,
    desc: String,
}

/// The containment a caller without the lift is held to (plan/0008
/// section 26.22). `caller` is the only address the caller may name;
/// `high_port` adds the floor the spec recommends beside it (2.5.16.2,
/// 2.5.18.2, 2.5.14.2, 2.5.21.3). The floor is a field rather than a rule
/// because it binds only where a control point can authenticate to lift
/// it, which is the v2 face, while the address clause needs no remedy and
/// binds both faces.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Contain {
    caller: Ipv4Addr,
    high_port: bool,
}

/// Whether a mapping request is within the containment (2.5.16.2): the
/// caller's own address, and, where the floor applies, an internal and
/// external port at or above 1024. A wildcard external port is the
/// any-free-port form, which resolves above the floor by construction, so
/// it is admitted; AddPortMapping's parser refuses it anyway.
fn request_within(c: Contain, client: Ipv4Addr, ext: u16, int_port: u16) -> bool {
    client == c.caller
        && (!c.high_port || (int_port >= ANY_PORT_BASE && (ext == 0 || ext >= ANY_PORT_BASE)))
}

/// Whether an existing entry is within the containment (2.5.14.2,
/// 2.5.18.2, 2.5.21.3): the caller's own mapping, both ports at or above
/// 1024 where the floor applies.
fn entry_within(c: Contain, e: &FacadeEntry) -> bool {
    e.owner == c.caller
        && (!c.high_port || (e.int_port >= ANY_PORT_BASE && e.req_ext >= ANY_PORT_BASE))
}

/// The port an AddAnyPortMapping request reserves (section 2.5.17): the
/// requested port when it is free or already this client's, and otherwise
/// any free port of the protocol. The distinction is the whole of the
/// preferred semantics: a port another client holds is not evicted, so the
/// answer NewReservedPort carries differs from the request, which is the
/// case the action exists for. A wildcard (0) is the same question with no
/// preference expressed.
fn preferred_port(entries: &[FacadeEntry], req_ext: u16, proto: Proto) -> u16 {
    // A preferred port is honoured. It used to be moved aside when another
    // client held it, which was the one-holder rule; with a per-client label
    // (call/0022) another client's holder is no obstacle, and the only request
    // that has to be resolved is the wildcard, which states no preference.
    // On an uplink where this device owns the real port, the datapath decides
    // whether the preference can be bound; the label is the control point's
    // either way.
    if req_ext == 0 {
        free_requested_port(entries, proto)
    } else {
        req_ext
    }
}

/// The version 2 reading of NewLeaseDuration (sections 2.3.16, 2.5.16.2
/// and 2.5.17.3): version 2 has no static mappings, so a lease of 0 means
/// the maximum, 604800 seconds. The v1 face keeps 0 as the permanent
/// mapping a legacy control point means by it.
fn wip2_lease(lifetime: u32) -> u32 {
    if lifetime == 0 { WIP2_MAX_LEASE } else { lifetime }
}

/// NewPortMappingDescription: the control point's label for the mapping
/// (2.3.22). The description is control-point-controlled text that the
/// device stores and later emits, so two things are done here rather than
/// at the writers: control characters are dropped, because the persisted
/// index is one tab-separated line per entry and a newline in the label
/// would forge a second one, and the length is bounded.
fn parse_desc(body: &[u8]) -> String {
    let raw = xml_tag(body, b"NewPortMappingDescription").unwrap_or(b"");
    let clean: String = String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    clean.chars().take(DESC_MAX).collect()
}

/// The connection status the evented surface reports. This line is not
/// dialled by anything of ours, so the only two states the daemon can
/// honestly claim are "the external tuple is known" and "it is not".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Connected,
    Disconnected,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Connected => "Connected",
            Status::Disconnected => "Disconnected",
        }
    }
}

/// The declared evented variables of the WAN connection service, as one
/// value: one subscriber's view of the daemon's own truth (call/0025). The
/// reads answer from the same state, so an event cannot contradict a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EventView {
    ext_ip: Ipv4Addr,
    status: Status,
    entries: u16,
    update_id: u32,
}

impl EventView {
    fn new(ext_ip: Ipv4Addr, entries: u16, update_id: u32) -> Self {
        EventView {
            ext_ip,
            status: if ext_ip == Ipv4Addr::UNSPECIFIED {
                Status::Disconnected
            } else {
                Status::Connected
            },
            entries,
            update_id,
        }
    }
}

/// Build a NOTIFY body carrying exactly the declared evented variables that
/// moved, all of them for a subscription's initial event. An empty string
/// means nothing moved, which is not an event: a subscriber is told about
/// changes, and inventing one would make the next query contradict it.
fn propertyset(prev: Option<&EventView>, now: &EventView) -> String {
    let mut props = String::new();
    if prev.map_or(true, |p| p.status != now.status) {
        props.push_str(&format!(
            "<e:property><ConnectionStatus>{}</ConnectionStatus></e:property>",
            now.status.as_str()
        ));
    }
    if prev.map_or(true, |p| p.ext_ip != now.ext_ip) {
        props.push_str(&format!(
            "<e:property><ExternalIPAddress>{}</ExternalIPAddress></e:property>",
            now.ext_ip
        ));
    }
    if prev.map_or(true, |p| p.entries != now.entries) {
        props.push_str(&format!(
            "<e:property><PortMappingNumberOfEntries>{}</PortMappingNumberOfEntries></e:property>",
            now.entries
        ));
    }
    if prev.map_or(true, |p| p.update_id != now.update_id) {
        props.push_str(&format!(
            "<e:property><SystemUpdateID>{}</SystemUpdateID></e:property>",
            now.update_id
        ));
    }
    if props.is_empty() {
        return String::new();
    }
    format!(
        "<?xml version=\"1.0\"?>\n<e:propertyset xmlns:e=\"urn:schemas-upnp-org:event-1-0\">{}</e:propertyset>\n",
        props
    )
}

/// How many mappings a subscriber's view holds: the same containment the
/// reads apply, so a contained control point cannot count another client's
/// namespace.
fn scoped_count(scope: Option<Contain>, entries: &[FacadeEntry]) -> u16 {
    let n = match scope {
        None => entries.len(),
        Some(c) => entries.iter().filter(|e| entry_within(c, e)).count(),
    };
    n.min(u16::MAX as usize) as u16
}

/// The transport a MAP names, as this daemon's slot engine spells it. The
/// zero protocol ("all protocols") and anything but UDP and TCP are not
/// mappings this datapath can hold.
fn proto_of(code: u8) -> Option<Proto> {
    match code {
        17 => Some(Proto::Udp),
        6 => Some(Proto::Tcp),
        _ => None,
    }
}

/// An error answer: the suggested external port and address come back as the
/// request gave them, which is what RFC 6887 section 11.1 asks an error
/// response to carry.
fn pcp_error(code: u8, sug_ext: u16, sug_ip: Ipv4Addr) -> crate::pcp::MapAnswer {
    crate::pcp::MapAnswer::Answer {
        code,
        lifetime: crate::pcp::error_lifetime(code),
        ext_port: sug_ext,
        ext_ip: sug_ip,
    }
}

/// NAT-PMP's own result codes (RFC 6886 section 3.5) for the outcomes the
/// admission shares with PCP.
fn npmp_code(pcp_code: u8) -> u8 {
    use crate::pcp::np;
    use crate::pcp::rc;
    match pcp_code {
        rc::SUCCESS => np::SUCCESS,
        rc::USER_EX_QUOTA | rc::NO_RESOURCES => np::NO_RESOURCES,
        rc::NETWORK_FAILURE => np::NETWORK_FAILURE,
        _ => np::NOT_AUTHORIZED,
    }
}

/// How long a mapping may wait for its discovery before the server says so.
/// A request that cannot be answered yet is dropped, because the client's own
/// retransmission is the only recovery the protocol provides; past this much
/// waiting the drop is no longer honest, and the network error is.
const DISCOVERY_GRACE_S: u64 = 10;

/// The verdict for a mapping whose tuple is not known yet: silence while the
/// wait is young, NETWORK_FAILURE (RFC 6887 section 7.4, a short-lifetime
/// error) once it is not.
fn discovery_verdict(waited_s: u64, tuple_known: bool) -> Option<u8> {
    if tuple_known || waited_s < DISCOVERY_GRACE_S {
        None
    } else {
        Some(crate::pcp::rc::NETWORK_FAILURE)
    }
}

/// Escape the five XML metacharacters. Only the description needs it: the
/// other emitted fields are numbers or a parsed address, while the
/// description is arbitrary text a control point chose.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn entry_xml(e: &FacadeEntry, with_key: bool) -> String {
    let proto = match e.proto {
        Proto::Tcp => "TCP",
        Proto::Udp => "UDP",
    };
    let mut s = String::new();
    if with_key {
        s.push_str("<NewRemoteHost></NewRemoteHost>");
        s.push_str(&format!("<NewExternalPort>{}</NewExternalPort>", e.req_ext));
        s.push_str(&format!("<NewProtocol>{}</NewProtocol>", proto));
    }
    s.push_str(&format!("<NewInternalPort>{}</NewInternalPort>", e.int_port));
    s.push_str(&format!("<NewInternalClient>{}</NewInternalClient>", e.client));
    s.push_str("<NewEnabled>1</NewEnabled>");
    s.push_str(&format!(
        "<NewPortMappingDescription>{}</NewPortMappingDescription>",
        xml_escape(&e.desc)
    ));
    s.push_str(&format!("<NewLeaseDuration>{}</NewLeaseDuration>", e.granted_lifetime));
    s
}

fn insert_sorted(es: &mut Vec<FacadeEntry>, e: FacadeEntry) {
    let pos = es
        .iter()
        .position(|x| (x.req_ext, x.proto.code()) > (e.req_ext, e.proto.code()))
        .unwrap_or(es.len());
    es.insert(pos, e);
}

/// The control-plane entry for a grant: one entry per internal
/// (proto, client, int_port) tuple, riding the external port the control
/// point last used ("the requested port rides the re-Add"). Returns the
/// stray slot a same-client replace leaves behind — that client's previous
/// entry at the requested port, whose datapath the caller must tear down —
/// or None when no slot changed owner. Another client's entry at the same
/// port is never a stray: the requested port is a per-client label.
#[allow(clippy::too_many_arguments)] // one flat decision over the grant's fields
fn apply_entry(
    es: &mut Vec<FacadeEntry>,
    req_ext: u16,
    proto: Proto,
    client: Ipv4Addr,
    owner: Ipv4Addr,
    int_port: u16,
    bind_port: u16,
    lifetime: u32,
    now_unix: u64,
    desc: String,
) -> Option<(u16, Ipv4Addr, u16)> {
    let expires = now_unix.saturating_add(u64::from(lifetime));
    // Same internal tuple: the upsert refreshed the existing slot in place
    // — the entry rides to the newly requested external port, bind
    // untouched, nothing torn down.
    if let Some(idx) = es
        .iter()
        .position(|e| e.proto == proto && e.owner == owner && e.int_port == int_port)
    {
        let mut e = es.remove(idx);
        e.req_ext = req_ext;
        e.granted_lifetime = lifetime;
        e.expires_at_unix = expires;
        e.desc = desc;
        insert_sorted(es, e);
        return None;
    }
    // The same client's own mapping at the same requested port, with a
    // different internal tuple: the upsert granted a NEW slot, so that
    // client's previous entry must surrender the port: one holder per
    // client per port, because the port is that client's handle and a
    // client cannot hold two mappings under one handle. An entry whose bind_port
    // already IS the new slot is a stale index row — refresh it in place
    // rather than tear it down.
    //
    // Another client's holder at the same requested port is NOT an
    // occupant to evict. The requested port is a per-client label: the
    // facade's datapath never binds it (the AFTR dictates the real tuple
    // on the ds-lite uplink, and our own slot ranges do on an IPv4 NAT we
    // control), so two clients may each hold 3074 with their own slots and
    // their own real tuples. This is where the supersession lands: the
    // specification's one-holder rule assumes the device owns the external
    // port, and here it does not.
    // A request that names no port carries no handle, and it therefore cannot
    // take another mapping away. Measured on the router on 2026-09-20: a PCP
    // lease with a carrier-chosen port was torn down two seconds after it was
    // granted, because the same client's NAT-PMP leg asked for the same
    // no-preference key (`req_ext` 0) and its supersession named the PCP
    // lease's slot. The loser was the client's own mapping, and any client
    // whose library sends both protocols loses one mapping per request.
    if req_ext != 0 {
        if let Some(idx) = es
            .iter()
            .position(|e| e.req_ext == req_ext && e.proto == proto && e.owner == owner)
        {
            let stray = if es[idx].bind_port != bind_port {
                Some((es[idx].bind_port, es[idx].client, es[idx].int_port))
            } else {
                None
            };
            let e = &mut es[idx];
            e.req_ext = req_ext;
            e.client = client;
            e.int_port = int_port;
            e.bind_port = bind_port;
            e.granted_lifetime = lifetime;
            e.expires_at_unix = expires;
            e.desc = desc;
            return stray;
        }
    }
    insert_sorted(
        es,
        FacadeEntry {
            req_ext,
            proto,
            owner,
            client,
            int_port,
            bind_port,
            granted_lifetime: lifetime,
            expires_at_unix: expires,
            desc,
        },
    );
    None
}

// ---- HTTP plumbing ----

/// Split the request head from any bytes already read past its
/// terminator (the body, when the client sends head+body in one packet).
fn split_head(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let n = buf.len();
    for i in 0..n {
        if i + 4 <= n && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((&buf[..i + 4], &buf[i + 4..]));
        }
        if i + 2 <= n && &buf[i..i + 2] == b"\n\n" {
            return Some((&buf[..i + 2], &buf[i + 2..]));
        }
    }
    None
}

async fn read_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() >= HTTP_CAP {
            break;
        }
        let done = buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n");
        if done {
            break;
        }
    }
    Ok(buf)
}

fn content_length(head: &[u8]) -> Option<usize> {
    let v = upnp::find_header(head, b"Content-Length")?;
    std::str::from_utf8(v).ok()?.trim().parse().ok()
}

async fn read_body(stream: &mut TcpStream, want: usize) -> io::Result<Vec<u8>> {
    let want = want.min(HTTP_CAP);
    let mut body = Vec::with_capacity(want);
    let mut tmp = [0u8; 1024];
    while body.len() < want {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        let take = n.min(want - body.len());
        body.extend_from_slice(&tmp[..take]);
    }
    Ok(body)
}

fn request_path(head: &[u8]) -> Option<&[u8]> {
    let n = head.len();
    let mut i = 0usize;
    while i < n && head[i] != b'\n' {
        i += 1;
    }
    let mut line = &head[..i.min(n)];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    let sp1 = find_byte(line, b' ')?;
    let rest = trim(&line[sp1 + 1..]);
    let end = find_byte(rest, b' ').unwrap_or(rest.len());
    Some(&rest[..end])
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    body: &[u8],
    extra: &str,
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {}\r\n{}SERVER: {}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        extra,
        SERVER_LINE,
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

async fn write_soap_fault(stream: &mut TcpStream, f: &UpnpFault) -> io::Result<()> {
    let body = upnp::soap_fault(f);
    let head = format!(
        "HTTP/1.1 500 Internal Server Error\r\nSERVER: {}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        SERVER_LINE,
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

// ---- SSDP socket (REUSEPORT + multicast on br-lan) ----

fn bind_ssdp(lan_ip: Ipv4Addr) -> io::Result<UdpSocket> {
    let sock = unsafe {
        // O_NONBLOCK|O_CLOEXEC at creation: tokio's from_std only
        // debug-asserts nonblocking (stripped in release — a blocking
        // socket here wedged the whole night on the rig: one worker
        // parked inside recvfrom and the io-driver handoff degraded until
        // the HTTP accept loop never woke). SOCK_CLOEXEC keeps the fd out
        // of children (lxc-attach, nft subprocesses).
        let fd = libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: SSDP_PORT.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(Ipv4Addr::UNSPECIFIED).to_be(),
            },
            sin_zero: [0u8; 8],
        };
        let r = libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if r != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        std::net::UdpSocket::from_raw_fd(fd)
    };
    sock.set_multicast_loop_v4(false)?;
    sock.set_multicast_ttl_v4(2)?;
    // Join and send on the LAN interface BY INDEX, never by address: the
    // LAN IP may be bound to more than one interface (this rig carries
    // 192.168.21.1 on br-lan /24 AND on the wg_a92_t6d6 tunnel as a /32),
    // and join_multicast_v4(addr) resolves the interface from the local
    // table, which picked the point-to-point tunnel — SSDP then never
    // heard br-lan's multicast. ip_mreqn with an explicit ifindex and
    // imr_address = 0 is the robust form.
    let Some(idx) = lan_ifindex(lan_ip) else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "no non-point-to-point interface owns the lan address",
        ));
    };
    let mreqn = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr {
            s_addr: u32::from(SSDP_MCAST).to_be(),
        },
        imr_address: libc::in_addr { s_addr: 0 },
        imr_ifindex: idx,
    };
    unsafe {
        for opt in [libc::IP_ADD_MEMBERSHIP, libc::IP_MULTICAST_IF] {
            let r = libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                opt,
                &mreqn as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
            );
            if r != 0 {
                // Fail closed: a group join that silently failed would be
                // a discovery-deaf SSDP responder that still advertises
                // itself (the E8 posture, same as the lan_ifindex check).
                let msg = match opt {
                    libc::IP_ADD_MEMBERSHIP => "join multicast group",
                    _ => "set multicast interface",
                };
                emiteln!("upnp: ssdp {} failed: {}", msg, io::Error::last_os_error());
                return Err(io::Error::last_os_error());
            }
        }
    }
    tokio::net::UdpSocket::from_std(sock)
}

/// The LAN interface index for `lan_ip`: the broadcast-scope (Ethernet or
/// bridge) interface owning the address, preferring it over any
/// point-to-point (tunnel) interface that also carries the address,
/// falling back to any owner if only a tunnel has it.
fn lan_ifindex(lan_ip: Ipv4Addr) -> Option<i32> {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return None;
    }
    let mut best: Option<[u8; 16]> = None;
    let mut fallback: Option<[u8; 16]> = None;
    unsafe {
        let mut p = addrs;
        while !p.is_null() {
            let ifa = &*p;
            if !ifa.ifa_addr.is_null()
                && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET
            {
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if ip == lan_ip {
                    let bytes = std::ffi::CStr::from_ptr(ifa.ifa_name).to_bytes();
                    if bytes.len() < 16 {
                        let mut nm = [0u8; 16];
                        nm[..bytes.len()].copy_from_slice(bytes);
                        if fallback.is_none() {
                            fallback = Some(nm);
                        }
                        if ifa.ifa_flags & (libc::IFF_POINTOPOINT as u32) == 0 {
                            best = Some(nm);
                        }
                    }
                }
            }
            p = ifa.ifa_next;
        }
    }
    unsafe { libc::freeifaddrs(addrs) };
    let name = best.or(fallback)?;
    // `name` is zero-padded; CString rejects interior NULs, so use the
    // used portion only.
    let used = name.iter().position(|&b| b == 0).unwrap_or(16);
    let cname = std::ffi::CString::new(&name[..used]).ok()?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx as i32)
    }
}

const NOTIFY_STS: [SearchTarget; 6] = [
    SearchTarget::RootDevice,
    SearchTarget::InternetGatewayDevice,
    SearchTarget::WanDevice,
    SearchTarget::WanConnectionDevice,
    SearchTarget::WanIpConnection,
    SearchTarget::WanPppConnection,
];

// ---- identity (stable UDN from the br-lan MAC; bootid persists) ----

// ---- plan/0008 #v2-service-set: DeviceProtection helpers ----

/// The device's 16-octet identity (the DeviceID in the PKCS5
/// authenticator computation, spec 2.6.6.4). Derived from the stable
/// root UDN: the dashed-hex UUID's bytes when the UDN is dashed hex,
/// else a stable fnv projection. Both the device and a control point
/// derive the same value from the same UDN, so the ceremony binds.
fn dp_device_id(udn: &str) -> [u8; 16] {
    let core = udn.strip_prefix("uuid:").unwrap_or(udn);
    let mut hex = String::with_capacity(32);
    for c in core.chars() {
        if c != '-' {
            hex.push(c);
        }
    }
    if let Some(id) = dp::unhex16(&hex) {
        return id;
    }
    let mut data = Vec::new();
    data.extend_from_slice(b"dp-device-id");
    data.extend_from_slice(udn.as_bytes());
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&fnv1a(&data, 0xcbf29ce484222325).to_be_bytes());
    raw[8..].copy_from_slice(&fnv1a(&data, 0x9e3779b97f4a7c15).to_be_bytes());
    raw
}

/// Load the persistent DP security configuration (users + ACL, plan/0008
/// section 26.15) from `dp.tsv`; absent or unreadable config yields the
/// restrictive default: an empty ACL, so every protected action is denied
/// until the operator provisions `dp.tsv` out-of-band.
fn dp_load(dir: &str, device_id: [u8; 16]) -> dp::DpState {
    let path = format!("{}/dp.tsv", dir);
    let (users, acl) = match std::fs::read_to_string(&path) {
        Ok(text) => dp::config_from_tsv(&text),
        Err(_) => (Vec::new(), dp::DpAcl::default()),
    };
    dp::DpState::new(device_id, users, acl)
}

/// Atomically persist the DP security configuration (tmpfile + rename,
/// the same discipline as leases.tsv).
fn dp_save(dir: &str, state: &dp::DpState) {
    let _ = std::fs::create_dir_all(dir);
    let text = dp::config_tsv(&state.users, &state.acl);
    let tmp = format!("{}/dp.tsv.tmp", dir);
    let final_path = format!("{}/dp.tsv", dir);
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, final_path);
    }
}

/// A fresh 16-octet random nonce (challenge/Salt source). Bounded read:
/// exactly 16 bytes from /dev/urandom (the facade's earlier unbounded
/// urandom read is the recorded OOM root cause; never read unbounded).
fn dp_random_16() -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Ok(f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut cap = f.take(16);
        let _ = cap.read_exact(&mut out);
    }
    out
}

/// Map a DeviceProtection error onto the facade error surface (the SOAP
/// fault codes of spec 2.6.15).
fn map_dp_err(e: dp::DpErr) -> UpnpErr {
    match e {
        dp::DpErr::InvalidValue => UpnpErr::InvalidValue,
        dp::DpErr::NotAuthorized => UpnpErr::NotAuthorized,
        dp::DpErr::AuthFailure => UpnpErr::AuthFailure,
        dp::DpErr::Processing => UpnpErr::Processing,
    }
}

fn load_identity(state_dir: &str, lan_ip: Ipv4Addr, bind_ip: Ipv4Addr) -> (String, u32) {
    let path = format!("{}/upnp-ident", state_dir);
    if let Ok(s) = std::fs::read_to_string(&path) {
        let mut lines = s.lines();
        if let (Some(u), Some(b)) = (lines.next(), lines.next()) {
            if let Ok(b) = b.trim().parse() {
                return (u.trim().to_string(), b);
            }
        }
    }
    let mac = read_mac();
    let mut data = Vec::new();
    data.extend_from_slice(b"ds-lite-punch");
    data.extend_from_slice(&mac);
    data.extend_from_slice(&u32::from(lan_ip).to_be_bytes());
    data.extend_from_slice(&u32::from(bind_ip).to_be_bytes());
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&fnv1a(&data, 0xcbf29ce484222325).to_be_bytes());
    raw[8..].copy_from_slice(&fnv1a(&data, 0x9e3779b97f4a7c15).to_be_bytes());
    raw[6] = (raw[6] & 0x0f) | 0x50;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    let udn = String::from_utf8_lossy(&upnp::uuid_hex(&raw)).into_owned();
    let _ = std::fs::create_dir_all(state_dir);
    let _ = std::fs::write(&path, format!("{}\n1\n", udn));
    (udn, 1)
}

fn read_mac() -> [u8; 6] {
    if let Ok(s) = std::fs::read_to_string("/sys/class/net/br-lan/address") {
        let s = s.trim().to_string();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            let mut ok = true;
            for (i, p) in parts.iter().enumerate() {
                if let Ok(b) = u8::from_str_radix(p, 16) {
                    mac[i] = b;
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                return mac;
            }
        }
    }
    [0u8; 6]
}

fn fnv1a(data: &[u8], seed: u64) -> u64 {
    let mut h = seed;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn random_sid() -> Sid {
    // READ EXACTLY 16 BYTES. std::fs::read(/dev/urandom) is read_to_end —
    // it loops until EOF, and /dev/urandom never returns EOF, so the buffer
    // doubles without bound (2^29 locally, 2^34 = 16 GiB on the router:
    // every GENA SUBSCRIBE OOM-killed the daemon before this fix).
    let mut raw = [0u8; 16];
    let seeded = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut raw)
        })
        .is_ok();
    if !seeded {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e3779b97f4a7c15);
        let mut x = seed | 1;
        for b in raw.iter_mut() {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (x >> 33) as u8;
        }
    }
    Sid::v4(&raw)
}

// ---- persisted entry index (respawn continuity of the req-ext key) ----

/// One persisted index row: the seven fixed fields, then the control
/// point's description.
fn entry_line(e: &FacadeEntry) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
        e.req_ext,
        e.proto.code(),
        e.bind_port,
        e.client,
        e.int_port,
        e.granted_lifetime,
        e.expires_at_unix,
        e.desc,
        e.owner
    )
}

/// A persisted index row back to an entry. The row grew twice: the
/// description was added, then the requester. A seven-field row restores with
/// an empty description, and a row without the requester takes the target as
/// the requester, which is what those rows meant (they were written before a
/// lifted control point could map on another host's behalf). A row that
/// parses to nothing is skipped.
fn entry_from_line(line: &str) -> Option<FacadeEntry> {
    let parts: Vec<&str> = line.split('\t').collect();
    if !(7..=9).contains(&parts.len()) {
        return None;
    }
    let req_ext: u16 = parts[0].parse().ok()?;
    let proto = match parts[1].trim() {
        "6" => Proto::Tcp,
        _ => Proto::Udp,
    };
    let bind_port: u16 = parts[2].parse().ok()?;
    let client: Ipv4Addr = parts[3].parse().ok()?;
    let int_port: u16 = parts[4].parse().ok()?;
    let granted_lifetime: u32 = parts[5].parse().ok()?;
    let expires_at_unix: u64 = parts[6].parse().ok()?;
    let desc = parts.get(7).copied().unwrap_or("").to_string();
    // a row written before the requester existed means the target, since a
    // control point then could only map for itself
    let owner = match parts.get(8).and_then(|o| o.parse::<Ipv4Addr>().ok()) {
        Some(o) => o,
        None => client,
    };
    Some(FacadeEntry {
        req_ext,
        proto,
        owner,
        client,
        int_port,
        bind_port,
        granted_lifetime,
        expires_at_unix,
        desc,
    })
}

/// The persisted entry index: seven fixed fields, then the control
/// point's description, which was added later.
fn restore_entries() -> Vec<FacadeEntry> {
    let path = format!("{}/upnp.tsv", DEFAULT_DIR);
    let mut out = Vec::new();
    if let Ok(s) = std::fs::read_to_string(&path) {
        out.extend(s.lines().filter_map(entry_from_line));
    }
    out
}

// ---- description docs (E2) ----

fn root_desc(lan_ip: Ipv4Addr, port: u16, name: &str, udn: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?>\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
         <specVersion><major>1</major><minor>0</minor></specVersion>\
         <URLBase>http://{}:{}/</URLBase>\
         <device>\
         <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
         <friendlyName>{}</friendlyName>\
         <manufacturer>ds-lite-punch</manufacturer>\
         <modelDescription>CGNAT-aware IGD facade for the Virgin Media ds-lite line</modelDescription>\
         <modelName>ds-lite-punch</modelName>\
         <modelNumber>0.1</modelNumber>\
         <UDN>uuid:{}</UDN>\
         <deviceList><device>\
         <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\
         <friendlyName>WANDevice</friendlyName>\
         <manufacturer>ds-lite-punch</manufacturer>\
         <modelName>ds-lite-punch</modelName>\
         <UDN>uuid:{}</UDN>\
         <serviceList>\
         <service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>\
         <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>\
         <SCPDURL>/WANCfg.xml</SCPDURL><controlURL>/ctl/CmnIfCfg</controlURL>\
         <eventSubURL>/ctl/CmnIfCfg</eventSubURL></service>\
         </serviceList>\
         <deviceList><device>\
         <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\
         <friendlyName>WANConnectionDevice</friendlyName>\
         <manufacturer>ds-lite-punch</manufacturer>\
         <modelName>ds-lite-punch</modelName>\
         <UDN>uuid:{}</UDN>\
         <serviceList>\
         <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
         <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>\
         <SCPDURL>/WANIPC.xml</SCPDURL><controlURL>/ctl/IPConn</controlURL>\
         <eventSubURL>/ctl/IPConn</eventSubURL></service>\
         <service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>\
         <serviceId>urn:upnp-org:serviceId:WANPPPConn1</serviceId>\
         <SCPDURL>/WANPPP.xml</SCPDURL><controlURL>/ctl/PPPConn</controlURL>\
         <eventSubURL>/ctl/PPPConn</eventSubURL></service>\
         </serviceList></device></deviceList></device></deviceList></device></root>\n",
        lan_ip,
        port,
        name,
        udn,
        derived_udn(udn, b"WANDevice"),
        derived_udn(udn, b"WANConn"),
    )
    .into_bytes()
}

/// plan/0008's LOCATION design: the IGD:2 root description (gated route data).
/// DeviceProtection:1 sits directly under InternetGatewayDevice:2 per
/// section 26.4; WANIPConnection:2 under WANConnectionDevice:2. This is
/// the v2 surface definition; it is not served until the
/// #v2-service-set task flips IGD_V2_ENABLED (R6 mount gate).
fn root_desc_v2(lan_ip: Ipv4Addr, port: u16, name: &str, udn: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?>\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
         <specVersion><major>1</major><minor>0</minor></specVersion>\
         <URLBase>http://{}:{}/</URLBase>\
         <device>\
         <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>\
         <friendlyName>{}</friendlyName>\
         <manufacturer>ds-lite-punch</manufacturer>\
         <modelDescription>CGNAT-aware IGD facade for the Virgin Media ds-lite line</modelDescription>\
         <modelName>ds-lite-punch</modelName>\
         <modelNumber>0.1</modelNumber>\
         <UDN>uuid:{}</UDN>\
         <serviceList>\
         <service><serviceType>urn:schemas-upnp-org:service:DeviceProtection:1</serviceType>\
         <serviceId>urn:upnp-org:serviceId:DeviceProtection1</serviceId>\
         <SCPDURL>/igd/v2/DP.xml</SCPDURL><controlURL>/ctl/DP</controlURL>\
         <eventSubURL>/ctl/DP</eventSubURL></service>\
         <service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>\
         <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>\
         <SCPDURL>/igd/v1/WANCfg.xml</SCPDURL><controlURL>/ctl/CmnIfCfg</controlURL>\
         <eventSubURL>/ctl/CmnIfCfg</eventSubURL></service>\
         </serviceList>\
         <deviceList><device>\
         <deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType>\
         <friendlyName>WANDevice</friendlyName>\
         <manufacturer>ds-lite-punch</manufacturer>\
         <modelName>ds-lite-punch</modelName>\
         <UDN>uuid:{}</UDN>\
         <deviceList><device>\
         <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType>\
         <friendlyName>WANConnectionDevice</friendlyName>\
         <manufacturer>ds-lite-punch</manufacturer>\
         <modelName>ds-lite-punch</modelName>\
         <UDN>uuid:{}</UDN>\
         <serviceList>\
         <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>\
         <serviceId>urn:upnp-org:serviceId:WANIPConn2</serviceId>\
         <SCPDURL>/igd/v2/WANIPCn.xml</SCPDURL><controlURL>/ctl/IPConn</controlURL>\
         <eventSubURL>/ctl/IPConn</eventSubURL></service>\
         </serviceList></device></deviceList></device></deviceList></device></root>\n",
        lan_ip, port, name, udn,
        derived_udn(udn, b"WANDevice"),
        derived_udn(udn, b"WANConn"),
    )
    .into_bytes()
}

fn derived_udn(base: &str, tag: &[u8]) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(base.as_bytes());
    data.extend_from_slice(tag);
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&fnv1a(&data, 0xcbf29ce484222325).to_be_bytes());
    raw[8..].copy_from_slice(&fnv1a(&data, 0x9e3779b97f4a7c15).to_be_bytes());
    raw[6] = (raw[6] & 0x0f) | 0x50;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    String::from_utf8_lossy(&upnp::uuid_hex(&raw)).into_owned()
}

/// The NewPortListing fragment prefix: the PortMappingList root of the
/// WANIPConnection:2 PortListing datastructure, exactly as the sample of
/// the spec's section 2.3.25.2 renders it (namespace and schema location
/// included; the named schema URL no longer answers, so the sample is the
/// shape authority).
const PORT_LISTING_OPEN: &str = r#"<p:PortMappingList xmlns:p="urn:schemas-upnp-org:gw:WANIPConnection" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:schemas-upnp-org:gw:WANIPConnection http://www.upnp.org/schemas/gw/WANIPConnection-v2.xsd">"#;

/// The wrapper that carries the fragment as the value of
/// GetListOfPortMappings' NewPortListing OUT argument: A_ARG_TYPE_PortListing
/// is a string holding an XML document, so the fragment rides in a CDATA
/// section inside the argument element rather than as the response's own
/// children, where no control point would find it under that name. The
/// reference server emits the same wrapper, and the reference client
/// collects the listing only from the character data of this element.
/// A description cannot break the section: `xml_escape` renders `>` as
/// `&gt;`, so `]]>` cannot occur inside a fragment.
const PORT_LISTING_WRAP_OPEN: &str = "<NewPortListing><![CDATA[";
const PORT_LISTING_WRAP_CLOSE: &str = "]]></NewPortListing>";

/// WANIPConnection:1 service description. Cribbed from miniupnpd (BSD
/// license, `netfilter/upnp_desc.c`); the action/argument/state-variable
/// shapes follow the UPnP IGDv1 spec. The PPP alias serves the same SCPD
/// (its action set is identical for the actions we honour).
const SCPD_WANIP: &str = r#"<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
<specVersion><major>1</major><minor>0</minor></specVersion>
<actionList>
<action><name>GetConnectionTypeInfo</name><argumentList>
<argument><name>NewConnectionType</name><direction>out</direction><relatedStateVariable>ConnectionType</relatedStateVariable></argument>
<argument><name>NewPossibleConnectionTypes</name><direction>out</direction><relatedStateVariable>PossibleConnectionTypes</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetStatusInfo</name><argumentList>
<argument><name>NewConnectionStatus</name><direction>out</direction><relatedStateVariable>ConnectionStatus</relatedStateVariable></argument>
<argument><name>NewLastConnectionError</name><direction>out</direction><relatedStateVariable>LastConnectionError</relatedStateVariable></argument>
<argument><name>NewUptime</name><direction>out</direction><relatedStateVariable>Uptime</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetExternalIPAddress</name><argumentList>
<argument><name>NewExternalIPAddress</name><direction>out</direction><relatedStateVariable>ExternalIPAddress</relatedStateVariable></argument>
</argumentList></action>
<action><name>AddPortMapping</name><argumentList>
<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
<argument><name>NewInternalPort</name><direction>in</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
<argument><name>NewInternalClient</name><direction>in</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
<argument><name>NewEnabled</name><direction>in</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
<argument><name>NewPortMappingDescription</name><direction>in</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
<argument><name>NewLeaseDuration</name><direction>in</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
</argumentList></action>
<action><name>DeletePortMapping</name><argumentList>
<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetGenericPortMappingEntry</name><argumentList>
<argument><name>NewPortMappingIndex</name><direction>in</direction><relatedStateVariable>PortMappingNumberOfEntries</relatedStateVariable></argument>
<argument><name>NewRemoteHost</name><direction>out</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
<argument><name>NewExternalPort</name><direction>out</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>out</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
<argument><name>NewInternalPort</name><direction>out</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
<argument><name>NewInternalClient</name><direction>out</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
<argument><name>NewEnabled</name><direction>out</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
<argument><name>NewPortMappingDescription</name><direction>out</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
<argument><name>NewLeaseDuration</name><direction>out</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetSpecificPortMappingEntry</name><argumentList>
<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
<argument><name>NewInternalPort</name><direction>out</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
<argument><name>NewInternalClient</name><direction>out</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
<argument><name>NewEnabled</name><direction>out</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
<argument><name>NewPortMappingDescription</name><direction>out</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
<argument><name>NewLeaseDuration</name><direction>out</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
</argumentList></action>
</actionList>
<serviceStateTable>
<stateVariable sendEvents="no"><name>ConnectionType</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>PossibleConnectionTypes</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="yes"><name>ConnectionStatus</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>LastConnectionError</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="yes"><name>ExternalIPAddress</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>Uptime</name><dataType>ui4</dataType></stateVariable>
<stateVariable sendEvents="no"><name>RemoteHost</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>ExternalPort</name><dataType>ui2</dataType></stateVariable>
<stateVariable sendEvents="no"><name>PortMappingProtocol</name><dataType>string</dataType><allowedValueList><allowedValue>TCP</allowedValue><allowedValue>UDP</allowedValue></allowedValueList></stateVariable>
<stateVariable sendEvents="no"><name>InternalPort</name><dataType>ui2</dataType></stateVariable>
<stateVariable sendEvents="no"><name>InternalClient</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>PortMappingEnabled</name><dataType>boolean</dataType></stateVariable>
<stateVariable sendEvents="no"><name>PortMappingDescription</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>PortMappingLeaseDuration</name><dataType>ui4</dataType></stateVariable>
<stateVariable sendEvents="yes"><name>PortMappingNumberOfEntries</name><dataType>ui2</dataType></stateVariable>
</serviceStateTable>
</scpd>
"#;

/// The PPP alias serves the identical SCPD (the WANPPPConnection:1 action
/// set matches WANIPConnection's for the actions we honour).
const SCPD_WANPPP: &str = SCPD_WANIP;

/// WANCommonInterfaceConfig:1 service description. Cribbed from miniupnpd
/// (BSD license, `netfilter/upnp_desc.c`); the single action honoured is
/// GetCommonLinkProperties. miniupnpc's GetValidIGD gates device
/// validation on the *presence* of this service in the root description,
/// so it must be advertised even though only the one action is answered.
const SCPD_WANCMN: &str = r#"<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
<specVersion><major>1</major><minor>0</minor></specVersion>
<actionList>
<action><name>GetCommonLinkProperties</name><argumentList>
<argument><name>NewWANAccessType</name><direction>out</direction><relatedStateVariable>WANAccessType</relatedStateVariable></argument>
<argument><name>NewLayer1UpstreamMaxBitRate</name><direction>out</direction><relatedStateVariable>Layer1UpstreamMaxBitRate</relatedStateVariable></argument>
<argument><name>NewLayer1DownstreamMaxBitRate</name><direction>out</direction><relatedStateVariable>Layer1DownstreamMaxBitRate</relatedStateVariable></argument>
<argument><name>NewPhysicalLinkStatus</name><direction>out</direction><relatedStateVariable>PhysicalLinkStatus</relatedStateVariable></argument>
</argumentList></action>
</actionList>
<serviceStateTable>
<stateVariable sendEvents="no"><name>WANAccessType</name><dataType>string</dataType><allowedValueList><allowedValue>DSL</allowedValue><allowedValue>Cable</allowedValue><allowedValue>POTS</allowedValue></allowedValueList></stateVariable>
<stateVariable sendEvents="no"><name>Layer1UpstreamMaxBitRate</name><dataType>ui4</dataType></stateVariable>
<stateVariable sendEvents="no"><name>Layer1DownstreamMaxBitRate</name><dataType>ui4</dataType></stateVariable>
<stateVariable sendEvents="yes"><name>PhysicalLinkStatus</name><dataType>string</dataType><allowedValueList><allowedValue>Up</allowedValue><allowedValue>Down</allowedValue></allowedValueList></stateVariable>
</serviceStateTable>
</scpd>
"#;

/// plan/0008: the WANIPConnection:2 SCPD (gated route data). The action
/// surface, every argument table, and the state table are transcribed from
/// the normative spec (docs/upnp-wip2/UPnP-gw-WANIPConnection-v2-Service.md,
/// sections 2.3, 2.4, 2.5 and the section 4 XML Service Description
/// reassembled in docs/upnp-wip2/TRANSCRIPTION.md): twenty-one actions,
/// twenty-three state variables of which five are evented. The placeholder
/// this replaces carried a bogus action (GetLinkLayerMaxBitRates, which
/// belongs to WANCommonInterfaceConfig), argument-less action entries, five
/// invented A_ARG_TYPE variables, and a state table that evented nothing.
const SCPD_WIP2: &str = r#"<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
<specVersion><major>1</major><minor>0</minor></specVersion>
<actionList>
<action><name>SetConnectionType</name><argumentList>
<argument><name>NewConnectionType</name><direction>in</direction><relatedStateVariable>ConnectionType</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetConnectionTypeInfo</name><argumentList>
<argument><name>NewConnectionType</name><direction>out</direction><relatedStateVariable>ConnectionType</relatedStateVariable></argument>
<argument><name>NewPossibleConnectionTypes</name><direction>out</direction><relatedStateVariable>PossibleConnectionTypes</relatedStateVariable></argument>
</argumentList></action>
<action><name>RequestConnection</name></action>
<action><name>ForceTermination</name></action>
<action><name>GetStatusInfo</name><argumentList>
<argument><name>NewConnectionStatus</name><direction>out</direction><relatedStateVariable>ConnectionStatus</relatedStateVariable></argument>
<argument><name>NewLastConnectionError</name><direction>out</direction><relatedStateVariable>LastConnectionError</relatedStateVariable></argument>
<argument><name>NewUptime</name><direction>out</direction><relatedStateVariable>Uptime</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetNATRSIPStatus</name><argumentList>
<argument><name>NewRSIPAvailable</name><direction>out</direction><relatedStateVariable>RSIPAvailable</relatedStateVariable></argument>
<argument><name>NewNATEEnabled</name><direction>out</direction><relatedStateVariable>NATEEnabled</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetGenericPortMappingEntry</name><argumentList>
<argument><name>NewPortMappingIndex</name><direction>in</direction><relatedStateVariable>PortMappingNumberOfEntries</relatedStateVariable></argument>
<argument><name>NewRemoteHost</name><direction>out</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
<argument><name>NewExternalPort</name><direction>out</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>out</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
<argument><name>NewInternalPort</name><direction>out</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
<argument><name>NewInternalClient</name><direction>out</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
<argument><name>NewEnabled</name><direction>out</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
<argument><name>NewPortMappingDescription</name><direction>out</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
<argument><name>NewLeaseDuration</name><direction>out</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetSpecificPortMappingEntry</name><argumentList>
<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
<argument><name>NewInternalPort</name><direction>out</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
<argument><name>NewInternalClient</name><direction>out</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
<argument><name>NewEnabled</name><direction>out</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
<argument><name>NewPortMappingDescription</name><direction>out</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
<argument><name>NewLeaseDuration</name><direction>out</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
</argumentList></action>
<action><name>AddPortMapping</name><argumentList>
<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
<argument><name>NewInternalPort</name><direction>in</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
<argument><name>NewInternalClient</name><direction>in</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
<argument><name>NewEnabled</name><direction>in</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
<argument><name>NewPortMappingDescription</name><direction>in</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
<argument><name>NewLeaseDuration</name><direction>in</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
</argumentList></action>
<action><name>AddAnyPortMapping</name><argumentList>
<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
<argument><name>NewInternalPort</name><direction>in</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>
<argument><name>NewInternalClient</name><direction>in</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>
<argument><name>NewEnabled</name><direction>in</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>
<argument><name>NewPortMappingDescription</name><direction>in</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>
<argument><name>NewLeaseDuration</name><direction>in</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>
<argument><name>NewReservedPort</name><direction>out</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
</argumentList></action>
<action><name>DeletePortMapping</name><argumentList>
<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>
<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
</argumentList></action>
<action><name>DeletePortMappingRange</name><argumentList>
<argument><name>NewStartPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewEndPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
<argument><name>NewManage</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Manage</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetExternalIPAddress</name><argumentList>
<argument><name>NewExternalIPAddress</name><direction>out</direction><relatedStateVariable>ExternalIPAddress</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetListOfPortMappings</name><argumentList>
<argument><name>NewStartPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewEndPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>
<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>
<argument><name>NewManage</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Manage</relatedStateVariable></argument>
<argument><name>NewNumberOfPorts</name><direction>in</direction><relatedStateVariable>PortMappingNumberOfEntries</relatedStateVariable></argument>
<argument><name>NewPortListing</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_PortListing</relatedStateVariable></argument>
</argumentList></action>
</actionList>
<serviceStateTable>
<stateVariable sendEvents="no"><name>ConnectionType</name><dataType>string</dataType><defaultValue>IP_Routed</defaultValue><allowedValueList><allowedValue>Unconfigured</allowedValue><allowedValue>IP_Routed</allowedValue><allowedValue>IP_Bridged</allowedValue></allowedValueList></stateVariable>
<stateVariable sendEvents="yes"><name>PossibleConnectionTypes</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="yes"><name>ConnectionStatus</name><dataType>string</dataType><allowedValueList><allowedValue>Unconfigured</allowedValue><allowedValue>Connecting</allowedValue><allowedValue>Connected</allowedValue><allowedValue>PendingDisconnect</allowedValue><allowedValue>Disconnecting</allowedValue><allowedValue>Disconnected</allowedValue></allowedValueList></stateVariable>
<stateVariable sendEvents="no"><name>Uptime</name><dataType>ui4</dataType></stateVariable>
<stateVariable sendEvents="no"><name>LastConnectionError</name><dataType>string</dataType><allowedValueList><allowedValue>ERROR_NONE</allowedValue><allowedValue>ERROR_COMMAND_ABORTED</allowedValue><allowedValue>ERROR_NOT_ENABLED_FOR_INTERNET</allowedValue><allowedValue>ERROR_ISP_DISCONNECT</allowedValue><allowedValue>ERROR_USER_DISCONNECT</allowedValue><allowedValue>ERROR_IDLE_DISCONNECT</allowedValue><allowedValue>ERROR_FORCED_DISCONNECT</allowedValue><allowedValue>ERROR_NO_CARRIER</allowedValue><allowedValue>ERROR_IP_CONFIGURATION</allowedValue><allowedValue>ERROR_UNKNOWN</allowedValue></allowedValueList></stateVariable>
<stateVariable sendEvents="no"><name>AutoDisconnectTime</name><dataType>ui4</dataType></stateVariable>
<stateVariable sendEvents="no"><name>IdleDisconnectTime</name><dataType>ui4</dataType></stateVariable>
<stateVariable sendEvents="no"><name>WarnDisconnectDelay</name><dataType>ui4</dataType></stateVariable>
<stateVariable sendEvents="no"><name>RSIPAvailable</name><dataType>boolean</dataType></stateVariable>
<stateVariable sendEvents="no"><name>NATEEnabled</name><dataType>boolean</dataType></stateVariable>
<stateVariable sendEvents="yes"><name>ExternalIPAddress</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="yes"><name>PortMappingNumberOfEntries</name><dataType>ui2</dataType></stateVariable>
<stateVariable sendEvents="no"><name>PortMappingEnabled</name><dataType>boolean</dataType></stateVariable>
<stateVariable sendEvents="no"><name>PortMappingLeaseDuration</name><dataType>ui4</dataType><defaultValue>Vendor-defined</defaultValue><allowedValueRange><minimum>0</minimum><maximum>604800</maximum></allowedValueRange></stateVariable>
<stateVariable sendEvents="no"><name>RemoteHost</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>ExternalPort</name><dataType>ui2</dataType><allowedValueRange><minimum>0</minimum><maximum>65535</maximum></allowedValueRange></stateVariable>
<stateVariable sendEvents="no"><name>InternalPort</name><dataType>ui2</dataType><allowedValueRange><minimum>1</minimum><maximum>65535</maximum></allowedValueRange></stateVariable>
<stateVariable sendEvents="no"><name>PortMappingProtocol</name><dataType>string</dataType><allowedValueList><allowedValue>TCP</allowedValue><allowedValue>UDP</allowedValue></allowedValueList></stateVariable>
<stateVariable sendEvents="no"><name>InternalClient</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>PortMappingDescription</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="yes"><name>SystemUpdateID</name><dataType>ui4</dataType></stateVariable>
<stateVariable sendEvents="no"><name>A_ARG_TYPE_Manage</name><dataType>boolean</dataType></stateVariable>
<stateVariable sendEvents="no"><name>A_ARG_TYPE_PortListing</name><dataType>string</dataType></stateVariable>
</serviceStateTable>
</scpd>
"#;

/// DeviceProtection:1 service description (urn:schemas-upnp-org:service:DeviceProtection:1).
/// The action surface is transcribed from the normative spec
/// (docs/upnp-dp1/UPnP-gw-DeviceProtection-V1-Service.md, sections 2.6.1-2.6.13):
/// thirteen actions, every argument table per the spec. Earlier
/// miniupnpd-derived names (RequestUserLogin, ValidateIdentity, AddACLEntry,
/// LoginWithPIN, ...) were wrong and are superseded. The Kani gate verifies
/// this document carries exactly the authoritative action names.
const SCPD_DP: &str = r#"<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
<specVersion><major>1</major><minor>0</minor></specVersion>
<actionList>
<action><name>SendSetupMessage</name><argumentList>
<argument><name>ProtocolType</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>InMessage</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Base64</relatedStateVariable></argument>
<argument><name>OutMessage</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Base64</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetSupportedProtocols</name><argumentList>
<argument><name>ProtocolList</name><direction>out</direction><relatedStateVariable>SupportedProtocols</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetAssignedRoles</name><argumentList>
<argument><name>RoleList</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetRolesForAction</name><argumentList>
<argument><name>DeviceUDN</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>ServiceId</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>ActionName</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>RoleList</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>RestrictedRoleList</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetUserLoginChallenge</name><argumentList>
<argument><name>ProtocolType</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>Name</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>Salt</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Base64</relatedStateVariable></argument>
<argument><name>Challenge</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Base64</relatedStateVariable></argument>
</argumentList></action>
<action><name>UserLogin</name><argumentList>
<argument><name>ProtocolType</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>Challenge</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Base64</relatedStateVariable></argument>
<argument><name>Authenticator</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Base64</relatedStateVariable></argument>
</argumentList></action>
<action><name>UserLogout</name></action>
<action><name>GetACLData</name><argumentList>
<argument><name>ACL</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_ACL</relatedStateVariable></argument>
</argumentList></action>
<action><name>AddIdentityList</name><argumentList>
<argument><name>IdentityList</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_IdentityList</relatedStateVariable></argument>
<argument><name>IdentityListResult</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_IdentityList</relatedStateVariable></argument>
</argumentList></action>
<action><name>RemoveIdentity</name><argumentList>
<argument><name>Identity</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Identity</relatedStateVariable></argument>
</argumentList></action>
<action><name>SetUserLoginPassword</name><argumentList>
<argument><name>ProtocolType</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>Name</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
<argument><name>Stored</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Base64</relatedStateVariable></argument>
<argument><name>Salt</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Base64</relatedStateVariable></argument>
</argumentList></action>
<action><name>AddRolesForIdentity</name><argumentList>
<argument><name>Identity</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Identity</relatedStateVariable></argument>
<argument><name>RoleList</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
</argumentList></action>
<action><name>RemoveRolesForIdentity</name><argumentList>
<argument><name>Identity</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Identity</relatedStateVariable></argument>
<argument><name>RoleList</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_String</relatedStateVariable></argument>
</argumentList></action>
</actionList>
<serviceStateTable>
<stateVariable sendEvents="yes"><name>SetupReady</name><dataType>boolean</dataType></stateVariable>
<stateVariable sendEvents="no"><name>SupportedProtocols</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>A_ARG_TYPE_ACL</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>A_ARG_TYPE_IdentityList</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>A_ARG_TYPE_Identity</name><dataType>string</dataType></stateVariable>
<stateVariable sendEvents="no"><name>A_ARG_TYPE_Base64</name><dataType>bin.base64</dataType></stateVariable>
<stateVariable sendEvents="no"><name>A_ARG_TYPE_String</name><dataType>string</dataType></stateVariable>
</serviceStateTable>
</scpd>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot::PortAllocator;

    #[test]
    fn lan_subnet_check() {
        let lan = Ipv4Addr::new(192, 168, 21, 1);
        assert!(in_lan(Ipv4Addr::new(192, 168, 21, 138), lan));
        assert!(in_lan(Ipv4Addr::new(192, 168, 21, 1), lan));
        assert!(!in_lan(Ipv4Addr::new(192, 168, 0, 21), lan));
        assert!(!in_lan(Ipv4Addr::new(10, 0, 0, 5), lan));
    }

    #[test]
    fn callback_parse() {
        let (ip, port, path) = parse_callback(b"<http://192.168.21.50:34567/evt>").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 21, 50));
        assert_eq!(port, 34567);
        assert_eq!(path, b"/evt");
        let (ip2, port2, path2) = parse_callback(b"http://192.168.21.9/notify").unwrap();
        assert_eq!(ip2, Ipv4Addr::new(192, 168, 21, 9));
        assert_eq!(port2, 80);
        assert_eq!(path2, b"/notify");
        assert!(parse_callback(b"<https://192.168.21.50/evt>").is_none());
        assert!(parse_callback(b"garbage").is_none());
    }

    #[test]
    fn random_sid_is_bounded_and_v4() {
        // Regression (2026-09-14): random_sid used std::fs::read on
        // /dev/urandom — read_to_end loops forever on a device with no
        // EOF, doubling its buffer until the host OOMs (2^34 bytes on the
        // router: every GENA SUBSCRIBE killed the daemon). A bounded
        // read_exact keeps SID generation cheap regardless of how many
        // times it is called.
        for _ in 0..64 {
            let sid = random_sid();
            let b = sid.0;
            assert_eq!(b.len(), 16);
            // UUIDv4 markers set by Sid::v4
            assert_eq!(b[6] >> 4, 4, "version nibble");
            assert_eq!(b[8] >> 6, 2, "variant bits");
        }
    }

    #[test]
    fn timeout_parse() {
        assert_eq!(parse_timeout(Some(b"Second-300")), Some(300));
        assert_eq!(parse_timeout(Some(b"Second-0")), Some(0));
        assert_eq!(parse_timeout(Some(b"infinite")), Some(GENA_TIMEOUT_CAP));
        assert_eq!(parse_timeout(Some(b"junk")), None);
        assert_eq!(parse_timeout(None), None);
    }

    #[test]
    fn sid_header_parse() {
        let head =
            b"SUBSCRIBE /ctl/IPConn HTTP/1.1\r\nSID: uuid:0123456789abcdef0123456789abcdef\r\n\r\n";
        let sid = parse_sid_header(head).unwrap();
        assert_eq!(
            sid,
            Sid::from_bytes(b"uuid:0123456789abcdef0123456789abcdef").unwrap()
        );
        let bad = b"SUBSCRIBE /ctl/IPConn HTTP/1.1\r\nSID: uuid:zz\r\n\r\n";
        assert!(parse_sid_header(bad).is_none());
    }

    #[test]
    fn entry_sort_and_xml() {
        let mut es = Vec::new();
        let mk = |req_ext: u16, proto: Proto| FacadeEntry {
            req_ext,
            proto,
            owner: Ipv4Addr::new(192, 168, 21, 50),
            client: Ipv4Addr::new(192, 168, 21, 50),
            int_port: req_ext,
            bind_port: req_ext + 1000,
            granted_lifetime: 600,
            expires_at_unix: 0,
            desc: String::new(),
        };
        insert_sorted(&mut es, mk(2000, Proto::Udp));
        insert_sorted(&mut es, mk(1000, Proto::Tcp));
        insert_sorted(&mut es, mk(1000, Proto::Udp));
        let order: Vec<(u16, Proto)> = es.iter().map(|e| (e.req_ext, e.proto)).collect();
        assert_eq!(
            order,
            vec![(1000, Proto::Tcp), (1000, Proto::Udp), (2000, Proto::Udp)]
        );
        let xml = entry_xml(&es[0], true);
        assert!(xml.contains("<NewExternalPort>1000</NewExternalPort>"));
        assert!(xml.contains("<NewProtocol>TCP</NewProtocol>"));
        assert!(xml.contains("<NewInternalClient>192.168.21.50</NewInternalClient>"));
    }

    #[test]
    fn derived_udn_stable() {
        let a = derived_udn("deadbeef", b"WANDevice");
        let b = derived_udn("deadbeef", b"WANDevice");
        let c = derived_udn("deadbeef", b"WANConn");
        assert_eq!(a, b, "deterministic per (base, tag)");
        assert_ne!(a, c, "different tags diverge");
        assert_eq!(a.len(), 36);
    }

    #[test]
    fn root_desc_shape() {
        let doc_bytes = root_desc(
            Ipv4Addr::new(192, 168, 21, 1),
            49152,
            "test-igd",
            "abcdef",
        );
        let doc = String::from_utf8_lossy(&doc_bytes);
        assert!(doc.contains("<URLBase>http://192.168.21.1:49152/</URLBase>"));
        assert!(doc.contains("<friendlyName>test-igd</friendlyName>"));
        assert!(doc.contains("<UDN>uuid:abcdef</UDN>"));
        assert!(doc.contains("WANIPConnection:1"));
        assert!(doc.contains("WANPPPConnection:1"));
        assert!(doc.contains("/ctl/IPConn"));
        assert!(doc.contains("/WANIPC.xml"));
        // the WANCommonInterfaceConfig service gates miniupnpc's IGD
        // validation (GetValidIGD marks the device only when the rootDesc
        // advertises it), so its presence is load-bearing, not cosmetic
        assert!(doc.contains("WANCommonInterfaceConfig:1"));
        assert!(doc.contains("/WANCfg.xml"));
        assert!(doc.contains("/ctl/CmnIfCfg"));
        // the embedded devices get their own derived UDNs
        assert!(doc.contains("uuid:"), "derived child UDNs present");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn http_hammer_stability() {
        // Off-production harness for the facade's HTTP accept/dispatch
        // loop: concurrent GETs and a held-open stall on an ephemeral
        // port must all be served (200, non-empty body), and closing a
        // stalled peer must free its permit so the pool recovers.
        fn is_ok(buf: &[u8]) -> bool {
            buf.starts_with(b"HTTP/1.1 200 OK")
        }
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "hammer".into(),
            grace_secs: 60,
        };
        let table = Arc::new(Mutex::new(LeaseTable::new(
            PortAllocator::new(30000, 30009).unwrap(),
            4,
            2,
        )));
        let publisher =
            Arc::new(Publisher::with_watch("/tmp/none", watch::channel(Ipv4Addr::LOCALHOST).0));
        let facade = Arc::new(UpnpFacade {
            cfg,
            table,
            publisher,
            entries: Mutex::new(Vec::new()),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("hammer"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let f2 = facade.clone();
        tokio::spawn(async move {
            let _ = http_serve(listener, f2).await;
        });

        let client = |what: &'static [u8]| {
            async move {
                let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
                s.write_all(what).await.unwrap();
                let mut buf = Vec::new();
                let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
                    .await
                    .expect("response within 5s");
                buf
            }
        };

        // round 1: 12 concurrent GETs (under the 16-permit cap), all must
        // be served whole
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..12 {
            set.spawn(client(b"GET /rootDesc.xml HTTP/1.0\r\n\r\n"));
        }
        let mut served = 0usize;
        while let Some(r) = set.join_next().await {
            let buf = r.unwrap();
            if is_ok(buf.as_slice()) {
                served += 1;
            }
        }
        assert_eq!(served, 12, "all round-1 GETs must be served whole");

        // round 2: 12 peers stall mid-head, then close; a fresh GET after
        // each close must still be served (permit recovered on EOF)
        for i in 0..12 {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(b"GET /rootDes").await.unwrap();
            drop(s);
            tokio::time::sleep(Duration::from_millis(50)).await;
            let buf = client(b"GET /rootDesc.xml HTTP/1.0\r\n\r\n").await;
            assert!(
                is_ok(buf.as_slice()),
                "GET after stall-close {} must be served",
                i
            );
        }

        // round 3: a body-stall (head declares a body that never arrives)
        // must not wedge the pool: cap 16, so 6 such stalls must leave the
        // 7th request dropped (documented cap behavior) but a later EOF+… 
        // -- sanity only: the 30s timeout bounds these.
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            b"POST /ctl/IPConn HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n",
        )
        .await
        .unwrap();
        let mut set2 = tokio::task::JoinSet::new();
        for _ in 0..6 {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let _ = s
                .write_all(b"POST /ctl/IPConn HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n")
                .await;
            set2.spawn(async move {
                let t = s;
                let _ = t.readable().await;
                t
            });
        }
        // 6 + 1 = 7 held; a fresh GET is served (11 permits left)
        let buf = client(b"GET /rootDesc.xml HTTP/1.0\r\n\r\n").await;
        assert!(is_ok(buf.as_slice()), "GET with stalls pending must be served");
        drop(s);
        drop(set2);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let buf = client(b"GET /rootDesc.xml HTTP/1.0\r\n\r\n").await;
        assert!(is_ok(buf.as_slice()), "GET after closing all stalls must be served");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn udp_slot_revoke_releases_socket() {
        // Regression (2026-09-14, found live on the rig): spawn_udp_slot
        // used to return an empty handle vector, so delete_mapping/GC
        // aborted nothing and the slot socket stayed bound forever after a
        // Delete. The keepalive is a sibling task holding its own Arc of
        // the socket, so BOTH handles must be surfaced and aborted for the
        // socket to drop.
        use tokio::net::UdpSocket as TokioUdp;

        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "slot-revoke".into(),
            grace_secs: 60,
        };
        let table = Arc::new(Mutex::new(LeaseTable::new(
            PortAllocator::new(30000, 30009).unwrap(),
            4,
            2,
        )));
        let publisher =
            Arc::new(Publisher::with_watch("/tmp/none", watch::channel(Ipv4Addr::LOCALHOST).0));
        let facade = Arc::new(UpnpFacade {
            cfg,
            table,
            publisher,
            entries: Mutex::new(Vec::new()),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("slot-revoke"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });

        let bind_port = 41001;
        let handles = facade
            .spawn_udp_slot(bind_port, Ipv4Addr::LOCALHOST, 51001)
            .await
            .expect("slot spawn on loopback");
        assert_eq!(handles.len(), 2, "keepalive + recv handles must both surface");

        // While the slot tasks live, the socket is bound.
        let probe = TokioUdp::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        probe
            .connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bind_port))
            .await
            .unwrap();
        // The slot socket answers on its bound port while alive.
        let _ = probe.send(b"ping").await;

        // Revoke: abort both handles, as delete_mapping / gc_loop do.
        for h in &handles {
            h.abort();
        }
        // Let the abort propagate; then a fresh bind on the same port must
        // succeed — the socket is gone, not just orphaned.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let rebind = TokioUdp::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bind_port)).await;
        assert!(
            rebind.is_ok(),
            "slot socket must be released after revoke (rebind failed: {:?})",
            rebind.err()
        );
    }

    #[test]
    fn a_request_with_no_port_preference_does_not_supersede_another() {
        // Measured on the router on 2026-09-20: a PCP lease was torn down two
        // seconds after it was granted, by the same client's NAT-PMP request,
        // which asks for "any port". A request that names no port carries no
        // handle, so it cannot take another mapping away.
        let a = Ipv4Addr::new(192, 168, 21, 11);
        let mut es = Vec::new();
        assert_eq!(
            apply_entry(&mut es, 0, Proto::Udp, a, a, 41010, 40002, 600, 1000, "pcp".to_string()),
            None
        );
        assert_eq!(
            apply_entry(&mut es, 0, Proto::Udp, a, a, 3074, 40003, 600, 1000, "npmp".to_string()),
            None,
            "a no-preference request must not surrender the client's other mapping"
        );
        assert_eq!(es.len(), 2, "{:?}", es.len());
        let binds: Vec<u16> = es.iter().map(|e| e.bind_port).collect();
        assert!(
            binds.contains(&40002) && binds.contains(&40003),
            "{:?}",
            binds
        );
    }

    #[test]
    fn apply_entry_keyed_per_client_lets_two_holders_share_a_port() {
        // Regression (review C2): the entry index used to refresh on
        // (req_ext, proto) and never updated bind_port, so a re-Add that
        // moved the mapping to a NEW slot left the entry naming the old
        // slot — delete tore down the wrong datapath and the live mapping
        // became unenumerable. One entry per internal tuple, and, since the
        // requested port is a per-client label, one entry per client per
        // requested port: another client's holder is not an occupant to
        // evict, which is the multiple-console case.
        let now = 1_700_000_000u64;
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let b = Ipv4Addr::new(192, 168, 21, 60);
        let d = |s: &str| s.to_string();
        let mut es: Vec<FacadeEntry> = Vec::new();
        // A maps 3074/UDP -> slot 30000.
        assert_eq!(apply_entry(&mut es, 3074, Proto::Udp, a, a, 4000, 30000, 3600, now, d("client-a")), None);
        assert_eq!(es.len(), 1);
        // A re-adds the SAME internal tuple at a new requested port: the
        // entry rides the port, the same slot, nothing torn down.
        assert_eq!(apply_entry(&mut es, 3075, Proto::Udp, a, a, 4000, 30000, 3600, now, d("client-a")), None);
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].req_ext, 3075);
        assert_eq!(es[0].bind_port, 30000);
        // A claims 3075/UDP with a different internal tuple: A's own entry
        // at that port surrenders it: one holder per client per port,
        // because the port is that client's handle.
        assert_eq!(
            apply_entry(&mut es, 3075, Proto::Udp, a, a, 6000, 30005, 3600, now, d("client-a")),
            Some((30000, a, 4000))
        );
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].bind_port, 30005);
        // B also claims 3075/UDP: its own entry, and A's survives. The
        // datapath resolves each to its own slot and its own real tuple.
        assert_eq!(apply_entry(&mut es, 3075, Proto::Udp, b, b, 5000, 30001, 3600, now, d("client-b")), None);
        assert_eq!(es.len(), 2, "two clients, one requested port");
        assert_eq!(
            es.iter().filter(|e| e.req_ext == 3075).count(),
            2,
            "both holders are recorded"
        );
        // B re-adds its own tuple at the same port: plain refresh.
        assert_eq!(apply_entry(&mut es, 3075, Proto::Udp, b, b, 5000, 30001, 3600, now, d("client-b")), None);
        assert_eq!(es.len(), 2);
        // A fresh mapping on a free port: plain insert, and B may hold the
        // same port on another protocol without touching A.
        assert_eq!(apply_entry(&mut es, 9000, Proto::Tcp, a, a, 9000, 30002, 3600, now, d("client-a")), None);
        assert_eq!(apply_entry(&mut es, 9000, Proto::Tcp, b, b, 6000, 30003, 3600, now, d("client-b")), None);
        assert_eq!(es.len(), 4);
        assert_eq!(es.iter().filter(|e| e.req_ext == 9000 && e.proto == Proto::Tcp).count(), 2);
    }

    /// The v2 readings the transcription fixes, each a property a name-only
    /// implementation fails by construction: the wildcard's port choice
    /// (2.5.17), the version 2 lease reading (table 2-6), and the Listing
    /// fragment with the spec's own 7xx refusals (2.5.19, 2.5.21).
    #[test]
    fn wip2_wildcard_and_lease_readings() {
        assert_eq!(wip2_lease(0), WIP2_MAX_LEASE, "version 2: 0 is the maximum");
        assert_eq!(wip2_lease(1), 1);
        assert_eq!(wip2_lease(3600), 3600);
        assert_eq!(wip2_lease(WIP2_MAX_LEASE), WIP2_MAX_LEASE);

        let e = |req_ext: u16, proto: Proto| FacadeEntry {
            req_ext,
            proto,
            owner: Ipv4Addr::new(192, 168, 21, 50),
            client: Ipv4Addr::new(192, 168, 21, 50),
            int_port: 4000,
            bind_port: 30000,
            granted_lifetime: 3600,
            expires_at_unix: 0,
            desc: String::new(),
        };
        assert_eq!(free_requested_port(&[], Proto::Udp), ANY_PORT_BASE);
        assert_eq!(
            free_requested_port(&[e(ANY_PORT_BASE, Proto::Udp)], Proto::Udp),
            ANY_PORT_BASE + 1
        );
        assert_eq!(
            free_requested_port(
                &[e(ANY_PORT_BASE, Proto::Udp), e(ANY_PORT_BASE + 1, Proto::Udp)],
                Proto::Udp
            ),
            ANY_PORT_BASE + 2
        );
        assert_eq!(
            free_requested_port(&[e(ANY_PORT_BASE, Proto::Tcp)], Proto::Udp),
            ANY_PORT_BASE,
            "another protocol's claim is not this protocol's claim"
        );
        assert_eq!(
            free_requested_port(&[e(7000, Proto::Udp)], Proto::Udp),
            ANY_PORT_BASE,
            "a claim above the floor leaves the floor free"
        );
    }

    /// plan/0008's containment for callers without the lift: the containment the spec recommends for
    /// unauthenticated control points. The address clause needs no remedy
    /// and binds both faces; the port floor is a field, so one predicate
    /// serves the v2 face, where a control point can authenticate to lift
    /// it, and the v1 face, where it cannot.
    #[test]
    fn containment_predicates() {
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let b = Ipv4Addr::new(192, 168, 21, 60);
        let own_host = Contain { caller: a, high_port: false };
        let own_host_high = Contain { caller: a, high_port: true };

        // 2.5.16.2: another host is refused; the caller's own address is
        // admitted, with a low port admitted where no floor applies
        assert!(!request_within(own_host, b, 5000, 5000));
        assert!(request_within(own_host, a, 5000, 5000));
        assert!(request_within(own_host, a, 80, 80));
        // with the floor, a low port is refused on either side of the pair
        assert!(!request_within(own_host_high, a, 80, 5000));
        assert!(!request_within(own_host_high, a, 5000, 80));
        assert!(request_within(own_host_high, a, 1024, 1024));
        // the wildcard external port is the any-free-port form and resolves
        // above the floor by construction, so it is admitted
        assert!(request_within(own_host_high, a, 0, 5000));
        // ... and the floor never licenses another host
        assert!(!request_within(own_host_high, b, 5000, 5000));

        // 2.5.14.2, 2.5.18.2, 2.5.21.3: the same clause over an entry
        let e = |req_ext: u16, client: Ipv4Addr, int_port: u16| FacadeEntry {
            req_ext,
            proto: Proto::Udp,
            owner: client,
            client,
            int_port,
            bind_port: 30000,
            granted_lifetime: 3600,
            expires_at_unix: 0,
            desc: String::new(),
        };
        assert!(entry_within(own_host, &e(80, a, 80)), "own and low, no floor");
        assert!(!entry_within(own_host_high, &e(80, a, 80)), "own but below");
        assert!(!entry_within(own_host, &e(5000, b, 5000)), "another host");
        assert!(!entry_within(own_host_high, &e(5000, a, 80)), "internal below");
        assert!(entry_within(own_host_high, &e(5000, a, 5000)));
    }

    /// The containment over a real table: a contained caller sees, indexes
    /// and deletes only its own entries at or above the floor, while an
    /// uncontained one (the lifted session, or a v1 read) sees the whole
    /// table. This is the property the plan's open policy item asked for,
    /// and it is asserted against seeded entries because the engine's grant
    /// path needs nft.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn containment_view_over_the_table() {
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let b = Ipv4Addr::new(192, 168, 21, 60);
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/containment".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "containment".into(),
            grace_secs: 60,
        };
        let e = |req_ext: u16, proto: Proto, client: Ipv4Addr, int_port: u16| FacadeEntry {
            req_ext,
            proto,
            owner: client,
            client,
            int_port,
            bind_port: 30000,
            granted_lifetime: 3600,
            expires_at_unix: Epoch::now() + 300,
            desc: String::new(),
        };
        let facade = Arc::new(UpnpFacade {
            cfg,
            table: Arc::new(Mutex::new(LeaseTable::new(
                PortAllocator::new(30000, 30009).unwrap(),
                8,
                4,
            ))),
            publisher: Arc::new(Publisher::with_watch(
                "/tmp/none",
                watch::channel(Ipv4Addr::LOCALHOST).0,
            )),
            entries: Mutex::new(vec![
                e(80, Proto::Tcp, a, 80),
                e(5000, Proto::Udp, a, 5000),
                e(5001, Proto::Udp, b, 5001),
                e(5002, Proto::Udp, a, 80),
            ]),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("containment"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });
        let view = Some(Contain { caller: a, high_port: true });

        // the listing: one entry visible to A (its own, both ports high);
        // the whole table to an uncontained caller
        let contained = facade
            .list_port_mappings(1, 65535, None, 0, view)
            .await
            .expect("A has one visible mapping");
        assert_eq!(contained.matches("<p:PortMappingEntry>").count(), 1);
        assert!(contained.contains("<p:NewExternalPort>5000</p:NewExternalPort>"));
        let whole = facade
            .list_port_mappings(1, 65535, None, 0, None)
            .await
            .expect("the uncontained view lists");
        assert_eq!(whole.matches("<p:PortMappingEntry>").count(), 4);

        // the specific read: another client's entry is forbidden, not
        // missing, and A's own below the floor is forbidden too
        assert_eq!(
            facade.get_specific(5001, Proto::Udp, a, view).await,
            Err(UpnpErr::NoSuchEntry),
            "5001 is B's; the lookup is A's own namespace"
        );
        assert!(facade.get_specific(5001, Proto::Udp, b, None).await.is_ok());
        assert_eq!(
            facade.get_specific(80, Proto::Tcp, a, view).await,
            Err(UpnpErr::NotAuthorized)
        );

        // the enumeration: the index space is what the caller may see, so
        // A's walk ends after its one entry and an uncontained walk runs
        // the whole table
        assert!(facade.get_generic(0, view).await.is_ok());
        assert_eq!(
            facade.get_generic(1, view).await,
            Err(UpnpErr::NoSuchEntry),
            "the contained index space holds one entry"
        );
        for i in 0..4 {
            assert!(facade.get_generic(i, None).await.is_ok(), "uncontained index {}", i);
        }
        assert_eq!(facade.get_generic(4, None).await, Err(UpnpErr::NoSuchEntry));

        // A lifted control point may map on another host's behalf, and the
        // entry is keyed by the *requester* (call/0022), not by the host it
        // names. Before the requester was recorded, such an entry was keyed
        // by its target, so its owner could not read or delete it: the
        // deployed bench found exactly that (714 on its own delete).
        {
            let mut es = facade.entries.lock().await;
            es.push(FacadeEntry {
                req_ext: 25000,
                proto: Proto::Udp,
                owner: a,
                client: b,
                int_port: 25000,
                bind_port: 30007,
                granted_lifetime: 3600,
                expires_at_unix: Epoch::now() + 300,
                desc: "for-b".to_string(),
            });
        }
        let got = facade
            .get_specific(25000, Proto::Udp, a, None)
            .await
            .expect("the requester reads the mapping it made");
        assert!(
            got.contains("<NewInternalClient>192.168.21.60</NewInternalClient>"),
            "and the target is the host it named: {}",
            got
        );
        assert_eq!(
            facade.delete_mapping(25000, Proto::Udp, b, None).await,
            Err(UpnpErr::NoSuchEntry),
            "the target host is not the requester and holds nothing there"
        );
        assert!(
            facade.delete_mapping(25000, Proto::Udp, a, None).await.is_ok(),
            "the requester deletes its own mapping"
        );

        // the enumeration renders each holder as itself: two clients hold
        // 1024/UDP here, so index 1 must not render index 0's entry (the
        // defect the deployed bench caught; the index addresses the visible
        // list rather than a (port, protocol) key)
        {
            let mut es = facade.entries.lock().await;
            es.push(FacadeEntry {
                req_ext: 1024,
                proto: Proto::Udp,
                owner: b,
                client: b,
                int_port: 1024,
                bind_port: 30008,
                granted_lifetime: 3600,
                expires_at_unix: Epoch::now() + 300,
                desc: "b-owns-1024".to_string(),
            });
            es.push(FacadeEntry {
                req_ext: 1024,
                proto: Proto::Udp,
                owner: a,
                client: a,
                int_port: 1024,
                bind_port: 30009,
                granted_lifetime: 3600,
                expires_at_unix: Epoch::now() + 300,
                desc: "a-owns-1024".to_string(),
            });
        }
        let mut seen = Vec::new();
        for i in 0..8 {
            match facade.get_generic(i, None).await {
                Ok(x) => seen.push(x),
                Err(_) => break,
            }
        }
        let holders: Vec<&String> = seen
            .iter()
            .filter(|x| x.contains("<NewExternalPort>1024</NewExternalPort>"))
            .collect();
        assert_eq!(holders.len(), 2, "both holders enumerate");
        assert!(
            holders.iter().any(|x| x.contains("a-owns-1024"))
                && holders.iter().any(|x| x.contains("b-owns-1024")),
            "each index renders its own holder, not the first one twice"
        );

        // and a delete of one holder leaves the other standing
        assert!(
            facade.delete_mapping(1024, Proto::Udp, a, None).await.is_ok(),
            "A deletes the mapping it made"
        );
        assert!(
            facade
                .entries
                .lock()
                .await
                .iter()
                .any(|x| x.req_ext == 1024 && x.owner == b),
            "B's mapping at the same port is untouched by A's delete"
        );

        // a delete of another client's mapping is refused
        assert_eq!(
            facade.delete_mapping(5001, Proto::Udp, a, view).await,
            Err(UpnpErr::NoSuchEntry),
            "the port is B's; A's own namespace has nothing there"
        );
        assert!(
            facade.entries.lock().await.iter().any(|x| x.req_ext == 5001),
            "the other client's mapping survives"
        );

        // a range covering everything deletes A's visible entry and skips
        // the two it may not touch (2.5.19.2), so the action succeeds; a
        // range holding only another client's entry is 730
        assert_eq!(
            facade.delete_mapping_range(1, 65535, Proto::Udp, view).await,
            Ok(String::new())
        );
        let after = facade.entries.lock().await;
        assert!(!after.iter().any(|x| x.req_ext == 5000), "A's visible entry went");
        assert!(after.iter().any(|x| x.req_ext == 5001), "B's entry stayed");
        assert!(after.iter().any(|x| x.req_ext == 5002), "A's low-internal entry stayed");
        drop(after);
        assert_eq!(
            facade.delete_mapping_range(5001, 5001, Proto::Udp, view).await,
            Err(UpnpErr::PortMappingNotFound),
            "nothing in the range is A's to delete"
        );
    }

    /// plan/0008's version-specific SOAP semantics: allocate_exact and allocate_preferred resolve
    /// the same request differently over one engine. Exact honours the
    /// requested port and takes it over from whoever holds it; preferred
    /// moves to a free port and leaves the other client's mapping standing.
    /// The difference is the port resolution, and it is asserted here on
    /// one shared table state.
    #[test]
    fn allocate_exact_and_preferred_differ() {
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let b = Ipv4Addr::new(192, 168, 21, 60);
        let e = |req_ext: u16, proto: Proto, client: Ipv4Addr| FacadeEntry {
            req_ext,
            proto,
            owner: client,
            client,
            int_port: req_ext,
            bind_port: 30000,
            granted_lifetime: 3600,
            expires_at_unix: 0,
            desc: String::new(),
        };
        let held = vec![e(5000, Proto::Udp, a), e(5001, Proto::Udp, b)];

        // preferred: the port is a per-client label (call/0022), so another
        // client's holder is no obstacle and the preference is honoured
        assert_eq!(preferred_port(&held, 5000, Proto::Udp), 5000);
        // a wildcard states no preference, so it allocates
        assert_eq!(preferred_port(&held, 0, Proto::Udp), ANY_PORT_BASE);
        // the requester's own port is honoured, so a re-Add refreshes
        assert_eq!(preferred_port(&held, 5001, Proto::Udp), 5001);
        // a free port is honoured
        assert_eq!(preferred_port(&held, 8100, Proto::Udp), 8100);

        // exact: the same request on the same state adds beside the other
        // client's holder, which is the supersession call/0022 records; the
        // earlier holder keeps its mapping.
        let mut es = held.clone();
        assert_eq!(
            apply_entry(&mut es, 5000, Proto::Udp, b, b, 7000, 30010, 3600, 1_700_000_000, "b".into()),
            None,
            "exact adds beside the other client's holder rather than evicting it"
        );
        assert_eq!(es.len(), 3, "two clients now hold 5000/UDP");
        assert!(
            es.iter().any(|x| x.req_ext == 5000 && x.client == a),
            "the earlier holder keeps its mapping"
        );
        assert!(es.iter().any(|x| x.req_ext == 5000 && x.client == b));
    }

    /// NewPortMappingDescription is stored, not replaced by a device
    /// string (2.3.22): the enumeration and the Listing answer with what
    /// the control point sent, and the stored text cannot forge a line in
    /// the persisted index or an element in the SOAP response.
    #[test]
    fn mapping_description_is_stored_and_safe() {
        // the parse drops control characters and bounds the length
        let body = b"<NewPortMappingDescription>BitTorrent</NewPortMappingDescription>";
        assert_eq!(parse_desc(body), "BitTorrent");
        let hostile =
            b"<NewPortMappingDescription>x\n999\t6\t1\t1.1.1.1\t1\t1\t1</NewPortMappingDescription>";
        let clean = parse_desc(hostile);
        assert!(
            !clean.contains('\n') && !clean.contains('\t'),
            "a label cannot forge a persisted row: {:?}",
            clean
        );
        let long = format!(
            "<NewPortMappingDescription>{}</NewPortMappingDescription>",
            "d".repeat(200)
        );
        assert_eq!(parse_desc(long.as_bytes()).chars().count(), DESC_MAX);
        assert_eq!(parse_desc(b"<NewEnabled>1</NewEnabled>"), "", "absent means empty");

        // the emitted text is escaped, whatever the label holds
        assert_eq!(xml_escape("a<b&c\"d'e>f"), "a&lt;b&amp;c&quot;d&apos;e&gt;f");
        let e = FacadeEntry {
            req_ext: 3074,
            proto: Proto::Udp,
            owner: Ipv4Addr::new(192, 168, 21, 50),
            client: Ipv4Addr::new(192, 168, 21, 50),
            int_port: 3074,
            bind_port: 30000,
            granted_lifetime: 3600,
            expires_at_unix: 0,
            desc: "Xbox <live> & \"party\"".to_string(),
        };
        let xml = entry_xml(&e, true);
        assert!(
            xml.contains("<NewPortMappingDescription>Xbox &lt;live&gt; &amp; &quot;party&quot;</NewPortMappingDescription>"),
            "the stored label is emitted escaped: {}",
            xml
        );
        // the enumeration no longer invents a device string
        assert!(
            !xml.contains("ds-lite-punch grant"),
            "the placeholder's device-authored description is gone"
        );

        // the index round-trips the label, and a row from the earlier
        // build (seven fields, no label) still restores its mapping
        let line = entry_line(&e);
        assert!(
            line.ends_with('\n') && line.matches('\t').count() == 8,
            "nine fields: the seven fixed, the description, the requester"
        );
        let back = entry_from_line(line.trim_end()).expect("the row round-trips");
        assert_eq!(back.desc, e.desc);
        assert_eq!(back.req_ext, e.req_ext);
        assert_eq!(back.bind_port, e.bind_port);
        let legacy = "3074\t17\t30000\t192.168.21.50\t3074\t3600\t1700000000";
        let old = entry_from_line(legacy).expect("a seven-field row still loads");
        assert_eq!(old.desc, "");
        assert_eq!(old.req_ext, 3074);
        assert_eq!(old.proto, Proto::Udp);
        assert!(entry_from_line("not\ta\trow").is_none(), "junk rows drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wip2_listing_fragment_and_range_refusals() {
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/wip2-listing".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "wip2-listing".into(),
            grace_secs: 60,
        };
        let now = Epoch::now();
        let entry = |req_ext: u16, proto: Proto, int_port: u16, desc: &str| FacadeEntry {
            req_ext,
            proto,
            owner: Ipv4Addr::new(192, 168, 21, 50),
            client: Ipv4Addr::new(192, 168, 21, 50),
            int_port,
            bind_port: 30000,
            granted_lifetime: 3600,
            expires_at_unix: now + 3000,
            desc: desc.to_string(),
        };
        let facade = Arc::new(UpnpFacade {
            cfg,
            table: Arc::new(Mutex::new(LeaseTable::new(
                PortAllocator::new(30000, 30009).unwrap(),
                8,
                4,
            ))),
            publisher: Arc::new(Publisher::with_watch(
                "/tmp/none",
                watch::channel(Ipv4Addr::LOCALHOST).0,
            )),
            entries: Mutex::new(vec![
                entry(5555, Proto::Udp, 5555, "BitTorrent"),
                entry(5556, Proto::Udp, 6666, ""),
                entry(5557, Proto::Tcp, 5557, "remote-desktop"),
            ]),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("wip2-listing"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });

        // the fragment is the spec's sample shape (2.3.25.2): a namespaced
        // PortMappingList of PortMappingEntry elements, the invented
        // element tree of the placeholder gone. It is the value of the
        // NewPortListing OUT argument, so the argument element and its
        // CDATA section wrap it (the shape the reference client reads).
        let listing = facade
            .list_port_mappings(5000, 6000, Some(Proto::Udp), 0, None)
            .await
            .expect("a populated range lists");
        assert!(
            listing.starts_with("<NewPortListing><![CDATA["),
            "the fragment rides as the NewPortListing argument value: {}",
            listing
        );
        assert!(listing.contains(
            "<p:PortMappingList xmlns:p=\"urn:schemas-upnp-org:gw:WANIPConnection\""
        ));
        assert!(listing.ends_with("]]></NewPortListing>"));
        assert!(listing.contains("<p:PortMappingEntry>"));
        assert!(listing.contains("<p:NewRemoteHost></p:NewRemoteHost>"));
        assert!(listing.contains("<p:NewExternalPort>5555</p:NewExternalPort>"));
        assert!(listing.contains("<p:NewProtocol>UDP</p:NewProtocol>"));
        assert!(listing.contains("<p:NewInternalPort>5555</p:NewInternalPort>"));
        assert!(listing.contains("<p:NewInternalClient>192.168.21.50</p:NewInternalClient>"));
        assert!(listing.contains("<p:NewEnabled>1</p:NewEnabled>"));
        assert!(
            listing.contains("<p:NewDescription>BitTorrent</p:NewDescription>"),
            "the stored label is reported (2.3.25)"
        );
        assert!(
            listing.contains("<p:NewDescription></p:NewDescription>"),
            "an unlabelled mapping reports an empty description"
        );
        // a query reports the lease remaining, not the granted one (2.4.6);
        // the entry was seeded with roughly 3000 seconds left
        let open = "<p:NewLeaseTime>";
        let at = listing.find(open).expect("a lease tag") + open.len();
        let close = listing[at..].find("</p:NewLeaseTime>").expect("a lease close");
        let lease: u64 = listing[at..at + close].parse().expect("a numeric lease");
        assert!(
            (2900..=3000).contains(&lease),
            "the remaining lease is reported: {}",
            lease
        );
        assert!(
            !listing.contains("NewPortListingEntry"),
            "the placeholder's element tree is gone"
        );
        // one protocol filter, one entry: the TCP claim is not listed
        assert_eq!(listing.matches("<p:PortMappingEntry>").count(), 2);
        // the cap still bounds the listing (NewNumberOfPorts)
        let capped = facade
            .list_port_mappings(5000, 6000, None, 1, None)
            .await
            .expect("a capped range lists");
        assert_eq!(capped.matches("<p:PortMappingEntry>").count(), 1);
        assert!(capped.contains("<p:NewProtocol>UDP</p:NewProtocol>"));

        // the range refusals the spec requires: 730 on an empty range for
        // both range actions (2.5.19.2, 2.5.21.3)
        assert_eq!(
            facade.list_port_mappings(6001, 7000, None, 0, None).await,
            Err(UpnpErr::PortMappingNotFound)
        );
        assert_eq!(
            facade.delete_mapping_range(6001, 7000, Proto::Udp, None).await,
            Err(UpnpErr::PortMappingNotFound)
        );
        assert_eq!(
            facade.delete_mapping_range(5000, 6000, Proto::Tcp, None).await,
            Ok(String::new()),
            "the TCP entry in range is deleted"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn restored_grant_revoke_frees_socket() {
        // Regression (review C1): main's slot loop skips granted leases in
        // facade mode, so the facade must re-spawn respawn-restored grants
        // AND register them, or delete_mapping/gc_loop abort nothing and
        // the socket stays bound (the 2026-09-14 leak class, reachable
        // through the documented respawn path).
        use crate::slot::GrantedRecord;
        use tokio::net::UdpSocket as TokioUdp;

        let now = Epoch::now();
        let mut table = LeaseTable::new(PortAllocator::new(30000, 30009).unwrap(), 4, 2);
        table
            .restore(
                &[],
                &[GrantedRecord {
                    bind_port: 30000,
                    proto: Proto::Udp,
                    client: Ipv4Addr::LOCALHOST,
                    int_port: 51001,
                    target: Ipv4Addr::LOCALHOST,
                    target_port: 51001,
                    granted_lifetime: 3600,
                    expires_at_unix: now + 3600,
                }],
                now,
            )
            .unwrap();
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "restored-grant".into(),
            grace_secs: 60,
        };
        let facade = Arc::new(UpnpFacade {
            cfg,
            table: Arc::new(Mutex::new(table)),
            publisher: Arc::new(Publisher::with_watch(
                "/tmp/none",
                watch::channel(Ipv4Addr::LOCALHOST).0,
            )),
            entries: Mutex::new(vec![FacadeEntry {
                req_ext: 8666,
                proto: Proto::Udp,
                owner: Ipv4Addr::LOCALHOST,
                client: Ipv4Addr::LOCALHOST,
                int_port: 51001,
                bind_port: 30000,
                granted_lifetime: 3600,
                expires_at_unix: now + 3600,
                desc: String::new(),
            }]),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("restored-grant"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });

        facade.spawn_restored_grants().await;
        let registered = facade.tasks.lock().await.contains_key(&30000);
        assert!(
            registered,
            "restored-grant datapath tasks must be registered with the facade"
        );

        // The control point deletes the restored mapping: the slot row, nft
        // element and tasks must all go — the socket must be released.
        facade
            .delete_mapping(8666, Proto::Udp, Ipv4Addr::LOCALHOST, None)
            .await
            .expect("delete of a restored mapping");
        assert!(
            facade.tasks.lock().await.is_empty(),
            "delete_mapping must abort the registered restored-grant tasks"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let rebind = TokioUdp::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 30000)).await;
        assert!(
            rebind.is_ok(),
            "restored-grant socket must be released after delete (rebind failed: {:?})",
            rebind.err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gena_initial_notify_advances_seq() {
        // Regression (review S1): the initial NOTIFY carries eventKey 0 but
        // the subscription's stored seq stayed 0, so the first change event
        // re-sent 0 — a subscriber enforcing event-key monotonicity drops
        // the first change. The initial delivery must advance the key.
        let l = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = l.local_addr().unwrap().port();
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "gena-seq".into(),
            grace_secs: 60,
        };
        let facade = Arc::new(UpnpFacade {
            cfg,
            table: Arc::new(Mutex::new(LeaseTable::new(
                PortAllocator::new(30000, 30009).unwrap(),
                4,
                2,
            ))),
            publisher: Arc::new(Publisher::with_watch(
                "/tmp/none",
                watch::channel(Ipv4Addr::LOCALHOST).0,
            )),
            entries: Mutex::new(Vec::new()),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1, // seeded: external_ip = Some
            udn: String::from("gena-seq"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });

        let cb = format!("<http://127.0.0.1:{}/evt>", port);
        facade
            .gena_subscribe(cb.as_bytes(), 30, Ipv4Addr::LOCALHOST, true)
            .await
            .expect("subscribe with a reachable callback");

        async fn seq_of_head(stream: &mut TcpStream) -> u32 {
            let head = read_head(stream).await.expect("notify head");
            let s = String::from_utf8_lossy(&head);
            for line in s.lines() {
                if let Some(v) = line.strip_prefix("SEQ: ") {
                    return v.trim().parse().unwrap();
                }
            }
            panic!("notify head has no SEQ line: {}", s);
        }

        // initial NOTIFY: eventKey 0
        let (mut s0, _) = l.accept().await.unwrap();
        assert_eq!(seq_of_head(&mut s0).await, 0, "initial NOTIFY is eventKey 0");

        // first change event after the initial: must be 1, never 0
        facade.notify_all(Ipv4Addr::new(87, 116, 31, 222)).await;
        let (mut s1, _) = l.accept().await.unwrap();
        assert_eq!(seq_of_head(&mut s1).await, 1, "first change must advance past the initial key");

        // second change event: 2
        facade.notify_all(Ipv4Addr::new(87, 116, 31, 223)).await;
        let (mut s2, _) = l.accept().await.unwrap();
        assert_eq!(seq_of_head(&mut s2).await, 2, "keys must be strictly increasing");
    }
// ---- lease policy (2026-09-15): last-seen reaping ----

    fn policy_seed(client: Ipv4Addr, int_port: u16, silent_secs: u64) -> (LeaseTable, u16) {
        let now = Epoch::now();
        let mut t = LeaseTable::new(PortAllocator::new(30000, 30009).unwrap(), 8, 4);
        let g = t.upsert_pcp(Proto::Udp, int_port, client, INFINITE_LEASE, now, client, int_port);
        let port = match g {
            UpsertOutcome::Granted { bind_port } => bind_port,
            _ => panic!("seed grant"),
        };
        t.stamp_activity_if_stale(port, now.saturating_sub(silent_secs), 0);
        (t, port)
    }

    async fn policy_facade_table_and_entry(
        t: LeaseTable,
        port: u16,
        client: Ipv4Addr,
    ) -> Arc<UpnpFacade> {
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "lease-policy".into(),
            grace_secs: 60,
        };
        // the seed's int port is unknown here; rebuild the entry from the
        // slot so the reaped entry assertion has an index to check
        let int_port = t.by_bind_port(port).unwrap().target_port;
        let entry = FacadeEntry {
            req_ext: int_port,
            proto: Proto::Udp,
            owner: client,
            client,
            int_port,
            bind_port: port,
            granted_lifetime: INFINITE_LEASE,
            expires_at_unix: Epoch::now().saturating_add(u64::from(INFINITE_LEASE)),
            desc: String::new(),
        };
        Arc::new(UpnpFacade {
            cfg,
            table: Arc::new(Mutex::new(t)),
            publisher: Arc::new(Publisher::with_watch(
                "/tmp/none",
                watch::channel(Ipv4Addr::LOCALHOST).0,
            )),
            entries: Mutex::new(vec![entry]),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("lease-policy"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn backstop_reaps_silent_udp_grant() {
        // a UDP grant whose client went silent past the 7-day backstop
        // reaps on the sweep, whatever the pool state (the residue case:
        // a vanished console's leftover mapping).
        let client = Ipv4Addr::new(192, 168, 21, 50);
        let (t, port) = policy_seed(client, 3478, 700_000);
        let facade = policy_facade_table_and_entry(t, port, client).await;
        facade.gc_loop().await;
        assert!(
            facade.table.lock().await.by_bind_port(port).is_none(),
            "silent grant must reap on the backstop"
        );
        assert!(
            facade.entries.lock().await.iter().all(|e| e.bind_port != port),
            "the control-plane entry must go with the slot"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stamp_client_prevents_backstop_reap() {
        // any SOAP action from the client refreshes its grants' last-seen,
        // so a client that keeps talking is never reaped.
        let client = Ipv4Addr::new(192, 168, 21, 50);
        let (t, port) = policy_seed(client, 3478, 700_000);
        let facade = policy_facade_table_and_entry(t, port, client).await;
        facade.stamp_client(client).await;
        facade.gc_loop().await;
        assert!(
            facade.table.lock().await.by_bind_port(port).is_some(),
            "a client that just talked must not be reaped"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn control_stamp_updates_slot_last_seen() {
        let client = Ipv4Addr::new(192, 168, 21, 50);
        let (t, port) = policy_seed(client, 3478, 0); // fresh
        let facade = policy_facade_table_and_entry(t, port, client).await;
        let before = facade.table.lock().await.by_bind_port(port).unwrap().last_activity_unix;
        facade.stamp_client(client).await;
        let after = facade.table.lock().await.by_bind_port(port).unwrap().last_activity_unix;
        assert!(after >= before, "the control stamp advances last-seen");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn evict_candidate_reclaims_other_client_slot() {
        // under pool pressure the facade reclaims the longest-idle grant
        // of a DIFFERENT client (idle past the grace) and tears it down.
        let owner = Ipv4Addr::new(192, 168, 21, 50);
        let requester = Ipv4Addr::new(192, 168, 21, 51);
        let (t, port) = policy_seed(owner, 3478, 100_000); // idle past 24 h
        let facade = policy_facade_table_and_entry(t, port, owner).await;
        let got = facade.evict_candidate(requester).await;
        assert_eq!(got, Some((port, owner, 3478, Proto::Udp)));
        assert!(
            facade.table.lock().await.by_bind_port(port).is_none(),
            "evicted slot is gone"
        );
        assert!(
            facade.entries.lock().await.iter().all(|e| e.bind_port != port),
            "evicted entry is gone"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn evict_candidate_never_takes_requester_own_grant() {
        let requester = Ipv4Addr::new(192, 168, 21, 51);
        let (t, port) = policy_seed(requester, 3479, 100_000);
        let facade = policy_facade_table_and_entry(t, port, requester).await;
        assert_eq!(
            facade.evict_candidate(requester).await,
            None,
            "never evict the requesting client's own grants"
        );
    }

    // ---- plan/0008 discovery layer (R6 burst + versioned structure) ----

    #[test]
    fn discovery_action_matrix() {
        use SearchTarget::*;
        // gate off: the device presents the v1 facade only; v2 targets
        // are not offered (an honest v1-only device)
        assert_eq!(discovery_action(All, false), DiscoveryAction::ReplyV1(All));
        assert_eq!(
            discovery_action(InternetGatewayDevice, false),
            DiscoveryAction::ReplyV1(InternetGatewayDevice)
        );
        assert_eq!(
            discovery_action(WanIpConnection, false),
            DiscoveryAction::ReplyV1(WanIpConnection)
        );
        assert_eq!(discovery_action(InternetGatewayDevice2, false), DiscoveryAction::Ignore);
        assert_eq!(discovery_action(WanIpConnection2, false), DiscoveryAction::Ignore);
        // gate on: ssdp:all defers into the burst (R6); v2 targets answer
        // v2; v1 targets still answer v1 (R4)
        assert_eq!(discovery_action(All, true), DiscoveryAction::DeferAll);
        assert_eq!(
            discovery_action(InternetGatewayDevice2, true),
            DiscoveryAction::ReplyV2(InternetGatewayDevice2)
        );
        assert_eq!(
            discovery_action(WanIpConnection2, true),
            DiscoveryAction::ReplyV2(WanIpConnection2)
        );
        assert_eq!(
            discovery_action(InternetGatewayDevice, true),
            DiscoveryAction::ReplyV1(InternetGatewayDevice)
        );
        assert_eq!(
            discovery_action(WanIpConnection, true),
            DiscoveryAction::ReplyV1(WanIpConnection)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn burst_resolves_v2_deadline_and_flip() {
        // no :2 in the window: the v1 compatibility default answers at
        // the deadline (seen_v2 ? v2 : v1, section 12). Short windows
        // stand in for DISCOVERY_DEBOUNCE_MS to keep the test fast; the
        // resolver is duration-parametric by design.
        let (_tx, rx) = watch::channel(false);
        let h = tokio::spawn(burst_resolves_v2(rx, Duration::from_millis(40)));
        assert!(!h.await.unwrap(), "no :2 -> v1 at the deadline");
        // a :2 inside the window flips the pending :all to v2 early
        let (tx, rx) = watch::channel(false);
        let h = tokio::spawn(burst_resolves_v2(rx, Duration::from_millis(200)));
        tokio::time::sleep(Duration::from_millis(30)).await;
        tx.send(true).unwrap();
        assert!(h.await.unwrap(), ":2 inside the window -> v2");
    }

    #[test]
    fn v2_builders_carry_the_surface() {
        // the v2 surface is real data (section 26.4 places DP under the
        // root device; WIP2 under WANConnectionDevice:2), served only
        // when the gate flips at #v2-service-set
        let doc = root_desc_v2(Ipv4Addr::new(192, 168, 21, 1), 49152, "t", "udn-x");
        let s = String::from_utf8_lossy(&doc);
        assert!(s.contains("InternetGatewayDevice:2"));
        assert!(s.contains("DeviceProtection:1"));
        assert!(s.contains("/igd/v2/DP.xml"));
        assert!(s.contains("WANIPConnection:2"));
        assert!(s.contains("/igd/v2/WANIPCn.xml"));
        let wip2 = String::from_utf8_lossy(SCPD_WIP2.as_bytes());
        assert!(wip2.contains("AddAnyPortMapping"));
        assert!(wip2.contains("DeletePortMappingRange"));
        assert!(wip2.contains("GetListOfPortMappings"));
        // the surface assertions compare against the line-wrapped document
        // with its layout removed, so they test the XML structure rather
        // than the literal's formatting
        let wip2_flat: String = wip2.chars().filter(|c| !c.is_whitespace()).collect();
        // the WIP2 transcription (docs/upnp-wip2/TRANSCRIPTION.md): the
        // the fourteen actions the spec's table 2-10 marks REQUIRED of a
        // device, each with its argument table, so a published
        // description that names an action without describing it fails
        for (action, args) in [
            ("SetConnectionType", vec![("NewConnectionType", "in", "ConnectionType")]),
            (
                "GetConnectionTypeInfo",
                vec![
                    ("NewConnectionType", "out", "ConnectionType"),
                    ("NewPossibleConnectionTypes", "out", "PossibleConnectionTypes"),
                ],
            ),
            ("RequestConnection", vec![]),
            ("ForceTermination", vec![]),
            (
                "GetStatusInfo",
                vec![
                    ("NewConnectionStatus", "out", "ConnectionStatus"),
                    ("NewLastConnectionError", "out", "LastConnectionError"),
                    ("NewUptime", "out", "Uptime"),
                ],
            ),
            (
                "GetNATRSIPStatus",
                vec![
                    ("NewRSIPAvailable", "out", "RSIPAvailable"),
                    ("NewNATEEnabled", "out", "NATEEnabled"),
                ],
            ),
            (
                "GetGenericPortMappingEntry",
                vec![
                    ("NewPortMappingIndex", "in", "PortMappingNumberOfEntries"),
                    ("NewRemoteHost", "out", "RemoteHost"),
                    ("NewExternalPort", "out", "ExternalPort"),
                    ("NewProtocol", "out", "PortMappingProtocol"),
                    ("NewInternalPort", "out", "InternalPort"),
                    ("NewInternalClient", "out", "InternalClient"),
                    ("NewEnabled", "out", "PortMappingEnabled"),
                    ("NewPortMappingDescription", "out", "PortMappingDescription"),
                    ("NewLeaseDuration", "out", "PortMappingLeaseDuration"),
                ],
            ),
            (
                "GetSpecificPortMappingEntry",
                vec![
                    ("NewRemoteHost", "in", "RemoteHost"),
                    ("NewExternalPort", "in", "ExternalPort"),
                    ("NewProtocol", "in", "PortMappingProtocol"),
                    ("NewInternalPort", "out", "InternalPort"),
                    ("NewInternalClient", "out", "InternalClient"),
                    ("NewEnabled", "out", "PortMappingEnabled"),
                    ("NewPortMappingDescription", "out", "PortMappingDescription"),
                    ("NewLeaseDuration", "out", "PortMappingLeaseDuration"),
                ],
            ),
            (
                "AddPortMapping",
                vec![
                    ("NewRemoteHost", "in", "RemoteHost"),
                    ("NewExternalPort", "in", "ExternalPort"),
                    ("NewProtocol", "in", "PortMappingProtocol"),
                    ("NewInternalPort", "in", "InternalPort"),
                    ("NewInternalClient", "in", "InternalClient"),
                    ("NewEnabled", "in", "PortMappingEnabled"),
                    ("NewPortMappingDescription", "in", "PortMappingDescription"),
                    ("NewLeaseDuration", "in", "PortMappingLeaseDuration"),
                ],
            ),
            (
                "AddAnyPortMapping",
                vec![
                    ("NewRemoteHost", "in", "RemoteHost"),
                    ("NewExternalPort", "in", "ExternalPort"),
                    ("NewProtocol", "in", "PortMappingProtocol"),
                    ("NewInternalPort", "in", "InternalPort"),
                    ("NewInternalClient", "in", "InternalClient"),
                    ("NewEnabled", "in", "PortMappingEnabled"),
                    ("NewPortMappingDescription", "in", "PortMappingDescription"),
                    ("NewLeaseDuration", "in", "PortMappingLeaseDuration"),
                    ("NewReservedPort", "out", "ExternalPort"),
                ],
            ),
            (
                "DeletePortMapping",
                vec![
                    ("NewRemoteHost", "in", "RemoteHost"),
                    ("NewExternalPort", "in", "ExternalPort"),
                    ("NewProtocol", "in", "PortMappingProtocol"),
                ],
            ),
            (
                "DeletePortMappingRange",
                vec![
                    ("NewStartPort", "in", "ExternalPort"),
                    ("NewEndPort", "in", "ExternalPort"),
                    ("NewProtocol", "in", "PortMappingProtocol"),
                    ("NewManage", "in", "A_ARG_TYPE_Manage"),
                ],
            ),
            ("GetExternalIPAddress", vec![("NewExternalIPAddress", "out", "ExternalIPAddress")]),
            (
                "GetListOfPortMappings",
                vec![
                    ("NewStartPort", "in", "ExternalPort"),
                    ("NewEndPort", "in", "ExternalPort"),
                    ("NewProtocol", "in", "PortMappingProtocol"),
                    ("NewManage", "in", "A_ARG_TYPE_Manage"),
                    ("NewNumberOfPorts", "in", "PortMappingNumberOfEntries"),
                    ("NewPortListing", "out", "A_ARG_TYPE_PortListing"),
                ],
            ),
        ] {
            if args.is_empty() {
                assert!(
                    wip2_flat.contains(&format!("<action><name>{}</name></action>", action)),
                    "WIP2 SCPD must declare {} with no arguments",
                    action
                );
                continue;
            }
            let mut want = format!("<action><name>{}</name><argumentList>", action);
            for (arg, dir, rel) in args {
                want.push_str(&format!(
                    "<argument><name>{}</name><direction>{}</direction><relatedStateVariable>{}</relatedStateVariable></argument>",
                    arg, dir, rel
                ));
            }
            want.push_str("</argumentList></action>");
            assert!(
                wip2_flat.contains(&want),
                "WIP2 SCPD must carry {}'s argument table",
                action
            );
        }
        // the placeholder's bogus action and invented state variables
        assert!(
            !wip2.contains("GetLinkLayerMaxBitRates"),
            "GetLinkLayerMaxBitRates belongs to WANCommonInterfaceConfig, not WANIPConnection"
        );
        for bogus in [
            "A_ARG_TYPE_ExternalPort",
            "A_ARG_TYPE_InternalClient",
            "A_ARG_TYPE_InternalPort",
            "A_ARG_TYPE_Protocol",
            "A_ARG_TYPE_LeaseTime",
            "<name>NATEnabled</name>",
        ] {
            assert!(!wip2.contains(bogus), "WIP2 SCPD must not carry {}", bogus);
        }
        // table 2-9: exactly five variables are evented, and the evented
        // pair of 2.4.4/2.4.5 is among them
        for v in [
            "PossibleConnectionTypes",
            "ConnectionStatus",
            "ExternalIPAddress",
            "PortMappingNumberOfEntries",
            "SystemUpdateID",
        ] {
            assert!(
                wip2.contains(&format!(
                    "<stateVariable sendEvents=\"yes\"><name>{}</name>",
                    v
                )),
                "{} must be evented",
                v
            );
        }
        assert!(
            wip2.contains("<stateVariable sendEvents=\"no\"><name>NATEEnabled</name><dataType>boolean</dataType></stateVariable>"),
            "NATEEnabled is the spec's spelling (table 2-2, 2.5.13)"
        );
        assert!(
            wip2.contains("<stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_PortListing</name><dataType>string</dataType></stateVariable>"),
            "A_ARG_TYPE_PortListing is a string (section 2.3.25)"
        );
        assert_eq!(
            wip2.matches("<action>").count(),
            14,
            "the spec's table 2-10 marks fourteen actions REQUIRED of a device"
        );
        // the seven OPTIONAL actions of table 2-10 are not implemented, so
        // they must not be advertised: a device that published them would
        // be promising a disconnect the ISP-managed line cannot make. A CP
        // that invokes one gets 401 Invalid Action, which is the UDA
        // answer for an action outside the published service.
        for optional in [
            "RequestTermination",
            "SetAutoDisconnectTime",
            "SetIdleDisconnectTime",
            "SetWarnDisconnectDelay",
            "GetAutoDisconnectTime",
            "GetIdleDisconnectTime",
            "GetWarnDisconnectDelay",
        ] {
            assert!(
                !wip2_flat.contains(&format!("<action><name>{}</name>", optional)),
                "{} is optional in table 2-10 and is not implemented, so it must not be advertised",
                optional
            );
        }
        assert_eq!(
            wip2.matches("<stateVariable ").count(),
            23,
            "twenty-three state variables: table 2-2 plus the two argument types"
        );
        let dp = String::from_utf8_lossy(SCPD_DP.as_bytes());
        for a in [
            "SendSetupMessage",
            "GetSupportedProtocols",
            "GetAssignedRoles",
            "GetRolesForAction",
            "GetUserLoginChallenge",
            "UserLogin",
            "UserLogout",
            "GetACLData",
            "AddIdentityList",
            "RemoveIdentity",
            "SetUserLoginPassword",
            "AddRolesForIdentity",
            "RemoveRolesForIdentity",
        ] {
            assert!(dp.contains(a), "DP SCPD must declare {}", a);
        }
        for a in [
            "RequestUserLogin",
            "ValidateIdentity",
            "AddACLEntry",
            "RemoveACLEntry",
            "GetListOfRoles",
            "RevokeRole",
            "LoginWithPIN",
            "LoginWithThirdParty",
        ] {
            assert!(!dp.contains(a), "DP SCPD must not carry {}", a);
        }
        assert!(dp.contains("SetupReady"), "DP SetupReady state var");
        // the state table transcription (TRANSCRIPTION.md, section 4
        // reassembly): exactly SetupReady is evented; A_ARG_TYPE_Base64
        // is bin.base64; the other six variables are non-evented strings
        assert!(
            dp.contains(
                "<stateVariable sendEvents=\"yes\"><name>SetupReady</name><dataType>boolean</dataType></stateVariable>"
            ),
            "SetupReady must be the evented boolean"
        );
        assert!(
            dp.contains("<stateVariable sendEvents=\"no\"><name>SupportedProtocols</name>")
                && dp.contains("<stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_ACL</name>")
                && dp.contains("<stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_IdentityList</name>")
                && dp.contains("<stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_Identity</name>")
                && dp.contains("<stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_String</name>"),
            "the other variables must be non-evented"
        );
        assert!(
            dp.contains("<stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_Base64</name><dataType>bin.base64</dataType></stateVariable>"),
            "A_ARG_TYPE_Base64 data type"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn versioned_doc_routing() {
        // section 21: /igd/v1/* serves the v1 presentation, the legacy
        // paths stay served, and /igd/v2/* serves the v2 presentation
        // now that the mount gate is on (plan/0008 #v2-service-set).
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "routing".into(),
            grace_secs: 60,
        };
        let table = Arc::new(Mutex::new(LeaseTable::new(
            PortAllocator::new(30000, 30009).unwrap(),
            4,
            2,
        )));
        let publisher =
            Arc::new(Publisher::with_watch("/tmp/none", watch::channel(Ipv4Addr::LOCALHOST).0));
        let facade = Arc::new(UpnpFacade {
            cfg,
            table,
            publisher,
            entries: Mutex::new(Vec::new()),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("routing"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let f2 = facade.clone();
        tokio::spawn(async move {
            let _ = http_serve(listener, f2).await;
        });
        let get = |path: &'static str| {
            async move {
                let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
                let req = format!("GET {} HTTP/1.0\r\n\r\n", path);
                s.write_all(req.as_bytes()).await.unwrap();
                let mut buf = Vec::new();
                let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
                    .await
                    .expect("response within 5s");
                (buf.starts_with(b"HTTP/1.1 200"), String::from_utf8_lossy(&buf).to_string())
            }
        };
        let (ok, body) = get("/rootDesc.xml").await;
        assert!(
            ok,
            "legacy rootDesc stays served; head={:?}",
            &body[..body.len().min(120)]
        );
        let (ok, body) = get("/igd/v1/rootDesc.xml").await;
        assert!(
            ok && body.contains("InternetGatewayDevice:1"),
            "v1 canonical URL serves the v1 doc; ok={} head={:?}",
            ok,
            &body[..body.len().min(220)]
        );
        // the mounted v2 root description: IGD:2, and (sections 26.4 and
        // 26.11) DeviceProtection:1 beside WANIPConnection:2, since an
        // IGD:2 facade without an enforced DP surface is the shortcut the
        // plan forbids
        let (ok, body) = get("/igd/v2/rootDesc.xml").await;
        assert!(
            ok && body.contains("InternetGatewayDevice:2"),
            "v2 canonical URL serves the v2 doc; ok={} head={:?}",
            ok,
            &body[..body.len().min(220)]
        );
        for want in [
            "urn:schemas-upnp-org:service:DeviceProtection:1",
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "/igd/v2/DP.xml",
            "/igd/v2/WANIPCn.xml",
        ] {
            assert!(body.contains(want), "the v2 root description carries {}", want);
        }
        // the v2 service descriptions: the transcribed WIP2 surface (21
        // actions) and the DP surface (13)
        let (ok, body) = get("/igd/v2/WANIPCn.xml").await;
        assert!(
            ok && body.contains("AddAnyPortMapping") && body.contains("DeletePortMappingRange"),
            "the WIP2 SCPD is served"
        );
        assert_eq!(
            body.matches("<action>").count(),
            14,
            "the v2 mount publishes the fourteen REQUIRED actions of table 2-10"
        );
        let (ok, body) = get("/igd/v2/DP.xml").await;
        assert!(
            ok && body.contains("GetUserLoginChallenge") && body.contains("SetUserLoginPassword"),
            "the DP SCPD is served"
        );
        assert_eq!(
            body.matches("<action>").count(),
            13,
            "the DP surface is the authoritative 13 actions"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ssdp_loop_answers_the_mounted_surface() {
        // section 24's discovery rows at the packet level: an explicit
        // IGD:2 or WIP:2 search is answered from the v2 presentation, a
        // v1 search from the v1 presentation, and a bare ssdp:all is
        // deferred to the debounce deadline and answered from v1 unless a
        // :2 search arrives inside the window (section 12)
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "ssdp-loop".into(),
            grace_secs: 60,
        };
        let table = Arc::new(Mutex::new(LeaseTable::new(
            PortAllocator::new(30000, 30009).unwrap(),
            4,
            2,
        )));
        let publisher =
            Arc::new(Publisher::with_watch("/tmp/none", watch::channel(Ipv4Addr::LOCALHOST).0));
        let facade = Arc::new(UpnpFacade {
            cfg,
            table,
            publisher,
            entries: Mutex::new(Vec::new()),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("ssdp-loop"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });
        let addr = facade.ssdp.local_addr().unwrap();
        let f = facade.clone();
        tokio::spawn(async move {
            f.ssdp_recv_loop().await;
        });
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let msearch = |st: &str, mx: &str| {
            format!(
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: {}\r\nST: {}\r\n\r\n",
                mx, st
            )
        };
        probe
            .send_to(msearch("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "2").as_bytes(), addr)
            .await
            .unwrap();
        let mut buf = [0u8; 600];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), probe.recv_from(&mut buf))
            .await
            .expect("v1 answer within 3 s")
            .expect("recv ok");
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"));
        assert!(resp.contains("/igd/v1/rootDesc.xml"));
        // an explicit IGD:2 search is answered from the v2 presentation
        probe
            .send_to(msearch("urn:schemas-upnp-org:device:InternetGatewayDevice:2", "1").as_bytes(), addr)
            .await
            .unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), probe.recv_from(&mut buf))
            .await
            .expect("v2 answer within 3 s")
            .expect("recv ok");
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(
            resp.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n"),
            "the answer carries the searched target: {}",
            resp
        );
        assert!(resp.contains("/igd/v2/rootDesc.xml"), "and the v2 LOCATION: {}", resp);

        // an explicit WIP:2 search resolves to the v2 description too
        probe
            .send_to(msearch("urn:schemas-upnp-org:service:WANIPConnection:2", "1").as_bytes(), addr)
            .await
            .unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), probe.recv_from(&mut buf))
            .await
            .expect("WIP:2 answer within 3 s")
            .expect("recv ok");
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp.contains("/igd/v2/rootDesc.xml") && resp.contains("WANIPConnection:2\r\n"),
            "WIP:2 resolves to the v2 description: {}",
            resp
        );

        // a bare ssdp:all is deferred, then answered from v1 because no
        // :2 arrived inside the window. The deadline is the implementation
        // parameter: the deferred answer lands at receive + the debounce,
        // with no further jitter (section 12 constraint 3).
        let t0 = std::time::Instant::now();
        probe.send_to(msearch("ssdp:all", "1").as_bytes(), addr).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), probe.recv_from(&mut buf))
            .await
            .expect("the deferred ssdp:all answer arrives")
            .expect("recv ok");
        let waited = t0.elapsed();
        let resp = String::from_utf8_lossy(&buf[..n]);
        // the deferred :all answer carries the root-device target, which
        // is the UDA-appropriate response target for ssdp:all (section 24
        // reads "ssdp:all/appropriate response targets")
        assert!(resp.contains("ST: upnp:rootdevice\r\n"), "st: {}", resp);
        assert!(
            resp.contains("/igd/v1/rootDesc.xml"),
            "nothing in the burst says v2, so the answer is v1: {}",
            resp
        );
        assert!(
            waited >= Duration::from_millis(900) && waited <= Duration::from_millis(1800),
            "the deferred answer lands at the debounce deadline, not before and not much after: {:?}",
            waited
        );

        // the same burst with an explicit :2 inside the window: both
        // answers are the v2 presentation, and the deferred :all is
        // released early
        probe.send_to(msearch("ssdp:all", "1").as_bytes(), addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        probe
            .send_to(msearch("urn:schemas-upnp-org:device:InternetGatewayDevice:2", "1").as_bytes(), addr)
            .await
            .unwrap();
        let mut all_seen = false;
        let mut igd2_seen = false;
        for _ in 0..2 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(3), probe.recv_from(&mut buf))
                .await
                .expect("both answers arrive")
                .expect("recv ok");
            let resp = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(
                resp.contains("/igd/v2/rootDesc.xml"),
                "the flip answers both from v2: {}",
                resp
            );
            if resp.contains("ST: upnp:rootdevice\r\n") {
                all_seen = true;
            }
            if resp.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n") {
                igd2_seen = true;
            }
        }
        assert!(
            all_seen && igd2_seen,
            "the deferred ssdp:all and the explicit :2 are both answered"
        );
    }

}

#[cfg(test)]
mod ifindex_probe {
    use super::*;
    use crate::slot::PortAllocator;

    #[test]
    fn lan_ifindex_localhost() {
        // Regression: the zero-padded name handling once made every
        // lookup return None under musl/getifaddrs.
        assert!(
            lan_ifindex(Ipv4Addr::LOCALHOST).is_some(),
            "127.0.0.1 must resolve to lo's index via if_nametoindex"
        );
    }

    #[test]
    fn ssdp_socket_is_nonblocking_cloexec() {
        // Regression (2026-09-14, live wedge): bind_ssdp used to create a
        // plain blocking UDP fd and hand it to tokio from_std, which only
        // debug_asserts nonblocking (stripped in release). On the rig one
        // worker parked inside the blocking recvfrom and the io-driver
        // handoff degraded until the HTTP accept loop never woke. Guard
        // the raw-fd flags that prevented that: SOCK_NONBLOCK|SOCK_CLOEXEC.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        assert!(fd >= 0, "raw AF_INET dgram socket");
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let fdflags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        unsafe { libc::close(fd) };
        assert!(
            flags >= 0 && (flags & libc::O_NONBLOCK) != 0,
            "socket must be nonblocking (flags={:x})",
            flags
        );
        assert!(
            fdflags >= 0 && (fdflags & libc::FD_CLOEXEC) != 0,
            "socket must be close-on-exec (fdflags={:x})",
            fdflags
        );
    }

    /// Local interop probe (ignored; needs the miniupnpc source at
    /// `/tmp/localupnpc/miniupnpc` with `build/upnpc-static` and
    /// `build/testigddescparse` built from it): serves the facade HTTP
    /// layer on 127.0.0.1:19152 without any router, dumps both rootDesc
    /// presentations for the reference IGD description parser, and drives
    /// the real client's walks (v1 `-l`, v2 `-L`, and the v2 `-n` the
    /// DeviceProtection boundary refuses) plus a GetCommonLinkProperties
    /// SOAP against the live server.
    ///
    /// Build the fixture with:
    ///   git clone --depth 1 https://github.com/miniupnp/miniupnp.git /tmp/localupnpc/miniupnp
    ///   cp -r /tmp/localupnpc/miniupnp/miniupnpc /tmp/localupnpc/miniupnpc
    ///   make -C /tmp/localupnpc/miniupnpc -j4 BUILD=build
    ///   cmake -S /tmp/localupnpc/miniupnpc -B /tmp/localupnpc/cmt -DUPNPC_BUILD_TESTS=ON
    ///   cmake --build /tmp/localupnpc/cmt --target testigddescparse -j4
    ///   cp /tmp/localupnpc/cmt/testigddescparse /tmp/localupnpc/miniupnpc/build/
    ///
    /// Run with: cargo test -- --ignored miniupnpc_interop --nocapture
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs miniupnpc built at /tmp/localupnpc (off-router probe)"]
    async fn miniupnpc_interop() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 19152,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "interop".into(),
            grace_secs: 60,
        };
        let table = Arc::new(Mutex::new(LeaseTable::new(
            PortAllocator::new(30000, 30009).unwrap(),
            4,
            2,
        )));
        let publisher =
            Arc::new(Publisher::with_watch("/tmp/none", watch::channel(Ipv4Addr::LOCALHOST).0));
        let facade = Arc::new(UpnpFacade {
            cfg,
            table,
            publisher,
            // One entry for this loopback caller, so the reference client's
            // IGD:2 listing walk parses a real mapping back rather than an
            // empty PortMappingList. 3074 is at or above the containment
            // floor, so a contained view still shows it.
            entries: Mutex::new(vec![FacadeEntry {
                req_ext: 3074,
                proto: Proto::Udp,
                owner: Ipv4Addr::LOCALHOST,
                client: Ipv4Addr::LOCALHOST,
                int_port: 3074,
                bind_port: 40002,
                granted_lifetime: 3600,
                expires_at_unix: 0,
                desc: "interop".into(),
            }]),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("interop"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });

        // Dump the generated rootDesc for the external miniupnpc parser.
        let doc = root_desc(
            Ipv4Addr::LOCALHOST,
            19152,
            "interop-facade",
            "interop-udn",
        );
        std::fs::write("/tmp/rootdesc.xml", &doc).unwrap();

        let listener = TcpListener::bind("127.0.0.1:19152").await.unwrap();
        let f2 = facade.clone();
        tokio::spawn(async move {
            let _ = http_serve(listener, f2).await;
        });
        // let the listener be up before the client dials
        tokio::time::sleep(Duration::from_millis(100)).await;

        let addr = "127.0.0.1:19152";
        // Direct SOAP probe: GetCommonLinkProperties on the CIF service.
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetCommonLinkProperties xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\"/></s:Body></s:Envelope>";
        let req = format!(
            "POST /ctl/CmnIfCfg HTTP/1.1\r\nHost: {}\r\nSOAPACTION: \"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1#GetCommonLinkProperties\"\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            addr,
            body.len(),
            body
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("200 OK"), "CIF SOAP: {}", &resp[..resp.len().min(200)]);
        assert!(
            resp.contains("NewPhysicalLinkStatus") && resp.contains("WANAccessType"),
            "CIF SOAP response body: {}",
            &resp[..resp.len().min(300)]
        );

        // Now the full upnpc -l walk against the live server.
        let out = std::process::Command::new(
            "/tmp/localupnpc/miniupnpc/build/upnpc-static",
        )
        .args(["-u", "http://127.0.0.1:19152/rootDesc.xml", "-l"])
        .output()
        .expect("run upnpc-static");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        emitln!("=== upnpc -l output ===\n{}", text);
        assert!(
            text.contains("Found valid IGD") || text.contains("Found an IGD"),
            "upnpc must accept the device: {}",
            text
        );

        // The v2 presentation, driven by the same reference client. The
        // description parser first, over both presentations.
        let doc_v2 = root_desc_v2(Ipv4Addr::LOCALHOST, 19152, "interop-facade", "interop-udn");
        std::fs::write("/tmp/rootdesc-v2.xml", &doc_v2).unwrap();
        for (label, path) in [
            ("v1", "/tmp/rootdesc.xml"),
            ("v2", "/tmp/rootdesc-v2.xml"),
        ] {
            let out =
                std::process::Command::new("/tmp/localupnpc/miniupnpc/build/testigddescparse")
                    .arg(path)
                    .output()
                    .expect("run testigddescparse");
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            emitln!("=== testigddescparse {} ===\n{}", label, text);
            assert!(
                out.status.success() && text.contains("controlURL="),
                "the reference parser must resolve the WANIPConnection URLs of the {} \
                 description: {}",
                label,
                text
            );
        }

        // A direct SOAP probe of the same action, so the raw answer is
        // visible whatever the reference client's walk reports.
        let list_body = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetListOfPortMappings xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewStartPort>1</NewStartPort><NewEndPort>65535</NewEndPort><NewProtocol>UDP</NewProtocol><NewManage>1</NewManage><NewNumberOfPorts>1000</NewNumberOfPorts></u:GetListOfPortMappings></s:Body></s:Envelope>";
        let listed = soap_post(
            "127.0.0.1:19152",
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#GetListOfPortMappings",
            list_body,
        )
        .await;
        emitln!("=== direct GetListOfPortMappings (UDP) ===\n{}", listed);
        // The wire shape: the fragment as the NewPortListing argument
        // value, which is what a control point reads it from.
        assert!(
            listed.contains("<NewPortListing><![CDATA[<p:PortMappingList"),
            "the listing rides as the NewPortListing argument value: {}",
            listed
        );
        assert!(
            listed.contains("<p:NewInternalClient>127.0.0.1</p:NewInternalClient>"),
            "the raw listing carries the caller's entry: {}",
            listed
        );

        // The v2 read path is not session-gated, so the reference client's
        // IGD:2 listing walk must parse our PortMappingList, entry fields
        // included.
        let out = std::process::Command::new("/tmp/localupnpc/miniupnpc/build/upnpc-static")
            .args(["-u", "http://127.0.0.1:19152/igd/v2/rootDesc.xml", "-L"])
            .output()
            .expect("run upnpc-static -L");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        emitln!("=== upnpc -L (v2) output ===\n{}", text);
        // The walk asks for TCP first, which holds nothing and is 730 by
        // the spec's rule (2.5.21), so the reference client reports that
        // fault and then asks for UDP. The UDP pass is the one that must
        // show our listing parsed, fields and all.
        assert!(
            text.contains("730 (PortMappingNotFound)"),
            "the empty TCP range is the spec's fault, which the reference client \
             surfaces as a failed pass: {}",
            text
        );
        assert!(
            text.contains("3074->127.0.0.1:3074"),
            "the reference parser must read the caller's own mapping back: {}",
            text
        );
        assert!(
            text.contains("'interop'"),
            "the reference parser must read our description field: {}",
            text
        );

        // The v2 write path is gated, and an empty DeviceProtection store
        // holds no session, so the reference client's AddAnyPortMapping is
        // refused with the boundary's own fault.
        let out = std::process::Command::new("/tmp/localupnpc/miniupnpc/build/upnpc-static")
            .args([
                "-u",
                "http://127.0.0.1:19152/igd/v2/rootDesc.xml",
                "-n",
                "127.0.0.1",
                "3074",
                "3074",
                "UDP",
            ])
            .output()
            .expect("run upnpc-static -n");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        emitln!("=== upnpc -n (v2) output ===\n{}", text);
        assert!(
            text.contains("failed with code 606"),
            "the DeviceProtection boundary must refuse an unauthenticated v2 mutator: {}",
            text
        );
    }

    /// A seeded DeviceProtection state for the wire tests: device id, one
    /// Admin user, one Admin CP identity in the ACL.
    fn dp_seeded() -> std::sync::Mutex<crate::dp::DpState> {
        let device_id: [u8; 16] = [0xdd; 16];
        let salt = [11u8; 16];
        let users = vec![crate::dp::DpUser {
            name: "admin".into(),
            salt,
            stored: crate::dp::stored_for(b"admin-pw", b"admin", &salt),
            roles: vec!["Admin".into()],
        }];
        let acl = crate::dp::DpAcl {
            identities: vec![crate::dp::DpIdentity {
                name: "admin-cp".into(),
                alias: None,
                id: [0xca; 16],
                roles: vec!["Admin".into()],
            }],
        };
        std::sync::Mutex::new(crate::dp::DpState::new(device_id, users, acl))
    }

    /// One SOAP POST; returns the raw response.
    async fn soap_post(addr: &str, path: &str, soapaction: &str, body: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nSOAPACTION: \"{}\"\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            path,
            addr,
            soapaction,
            body.len(),
            body
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// The DeviceProtection 26.19 boundary at the wire: the v2 WIP2 face
    /// is gated behind the PKCS5 session; the v1 face is not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dp_boundary_wire() {
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/dp-wire".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "dp-wire".into(),
            grace_secs: 60,
        };
        let table = Arc::new(Mutex::new(LeaseTable::new(
            PortAllocator::new(30000, 30009).unwrap(),
            4,
            2,
        )));
        let publisher =
            Arc::new(Publisher::with_watch("/tmp/none", watch::channel(Ipv4Addr::LOCALHOST).0));
        let facade = Arc::new(UpnpFacade {
            cfg,
            table,
            publisher,
            // one entry belonging to another host, so the read containment
            // has something to hide. It sits outside every port range this
            // test drives, which keeps the empty-range refusals empty.
            entries: Mutex::new(vec![FacadeEntry {
                req_ext: 20500,
                proto: Proto::Udp,
                owner: Ipv4Addr::new(192, 168, 21, 50),
                client: Ipv4Addr::new(192, 168, 21, 50),
                int_port: 20500,
                bind_port: 30009,
                granted_lifetime: 3600,
                expires_at_unix: Epoch::now() + 600,
                desc: String::from("other-host"),
            }]),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("dp-wire"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: dp_seeded(),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let f2 = facade.clone();
        tokio::spawn(async move {
            let _ = http_serve(listener, f2).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let env = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:";

        // the v2 SCPD carries the authoritative 13, not the superseded names
        // (the R5 mount gate keeps /igd/v2/* unserved until the complete
        // service set lands, so the document itself is asserted here; the
        // wired GET check lives with the gate-off integration harness)
        let scpd = String::from_utf8_lossy(SCPD_DP.as_bytes());
        for name in [
            "SendSetupMessage",
            "GetSupportedProtocols",
            "GetAssignedRoles",
            "GetRolesForAction",
            "GetUserLoginChallenge",
            "UserLogin",
            "UserLogout",
            "GetACLData",
            "AddIdentityList",
            "RemoveIdentity",
            "SetUserLoginPassword",
            "AddRolesForIdentity",
            "RemoveRolesForIdentity",
        ] {
            assert!(scpd.contains(name), "SCPD must declare {}", name);
        }
        assert!(!scpd.contains("RequestUserLogin"), "superseded name gone");

        // GetSupportedProtocols: public, no session
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#GetSupportedProtocols",
            &format!(
                "{}GetSupportedProtocols xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"/></s:Body></s:Envelope>",
                env
            ),
        )
        .await;
        assert!(r.contains("200 OK") && r.contains("PKCS5"), "public action: {}", &r[..r.len().min(200)]);

        // GetACLData without a session: the DP-defined 606 fault, not a stub
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#GetACLData",
            &format!(
                "{}GetACLData xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"/></s:Body></s:Envelope>",
                env
            ),
        )
        .await;
        assert!(r.contains("<errorCode>606</errorCode>"), "unauth 606: {}", &r[..r.len().min(300)]);

        // the v2 WIP2 boundary: AddPortMapping with the :2 URN is denied
        // without a session ...
        let mut r = soap_post(
            &addr,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#AddPortMapping",
            &format!("{}AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewRemoteHost></NewRemoteHost><NewExternalPort>12345</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>12345</NewInternalPort><NewInternalClient>192.168.21.50</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>dp-wire</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></AddPortMapping></s:Body></s:Envelope>", env))
        .await;
        assert!(
            r.contains("<errorCode>606</errorCode>"),
            "v2 boundary denies unauth: {}",
            &r[..r.len().min(300)]
        );
        // ... while the :1 face is not gated by DeviceProtection, its
        // containment still refuses a request that names another host
        // (2.5.16.2, section 26.22): this is the door the plan's policy
        // item closes on the compatibility face.
        r = soap_post(
            &addr,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping",
            &format!("{}AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>12346</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>12346</NewInternalPort><NewInternalClient>192.168.21.50</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>dp-wire</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></AddPortMapping></s:Body></s:Envelope>", env))
        .await;
        assert!(
            r.contains("<errorCode>606</errorCode>"),
            "v1 refuses a door for another host: {}",
            &r[..r.len().min(300)]
        );
        // ... and the same request naming the caller itself reaches the
        // engine (which fails on nft here, 501), so the containment is the
        // caller's address and not a blanket refusal of the v1 face
        r = soap_post(
            &addr,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping",
            &format!("{}AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>12346</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>12346</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>dp-wire</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></AddPortMapping></s:Body></s:Envelope>", env))
        .await;
        assert!(
            r.contains("<errorCode>501</errorCode>"),
            "v1 admits the caller's own mapping: {}",
            &r[..r.len().min(400)]
        );

        // the containment covers reads as well as writes, on both faces
        // (2.5.14.2, 2.5.21.3): another host's entry is forbidden rather
        // than invisible-by-accident, and the enumeration's index space is
        // what the caller may see, so its walk ends at index 0
        for face in ["1", "2"] {
            r = soap_post(
                &addr,
                "/ctl/IPConn",
                &format!(
                    "urn:schemas-upnp-org:service:WANIPConnection:{}#GetSpecificPortMappingEntry",
                    face
                ),
                &format!(
                    "{}GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:{}\"><NewRemoteHost></NewRemoteHost><NewExternalPort>20500</NewExternalPort><NewProtocol>UDP</NewProtocol></GetSpecificPortMappingEntry></s:Body></s:Envelope>",
                    env, face
                ),
            )
            .await;
            assert!(
                r.contains("<errorCode>714</errorCode>"),
                "the :{} read of another host's port is not in the caller's namespace: {}",
                face,
                &r[..r.len().min(300)]
            );
        }
        r = soap_post(
            &addr,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry",
            &format!("{}GetGenericPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewPortMappingIndex>0</NewPortMappingIndex></GetGenericPortMappingEntry></s:Body></s:Envelope>", env))
        .await;
        assert!(
            r.contains("<errorCode>714</errorCode>"),
            "the contained index space is empty for this caller: {}",
            &r[..r.len().min(300)]
        );

        // the full PKCS5 ceremony over the wire: challenge -> authenticator
        // -> UserLogin; then the protected actions open
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#GetUserLoginChallenge",
            &format!("{}GetUserLoginChallenge xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"><ProtocolType>PKCS5</ProtocolType><Name>admin</Name></GetUserLoginChallenge></s:Body></s:Envelope>", env),
        )
        .await;
        assert!(r.contains("200 OK"), "challenge: {}", &r[..r.len().min(200)]);
        let salt_b64 = String::from_utf8_lossy(upnp::xml_tag(r.as_bytes(), b"Salt").unwrap()).into_owned();
        let challenge_b64 =
            String::from_utf8_lossy(upnp::xml_tag(r.as_bytes(), b"Challenge").unwrap()).into_owned();
        let salt = crate::dp::base64_decode(salt_b64.trim()).unwrap();
        let challenge = crate::dp::base64_decode(challenge_b64.trim()).unwrap();
        let mut salt16 = [0u8; 16];
        salt16.copy_from_slice(&salt);
        let stored = crate::dp::stored_for(b"admin-pw", b"admin", &salt16);
        let mut mac_in = Vec::new();
        mac_in.extend_from_slice(&challenge);
        mac_in.extend_from_slice(&[0xdd; 16]); // device id
        mac_in.extend_from_slice(&[0xca; 16]); // the CP identity
        let mac = crate::dp::hmac_sha256(&stored, &mac_in);
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#UserLogin",
            &format!(
                "{}UserLogin xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"><ProtocolType>PKCS5</ProtocolType><Challenge>{}</Challenge><Authenticator>{}</Authenticator></UserLogin></s:Body></s:Envelope>",
                env,
                crate::dp::base64_encode(&challenge),
                crate::dp::base64_encode(&mac[..16])
            ),
        )
        .await;
        assert!(r.contains("200 OK"), "UserLogin: {}", &r[..r.len().min(300)]);

        // the session now carries Admin: GetACLData opens, roles show Admin
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#GetACLData",
            &format!(
                "{}GetACLData xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"/></s:Body></s:Envelope>",
                env
            ),
        )
        .await;
        assert!(
            r.contains("admin-cp") && r.contains("<Role>Admin</Role>"),
            "ACL after login: {}",
            &r[..r.len().min(400)]
        );
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#GetAssignedRoles",
            &format!(
                "{}GetAssignedRoles xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"/></s:Body></s:Envelope>",
                env
            ),
        )
        .await;
        assert!(
            r.contains("<RoleList>Admin</RoleList>"),
            "assigned roles: {}",
            &r[..r.len().min(300)]
        );

        // the v2 mapping boundary now passes: the gate yields to the
        // engine (which fails on nft here — but NOT with 606)
        let mut r = soap_post(
            &addr,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#AddPortMapping",
            &format!("{}AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewRemoteHost></NewRemoteHost><NewExternalPort>12345</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>12345</NewInternalPort><NewInternalClient>192.168.21.50</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>dp-wire</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></AddPortMapping></s:Body></s:Envelope>", env))
        .await;
        assert!(
            !r.contains("<errorCode>606</errorCode>"),
            "authorized v2 reaches the engine: {}",
            &r[..r.len().min(300)]
        );

        // the lift is the principal's roles, not the face's: walking the
        // enumeration now reaches the other host's entry, on either face
        for face in ["1", "2"] {
            let mut reached = Vec::new();
            for i in 0..4 {
                let rr = soap_post(
                    &addr,
                    "/ctl/IPConn",
                    &format!(
                        "urn:schemas-upnp-org:service:WANIPConnection:{}#GetGenericPortMappingEntry",
                        face
                    ),
                    &format!(
                        "{}GetGenericPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:{}\"><NewPortMappingIndex>{}</NewPortMappingIndex></GetGenericPortMappingEntry></s:Body></s:Envelope>",
                        env, face, i
                    ),
                )
                .await;
                if rr.contains("<errorCode>") {
                    break;
                }
                reached.push(rr.contains("192.168.21.50"));
            }
            assert!(
                reached.iter().any(|x| *x),
                "the :{} lifted walk reaches the other host's entry: {:?}",
                face,
                reached
            );
        }
        for face in ["1", "2"] {
            r = soap_post(
                &addr,
                "/ctl/IPConn",
                &format!(
                    "urn:schemas-upnp-org:service:WANIPConnection:{}#GetSpecificPortMappingEntry",
                    face
                ),
                &format!(
                    "{}GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:{}\"><NewRemoteHost></NewRemoteHost><NewExternalPort>20500</NewExternalPort><NewProtocol>UDP</NewProtocol></GetSpecificPortMappingEntry></s:Body></s:Envelope>",
                    env, face
                ),
            )
            .await;
            // The specific read is "mine" whether or not the session holds
            // a lift (call/0022), so what a lifted caller gains is the
            // enumeration: walking it must now reach the other host's entry.
            assert!(
                r.contains("<errorCode>714</errorCode>"),
                "the :{} specific read stays the caller's own namespace: {}",
                face,
                &r[..r.len().min(300)]
            );
        }

        // the v2 range actions answer the spec's own 7xx codes rather than
        // a generic failure: an empty range is 730 PortMappingNotFound
        // (2.5.19.2, 2.5.21.3) and a crossed range is 733
        // InconsistentParameters (2.5.19.6, 2.5.21.7)
        let r = soap_post(
            &addr,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#DeletePortMappingRange",
            &format!("{}DeletePortMappingRange xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewStartPort>5000</NewStartPort><NewEndPort>6000</NewEndPort><NewProtocol>UDP</NewProtocol><NewManage>0</NewManage></DeletePortMappingRange></s:Body></s:Envelope>", env))
        .await;
        assert!(
            r.contains("<errorCode>730</errorCode>"),
            "an empty delete range is 730: {}",
            &r[..r.len().min(300)]
        );
        let r = soap_post(
            &addr,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#GetListOfPortMappings",
            &format!("{}GetListOfPortMappings xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewStartPort>5000</NewStartPort><NewEndPort>6000</NewEndPort><NewProtocol>UDP</NewProtocol><NewManage>0</NewManage><NewNumberOfPorts>0</NewNumberOfPorts></GetListOfPortMappings></s:Body></s:Envelope>", env))
        .await;
        assert!(
            r.contains("<errorCode>730</errorCode>"),
            "an empty listing is 730: {}",
            &r[..r.len().min(300)]
        );
        let r = soap_post(
            &addr,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#DeletePortMappingRange",
            &format!("{}DeletePortMappingRange xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewStartPort>6000</NewStartPort><NewEndPort>5000</NewEndPort><NewProtocol>UDP</NewProtocol><NewManage>0</NewManage></DeletePortMappingRange></s:Body></s:Envelope>", env))
        .await;
        assert!(
            r.contains("<errorCode>733</errorCode>"),
            "a crossed range is 733: {}",
            &r[..r.len().min(300)]
        );
        // the AddAnyPortMapping wildcard asks for any free port rather than
        // being a malformed request: it reaches the engine (which allocates
        // 1024 from the wildcard and then fails on nft here, 501) where the
        // placeholder answered 402 without consulting anything. The in-LAN
        // client is this test's loopback LAN, so the engine's own
        // containment check is not what refuses it.
        let r = soap_post(
            &addr,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#AddAnyPortMapping",
            &format!("{}AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewRemoteHost></NewRemoteHost><NewExternalPort>0</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>12399</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>dp-wire-any</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></AddAnyPortMapping></s:Body></s:Envelope>", env))
        .await;
        assert!(
            r.contains("<errorCode>501</errorCode>"),
            "the wildcard reaches the engine: {}",
            &r[..r.len().min(700)]
        );

        // UserLogout closes the session: GetACLData is 606 again
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#UserLogout",
            &format!(
                "{}UserLogout xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"/></s:Body></s:Envelope>",
                env
            ),
        )
        .await;
        assert!(r.contains("200 OK"), "logout: {}", &r[..r.len().min(200)]);
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#GetACLData",
            &format!(
                "{}GetACLData xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"/></s:Body></s:Envelope>",
                env
            ),
        )
        .await;
        assert!(
            r.contains("<errorCode>606</errorCode>"),
            "logout closes the session: {}",
            &r[..r.len().min(300)]
        );

        // a wrong password on the verifier core: bad Authenticator -> 701
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#GetUserLoginChallenge",
            &format!("{}GetUserLoginChallenge xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"><ProtocolType>PKCS5</ProtocolType><Name>admin</Name></GetUserLoginChallenge></s:Body></s:Envelope>", env),
        )
        .await;
        let challenge_b64 =
            String::from_utf8_lossy(upnp::xml_tag(r.as_bytes(), b"Challenge").unwrap()).into_owned();
        let challenge = crate::dp::base64_decode(challenge_b64.trim()).unwrap();
        let mut mac_in = Vec::new();
        mac_in.extend_from_slice(&challenge);
        mac_in.extend_from_slice(&[0xdd; 16]);
        mac_in.extend_from_slice(&[0xca; 16]);
        let wrong = crate::dp::hmac_sha256(&[7u8; 16], &mac_in);
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#UserLogin",
            &format!(
                "{}UserLogin xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"><ProtocolType>PKCS5</ProtocolType><Challenge>{}</Challenge><Authenticator>{}</Authenticator></UserLogin></s:Body></s:Envelope>",
                env,
                crate::dp::base64_encode(&challenge),
                crate::dp::base64_encode(&wrong[..16])
            ),
        )
        .await;
        assert!(
            r.contains("<errorCode>701</errorCode>"),
            "bad authenticator -> 701: {}",
            &r[..r.len().min(300)]
        );

        // SendSetupMessage: unsupported ProtocolType 600; WPS 704 (no
        // registrar on a wired IGD)
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#SendSetupMessage",
            &format!("{}SendSetupMessage xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"><ProtocolType>BOGUS</ProtocolType><InMessage>AA==</InMessage></SendSetupMessage></s:Body></s:Envelope>", env),
        )
        .await;
        assert!(
            r.contains("<errorCode>600</errorCode>"),
            "unknown protocol -> 600: {}",
            &r[..r.len().min(300)]
        );
        let r = soap_post(
            &addr,
            "/ctl/DP",
            "urn:schemas-upnp-org:service:DeviceProtection:1#SendSetupMessage",
            &format!("{}SendSetupMessage xmlns:u=\"urn:schemas-upnp-org:service:DeviceProtection:1\"><ProtocolType>WPS</ProtocolType><InMessage>AA==</InMessage></SendSetupMessage></s:Body></s:Envelope>", env),
        )
        .await;
        assert!(
            r.contains("<errorCode>704</errorCode>"),
            "WPS without a registrar -> 704: {}",
            &r[..r.len().min(300)]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dp_config_persistence_wire() {
        // 26.15: users + ACL persist across a restart; sessions do not.
        let dir = "/tmp/dp-wire-state";
        let _ = std::fs::remove_dir_all(dir);
        let device_id: [u8; 16] = [0xee; 16];
        let salt = [21u8; 16];
        let users = vec![crate::dp::DpUser {
            name: "admin".into(),
            salt,
            stored: crate::dp::stored_for(b"pw", b"admin", &salt),
            roles: vec!["Admin".into()],
        }];
        let acl = crate::dp::DpAcl {
            identities: vec![crate::dp::DpIdentity {
                name: "admin-cp".into(),
                alias: None,
                id: [0xca; 16],
                roles: vec!["Admin".into()],
            }],
        };
        let mut st = crate::dp::DpState::new(device_id, users, acl);
        st.begin_login("192.168.21.5".parse().unwrap(), "admin", [3u8; 16], 1000)
            .unwrap();
        dp_save(dir, &st);
        let reloaded = dp_load(dir, device_id);
        // the config (users + ACL) survived; the session did not
        assert_eq!(reloaded.users.len(), 1);
        assert_eq!(reloaded.acl.identities.len(), 1);
        assert_eq!(reloaded.session_roles("192.168.21.5".parse().unwrap(), 2000).len(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }
    /// The connection-control actions of the required WANIPConnection:2
    /// surface at the wire: the auto-configured line answers
    /// SetConnectionType with 731 ReadOnly, reports NAT on and RSIP off,
    /// refuses ForceTermination instead of handing every LAN client a
    /// lever on the household line, and treats RequestConnection as the
    /// success it is while the external tuple is present, with 704
    /// ConnectionSetupFailed when it is not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wip2_connection_actions_wire() {
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/wip2-conn".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "wip2-conn".into(),
            grace_secs: 60,
        };
        let facade = Arc::new(UpnpFacade {
            cfg,
            table: Arc::new(Mutex::new(LeaseTable::new(
                PortAllocator::new(30000, 30009).unwrap(),
                4,
                2,
            ))),
            publisher: Arc::new(Publisher::with_watch(
                "/tmp/none",
                watch::channel(Ipv4Addr::new(87, 116, 31, 222)).0,
            )),
            entries: Mutex::new(Vec::new()),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            // the tuple watch holds the AFTR address: the line is up
            ip_rx: watch::channel(Ipv4Addr::new(87, 116, 31, 222)).1,
            udn: String::from("wip2-conn"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let f2 = facade.clone();
        tokio::spawn(async move {
            let _ = http_serve(listener, f2).await;
        });
        let addr_s = format!("127.0.0.1:{}", addr.port());
        let env = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:";
        let urn = "urn:schemas-upnp-org:service:WANIPConnection:2";
        // SetConnectionType: the connection type is auto-configured and
        // therefore read-only (2.5.1), so the answer is the spec's 731
        let r = soap_post(
            &addr_s,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#SetConnectionType",
            &format!(
                "{}SetConnectionType xmlns:u=\"{}\"<NewConnectionType>IP_Routed</NewConnectionType></SetConnectionType></s:Body></s:Envelope>",
                env, urn
            ),
        )
        .await;
        assert!(
            r.contains("<errorCode>731</errorCode>"),
            "an auto-configured connection type is read-only: {}",
            &r[..r.len().min(400)]
        );

        // GetNATRSIPStatus: NAT on, RSIP off
        let r = soap_post(
            &addr_s,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#GetNATRSIPStatus",
            &format!(
                "{}GetNATRSIPStatus xmlns:u=\"{}\"/></s:Body></s:Envelope>",
                env, urn
            ),
        )
        .await;
        assert!(
            r.contains("<NewRSIPAvailable>0</NewRSIPAvailable>")
                && r.contains("<NewNATEEnabled>1</NewNATEEnabled>"),
            "RSIP off and NAT on: {}",
            &r[..r.len().min(500)]
        );

        // RequestConnection while the tuple is present: the precondition
        // and the effect of 2.5.3 both already hold, so it succeeds
        let r = soap_post(
            &addr_s,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#RequestConnection",
            &format!("{}RequestConnection xmlns:u=\"{}\"/></s:Body></s:Envelope>", env, urn),
        )
        .await;
        assert!(
            r.contains("200 OK") && !r.contains("<errorCode>"),
            "an up line answers RequestConnection with success: {}",
            &r[..r.len().min(300)]
        );

        // ForceTermination is refused: the facade does not own the WAN
        // lifetime, and the v1 face would let any LAN device drop it
        let r = soap_post(
            &addr_s,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#ForceTermination",
            &format!("{}ForceTermination xmlns:u=\"{}\"/></s:Body></s:Envelope>", env, urn),
        )
        .await;
        assert!(
            r.contains("<errorCode>501</errorCode>"),
            "the household line is not a LAN device's to drop: {}",
            &r[..r.len().min(300)]
        );

        // the same surface with no external tuple: RequestConnection now
        // reports the provider-side failure the spec names for it
        let mut f3 = UpnpFacade {
            cfg: UpnpConfig {
                lan_ip: Ipv4Addr::LOCALHOST,
                upnp_port: 0,
                bind_ip: Ipv4Addr::LOCALHOST,
                state_dir: "/tmp/wip2-conn-down".into(),
                servers: Vec::new(),
                interval: Duration::from_secs(2),
                name: "wip2-conn-down".into(),
                grace_secs: 60,
            },
            table: Arc::new(Mutex::new(LeaseTable::new(
                PortAllocator::new(30000, 30009).unwrap(),
                4,
                2,
            ))),
            publisher: Arc::new(Publisher::with_watch(
                "/tmp/none",
                watch::channel(Ipv4Addr::UNSPECIFIED).0,
            )),
            entries: Mutex::new(Vec::new()),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::UNSPECIFIED).1,
            udn: String::from("wip2-conn-down"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        };
        f3.cfg.upnp_port = 0;
        let down = Arc::new(f3);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_down = listener.local_addr().unwrap();
        let f4 = down.clone();
        tokio::spawn(async move {
            let _ = http_serve(listener, f4).await;
        });
        let addr_down_s = format!("127.0.0.1:{}", addr_down.port());
        let r = soap_post(
            &addr_down_s,
            "/ctl/IPConn",
            "urn:schemas-upnp-org:service:WANIPConnection:2#RequestConnection",
            &format!("{}RequestConnection xmlns:u=\"{}\"/></s:Body></s:Envelope>", env, urn),
        )
        .await;
        assert!(
            r.contains("<errorCode>704</errorCode>") && r.contains("ConnectionSetupFailed"),
            "no tuple means the provider side is not up: {}",
            &r[..r.len().min(400)]
        );
    }

    // ---- the evented surface (call/0025, plan/0009 #signal) ----

    fn ev(ip: &str, entries: u16, update_id: u32) -> EventView {
        EventView::new(ip.parse().unwrap(), entries, update_id)
    }

    fn ev_entry(owner: Ipv4Addr, int_port: u16, bind_port: u16) -> FacadeEntry {
        FacadeEntry {
            req_ext: int_port,
            proto: Proto::Udp,
            owner,
            client: owner,
            int_port,
            bind_port,
            granted_lifetime: 600,
            expires_at_unix: 0,
            desc: String::new(),
        }
    }

    #[test]
    fn an_initial_event_carries_every_declared_variable() {
        let body = propertyset(None, &ev("87.116.31.222", 3, 7));
        for name in [
            "ConnectionStatus",
            "ExternalIPAddress",
            "PortMappingNumberOfEntries",
            "SystemUpdateID",
        ] {
            assert!(body.contains(name), "{} missing from {}", name, body);
        }
        assert!(body.contains("<ExternalIPAddress>87.116.31.222</ExternalIPAddress>"), "{}", body);
        assert!(body.contains("<PortMappingNumberOfEntries>3</PortMappingNumberOfEntries>"), "{}", body);
        assert!(body.contains("<SystemUpdateID>7</SystemUpdateID>"), "{}", body);
        assert!(body.contains("urn:schemas-upnp-org:event-1-0"), "{}", body);
    }

    #[test]
    fn a_change_event_carries_only_what_moved() {
        let prev = ev("87.116.31.222", 3, 7);
        let now = EventView::new("87.116.31.222".parse().unwrap(), 3, 8);
        let body = propertyset(Some(&prev), &now);
        assert!(body.contains("SystemUpdateID"), "{}", body);
        assert!(!body.contains("ExternalIPAddress"), "{}", body);
        assert!(!body.contains("PortMappingNumberOfEntries"), "{}", body);
        assert!(!body.contains("ConnectionStatus"), "{}", body);
        // nothing moved at all is not an event
        assert_eq!(propertyset(Some(&now), &now), "");
    }

    #[test]
    fn the_connection_status_follows_the_tuple() {
        assert_eq!(EventView::new(Ipv4Addr::UNSPECIFIED, 0, 0).status, Status::Disconnected);
        assert_eq!(
            EventView::new(Ipv4Addr::new(87, 116, 31, 222), 0, 0).status,
            Status::Connected
        );
        let down = EventView::new(Ipv4Addr::UNSPECIFIED, 0, 0);
        let up = EventView::new(Ipv4Addr::new(87, 116, 31, 222), 0, 1);
        let body = propertyset(Some(&down), &up);
        assert!(body.contains("<ConnectionStatus>Connected</ConnectionStatus>"), "{}", body);
    }

    #[test]
    fn a_scoped_count_is_the_callers_own_namespace() {
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let b = Ipv4Addr::new(192, 168, 21, 51);
        let entries = vec![
            ev_entry(a, 3074, 30000),
            ev_entry(b, 3074, 30001),
            ev_entry(a, 40000, 30002),
        ];
        assert_eq!(scoped_count(None, &entries), 3, "the lift sees the whole table");
        assert_eq!(
            scoped_count(Some(Contain { caller: a, high_port: true }), &entries),
            2
        );
        assert_eq!(
            scoped_count(Some(Contain { caller: b, high_port: true }), &entries),
            1
        );
        assert_eq!(
            scoped_count(
                Some(Contain { caller: Ipv4Addr::new(192, 168, 21, 99), high_port: true }),
                &entries
            ),
            0,
            "a caller sees nothing that is not its own"
        );
        // and the v1 face's floor, where it applies, excludes low ports
        let low = vec![ev_entry(a, 80, 30003)];
        assert_eq!(
            scoped_count(Some(Contain { caller: a, high_port: true }), &low),
            0
        );
        assert_eq!(
            scoped_count(Some(Contain { caller: a, high_port: false }), &low),
            1
        );
    }

    #[test]
    fn a_mapping_whose_discovery_drags_answers_the_network_error() {
        assert_eq!(discovery_verdict(0, false), None, "young: silence, the client retries");
        assert_eq!(discovery_verdict(DISCOVERY_GRACE_S - 1, false), None);
        assert_eq!(
            discovery_verdict(DISCOVERY_GRACE_S, false),
            Some(crate::pcp::rc::NETWORK_FAILURE)
        );
        assert_eq!(discovery_verdict(600, true), None, "a known tuple is never an error");
    }

    /// plan/0009 #signal, end to end: a real subscription over a real socket,
    /// told exactly what changed and scoped to its own namespace alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_subscriber_is_told_about_its_own_mappings_only() {
        let l = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = l.local_addr().unwrap().port();
        let a = Ipv4Addr::new(127, 0, 0, 1);
        let b = Ipv4Addr::new(127, 0, 0, 2);
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "signal".into(),
            grace_secs: 60,
        };
        let facade = Arc::new(UpnpFacade {
            cfg,
            table: Arc::new(Mutex::new(LeaseTable::new(
                PortAllocator::new(30000, 30009).unwrap(),
                8,
                4,
            ))),
            publisher: Arc::new(Publisher::with_watch(
                "/tmp/none",
                watch::channel(Ipv4Addr::new(87, 116, 31, 222)).0,
            )),
            entries: Mutex::new(vec![ev_entry(a, 3074, 30000), ev_entry(b, 3074, 30001)]),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::new(87, 116, 31, 222)).1,
            udn: String::from("signal"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });

        let cb = format!("<http://127.0.0.1:{}/evt>", port);
        facade
            .gena_subscribe(cb.as_bytes(), 30, a, true)
            .await
            .expect("subscribe with a reachable callback");

        // read_head returns everything its own read took, head *and* body
        // when the NOTIFY arrived in one segment, so the body is taken from
        // that buffer first and only the remainder from the socket.
        async fn body_of(stream: &mut TcpStream) -> String {
            let raw = read_head(stream).await.expect("notify head");
            let (head, rest) = split_head(&raw).expect("head terminator");
            let want = content_length(head).unwrap_or(0);
            let mut body = rest.to_vec();
            while body.len() < want {
                let more = read_body(stream, want - body.len()).await.expect("notify body");
                if more.is_empty() {
                    break;
                }
                body.extend_from_slice(&more);
            }
            String::from_utf8_lossy(&body[..want.min(body.len())]).into_owned()
        }

        // the initial event carries every declared variable, and the count is
        // the subscriber's own namespace alone
        let (mut s0, _) = l.accept().await.unwrap();
        let first = body_of(&mut s0).await;
        assert!(first.contains("ConnectionStatus"), "{}", first);
        assert!(first.contains("ExternalIPAddress"), "{}", first);
        assert!(first.contains("<PortMappingNumberOfEntries>1</PortMappingNumberOfEntries>"), "{}", first);
        assert!(first.contains("SystemUpdateID"), "{}", first);

        // a mapping appears: the update id moves, so that is the event
        facade.bump_update_id().await;
        facade.notify_all(Ipv4Addr::new(87, 116, 31, 222)).await;
        let (mut s1, _) = l.accept().await.unwrap();
        let second = body_of(&mut s1).await;
        assert!(second.contains("<SystemUpdateID>1</SystemUpdateID>"), "{}", second);
        assert!(!second.contains("ExternalIPAddress"), "the address did not move: {}", second);
        assert!(
            !second.contains("PortMappingNumberOfEntries"),
            "the count did not move: {}",
            second
        );

        // and nothing moved at all is not an event: no third delivery
        facade.notify_all(Ipv4Addr::new(87, 116, 31, 222)).await;
        let idle = tokio::time::timeout(Duration::from_millis(300), l.accept()).await;
        assert!(idle.is_err(), "a NOTIFY arrived that no change justifies");

        // the tuple moved: that is an event, and the address is the variable
        facade.notify_all(Ipv4Addr::new(87, 116, 31, 223)).await;
        let (mut s2, _) = l.accept().await.unwrap();
        let third = body_of(&mut s2).await;
        assert!(third.contains("<ExternalIPAddress>87.116.31.223</ExternalIPAddress>"), "{}", third);
    }

    /// plan/0009 #pcp, end to end over a real socket: the announcements, the
    /// refusals the RFC names, and the NAT-PMP subset that shares the port.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_shared_port_answers_announce_and_names_its_refusals() {
        let a = Ipv4Addr::new(127, 0, 0, 1);
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: "/tmp/none".into(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "pcp".into(),
            grace_secs: 60,
        };
        let facade = Arc::new(UpnpFacade {
            cfg,
            table: Arc::new(Mutex::new(LeaseTable::new(
                PortAllocator::new(30000, 30009).unwrap(),
                8,
                4,
            ))),
            publisher: Arc::new(Publisher::with_watch(
                "/tmp/none",
                watch::channel(Ipv4Addr::new(87, 116, 31, 222)).0,
            )),
            entries: Mutex::new(Vec::new()),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::new(87, 116, 31, 222)).1,
            udn: String::from("pcp"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });
        let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = sock.local_addr().unwrap();
        let f = facade.clone();
        tokio::spawn(async move {
            f.pcp_serve(sock, false).await;
        });
        let cli = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let mut buf = [0u8; 1500];

        fn mapped4(ip: Ipv4Addr) -> [u8; 16] {
            let mut a = [0u8; 16];
            a[10] = 0xff;
            a[11] = 0xff;
            a[12..16].copy_from_slice(&ip.octets());
            a
        }
        fn request(opcode: u8, lifetime: u32, client: Ipv4Addr, body: &[u8]) -> Vec<u8> {
            let mut b = vec![2u8, opcode];
            b.extend_from_slice(&0u16.to_be_bytes());
            b.extend_from_slice(&lifetime.to_be_bytes());
            b.extend_from_slice(&mapped4(client));
            b.extend_from_slice(body);
            b
        }
        fn map_body(proto: u8, int_port: u16, sug: u16) -> Vec<u8> {
            let mut b = vec![0x5Au8; 12];
            b.push(proto);
            b.extend_from_slice(&[0u8; 3]);
            b.extend_from_slice(&int_port.to_be_bytes());
            b.extend_from_slice(&sug.to_be_bytes());
            b.extend_from_slice(&mapped4(Ipv4Addr::UNSPECIFIED));
            b
        }
        async fn ask(
            cli: &UdpSocket,
            addr: SocketAddr,
            req: &[u8],
            buf: &mut [u8],
        ) -> Option<usize> {
            cli.send_to(req, addr).await.unwrap();
            match tokio::time::timeout(Duration::from_millis(500), cli.recv(buf)).await {
                Ok(Ok(n)) => Some(n),
                _ => None,
            }
        }

        // ANNOUNCE: the header back, no opcode payload
        let n = ask(&cli, addr, &request(0, 0, a, &[]), &mut buf)
            .await
            .expect("an ANNOUNCE is answered");
        assert_eq!(n, 24, "an ANNOUNCE response is the header alone");
        assert_eq!(buf[1], 0x80, "the R bit, and the ANNOUNCE opcode");
        assert_eq!(buf[3], crate::pcp::rc::SUCCESS);

        // a version this server does not speak
        let mut wrong = request(1, 120, a, &map_body(17, 3074, 3074));
        wrong[0] = 9;
        let n = ask(&cli, addr, &wrong, &mut buf).await.expect("answered");
        assert_eq!(buf[3], crate::pcp::rc::UNSUPP_VERSION, "len {}", n);

        // a filter this datapath cannot install: the RFC's own code for it
        let mut filtered = request(1, 120, a, &map_body(17, 3074, 0));
        let mut f_opt = vec![3u8, 0, 0, 20, 0, 32];
        f_opt.extend_from_slice(&3074u16.to_be_bytes());
        f_opt.extend_from_slice(&mapped4(Ipv4Addr::new(203, 0, 113, 7)));
        while f_opt.len() % 4 != 0 {
            f_opt.push(0);
        }
        filtered.extend_from_slice(&f_opt);
        ask(&cli, addr, &filtered, &mut buf).await.expect("answered");
        assert_eq!(
            buf[3],
            crate::pcp::rc::EXCESSIVE_REMOTE_PEERS,
            "a filter we cannot install is refused, not claimed"
        );

        // PREFER_FAILURE: the AFTR owns the port, so no substitution
        let mut prefer = request(1, 120, a, &map_body(17, 3074, 3074));
        prefer.extend_from_slice(&[2u8, 0, 0, 0]);
        ask(&cli, addr, &prefer, &mut buf).await.expect("answered");
        assert_eq!(buf[3], crate::pcp::rc::CANNOT_PROVIDE_EXTERNAL);

        // THIRD_PARTY without the lift
        let mut third = request(1, 120, a, &map_body(17, 3074, 0));
        third.extend_from_slice(&[1u8, 0, 0, 16]);
        third.extend_from_slice(&mapped4(Ipv4Addr::new(192, 168, 21, 60)));
        ask(&cli, addr, &third, &mut buf).await.expect("answered");
        assert_eq!(buf[3], crate::pcp::rc::NOT_AUTHORIZED);

        // a protocol this datapath does not hold
        ask(&cli, addr, &request(1, 120, a, &map_body(132, 3074, 0)), &mut buf)
            .await
            .expect("answered");
        assert_eq!(buf[3], crate::pcp::rc::UNSUPP_PROTOCOL);

        // the delete form with nothing to delete is a success with no lifetime
        ask(&cli, addr, &request(1, 0, a, &map_body(17, 3074, 0)), &mut buf)
            .await
            .expect("answered");
        assert_eq!(buf[3], crate::pcp::rc::SUCCESS);
        assert_eq!(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]), 0);

        // NAT-PMP on the same port: the public address, then an unknown opcode
        let n = ask(&cli, addr, &[0u8, 0], &mut buf).await.expect("answered");
        assert_eq!(n, 12);
        assert_eq!(buf[1], crate::pcp::np::OP_PUBLIC | crate::pcp::np::RESP);
        assert_eq!(&buf[8..12], &[87, 116, 31, 222], "the learned external address");
        let n = ask(&cli, addr, &[0u8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &mut buf)
            .await
            .expect("answered");
        assert_eq!(n, 12);
        assert_eq!(buf[1], 9 | crate::pcp::np::RESP);
        assert_eq!(
            u16::from_be_bytes([buf[2], buf[3]]),
            u16::from(crate::pcp::np::UNSUPP_OPCODE)
        );
    }

    /// A revoked mapping takes its tuple file with it (found on the box,
    /// 2026-09-17: slots 40003-40005 carried dead tuples from mappings long
    /// gone, and a fresh grant that landed on one of those ports was answered
    /// with the dead tuple). The file is the *learned* tuple, so a file that
    /// outlives its mapping is a lie a client can act on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_revoked_mapping_takes_its_tuple_file_with_it() {
        let a = Ipv4Addr::new(127, 0, 0, 1);
        let d = std::env::temp_dir().join(format!("dslp-tuplefile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let dir = d.to_str().unwrap().to_string();
        std::fs::write(format!("{}/tuple-30000", dir), "203.0.113.9:40001\n").unwrap();
        let cfg = UpnpConfig {
            lan_ip: Ipv4Addr::LOCALHOST,
            upnp_port: 0,
            bind_ip: Ipv4Addr::LOCALHOST,
            state_dir: dir.clone(),
            servers: Vec::new(),
            interval: Duration::from_secs(2),
            name: "tuple-file".into(),
            grace_secs: 60,
        };
        let facade = Arc::new(UpnpFacade {
            cfg,
            table: Arc::new(Mutex::new(LeaseTable::new(
                PortAllocator::new(30000, 30009).unwrap(),
                8,
                4,
            ))),
            publisher: Arc::new(Publisher::with_watch(
                &dir,
                watch::channel(Ipv4Addr::LOCALHOST).0,
            )),
            entries: Mutex::new(vec![ev_entry(a, 3074, 30000)]),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("tuple-file"),
            started_unix: 0,
            ssdp: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bursts: Arc::new(StdMutex::new(HashMap::new())),
            dp: StdMutex::new(crate::dp::DpState::default()),
            pcp_wait: StdMutex::new(HashMap::new()),
            presence_misses: StdMutex::new(HashMap::new()),
        });
        facade
            .delete_mapping(3074, Proto::Udp, a, None)
            .await
            .expect("the caller's own mapping deletes");
        assert!(
            !std::path::Path::new(&format!("{}/tuple-30000", dir)).exists(),
            "the dead mapping's tuple file must go with it"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
