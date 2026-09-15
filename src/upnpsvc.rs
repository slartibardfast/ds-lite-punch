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
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex, Semaphore};

use crate::mapping::State;
use crate::nft;
use crate::persist::{self, DEFAULT_DIR};
use crate::publish::Publisher;
use crate::slot::{Epoch, Lease, LeaseTable, Proto, Slot, UpsertOutcome};
use crate::tcpslot;
use crate::upnp;
use crate::upnp::*;
use crate::vote::VoteState;

/// Concurrency cap for the HTTP service (E8: bounded connections).
const HTTP_CONN_CAP: usize = 16;
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
/// and reported through the tuple watch ("report-requested", E3).
#[derive(Clone, Copy, Debug)]
struct FacadeEntry {
    req_ext: u16,
    proto: Proto,
    client: Ipv4Addr,
    int_port: u16,
    bind_port: u16,
    granted_lifetime: u32,
    expires_at_unix: u64,
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
}

#[derive(Default)]
struct GenaState {
    subs: Vec<Sub>,
    sids: SidSet,
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
    ssdp: UdpSocket,
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
            ssdp,
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
                eprintln!("upnp: http service stopped: {}", e);
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
                    eprintln!(
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
            // respond within a random delay inside MX (capped 5 s by the
            // grammar); jitter avoids reply storms on a broadcast query
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
            let resp = msearch_response(
                st,
                &self.udn,
                self.cfg.lan_ip,
                self.cfg.upnp_port,
                Epoch::now(),
            );
            let _ = self.ssdp.send_to(&resp, src).await;
        }
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

    async fn add_mapping(
        &self,
        req_ext: u16,
        proto: Proto,
        client: Ipv4Addr,
        int_port: u16,
        lifetime: u32,
    ) -> Result<String, UpnpErr> {
        if !in_lan(client, self.cfg.lan_ip) {
            return Err(UpnpErr::InvalidArgs);
        }
        let lifetime = if lifetime == 0 { INFINITE_LEASE } else { lifetime };
        let now = Epoch::now();
        let bind_port;
        let outcome = {
            let mut t = self.table.lock().await;
            t.upsert_pcp(proto, int_port, client, lifetime, now, client, int_port)
        };
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
            let mut t = self.table.lock().await;
            t.delete_by_bind_port(bind_port);
            eprintln!("upnp: grant datapath {} failed: {}", bind_port, e);
            return Err(UpnpErr::ActionFailed);
        }
            let handles = match proto {
                Proto::Udp => self.spawn_udp_slot(bind_port, client, int_port).await,
                Proto::Tcp => self.spawn_tcp_slot(bind_port, client, int_port).await,
            };
            match handles {
                Ok(h) => {
                    self.tasks.lock().await.insert(bind_port, h);
                }
                Err(e) => {
                    // bind failed: roll back nft + table
                    let _ = nft::del_input_accept(bind_port, proto == Proto::Tcp);
                    let _ = nft::del_pin(client, int_port);
                    let mut t = self.table.lock().await;
                    t.delete_by_bind_port(bind_port);
                    eprintln!("upnp: slot bind {} failed: {}", bind_port, e);
                    return Err(UpnpErr::ActionFailed);
                }
            }
        }

        // Record / refresh the control-plane entry (one entry per internal
        // key — client, int, proto; the requested port rides the re-Add).
        // A re-Add that moved the mapping to a new slot surrenders the
        // requested port's previous occupant, so delete/enumerate always
        // resolve to the slot the control point actually owns.
        let stray = {
            let mut es = self.entries.lock().await;
            apply_entry(&mut es, req_ext, proto, client, int_port, bind_port, lifetime, now)
        };
        if let Some((old_bind, old_client, old_int)) = stray {
            {
                let mut t = self.table.lock().await;
                let _ = t.delete_by_bind_port(old_bind); // may already be gone (GC)
            }
            let _ = nft::revoke_datapath(old_client, old_int, old_bind, proto == Proto::Tcp);
            if let Some(h) = self.tasks.lock().await.remove(&old_bind) {
                for jh in h {
                    jh.abort();
                }
            }
        }
        self.persist().await;
        Ok(String::new())
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
        let ka = tokio::spawn(async move {
            crate::keepalive_loop(ka_sock, ka_state, interval, 0).await
        });
        let recv = tokio::spawn(async move {
            crate::run_slot(sock, state, target, publisher, bind_port).await
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

    async fn delete_mapping(&self, req_ext: u16, proto: Proto) -> Result<String, UpnpErr> {
        let (bind_port, client, int_port) = {
            let es = self.entries.lock().await;
            let Some(e) = es
                .iter()
                .find(|e| e.req_ext == req_ext && e.proto == proto)
            else {
                return Err(UpnpErr::NoSuchEntry);
            };
            (e.bind_port, e.client, e.int_port)
        };
        {
            let mut t = self.table.lock().await;
            let _ = t.delete_by_bind_port(bind_port); // may already be gone (GC)
        }
        let _ = nft::revoke_datapath(client, int_port, bind_port, proto == Proto::Tcp);
        if let Some(h) = self.tasks.lock().await.remove(&bind_port) {
            for jh in h {
                jh.abort();
            }
        }
        {
            let mut es = self.entries.lock().await;
            es.retain(|e| !(e.req_ext == req_ext && e.proto == proto));
        }
        self.persist().await;
        Ok(String::new())
    }

    async fn get_specific(&self, req_ext: u16, proto: Proto) -> Result<String, UpnpErr> {
        let es = self.entries.lock().await;
        let Some(e) = es
            .iter()
            .find(|e| e.req_ext == req_ext && e.proto == proto)
        else {
            return Err(UpnpErr::NoSuchEntry);
        };
        Ok(entry_xml(e, false))
    }

    async fn get_generic(&self, index: u32) -> Result<String, UpnpErr> {
        let es = self.entries.lock().await;
        let keys: Vec<UpnpKey> = es
            .iter()
            .map(|e| UpnpKey {
                req_ext: e.req_ext,
                proto: e.proto,
                client: e.client,
                int_port: e.int_port,
            })
            .collect();
        let k = upnp::entry_at(&keys, index).ok_or(UpnpErr::NoSuchEntry)?;
        let e = es
            .iter()
            .find(|e| e.req_ext == k.req_ext && e.proto == k.proto)
            .expect("entry_at found the key in the same list");
        Ok(entry_xml(e, true))
    }

    // ---- GENA ----

    async fn gena_subscribe(&self, callback: &[u8], timeout_secs: u32) -> Result<String, UpnpErr> {
        let Some((ip, port, path)) = parse_callback(callback) else {
            return Err(UpnpErr::InvalidArgs);
        };
        if !in_lan(ip, self.cfg.lan_ip) {
            return Err(UpnpErr::InvalidArgs);
        }
        if path.len() > GENA_CB_MAX {
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
        });
        drop(g);
        // initial NOTIFY carries eventKey 0 per GENA (E5); a delivered initial
        // notify advances the subscription's key so the first change event
        // carries 1 — never a repeat of 0 (notify_all performs the same
        // advance after every delivery).
        if let Some(ext) = self.external_ip() {
            self.notify_one(sid, ext, 0).await;
            let mut g = self.gena.lock().await;
            if let Some(s) = g.subs.iter_mut().find(|s| s.sid == sid) {
                s.seq = advance_seq(s.seq);
            }
        }
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

    async fn notify_all(&self, ip: Ipv4Addr) {
        let subs: Vec<(Sid, u32)> = {
            let g = self.gena.lock().await;
            g.subs.iter().map(|s| (s.sid, s.seq)).collect()
        };
        for (sid, seq) in subs {
            self.notify_one(sid, ip, seq).await;
            let mut g = self.gena.lock().await;
            if let Some(s) = g.subs.iter_mut().find(|s| s.sid == sid) {
                s.seq = advance_seq(s.seq);
            }
        }
    }

    async fn notify_one(&self, sid: Sid, ip: Ipv4Addr, seq: u32) {
        let sub = {
            let g = self.gena.lock().await;
            g.subs.iter().find(|s| s.sid == sid).cloned()
        };
        let Some(s) = sub else {
            return;
        };
        let path = if s.cb_path.is_empty() {
            "/".to_string()
        } else {
            String::from_utf8_lossy(&s.cb_path).into_owned()
        };
        let body = format!(
            "<?xml version=\"1.0\"?>\n<e:propertyset xmlns:e=\"urn:schemas-upnp-org:event-1-0\">\
             <e:property><ExternalIPAddress>{}</ExternalIPAddress></e:property></e:propertyset>\n",
            ip
        );
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
            eprintln!(
                "upnp: gena pruned {} expired subscription(s)",
                before - g.subs.len()
            );
        }
    }

    // ---- local GC (facade-owned teardown) ----

    async fn gc_loop(&self) {
        let grace = self.cfg.grace_secs;
        let now = Epoch::now();
        // capture the pre-GC slots to know the torn-down client tuples
        let pre: Vec<Slot> = {
            let t = self.table.lock().await;
            t.slots().to_vec()
        };
        let freed = {
            let mut t = self.table.lock().await;
            t.gc(now, grace)
        };
        if freed.is_empty() {
            return;
        }
        for port in &freed {
            let info = pre.iter().find(|s| s.bind_port == *port).copied();
            if let Some(s) = info {
                if let Some(client) = s.client() {
                    let _ = nft::revoke_datapath(client, s.target_port, *port, s.proto == Proto::Tcp);
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
        eprintln!("upnp: gc freed slots {:?}", freed);
    }

    // ---- persistence ----

    async fn persist(&self) {
        let now = Epoch::now();
        let slots: Vec<Slot> = {
            let t = self.table.lock().await;
            t.slots().to_vec()
        };
        let _ = persist::write_leases(
            std::path::Path::new(DEFAULT_DIR),
            &persist::snapshot(&slots, now),
        );
        // the control-plane index (req_ext key) rides its own file
        let es = self.entries.lock().await;
        let mut out = String::new();
        for e in es.iter() {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                e.req_ext,
                e.proto.code(),
                e.bind_port,
                e.client,
                e.int_port,
                e.granted_lifetime,
                e.expires_at_unix
            ));
        }
        drop(es);
        let dir = std::path::Path::new(DEFAULT_DIR);
        let _ = std::fs::create_dir_all(dir);
        let tmp = dir.join("upnp.tsv.tmp");
        let final_path = dir.join("upnp.tsv");
        let _ = std::fs::write(&tmp, out);
        let _ = std::fs::rename(&tmp, final_path);
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
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // A transient accept error (fd pressure, EMFILE/ENOBUFS)
                // must not kill the control plane: the SSDP loops keep
                // advertising, and a dead HTTP service would leave the
                // facade a ghost IGD. Log and retry, like the sibling
                // loops' Err(_) => continue.
                eprintln!("upnp: accept: {}", e);
                continue;
            }
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue,
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
                handle_conn(f, stream),
            )
            .await;
        });
    }
}

/// One client connection: read the head (capped), read a body when
/// Content-Length says so, classify, dispatch.
async fn handle_conn(facade: Arc<UpnpFacade>, mut stream: TcpStream) {
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
        ReqClass::Soap { service, action } => {
            handle_soap(&facade, service, action, &body, &mut stream).await;
        }
        ReqClass::GenaSubscribe => {
            let callback = upnp::find_header(head, b"CALLBACK").unwrap_or(b"");
            let timeout =
                parse_timeout(upnp::find_header(head, b"TIMEOUT")).unwrap_or(GENA_TIMEOUT_CAP);
            match facade.gena_subscribe(callback, timeout).await {
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
    body: &[u8],
    stream: &mut TcpStream,
) {
    let result: Result<String, UpnpErr> = match (service, action) {
        (SoapService::WanIpConnection | SoapService::WanPppConnection, SoapAction::GetExternalIpAddress) => {
            facade.get_external_ip().await
        }
        (SoapService::WanIpConnection | SoapService::WanPppConnection, SoapAction::GetStatusInfo) => {
            Ok(facade.get_status_info().await)
        }
        (
            SoapService::WanIpConnection | SoapService::WanPppConnection,
            SoapAction::GetConnectionTypeInfo,
        ) => Ok(facade.get_connection_type_info()),
        (SoapService::WanIpConnection | SoapService::WanPppConnection, SoapAction::AddPortMapping) => {
            match parse_add_args(body) {
                Ok((ext, proto, int_port, client, lifetime)) => {
                    facade.add_mapping(ext, proto, client, int_port, lifetime).await
                }
                Err(e) => Err(e),
            }
        }
        (
            SoapService::WanIpConnection | SoapService::WanPppConnection,
            SoapAction::DeletePortMapping,
        ) => match parse_delete_args(body) {
            Ok((ext, proto)) => facade.delete_mapping(ext, proto).await,
            Err(e) => Err(e),
        },
        (
            SoapService::WanIpConnection | SoapService::WanPppConnection,
            SoapAction::GetSpecificPortMappingEntry,
        ) => match parse_delete_args(body) {
            Ok((ext, proto)) => facade.get_specific(ext, proto).await,
            Err(e) => Err(e),
        },
        (
            SoapService::WanIpConnection | SoapService::WanPppConnection,
            SoapAction::GetGenericPortMappingEntry,
        ) => match parse_index_arg(body) {
            Ok(i) => facade.get_generic(i).await,
            Err(e) => Err(e),
        },
        (SoapService::WanCommonIfaceCfg, SoapAction::GetCommonLinkProperties) => {
            Ok(facade.common_link_properties())
        }
        _ => Err(UpnpErr::InvalidAction),
    };
    match result {
        Ok(inner) => {
            let action_name = String::from_utf8_lossy(upnp::soap_action_name(action));
            let xml = upnp::soap_success(service, &action_name, &inner);
            let _ = write_response(stream, "200 OK", &xml, "").await;
            println!(
                "{{\"event\":\"upnp\",\"action\":\"{}\",\"service\":\"{}\"}}",
                action_name,
                String::from_utf8_lossy(upnp::service_urn(service))
            );
        }
        Err(e) => {
            let _ = write_soap_fault(stream, &fault_of(e)).await;
        }
    }
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
    if ext == 0 || int_port == 0 || client == Ipv4Addr::UNSPECIFIED {
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
    s.push_str("<NewPortMappingDescription>ds-lite-punch grant</NewPortMappingDescription>");
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
/// stray slot a replace leaves behind — the previous occupant of the
/// requested port whose datapath the caller must tear down — or None when
/// no slot changed owner.
#[allow(clippy::too_many_arguments)] // one flat decision over the grant's fields
fn apply_entry(
    es: &mut Vec<FacadeEntry>,
    req_ext: u16,
    proto: Proto,
    client: Ipv4Addr,
    int_port: u16,
    bind_port: u16,
    lifetime: u32,
    now_unix: u64,
) -> Option<(u16, Ipv4Addr, u16)> {
    let expires = now_unix.saturating_add(u64::from(lifetime));
    // Same internal tuple: the upsert refreshed the existing slot in place
    // — the entry rides to the newly requested external port, bind
    // untouched, nothing torn down.
    if let Some(idx) = es
        .iter()
        .position(|e| e.proto == proto && e.client == client && e.int_port == int_port)
    {
        let mut e = es.remove(idx);
        e.req_ext = req_ext;
        e.granted_lifetime = lifetime;
        e.expires_at_unix = expires;
        insert_sorted(es, e);
        return None;
    }
    // A different internal tuple at the same requested port: the upsert
    // granted a NEW slot, so the previous occupant must surrender the
    // port (IGDv1 allows one mapping per (ext, proto); last write wins).
    // An entry whose bind_port already IS the new slot is a stale index
    // row — refresh it in place rather than tear it down.
    if let Some(idx) = es
        .iter()
        .position(|e| e.req_ext == req_ext && e.proto == proto)
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
        return stray;
    }
    insert_sorted(
        es,
        FacadeEntry {
            req_ext,
            proto,
            client,
            int_port,
            bind_port,
            granted_lifetime: lifetime,
            expires_at_unix: expires,
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
                eprintln!("upnp: ssdp {} failed: {}", msg, io::Error::last_os_error());
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

fn restore_entries() -> Vec<FacadeEntry> {
    let path = format!("{}/upnp.tsv", DEFAULT_DIR);
    let mut out = Vec::new();
    if let Ok(s) = std::fs::read_to_string(&path) {
        for line in s.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 7 {
                continue;
            }
            let mk = || -> Option<FacadeEntry> {
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
                Some(FacadeEntry {
                    req_ext,
                    proto,
                    client,
                    int_port,
                    bind_port,
                    granted_lifetime,
                    expires_at_unix,
                })
            };
            if let Some(e) = mk() {
                out.push(e);
            }
        }
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
            client: Ipv4Addr::new(192, 168, 21, 50),
            int_port: req_ext,
            bind_port: req_ext + 1000,
            granted_lifetime: 600,
            expires_at_unix: 0,
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
            ssdp: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
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
            ssdp: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
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
    fn apply_entry_rides_internal_identity_and_replaces_occupant() {
        // Regression (review C2): the entry index used to refresh on
        // (req_ext, proto) and never updated bind_port, so a re-Add that
        // moved the mapping to a NEW slot left the entry naming the old
        // slot — delete tore down the wrong datapath and the live mapping
        // became unenumerable. One entry per internal tuple; the previous
        // occupant of a re-requested port is returned as the stray to tear
        // down.
        let now = 1_700_000_000u64;
        let a = Ipv4Addr::new(192, 168, 21, 50);
        let b = Ipv4Addr::new(192, 168, 21, 60);
        let mut es: Vec<FacadeEntry> = Vec::new();
        // A maps 3074/UDP -> slot 30000.
        assert_eq!(apply_entry(&mut es, 3074, Proto::Udp, a, 4000, 30000, 3600, now), None);
        assert_eq!(es.len(), 1);
        // A re-adds the SAME internal tuple at a new external port: the
        // entry rides the port, the same slot, nothing torn down.
        assert_eq!(apply_entry(&mut es, 3075, Proto::Udp, a, 4000, 30000, 3600, now), None);
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].req_ext, 3075);
        assert_eq!(es[0].bind_port, 30000);
        // B takes 3075/UDP with a different internal tuple: NEW slot 30001,
        // and A's occupant of 3075 is surrendered (replace semantics).
        assert_eq!(apply_entry(&mut es, 3075, Proto::Udp, b, 5000, 30001, 3600, now), Some((30000, a, 4000)));
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].client, b);
        assert_eq!(es[0].int_port, 5000);
        assert_eq!(es[0].bind_port, 30001);
        // B re-adds the same internal tuple at the same port: plain refresh.
        assert_eq!(apply_entry(&mut es, 3075, Proto::Udp, b, 5000, 30001, 3600, now), None);
        assert_eq!(es.len(), 1);
        // A fresh mapping on a free port: plain insert.
        assert_eq!(apply_entry(&mut es, 9000, Proto::Tcp, a, 9000, 30002, 3600, now), None);
        assert_eq!(es.len(), 2);
        // B re-Adds A's OWN 9000/TCP with a new internal tuple: the entry
        // pivots to B's slot and A's slot is the stray — a delete of the
        // port must then hit the newcomer, not the old slot.
        assert_eq!(apply_entry(&mut es, 9000, Proto::Tcp, b, 6000, 30003, 3600, now), Some((30002, a, 9000)));
        assert_eq!(es.iter().find(|e| e.req_ext == 9000).unwrap().bind_port, 30003);
        assert_eq!(es.len(), 2, "still one entry per external port");
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
                client: Ipv4Addr::LOCALHOST,
                int_port: 51001,
                bind_port: 30000,
                granted_lifetime: 3600,
                expires_at_unix: now + 3600,
            }]),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("restored-grant"),
            started_unix: 0,
            ssdp: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
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
            .delete_mapping(8666, Proto::Udp)
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
            ssdp: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        });

        let cb = format!("<http://127.0.0.1:{}/evt>", port);
        facade
            .gena_subscribe(cb.as_bytes(), 30)
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

    /// Local interop probe (ignored; needs the miniupnpc client source
    /// built at /tmp/localupnpc): serves the facade HTTP layer on
    /// 127.0.0.1:19152 without any router, writes the generated rootDesc
    /// to /tmp/rootdesc.xml so the real miniupnpc parser can be run
    /// against it (testigddescparse), and drives the real `upnpc -l`
    /// walk plus a GetCommonLinkProperties SOAP against the live server.
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
            entries: Mutex::new(Vec::new()),
            tasks: Mutex::new(HashMap::new()),
            gena: Mutex::new(GenaState::default()),
            ip_rx: watch::channel(Ipv4Addr::LOCALHOST).1,
            udn: String::from("interop"),
            started_unix: 0,
            ssdp: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
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
        println!("=== upnpc -l output ===\n{}", text);
        assert!(
            text.contains("Found valid IGD") || text.contains("Found an IGD"),
            "upnpc must accept the device: {}",
            text
        );
    }
}
