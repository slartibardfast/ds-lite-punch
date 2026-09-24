//! UPnP IGDv1 facade core: the pure, alloc-free layer the Kani proofs run over (`upnpsvc.rs` is the runtime).

use std::net::Ipv4Addr;

use crate::slot::Proto;

// ---- constants ----

pub const SSDP_MCAST: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
pub const SSDP_PORT: u16 = 1900;
pub const UPNP_DEFAULT_PORT: u16 = 49152;
/// The br-lan address the HTTP service and SSDP membership bind (`--lan-ip` overrides).
pub const DEFAULT_LAN_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 21, 1);
/// SSDP CACHE-CONTROL max-age (s); the alive NOTIFY interval is max-age/2.
pub const SSDP_MAX_AGE: u32 = 1800;
pub const SSDP_ALIVE_PERIOD_S: u64 = 900;
/// The SOAP envelope namespace every M-POST MAN header must name.
pub const SOAP_NS: &[u8] = b"http://schemas.xmlsoap.org/soap/envelope/";
/// Request head/body cap; UPnP request bodies are small.
pub const HTTP_CAP: usize = 8192;
/// GENA bounds: subscriptions, callback URL length, timeout cap.
pub const MAX_GENA_SUBS: usize = 8;
pub const GENA_CB_MAX: usize = 256;
pub const GENA_TIMEOUT_CAP: u32 = 1800;
/// A lease of 0 is "infinite": the max lifetime, kept from expiring by the engine's self-refresh.
pub const INFINITE_LEASE: u32 = u32::MAX;

/// The SERVER header product line (SSDP + HTTP responses).
pub const SERVER_LINE: &str = "ImmortalWrt/1.0 UPnP/1.0 ds-lite-punch/0.1";

// ---- shared byte helpers (all Kani-modelable: bounded index loops) ----

pub fn eq_ia(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

pub fn starts_with_ia(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && eq_ia(&hay[..needle.len()], needle)
}

pub(crate) fn find_byte(hay: &[u8], b: u8) -> Option<usize> {
    for i in 0..hay.len() {
        if hay[i] == b {
            return Some(i);
        }
    }
    None
}

/// Trim leading/trailing ASCII spaces, tabs, CR and LF.
pub(crate) fn trim(mut s: &[u8]) -> &[u8] {
    while matches!(s.first(), Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n')) {
        s = &s[1..];
    }
    while matches!(s.last(), Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n')) {
        s = &s[..s.len() - 1];
    }
    s
}

/// Strip a single pair of surrounding double quotes if present.
fn strip_quotes(s: &[u8]) -> &[u8] {
    if s.len() >= 2 && s[0] == b'"' && s[s.len() - 1] == b'"' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// The value of the first header whose key matches `key` case-insensitively, skipping the request line.
pub fn find_header<'a>(head: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let n = head.len();
    let mut i = 0usize;
    while i < n && head[i] != b'\n' {
        i += 1;
    }
    i += 1; // past the request line's `\n` (or n)
    while i < n {
        let mut j = i;
        while j < n && head[j] != b'\n' {
            j += 1;
        }
        let mut line = &head[i..j];
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        i = j + 1;
        if let Some(colon) = find_byte(line, b':') {
            if eq_ia(trim(&line[..colon]), key) {
                return Some(trim(&line[colon + 1..]));
            }
        }
    }
    None
}

/// True when any header's value for `key` contains `needle`, case-insensitively.
pub fn header_contains(head: &[u8], key: &[u8], needle: &[u8]) -> bool {
    match find_header(head, key) {
        Some(v) => contains_ia(v, needle),
        None => false,
    }
}

fn contains_ia(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    for i in 0..=hay.len() - needle.len() {
        if eq_ia(&hay[i..i + needle.len()], needle) {
            return true;
        }
    }
    false
}

// ---- SSDP ----

/// The v1 search targets plus `ssdp:all`, which is answered with the root-device advertisement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SearchTarget {
    RootDevice,
    InternetGatewayDevice,
    InternetGatewayDevice2,
    WanDevice,
    WanConnectionDevice,
    WanIpConnection,
    WanIpConnection2,
    WanPppConnection,
    WanPppConnection2,
    All,
}

pub const ST_NAMES: &[(&[u8], SearchTarget)] = &[
    (b"upnp:rootdevice", SearchTarget::RootDevice),
    (
        b"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        SearchTarget::InternetGatewayDevice,
    ),
    (
        b"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        SearchTarget::InternetGatewayDevice2,
    ),
    (
        b"urn:schemas-upnp-org:device:WANDevice:1",
        SearchTarget::WanDevice,
    ),
    (
        b"urn:schemas-upnp-org:device:WANConnectionDevice:1",
        SearchTarget::WanConnectionDevice,
    ),
    (
        b"urn:schemas-upnp-org:service:WANIPConnection:1",
        SearchTarget::WanIpConnection,
    ),
    (
        b"urn:schemas-upnp-org:service:WANIPConnection:2",
        SearchTarget::WanIpConnection2,
    ),
    (
        b"urn:schemas-upnp-org:service:WANPPPConnection:1",
        SearchTarget::WanPppConnection,
    ),
    (
        b"urn:schemas-upnp-org:service:WANPPPConnection:2",
        SearchTarget::WanPppConnection2,
    ),
    (b"ssdp:all", SearchTarget::All),
];

pub fn parse_st(bytes: &[u8]) -> Option<SearchTarget> {
    let v = strip_quotes(trim(bytes));
    for (lit, t) in ST_NAMES {
        if eq_ia(lit, v) {
            return Some(*t);
        }
    }
    None
}

/// The ST token to echo for a request's target; `ssdp:all` echoes `upnp:rootdevice`.
pub fn st_name(st: SearchTarget) -> &'static [u8] {
    match st {
        SearchTarget::RootDevice | SearchTarget::All => b"upnp:rootdevice",
        SearchTarget::InternetGatewayDevice => {
            b"urn:schemas-upnp-org:device:InternetGatewayDevice:1"
        }
        SearchTarget::InternetGatewayDevice2 => {
            b"urn:schemas-upnp-org:device:InternetGatewayDevice:2"
        }
        SearchTarget::WanDevice => b"urn:schemas-upnp-org:device:WANDevice:1",
        SearchTarget::WanConnectionDevice => {
            b"urn:schemas-upnp-org:device:WANConnectionDevice:1"
        }
        SearchTarget::WanIpConnection => b"urn:schemas-upnp-org:service:WANIPConnection:1",
        SearchTarget::WanIpConnection2 => b"urn:schemas-upnp-org:service:WANIPConnection:2",
        SearchTarget::WanPppConnection => b"urn:schemas-upnp-org:service:WANPPPConnection:1",
        SearchTarget::WanPppConnection2 => b"urn:schemas-upnp-org:service:WANPPPConnection:2",
    }
}

/// M-SEARCH parse outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MSearchParse {
    /// A target we answer after a random delay within MX (capped at 5 s).
    Answer { st: SearchTarget, mx: u8 },
    /// A well-formed discovery for a target we do not provide.
    Ignore,
    /// Not a well-formed M-SEARCH (no answer, no error).
    Malformed,
}

/// Parse an M-SEARCH datagram: MAN/MX/ST headers, CRLF or bare LF, MX capped at 5.
pub fn parse_msearch(buf: &[u8]) -> MSearchParse {
    let n = buf.len();
    let mut i = 0usize;
    let mut first_line = true;
    let mut man_ok = false;
    let mut mx: u8 = 0;
    let mut st: Option<SearchTarget> = None;
    while i < n {
        let mut j = i;
        while j < n && buf[j] != b'\n' {
            j += 1;
        }
        let mut line = &buf[i..j];
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        i = j + 1;
        let t = trim(line);
        if t.is_empty() {
            continue;
        }
        if first_line {
            if !starts_with_ia(t, b"M-SEARCH") {
                return MSearchParse::Malformed;
            }
            first_line = false;
            continue;
        }
        let Some(colon) = find_byte(t, b':') else {
            continue;
        };
        let key = trim(&t[..colon]);
        let val = trim(&t[colon + 1..]);
        if eq_ia(key, b"MAN") {
            man_ok = contains_ia(val, b"ssdp:discover");
        } else if eq_ia(key, b"MX") {
            mx = parse_u8(val).min(5);
        } else if eq_ia(key, b"ST") {
            st = parse_st(val);
        }
    }
    if first_line {
        return MSearchParse::Malformed;
    }
    if !man_ok {
        return MSearchParse::Malformed;
    }
    match st {
        Some(t) => MSearchParse::Answer { st: t, mx },
        None => MSearchParse::Ignore,
    }
}

fn parse_u8(s: &[u8]) -> u8 {
    let mut v: u16 = 0;
    for c in s {
        if !c.is_ascii_digit() {
            break;
        }
        v = v * 10 + u16::from(*c - b'0');
        if v > 255 {
            break;
        }
    }
    v.min(255) as u8
}

/// The UDN suffix of a location path: "uuid:" + 36 hex-with-dash bytes.
pub const UDN_LEN: usize = 41; // "uuid:" (5) + 36

/// Render 16 bytes as the 36-byte dashed UUID hex form, version/variant nibbles as given.
pub(crate) fn uuid_hex(b: &[u8; 16]) -> [u8; 36] {
    let hex = b"0123456789abcdef";
    let mut out = [0u8; 36];
    const DASH: [usize; 4] = [8, 13, 18, 23];
    // position maps: uuid char positions -> byte index pairs
    let mut src = 0usize;
    let mut di = 0usize;
    for o in 0..36 {
        if di < 4 && o == DASH[di] {
            out[o] = b'-';
            di += 1;
            continue;
        }
        let b = b[src / 2];
        let hi = if src % 2 == 0 { b >> 4 } else { b & 0x0f };
        out[o] = hex[hi as usize];
        src += 1;
    }
    out
}

/// Parse a SID in wire form: an optional `uuid:` prefix, then 36 dashed or 32 raw hex bytes.
pub fn sid_from_bytes(b: &[u8]) -> Option<Sid> {
    let core = strip_quotes(trim(b));
    let core = match core.strip_prefix(b"uuid:") {
        Some(c) => c,
        None => core,
    };
    // 36-with-dashes or 32-raw
    let mut nib = [0u8; 32];
    let bytes: &[u8] = if core.len() == 36 {
        let mut k = 0usize;
        for c in core {
            if *c == b'-' {
                continue;
            }
            if k >= 32 {
                return None;
            }
            let v = hex_val(*c)?;
            nib[k] = v;
            k += 1;
        }
        if k != 32 {
            return None;
        }
        &nib
    } else if core.len() == 32 {
        for (i, c) in core.iter().enumerate() {
            nib[i] = hex_val(*c)?;
        }
        &nib
    } else {
        return None;
    };
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = (bytes[2 * i] << 4) | bytes[2 * i + 1];
    }
    Some(Sid(out))
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---- GENA ----

/// A subscription ID: 16 random-byte UUID. Copy; equality is bytewise.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Sid(pub [u8; 16]);

impl Sid {
    /// UUIDv4 from 16 caller bytes: the version nibble 4 and the variant bits 0b10.
    pub fn v4(b: &[u8; 16]) -> Sid {
        let mut o = *b;
        o[6] = (o[6] & 0x0f) | 0x40;
        o[8] = (o[8] & 0x3f) | 0x80;
        Sid(o)
    }

    pub fn from_bytes(b: &[u8]) -> Option<Sid> {
        sid_from_bytes(b)
    }

    pub fn wire(&self) -> [u8; UDN_LEN] {
        let mut out = [0u8; UDN_LEN];
        out[..5].copy_from_slice(b"uuid:");
        let h = uuid_hex(&self.0);
        out[5..].copy_from_slice(&h);
        out
    }
}

/// The eventKey advance: starts at 0 with the initial NOTIFY and wraps at 2^32.
pub fn advance_seq(seq: u32) -> u32 {
    seq.wrapping_add(1)
}

/// The bounded set of live subscription SIDs the SID-discipline proofs run over.
#[derive(Clone, Copy, Debug)]
pub struct SidSet {
    sids: [Option<Sid>; MAX_GENA_SUBS],
    n: usize,
}

impl SidSet {
    pub fn new() -> Self {
        SidSet {
            sids: [None; MAX_GENA_SUBS],
            n: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_full(&self) -> bool {
        self.len() >= MAX_GENA_SUBS
    }

    pub fn has(&self, s: Sid) -> bool {
        for i in 0..self.n {
            if self.sids[i] == Some(s) {
                return true;
            }
        }
        false
    }

    /// Insert; false when full or already present. Never duplicates.
    pub fn add(&mut self, s: Sid) -> bool {
        if self.has(s) || self.is_full() {
            return false;
        }
        self.sids[self.n] = Some(s);
        self.n += 1;
        true
    }

    /// Remove; false when absent.
    pub fn remove(&mut self, s: Sid) -> bool {
        for i in 0..self.n {
            if self.sids[i] == Some(s) {
                self.sids.swap(i, self.n - 1);
                self.sids[self.n - 1] = None;
                self.n -= 1;
                return true;
            }
        }
        false
    }
}

impl Default for SidSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---- SOAP ----

/// The four services answered: the two WAN connection services, WANCommonInterfaceConfig:1 and DeviceProtection:1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SoapService {
    WanIpConnection,
    WanPppConnection,
    WanCommonIfaceCfg,
    DeviceProtection,
}

/// The v1 service URN; `service_urn_v` follows the invocation's own version attribution.
#[allow(dead_code)] // the v1 envelope builder, exercised by the test suite
pub fn service_urn(s: SoapService) -> &'static [u8] {
    service_urn_v(s, false)
}

/// The response envelope's service URN: a `:2` SOAPACTION is answered in the WANIPConnection:2 URN.
pub fn service_urn_v(s: SoapService, v2: bool) -> &'static [u8] {
    match s {
        SoapService::WanIpConnection if v2 => b"urn:schemas-upnp-org:service:WANIPConnection:2",
        SoapService::WanIpConnection => b"urn:schemas-upnp-org:service:WANIPConnection:1",
        SoapService::WanPppConnection => b"urn:schemas-upnp-org:service:WANPPPConnection:1",
        SoapService::WanCommonIfaceCfg => {
            b"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"
        }
        SoapService::DeviceProtection => b"urn:schemas-upnp-org:service:DeviceProtection:1",
    }
}

pub const CTL_IPCONN: &[u8] = b"/ctl/IPConn";
pub const CTL_PPPCONN: &[u8] = b"/ctl/PPPConn";
pub const CTL_CMNIFCFG: &[u8] = b"/ctl/CmnIfCfg";
pub const CTL_DP: &[u8] = b"/ctl/DP";

pub fn service_of_path(path: &[u8]) -> Option<SoapService> {
    if eq_ia(path, CTL_IPCONN) {
        return Some(SoapService::WanIpConnection);
    }
    if eq_ia(path, CTL_PPPCONN) {
        return Some(SoapService::WanPppConnection);
    }
    if eq_ia(path, CTL_CMNIFCFG) {
        return Some(SoapService::WanCommonIfaceCfg);
    }
    if eq_ia(path, CTL_DP) {
        return Some(SoapService::DeviceProtection);
    }
    None
}

/// The actions honoured: the WANIPConnection set, the v2-only range actions and DeviceProtection's thirteen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SoapAction {
    GetExternalIpAddress,
    GetStatusInfo,
    GetConnectionTypeInfo,
    // the connection control actions and the RSIP/NAT report, before the v2-only and DP variants
    SetConnectionType,
    RequestConnection,
    ForceTermination,
    GetNatRsipStatus,
    AddPortMapping,
    DeletePortMapping,
    GetSpecificPortMappingEntry,
    GetGenericPortMappingEntry,
    GetCommonLinkProperties,
    // WANIPConnection:2-only actions
    AddAnyPortMapping,
    DeletePortMappingRange,
    GetListOfPortMappings,
    // DeviceProtection:1's thirteen actions (the authoritative set)
    SendSetupMessage,
    GetSupportedProtocols,
    GetAssignedRoles,
    GetRolesForAction,
    GetUserLoginChallenge,
    UserLogin,
    UserLogout,
    GetAclData,
    AddIdentityList,
    RemoveIdentity,
    SetUserLoginPassword,
    AddRolesForIdentity,
    RemoveRolesForIdentity,
}

pub fn soap_action_name(a: SoapAction) -> &'static [u8] {
    match a {
        SoapAction::GetExternalIpAddress => b"GetExternalIPAddress",
        SoapAction::GetStatusInfo => b"GetStatusInfo",
        SoapAction::GetConnectionTypeInfo => b"GetConnectionTypeInfo",
        SoapAction::SetConnectionType => b"SetConnectionType",
        SoapAction::RequestConnection => b"RequestConnection",
        SoapAction::ForceTermination => b"ForceTermination",
        SoapAction::GetNatRsipStatus => b"GetNATRSIPStatus",
        SoapAction::AddPortMapping => b"AddPortMapping",
        SoapAction::DeletePortMapping => b"DeletePortMapping",
        SoapAction::GetSpecificPortMappingEntry => b"GetSpecificPortMappingEntry",
        SoapAction::GetGenericPortMappingEntry => b"GetGenericPortMappingEntry",
        SoapAction::GetCommonLinkProperties => b"GetCommonLinkProperties",
        SoapAction::AddAnyPortMapping => b"AddAnyPortMapping",
        SoapAction::DeletePortMappingRange => b"DeletePortMappingRange",
        SoapAction::GetListOfPortMappings => b"GetListOfPortMappings",
        SoapAction::SendSetupMessage => b"SendSetupMessage",
        SoapAction::GetSupportedProtocols => b"GetSupportedProtocols",
        SoapAction::GetAssignedRoles => b"GetAssignedRoles",
        SoapAction::GetRolesForAction => b"GetRolesForAction",
        SoapAction::GetUserLoginChallenge => b"GetUserLoginChallenge",
        SoapAction::UserLogin => b"UserLogin",
        SoapAction::UserLogout => b"UserLogout",
        SoapAction::GetAclData => b"GetACLData",
        SoapAction::AddIdentityList => b"AddIdentityList",
        SoapAction::RemoveIdentity => b"RemoveIdentity",
        SoapAction::SetUserLoginPassword => b"SetUserLoginPassword",
        SoapAction::AddRolesForIdentity => b"AddRolesForIdentity",
        SoapAction::RemoveRolesForIdentity => b"RemoveRolesForIdentity",
    }
}

/// The action name after the final `#` of a SOAPACTION value, unquoted; names are case-sensitive.
pub fn parse_soap_action(hdr: &[u8]) -> Option<SoapAction> {
    let v = strip_quotes(trim(hdr));
    let mut hash: Option<usize> = None;
    for i in (0..v.len()).rev() {
        if v[i] == b'#' {
            hash = Some(i);
            break;
        }
    }
    let name = match hash {
        Some(h) => &v[h + 1..],
        None => v,
    };
    for a in [
        SoapAction::GetExternalIpAddress,
        SoapAction::GetStatusInfo,
        SoapAction::GetConnectionTypeInfo,
        SoapAction::SetConnectionType,
        SoapAction::RequestConnection,
        SoapAction::ForceTermination,
        SoapAction::GetNatRsipStatus,
        SoapAction::AddPortMapping,
        SoapAction::DeletePortMapping,
        SoapAction::GetSpecificPortMappingEntry,
        SoapAction::GetGenericPortMappingEntry,
        SoapAction::GetCommonLinkProperties,
        SoapAction::AddAnyPortMapping,
        SoapAction::DeletePortMappingRange,
        SoapAction::GetListOfPortMappings,
        SoapAction::SendSetupMessage,
        SoapAction::GetSupportedProtocols,
        SoapAction::GetAssignedRoles,
        SoapAction::GetRolesForAction,
        SoapAction::GetUserLoginChallenge,
        SoapAction::UserLogin,
        SoapAction::UserLogout,
        SoapAction::GetAclData,
        SoapAction::AddIdentityList,
        SoapAction::RemoveIdentity,
        SoapAction::SetUserLoginPassword,
        SoapAction::AddRolesForIdentity,
        SoapAction::RemoveRolesForIdentity,
    ] {
        if eq_ia(soap_action_name(a), name) {
            return Some(a);
        }
    }
    None
}

/// True when the SOAPACTION's service URN is WANIPConnection:2 (the control URLs are shared, the URN decides).
pub fn soapaction_is_v2(v: &[u8]) -> bool {
    let v = strip_quotes(trim(v));
    let mut hash: Option<usize> = None;
    for i in (0..v.len()).rev() {
        if v[i] == b'#' {
            hash = Some(i);
            break;
        }
    }
    let (urn, _) = match hash {
        Some(h) => (&v[..h], &v[h + 1..]),
        None => return false,
    };
    eq_ia(urn, b"urn:schemas-upnp-org:service:WANIPConnection:2")
}

/// The `ns=NN` token of an M-POST MAN header naming our envelope namespace; only the URL is quoted.
pub fn mpost_ns(head: &[u8]) -> Option<&[u8]> {
    let raw = find_header(head, b"MAN")?;
    let mut v = trim(raw);
    if v.first() == Some(&b'"') {
        v = &v[1..];
    }
    if !starts_with_ia(v, SOAP_NS) {
        return None;
    }
    let rest = &v[SOAP_NS.len()..];
    // `;ns=01` (whitespace tolerated; further params after `;` allowed)
    let mut i = 0usize;
    while i < rest.len() && rest[i] != b';' {
        i += 1;
    }
    let params = &rest[i..];
    let mut p = 0usize;
    while p < params.len() {
        let mut q = p;
        while q < params.len() && params[q] != b';' {
            q += 1;
        }
        let part = trim(&params[p..q]);
        p = q + 1;
        if let Some(eq) = find_byte(part, b'=') {
            let k = trim(&part[..eq]);
            if eq_ia(k, b"ns") {
                let v2 = trim(&part[eq + 1..]);
                if !v2.is_empty() && v2.len() <= 4 {
                    return Some(v2);
                }
                return None;
            }
        }
    }
    None
}

/// Locate the `<ns>SOAPACTION` header of an M-POST (ns is 1-4 bytes).
pub fn find_ns_soapaction<'a>(head: &'a [u8], ns: &[u8]) -> Option<&'a [u8]> {
    if ns.is_empty() || ns.len() > 4 {
        return None;
    }
    let mut key = [0u8; 15];
    key[..ns.len()].copy_from_slice(ns);
    let suf = b"-SOAPACTION";
    let start = ns.len();
    key[start..start + suf.len()].copy_from_slice(suf);
    find_header(head, &key[..start + suf.len()])
}

/// Request-head classification: the pure dispatch decision over the request line and headers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReqClass {
    /// A description-document GET.
    Get,
    /// A SOAP invocation; `v2` is the version attribution read from the SOAPACTION URN.
    Soap {
        service: SoapService,
        action: SoapAction,
        v2: bool,
    },
    /// GENA control messages.
    GenaSubscribe,
    GenaRenew,
    GenaUnsubscribe,
    /// A SOAP-shaped request whose action could not be resolved: 401.
    SoapInvalidAction,
    /// Anything else: 404.
    NotFound,
}

/// Classify a request head; equivalent POST and M-POST requests classify identically.
pub fn classify(head: &[u8]) -> ReqClass {
    let n = head.len();
    let mut i = 0usize;
    while i < n && head[i] != b'\n' {
        i += 1;
    }
    let mut line = &head[..i.min(n)];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    let sp1 = match find_byte(line, b' ') {
        Some(p) => p,
        None => return ReqClass::NotFound,
    };
    let method = trim(&line[..sp1]);
    let rest = trim(&line[sp1 + 1..]);
    let path = match find_byte(rest, b' ') {
        Some(p) => &rest[..p],
        None => rest,
    };

    if eq_ia(method, b"GET") {
        if eq_ia(path, b"/") || eq_ia(path, b"/rootDesc.xml")
            || eq_ia(path, b"/WANIPC.xml") || eq_ia(path, b"/WANPPP.xml")
            || eq_ia(path, b"/WANCfg.xml")
            // the versioned v1/v2 prefixes are recognized even while the mount gate is off; a gated path 404s
            || starts_with_ia(path, b"/igd/v1/")
            || starts_with_ia(path, b"/igd/v2/")
        {
            return ReqClass::Get;
        }
        return ReqClass::NotFound;
    }
    if eq_ia(method, b"SUBSCRIBE") {
        // GENA subscribe (NT/CALLBACK) and renewal (SID).
        if header_contains(head, b"NT", b"upnp:event")
            && find_header(head, b"CALLBACK").is_some()
        {
            return ReqClass::GenaSubscribe;
        }
        if find_header(head, b"SID").is_some() {
            return ReqClass::GenaRenew;
        }
        return ReqClass::NotFound;
    }
    if eq_ia(method, b"UNSUBSCRIBE") {
        if find_header(head, b"SID").is_some() {
            return ReqClass::GenaUnsubscribe;
        }
        return ReqClass::NotFound;
    }
    let is_post = eq_ia(method, b"POST");
    let is_mpost = eq_ia(method, b"M-POST");
    if !is_post && !is_mpost {
        return ReqClass::NotFound;
    }
    // the GENA markers run on POST and M-POST alike, so both transports dispatch the same way
    if header_contains(head, b"NT", b"upnp:event") && find_header(head, b"CALLBACK").is_some() {
        return ReqClass::GenaSubscribe;
    }
    if find_header(head, b"SID").is_some() {
        return ReqClass::GenaRenew;
    }
    let soapaction = if is_post {
        find_header(head, b"SOAPACTION")
    } else {
        // M-POST: the MAN namespace selects the service and the action comes from <ns>SOAPACTION
        let Some(ns) = mpost_ns(head) else {
            return ReqClass::SoapInvalidAction;
        };
        find_ns_soapaction(head, ns)
    };
    let Some(soapaction) = soapaction else {
        return ReqClass::SoapInvalidAction;
    };
    let Some(action) = parse_soap_action(soapaction) else {
        return ReqClass::SoapInvalidAction;
    };
    // the version attribution comes from the same SOAPACTION value in both transports, keeping parity
    let v2 = soapaction_is_v2(soapaction);
    match service_of_path(path) {
        Some(service) => ReqClass::Soap { service, action, v2 },
        None => ReqClass::SoapInvalidAction,
    }
}

// ---- faults ----

/// The error outcomes a handler returns; `fault_of` maps them to the SOAP fault table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpnpErr {
    /// 401 Invalid Action (action not honoured on the addressed service).
    InvalidAction,
    /// 402 Invalid Args.
    InvalidArgs,
    /// 714 NoSuchEntryInArray (delete/specific past end).
    NoSuchEntry,
    /// 501 Action Failed (quota, table full, datapath failure).
    ActionFailed,
    /// 730 PortMappingNotFound: WANIPConnection:2's code for a range action that found nothing.
    PortMappingNotFound,
    /// 733 InconsistentParameters: the range endpoints disagree (a start above the end).
    InconsistentParameters,
    /// 731 ReadOnly: the connection type is auto-configured, so SetConnectionType cannot set it.
    ReadOnly,
    /// 704 ConnectionSetupFailed; the code is shared with DeviceProtection's Processing Error.
    ConnectionSetupFailed,
    /// 600 Argument Value Invalid (DeviceProtection).
    InvalidValue,
    /// 606 Action not authorized: DeviceProtection's own code for an action the roles refuse.
    NotAuthorized,
    /// 701 Authentication Failure (DeviceProtection).
    AuthFailure,
    /// 704 Processing Error (DeviceProtection).
    Processing,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UpnpFault {
    pub code: u16,
    pub desc: &'static str,
}

pub const FAULT_INVALID_ACTION: UpnpFault = UpnpFault {
    code: 401,
    desc: "Invalid Action",
};
pub const FAULT_INVALID_ARGS: UpnpFault = UpnpFault {
    code: 402,
    desc: "Invalid Args",
};
pub const FAULT_ACTION_FAILED: UpnpFault = UpnpFault {
    code: 501,
    desc: "Action Failed",
};
pub const FAULT_NO_SUCH_ENTRY: UpnpFault = UpnpFault {
    code: 714,
    desc: "NoSuchEntryInArray",
};
pub const FAULT_PORT_MAPPING_NOT_FOUND: UpnpFault = UpnpFault {
    code: 730,
    desc: "PortMappingNotFound",
};
pub const FAULT_INCONSISTENT_PARAMETERS: UpnpFault = UpnpFault {
    code: 733,
    desc: "InconsistentParameters",
};
pub const FAULT_READ_ONLY: UpnpFault = UpnpFault {
    code: 731,
    desc: "ReadOnly",
};
pub const FAULT_CONNECTION_SETUP_FAILED: UpnpFault = UpnpFault {
    code: 704,
    desc: "ConnectionSetupFailed",
};
pub const FAULT_INVALID_VALUE: UpnpFault = UpnpFault {
    code: 600,
    desc: "Argument Value Invalid",
};
pub const FAULT_NOT_AUTHORIZED: UpnpFault = UpnpFault {
    code: 606,
    desc: "Action not authorized",
};
pub const FAULT_AUTH_FAILURE: UpnpFault = UpnpFault {
    code: 701,
    desc: "Authentication Failure",
};
pub const FAULT_PROCESSING: UpnpFault = UpnpFault {
    code: 704,
    desc: "Processing Error",
};
pub fn fault_of(e: UpnpErr) -> UpnpFault {
    match e {
        UpnpErr::InvalidAction => FAULT_INVALID_ACTION,
        UpnpErr::InvalidArgs => FAULT_INVALID_ARGS,
        UpnpErr::NoSuchEntry => FAULT_NO_SUCH_ENTRY,
        UpnpErr::ActionFailed => FAULT_ACTION_FAILED,
        UpnpErr::PortMappingNotFound => FAULT_PORT_MAPPING_NOT_FOUND,
        UpnpErr::InconsistentParameters => FAULT_INCONSISTENT_PARAMETERS,
        UpnpErr::ReadOnly => FAULT_READ_ONLY,
        UpnpErr::ConnectionSetupFailed => FAULT_CONNECTION_SETUP_FAILED,
        UpnpErr::InvalidValue => FAULT_INVALID_VALUE,
        UpnpErr::NotAuthorized => FAULT_NOT_AUTHORIZED,
        UpnpErr::AuthFailure => FAULT_AUTH_FAILURE,
        UpnpErr::Processing => FAULT_PROCESSING,
    }
}

// ---- enumeration ----

/// One granted mapping as a control point sees it, keyed by the requested port (the AFTR dictates the real tuple).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UpnpKey {
    pub req_ext: u16,
    pub proto: Proto,
    pub client: Ipv4Addr,
    pub int_port: u16,
}

/// Index into a stable sorted enumeration: Some exactly when the index is below the length.
pub fn entry_at(entries: &[UpnpKey], index: u32) -> Option<UpnpKey> {
    let i = index as usize;
    if i < entries.len() {
        Some(entries[i])
    } else {
        None
    }
}

// ---- XML arg extraction (runtime; unit-tested, Kani non-goal) ----

/// First index of `needle` in `hay`, or None; the marker search for `-->` / `]]>`.
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The text of the first element named exactly `tag`; comments, CDATA or nesting inside the value fail closed.
pub fn xml_tag<'a>(body: &'a [u8], tag: &[u8]) -> Option<&'a [u8]> {
    let n = body.len();
    let mut i = 0usize;
    while i < n {
        if body[i] != b'<' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < n && body[j] != b'>' && body[j] != b'<' {
            j += 1;
        }
        if j >= n || body[j] != b'>' {
            return None;
        }
        let name = &body[i + 1..j];
        if eq_ia(name, tag) {
            return find_close(&body[j + 1..], tag);
        }
        i = j + 1;
    }
    None
}

/// The value text before the `</tag>` closer, skipping comment and CDATA spans.
fn find_close<'a>(rest: &'a [u8], tag: &[u8]) -> Option<&'a [u8]> {
    let n = rest.len();
    let cl = 2 + tag.len() + 1; // `</tag>`
    if cl > n {
        return None;
    }
    let mut i = 0usize;
    while i <= n - cl {
        // a comment or CDATA mentioning `</tag>` is not a closer
        if rest[i..].starts_with(b"<!--") {
            i = find_sub(&rest[i + 4..], b"-->")
                .map(|e| i + 4 + e + 3)
                .unwrap_or(n);
            continue;
        }
        if rest[i..].starts_with(b"<![CDATA[") {
            i = find_sub(&rest[i + 9..], b"]]>")
                .map(|e| i + 9 + e + 3)
                .unwrap_or(n);
            continue;
        }
        if rest[i] == b'<'
            && rest[i + 1] == b'/'
            && eq_ia(&rest[i + 2..i + 2 + tag.len()], tag)
            && rest[i + 2 + tag.len()] == b'>'
        {
            return Some(unwrap_value(&rest[..i]));
        }
        i += 1;
    }
    None
}

/// Index of the LAST occurrence of `needle` in `hay`, or None.
fn rfind_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// Trim whitespace and a whole-value CDATA wrapper; a partial CDATA span stays whole so the parse rejects it.
fn unwrap_value(mut v: &[u8]) -> &[u8] {
    loop {
        v = trim(v);
        if v.starts_with(b"<![CDATA[") {
            let Some(e) = find_sub(v, b"]]>") else {
                break; // unterminated: leave for the parse to reject
            };
            if e + 3 != v.len() {
                break; // trailing text outside the span: fail closed
            }
            v = &v[9..e];
            continue;
        }
        // a trailing comment is not text
        if v.ends_with(b"-->") {
            let Some(open) = rfind_sub(v, b"<!--") else {
                break;
            };
            v = &v[..open];
            continue;
        }
        // a leading comment is not text
        if v.starts_with(b"<!--") {
            let Some(e) = find_sub(v, b"-->") else {
                break; // unterminated: leave for the parse to reject
            };
            v = &v[e + 3..];
            continue;
        }
        break;
    }
    v
}

// ---- response builders (heap; unit-tested) ----

/// RFC-7231 HTTP date from unix seconds (Hinnant's civil calendar; GMT).
pub fn http_date(unix: u64) -> String {
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (unix / 86400) as i64;
    let secs = unix % 86400;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y0 = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y0 + 1 } else { y0 };
    let wd = (days + 4).rem_euclid(7);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        WD[wd as usize],
        d,
        MON[(m - 1) as usize],
        y,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// One SSDP M-SEARCH response, unicast to the requester, with the given description path.
pub fn msearch_response(
    st: SearchTarget,
    udn: &str,
    lan_ip: Ipv4Addr,
    port: u16,
    now_unix: u64,
    loc_path: &str,
) -> Vec<u8> {
    let st_bytes = st_name(st);
    let st_text = String::from_utf8_lossy(st_bytes);
    let mut out = String::with_capacity(256);
    out.push_str("HTTP/1.1 200 OK\r\n");
    out.push_str(&format!("CACHE-CONTROL: max-age={}\r\n", SSDP_MAX_AGE));
    out.push_str(&format!("DATE: {}\r\n", http_date(now_unix)));
    out.push_str("EXT:\r\n");
    out.push_str(&format!("LOCATION: http://{}:{}{}\r\n", lan_ip, port, loc_path));
    out.push_str(&format!("SERVER: {}\r\n", SERVER_LINE));
    out.push_str(&format!("ST: {}\r\n", st_text));
    out.push_str(&format!("USN: uuid:{}::{}\r\n", udn, st_text));
    out.push_str("Content-Length: 0\r\n\r\n");
    out.into_bytes()
}

/// One SSDP NOTIFY advertisement (alive or byebye), multicast.
pub fn notify_payload(
    st: SearchTarget,
    nts: &[u8],
    udn: &str,
    lan_ip: Ipv4Addr,
    port: u16,
    now_unix: u64,
    loc_path: &str,
) -> Vec<u8> {
    let st_bytes = st_name(st);
    let st_text = String::from_utf8_lossy(st_bytes);
    let nts_text = String::from_utf8_lossy(nts);
    let mut out = String::with_capacity(256);
    out.push_str("NOTIFY * HTTP/1.1\r\n");
    out.push_str(&format!("HOST: {}:{}\r\n", SSDP_MCAST, SSDP_PORT));
    out.push_str(&format!("CACHE-CONTROL: max-age={}\r\n", SSDP_MAX_AGE));
    out.push_str(&format!("DATE: {}\r\n", http_date(now_unix)));
    out.push_str(&format!("LOCATION: http://{}:{}{}\r\n", lan_ip, port, loc_path));
    out.push_str(&format!("SERVER: {}\r\n", SERVER_LINE));
    out.push_str(&format!("NT: {}\r\n", st_text));
    out.push_str(&format!("NTS: ssdp:{}\r\n", nts_text));
    out.push_str(&format!("USN: uuid:{}::{}\r\n", udn, st_text));
    out.push_str("Content-Length: 0\r\n\r\n");
    out.into_bytes()
}

/// A 200 OK SOAP envelope carrying the action's response element, in the service's own namespace.
#[allow(dead_code)] // the v1 envelope builder, exercised by the test suite
pub fn soap_success(service: SoapService, action: &str, inner: &str) -> Vec<u8> {
    soap_success_v(service, false, action, inner)
}

/// [`soap_success`] honouring the invocation's version: a v2 invocation is answered from the `:2` namespace.
pub fn soap_success_v(service: SoapService, v2: bool, action: &str, inner: &str) -> Vec<u8> {
    let urn = String::from_utf8_lossy(service_urn_v(service, v2));
    format!(
        "<?xml version=\"1.0\"?>\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{}Response xmlns:u=\"{}\">{}</u:{}Response>\
         </s:Body></s:Envelope>\n",
        action, urn, inner, action
    )
    .into_bytes()
}

/// A SOAP Fault envelope for `f`.
pub fn soap_fault(f: &UpnpFault) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?>\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>\
         <detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
         <errorCode>{}</errorCode><errorDescription>{}</errorDescription>\
         </UPnPError></detail></s:Fault></s:Body></s:Envelope>\n",
        f.code, f.desc
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn st_parse_roundtrip() {
        assert_eq!(parse_st(b"upnp:rootdevice"), Some(SearchTarget::RootDevice));
        assert_eq!(
            parse_st(b"urn:schemas-upnp-org:service:WANIPConnection:1"),
            Some(SearchTarget::WanIpConnection)
        );
        assert_eq!(parse_st(b"SSDP:ALL"), Some(SearchTarget::All));
        assert_eq!(parse_st(b"\"upnp:rootdevice\""), Some(SearchTarget::RootDevice));
        assert_eq!(parse_st(b"urn:unknown:1"), None);
    }

    #[test]
    fn st_v2_targets_parse_and_roundtrip() {
        // explicit IGD:2/WIP2 searches must parse and echo their version
        assert_eq!(
            parse_st(b"urn:schemas-upnp-org:device:InternetGatewayDevice:2"),
            Some(SearchTarget::InternetGatewayDevice2)
        );
        assert_eq!(
            parse_st(b"urn:schemas-upnp-org:service:WANIPConnection:2"),
            Some(SearchTarget::WanIpConnection2)
        );
        assert_eq!(
            parse_st(b"urn:schemas-upnp-org:service:WANPPPConnection:2"),
            Some(SearchTarget::WanPppConnection2)
        );
        assert_eq!(
            parse_st(st_name(SearchTarget::InternetGatewayDevice2)),
            Some(SearchTarget::InternetGatewayDevice2)
        );
        assert_eq!(
            parse_st(st_name(SearchTarget::WanIpConnection2)),
            Some(SearchTarget::WanIpConnection2)
        );
    }

    #[test]
    fn msearch_grammar() {
        let req = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: upnp:rootdevice\r\n\r\n";
        assert_eq!(
            parse_msearch(req),
            MSearchParse::Answer {
                st: SearchTarget::RootDevice,
                mx: 3
            }
        );
        // unknown ST -> Ignore
        let unknown = b"M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\r\nMX: 1\r\n";
        assert_eq!(parse_msearch(unknown), MSearchParse::Ignore);
        // MX capped at 5
        let big = b"M-SEARCH * HTTP/1.1\nMAN: \"ssdp:discover\"\nST: ssdp:all\nMX: 30\n";
        assert_eq!(
            parse_msearch(big),
            MSearchParse::Answer {
                st: SearchTarget::All,
                mx: 5
            }
        );
        // missing MAN -> Malformed
        assert_eq!(
            parse_msearch(b"NOTIFY * HTTP/1.1\r\nST: upnp:rootdevice\r\n"),
            MSearchParse::Malformed
        );
        assert_eq!(parse_msearch(b"junk"), MSearchParse::Malformed);
        assert_eq!(parse_msearch(b""), MSearchParse::Malformed);
        // bare-LF tolerance + no MX -> 0
        assert_eq!(
            parse_msearch(b"M-SEARCH * HTTP/1.1\nMAN: \"ssdp:discover\"\nST: upnp:rootdevice\n"),
            MSearchParse::Answer {
                st: SearchTarget::RootDevice,
                mx: 0
            }
        );
    }

    #[test]
    fn header_lookup() {
        let head = b"GET /rootDesc.xml HTTP/1.1\r\nHost: 192.168.21.1:49152\r\n\r\n";
        assert_eq!(find_header(head, b"host"), Some(&b"192.168.21.1:49152"[..]));
        assert_eq!(find_header(head, b"Host"), Some(&b"192.168.21.1:49152"[..]));
        assert_eq!(find_header(head, b"missing"), None);
    }

    #[test]
    fn soap_classify_post() {
        let post = b"POST /ctl/IPConn HTTP/1.1\r\nSOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\nContent-Type: text/xml\r\n\r\n";
        assert_eq!(
            classify(post),
            ReqClass::Soap {
                service: SoapService::WanIpConnection,
                action: SoapAction::AddPortMapping,
                v2: false
            }
        );
        let ppp = b"POST /ctl/PPPConn HTTP/1.1\r\nSOAPACTION: urn:schemas-upnp-org:service:WANPPPConnection:1#GetStatusInfo\r\n\r\n";
        assert_eq!(
            classify(ppp),
            ReqClass::Soap {
                service: SoapService::WanPppConnection,
                action: SoapAction::GetStatusInfo,
                v2: false
            }
        );
        let bad = b"POST /ctl/IPConn HTTP/1.1\r\nSOAPACTION: \"urn:...#Nope\"\r\n\r\n";
        assert_eq!(classify(bad), ReqClass::SoapInvalidAction);
        // the CIF service path dispatches to its own service/action pair
        let cif = b"POST /ctl/CmnIfCfg HTTP/1.1\r\nSOAPACTION: \"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1#GetCommonLinkProperties\"\r\n\r\n";
        assert_eq!(
            classify(cif),
            ReqClass::Soap {
                service: SoapService::WanCommonIfaceCfg,
                action: SoapAction::GetCommonLinkProperties,
                v2: false
            }
        );
    }

    #[test]
    fn soap_classify_mpost_parity() {
        let mpost = b"M-POST /ctl/IPConn HTTP/1.1\r\nMAN: \"http://schemas.xmlsoap.org/soap/envelope/\";ns=01\r\n01-SOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\n\r\n";
        let post = b"POST /ctl/IPConn HTTP/1.1\r\nSOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\n\r\n";
        assert_eq!(classify(mpost), classify(post), "M-POST must dispatch identically");
        assert_eq!(
            classify(mpost),
            ReqClass::Soap {
                service: SoapService::WanIpConnection,
                action: SoapAction::GetExternalIpAddress,
                v2: false
            }
        );
        // foreign MAN -> invalid
        let foreign = b"M-POST /ctl/IPConn HTTP/1.1\r\nMAN: \"http://example.com/soap\";ns=01\r\n01-SOAPACTION: \"urn:x#AddPortMapping\"\r\n\r\n";
        assert_eq!(classify(foreign), ReqClass::SoapInvalidAction);
        // missing MAN -> invalid
        let noman = b"M-POST /ctl/IPConn HTTP/1.1\r\n01-SOAPACTION: \"urn:x#AddPortMapping\"\r\n\r\n";
        assert_eq!(classify(noman), ReqClass::SoapInvalidAction);
    }

    #[test]
    fn mpost_post_parity_multiline_corners() {
        // a quoted action value spanning lines must classify the same on both transports
        let cases: [&[u8]; 4] = [
            b"\nSID: xA",
            b"\nNT: upnp:event\nCALLBACK: c",
            b"\nSID: xA\nCALLBACK: <http://192.168.21.50/evt>",
            b"GetExternalIPAddress",
        ];
        for action in cases {
            let post = format!(
                "POST /ctl/IPConn HTTP/1.1\r\nSOAPACTION: \"{}\"\r\n\r\n",
                String::from_utf8_lossy(action)
            );
            let mpost = format!(
                "M-POST /ctl/IPConn HTTP/1.1\r\nMAN: \
                 \"http://schemas.xmlsoap.org/soap/envelope/\";ns=01\r\n\
                 01-SOAPACTION: \"{}\"\r\n\r\n",
                String::from_utf8_lossy(action)
            );
            assert_eq!(
                classify(post.as_bytes()),
                classify(mpost.as_bytes()),
                "M-POST must dispatch identically for spliced action {:?}",
                action
            );
        }
        // the SID corner resolves to the marker class on BOTH transports
        let post = b"POST /ctl/IPConn HTTP/1.1\r\nSOAPACTION: \"\nSID: xA\"\r\n\r\n";
        let mpost = b"M-POST /ctl/IPConn HTTP/1.1\r\nMAN: \
            \"http://schemas.xmlsoap.org/soap/envelope/\";ns=01\r\n\
            01-SOAPACTION: \"\nSID: xA\"\r\n\r\n";
        assert_eq!(classify(post), ReqClass::GenaRenew);
        assert_eq!(classify(mpost), ReqClass::GenaRenew);
    }

    #[test]
    fn soap_classify_gena() {
        let sub = b"SUBSCRIBE /ctl/IPConn HTTP/1.1\r\nHOST: 192.168.21.1:49152\r\nCALLBACK: <http://192.168.21.50:34567/evt>\r\nNT: upnp:event\r\nTIMEOUT: Second-300\r\n\r\n";
        assert_eq!(classify(sub), ReqClass::GenaSubscribe);
        let renew = b"SUBSCRIBE /ctl/IPConn HTTP/1.1\r\nSID: uuid:0123456789abcdef0123456789abcdef\r\nTIMEOUT: Second-600\r\n\r\n";
        assert_eq!(classify(renew), ReqClass::GenaRenew);
        let unsub = b"UNSUBSCRIBE /ctl/IPConn HTTP/1.1\r\nSID: uuid:0123456789abcdef0123456789abcdef\r\n\r\n";
        assert_eq!(classify(unsub), ReqClass::GenaUnsubscribe);
    }

    #[test]
    fn gena_sid_and_set() {
        let mut s = SidSet::new();
        let a = Sid([1u8; 16]);
        let b = Sid([2u8; 16]);
        assert!(s.add(a));
        assert!(!s.add(a), "duplicate refused");
        assert!(s.add(b));
        assert_eq!(s.len(), 2);
        assert!(s.has(a) && s.has(b));
        assert!(s.remove(a));
        assert!(!s.has(a));
        assert!(!s.remove(a), "absent remove is false");
        // wire roundtrip
        let w = b.wire();
        assert_eq!(w.len(), UDN_LEN);
        assert!(w.starts_with(b"uuid:"));
        let back = Sid::from_bytes(&w).unwrap();
        assert_eq!(back, b);
        // hex without dashes also parses
        let raw = Sid::from_bytes(b"0102030405060708090a0b0c0d0e0f10").unwrap();
        assert_eq!(raw, Sid([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]));
    }

    #[test]
    fn seq_wraps() {
        assert_eq!(advance_seq(0), 1);
        assert_eq!(advance_seq(u32::MAX), 0);
    }

    #[test]
    fn faults_map() {
        assert_eq!(fault_of(UpnpErr::InvalidArgs), FAULT_INVALID_ARGS);
        assert_eq!(fault_of(UpnpErr::NoSuchEntry), FAULT_NO_SUCH_ENTRY);
        assert_eq!(fault_of(UpnpErr::ActionFailed), FAULT_ACTION_FAILED);
        // these two 7xx codes are WANIPConnection:2's own
        assert_eq!(fault_of(UpnpErr::PortMappingNotFound).code, 730);
        assert_eq!(fault_of(UpnpErr::InconsistentParameters).code, 733);
        assert_eq!(fault_of(UpnpErr::ReadOnly).code, 731);
        assert_eq!(fault_of(UpnpErr::ConnectionSetupFailed).code, 704);
        assert_eq!(fault_of(UpnpErr::ConnectionSetupFailed).desc, "ConnectionSetupFailed");
    }

    #[test]
    fn entry_at_bounds() {
        let e = [
            UpnpKey {
                req_ext: 3074,
                proto: Proto::Tcp,
                client: Ipv4Addr::new(192, 168, 21, 138),
                int_port: 3074,
            },
            UpnpKey {
                req_ext: 3074,
                proto: Proto::Udp,
                client: Ipv4Addr::new(192, 168, 21, 138),
                int_port: 3074,
            },
        ];
        assert_eq!(entry_at(&e, 0), Some(e[0]));
        assert_eq!(entry_at(&e, 1), Some(e[1]));
        assert_eq!(entry_at(&e, 2), None);
        assert_eq!(entry_at(&e, u32::MAX), None);
    }

    #[test]
    fn xml_tag_extraction() {
        let body = b"<?xml version=\"1.0\"?><s:Envelope><s:Body><u:AddPortMapping xmlns:u=\"urn:...\"><NewExternalPort>3074</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalClient>192.168.21.138</NewInternalClient></u:AddPortMapping></s:Body></s:Envelope>";
        assert_eq!(xml_tag(body, b"NewExternalPort"), Some(&b"3074"[..]));
        assert_eq!(xml_tag(body, b"NewProtocol"), Some(&b"UDP"[..]));
        assert_eq!(xml_tag(body, b"NewInternalClient"), Some(&b"192.168.21.138"[..]));
        assert_eq!(xml_tag(body, b"NewRemoteHost"), None);
        // whitespace-trimmed value
        let ws = b"<a>\n  42  </a>";
        assert_eq!(xml_tag(ws, b"a"), Some(&b"42"[..]));
    }

    #[test]
    fn xml_tag_skips_comments_and_cdata() {
        // a comment or CDATA span mentioning the closer must not truncate the value
        assert_eq!(
            xml_tag(b"<a>3<!-- </a> remembered -->074</a>", b"a"),
            Some(&b"3<!-- </a> remembered -->074"[..]),
            "value keeps its comment text; the closer search skips the comment span"
        );
        // leading comment between the open tag and the value is not text
        assert_eq!(
            xml_tag(b"<a><!-- c -->3074</a>", b"a"),
            Some(&b"3074"[..])
        );
        // CDATA-wrapped value unwraps to the literal text
        assert_eq!(
            xml_tag(b"<a><![CDATA[3074]]></a>", b"a"),
            Some(&b"3074"[..])
        );
        // a comment at the tail is trimmed like whitespace
        assert_eq!(
            xml_tag(b"<a>3074<!-- tail --></a>", b"a"),
            Some(&b"3074"[..])
        );
        // a CDATA span with text outside it stays whole, so the caller's parse rejects it
        assert_eq!(
            xml_tag(b"<a><![CDATA[30]]>74</a>", b"a"),
            Some(&b"<![CDATA[30]]>74"[..])
        );
    }

    #[test]
    fn http_date_known_values() {
        // 0 = epoch = Thursday, 01 Jan 1970
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_789_257_600), "Sun, 13 Sep 2026 00:00:00 GMT");
    }

    #[test]
    fn response_builders() {
        let r = msearch_response(
            SearchTarget::RootDevice,
            "abcdef",
            Ipv4Addr::new(192, 168, 21, 1),
            49152,
            0,
            "/igd/v1/rootDesc.xml",
        );
        let text = String::from_utf8_lossy(&r);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("LOCATION: http://192.168.21.1:49152/igd/v1/rootDesc.xml\r\n"));
        assert!(text.contains("ST: upnp:rootdevice\r\n"));
        assert!(text.contains("USN: uuid:abcdef::upnp:rootdevice\r\n"));
        assert!(text.contains("CACHE-CONTROL: max-age=1800\r\n"));

        let n = notify_payload(
            SearchTarget::WanIpConnection,
            b"alive",
            "abcdef",
            Ipv4Addr::new(192, 168, 21, 1),
            49152,
            0,
            "/igd/v1/rootDesc.xml",
        );
        let t = String::from_utf8_lossy(&n);
        assert!(t.starts_with("NOTIFY * HTTP/1.1\r\n"));
        assert!(t.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(t.contains("NTS: ssdp:alive\r\n"));
        assert!(t.contains("NT: urn:schemas-upnp-org:service:WANIPConnection:1\r\n"));

        let s = soap_success(SoapService::WanIpConnection, "AddPortMapping", "<NewPortMappingDescription/>");
        let stext = String::from_utf8_lossy(&s);
        assert!(stext.contains("<u:AddPortMappingResponse"));
        assert!(stext.contains("WANIPConnection:1"));

        let sp = soap_success(SoapService::WanPppConnection, "GetStatusInfo", "");
        let spt = String::from_utf8_lossy(&sp);
        assert!(spt.contains("WANPPPConnection:1"));

        let f = soap_fault(&FAULT_INVALID_ARGS);
        let ftext = String::from_utf8_lossy(&f);
        assert!(ftext.contains("<errorCode>402</errorCode>"));
        assert!(ftext.contains("Invalid Args"));
    }
}

/// Kani proofs: the SSDP grammar, SOAP dispatch, enumeration index math and SID/SEQ.
#[cfg(kani)]
mod verify {
    use super::*;

    /// The parity builder's head buffer: the longest prefix plus the longest action name plus the suffix.
    const HDR_CAP: usize = 160;
    const ACT_CAP: usize = 28;

    /// Copy `src` into `dst` at `*offset`, advancing the offset.
    fn put(dst: &mut [u8; HDR_CAP], offset: &mut usize, src: &[u8]) {
        let mut k = 0usize;
        while k < src.len() {
            dst[*offset + k] = src[k];
            k += 1;
        }
        *offset += src.len();
    }

    /// The POST and M-POST heads for one action text, so the unit test and the proof share one builder.
    fn parity_heads(action: &[u8]) -> ([u8; HDR_CAP], usize, [u8; HDR_CAP], usize) {
        let pre_p: &[u8] = b"POST /ctl/IPConn HTTP/1.1\r\nSOAPACTION: \"";
        let pre_m: &[u8] = b"M-POST /ctl/IPConn HTTP/1.1\r\nMAN: \
            \"http://schemas.xmlsoap.org/soap/envelope/\";ns=01\r\n\
            01-SOAPACTION: \"";
        let suf: &[u8] = b"\"\r\n\r\n";
        let mut pb = [0u8; HDR_CAP];
        let mut mb = [0u8; HDR_CAP];
        let fits = action.len() <= ACT_CAP && pre_p.len() + action.len() + suf.len() <= HDR_CAP
            && pre_m.len() + action.len() + suf.len() <= HDR_CAP;
        if !fits {
            // identical overflow marker in both buffers: equal classes by construction
            let m = b"over";
            let mut i = 0usize;
            while i < m.len() && i < HDR_CAP {
                pb[i] = m[i];
                mb[i] = m[i];
                i += 1;
            }
            return (pb, m.len().min(HDR_CAP), mb, m.len().min(HDR_CAP));
        }
        let mut n = 0usize;
        put(&mut pb, &mut n, pre_p);
        put(&mut pb, &mut n, action);
        put(&mut pb, &mut n, suf);
        let pl = n;
        n = 0;
        put(&mut mb, &mut n, pre_m);
        put(&mut mb, &mut n, action);
        put(&mut mb, &mut n, suf);
        let ml = n;
        (pb, pl, mb, ml)
    }

    #[kani::proof]
    #[kani::unwind(96)]
    fn msearch_never_panics_and_answers_only_known() {
        // Totality: any 32-byte datagram classifies without panic; an Answer names a known ST with MX <= 5.
        let buf: [u8; 32] = kani::any();
        match parse_msearch(&buf) {
            MSearchParse::Answer { st, mx } => {
                assert!(mx <= 5);
                assert!(parse_st(st_name(st)).is_some());
            }
            MSearchParse::Ignore | MSearchParse::Malformed => {}
        }
    }

    #[kani::proof]
    fn action_name_roundtrip() {
        // Round trip for the seven actions named here; the table holds 28, so this covers a quarter of it.
        for a in [
            SoapAction::GetExternalIpAddress,
            SoapAction::GetStatusInfo,
            SoapAction::GetConnectionTypeInfo,
            SoapAction::AddPortMapping,
            SoapAction::DeletePortMapping,
            SoapAction::GetSpecificPortMappingEntry,
            SoapAction::GetGenericPortMappingEntry,
        ] {
            assert_eq!(parse_soap_action(soap_action_name(a)), Some(a));
        }
    }

    #[kani::proof]
    #[kani::unwind(200)]
    fn soap_classify_never_panics() {
        // Totality: any 64-byte head classifies without panic and a Soap class round-trips its own action.
        let buf: [u8; 64] = kani::any();
        match classify(&buf) {
            ReqClass::Soap { action, .. } => {
                assert_eq!(parse_soap_action(soap_action_name(action)), Some(action));
            }
            ReqClass::Get
            | ReqClass::GenaSubscribe
            | ReqClass::GenaRenew
            | ReqClass::GenaUnsubscribe
            | ReqClass::SoapInvalidAction
            | ReqClass::NotFound => {}
        }
    }

    #[kani::proof]
    #[kani::unwind(96)]
    fn mpost_post_parity() {
        // Parity for any clean short action text; the multi-line corners are the unit test's.
        let action: [u8; 8] = kani::any();
        kani::assume(action.iter().all(|&b| b >= b' '));
        let (pb, pl, mb, ml) = parity_heads(&action);
        assert_eq!(classify(&pb[..pl]), classify(&mb[..ml]));
    }

    #[kani::proof]
    #[kani::unwind(96)]
    fn mpost_post_parity_real_actions() {
        // Parity at full wire size for every real action name, and for junk.
        let names: [&[u8]; 8] = [
            b"GetExternalIPAddress",
            b"GetStatusInfo",
            b"GetConnectionTypeInfo",
            b"AddPortMapping",
            b"DeletePortMapping",
            b"GetSpecificPortMappingEntry",
            b"GetGenericPortMappingEntry",
            b"NotAnAction",
        ];
        for name in names {
            let (pb, pl, mb, ml) = parity_heads(name);
            assert_eq!(classify(&pb[..pl]), classify(&mb[..ml]));
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn entry_at_bounds_proof() {
        // entry_at never indexes out of bounds, and Some exactly when the index is below the length.
        let arr: [UpnpKey; 4] = [UpnpKey {
            req_ext: kani::any(),
            proto: if kani::any() {
                Proto::Udp
            } else {
                Proto::Tcp
            },
            client: Ipv4Addr::from(kani::any::<[u8; 4]>()),
            int_port: kani::any(),
        }; 4];
        let idx: u32 = kani::any();
        match entry_at(&arr, idx) {
            Some(e) => {
                assert!((idx as usize) < 4);
                assert_eq!(e, arr[idx as usize]);
            }
            None => assert!((idx as usize) >= 4),
        }
    }

    #[kani::proof]
    fn advance_seq_injective() {
        // the eventKey advance is injective, so a key never repeats before a full 2^32 cycle
        let a: u32 = kani::any();
        let b: u32 = kani::any();
        kani::assume(advance_seq(a) == advance_seq(b));
        assert_eq!(a, b);
    }

    #[kani::proof]
    #[kani::unwind(40)]
    fn sid_set_invariants() {
        // add succeeds only when the sid was absent and under capacity; remove succeeds iff present
        let mut set = SidSet::new();
        let a: Sid = Sid(kani::any());
        let b: Sid = Sid(kani::any());
        for step in 0..4u32 {
            if step % 2 == 0 {
                let was = set.has(a);
                let added = set.add(a);
                assert!(added || was || set.is_full(), "add fails only on duplicate/full");
                assert!(set.has(a), "after add the sid is present");
            } else {
                let was = set.has(b);
                let removed = set.remove(b);
                assert_eq!(removed, was, "remove succeeds iff present");
                assert!(!set.has(b), "after remove the sid is absent");
            }
            assert!(set.len() <= MAX_GENA_SUBS, "capacity never exceeded");
        }
    }
}