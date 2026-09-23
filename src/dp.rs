//! DeviceProtection:1 service core (plan/0008 #v2-service-set).
//!
//! Pure, dependency-free implementation of the normative contract
//! transcribed from the internalized specification
//! (docs/upnp-dp1/UPnP-gw-DeviceProtection-V1-Service.md): the
//! SupportedProtocols document (the mandated WPS introduction and
//! PKCS5 login protocol names), the ACL / IdentityList / Identity
//! datastructures, the challenge-response UserLogin ceremony, role
//! management, and the authorization decision for protected actions.
//!
//! The PKCS5 ceremony per the spec (2.6.5.6 / 2.6.6.4): a device keeps,
//! per user Name, a random 16-octet Salt and STORED = the first 128 bits
//! of T1, where T1 is computed as PBKDF2 with PRF = HMAC-SHA-256,
//! password = Password, salt = Name || Salt (both UTF-8), c = 5000
//! iterations. GetUserLoginChallenge issues a fresh Challenge;
//! UserLogin's Authenticator is the Base64 of the first 128 bits of
//! HMAC-SHA-256(STORED, Challenge || DeviceID || ControlPointID). This
//! module implements SHA-256, HMAC and PBKDF2 in pure Rust (the crate
//! is dependency-free) with standard test vectors.
//!
//! Kani non-goal: the core is io-free and unit-tested; the vector
//! pins below are the invariants the ceremony depends on.

// ---- SHA-256 (FIPS 180-4) ----

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 of `msg`.
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    // message padding: append 0x80, zeros, then the 64-bit bit length
    let bitlen = (msg.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(msg.len() + 72);
    padded.extend_from_slice(msg);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bitlen.to_be_bytes());

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// HMAC-SHA-256 (RFC 2104, key truncated/padded to the 64-byte block).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_digest = sha256(&inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_digest);
    sha256(&outer)
}

/// PBKDF2 (RFC 2898) with PRF = HMAC-SHA-256, producing `dk_len` octets.
#[allow(dead_code)] // the CP-side half of the ceremony; pinned by the vector tests
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dk_len);
    let mut block = 1u32;
    while out.len() < dk_len {
        let mut u = Vec::with_capacity(salt.len() + 4);
        u.extend_from_slice(salt);
        u.extend_from_slice(&block.to_be_bytes());
        let mut t = hmac_sha256(password, &u);
        let mut u = t;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= ui;
            }
        }
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(dk_len);
    out
}

// ---- the DP:1 datastructures (per the internalized spec) ----

/// One Identity in the ACL: a Control Point identity with its assigned
/// roles (spec section 2.4.4 / 2.4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpIdentity {
    /// the case-sensitive identity name (CP certificate CN)
    pub name: String,
    /// a user-settable display label, no certificate impact
    pub alias: Option<String>,
    /// the 16-octet binary identity (UUID) of the control point
    pub id: [u8; 16],
    /// assigned role names (e.g. Admin)
    pub roles: Vec<String>,
}

/// A user login credential record: Salt + STORED (spec 2.6.5) plus the
/// roles associated with the Name (spec 2.6.5.7: "the Roles associated
/// with Name").
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DpUser {
    pub name: String,
    /// 16-octet random salt, per user
    pub salt: [u8; 16],
    /// first 128 bits of T1 (PBKDF2-HMAC-SHA-256, spec 2.6.5.6)
    pub stored: [u8; 16],
    /// the roles assigned to this user Name
    pub roles: Vec<String>,
}

/// The ACL document (spec 2.4.4): identities and roles.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DpAcl {
    pub identities: Vec<DpIdentity>,
}

/// A pending login challenge (spec 2.6.5 / 2.6.6).
#[derive(Clone, Debug)]
pub struct DpChallenge {
    /// the fresh nonce a CP must authenticate against
    pub nonce: [u8; 16],
}

/// The set of roles a control point holds for an action (spec 3.1,
/// "Determining Roles Required for Actions").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DpAuthz {
    /// the action is public: no role required
    Public,
    /// the action requires any of these roles
    Roles(Vec<String>),
}

/// Evaluate an ACL for a control point identity presented by its
/// 16-octet ID: the roles assigned to that identity.
pub fn roles_for_identity(acl: &DpAcl, id: &[u8; 16]) -> Vec<String> {
    acl.identities
        .iter()
        .find(|i| &i.id == id)
        .map(|i| i.roles.clone())
        .unwrap_or_default()
}

/// The role hierarchy: a principal holding a higher role satisfies a
/// requirement for any lower role (the spec's recurring "Basic or Admin"
/// pair means Admin covers Basic). An unknown role satisfies nothing.
fn role_level(role: &str) -> Option<u8> {
    match role {
        "Basic" => Some(0),
        "Admin" => Some(1),
        _ => None,
    }
}

/// True when a principal role `r` satisfies a requirement role `n`.
fn role_satisfies(r: &str, n: &str) -> bool {
    match (role_level(r), role_level(n)) {
        (Some(lr), Some(ln)) => lr >= ln,
        _ => r == n,
    }
}

/// The authorization decision: a control point holding `roles` may
/// invoke an action gated by `required`. Public actions need nothing.
///
/// Source-IP independence is structural: the decision is a pure
/// function of (roles, required), never of the transport address.
pub fn authorize(roles: &[String], required: &DpAuthz) -> bool {
    match required {
        DpAuthz::Public => true,
        DpAuthz::Roles(needed) => roles.iter().any(|r| needed.iter().any(|n| role_satisfies(r, n))),
    }
}

/// The SupportedProtocols document (spec 2.4.3): the WPS introduction
/// and PKCS5 login protocols are MANDATORY; vendor additions may follow.
pub fn supported_protocols_xml() -> String {
    concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<SupportedProtocols xmlns=\"urn:schemas-upnp-org:gw:DeviceProtection\">\n",
        "  <Introduction><Name>WPS</Name></Introduction>\n",
        "  <Login><Name>PKCS5</Name></Login>\n",
        "</SupportedProtocols>\n"
    )
    .to_string()
}

/// The ACL document XML (spec 2.4.4).
pub fn acl_xml(acl: &DpAcl) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ACL xmlns=\"urn:schemas-upnp-org:gw:DeviceProtection\">\n",
    );
    out.push_str("  <Identities>\n");
    for id in &acl.identities {
        out.push_str("    <User>\n");
        out.push_str(&format!("      <Name>{}</Name>\n", id.name));
        if let Some(alias) = &id.alias {
            out.push_str(&format!("      <Alias>{}</Alias>\n", alias));
        }
        out.push_str("      <RoleList>\n");
        for r in &id.roles {
            out.push_str(&format!("        <Role>{}</Role>\n", r));
        }
        out.push_str("      </RoleList>\n");
        out.push_str("    </User>\n");
    }
    out.push_str("  </Identities>\n</ACL>\n");
    out
}

/// The IdentityList document XML (spec 2.4.5).
pub fn identity_list_xml(acl: &DpAcl) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<IdentityList xmlns=\"urn:schemas-upnp-org:gw:DeviceProtection\">\n",
    );
    for id in &acl.identities {
        out.push_str(&format!("  <Identity><Name>{}</Name></Identity>\n", id.name));
    }
    out.push_str("</IdentityList>\n");
    out
}

/// Issue a fresh login challenge with a device-random nonce.
pub fn new_challenge(nonce: [u8; 16]) -> DpChallenge {
    DpChallenge { nonce }
}

/// PBKDF2 iteration count c for the PKCS5 ceremony (spec 2.6.5.6).
#[allow(dead_code)] // the CP-side half of the ceremony; pinned by the vector tests
pub const DP_PBKDF2_ITERATIONS: u32 = 5000;

/// Compute STORED = first 128 bits of T1, where T1 is the PBKDF2
/// (PRF = HMAC-SHA-256, c = DP_PBKDF2_ITERATIONS) output over
/// password = Password and salt = Name || Salt (spec 2.6.5.6).
/// Password and Name are UTF-8.
#[allow(dead_code)] // the CP-side half of the ceremony; pinned by the vector tests
pub fn stored_for(password: &[u8], name: &[u8], salt: &[u8; 16]) -> [u8; 16] {
    let mut pbkdf2_salt = Vec::with_capacity(name.len() + 16);
    pbkdf2_salt.extend_from_slice(name);
    pbkdf2_salt.extend_from_slice(salt);
    let mut out = [0u8; 16];
    let dk = pbkdf2_hmac_sha256(password, &pbkdf2_salt, DP_PBKDF2_ITERATIONS, 16);
    out.copy_from_slice(&dk);
    out
}

/// Verify a UserLogin authenticator:
/// Authenticator == first 16 bytes of
/// HMAC-SHA-256(STORED, Challenge || DeviceID || ControlPointID)
/// per spec 2.6.6.
pub fn verify_authenticator(
    stored: &[u8; 16],
    challenge: &[u8; 16],
    device_id: &[u8; 16],
    cp_id: &[u8; 16],
    authenticator: &[u8],
) -> bool {
    let mut mac_in = Vec::with_capacity(48);
    mac_in.extend_from_slice(challenge);
    mac_in.extend_from_slice(device_id);
    mac_in.extend_from_slice(cp_id);
    let mac = hmac_sha256(stored, &mac_in);
    authenticator.len() >= 16 && mac[..16] == authenticator[..16]
}

// ---- the stateful service core ----

/// The DeviceProtection error set (spec 2.6.15 summary and the per-
/// action error tables): the faults this service can return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpErr {
    /// 600 Argument Value Invalid (unknown Name, unknown Challenge,
    /// unsupported ProtocolType, malformed arguments)
    InvalidValue,
    /// 606 Action not authorized (2.6.5.10 and the admin-action tables)
    NotAuthorized,
    /// 701 Authentication Failure (2.6.6.9)
    AuthFailure,
    /// 704 Processing Error (2.6.1.9)
    Processing,
}

/// One control point's session. The plain-HTTP analogue of the spec's
/// authenticated TLS session: keyed by the control point's address (the
/// transport the facade serves), holding the login state the spec ties to
/// a session. The principal (user + CP identity + roles) is established
/// by the PKCS5 challenge-response; the address keys the session the same
/// way the TLS connection handle does and is never the authorization
/// input itself (plan/0008's security context).
#[derive(Clone, Debug)]
struct DpSession {
    /// the most recent challenge issued (2.6.5.9: only the most recent is
    /// kept) and the user Name it was issued for
    challenge: Option<DpChallenge>,
    challenge_user: Option<String>,
    /// the logged-in principal: user Name and the matched ACL identity ID
    /// (2.6.6.8). The role set is evaluated live from the ACL at read
    /// time, so an ACL/role change takes effect on live sessions.
    user: Option<String>,
    cp_identity: Option<[u8; 16]>,
    /// failed UserLogin attempts since the last challenge (2.6.6.8: after
    /// about five, the session state is freed and a fresh challenge is
    /// required)
    failures: u8,
    last_seen: u64,
}

impl DpSession {
    fn fresh(now: u64) -> Self {
        DpSession {
            challenge: None,
            challenge_user: None,
            user: None,
            cp_identity: None,
            failures: 0,
            last_seen: now,
        }
    }
}

/// Session idle ceiling for a plain-HTTP login session (the "session
/// validity / expiry" of plan/0008's security context; the spec's sessions die
/// with the TLS connection, which this facade does not offer).
pub const DP_SESSION_TTL_SECS: u64 = 1800;

/// Failed UserLogin attempts before the session challenge is freed and a
/// fresh GetUserLoginChallenge is required (spec 2.6.6.8, recommended
/// five).
pub const DP_LOGIN_FAILURE_LIMIT: u8 = 5;

/// The full DP:1 service state: the persistent security configuration
/// (users + ACL, per plan/0008's persistence rules) and the transient sessions.
/// Pure and io-free: the clock is injected so the conformance tests are
/// deterministic, and the caller persists through `config_tsv` /
/// `config_from_tsv`.
#[derive(Clone, Debug, Default)]
pub struct DpState {
    /// the device's 16-octet identity (the DeviceID in the authenticator
    /// computation; derived from the root UDN by the caller)
    pub device_id: [u8; 16],
    /// the password file: one record per login Name
    pub users: Vec<DpUser>,
    /// the ACL: identities with assigned roles
    pub acl: DpAcl,
    /// transient login state, one session per control point address
    sessions: std::collections::HashMap<std::net::Ipv4Addr, DpSession>,
}

impl DpState {
    pub fn new(device_id: [u8; 16], users: Vec<DpUser>, acl: DpAcl) -> Self {
        DpState {
            device_id,
            users,
            acl,
            sessions: std::collections::HashMap::new(),
        }
    }

    /// SetupReady (spec 2.4.2): the device is never busy — it runs no
    /// setup protocol registrar, so no setup operation is pending and the
    /// only pressure a setup-capable CP can meet is the SendSetupMessage
    /// fault path. The value stays 1 (evented variable; no transitions).
    pub fn setup_ready(&self) -> bool {
        true
    }

    /// GetUserLoginChallenge (2.6.5). The Name must be a known user
    /// (2.6.5.10: an unknown Name is 600); the issued challenge replaces
    /// the session's previous one (2.6.5.9).
    pub fn begin_login(
        &mut self,
        key: std::net::Ipv4Addr,
        name: &str,
        nonce: [u8; 16],
        now: u64,
    ) -> Result<([u8; 16], [u8; 16]), DpErr> {
        let user = self
            .users
            .iter()
            .find(|u| u.name == name)
            .ok_or(DpErr::InvalidValue)?;
        let session = self
            .sessions
            .entry(key)
            .or_insert_with(|| DpSession::fresh(now));
        session.challenge = Some(new_challenge(nonce));
        session.challenge_user = Some(name.to_string());
        session.failures = 0;
        session.last_seen = now;
        Ok((user.salt, session.challenge.as_ref().unwrap().nonce))
    }

    /// UserLogin (2.6.6). Verifies the Authenticator against STORED of
    /// the challenge's user Name, trying each ACL identity ID as the
    /// ControlPointID (2.6.6.4: the MAC input binds Challenge,
    /// DeviceID and ControlPointID; the CP identity MUST be in the ACL,
    /// 2.6.6.5). On success the session principal becomes the user with
    /// the union of the user's and the matched identity's roles
    /// (2.6.6.8). An unrecognized challenge is 600 (2.6.6.9); a bad
    /// Authenticator is 701; after the failure limit the challenge is
    /// freed so a fresh one is required (2.6.6.8 backstop).
    pub fn login(
        &mut self,
        key: std::net::Ipv4Addr,
        challenge: [u8; 16],
        authenticator: &[u8],
        now: u64,
    ) -> Result<(), DpErr> {
        let device_id = self.device_id;
        let session = self
            .sessions
            .get_mut(&key)
            .ok_or(DpErr::InvalidValue)?;
        session.last_seen = now;
        let (pending, challenge_user) = match (&session.challenge, &session.challenge_user) {
            (Some(c), Some(u)) => (c.nonce, u.clone()),
            _ => return Err(DpErr::InvalidValue),
        };
        if pending != challenge {
            return Err(DpErr::InvalidValue);
        }
        if session.failures >= DP_LOGIN_FAILURE_LIMIT {
            // 2.6.6.8: session state freed -> a fresh challenge is needed
            session.challenge = None;
            session.challenge_user = None;
            session.failures = 0;
            return Err(DpErr::InvalidValue);
        }
        let stored = match self.users.iter().find(|u| u.name == challenge_user) {
            Some(u) => u.stored,
            None => {
                session.challenge = None;
                session.challenge_user = None;
                return Err(DpErr::InvalidValue);
            }
        };
        // the CP identity must be an ACL identity (2.6.6.5); the
        // authenticator binds it into the MAC, so guessing requires the
        // password-derived STORED
        let mut matched: Option<[u8; 16]> = None;
        for identity in &self.acl.identities {
            if identity.id == [0u8; 16] {
                continue; // a User-name identity carries no CP ID
            }
            if verify_authenticator(&stored, &challenge, &device_id, &identity.id, authenticator) {
                matched = Some(identity.id);
                break;
            }
        }
        let matched = match matched {
            Some(id) => id,
            None => {
                session.failures = session.failures.saturating_add(1);
                if session.failures >= DP_LOGIN_FAILURE_LIMIT {
                    session.challenge = None;
                    session.challenge_user = None;
                    session.failures = 0;
                }
                return Err(DpErr::AuthFailure);
            }
        };
        session.user = Some(challenge_user);
        session.cp_identity = Some(matched);
        session.failures = 0;
        Ok(())
    }

    /// UserLogout (2.6.7): the session principal is dropped — a no-op
    /// when nothing is logged in, per 2.6.7.
    pub fn logout(&mut self, key: std::net::Ipv4Addr, now: u64) {
        let session = self.sessions.entry(key).or_insert_with(|| DpSession::fresh(now));
        session.user = None;
        session.cp_identity = None;
        session.challenge = None;
        session.challenge_user = None;
        session.failures = 0;
        session.last_seen = now;
    }

    /// Touch a session (caller: after an authorized protected action).
    pub fn touch(&mut self, key: std::net::Ipv4Addr, now: u64) {
        if let Some(s) = self.sessions.get_mut(&key) {
            s.last_seen = now;
        }
    }

    /// The session's role set, empty when not logged in or expired.
    /// Evaluated LIVE from the password file and ACL: an ACL or role
    /// change takes effect on existing sessions immediately (plan/0008
    /// section 26.19 "ACL change / role change" obligations).
    pub fn session_roles(&self, key: std::net::Ipv4Addr, now: u64) -> Vec<String> {
        let Some(s) = self.sessions.get(&key) else {
            return Vec::new();
        };
        if s.user.is_none() || now.saturating_sub(s.last_seen) > DP_SESSION_TTL_SECS {
            return Vec::new();
        }
        let mut roles = self
            .users
            .iter()
            .find(|u| u.name == s.user.as_deref().unwrap_or(""))
            .map(|u| u.roles.clone())
            .unwrap_or_default();
        if let Some(cp) = s.cp_identity {
            for r in roles_for_identity(&self.acl, &cp) {
                if !roles.contains(&r) {
                    roles.push(r);
                }
            }
        }
        roles
    }

    /// The logged-in user Name of a live session.
    pub fn session_user(&self, key: std::net::Ipv4Addr, now: u64) -> Option<&str> {
        match self.sessions.get(&key) {
            Some(s)
                if s.user.is_some() && now.saturating_sub(s.last_seen) <= DP_SESSION_TTL_SECS =>
            {
                s.user.as_deref()
            }
            _ => None,
        }
    }

    /// The authorization decision (plan/0008's security context): a pure
    /// function of the session principal's roles and the action's
    /// requirement. The address keys the session store only; the decision
    /// never consults it, so the outcome is source-IP independent for a
    /// given principal.
    pub fn enforce(&self, key: std::net::Ipv4Addr, required: &DpAuthz, now: u64) -> Result<(), DpErr> {
        match required {
            DpAuthz::Public => Ok(()),
            DpAuthz::Roles(_) => {
                let roles = self.session_roles(key, now);
                if authorize(&roles, required) {
                    Ok(())
                } else {
                    Err(DpErr::NotAuthorized)
                }
            }
        }
    }

    /// GetACLData (2.6.8): the ACL document.
    pub fn acl(&self) -> &DpAcl {
        &self.acl
    }

    /// AddIdentityList (2.6.9): union-add the incoming identities; the
    /// result is the identities actually added (2.6.9.3). A User identity
    /// is keyed by name, a CP identity by its 16-octet ID; an entry
    /// already present is not re-added.
    pub fn add_identities(&mut self, incoming: &DpAcl) -> DpAcl {
        let mut added = DpAcl::default();
        for id in &incoming.identities {
            let present = self.acl.identities.iter().any(|x| {
                (id.id != [0u8; 16] && x.id == id.id) || (id.name == x.name)
            });
            if !present {
                self.acl.identities.push(id.clone());
                added.identities.push(id.clone());
            }
        }
        added
    }

    /// RemoveIdentity (2.6.10): remove by Name, case-sensitive. Unknown
    /// names are a no-op success (the spec's error table cites 600 for an
    /// invalid Identity; the absence of an identity is idempotent from
    /// the caller's side — the caller decides whether to fault).
    pub fn remove_identity(&mut self, name: &str) -> bool {
        let before = self.acl.identities.len();
        self.acl.identities.retain(|x| x.name != name);
        self.acl.identities.len() != before
    }

    /// SetUserLoginPassword (2.6.11): sets the Stored/Salt for a login
    /// Name, creating the user record when absent (2.6.11.9 "the password
    /// associated with the user name ... is updated"). Returns false when
    /// the identity is entirely unknown (600 is the caller's choice).
    pub fn set_user_password(&mut self, name: &str, stored: [u8; 16], salt: [u8; 16]) -> bool {
        match self.users.iter_mut().find(|u| u.name == name) {
            Some(u) => {
                u.stored = stored;
                u.salt = salt;
                true
            }
            None => {
                let known = self.acl.identities.iter().any(|x| x.name == name)
                    || self.acl.identities.iter().any(|x| x.id != [0u8; 16]);
                if known {
                    self.users.push(DpUser {
                        name: name.to_string(),
                        salt,
                        stored,
                        roles: Vec::new(),
                    });
                    true
                } else {
                    false
                }
            }
        }
    }

    /// AddRolesForIdentity (2.6.12): strictly additive union on the ACL
    /// entry or the user record named `identity`. Returns false if the
    /// identity does not exist.
    pub fn add_roles(&mut self, identity: &str, roles: &[String]) -> bool {
        if let Some(u) = self.users.iter_mut().find(|u| u.name == identity) {
            for r in roles {
                if !u.roles.contains(r) {
                    u.roles.push(r.clone());
                }
            }
            return true;
        }
        if let Some(i) = self.acl.identities.iter_mut().find(|x| x.name == identity) {
            for r in roles {
                if !i.roles.contains(r) {
                    i.roles.push(r.clone());
                }
            }
            return true;
        }
        false
    }

    /// RemoveRolesForIdentity (2.6.13): the symmetric removal.
    pub fn remove_roles(&mut self, identity: &str, roles: &[String]) -> bool {
        if let Some(u) = self.users.iter_mut().find(|u| u.name == identity) {
            u.roles.retain(|r| !roles.contains(r));
            return true;
        }
        if let Some(i) = self.acl.identities.iter_mut().find(|x| x.name == identity) {
            i.roles.retain(|r| !roles.contains(r));
            return true;
        }
        false
    }
}

/// The services whose actions the DP boundary gates (the WANIPConnection
/// integration: the mapping service flows through the authorization layer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpTarget {
    DeviceProtection,
    WanIpConnection,
}

/// The device's role policy (plan/0008's public-versus-protected operations through its default security posture): which role
/// each action requires. Public actions need no session; the WIP2
/// mapping mutators require an authenticated session holding at least
/// "Basic"; the security-administration DP actions require
/// "Admin". SetUserLoginPassword additionally permits the
/// session's own user (checked in the caller).
pub fn required_role(target: DpTarget, action: &str) -> DpAuthz {
    match target {
        DpTarget::WanIpConnection => match action {
            "AddPortMapping" | "AddAnyPortMapping" | "DeletePortMapping" | "DeletePortMappingRange" => {
                DpAuthz::Roles(vec!["Basic".into()])
            }
            _ => DpAuthz::Public,
        },
        DpTarget::DeviceProtection => match action {
            "GetACLData" | "AddIdentityList" | "RemoveIdentity" | "SetUserLoginPassword"
            | "AddRolesForIdentity" | "RemoveRolesForIdentity" => {
                DpAuthz::Roles(vec!["Admin".into()])
            }
            _ => DpAuthz::Public,
        },
    }
}

/// The role names the device recognizes (unknown roles are rejected with
/// 600 per 2.6.12.3).
pub fn valid_role(role: &str) -> bool {
    matches!(role, "Admin" | "Basic")
}

// ---- persistence projection (plan/0008's persistence rules) ----
//
// users + ACL are the persistent security configuration; sessions are
// transient. The TSV shapes:
//   U <name> <salt-hex32> <stored-hex32> <role,role,...>
//   A <name> <alias-or--> <id-hex32> <role,role,...>

pub fn config_tsv(users: &[DpUser], acl: &DpAcl) -> String {
    let mut out = String::new();
    for u in users {
        out.push_str(&format!(
            "U\t{}\t{}\t{}\t{}\n",
            u.name,
            hex(&u.salt),
            hex(&u.stored),
            u.roles.join(",")
        ));
    }
    for i in &acl.identities {
        let alias = i.alias.clone().unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "A\t{}\t{}\t{}\t{}\n",
            i.name,
            alias,
            hex(&i.id),
            i.roles.join(",")
        ));
    }
    out
}

/// Parse the TSV projection; malformed lines are skipped (the caller
/// decides whether a partial parse is fatal). Salt/stored/id decode from
/// lowercase hex; an alias of `-` is None.
pub fn config_from_tsv(text: &str) -> (Vec<DpUser>, DpAcl) {
    let mut users = Vec::new();
    let mut acl = DpAcl::default();
    for line in text.lines() {
        let mut cols = line.split('\t');
        let Some(kind) = cols.next() else { continue };
        match kind {
            "U" => {
                let (Some(name), Some(salt), Some(stored), Some(roles)) =
                    (cols.next(), cols.next(), cols.next(), cols.next())
                else {
                    continue;
                };
                let (Some(salt), Some(stored)) = (unhex16(salt), unhex16(stored)) else {
                    continue;
                };
                let roles = roles.split(',').filter(|r| !r.is_empty() && valid_role(r)).map(str::to_string).collect();
                users.push(DpUser { name: name.to_string(), salt, stored, roles });
            }
            "A" => {
                let (Some(name), Some(alias), Some(id), Some(roles)) =
                    (cols.next(), cols.next(), cols.next(), cols.next())
                else {
                    continue;
                };
                let Some(id) = unhex16(id) else { continue };
                let alias = if alias == "-" { None } else { Some(alias.to_string()) };
                let roles = roles.split(',').filter(|r| !r.is_empty() && valid_role(r)).map(str::to_string).collect();
                acl.identities.push(DpIdentity { name: name.to_string(), alias, id, roles });
            }
            _ => {}
        }
    }
    (users, acl)
}

fn hex(v: &[u8]) -> String {
    let mut out = String::with_capacity(v.len() * 2);
    for b in v {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub(crate) fn unhex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ---- base64 (RFC 4648): the DP base64 arguments ----

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `data` as standard base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((triple >> 18) & 63) as usize] as char);
        out.push(B64[((triple >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[((triple >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(triple & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64 (whitespace tolerated; strict about padding:
/// `=` appears only in the final group's last two slots).
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if s.is_empty() {
        return Some(Vec::new());
    }
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let bytes = s.as_bytes();
    if let Some(p) = bytes.iter().position(|b| *b == b'=') {
        if p + 2 < bytes.len() {
            return None;
        }
        if bytes[p..].iter().any(|b| *b != b'=') {
            return None;
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for group in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        for (i, b) in group.iter().enumerate() {
            buf[i] = match *b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 0,
                _ => return None,
            };
        }
        let triple = ((buf[0] as u32) << 18)
            | ((buf[1] as u32) << 12)
            | ((buf[2] as u32) << 6)
            | (buf[3] as u32);
        out.push(((triple >> 16) & 0xff) as u8);
        if group[2] != b'=' {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if group[3] != b'=' {
            out.push((triple & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vectors() {
        // FIPS 180-4 / NIST examples
        let empty = sha256(b"");
        assert_eq!(
            empty.as_slice(),
            &hex::hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        let abc = sha256(b"abc");
        assert_eq!(
            abc.as_slice(),
            &hex::hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        let fox = sha256(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            fox.as_slice(),
            &hex::hex_decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
        );
    }

    #[test]
    fn hmac_sha256_vectors() {
        // RFC 4231 test case 1
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            mac.as_slice(),
            &hex::hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        // RFC 4231 test case 2
        let key2 = b"Jefe";
        let mac2 = hmac_sha256(key2, b"what do ya want for nothing?");
        assert_eq!(
            mac2.as_slice(),
            &hex::hex_decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn pbkdf2_hmac_sha256_vectors() {
        // RFC 7914 (scrypt) published PBKDF2-HMAC-SHA256 vectors
        let dk = pbkdf2_hmac_sha256(b"passwd", b"salt", 1, 64);
        assert_eq!(
            dk.as_slice(),
            &hex::hex_decode(
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
            )
        );
    }

    #[test]
    fn supported_protocols_carries_mandated_protocols() {
        let doc = supported_protocols_xml();
        assert!(doc.contains("<Introduction><Name>WPS</Name></Introduction>"));
        assert!(doc.contains("<Login><Name>PKCS5</Name></Login>"));
        assert!(doc.contains("urn:schemas-upnp-org:gw:DeviceProtection"));
    }

    #[test]
    fn login_ceremony_roundtrip_and_tamper() {
        // a full PKCS5 UserLogin exchange: salt -> STORED -> challenge
        // -> authenticator -> verify
        let salt = [42u8; 16];
        let name = b"network-admin";
        // the device keeps the user record (Name, Salt, STORED) in its
        // password file, as SetUserLoginPassword would have written it
        let stored = stored_for(b"correct horse battery staple", name, &salt);
        let user = DpUser {
            name: String::from_utf8(name.to_vec()).unwrap(),
            salt,
            stored,
            roles: Vec::new(),
        };
        let device_id: [u8; 16] = [1u8; 16];
        let cp_id: [u8; 16] = [2u8; 16];
        let challenge = new_challenge([7u8; 16]);
        let mut mac_in = Vec::new();
        mac_in.extend_from_slice(&challenge.nonce);
        mac_in.extend_from_slice(&device_id);
        mac_in.extend_from_slice(&cp_id);
        // the CP computes the authenticator from the returned Salt, its
        // own Password and Name; the device verifies against STORED
        let good = hmac_sha256(&user.stored, &mac_in);
        assert!(verify_authenticator(
            &user.stored,
            &challenge.nonce,
            &device_id,
            &cp_id,
            &good[..16]
        ));
        // a wrong password yields a different STORED -> rejected
        let wrong_stored = stored_for(b"wrong", name, &user.salt);
        let bad = hmac_sha256(&wrong_stored, &mac_in);
        assert!(!verify_authenticator(
            &user.stored,
            &challenge.nonce,
            &device_id,
            &cp_id,
            &bad[..16]
        ));
        // the PBKDF2 salt is Name || Salt: a different Name (or a
        // different Salt) yields a different STORED for the same password
        let other_name = stored_for(b"correct horse battery staple", b"other-user", &user.salt);
        assert_ne!(user.stored, other_name);
        let other_salt = stored_for(b"correct horse battery staple", name, &[43u8; 16]);
        assert_ne!(user.stored, other_salt);
        assert_eq!(user.name, "network-admin");
        // the iteration count is the spec value, not an invention
        assert_eq!(DP_PBKDF2_ITERATIONS, 5000);
    }

    #[test]
    fn acl_authorization_is_role_and_source_independent() {
        let admin_id: [u8; 16] = [9u8; 16];
        let guest_id: [u8; 16] = [8u8; 16];
        let acl = DpAcl {
            identities: vec![
                DpIdentity {
                    name: "Trusted CP".into(),
                    alias: None,
                    id: admin_id,
                    roles: vec!["Admin".into()],
                },
                DpIdentity {
                    name: "Guest".into(),
                    alias: None,
                    id: guest_id,
                    roles: vec![],
                },
            ],
        };
        let admin_roles = roles_for_identity(&acl, &admin_id);
        let guest_roles = roles_for_identity(&acl, &guest_id);
        let protected = DpAuthz::Roles(vec!["Admin".into()]);
        assert!(authorize(&admin_roles, &protected));
        assert!(!authorize(&guest_roles, &protected));
        assert!(authorize(&guest_roles, &DpAuthz::Public));
        // the decision does not name any address: transport source cannot
        // influence it (the structural source-independence of 26.19)
        let doc = acl_xml(&acl);
        assert!(doc.contains("<Name>Trusted CP</Name>"));
        assert!(doc.contains("<Role>Admin</Role>"));
        let list = identity_list_xml(&acl);
        assert!(list.contains("<Identity><Name>Guest</Name></Identity>"));
    }

    /// The PKCS5 client half of the ceremony for the conformance suite:
    /// GetUserLoginChallenge then compute and present the Authenticator.
    #[allow(clippy::too_many_arguments)]
    fn dp_login(
        dp: &mut DpState,
        device_id: &[u8; 16],
        ip: std::net::Ipv4Addr,
        name: &str,
        pw: &[u8],
        cp_id: [u8; 16],
        nonce: [u8; 16],
        salt: &[u8; 16],
        now: u64,
    ) -> Result<(), DpErr> {
        let (_, challenge) = dp
            .begin_login(ip, name, nonce, now)
            .expect("challenge issued for a known user");
        let mut mac_in = Vec::new();
        mac_in.extend_from_slice(&challenge);
        mac_in.extend_from_slice(device_id);
        mac_in.extend_from_slice(&cp_id);
        let stored = stored_for(pw, name.as_bytes(), salt);
        let mac = hmac_sha256(&stored, &mac_in);
        dp.login(ip, challenge, &mac[..16], now)
    }

    fn dp_enforce(
        dp: &DpState,
        ip: std::net::Ipv4Addr,
        required: &DpAuthz,
        now: u64,
    ) -> Result<(), DpErr> {
        dp.enforce(ip, required, now)
    }

    #[test]
    fn dp19_conformance_suite() {
        // plan/0008's conformance suite: the anti-stub gate. A stub that answers
        // names but never enforces fails every one of these by
        // construction.
        let device_id: [u8; 16] = [0xdd; 16];
        let cp_admin: [u8; 16] = [0xca; 16];
        let cp_basic: [u8; 16] = [0xcb; 16];
        let cp_unknown: [u8; 16] = [0xcc; 16];
        let cp_readonly: [u8; 16] = [0xcd; 16];
        let acl = DpAcl {
            identities: vec![
                DpIdentity {
                    name: "admin-cp".into(),
                    alias: None,
                    id: cp_admin,
                    roles: vec!["Admin".into()],
                },
                DpIdentity {
                    name: "basic-cp".into(),
                    alias: None,
                    id: cp_basic,
                    roles: vec!["Basic".into()],
                },
                DpIdentity {
                    name: "readonly-cp".into(),
                    alias: None,
                    id: cp_readonly,
                    roles: vec![],
                },
            ],
        };
        let salt_a = [11u8; 16];
        let users = vec![
            DpUser {
                name: "admin".into(),
                salt: salt_a,
                stored: stored_for(b"admin-pw", b"admin", &salt_a),
                roles: vec!["Admin".into()],
            },
            DpUser {
                name: "guest".into(),
                salt: [12u8; 16],
                stored: stored_for(b"guest-pw", b"guest", &[12u8; 16]),
                roles: vec![],
            },
        ];
        let mut dp = DpState::new(device_id, users, acl);
        let ip_a: std::net::Ipv4Addr = "192.168.21.50".parse().unwrap();
        let ip_b: std::net::Ipv4Addr = "192.168.21.51".parse().unwrap();
        let ip_c: std::net::Ipv4Addr = "192.168.21.52".parse().unwrap();
        let ip_d: std::net::Ipv4Addr = "192.168.21.53".parse().unwrap();
        let ip_e: std::net::Ipv4Addr = "10.0.0.9".parse().unwrap();
        let mut now = 1000u64;

        // unauthenticated public action: allowed, from any source
        assert_eq!(
            dp_enforce(&dp, ip_a, &DpAuthz::Public, now),
            Ok(()),
            "unauth public action allowed"
        );
        assert_eq!(
            dp_enforce(&dp, ip_d, &DpAuthz::Public, now),
            Ok(()),
            "unauth public action allowed from another source"
        );
        // unauthenticated protected action: denied 606
        assert_eq!(
            dp_enforce(&dp, ip_a, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Err(DpErr::NotAuthorized),
            "unauth protected action denied"
        );

        // login ceremony for a known user; the CP identity must be in the ACL
        assert!(matches!(
            dp_login(&mut dp, &device_id, ip_a, "admin", b"admin-pw", cp_admin, [1u8; 16], &salt_a, now),
            Ok(())
        ));
        // authenticated authorized action: the admin session may add mappings
        // and read the ACL
        assert_eq!(
            dp_enforce(&dp, ip_a, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Ok(()),
            "authed authorized action allowed"
        );
        assert_eq!(
            dp_enforce(&dp, ip_a, &required_role(DpTarget::DeviceProtection, "GetACLData"), now),
            Ok(()),
            "admin may read the ACL"
        );
        // authenticated, authorized action: a Basic holder may map but may
        // not administer the ACL
        assert!(matches!(
            dp_login(&mut dp, &device_id, ip_b, "guest", b"guest-pw", cp_basic, [2u8; 16], &[12u8; 16], now),
            Ok(())
        ));
        assert_eq!(
            dp_enforce(&dp, ip_b, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Ok(()),
            "Basic session may map"
        );
        assert_eq!(
            dp_enforce(&dp, ip_b, &required_role(DpTarget::DeviceProtection, "GetACLData"), now),
            Err(DpErr::NotAuthorized),
            "Basic may not administer the ACL"
        );
        // authenticated unauthorized action: a session whose roles contain
        // neither Basic nor Admin cannot map
        assert!(matches!(
            dp_login(&mut dp, &device_id, ip_c, "guest", b"guest-pw", cp_readonly, [3u8; 16], &[12u8; 16], now),
            Ok(())
        ));
        assert_eq!(
            dp_enforce(&dp, ip_c, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Err(DpErr::NotAuthorized),
            "authed but unauthorized action denied"
        );

        // invalid credentials: a wrong password fails 701 without logging
        // out the existing session
        assert!(matches!(
            dp_login(&mut dp, &device_id, ip_a, "admin", b"wrong", cp_admin, [4u8; 16], &salt_a, now),
            Err(DpErr::AuthFailure)
        ));
        assert!(
            dp.session_roles(ip_a, now).contains(&"Admin".to_string()),
            "a failed login does not degrade an existing session"
        );

        // invalid authorization context: an unknown CP identity cannot log
        // in even with the right password (2.6.6.5: identity in the ACL)
        assert!(matches!(
            dp_login(&mut dp, &device_id, ip_a, "admin", b"admin-pw", cp_unknown, [5u8; 16], &salt_a, now),
            Err(DpErr::AuthFailure)
        ));

        // expired session: after the TTL every principal is gone
        now += DP_SESSION_TTL_SECS + 1;
        assert_eq!(
            dp_enforce(&dp, ip_a, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Err(DpErr::NotAuthorized),
            "expired session denied"
        );
        assert_eq!(
            dp_enforce(&dp, ip_b, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Err(DpErr::NotAuthorized),
            "expired Basic session denied"
        );

        // ACL change: grant Basic to the readonly identity -> its session
        // may now map; revoke -> denied again
        now += 10;
        assert!(matches!(
            dp_login(&mut dp, &device_id, ip_c, "guest", b"guest-pw", cp_readonly, [6u8; 16], &[12u8; 16], now),
            Ok(())
        ));
        assert_eq!(
            dp_enforce(&dp, ip_c, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Err(DpErr::NotAuthorized)
        );
        dp.add_roles("readonly-cp", &["Basic".to_string()]);
        assert_eq!(
            dp_enforce(&dp, ip_c, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Ok(()),
            "role grant takes effect on the live session"
        );
        dp.remove_roles("readonly-cp", &["Basic".to_string()]);
        assert_eq!(
            dp_enforce(&dp, ip_c, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Err(DpErr::NotAuthorized),
            "role revocation takes effect on the live session"
        );
        // RemoveIdentity removes the principal entirely -> a fresh login as
        // the removed identity fails
        dp.remove_identity("readonly-cp");
        assert!(
            matches!(
                dp_login(&mut dp, &device_id, ip_c, "guest", b"guest-pw", cp_readonly, [7u8; 16], &[12u8; 16], now),
                Err(DpErr::AuthFailure)
            ),
            "removed identity cannot authenticate"
        );

        // multiple simultaneous control points: separate principals,
        // independent decisions, after a service restart (fresh logins at
        // the new clock — the session store is transient, 26.15)
        assert!(matches!(
            dp_login(&mut dp, &device_id, ip_a, "admin", b"admin-pw", cp_admin, [8u8; 16], &salt_a, now),
            Ok(())
        ));
        assert!(matches!(
            dp_login(&mut dp, &device_id, ip_b, "guest", b"guest-pw", cp_basic, [9u8; 16], &[12u8; 16], now),
            Ok(())
        ));
        assert_eq!(
            dp_enforce(&dp, ip_a, &required_role(DpTarget::DeviceProtection, "GetACLData"), now),
            Ok(())
        );
        assert_eq!(
            dp_enforce(&dp, ip_b, &required_role(DpTarget::DeviceProtection, "GetACLData"), now),
            Err(DpErr::NotAuthorized),
            "guest stays unauthorized while admin is authorized"
        );

        // source-IP independence: the decision is a pure function of the
        // principal's roles; an unauthenticated source is denied wherever
        // it sits
        assert_eq!(
            dp_enforce(&dp, ip_e, &required_role(DpTarget::WanIpConnection, "AddPortMapping"), now),
            Err(DpErr::NotAuthorized),
            "unauthenticated is denied from any source"
        );

        // failure backstop: DP_LOGIN_FAILURE_LIMIT bad authenticators
        // against ONE challenge free the session state (2.6.6.8), so the
        // attacker must obtain a fresh challenge
        let (_, challenge) = dp.begin_login(ip_d, "guest", [0x60; 16], now).unwrap();
        for i in 0..DP_LOGIN_FAILURE_LIMIT {
            let bad = hmac_sha256(&[0x99u8; 16], &challenge);
            let r = dp.login(ip_d, challenge, &bad[..16], now);
            assert_eq!(r, Err(DpErr::AuthFailure), "attempt {} fails", i + 1);
        }
        assert_eq!(
            dp.login(ip_d, challenge, &[7u8; 16], now),
            Err(DpErr::InvalidValue),
            "the freed challenge is refused"
        );
        let (_, challenge2) = dp.begin_login(ip_d, "guest", [0x61; 16], now).unwrap();
        assert_ne!(challenge2, challenge, "a fresh challenge is issued");
    }

    #[test]
    fn base64_rfc4648_vectors() {
        // RFC 4648 section 10 vectors
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(
                base64_decode(&base64_encode(s.as_bytes())).unwrap(),
                s.as_bytes(),
                "roundtrip {}",
                s
            );
        }
        // whitespace tolerated
        assert_eq!(base64_decode("Zm9v\nYmFy").unwrap(), b"foobar");
        // strict padding: '=' only in the final group's last two slots
        assert!(base64_decode("Zm=v").is_none());
        assert!(base64_decode("Zg===").is_none());
        assert!(base64_decode("Zm9vYg=A").is_none());
        assert!(base64_decode("not base64!").is_none());
    }

    #[test]
    fn config_tsv_roundtrip_and_malformed_skip() {
        let salt = [0x2au8; 16];
        let users = vec![
            DpUser {
                name: "admin".into(),
                salt,
                stored: stored_for(b"pw", b"admin", &salt),
                roles: vec!["Admin".into()],
            },
            DpUser {
                name: "guest".into(),
                salt: [3u8; 16],
                stored: [4u8; 16],
                roles: vec![],
            },
        ];
        let acl = DpAcl {
            identities: vec![DpIdentity {
                name: "admin-cp".into(),
                alias: Some("Admin console".into()),
                id: [0xca; 16],
                roles: vec!["Admin".into()],
            }],
        };
        let tsv = config_tsv(&users, &acl);
        let (u2, a2) = config_from_tsv(&tsv);
        assert_eq!(u2, users);
        assert_eq!(a2, acl);

        // malformed rows are skipped, valid ones survive; unknown roles
        // are dropped (2.6.12.3: the device rejects roles it does not
        // understand)
        let mixed = "U\tbroken\nU\tok\t2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\t11111111111111111111111111111111\tBogusRole,Basic\nX\tjunk\n";
        let (u3, a3) = config_from_tsv(mixed);
        assert_eq!(a3.identities.len(), 0);
        assert_eq!(u3.len(), 1);
        assert_eq!(u3[0].name, "ok");
        assert_eq!(u3[0].roles, vec!["Basic".to_string()]);
    }

    mod hex {
        pub fn hex_decode(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
    }
}