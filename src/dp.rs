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
    /// assigned role names (e.g. Administrator)
    pub roles: Vec<String>,
}

/// A user login credential record: Salt + STORED (spec 2.6.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpUser {
    pub name: String,
    /// 16-octet random salt, per user
    pub salt: [u8; 16],
    /// first 128 bits of PBKDF2-HMAC-SHA-256(password, salt)
    pub stored: [u8; 16],
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
    /// always denied regardless of roles (an action reserved to the
    /// device's own machinery)
    Denied,
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

/// The authorization decision: a control point holding `roles` may
/// invoke an action gated by `required`. Public actions need nothing.
///
/// Source-IP independence is structural: the decision is a pure
/// function of (roles, required), never of the transport address.
pub fn authorize(roles: &[String], required: &DpAuthz) -> bool {
    match required {
        DpAuthz::Public => true,
        DpAuthz::Denied => false,
        DpAuthz::Roles(needed) => roles.iter().any(|r| needed.iter().any(|n| n == r)),
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
pub const DP_PBKDF2_ITERATIONS: u32 = 5000;

/// Compute STORED = first 128 bits of T1, where T1 is the PBKDF2
/// (PRF = HMAC-SHA-256, c = DP_PBKDF2_ITERATIONS) output over
/// password = Password and salt = Name || Salt (spec 2.6.5.6).
/// Password and Name are UTF-8.
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
                    roles: vec!["Administrator".into()],
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
        let protected = DpAuthz::Roles(vec!["Administrator".into()]);
        assert!(authorize(&admin_roles, &protected));
        assert!(!authorize(&guest_roles, &protected));
        assert!(authorize(&guest_roles, &DpAuthz::Public));
        assert!(!authorize(&admin_roles, &DpAuthz::Denied));
        // the decision does not name any address: transport source cannot
        // influence it (the structural source-independence of 26.19)
        let doc = acl_xml(&acl);
        assert!(doc.contains("<Name>Trusted CP</Name>"));
        assert!(doc.contains("<Role>Administrator</Role>"));
        let list = identity_list_xml(&acl);
        assert!(list.contains("<Identity><Name>Guest</Name></Identity>"));
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