# DeviceProtection:1 transcription record

Source: `UPnP-gw-DeviceProtection-V1-Service.md` (the internalized
specification, itself a conversion of the UPnP gateway DeviceProtection:1
service document). This file is the implementation contract the facade
implements at plan/0008 #v2-service-set. Every claim below cites the
specification section it transcribes; where the transcription corrects an
earlier assumption, the correction is named.

## The service identity

- Service type: `urn:schemas-upnp-org:service:DeviceProtection:1`
- Service ID convention: `urn:upnp-org:serviceId:DeviceProtection` (per the
  spec's service description convention, section 2.2).
- XML namespace of the datastructures (SupportedProtocols, ACL,
  IdentityList, Identity): `urn:schemas-upnp-org:gw:DeviceProtection`
  (sections 2.4.3, 2.4.4, 2.4.5, 2.4.6).

## State variables (section 2.4)

| Variable | Evented | Data type | Section |
|---|---|---|---|
| SetupReady | YES | boolean | 2.4.2 |
| SupportedProtocols | NO | string | 2.4.3 |
| A_ARG_TYPE_ACL | NO | string | 2.4.4 |
| A_ARG_TYPE_IdentityList | NO | string | 2.4.5 |
| A_ARG_TYPE_Identity | NO | string | 2.4.6 |
| A_ARG_TYPE_Base64 | NO | bin.base64 | 2.4.1 |
| A_ARG_TYPE_String | NO | string | 2.4.1 |

Only SetupReady is evented (section 2.5 eventing table). The SCPD's
serviceStateTable carries exactly these seven variables.

### SetupReady semantics (2.4.2)

- `0` = busy / requires user input; `1` = ready to proceed with a setup
  operation.
- The value is a hint: a CP must not rely on it as a reliable gate; the
  device signals readiness changes by eventing.
- A device that supports only one setup operation at a time MUST clear
  SetupReady when the operation completes (2.6.1.8).

## The 13 actions (section 2.6.1-2.6.13)

Authoritative names and argument tables. **Correction:** an earlier
miniupnpd-derived SCPD carried 14 wrong names (`RequestUserLogin`,
`ValidateIdentity`, `AddACLEntry`, `RemoveACLEntry`, `GetListOfRoles`,
`RevokeRole`, `LoginWithPIN`, `LoginWithThirdParty`); none of those are
actions of this service. The SCPD now carries exactly the list below.

| # | Action | Arguments (in / out) | Section |
|---|---|---|---|
| 1 | SendSetupMessage | ProtocolType in (A_ARG_TYPE_String), InMessage in (A_ARG_TYPE_Base64), OutMessage out (A_ARG_TYPE_Base64) | 2.6.1 |
| 2 | GetSupportedProtocols | ProtocolList out (SupportedProtocols) | 2.6.2 |
| 3 | GetAssignedRoles | RoleList out (A_ARG_TYPE_String) | 2.6.3 |
| 4 | GetRolesForAction | DeviceUDN in, ServiceId in, ActionName in (A_ARG_TYPE_String), RoleList out, RestrictedRoleList out (A_ARG_TYPE_String) | 2.6.4 |
| 5 | GetUserLoginChallenge | ProtocolType in, Name in (A_ARG_TYPE_String), Salt out, Challenge out (A_ARG_TYPE_Base64) | 2.6.5 |
| 6 | UserLogin | ProtocolType in (A_ARG_TYPE_String), Challenge in, Authenticator in (A_ARG_TYPE_Base64) | 2.6.6 |
| 7 | UserLogout | (none) | 2.6.7 |
| 8 | GetACLData | ACL out (A_ARG_TYPE_ACL) | 2.6.8 |
| 9 | AddIdentityList | IdentityList in, IdentityListResult out (A_ARG_TYPE_IdentityList) | 2.6.9 |
| 10 | RemoveIdentity | Identity in (A_ARG_TYPE_Identity) | 2.6.10 |
| 11 | SetUserLoginPassword | ProtocolType in, Name in (A_ARG_TYPE_String), Stored in, Salt in (A_ARG_TYPE_Base64) | 2.6.11 |
| 12 | AddRolesForIdentity | Identity in (A_ARG_TYPE_Identity), RoleList in (A_ARG_TYPE_String) | 2.6.12 |
| 13 | RemoveRolesForIdentity | Identity in (A_ARG_TYPE_Identity), RoleList in (A_ARG_TYPE_String) | 2.6.13 |

The section 2.6.10 heading in the source marks `Removelidentity()`; the
table of contents and the action name table give `RemoveIdentity()`, which
is the action name this implementation uses. The header spelling is a
specimen typo.

## SupportedProtocols (2.4.3, 2.6.2)

- The document is XML in the gw:DeviceProtection namespace with an
  `<Introduction>` list and a `<Login>` list of `<Name>` entries.
- **Mandatory:** the WPS introduction protocol and the PKCS5 login
  protocol MUST appear (section 2.4.3); vendor additions may follow.
- GetSupportedProtocols returns this document as ProtocolList, and its
  minimum required value is the two mandated names (2.6.2.2).

## The ACL model (2.4.4)

- `ACL` contains `<Identities>` each with `<User>` entries: `<Name>`
  (case-sensitive identity, the certificate CN), optional `<Alias>`, and a
  `<RoleList>` of `<Role>` names.
- Identities are identified by their 16-octet binary ID (the CP's UUID).
- Role names are case-sensitive strings; the standard roles are `Public`, `Basic` and `Admin` (section 0).
- The ACL is local to a device; DeviceProtection defines no network-wide
  ACL (2.6.8).

## The certificate / identity model (2.4.1, 2.4.6, 2.6.10)

- Control points present an X.509 certificate; the device maps the
  certificate to an Identity (its ID, name, and assigned roles).
- TLS-client-certificate authentication is the transport for the role
  actions: protected actions MUST be invoked over a TLS connection
  authenticated by the CP's certificate, else the device returns
  `600 DP_UnauthenticatedIdentity` (2.6.10.3, error table 2-27).

## The PKCS5 login ceremony (2.6.5, 2.6.6, 2.6.11)

- Per user `Name`, the device stores a random 16-octet `Salt` and
  `STORED` = the first 128 bits of T1 where T1 is PBKDF2 with
  PRF = HMAC-SHA-256, password = Password (UTF-8), salt = Name (UTF-8)
  concatenated with Salt, and c = 5000 iterations (2.6.5.6).
  SetUserLoginPassword supplies Stored and Salt directly (2.6.11).
- GetUserLoginChallenge(ProtocolType=PKCS5, Name) returns Salt and a fresh
  Challenge (2.6.5).
- UserLogin(ProtocolType, Challenge, Authenticator): the Authenticator is
  the Base64 of the first 128 bits of
  HMAC-SHA-256(STORED, Challenge || DeviceID || CPID) where DeviceID is
  the device's 16-octet identity and CPID the control point's (2.6.6.4).
- A successful login upgrades the session roles to the union of the CP
  identity's ACL roles and the user's roles (2.6.6.8); UserLogout restores
  the roles to those of the certificate identity alone (2.6.7.4).
- Errors: `701 Authentication Failure` on a bad Authenticator (2.6.6.9);
  `600 Argument Value Invalid` for an unknown Name or unrecognized
  Challenge; `606 Action not authorized`; `704 Processing Error`;
  `708 Busy` (2.6.15 summary).
- Brute-force backstop: after about five failed UserLogin attempts the
  device SHOULD drop the CP's TLS session (2.6.6.8).

## Role requirements (3.1, "Determining Roles Required for Actions")

- Each action each of the services exposed by the device is gated by a
  role requirement; the device answers an unauthorized invocation with
  `606 Action Not Authorized` (UPnP architecture; the DP error tables cite
  600-699 as TBD where unspecified).
- Recommended roles are named per action (e.g. SendSetupMessage Public (2.6.1.6), AddIdentityList Basic or Admin
  (2.6.9.5), UserLogout Public (2.6.7.2)); the device decides the enforced
  set (plan/0008 section 26.6).
- **Source-IP independence:** the authorization decision in this
  implementation is a pure function of the CP identity's roles and the
  action's requirement; the transport address plays no part. (This is a
  design invariant of the facade, tested at plan/0008 section 26.19.)

## Eventing

- SetupReady is evented (2.5); after a SendSetupMessage that completes a
  setup operation, the device events SetupReady (2.6.1.8).

## Section 4 XML Service Description (reassembled)

The specification's section 4 is the normative `<scpd>` document. The OCR
conversion of the PDF broke it into fragments (code blocks split by table
cells, stray `<relatedStateVariable>` lines, and mis-rows such as a
`GetUserLoginChallenge` name inside the GetRolesForAction row and a
`ServiceID` casing that the clean 2.6.4 argument table disproves — the
argument name is `ServiceId`). The clean document, reassembled against
sections 2.4 (state variables) and 2.6 (argument tables), is exactly what
the facade's `SCPD_DP` publishes:

```xml
<?xml version="1.0"?>
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
```

Verification notes ("you already have this" — the cleanup was done on the
internalized conversion, no re-conversion needed):

- Every argument table in the document above is confirmed twice: against
  the clean per-action tables of section 2.6 and independently against the
  recovered section 4 fragments.
- The state table is confirmed against both section 2.4 and the section 4
  fragments: seven variables; `A_ARG_TYPE_Base64` is `bin.base64`, the
  rest are `string`; exactly one variable is evented (`SetupReady`, with
  `sendEvents="yes"`), matching the eventing table of section 2.5.
- The facade's `SCPD_DP` matches this document byte for byte modulo
  whitespace; the transcription is closed.

## Corrections recorded against earlier work

1. The SCPD action surface: wrong (miniupnpd-derived) names replaced by the
   thirteen authoritative actions above.
2. SendSetupMessage's OutMessage returns a Base64 setup message; the WPS
   transport is not a separate action — it is the WPS protocol spoken
   through SendSetupMessage with ProtocolType = "WPS" (2.6.1.2, 2.6.1.4).
3. SetupReady is a hint, not a guarantee (2.4.2); the facade events it
   rather than gating dispatch on it.