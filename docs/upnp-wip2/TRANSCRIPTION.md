# WANIPConnection:2 transcription record

Source: `UPnP-gw-WANIPConnection-v2-Service.md` (the internalized
specification, a conversion of the UPnP gateway WANIPConnection:2 service
document), with the authoritative rendering beside it as
`UPnP-gw-WANIPConnection-v2-Service.pdf`. This file is the implementation
contract the facade's v2 face implements at plan/0008 #v2-service-set. Every
claim below cites the specification section it transcribes; where the
transcription corrects the placeholder SCPD the facade carried, the correction
is named.

### Figures

The conversion carried its diagrams as signed crop URLs pointing at the
converter's object store, and those signatures expire. The five crops are
re-hosted in `images/` and the document references them relatively:

| Figure | File | Section |
|---|---|---|
| Figure 2-1, IGD terminology for NAT rules | `images/fig-2-1.jpg` | 2.3 |
| Figure 2-2, AddPortMapping and port triggering | `images/fig-2-2.jpg` | 2.5.16 |
| Figure 2-5, state diagram for IP connection | `images/fig-2-5.jpg` | 2.6.1 |
| Figure 3-1, NAT is an IP address translator | `images/fig-3-1.jpg` | 3.2 |
| Figure 3-2, NAT with bundled session applications | `images/fig-3-2.jpg` | 3.2 |

Figures 2-3 and 2-4 are the result tables of 2.5.16 and 2.5.17, rendered as
tables in the conversion rather than as images, so no crop exists for them.

## The service identity

- Service type: `urn:schemas-upnp-org:service:WANIPConnection:2` (section 2.1).
- Service ID convention: `urn:upnp-org:serviceId:WANIPConn1` shared with the
  v1 service in the device description (section 2.1; the facade's
  `SoapService::WanIpConnection` serves both faces, distinguished by the
  SOAPACTION URN version).
- The PortListing datastructure namespace: `urn:schemas-upnp-org:gw:WANIPConnection`
  (section 2.3.25.1).

## Version posture (section 1.2)

The service is fully compliant with WANIPConnection:1 except where access
control is added. The changes that bind this implementation:

- The device exposes UPnP only over the LAN interface and MUST reject UPnP
  requests arriving on a WAN interface (section 1.2; the facade's `in_lan`
  guard).
- On startup the device MUST broadcast `ssdp:byebye` before the initial
  `ssdp:alive`, so a control point discards state about the previous device
  instance (section 1.2, restated at 2.3.23).
- Error codes 724 `SamePortValuesRequired`, 725 `OnlyPermanentLeasesSupported`,
  726 `RemoteHostOnlySupportsWildcard` and 727 `ExternalPortOnlySupportsWildcard`
  are deprecated from the device in version 2. The device MUST NOT emit them;
  control points MUST still accept them (sections 1.2 and 2.5.16.3).
- The device MUST support a specific (non-wildcard) `RemoteHost` and a specific
  (non-wildcard) `ExternalPort` (sections 1.2, 2.3.17, 2.3.18).
- The device MUST support an internal port different from the external port
  (section 2.5.17).
- A lease value of `0` is not a static mapping in version 2: it MUST be
  interpreted as the maximum value, 604800 seconds. Static mappings are made
  out of band only (sections 1.2, 2.3.16, 2.5.16.2, 2.5.17.3, table 2-11).
- The RECOMMENDED default lease is 3600 seconds; the allowed range is 0 to
  604800 (table 2-6, table 2-11).

## State variables (sections 2.3 and 2.4)

The service carries 23 state variables: the 21 of table 2-2 and the two
argument types added by version 2. Eventing is fixed by table 2-9 and by the
section 4 `serviceStateTable`; exactly five variables are evented.

| Variable | Evented | Data type | Source |
|---|---|---|---|
| ConnectionType | no | string | 2.3.3 |
| PossibleConnectionTypes | yes | string (CSV) | 2.3.4, 2.4.1 |
| ConnectionStatus | yes | string | 2.3.5, 2.4.2 |
| Uptime | no | ui4 | 2.3.6 |
| LastConnectionError | no | string | 2.3.7 |
| AutoDisconnectTime | no | ui4 | 2.3.8 |
| IdleDisconnectTime | no | ui4 | 2.3.9 |
| WarnDisconnectDelay | no | ui4 | 2.3.10 |
| RSIPAvailable | no | boolean | 2.3.11 |
| NATEEnabled | no | boolean | 2.3.12 |
| ExternalIPAddress | yes | string | 2.3.13, 2.4.3 |
| PortMappingNumberOfEntries | yes | ui2 | 2.3.14, 2.4.4 |
| PortMappingEnabled | no | boolean | 2.3.15 |
| PortMappingLeaseDuration | no | ui4 | 2.3.16 |
| RemoteHost | no | string | 2.3.17 |
| ExternalPort | no | ui2 | 2.3.18 |
| InternalPort | no | ui2 | 2.3.19 |
| PortMappingProtocol | no | string | 2.3.20 |
| InternalClient | no | string | 2.3.21 |
| PortMappingDescription | no | string | 2.3.22 |
| SystemUpdateID | no | ui4 | 2.3.23 |
| A_ARG_TYPE_Manage | no | boolean | 2.3.24 |
| A_ARG_TYPE_PortListing | no | string (XML fragment) | 2.3.25 |

The spelling is `NATEEnabled`, not `NATEnabled` (table 2-2, and the argument
`NewNATEEnabled` of 2.5.13). The data type of `A_ARG_TYPE_PortListing` is
`string`: the fragment is carried as an escaped string inside the SOAP
response (section 2.3.25.2, closing note).

### Allowed values and ranges

- `ConnectionType`: `Unconfigured`, `IP_Routed`, `IP_Bridged`, default
  `IP_Routed` (table 2-3).
- `ConnectionStatus`: `Unconfigured`, `Connecting`, `Connected`,
  `PendingDisconnect`, `Disconnecting`, `Disconnected` (table 2-4).
- `LastConnectionError`: `ERROR_NONE`, `ERROR_COMMAND_ABORTED`,
  `ERROR_NOT_ENABLED_FOR_INTERNET`, `ERROR_ISP_DISCONNECT`,
  `ERROR_USER_DISCONNECT`, `ERROR_IDLE_DISCONNECT`, `ERROR_FORCED_DISCONNECT`,
  `ERROR_NO_CARRIER`, `ERROR_IP_CONFIGURATION`, `ERROR_UNKNOWN` (table 2-5).
- `PortMappingProtocol`: `TCP`, `UDP` (table 2-8); no wildcard protocol value
  exists, so a `NewProtocol` outside this list is a 601 `Argument Value Out of
  Range` (2.5.16.2, 2.5.17.3, 2.5.19.2, 2.5.21.3).
- `InternalPort`: 1 to 65535; a value of 0 is not allowed (table 2-7, 2.3.19).
- `PortMappingLeaseDuration`: 0 to 604800, default vendor-defined with 3600
  RECOMMENDED (table 2-6).
- `RemoteHost` is the wildcard (empty string), four decimal digit groups, or a
  dotted DNS name (2.3.17). `InternalClient` is an address or a dotted name and
  cannot be the wildcard (2.3.21); the broadcast address 255.255.255.255 is
  settable for UDP mappings.

### Eventing rules

`PortMappingNumberOfEntries` and `SystemUpdateID` MUST be evented together
whenever a mapping rule is added or removed (2.4.4, 2.4.5). `SystemUpdateID`
increments by one per change and is evented once per change even when several
rules are affected (2.3.23). A lease counts down independently of
`PortMappingEnabled`; `GetGenericPortMappingEntry` and
`GetSpecificPortMappingEntry` return the remaining time (2.4.6). The device
does not re-initiate a mapping; the control point refreshes before expiry
(2.4.6).

## The actions (table 2-10, sections 2.5.1 to 2.5.21)

The service defines twenty-one actions, and table 2-10's device column splits
them: **fourteen are REQUIRED** of a device and **seven are OPTIONAL**. A
device implements the required set and MAY omit an optional one, and the SCPD
is the description of what the device implements, so the seven optional
actions are neither advertised nor dispatched here. A control point that
invokes one receives 401 Invalid Action, which is the UDA answer for an
action outside the published service.

The seven OMITTED actions, each marked `O` in table 2-10's device column:

| Action | Why it is omitted here |
|---|---|
| RequestTermination | it would tear down the household line, which this device does not own |
| SetAutoDisconnectTime | the disconnect timers act only on a connection the device manages |
| SetIdleDisconnectTime | the same |
| SetWarnDisconnectDelay | the same |
| GetAutoDisconnectTime | it reads back a timer this device never sets |
| GetIdleDisconnectTime | the same |
| GetWarnDisconnectDelay | the same |

Publishing a timer the device would not act on, or a termination it cannot
perform, would be a promise the facade cannot keep. The required fourteen are
all dispatched, and their argument tables below are transcribed from table
2-11 (common parameters) and each action's own table, each confirmed against
the section 4 `<scpd>` fragments where those are legible.

| # | Action | Arguments (in / out) | Table |
|---|---|---|---|
| 1 | SetConnectionType | NewConnectionType in | 2-12 |
| 2 | GetConnectionTypeInfo | NewConnectionType out, NewPossibleConnectionTypes out | 2-13 |
| 3 | RequestConnection | (none) | 2.5.3.1 |
| 4 | ~~RequestTermination~~ (optional, omitted) | (none) | 2.5.4.1 |
| 5 | ForceTermination | (none) | 2.5.5.1 |
| 6 | ~~SetAutoDisconnectTime~~ (optional, omitted) | NewAutoDisconnectTime in | 2-19 |
| 7 | ~~SetIdleDisconnectTime~~ (optional, omitted) | NewIdleDisconnectTime in | 2-21 |
| 8 | ~~SetWarnDisconnectDelay~~ (optional, omitted) | NewWarnDisconnectDelay in | 2-23 |
| 9 | GetStatusInfo | NewConnectionStatus out, NewLastConnectionError out, NewUptime out | 2-2x |
| 10 | ~~GetAutoDisconnectTime~~ (optional, omitted) | NewAutoDisconnectTime out | 2-26 |
| 11 | ~~GetIdleDisconnectTime~~ (optional, omitted) | NewIdleDisconnectTime out | 2-28 |
| 12 | ~~GetWarnDisconnectDelay~~ (optional, omitted) | NewWarnDisconnectDelay out | 2-30 |
| 13 | GetNATRSIPStatus | NewRSIPAvailable out, NewNATEEnabled out | 2-32 |
| 14 | GetGenericPortMappingEntry | NewPortMappingIndex in; NewRemoteHost, NewExternalPort, NewProtocol, NewInternalPort, NewInternalClient, NewEnabled, NewPortMappingDescription, NewLeaseDuration out | 2-32 |
| 15 | GetSpecificPortMappingEntry | NewRemoteHost, NewExternalPort, NewProtocol in; NewInternalPort, NewInternalClient, NewEnabled, NewPortMappingDescription, NewLeaseDuration out | 2-34 |
| 16 | AddPortMapping | NewRemoteHost, NewExternalPort, NewProtocol, NewInternalPort, NewInternalClient, NewEnabled, NewPortMappingDescription, NewLeaseDuration in | 2-36 |
| 17 | AddAnyPortMapping | the eight of AddPortMapping in; NewReservedPort out | 2-41 |
| 18 | DeletePortMapping | NewRemoteHost, NewExternalPort, NewProtocol in | 2-44 |
| 19 | DeletePortMappingRange | NewStartPort, NewEndPort, NewProtocol, NewManage in | 2-45 |
| 20 | GetExternalIPAddress | NewExternalIPAddress out | 2-47 |
| 21 | GetListOfPortMappings | NewStartPort, NewEndPort, NewProtocol, NewManage, NewNumberOfPorts in; NewPortListing out | 2-49 |

`NewReservedPort` is a `ui2` OUT argument related to `ExternalPort` (2.5.17.2).
`NewPortListing` is an OUT argument related to `A_ARG_TYPE_PortListing`
(2.5.21.1). `NewStartPort` MUST be less than or equal to `NewEndPort`, and
`NewEndPort` MUST be greater than or equal to `NewStartPort` (table 2-11); a
violation is 733 `InconsistentParameters` (2.5.19.6, 2.5.21.7).

### The connection-control actions

The required group that acts on the connection rather than on the mapping
table, and what this device answers, each with the section that decides it:

- **SetConnectionType**: section 2.5.1 notes that `ConnectionType` may be
  read-only "in cases where some form of auto configuration is employed", and
  this line is auto-configured (the ISP owns the ds-lite WAN). The device
  answers 731 `ReadOnly`, the code the error summary of 2.5.23 names for this
  action.
- **RequestConnection**: 2.5.3.4 requires a `ConnectionStatus` of
  Disconnected, PendingDisconnect or Connected with an `IP_Routed` type, and
  2.5.3.5 makes the effect Connected. When the facade holds an external tuple
  both already hold, so the action succeeds with an empty response; when no
  tuple is held the provider side is not up and the answer is 704
  `ConnectionSetupFailed` (2.5.3.6).
- **ForceTermination**: refused with 501 `Action Failed`. The facade does not
  own the WAN lifetime (netifd and the ISP do), and the action is public on
  the v1 face, so honouring it would hand every device on the LAN a lever
  that drops the line for every client. The specification's table for the
  action (2.5.5.6) has no code for a device that may not terminate, so the
  UDA generic failure is the answer; a CP that requires termination needs a
  device that manages its own connection.
- **GetNATRSIPStatus**: `RSIPAvailable` 0 (`lo` has no RSIP server,
  2.3.11) and `NATEEnabled` 1 (the facade performs the NAT, 2.3.12).

## The v2-only actions

### AddAnyPortMapping (2.5.17)

The action creates a mapping with the AddPortMapping arguments; the behaviour
differs only where the requested external port is not free, and there the
device reserves any free port and returns it as `NewReservedPort`. The free
port algorithm is vendor-defined and this implementation's engine supplies it.

- The action is encouraged over AddPortMapping (2.5.17) and is REQUIRED of the
  device (table 2-10).
- Wildcard `NewExternalPort` (0) is one of the features an implementation may
  omit (2.5.17 note). This implementation supports it: the request is an
  any-port allocation, and `NewReservedPort` carries the granted port. The spec
  notes that when `NewExternalPort` is the wildcard and the device supports it,
  the action returns 0 in `NewReservedPort` (2.5.17.3); with a granted-port
  engine the returned value is the granted port, which is the more informative
  answer and is what a control point needs in order to use the mapping.
- A lease of 0 MUST be read as 604800 (2.5.17.3).
- If `NewProtocol` is outside the `PortMappingProtocol` allowed list the device
  MUST return 601 (2.5.17.3).
- The result table of 2.5.17 defines the cases: a free requested port returns
  `NewReservedPort = NewExternalPort`; a taken requested port with a distinct
  remote host, internal client or protocol returns
  `NewReservedPort != NewExternalPort`; an identical remote host, external
  port, protocol and internal client is an overwrite.
- The distinction is why the mapping engine is reached through two entry
  points (plan/0008's version-specific SOAP semantics): `allocate_exact` for
  `AddPortMapping`, and `allocate_preferred` for this action, where a port
  another client holds moves the request to a free one. Both resolve to the
  same mapping objects over the one engine; only the port resolution differs.

### The key is per client, not per port

The mapping table is keyed `(client, external port, protocol)`, so several
clients may hold the same requested port, and the specification's one-holder
rule does not apply here. That is the supersession
[host call/0022](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0022-requested-port-is-a-per-client-label.md)
records: the rule assumes the device owns the external port, and on this line
it owns it on neither uplink. With an AFTR the CGNAT dictates the tuple and
the requested port is never bound; where `ds-lite-punch` does own the port, a
second claimant is served by the any-port path above. A write replaces only
the caller's own entry at that port, so the earlier holder keeps its mapping:
two consoles may each hold `3074/UDP`, with their own slots and their own real
tuples.

Two actions carry no client in their key, so they resolve inside the caller's
own namespace: `GetSpecificPortMappingEntry` and `DeletePortMapping` answer
for the caller's own entry at that port, or 714. `GetListOfPortMappings` and
`GetGenericPortMappingEntry` are lists, so duplicates are ordinary there, and
the range delete with `NewManage` (2.5.19) is the bulk path for entries other
than the caller's own.

### DeletePortMappingRange (2.5.19)

- `NewManage` states the intent: `0` removes only mappings whose
  `InternalClient` is the control point's address; `1` removes every mapping in
  the range (2.5.19). Table 2-11 adds that the flag does not supersede access
  control based on the control point's address.
- If the control point lacks permission for a specific entry inside the range,
  the device SHOULD skip that entry and continue (2.5.19.2).
- If no mapping is found in the range the device MUST return 730
  `PortMappingNotFound` (2.5.19.2, 2.5.19.6).
- The whole action MUST be atomic: all deletable mappings in the range are
  deleted as one operation (2.5.19.2).
- Each deletion compacts the array, decrements the evented
  `PortMappingNumberOfEntries` and increments the evented `SystemUpdateID`
  (2.5.19).

### GetListOfPortMappings (2.5.21)

- With `NewManage` `0`, the action returns the mappings whose `InternalClient`
  is the control point's address inside the range; with `1` it MUST return
  every mapping in the range (2.5.21).
- `NewNumberOfPorts` limits the returned list; `0` means all mappings in the
  range (2.5.21).
- The same skip-unauthorized-entries rule and the same 730
  `PortMappingNotFound` on an empty result as DeletePortMappingRange
  (2.5.21.3, 2.5.21.7).
- The action has no dependency on and no effect on device state (2.5.21.5,
  2.5.21.6).

## Access control (sections 1.2 and 2.5.x)

Version 2 introduces access control, and the specification RECOMMENDS rather
than mandates a policy (1.2), leaving the enforced set to the device. What is
mandated inside any policy that is chosen:

- Before processing a security-sensitive request the device MUST apply its
  policy and authenticate and authorize the control point; an unauthorized
  request MUST NOT take effect and MUST return 606 `Action not authorized`
  (2.5.16.2, 2.5.17.3, 2.5.19.2, 2.5.21.3).
- The recommended policy for an unauthenticated or unauthorized control point:
  external and internal ports at or above 1024, and an `InternalClient` equal
  to the control point's own address (2.5.16.2, 2.5.17.3, 2.5.19.2, 2.5.21.3).
- The recommended model split: no access control is needed in the two-box
  model where the control point is the device that receives the traffic, and
  authentication and authorization are recommended in the three-box model
  (1.2).

The facade enforces this boundary at plan/0008's WANIPConnection integration through the
DeviceProtection session principal, and the enforcement is a pure function of
the principal's roles and the action's requirement, never of the transport
address (plan/0008's conformance suite).

### The policy this device enforces

The specification leaves the enforced set to the device (1.2, 26.6 in
plan/0008), so the applied set is stated here rather than inferred. Plan/0008
section 26.22 carries the reasoning; what the device applies is:

- `AddPortMapping`, `AddAnyPortMapping`, `DeletePortMapping` and
  `DeletePortMappingRange` require an authenticated session holding at least
  `Basic`. An unauthenticated invocation receives 606 and no mapping changes.
- A caller without that lift is contained, as 2.5.16.2, 2.5.18.2, 2.5.14.2 and
  2.5.21.3 recommend: it may name only its own host, at ports at or above 1024
  where the floor applies, and it sees, enumerates, deletes and lists only its
  own entries at or above that floor. A read of another client's entry is 606
  rather than 714.
- The address clause and the read containment bind both faces: the v1 service
  refuses a mapping that names another host, and it answers a read of another
  host's entry with 606 rather than 714. The port floor is the clause bound to
  the v2 face alone, since it is the one a legacy client may legitimately
  exceed.
- A DeviceProtection session holding Basic lifts every clause, and the lift
  belongs to the principal rather than to the face, so a control point that
  authenticates over DeviceProtection reaches the whole table on either face.
  The device's own view of the table needs no part of this: the entry index is
  written to the daemon's state file, which is a local read.
- The remaining WANIPConnection:2 actions remain public: connection status,
  the connection type, the external address, and the report of whether NAT and
  RSIP are in use.

No information surface is left open by choice: an unauthenticated caller sees
its own mappings and nothing else, on either face. The reasoning, including
why the anonymous read is the ingress map rather than a status page, is in
plan/0008's containment for callers without the lift.

## Error codes (section 2.5.23)

| Code | Name | Where it applies |
|---|---|---|
| 601 | Argument Value Out of Range | a `NewProtocol` outside the allowed list, and any out-of-range argument |
| 606 | Action not authorized | the access-control refusal |
| 713 | SpecifiedArrayIndexInvalid | an out-of-bounds `NewPortMappingIndex` |
| 714 | NoSuchEntryInArray | `GetSpecificPortMappingEntry` on an absent mapping |
| 715 | WildCardNotPermittedInSrcIP | an empty `NewInternalClient` |
| 716 | WildCardNotPermittedInExtPort | a wildcard external port where the action forbids it |
| 718 | ConflictInMappingEntry | a mapping conflicting with one assigned to another client |
| 728 | NoPortMapsAvailable | `AddPortMapping` and `AddAnyPortMapping` with no free port |
| 729 | ConflictWithOtherMechanisms | a mapping conflicting with another configuration mechanism |
| 730 | PortMappingNotFound | `DeletePortMappingRange` and `GetListOfPortMappings` finding nothing |
| 731 | ReadOnly | `SetConnectionType` |
| 732 | WildCardNotPermittedInIntPort | a wildcard internal port |
| 733 | InconsistentParameters | start and end port inconsistent |

Codes 724 to 727 are accepted on input and MUST NOT be emitted (2.5.16.3).

## The PortListing fragment (section 2.3.25)

`A_ARG_TYPE_PortListing` is an XML fragment that MUST validate against the
`PortMappingList` schema in the `urn:schemas-upnp-org:gw:WANIPConnection`
namespace. The schema location the specification names,
`http://www.upnp.org/schemas/gw/WANIPConnection-v2.xsd`, no longer serves the
schema (the URL answers with an HTML placeholder), so the sample document of
2.3.25.2 is the shape authority and is transcribed here:

```xml
<p:PortMappingList xmlns:p="urn:schemas-upnp-org:gw:WANIPConnection"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="urn:schemas-upnp-org:gw:WANIPConnection http://www.upnp.org/schemas/gw/WANIPConnection-v2.xsd">
  <p:PortMappingEntry>
    <p:NewRemoteHost>202.233.2.1</p:NewRemoteHost>
    <p:NewExternalPort>2345</p:NewExternalPort>
    <p:NewProtocol>TCP</p:NewProtocol>
    <p:NewInternalPort>2345</p:NewInternalPort>
    <p:NewInternalClient>192.168.1.137</p:NewInternalClient>
    <p:NewEnabled>1</p:NewEnabled>
    <p:NewDescription>dooom</p:NewDescription>
    <p:NewLeaseTime>345</p:NewLeaseTime>
  </p:PortMappingEntry>
</p:PortMappingList>
```

The element names inside an entry are `NewRemoteHost`, `NewExternalPort`,
`NewProtocol`, `NewInternalPort`, `NewInternalClient`, `NewEnabled`,
`NewDescription` and `NewLeaseTime` (2.3.25.2). The prose of 2.3.25.1.1 calls
the entry fields XML attributes while the sample renders them as child
elements; the sample is followed, because it is the document a control point
parses and the field prose is loose about the distinction. The fragment is
carried inside the SOAP response and therefore must be escaped there; the XML
declaration is OPTIONAL (2.3.25.2).

## Section 4 XML Service Description (reassembled)

The specification's section 4 is the normative `<scpd>` document. The OCR
conversion shattered it more thoroughly than the DeviceProtection document:
almost every word is split (`<name>Add Any Port Mapping</name>`), tag names are
spaced (`</ argument List>`), and the action list is cut into markdown tables
whose cells carry escaped fragments out of order. The document below is
reassembled from the clean argument tables of section 2.5 and the state
variable definitions of section 2.3, with the fragments used as corroboration:
the eventing attributes, the allowed value lists, the ranges and the argument
directions each appear in the fragments and are reproduced here.

The document below is the specification's, with all twenty-one actions. The
SCPD this device publishes is the projection that table 2-10's device column
licenses: the fourteen REQUIRED actions and the full state table, with the
seven OPTIONAL actions absent (listed above). Three state variables,
`AutoDisconnectTime`, `IdleDisconnectTime` and `WarnDisconnectDelay`, are read
only by those seven and are declared here with their defaults, so the
published state table is the service's own.

```xml
<?xml version="1.0"?>
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
<action><name>RequestTermination</name></action>
<action><name>ForceTermination</name></action>
<action><name>SetAutoDisconnectTime</name><argumentList>
<argument><name>NewAutoDisconnectTime</name><direction>in</direction><relatedStateVariable>AutoDisconnectTime</relatedStateVariable></argument>
</argumentList></action>
<action><name>SetIdleDisconnectTime</name><argumentList>
<argument><name>NewIdleDisconnectTime</name><direction>in</direction><relatedStateVariable>IdleDisconnectTime</relatedStateVariable></argument>
</argumentList></action>
<action><name>SetWarnDisconnectDelay</name><argumentList>
<argument><name>NewWarnDisconnectDelay</name><direction>in</direction><relatedStateVariable>WarnDisconnectDelay</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetStatusInfo</name><argumentList>
<argument><name>NewConnectionStatus</name><direction>out</direction><relatedStateVariable>ConnectionStatus</relatedStateVariable></argument>
<argument><name>NewLastConnectionError</name><direction>out</direction><relatedStateVariable>LastConnectionError</relatedStateVariable></argument>
<argument><name>NewUptime</name><direction>out</direction><relatedStateVariable>Uptime</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetAutoDisconnectTime</name><argumentList>
<argument><name>NewAutoDisconnectTime</name><direction>out</direction><relatedStateVariable>AutoDisconnectTime</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetIdleDisconnectTime</name><argumentList>
<argument><name>NewIdleDisconnectTime</name><direction>out</direction><relatedStateVariable>IdleDisconnectTime</relatedStateVariable></argument>
</argumentList></action>
<action><name>GetWarnDisconnectDelay</name><argumentList>
<argument><name>NewWarnDisconnectDelay</name><direction>out</direction><relatedStateVariable>WarnDisconnectDelay</relatedStateVariable></argument>
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
```

Verification notes:

- Every argument row above is confirmed twice: against the clean per-action
  table of section 2.5 and against the recovered section 4 fragments, which
  name the same arguments in the same directions for the actions they cover.
- The state table is confirmed against table 2-2 (names and types), table 2-9
  (eventing), table 2-6 and table 2-7 (ranges), table 2-3 through table 2-5 and
  table 2-8 (allowed values), and the section 4 fragments (eventing attributes
  and ranges reproduced verbatim).
- Exactly five variables are evented, and the fragment attributes agree:
  `PossibleConnectionTypes`, `ConnectionStatus`, `ExternalIPAddress`,
  `PortMappingNumberOfEntries` and `SystemUpdateID`. Every other variable
  carries `sendEvents="no"`.
- The section 4 action list carries no action beyond the 21 above, and no
  vendor action is declared.

## Corrections recorded against the placeholder

The facade's `SCPD_WIP2` was authored before the source was internalized. It
carried:

1. A bogus action, `GetLinkLayerMaxBitRates`. That action belongs to
   WANCommonInterfaceConfig, not to this service. It is removed.
2. Bare `<action><name>...</name></action>` entries with no `argumentList`, so
   the published service description named the v2 actions without describing
   them. Every action now carries its argument table.
3. Invented argument state variables (`A_ARG_TYPE_ExternalPort`,
   `A_ARG_TYPE_InternalClient`, `A_ARG_TYPE_InternalPort`, `A_ARG_TYPE_Protocol`,
   `A_ARG_TYPE_LeaseTime`). No such state variables exist in this service:
   arguments relate to the state variable they share a name with, except
   `NewManage` and `NewPortListing`, which relate to `A_ARG_TYPE_Manage` and
   `A_ARG_TYPE_PortListing`.
4. The misspelling `NATEnabled` for `NATEEnabled` (table 2-2, 2.5.13).
5. A state table that marked every variable `sendEvents="no"`, which would have
   hidden the eventing of `SystemUpdateID` and `PortMappingNumberOfEntries` and
   contradicted the evented-together rule of 2.4.4 and 2.4.5.

6. The action count. The first transcription carried the service's
   twenty-one actions and asserted that every one is REQUIRED of the device.
   Table 2-10 says otherwise: fourteen are REQUIRED and seven are OPTIONAL,
   and the facade implemented neither group completely. The seven optional
   actions are now omitted from the published SCPD as well as from the
   dispatch (they are enumerated above), and the four required actions that
   had no dispatch arm (SetConnectionType, RequestConnection,
   ForceTermination, GetNATRSIPStatus) now have one, each with the section
   cited in "The connection-control actions".

The PortListing fragment emitted by `list_port_mappings` is corrected in the
same pass: it produced `<NewPortListing>` elements named
`<NewPortListingEntry>`, whereas the normative fragment is a
`PortMappingList` of `PortMappingEntry` elements in the
`urn:schemas-upnp-org:gw:WANIPConnection` namespace, as the sample of 2.3.25.2
above shows.