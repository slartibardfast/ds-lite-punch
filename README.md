# ds-lite-punch

CGNAT-aware UDP relay for the Virgin Media Ireland ds-lite softwire, plus PCP
and UPnP IGDv1 facade work — **code only** (design docs and the operational
agentic structure live in the rope-agentic monorepo and will be moved here
later).

- Single-binary Rust daemon holding a live CGNAT mapping via STUN and
  forwarding inbound UDP to a br-lan target with source preserved.
- Built for the ImmortalWrt router host: musl-static
  `x86_64-unknown-linux-musl`, no TLS, leanish deps.

## UPnP IGD facade (plan/0007 phase E)

Enabled by default (E1–E8): an SSDP responder on br-lan, the IGD
description chain (`rootDesc.xml` + `WANIPConnection:1`/`WANPPPConnection:1`
SCPDs cribbed from miniupnpd), SOAP with POST and M-POST parity, GENA
subscriptions, and `AddPortMapping` grants for UDP and TCP that build real
datapaths (the call/0017 TCP slot for TCP). `--no-upnp` disables it;
`--upnp-port` and `--lan-ip` (default 49152 / 192.168.21.1) place it.

**Documented divergences from a conventional IGD** (E8): the AFTR dictates
the external tuple, so a grant cannot honour the requested external port —
the request is the mapping key ("report-requested"), the granted R is
reported through enumeration, and the real external tuple arrives via STUN
publication; `GetExternalIPAddress` returns the live STUN value (never
0.0.0.0; a pre-discovery request is answered from the last published tuple,
and a reboot-fresh box with no tuple yet answers ActionFailed rather than
fabricating an address); and unlike miniupnpd's leases file there is no
lease-file tail escape — the lease table is capped (`--max-slots`,
`--max-maps-per-client`) and persisted atomically.
miniupnpd's "WAN-deaf" behaviour (an IGD that never answers) is likewise not
reproduced: the facade answers on br-lan as soon as it starts, and
`SIGTERM` sends the SSDP byebye NOTIFYs before exit.

## Layout

| Path | What |
|---|---|
| `src/` | crate code (STUN codec, slot table with PCP/UPnP indices, mapping state machine, forward, nft, observation engine, the UPnP facade: `upnp.rs` pure core + `upnpsvc.rs` runtime) |
| `deploy/` | procd init script, env, install.sh |

## Build

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

Formal verification via `cargo kani` over the parser and pure state machine
(bit-precise, all inputs): STUN codec, slot/holder invariants, SSDP grammar,
SOAP dispatch with M-POST parity, enumeration index math, SID/SEQ.

## DeviceProtection bootstrap

The v2 facade's mapping mutators need an authenticated `Basic` session, and
the device has no in-band way to create its first identity (the WPS
introduction protocol is deferred, `call/0021`), so an empty store refuses
every role-gated action. The operator seeds it: write `/etc/ds-lite-punch.acl`
(root, mode 600) in the store's tab-separated form and restart the service.
The init script copies it into the state directory at start and only when no
store exists yet, so it creates the first identity and never reverts a store
the device already holds. The format and the PBKDF2 derivation are documented
in `deploy/ds-lite-punch.env`; `call/0023` records the decision.
