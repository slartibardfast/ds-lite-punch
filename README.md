# ds-lite-punch

**DS-Lite Proxy UPnP NAT/CGNAT Holder (ds-lite-punch).**

This daemon runs on a router at the end of a ds-lite line. It keeps one path
through the carrier CGNAT open. It sends inbound traffic to one host on the
local network.

## What it does

- **Keepalive.** The daemon keeps one external mapping for the router. A STUN
  request every two seconds refreshes it and reads its external address and
  port.
- **Forward.** The daemon sends inbound UDP and TCP to a target on the local
  network. The target sees the real source address of the peer.
- **Answer.** The daemon answers UPnP IGD, PCP and NAT-PMP. A client can ask
  for a mapping, and it can read the mapping back.

## State at 2026-09-19

Working on the test router today:

- A mapping kept alive survives the silence of its client. The external vantage
  answered the mapping after 30, 60, 120 and 300 seconds of silence
  ([measurements](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/results/RESULTS-2026-09-18-held-mapping-silence.md)).
- Inbound UDP and TCP forward to the target, with the source address kept.
- The UPnP IGD facade answers for both service versions: `WANIPConnection:1`
  and `WANIPConnection:2`, with `DeviceProtection:1`.
- PCP and NAT-PMP answer on UDP port 5351, on the local network only.
- The keepalive's admission: the operator names the devices whose mappings are
  kept alive.
- The collision rules hold for a port that nobody allocated.

Evidence, for a reader who must re-derive these claims:

| Item | Value |
|---|---|
| pin | the commit in the host record, [`.host-software`](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/.host-software) |
| branch | `main` |
| toolchain | `ghcr.io/rust-cross/rust-musl-cross@sha256:ce75e9174325d4fbb3de85c309e2d7ca29f7500169bc4b5d2c611ff7e86d549a` |
| build | `cargo build --release --target x86_64-unknown-linux-musl` |
| artifact | `target/x86_64-unknown-linux-musl/release/ds-lite-punch` |
| artifact sha256 | `ab0f9bd517ef075885fd5b6e6a91b9fcc7e64ad9805e7d6450f2bd3eefd11a45` |
| tests | 196 passed, 1 ignored |
| proofs | Kani harnesses: the STUN codec, the slot and TCP-mapping invariants, the SSDP grammar, the SOAP dispatch, the enumeration index, the session identifier, the sequence number |
| lane | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |

The lane runs the tests and the release build inside the toolchain image above.
It prints the artifact line that the host record uses. It uploads the binary,
and an empty upload fails the job. The test router runs the bytes from the lane
([call/0032](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0032-the-builder-of-record-is-the-lane.md)).

## Limits

- The carrier chooses the external port. A request for a port is a key, and it
  is not a promise ([call/0018](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0018-igd-facade-honours-requests-as-reported.md)).
- A device's mapping is kept alive only when the operator names it
  ([call/0029](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0029-the-named-device-is-the-admission.md)).
- One client holds one mapping on one port
  ([call/0022](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0022-requested-port-is-a-per-client-label.md)).
- The carrier drops an idle UDP mapping in 5 to 10 seconds. It drops an idle
  TCP mapping in 120 to 300 seconds. These numbers are measured on this line
  ([call/0030](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0030-a-mapping-ends-with-its-device.md)).

## Future work

1. **The lobby case.** A console in a lobby sends no traffic. The keepalive must
   survive that silence on a real console. This test needs the operator
   ([plan/0009](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/plan/0009-mapping-keepalive-and-signalling/README.md)).
2. **The Kani suite on a larger host.** The full suite waits for a host with
   more memory
   ([call/0019](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0019-facade-kani-deferred-to-larger-host.md)).
3. **The R4 rule.** A late collision moves an allocation, and it never moves a
   punch. Decide if the rule must follow the protocol of the entry
   ([call/0027](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0027-collisions-for-punched-ports.md),
   [result](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/results/RESULTS-2026-09-18-collision-yield.md)).
4. **EIF loss.** Detect a change in the filtering behaviour of the carrier
   ([plan/0004](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/plan/0004-ds-lite-punch/README.md)).

## Build

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

A local build is for iteration. It is not a deployment source.

## Deploy

1. Write the device list to `/etc/ds-lite-punch.allow`.
2. Make the first `DeviceProtection` identity in `/etc/ds-lite-punch.acl`, then
   restart the service
   ([call/0023](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0023-the-operator-bootstraps-deviceprotection.md)).
3. Install the binary from a lane run. Check the hash against the host record
   before the service starts.

## Where the thought lives

The plans, the decisions and the record are in the host repository:
[agentic-ds-lite-punch](https://github.com/slartibardfast/agentic-ds-lite-punch).

## Terms

| Term | Meaning |
|---|---|
| AFTR | the carrier router at the far end of the ds-lite tunnel |
| CGNAT | carrier-grade network address translation |
| ds-lite | dual-stack lite: IPv4 over a tunnel to the carrier |
| mapping | one external address and port that the carrier holds open |
| STUN | the protocol that keeps the mapping and reads it |
| UPnP IGD | the UPnP Internet Gateway Device interface |
| DeviceProtection | the UPnP service that authenticates a control point |
| PCP | Port Control Protocol, a way for a client to ask for a mapping |
| NAT-PMP | NAT Port Mapping Protocol, the older form of that request |
| procd | the service manager on the router |
| pin | the source commit that the host record names |
| artifact | the release binary that the lane builds from the pin |

## Documentation

The operator pages cover the install, the configuration, the running of the
daemon, the upgrade and the troubleshooting:
<https://slartibardfast.github.io/ds-lite-punch/>

The manual page is generated from the same definition as `--help`, and it ships
in every release as `ds-lite-punch.8`.

## License

Released into the public domain under the Unlicense. See [LICENSE](LICENSE).