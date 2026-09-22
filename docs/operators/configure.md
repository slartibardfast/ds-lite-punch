# Configure ds-lite-punch

The service reads one shell file, `/etc/ds-lite-punch.env`, and turns its keys
into command-line flags. Restart the service after a change:

```sh
vi /etc/ds-lite-punch.env
/etc/init.d/ds-lite-punch restart
```

A key that is absent keeps the flag's own default. The defaults below are the
program's, and they suit one particular layout: read them, and set the ones your
line needs.

## The line and the mapping

| Key | Default | What it does |
|---|---|---|
| `BIND` | none, required | The address and port the daemon binds on the CGNAT-facing interface, as `ip:port`. The carrier maps this tuple. |
| `TARGET` | none, required | The local host and port that receives inbound traffic, as `ip:port`. The peer's source address is preserved. |
| `STUN` | `stun.l.google.com:19302,stun.cloudflare.com:3478` | The servers that read and refresh the mapping, comma-separated. One that falls silent is rotated out. |
| `INTERVAL` | `2` | Seconds between the STUN writes that keep the mapping alive. The carrier drops an idle UDP mapping in a few seconds, so treat this value as the lifetime of the mapping. Minimum 1. |
| `GATEWAY` | `192.168.0.1` | The next hop used to route the STUN writes out the line the mapping is on. Without it the default route wins and STUN reports the wrong address. |

## The slot engine

A slot is one mapping the daemon keeps for a client or a static entry.
These keys cap the engine.

| Key | Default | What it does |
|---|---|---|
| `SLOT_RANGE` | `30000-39999` | The ports the engine allocates from. Keep the range clear of the `BIND` port. |
| `MAX_SLOTS` | `32` | The maximum number of slots at once. |
| `MAX_MAPS_PER_CLIENT` | `16` | The maximum mappings per client. |

`SLOT_RANGE`, `MAX_SLOTS` and `MAX_MAPS_PER_CLIENT` are read by the service
script and appear in no shipped environment file. Add them to
`/etc/ds-lite-punch.env` to set them.

## The UPnP IGD facade

The facade answers `WANIPConnection:1`, `WANIPConnection:2` and
`DeviceProtection:1` on the local network. A client can ask for a mapping and
read one back.

| Key | Default | What it does |
|---|---|---|
| `UPNP` | `1` | `1` leaves the facade on. `0` turns it off, and it adds `--no-upnp`. |
| `UPNP_PORT` | `49152` | The port the facade serves HTTP on. |
| `LAN_IP` | `192.168.21.1` | The local address the facade binds and joins the SSDP group on. |

Set `UPNP=0` when another device on the local network already answers SSDP. Two
responders on UDP 1900 make both unreliable.

## PCP and NAT-PMP

PCP (RFC 6887) and NAT-PMP (RFC 6886) listen on UDP 5351, on the local network
only, and use the same slot engine as the facade.

| Key | Default | What it does |
|---|---|---|
| `PCP` | `0` | `1` answers PCP and NAT-PMP. |
| `PCP_PEER` | `0` | `1` answers the PCP `PEER` opcode with the mapping's own tuple. |

Both are off by default, because nothing on a local network asks for PCP unless
it is told to.

## The keepalive

The keepalive keeps a named device's mappings past the point where the carrier
would drop them. The daemon writes to each flow it keeps alive, on the local side and the kernel keeps
the carrier's own lifetime.

| Key | Default | What it does |
|---|---|---|
| `ALLOWLIST` | none | The path of the file that names the devices, one IPv4 address per line, with `#` for comments. |
| `KEEPALIVE` | `0` | `1` keeps the named devices' mappings alive. Without it the arm reports them and touches nothing. |
| `OBSERVATION` | `0` | `1` turns the observation arm on, which is what reports the named devices' live flows. |

To keep a device's mapping alive, name it in the allowlist and set `KEEPALIVE=1` with
`OBSERVATION=1`. The allowlist is a budget as well as an admission: a flow kept alive
costs about half a packet a second at the default cadence. Start with the devices
you need, and watch the count.

To add a device safely, name it while `KEEPALIVE=0` stays set, read the report, and
then set `KEEPALIVE=1`.

## The carrier watch

The watch counts a marked datagram from a helper outside your line, and raises an
event when the count stops rising. It tells a change in the carrier's filtering
from a client's story.

| Key | Default | What it does |
|---|---|---|
| `CARRIER_PROBE` | `0` | `1` arms the watch. |
| `CARRIER_PROBE_INTERVAL` | `900` | Seconds expected between the helper's probes. |
| `CARRIER_PROBE_MISSES` | `3` | Intervals of silence that raise `carrier-silent`. |
| `CARRIER_PROBE_POLL` | `5` | Seconds between readings of the counter. |

Arming the watch obliges the helper to run. A helper that has stopped and a
carrier that has stopped look the same from the router, so the alarm names both
causes. The helper is `deploy/carrier-probe.py`, and it runs on a host outside
the line.

## Options with no environment key

Some flags are reachable from the command line only. Add them to the `command`
line in `/etc/init.d/ds-lite-punch` when you need them:

| Flag | Default | What it does |
|---|---|---|
| `--state-dir` | `/run/ds-lite-punch` | Where the live state is written. |
| `--upnp-name` | `ds-lite-punch IGD` | The friendly name the facade reports. |
| `--cdc` | `nft` | How conntrack entries are removed: `proc`, `nft` or `aya`. |
| `--gc-grace-factor` | `3` | A multiplier on a slot's lifetime before collection. |
| `--max-refresh-attempts` | `8` | The keepalive's budget: refresh attempts for one flow whose conntrack entry has gone, and the number of flows the hold keeps at once. |

## Several mappings at once

The service script passes one `BIND` and one `TARGET`, which is one static
mapping. For more, replace that pair with one `--static-map` argument per
mapping:

```text
--static-map 40000=192.168.21.12:40002 --static-map 41000=192.168.21.13:41002
```

The `--static-map` form is repeatable, and it cannot be combined with
`--bind`/`--target`.

## Where to go next

- [Install](install.md) the daemon.
- [Operate](operate.md) it, and check a mapping from outside the line.
- [Troubleshoot](troubleshoot.md) a failure.