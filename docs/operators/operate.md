# Operate ds-lite-punch

This page covers the day-to-day reading of a running daemon: the files it writes,
the events it logs, the rules it installs, and the one check that matters from
outside the line.

## Read the mapping

The carrier holds one external address and port for the line. The daemon learns
them with STUN and writes them to the state directory.

```sh
cat /run/ds-lite-punch/tuple
```

```text
203.0.113.7:59278
```

That file is the answer to "what does the line hold now". A client that others
must reach uses that address and port, and the carrier chose the port.

## The state directory

`/run/ds-lite-punch` is on a temporary filesystem, so every file in it is written
again after a reboot.

| File | What it holds |
|---|---|
| `tuple` | the mapping's external address and port |
| `tuple-R` | the same for the held slot whose port is `R`, one file per slot |
| `upnp-ident` | the facade's own identity, the uuid it reports to control points |
| `leases.tsv` | the facade's live leases, written when it has any |
| `upnp.tsv` | the facade's own state |
| `dp.tsv` | the DeviceProtection store: users and identities, seeded at start from `/etc/ds-lite-punch.acl` |

## Read the events

Every event is one line of JSON on syslog. Read them with `logread`:

```sh
logread | grep ds-lite-punch
```

| Event | Fields | What it means |
|---|---|---|
| `start` | `bind`, `target`, `stun_servers`, `slots` | the configuration the daemon started with |
| `tuple` | `ip`, `port`, and `slot` for a held slot | the mapping the carrier is holding |
| `upnp` | `lan`, `udn` | the facade is serving |
| `pcp` | `bind`, `peer` | the PCP and NAT-PMP listener is serving |
| `hold` | `devices`, `ruleset_in_force` | the hold's admission and its state |
| `observe` | `cdc`, `max_rescues`, `allowed`, `hold` | the observation arm's reading |
| `carrier-watch` | `counter`, `interval`, `misses`, `poll` | the watch is armed |
| `carrier-probe` | `count`, `epoch` | a probe from the helper was counted |
| `carrier-silent` | `last_probe`, `waited`, `epoch` | the count stopped rising |

Other lines carry an event name and a `detail` field, for a state a slot or a
flow passed through.

A healthy start is a `start` event and then a `tuple` event. A `tuple` event
that changes means the carrier gave the line a new port, and every client that
others reach from outside needs the new address.

## The rules the daemon installs

The daemon owns its datapath and removes it when the service stops.

```sh
nft list table ip dslp
ip rule show
```

| Where | What it is |
|---|---|
| `table ip dslp` | the daemon's own table: the sets and maps for the slot ports, the prerouting translation, and the hold's conntrack policy |
| `inet fw4` | the accept rules the daemon inserts for the slot ports, each marked with the comment `dslitepunch-R` |
| `ip rule`, priority `25100` | the policy route the relay's own egress uses, over table `1001` |
| `ip route`, table `1001` | the source route that keeps the relay's replies on the line that holds the mapping |

The daemon also adds one host route per STUN server, through `GATEWAY`, so the
STUN writes leave by the right line.

## The manual, on the box and off it

The router carries no manual reader. Read the flag reference on the box with:

```sh
ds-lite-punch --help
```

The manual page is installed at `/usr/share/man/man8/ds-lite-punch.8`, and it
ships in every release as `ds-lite-punch.8`. On a workstation, read either one:

```sh
man -l ds-lite-punch.8
```

## Check a mapping from outside the line

The daemon's own view and the carrier's view can disagree. This check reads the
mapping from the outside, which is the only place the carrier's filtering is
visible.

On the router, read the tuple:

```sh
cat /run/ds-lite-punch/tuple
```

On a host outside your line, send a datagram to that address and port. Use a
fixed source port so the arrival is easy to read:

```sh
echo ds-lite-check | nc -u -p 41000 -w 2 203.0.113.7 59278
```

On the router, watch for the arrival at the target:

```sh
tcpdump -i br-lan -nn -c 5 host TARGET_IP
```

The arrival proves two things at once: the carrier still forwards an unsolicited
datagram to your mapping, and the daemon translates it to the target. A command
that sends and then leaves without an answer is normal for UDP.

The target replies only when something is listening on its port. When nothing
is, the router answers with an ICMP port unreachable, and the arrival itself is
still the evidence you need.

## Where to go next

- [Configure](configure.md) the daemon.
- [Upgrade](upgrade.md) it, or roll back.
- [Troubleshoot](troubleshoot.md) a failure.