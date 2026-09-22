# Troubleshoot ds-lite-punch

Every case on this page was measured on a working ds-lite line. Each one names
what to read first, because the daemon's own view and the carrier's view can
disagree.

## The service restarts in a loop

Read the log:

```sh
logread | grep ds-lite-punch | tail -30
```

The daemon prints `error:` and the full help text when it refuses its command
line. The procd service then respawns it every five seconds, with no limit, so
the log fills quickly and the datapath is absent between attempts.

The usual cause is a value in `/etc/ds-lite-punch.env`. Check these:

- `BIND` and `TARGET` are present and are `ip:port`.
- An `ALLOWLIST` path names a file that exists, and every line in it is an IPv4
  address.
- `SLOT_RANGE` is `LO-HI`, and it does not overlap the `BIND` port.

Fix the value, and start the service again. With no mappings to hold, the log
line is:

```text
error: no mappings: use --bind/--target (single) or --static-map R=ip:port (repeatable)
```

Confirm the daemon is running and bound:

```sh
netstat -lnup | grep ds-lite-punch
```

The line names the `BIND` address and port and the process identifier, which is
what you want to see.

## The mapping moved

Read the tuple file, and compare it with what a client uses:

```sh
cat /run/ds-lite-punch/tuple
logread | grep ds-lite-punch | grep tuple
```

The carrier chooses the external port, and it can choose a different one after a
new session, a line re-provision, or an AFTR restart. The daemon follows the
change and logs a new `tuple` event. Nothing on the router needs a fix, and every
client that others reach from outside needs the new address and port.

## The daemon's rules are gone after a firewall change

The daemon installs its rules when it starts. A reload of the router's firewall
rebuilds that firewall's tables, and the rules the daemon inserted into them go
with the rebuild. This was measured on 2026-09-22, on a dslite line whose firewall
reloaded while the daemon held a mapping. Check what is there:

```sh
nft list ruleset | grep -E "dslp|dslitepunch"
```

A missing slot-port accept, or a missing carrier counter, is this case. Restart
the service, which installs them again:

```sh
/etc/init.d/ds-lite-punch restart
```

The daemon's own table, `table ip dslp`, is not part of the firewall's tables and
survives the reload. The daemon's rules inside the firewall's tables do not.

## The carrier watch says carrier-silent

The alarm names two causes, and the helper is the first to rule out:

1. Read the tuple, and compare it with the address and port the helper sends to.
   A moved port leaves the helper sending to nothing.
2. Read the counter, and confirm the rules are present:

   ```sh
   nft list ruleset | grep -A2 carrier_probe
   ```

   No rules means the case above, and the silence is the instrument's.
3. On the helper host, confirm the timer is alive and the journal shows a send:

   ```sh
   systemctl status carrier-probe
   journalctl -u carrier-probe | tail
   ```

If the helper sends, the counter is installed and rising, and there is still no
event, the carrier has stopped forwarding to your mapping. That is the finding
the watch exists to produce.

## A client cannot be reached from outside

Work in this order:

1. `cat /run/ds-lite-punch/tuple`, and compare the port with the one the client
   published. A moved port is the most common cause.
2. Check that a slot is holding the port:

   ```sh
   nft list table ip dslp
   ```

   The slot's port appears in the input set and in the translation map.
3. Confirm the target is listening on its port:

   ```sh
   netstat -lnup | grep TARGET_PORT
   ```
4. Run the outside check in [operate](operate.md). An arrival on the local
   network with no reply means the carrier and the daemon are both working, and
   nothing is listening at the target.

## The facade answers nothing

```sh
logread | grep ds-lite-punch | grep upnp
```

- Confirm `UPNP=1`. The flag is on by default, and `UPNP=0` turns it off.
- Confirm no other device on the local network answers SSDP on UDP 1900. Two
  responders make both unreliable.
- Confirm the facade is bound to the local address in `LAN_IP`, and reachable
  from the client's network.

PCP and NAT-PMP are off by default, and they answer only when `PCP=1` is set.

## The hold does not hold

```sh
logread | grep ds-lite-punch | grep -E "hold|observe"
```

- A device is held only when it is named in the file `ALLOWLIST` points at.
- `HOLD=1` is what makes the arm hold. With `HOLD=0` the arm reports the named
  devices' flows and touches nothing.
- `OBSERVATION=1` is what turns the reporting arm on.

The `hold` event names the devices and whether the ruleset is in force.

## A mapping request is refused

Every role-gated action answers `606` until the DeviceProtection store holds an
identity. Check these:

```sh
cat /run/ds-lite-punch/dp.tsv
cat /etc/ds-lite-punch.acl
```

The store is seeded from the ACL file at start, and only when the store is
absent. After you change the ACL file, restart the service.

The carrier can also answer a request with a different port. A request for a
port is a key, and the carrier is free to ignore it.

## Where to go next

- [Install](install.md) the daemon.
- [Configure](configure.md) it.
- [Operate](operate.md) it.
- [Upgrade](upgrade.md) it.