# The manual: publish a service, reach it from outside

This page walks the front door end to end. The household side holds one port
through the carrier's CGNAT and serves names on it from a public front. The
client side reaches those names from anywhere with one credential. Each step
carries its own check, and the deep pages carry each step's full story.

The two halves have two readers. The household half is the operator's, and it
assumes root on the router and on the front. The client half assumes nothing
beyond the three things the operator hands over, and it serves every shape of
client this household has: a member on a phone, the operator roaming, a friend
with a short-lived certificate, and an agent running one command. The readers
have profiles in [the cast](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/cast/operator.md)
([the client](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/cast/client.md)
is the second), and the client half is written against it.

## The values this page uses

| Value | Stands for |
|---|---|
| `front.example` | the protected name: TLS ends at the front, and a client certificate is demanded |
| `passthru.example` | the passthrough name: it rides untouched to the held port, where the service's own certificate answers |
| `192.0.2.10` | the front's public address |
| `8443` | the public port both names answer on |
| `203.0.113.7:59278` | the line's tuple, which the carrier assigned and can move |
| `192.168.21.97:443` | the TLS service on the household's LAN that the held port forwards to |

Replace every value with your own. The addresses are the documentation's
reserved ranges, so a copy-paste that escapes your notes lands nowhere.

## The household side

### The line

The daemon holds the port. The [install](operators/install.md) page puts it on
the router, and the [configure](operators/configure.md) page explains every key.
The values this deployment needs:

| Key | Value |
|---|---|
| `BIND` and `TARGET`, or `--static-map` | the mapping itself; the static form is repeatable, one entry per mapping |
| `GATEWAY` | the next hop on the CGNAT-facing interface, so STUN leaves by the right line |
| `INTERVAL` | the keepalive seconds, which are the mapping's lifetime |

The example forwards to a LAN TLS service, and the static entry that holds its
port reads `--static-map 40000=192.168.21.97:443`. A static port sits inside the
slot range, so `SLOT_RANGE` in `/etc/init.d/ds-lite-punch` covers it
(`40000-49999` here), and the daemon's own `BIND` port stays outside that range.

The passthrough name's path carries a client's TLS untouched to the held port,
so the service's own certificate answers there. The held port is one slot: ask
for it over the facade from a LAN client, or declare it as a static entry, and
[the front door page](operators/front-door.md) carries the protocol detail.

### Mint the household's certificates

One authority signs everything: the front's leaf, the daemon's identity, and
every client's. On the line, as root:

```sh
sh deploy/front-door/mint.sh --protected-name front.example --passthru-name passthru.example
```

The command mints into `/etc/ds-lite-punch-tls` the authority and the two leaves
signed by it: the front's, which covers both names, and the daemon's own. It
prints the copy commands for the front and the three settings the daemon wants.

### Point the daemon at the front

Five keys in `/etc/ds-lite-punch.env`:

| Key | Value |
|---|---|
| `POKE` | `192.0.2.10:8443`, the front's public port |
| `FRONT_ENDPOINT` | `192.0.2.10:8443`; setting it turns the control channel on |
| `FRONT_NAME` | `front.example`, the name the front's certificate answers on |
| `CLIENT_IDENTITY` | the daemon identity's certificate and key, as two PEM paths joined with a colon |
| `FRONT_ANCHOR` | the authority's certificate, as a PEM path |

Restart the service. A missing half of the identity stops the start, and the
refusal names the flag. Confirm the mapping with:

```sh
cat /run/ds-lite-punch/tuple
```

### The front

One public host with nginx. Provision the server and its stream module (`nginx`
and `libnginx-mod-stream` on Debian and Ubuntu), copy the three certificate
files mint.sh printed into `/etc/front-door/certs`, and install:

```sh
sh deploy/front-door/install.sh --public-port 8443 \
    --protected-name front.example --protected-upstream 127.0.0.1:8080 \
    --passthru-name passthru.example
```

The installer writes the front's root, its relay, the rendered configuration
and both units, checks the configuration, and starts them. What it leaves is on
its last lines, and every line of them is a measured lesson:

1. The edge admits the world to that port: one ingress rule for TCP and another
   for UDP, source `0.0.0.0/0`, and the source port range left empty. A source
   port range there admits only packets whose source port matches, which is how
   one front lost every connection with rules that looked right.
2. The protected name's upstream has to serve, or that name answers 502.

### Wire and confirm

After the daemon's restart, its poke lands on the relay's socket and teaches it
the line's tuple, and the daemon's push fills the table too. From your own desk,
with a client identity minted below, read both sides:

```sh
cat /run/ds-lite-punch/tuple
curl --cacert ca.crt --cert alice.crt --key alice.key \
    https://front.example:8443/table
```

The table's answer carries the tuple the front sees for the line, and every
line names the view that supplied it. When the two readings name the same
tuple, the whole exchange works. An empty table after a restart is the
provider case: a host whose provider rewrites its outbound source port loses
the poke, and [the deep page](operators/front-door.md) carries the check for it.

Two finishing steps, and the deep page carries both in full:

- The return path: the LAN service's answers follow the router's default route,
  which is the wrong line, so the service host needs a route rule for the
  peer's address (`ip rule add from 192.168.21.97 to <peer> lookup 1001 prio
  25002`). A granted TCP slot needs none.
- The standing watch: [the monitors](../deploy/monitor/README.md) run one check
  from outside (`external-monitor.py --once`) and one beside the daemon, and
  both emit one JSON line per pass.

### Hand a client their credential

First the store can mint: write one `U` row into `/etc/ds-lite-punch.acl`,
restart the service, and confirm it with `cat /run/ds-lite-punch/dp.tsv`. The
row's format is on the [install](operators/install.md) page, and minting
demands the `Admin` role.

Then, per person, on the line where the store and the authority live (the
router wants `python3` and `openssl` installed):

```sh
printf '%s\n' "$password" | python3 deploy/front-door/mint-client.py \
    --store /run/ds-lite-punch/dp.tsv --name alice --allow front.example \
    --ca-dir /etc/ds-lite-punch-tls --out-dir /etc/ds-lite-punch-tls/clients
```

The password arrives on standard input and stays out of a shell history. The
certificate lasts thirty days by default, and its subject carries the identity
and the name it may reach. Hand over four things:

1. `alice.p12`, the pair bundled the way a phone or a browser imports it:
   `openssl pkcs12 -export -in alice.crt -inkey alice.key -out alice.p12`
2. `ca.crt`, the household authority, which their device trusts for the front's
   own certificate
3. the name, and which of the two paths it takes
4. the link to [the client side](#the-client-side) of this page

## The client side

Everything on this half needs the three things the operator handed you: the
name, the household's `ca.crt`, and your own certificate. If one of them is
missing, ask before you improvise.

### Install your credential

- **A phone:** import `alice.p12` as a user certificate and trust `ca.crt` as a
  credential of the signing kind. Every vendor buries the option somewhere
  different; the settings search finds both on current iOS and Android.
- **A laptop:** import the same two files in your browser's or your system's
  certificate store, or skip the import and hand the PEM paths to curl below.
- **An agent:** nothing to import. The PEM paths go straight onto the command
  line.

### Reach your name

The protected name, in a browser, is the household's published page:

```text
https://front.example:8443/
```

The browser offers your certificate automatically after the import. The same
name under `/table` answers with the line's tuple as the front sees it, which
is the household's own health answer.

The passthrough name serves the service's own certificate, and the front stays
invisible by design. If the service signs its own certificate, your browser
warns about it; the warning belongs to the service, and it is the service you
were sent to.

One command covers both, and it is the deterministic form an agent runs:

```sh
curl --cacert ca.crt --cert alice.crt --key alice.key \
    https://front.example:8443/table
```

| What you see | What it means |
|---|---|
| the page, or the table answer | working |
| `400` with `No required SSL certificate was sent` | the front received no certificate from you; the import missed, or the paths are wrong |
| a certificate warning your browser will not pass | the household's `ca.crt` is missing; the front's own certificate is signed by it |
| an immediate refusal | the name is unpublished, or the front is down |
| a long silence | the line's mapping has gone quiet; report it |

curl prints its reason on stderr and exits 60 for the untrusted anchor and 56
for the refusal, which is the agent's contract.

### When it does not work

Work in this order:

1. Reload once.
2. Switch networks once: mobile data against the home wifi, or the reverse.
3. Still broken: stop, and report. The fix is the operator's; your report is
   its input. Four lines are enough: the name, the exact error text, the time,
   and which network you were on.

A certificate that has passed its thirty days fails with the `400` shape above,
and a fresh mint is the operator's one-line answer.

### The limits

- The datagram leg serves one client at a time. HTTP/3 and QUIC ride it, and a
  second client takes the socket over.
- The carrier owns the external port and can move it. The front follows the
  move within its lease, and your name stays your name.
- What the household publishes can change. A name that refused yesterday and
  serves today is the operator's edit, and the four-line report still applies.

## Where the deep pages are

| Page | What it carries |
|---|---|
| [Install](operators/install.md) | the daemon's release, its files, its first start |
| [Configure](operators/configure.md) | every key of `/etc/ds-lite-punch.env` |
| [Operate](operators/operate.md) | the state files, the events, the outside check |
| [Front door](operators/front-door.md) | the deep recipe this manual walks: the split, the poke, the return path |
| [Troubleshoot](operators/troubleshoot.md) | the failures measured on a working line |
| [The monitors](../deploy/monitor/README.md) | the standing watch, one JSON line per pass |
| [The manual page](https://github.com/slartibardfast/ds-lite-punch/blob/main/deploy/man/ds-lite-punch.8) | every flag, shipped in every release as `ds-lite-punch.8` |

The plans and the decisions behind the shape live in the
[host repository](https://github.com/slartibardfast/agentic-ds-lite-punch).
