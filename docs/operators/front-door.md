# Serve a port from outside the line, with no tunnel

A carrier-grade NAT takes port forwarding away: the address the world sees belongs
to the carrier, and a mapping appears only when the line speaks first. This page
describes the shape that puts a service back on a name. It uses a small front on a
public address and the port this daemon already holds.

Nothing on the data path is encapsulated. The front routes a name to the carrier's
mapped port, the daemon keeps that port alive, and the two of them agree on which
port it is without a tunnel between them.

## What sits where

| Where | What it holds | What it does |
|---|---|---|
| The line | The mapping | The daemon pokes the front from a slot's own socket, which makes the carrier create and renew the mapping, and then reports the tuple the daemon has learned. |
| The front | The name, admission, and the datagram socket | nginx routes by name on TCP, passes a name through untouched or terminates it and demands a client certificate, and the relay owns the public UDP port: the pokes land on it, it learns the tuple from them, and it sends everything else onward from that same socket. |
| The client | A certificate, when the name is protected | It reaches the front's address and port, and never learns the carrier's tuple. |

The exchange is two-fold, and it is worth keeping the halves apart. The line's half
opens and keeps the port. The front's half authorises. Each has one channel: a
datagram that opens the port toward a peer, and an authenticated control channel
that carries what the front needs to know.

## The front's configuration

`deploy/front-door/nginx.conf` is the shipped configuration, written as a template
whose tokens name the front's own paths and the local block that terminates the
protected ones. `deploy/front-door/render.sh` fills those tokens, `install.sh` runs
it and writes the rest of the front, and the lane's harness renders through the same
renderer, so what CI tests is the shipped shape. Three facts about it matter on
Debian and Ubuntu:

- The stream module is a dynamic module, so the configuration loads it by name.
- The stream module in this nginx release cannot terminate several names on one
  listener, so a protected name is routed to a local `https` block that does the
  terminating. That block holds the only certificate the front has, and it is the
  only place a client certificate is checked.
- The datagram leg is not nginx's at all. nginx's UDP proxy opens an ephemeral
  source port for its upstream, and the carrier admits a peer by the exact tuple the
  line's mapping spoke to, so a forwarded datagram has to carry the port the poke
  was addressed to as its source. Only the relay's own socket does that.

`deploy/front-door/test-local.sh` proves the split on one machine: it renders the
shipped file with throwaway values, mints a one-day authority and three leaves,
and asserts that a pass-through name reaches the service's own certificate, that a
protected name is refused without a client certificate and served with one, that a
name nobody published reaches nothing, and that a client's datagram leaves for the
learned tuple from the socket the poke landed on. The component's lane runs it.

## Deploy it

Two ceremonies, and neither runs where the other does. On the line, as root:

```
sh deploy/front-door/mint.sh --protected-name front.example --passthru-name passthru.example
```

That mints the authority where `call/0040` requires it, signs the front's leaf and
the daemon's own identity, and prints the copy commands for the front and the three
settings for the daemon. On the front, as root:

```
sh deploy/front-door/install.sh --public-port 8443 \
    --protected-name front.example --protected-upstream 127.0.0.1:8080 \
    --passthru-name passthru.example
```

It writes the root, the relay, the rendered configuration and both units, checks
the configuration with `nginx -t`, and starts them. Then the edge: **ingress**, from
`0.0.0.0/0`, one rule for TCP and another for UDP on that port, with the **source
port range left empty**. A source port range there admits only packets whose source
port matches, which is how one front lost every connection even though its rules
looked right. Persist the host's own firewall rules separately, and point the daemon at
the front with `--poke <front>:$port`, `--client-identity`, `--front-anchor`,
`--front-endpoint` and `--front-name`.

## The relay learns the tuple and carries the datagrams

`deploy/front-door/poke-listener.py` is the front's relay. It owns the public UDP
port, so the daemon's pokes land on its socket and teach it the line's tuple, and
every datagram that is not a poke leaves for that tuple from that same socket.
`install.sh` runs it as a unit; run by hand it takes the port, the table's path, the
name this front serves, and a reload command:

```
poke-listener.py --listen 0.0.0.0:8443 --name passthru.example \
    --out /etc/front-door/upstreams.map --udp-port 8443 --udp-only \
    --http-listen 127.0.0.1:8448 --lease 300 --reload "nginx -s reload"
```

Two views teach it, in a fixed order, which
[call/0046](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0046-the-front-learns-from-the-poke-and-from-the-push.md)
records. The poke's own source is authoritative for its protocol while the lease
holds it, and the table the daemon's control-channel push carries fills a protocol
the poke has not reached. Every line the status file and the answer carry names the
view that supplied it, so a fallback never wins quietly and a protocol with neither
says so. `--udp-only` leaves the port's TCP half to nginx, where the name split
lives.

One flow at a time holds the socket: a datagram from a new client takes it over,
and the tuple's own datagrams go back to that client. A front serving
many datagram clients at once wants the carrier's admission to accept them by
address alone, which the measurements have not yet shown.

The TCP leg is the next piece, and it is why the poke's dial on that port is routed
to the relay's place in the configuration: a TCP arrival has to carry the port the
poke was addressed to as its source, and a socket that listens there cannot also
originate from it.

## Mint a client

The front demands a client certificate on a protected name, and the authority for
that certificate lives on the line. `deploy/front-door/mint-client.py` holds the
authority, checks a password against the store the daemon keeps, and signs a
certificate that carries what its identity may reach:

```
printf '%s\n' "$password" | python3 mint-client.py \
    --store /tmp/dslp/dp.tsv --name alice --allow passthru.example \
    --ca-dir /etc/front-door/ca --out-dir /etc/front-door/clients
```

The password arrives on standard input, so it stays out of a process list and out
of a shell history. The identity must hold the role named by `--require-role`,
which defaults to `Admin`, and the store's roles decide that. The certificate's
subject carries the identity in its common name and the name it may reach in its
organisational unit, which is the part the front reads.

The front needs the public half of the authority, and nothing else about it:

```
ssl_client_certificate /etc/front-door/ca/ca.crt;
```

## Hold the port

A slot is one mapping. Ask for one from a LAN client over the PCP or UPnP facade,
or declare it as a static entry. A granted slot is remembered, so it comes back
after a restart:

```
40001   1       192.168.21.97   443     0       600     1790511683      1790511085      6
```

The columns name the inner port the daemon binds, the kind, the client that asked,
the client's own port, the requested external port, the granted lifetime, and the
protocol. While the slot lives, the daemon writes two files: `tuple` holds a tuple
for the line, and `tuple-<R>` holds the tuple for that slot, where `<R>` is the
inner port. Those files carry the carrier's assigned address and port, learned by
STUN and confirmed against a second server before it is published.

A TCP slot learns its tuple by dialling a STUN server over TCP, and it can use
only a server that answers there. The default list carries one; a list without such
a server leaves TCP slots with no tuple at all, and the facade then answers
`NETWORK_FAILURE` for a mapping that does exist.

## The front has to be a peer

The carrier admits a peer the line has spoken to, and refuses everything else. A
front therefore cannot reach a held port by knowing its address, and the daemon
pokes it:

```
--poke 170.9.238.141:8443
```

Every keepalive interval, each slot's own socket sends a short datagram to that
address, which is the front's public port and the socket the relay holds. A TCP slot
does the same with a connection, opened on a fresh port folded to the slot. The peer
then sees the line's tuple in the traffic it receives, and it can answer. A UDP
reply arrives with the peer's own address and port intact, which is what a service
in the LAN will see. The reply to a TCP slot reaches the client that asked for the
mapping, on that client's own port.

The front's own provider has a part here too. The carrier admits the peer by the
tuple it spoke to, so the front's datagrams have to leave with the port the poke was
addressed to. A provider that rewrites the source port of what its host sends
breaks that, and the front's traffic is refused at the carrier with nothing on the
line to show for it. Check it before blaming the front: send from the host and look
at what arrives, or run the two captures the milestone's results describe.

## The return path

Whatever answers on the LAN side must reach the peer down the line the mapping is
on. The router sends most traffic out its default route, which is not that line, so
a service host needs an egress rule for the peer's address:

```
ip rule add from <service host> to <peer> lookup 1001 prio 25002
```

The consoles on this network carry rules of their own and work for that reason. A
granted TCP slot needs none: the daemon's own connection to the client originates
from its bind address, which carries the rule already, so the reply takes the line
the mapping is on.

## What the carrier decides, not you

- The external port belongs to the carrier. A request for a port is a key, and it
  is not a promise. `PREFER_FAILURE` is refused for that reason.
- Each slot has an external port of its own, and the carrier can move it. The
  daemon republishes the change, and the peer learns the new tuple from the next
  poke.
- A mapping lives only while the line keeps writing to it. The keepalive interval
  is the mapping's lifetime, and the UDP mapping is dropped within seconds of
  silence.

## What a front door gives you, and what it gives up

A name over TLS is served from a port the carrier holds, with no tunnel anywhere.
The datagram leg carries HTTP/3 and QUIC, since both ride UDP, and by default one
client at a time holds its socket. Over UDP the service sees the client's own
address. Over TCP it does not, because the daemon's splice originates the
connection; where the front terminates a name, PROXY protocol is the only way that
address survives.

A tunnel of the kind David Álvarez Rosa describes in
[Self-Hosting Behind CGNAT](https://david.alvarezrosa.com/posts/self-hosting-behind-cgnat/)
still buys three things this does not: one address for arbitrarily many ports, an
address that does not follow the carrier's assignment, and independence from the
transport. That post is the inspiration for the front-door use case, and its
bridge is a fine answer when a static address is not on offer.

## Where the reasoning is recorded

The plans and decisions for this component live in the host repository, so these
are links out.

- [call/0038](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0038-the-front-door-is-a-held-port.md)
  settles the shape: the two classes of name, and the lease.
- [plan/0012](https://github.com/slartibardfast/agentic-ds-lite-punch/tree/main/plan/0012-the-front-door)
  carries the tasks, and its results directory holds the measurements this page
  summarises: the carrier's admission rule, the STUN-over-TCP finding, and the
  return path.
- [call/0045](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0045-the-control-channel-carries-the-tuple-the-front-sees.md)
  gives the control channel its payload, and
  [call/0046](https://github.com/slartibardfast/agentic-ds-lite-punch/blob/main/call/0046-the-front-learns-from-the-poke-and-from-the-push.md)
  fixes the order of the front's two views.
- [plan/0013](https://github.com/slartibardfast/agentic-ds-lite-punch/tree/main/plan/0013-the-fronts-two-views)
  released the two views, and
  [plan/0014](https://github.com/slartibardfast/agentic-ds-lite-punch/tree/main/plan/0014-the-fronts-legs)
  carries the legs on the poked socket, with its results holding the admission
  measurements and the datagram leg's run.