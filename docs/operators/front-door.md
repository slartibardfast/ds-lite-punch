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
| The front | The name, and admission | nginx routes by name, passes a name through untouched or terminates it and demands a client certificate, and forwards to the carrier's tuple. |
| The client | A certificate, when the name is protected | It reaches the front's address and port, and never learns the carrier's tuple. |

The exchange is two-fold, and it is worth keeping the halves apart. The line's half
opens and keeps the port. The front's half authorises. Each has one channel: a
datagram that opens the port toward a peer, and an authenticated control channel
that carries what the front needs to know.

## The front's configuration

`deploy/front-door/nginx.conf` is the shipped configuration, written as a template
whose tokens name the front's own paths, the carrier tuple for each pass-through
name, and the local block that terminates the protected ones. Two facts about it
matter on Debian and Ubuntu, and both are in the file:

- The stream module is a dynamic module, so the configuration loads it by name.
- The stream module in this nginx release cannot terminate several names on one
  listener, so a protected name is routed to a local `https` block that does the
  terminating. That block holds the only certificate the front has, and it is the
  only place a client certificate is checked.

`deploy/front-door/test-local.sh` proves the split on one machine: it renders the
shipped file with throwaway values, mints a one-day authority and three leaves,
and asserts that a pass-through name reaches the service's own certificate, that a
protected name is refused without a client certificate and served with one, and
that a name nobody published reaches nothing. The component's lane runs it.

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
--poke 170.9.238.141:41001
```

Every keepalive interval, each slot's own socket sends a short datagram to that
address. A TCP slot does the same with a connection, opened on a fresh port folded
to the slot. The peer then sees the line's tuple in the traffic it receives, and it
can answer. A UDP reply arrives with the peer's own address and port intact, which
is what a service in the LAN will see. The reply to a TCP slot reaches the client
that asked for the mapping, on that client's own port.

## The return path

Whatever answers on the LAN side must reach the peer down the line the mapping is
on. The router sends most traffic out its default route, which is not that line, so
a service host needs an egress rule for the peer's address:

```
ip rule add from <service host> to <peer> lookup 1001 prio 25002
```

The consoles on this network carry rules of their own and work for that reason. A
deployment that would rather not configure the service host can wait for the
daemon-side rewrite, which presents the daemon's own bind address and needs no rule.

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
Over UDP, and therefore over QUIC, the service sees the client's own address. Over
TCP it does not, because the daemon's splice originates the connection; where the
front terminates a name, PROXY protocol is the only way that address survives.

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