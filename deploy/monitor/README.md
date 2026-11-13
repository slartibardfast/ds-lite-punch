# The monitors

The standing correlation pair the record calls for: two scripts the
repository emits, so a line anomaly arrives with its mechanism named instead
of as an unexplained silence.

- `external-monitor.py` runs outside the line and watches the published
  path: the protected name's table answer over TLS with the household
  identity, and the passthrough name's certificate against the service's
  own. It exits 0 when every check answered as it currently should and 2
  when one did not, which is what a cron line or a health check keys on.
- `router-sampler.py` stands beside the daemon and samples what the line
  looks like from inside: the daemon's event log since the sampler last
  looked (warn lines are always carried), the WAN interface's byte counters,
  and the conntrack table's weight.

Both emit one JSON line per pass, on stdout, in the same shape, so the two
streams correlate by timestamp. Both take `--interval`; both take `--once`
for a single pass, which is how the carrier environment's harness runs them
against the standing exchange.

On the deployed router the sampler's `--log` is the daemon's own event log
(the init script writes it beside the lease records) and `--iface` is the
line-facing interface. The external monitor runs wherever the vantage is:
the household's second wire, a VPS, or any host that can reach the published
name.
