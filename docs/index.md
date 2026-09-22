# ds-lite-punch

**DS-Lite Proxy UPnP NAT/CGNAT Holder.**

A small static daemon for an OpenWrt or ImmortalWrt router at the end of a
ds-lite line. It holds one mapping through the carrier's CGNAT, forwards inbound
UDP and TCP to a host on the local network, and answers UPnP IGD, PCP and
NAT-PMP on the LAN.

The binary is Rust, built for `x86_64-unknown-linux-musl`. It is about one
megabyte, and procd manages it as one service.

## For operators

| Page | What it covers |
|---|---|
| [Install](operators/install.md) | the release, the hash check, the files, the first start, the DeviceProtection seed |
| [Configure](operators/configure.md) | every key of `/etc/ds-lite-punch.env`, the facade, the hold, the carrier watch |
| [Operate](operators/operate.md) | the state files, the log events, the rules, and how to check a mapping from outside the line |
| [Upgrade](operators/upgrade.md) | how a release is made, the upgrade, the rollback, and the removal |
| [Troubleshoot](operators/troubleshoot.md) | the failure cases measured on a working line |

## Reference

- The manual page:
  [`deploy/man/ds-lite-punch.8`](https://github.com/slartibardfast/ds-lite-punch/blob/main/deploy/man/ds-lite-punch.8),
  which ships in every release as `ds-lite-punch.8`.
- The command line: `ds-lite-punch --help` on the router, which prints the same
  text the manual page is generated from.
- The UPnP service transcriptions:
  [DeviceProtection:1](upnp-dp1/TRANSCRIPTION.md) and
  [WANIPConnection:2](upnp-wip2/TRANSCRIPTION.md).

## The code and the thought

The daemon's source is in this repository, together with the deployment files
under `deploy/` and the CLI authoring tool under `tools/argdoc/`.

The plans, the decisions and the measured results for this component are in the
host repository:
[agentic-ds-lite-punch](https://github.com/slartibardfast/agentic-ds-lite-punch).

## Releases

```text
https://github.com/slartibardfast/ds-lite-punch/releases
```

A release carries the binary, the manual page, and a text file naming the build
path and the sha256 of the binary.