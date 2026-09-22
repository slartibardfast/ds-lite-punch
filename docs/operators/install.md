# Install ds-lite-punch

This page installs ds-lite-punch on a router that runs OpenWrt or ImmortalWrt.
The service manager is procd. The daemon holds one mapping on a ds-lite line and
forwards inbound traffic to one host on the local network.

## What you need

- A router with OpenWrt or ImmortalWrt, procd, and nftables. The daemon installs
  its datapath with `nft`.
- A ds-lite line: IPv4 over a tunnel to a carrier AFTR, with the carrier's CGNAT
  in front.
- Root access over ssh.
- The release binary, or a build of the same source. The binary is static musl,
  so the router needs no libraries for it.

The daemon needs the tuple of the line. Read the address on the CGNAT-facing
interface of the router, and the address of the local host that receives inbound
traffic. These two values are `BIND` and `TARGET` later in this page.

## Get the binary

Take the binary from the releases page:

```text
https://github.com/slartibardfast/ds-lite-punch/releases
```

A release carries three assets:

| Asset | What it is |
|---|---|
| `ds-lite-punch` | the static binary |
| `ds-lite-punch.8` | the manual page |
| `artifact-record.txt` | the build path and the sha256 of that binary |

Check the binary against the recorded hash before you install it:

```sh
sha256sum ds-lite-punch
cat artifact-record.txt
```

The two hashes must agree. The same source and the same toolchain are recorded
in the host repository's `.host-software` file, which is the anchor for the
project's own deployment.

A build from source is a second compiler. Use it for a test line only:

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

## Copy the files to the router

The `deploy/` directory of the source holds the service script, a sample
configuration, the installer, and the manual page. Collect them in one directory
on the router, and put the binary in place.

```sh
scp ds-lite-punch deploy/install.sh deploy/ds-lite-punch.init \
    deploy/ds-lite-punch.env root@ROUTER:/tmp/ds-lite-punch/
scp ds-lite-punch root@ROUTER:/usr/bin/ds-lite-punch
chmod 755 /usr/bin/ds-lite-punch
```

Many ImmortalWrt builds carry no `scp` binary. Where that is the case, pipe the
files over ssh instead:

```sh
ssh root@ROUTER 'cat > /usr/bin/ds-lite-punch' < ds-lite-punch
ssh root@ROUTER 'mkdir -p /tmp/ds-lite-punch'
ssh root@ROUTER 'cat > /tmp/ds-lite-punch/install.sh' < deploy/install.sh
```

## Set the configuration before the first start

The sample `ds-lite-punch.env` comes from one working line. Change at least two
values before the service starts.

| Key | What to put there |
|---|---|
| `BIND` | the address and port the daemon binds on the CGNAT-facing interface, as `ip:port`. The carrier maps this tuple. |
| `TARGET` | the local host and port that receives inbound traffic, as `ip:port`. |
| `GATEWAY` | the next hop on the CGNAT-facing interface. It is used to send the STUN writes out the right line. |

The full list of keys is in the [configuration](configure.md) page.

## Run the installer

```sh
cd /tmp/ds-lite-punch
sh install.sh
```

The installer does these things:

1. Copies the service script to `/etc/init.d/ds-lite-punch` with mode 755.
2. Writes the sample configuration to `/etc/ds-lite-punch.env`, and only when no
   file is there yet.
3. Creates `/etc/ds-lite-punch.allow` as an empty file. That file names the
   devices the keepalive acts for.
4. Puts the manual page at `/usr/share/man/man8/ds-lite-punch.8`.
5. Enables the service, restarts it, and prints the status, the mapping, and the
   next steps.

The installer is safe to run again. A file that is already present is kept.

## Check the first start

The daemon writes the mapping to the state directory as soon as STUN has
answered. The exchange takes a second or two.

```sh
cat /run/ds-lite-punch/tuple
logread | grep ds-lite-punch
```

The `tuple` file holds the external address and port as the carrier reports
them. Two log lines tell you the daemon is well:

```json
{"event":"start","bind":"...","target":"...","stun_servers":[...],"slots":...}
{"event":"tuple","ip":"...","port":...}
```

If the service starts and stops in a loop, read the log. The daemon prints
`error:` and the full help text when the command line is bad. See
[troubleshoot](troubleshoot.md).

## Seed the first DeviceProtection identity

The UPnP facade gates its actions by the DeviceProtection service. The store for
it lives in the state directory, which is a temporary filesystem, so it is
seeded at every start from `/etc/ds-lite-punch.acl`. Until that file holds an
identity, every gated action answers `606`.

Write the first identity in the ACL file, and restart the service:

```sh
vi /etc/ds-lite-punch.acl
/etc/init.d/ds-lite-punch restart
```

The format is one tab-separated row per entry, and the same as the store the
daemon keeps:

```text
U<TAB>name<TAB>salt-hex32<TAB>stored-hex32<TAB>roles
A<TAB>name<TAB>alias-or-dash<TAB>id-hex32<TAB>roles
```

`stored` is the first 128 bits of PBKDF2-HMAC-SHA-256 of the password with
`name || salt` and 5000 iterations. Two roles sit below `Admin`: `Public` and
`Basic`. Holding `Admin` satisfies `Basic` as well. Set
`DEVICE_PROTECTION_ACL=none` to disable the seed and keep the store empty.

## Where to go next

- [Configure](configure.md) the daemon: the keys, the facade, the keepalive, and the
  carrier watch.
- [Operate](operate.md) it: the state files, the log events, and how to check a
  mapping from outside the line.
- [Upgrade](upgrade.md) it to a new release, or undo one.
- [Troubleshoot](troubleshoot.md) the failures that are measured on this line.
- Read the manual page: `man ds-lite-punch` where a reader is installed, and
  `ds-lite-punch --help` on the router, which has no manual reader.