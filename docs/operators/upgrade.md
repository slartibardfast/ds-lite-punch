# Upgrade, roll back, and remove ds-lite-punch

The version in a release is the version of the source that built it. Read it in
either place:

```sh
ds-lite-punch --version
cat artifact-record.txt
```

## How a release is made

A release starts at a version bump in the source, and the bump must carry a
matching annotated tag. The tag is the release:

1. The version in `Cargo.toml` moves.
2. The tag `vX.Y.Z` is pushed.
3. The release lane builds the binary from the tagged commit, inside a
   digest-pinned toolchain image, and prints the build path and the sha256.
4. The lane attaches the binary, `ds-lite-punch.8` and `artifact-record.txt` to
   the release.

A release whose tag is spent can never be re-created, so a mistake ships as the
next version.

## Upgrade

1. Note what you are running now, so a roll back is a copy rather than a guess:

   ```sh
   sha256sum /usr/bin/ds-lite-punch
   ds-lite-punch --version
   ```

2. Take the new binary and its manual page from the releases page:

   ```text
   https://github.com/slartibardfast/ds-lite-punch/releases
   ```

3. Check the binary against the recorded hash:

   ```sh
   sha256sum ds-lite-punch
   cat artifact-record.txt
   ```

4. Park the binary you have, and install the new one:

   ```sh
   cp /usr/bin/ds-lite-punch /usr/bin/ds-lite-punch.prev
   ssh root@ROUTER 'cat > /usr/bin/ds-lite-punch' < ds-lite-punch
   ssh root@ROUTER 'chmod 755 /usr/bin/ds-lite-punch'
   ```

5. Install the manual page, and restart the service:

   ```sh
   ssh root@ROUTER 'cat > /tmp/ds-lite-punch.8' < ds-lite-punch.8
   ssh root@ROUTER 'mkdir -p /usr/share/man/man8 && \
       cp /tmp/ds-lite-punch.8 /usr/share/man/man8/ds-lite-punch.8 && \
       chmod 644 /usr/share/man/man8/ds-lite-punch.8'
   ssh root@ROUTER '/etc/init.d/ds-lite-punch restart'
   ```

6. Check the new start:

   ```sh
   ssh root@ROUTER 'ds-lite-punch --version; cat /run/ds-lite-punch/tuple'
   ssh root@ROUTER 'logread | grep ds-lite-punch | tail'
   ```

Your configuration is untouched by an upgrade. The service reads
`/etc/ds-lite-punch.env` at every start.

## Roll back

```sh
ssh root@ROUTER 'cp /usr/bin/ds-lite-punch.prev /usr/bin/ds-lite-punch'
ssh root@ROUTER '/etc/init.d/ds-lite-punch restart'
```

The configuration file, the allowlist and the ACL file are shared by both
versions, so a roll back needs only the binary. A version that changed a
configuration default is named in that version's release notes.

## Remove

The service script reverts the datapath when it stops, so stop it before you
remove the files:

```sh
ssh root@ROUTER '/etc/init.d/ds-lite-punch stop'
ssh root@ROUTER '/etc/init.d/ds-lite-punch disable'
```

The stop path removes the daemon's own table, the accept rules it inserted, and
its policy route. Then remove what the installer placed:

```sh
ssh root@ROUTER 'rm -f /usr/bin/ds-lite-punch /usr/bin/ds-lite-punch.prev \
    /etc/init.d/ds-lite-punch /etc/ds-lite-punch.env \
    /etc/ds-lite-punch.allow /etc/ds-lite-punch.acl \
    /usr/share/man/man8/ds-lite-punch.8'
```

The state directory is on a temporary filesystem and needs no cleanup.

## Where to go next

- [Install](install.md) the daemon.
- [Configure](configure.md) it.
- [Troubleshoot](troubleshoot.md) a failure.