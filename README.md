# ds-lite-punch

CGNAT-aware UDP relay for the Virgin Media Ireland ds-lite softwire, plus PCP
and UPnP IGDv1 facade work — **code only** (design docs and the operational
agentic structure live in the rope-agentic monorepo and will be moved here
later).

- Single-binary Rust daemon holding a live CGNAT mapping via STUN and
  forwarding inbound UDP to a br-lan target with source preserved.
- Built for the ImmortalWrt router host: musl-static
  `x86_64-unknown-linux-musl`, no TLS, leanish deps.

## Layout

| Path | What |
|---|---|
| `src/` | crate code (STUN codec, slot table with PCP/UPnP indices, mapping state machine, forward, nft, observation engine) |
| `deploy/` | procd init script, env, install.sh |

## Build

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

Formal verification via `cargo kani` over the parser and pure state machine
(bit-precise, all inputs).