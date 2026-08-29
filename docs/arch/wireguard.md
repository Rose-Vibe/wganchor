# WireGuard: Interface Creation, Config, and Keys

Companion to `docs/arch/overview.md` (routing/packet path) and
`docs/arch/config-and-lifecycle.md` (config file format/location, which
already covers where keys live on disk — this doc covers the WireGuard-
specific mechanics: how the interface and keys get created).

## Interface & peer management: shell out, don't add a Go dependency

Decision: `wganchor` drives `ip` (iproute2) and `wg`/`wg-quick`
(wireguard-tools) via `os/exec`, rather than using `wgctrl-go` or a
netlink library like `vishvananda/netlink`.

Why:
- `wgctrl-go` only *configures* an existing WireGuard device — it doesn't
  create one. Creating the device still needs `ip link add` or a netlink
  call either way, so pulling in `wgctrl-go` only covers part of the
  problem.
- Both machines already require `wireguard-tools` and `iproute2`
  installed (`plan-environment.md`) — `iproute2` ships standard on both
  Ubuntu images already. Shelling out introduces no *new* runtime
  dependency beyond what's already required.
- The manual PoC (`plan-wireguard-poc.md`) validates the design using
  exactly these commands by hand. Having the Go code run the same
  commands, in the same idempotent forms recorded from the PoC, means the
  automated path is behaviorally identical to what was hand-tested —
  rather than a from-scratch netlink implementation that could diverge in
  some edge case the manual test never hit.
- Matches CLAUDE.md's "no external frameworks for simple tasks": zero
  third-party Go module dependencies for the core interface/routing path.

Consequence: the exact idempotent command forms recorded during the PoC
(`ip addr replace`, `ip route replace`, `ip link add ... type wireguard`
guarded by an existence check, `wg syncconf` or `wg setconf`) are the
actual implementation, not just a reference — `plan-research.md`'s
deliverable to record them is what sprint 2 will translate into
`exec.Command` calls almost directly.

## Keys

Generated the same way: `wg genkey` / `wg pubkey`, shelled out — no
`golang.org/x/crypto/curve25519` dependency, for the same reasons as
above. Storage location and file-mode enforcement are already decided in
`docs/arch/config-and-lifecycle.md`.

**The private key must never appear as a command-line argument.** Any
process's argv is readable by other users via `/proc/<pid>/cmdline` — this
is exactly why `wg genkey` writes to stdout and `wg set ... private-key`
takes a *file path* rather than accepting the key inline. When sprint 2
turns these into `exec.Command` calls, the key reaches `wg` only via a
`0600` file path or stdin, never as an argument. Easy to get wrong if the
PoC's shell commands are copied without this in mind — worth stating
explicitly since the doc above describes the translation as "almost
direct."

Who generates them: the subcommand that first needs a keypair generates
one if the config doesn't already have it (i.e. `wganchor server` and
`wganchor client` each self-provision on first run) rather than a
separate `keygen` step — one less subcommand, and matches "config file
loading, then act on it" being the only thing the bootstrap-sprint
skeleton needs to do. A dedicated `keygen`/`init` subcommand can be added
later if key rotation or pre-provisioning needs it; not required for v1.

Exchange: manual/file-based, as already decided — whoever sets up the
second side copies the first side's public key and endpoint into their
config by hand. No auto-exchange protocol in scope.

## PersistentKeepalive

25 seconds — the standard default used by `wg-quick`/most WireGuard
tooling (including Tailscale) for NAT traversal, and short enough that the
PoC's "idle 5+ minutes, re-test" step will clearly show whether it's
working (a stale NAT mapping would show up well within 5 minutes at a
25s keepalive). Set on the home (NAT'd) side's peer config; not needed on
the VPS side, which has a public, stable endpoint.

## Config schema (WireGuard-relevant fields)

Per `docs/arch/config-and-lifecycle.md`'s JSON format. Minimum fields
needed by both `server` and `client`:

- `private_key` — this side's WireGuard private key.
- `peer_public_key` — the other side's public key.
- `peer_endpoint` — `host:port` to dial (VPS's primary IP, *not* the
  relay IP, since the relay IP isn't bound anywhere to receive a
  WireGuard handshake) — set on the home/client side only; the VPS side
  has no endpoint to dial, it waits for the client's handshake.
- `listen_port` — UDP port WireGuard listens on (VPS side; needs the
  port-collision check from `plan-environment.md`).
- `relay_ip` — the secondary IP being relayed (`203.0.113.20` for this
  deployment) — used by both sides to set up their respective routes /
  local bind address.
- `persistent_keepalive` — defaults to `25`, overridable.

This is a minimum for the bootstrap sprint's skeleton to parse; sprint 2
may add fields as the PoC surfaces needs (e.g. explicit interface name,
MTU override) — extend, don't restructure, since JSON was chosen
specifically to make additive schema growth cheap.

## Status

- [x] Interface/peer management approach decided: shell out to `ip`/`wg`.
- [x] Key generation approach decided: shell out to `wg genkey`/`wg pubkey`,
      self-provisioned on first run.
- [x] `PersistentKeepalive` interval decided: 25s, home side only.
- [x] Minimum config schema drafted.
- [ ] Schema will likely need small additions once the PoC is run —
      expected, not a gap.
