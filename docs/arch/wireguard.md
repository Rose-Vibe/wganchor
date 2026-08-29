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

## Interface name and port: don't collide with a "typical" WireGuard setup

`wganchor` uses WireGuard, but a machine running it might also be running an
unrelated WireGuard VPN (a personal tunnel, a corporate client, etc.) set up
the conventional way. Two defaults are chosen specifically so the two never
step on each other without someone going out of their way to make that
happen:

- **Interface name: `wganchor0`**, not `wg0`. `wg0` is the name essentially
  every WireGuard tutorial, `wg-quick` example config, and NetworkManager
  profile uses — it's the single most likely interface name to already
  exist on a box for an unrelated reason. `wganchor` creates its own
  `wganchor0` via `ip link add wganchor0 type wireguard` and never reads or
  writes anything under `/etc/wireguard/` (its config lives at
  `/etc/wganchor/0.json`, per `config-and-lifecycle.md`) — so it has no
  path by which it could interact with an existing `wg-quick`-managed setup
  at all, let alone collide with one.
- **Default `listen_port`: `60217`**, not `51820`. `51820` is the
  IANA-unassigned-but-universally-used default baked into virtually every
  WireGuard example, and multi-tunnel setups that increment from it
  (`51820`, `51821`, `51822`, ...) are common enough that picking a
  neighboring number doesn't actually buy independence. `60217` has no
  relationship to `51820` and isn't part of that incrementing pattern — it's
  just a fixed, arbitrary port in the IANA dynamic/private range
  (49152–65535, never assigned to a registered service), documented here so
  both sides agree on it without needing to negotiate. It's still fully
  overridable via the `listen_port` config field for anyone who wants
  something else.

Neither choice is a hard guarantee against collision — any interface name
or port can theoretically already be in use — but both clear the bar of
"you'd have to deliberately pick the same unusual values to conflict,"
rather than colliding with the common-case default setup.

## Multiple interfaces: `wganchor0`, `wganchor1`, ... (naming reserved, not built)

Numbering the interface (`wganchor0` implying a `wganchor1` is possible) is
deliberate, but it's reserved for one specific scaling need, not "more
relay IPs" in general:

- **More relay IPs through the same tunnel** (e.g. a second Vultr secondary
  IP relayed to the same home machine) does **not** need a second
  interface. WireGuard peers already support multiple `AllowedIPs` — a
  second relay IP is just another route plus another `AllowedIPs` entry on
  the existing peer on `wganchor0`. (Vultr also caps additional IPs at 2
  per instance, so this ceiling is small regardless — see
  `plan-research.md`.)
- **A second, independent tunnel relationship** — e.g. a second, unrelated
  VPS acting as its own relay provider, with its own keypair and
  endpoint — is what `wganchor1` is for. That's a genuinely separate
  thing, not a bigger version of the first.

Decided now as one uniform formula, not a default case plus a special
case for it — `0` is not special-cased, it's just what an unspecified
`--instance` resolves to, and `--instance=0` is always valid and always
identical to omitting the flag:

- Interface: `wganchor<N>`.
- Config file (when `--config` isn't given explicitly): `/etc/wganchor/
  <N>.json`, or `$XDG_CONFIG_HOME/wganchor/<N>.json` for the user-level
  lookup step. Today's only instance is therefore `/etc/wganchor/0.json`
  — not a specially-named `config.json` — precisely so that adding a real
  `--instance` flag later never renames a file that's already in use.
- `listen_port` default: `60217 + N` (still overridable per-config, still
  needs the collision check from `plan-environment.md`). `N=0` gives
  `60217`, unchanged from above.
- Systemd unit: always the templated form, `wganchor-server@<N>.service` /
  `wganchor-client@<N>.service` (`config-and-lifecycle.md`). `wganchor
  install server` with no `--instance` installs/enables instance `0` as
  `wganchor-server@0.service` — an ordinary systemd template instantiation,
  not a special flat unit name that would need replacing if a second
  instance shows up later.

The `--instance` flag itself, and everything systemd/install-related, are
still not being built in the bootstrap sprint — there's no second VPS in
scope yet, and building unused multi-instance plumbing now is exactly the
kind of speculative feature CLAUDE.md's conventions argue against. What
*is* in scope now, because the bootstrap sprint's Go skeleton does load a
config file: it must look for `/etc/wganchor/0.json` (and the XDG
equivalent), not `config.json` — see `plan-wireguard-poc.md` — so the
uniform formula is true from the very first line of config-loading code,
not retrofitted when `--instance` is actually implemented.

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
- `peer_endpoint` — `host:port` to dial (VPS's primary IP, *not* any of
  the `relay_ips`, since a relay IP isn't bound anywhere to receive a
  WireGuard handshake) — set on the home/client side only; the VPS side
  has no endpoint to dial, it waits for the client's handshake.
- `listen_port` — UDP port WireGuard listens on (VPS side). Defaults to
  `60217 + N` (see above), overridable; needs the port-collision check
  from `plan-environment.md`. This is a persisted config field, not a
  runtime-only default: `wganchor install` writes the concrete value into
  the generated config skeleton rather than leaving it implicit, so the
  same port is read back on every start — including after a reboot,
  via the systemd unit re-invoking `wganchor` and re-reading this file —
  with nothing resetting or re-deriving it in memory. (Only the keypair is
  ever self-provisioned at runtime; the port is not.)
- `interface_name` — defaults to `wganchor<N>` (see above), overridable in
  case that name itself somehow collides.
- `relay_ips` — list of secondary IPs being relayed through this one
  tunnel (currently `["203.0.113.20"]` for this deployment). A list, not
  a single value, because multiple relay IPs through the *same* tunnel are
  expected to be normal (see "Multiple interfaces" above) — each entry
  gets its own VPS-side route (`ip route replace <ip>/32 dev wganchor<N>`)
  and needs to be reflected in the WireGuard `AllowedIPs` on at least the
  VPS-side peer entry, so WireGuard itself routes traffic for each relay
  IP to the home peer. The exact `AllowedIPs` shape on the home side
  (likely broader, since it's accepting arbitrary internet sources relayed
  through the VPS, not just traffic to/from other relay IPs) is exactly
  the kind of thing `plan-wireguard-poc.md`'s outbound-path test exists to
  pin down empirically before it's asserted here as fact. Adding a second
  Vultr secondary IP later is a one-line config change (append to the
  list), not a schema or interface change.
- `persistent_keepalive` — defaults to `25`, overridable.

This is a minimum for the bootstrap sprint's skeleton to parse; sprint 2
may add fields as the PoC surfaces needs (e.g. explicit interface name,
MTU override) — extend, don't restructure, since JSON was chosen
specifically to make additive schema growth cheap.

## Status

- [x] Interface/peer management approach decided: shell out to `ip`/`wg`.
- [x] Interface name decided: `wganchor<N>` (not `wg0`), `N=0` by default
      and not special-cased, overridable.
- [x] Default listen port decided: `60217 + N` (not `51820`), persisted in
      config (not runtime-only), overridable.
- [x] Multi-interface naming reserved (`wganchor0`, `wganchor1`, ...) for
      independent tunnel relationships, as one uniform formula rather than
      a default plus a special case; multiple relay IPs on one tunnel use
      `relay_ips` + peer `AllowedIPs` instead. `--instance` flag itself
      not implemented — naming/path shape only, kept additive for later.
- [x] Config schema uses `relay_ips` (list), not a single `relay_ip`.
- [x] Key generation approach decided: shell out to `wg genkey`/`wg pubkey`,
      self-provisioned on first run.
- [x] `PersistentKeepalive` interval decided: 25s, home side only.
- [x] Minimum config schema drafted.
- [ ] Schema will likely need small additions once the PoC is run —
      expected, not a gap.
