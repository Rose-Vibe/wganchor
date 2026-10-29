# WireGuard: Interface Creation, Config, and Keys

Companion to `docs/arch/overview.md` (routing/packet path) and
`docs/arch/config-and-lifecycle.md` (config file format/location) — this
doc covers the WireGuard-specific mechanics: how the interface and keys
get created, and the config schema that drives them.

## Interface & peer management: shell out, no Go WireGuard dependency

`wganchor` drives `ip` (iproute2) and `wg`/`wg-quick` (wireguard-tools) via
`os/exec`, rather than a library like `wgctrl-go` or `vishvananda/netlink`.
`wgctrl-go` only *configures* an existing device — creating one still needs
`ip link add` either way — and both machines already require
`wireguard-tools`/`iproute2` installed, so shelling out adds no new runtime
dependency. This also matches CLAUDE.md's "no external frameworks for
simple tasks": zero third-party Go module dependencies for the core
interface/routing path.

## Interface name and port: don't collide with a "typical" WireGuard setup

A machine running `wganchor` might also run an unrelated WireGuard VPN set
up the conventional way. Two defaults keep the two from colliding without
someone going out of their way to make that happen:

- **Interface name: `wganchor0`**, not `wg0`. `wg0` is the name nearly
  every WireGuard tutorial and `wg-quick` config uses, making it the most
  likely name to already exist on a box for an unrelated reason.
  `wganchor` creates its own `wganchor0` via `ip link add wganchor0 type
  wireguard` and never reads or writes anything under `/etc/wireguard/`
  (its config lives at `/etc/wganchor/0.json`, per
  `config-and-lifecycle.md`) — it has no path by which it could interact
  with an existing `wg-quick`-managed setup at all.
- **Default `listen_port`: `60217`**, not `51820`. `51820` is the
  universally-used WireGuard default, and multi-tunnel setups that
  increment from it (`51820`, `51821`, ...) are common enough that a
  neighboring port doesn't buy independence either. `60217` has no
  relationship to `51820` and sits in the IANA dynamic/private range
  (49152–65535). Fully overridable via the `listen_port` config field.

Neither choice is a hard guarantee against collision, but both clear the
bar of "you'd have to deliberately pick the same unusual values to
conflict."

## Multiple instances: `wganchor0`, `wganchor1`, ...

The interface is numbered (`wganchor0` implying `wganchor1` is possible)
for one specific case: **a second, independent tunnel relationship** —
e.g. a second, unrelated VPS acting as its own relay provider, with its own
keypair and endpoint. This is what `--instance <N>` is for.

**More relay IPs through the same tunnel** (e.g. a second Vultr secondary
IP relayed to the same home machine) does *not* need a second instance —
WireGuard peers support multiple `AllowedIPs`, so a second relay IP is just
another entry in that one tunnel's `relay_ips` list (see "Config schema"
below). Vultr also caps additional IPs at 2 per instance, so this ceiling
is small regardless.

One uniform formula, with `N=0` as the unspecial default (`--instance=0`
is always valid and always identical to omitting the flag):

- Interface: `wganchor<N>`.
- Config file (when `--config` isn't given explicitly): `/etc/wganchor/
  <N>.json`, or `$XDG_CONFIG_HOME/wganchor/<N>.json` for the user-level
  lookup step.
- `listen_port` default: `60217 + N`. `N=0` gives `60217`.
- Systemd unit: the templated form, `wganchor-server@<N>.service` /
  `wganchor-client@<N>.service` (`config-and-lifecycle.md`). `wganchor
  install server` with no `--instance` installs/enables instance `0` as
  `wganchor-server@0.service` — an ordinary systemd template
  instantiation, not a special-cased flat unit name.

## Keys

Generated the same way as the interface: `wg genkey` / `wg pubkey`, shelled
out — no `golang.org/x/crypto/curve25519` dependency. Storage location and
file-mode enforcement are decided in `docs/arch/config-and-lifecycle.md`.

**The private key never appears as a command-line argument** — any
process's argv is readable by other users via `/proc/<pid>/cmdline`. Key
delivery to WireGuard uses `wg set <iface> private-key /dev/stdin` (the key
piped over stdin), not a temp file: this VPS's AppArmor profile
(`/etc/apparmor.d/wg`) confines `/usr/bin/wg` to only open files under
`/etc/wireguard/`, so a temp file anywhere else fails with `fopen:
Permission denied`. `/dev/stdin` sidesteps that confinement entirely and
never writes the key to disk even transiently, which this project
deliberately never does under `/etc/wireguard/` (see "Interface name and
port" above).

**Who generates them**: the subcommand that first needs a keypair
generates one if the config doesn't already have it — `wganchor server`
and `wganchor client` each self-provision on first run, rather than a
separate `keygen` step.

**Exchange**: manual/file-based — whoever sets up the second side copies
the first side's public key and endpoint into their config by hand.
`wganchor pair` (see `docs/sprints/pairing/plan-pairing.md`) automates
*performing* that manual step over SSH (or any user-supplied
`--remote-exec`); each side's half is still just `wganchor pair
pubkey`/`wganchor pair peer`, runnable by hand exactly as before. There is
no separate auto-exchange protocol or trust mechanism beyond WireGuard's
own pubkey pairing.

## Known gaps

- **Stale peers are never removed.** `ConfigureInterface` only ever *adds*
  a peer via `wg set ... peer <new> ...` — there is no code path that
  removes a peer no longer referenced by config. Changing
  `peer_public_key` and re-running `server`/`client` does not swap the
  live interface's authorized peer; it adds the new key as an *additional*
  authorized peer while the old one remains live and handshake-capable,
  with no visible symptom (the old peer's handshake counter looks exactly
  as healthy as before). Fixing `ConfigureInterface` to prune stale peers
  is future work.
- **`wganchor watch` doesn't cover `AllowedIPs` drift on the server role.**
  `watch`'s periodic reconciliation (`internal/watch/watch.go`) only calls
  the `Reconcile*` routing functions, never `ConfigureInterface` — so on
  the **server** role specifically, if something external ever reset the
  live peer's `AllowedIPs` between `relay add`/`remove` calls, `watch`
  would not repair that (only a fresh `relay add`/`remove` or a full
  `server` bring-up re-applies it). No evidence this happens in practice,
  unlike the `ip rule`-flush behavior `docs/arch/resilience.md` addresses.

## PersistentKeepalive

25 seconds — the standard default used by `wg-quick`/most WireGuard
tooling (including Tailscale) for NAT traversal. Set on the home (NAT'd)
side's peer config only; not needed on the VPS side, which has a public,
stable endpoint.

## Config schema (WireGuard-relevant fields)

Per `docs/arch/config-and-lifecycle.md`'s JSON format. Fields needed by
both `server` and `client`:

- `private_key` — this side's WireGuard private key.
- `peer_public_key` — the other side's public key.
- `peer_endpoint` — `host:port` to dial (the VPS's *primary* IP, never one
  of the `relay_ips`, since a relay IP isn't bound anywhere to receive a
  WireGuard handshake) — set on the home/client side only; the VPS side
  has no endpoint to dial, it waits for the client's handshake.
- `listen_port` — UDP port WireGuard listens on (VPS side). Defaults to
  `60217 + N` (see above), overridable. This is a persisted config field,
  not a runtime-only default: `wganchor install` writes the concrete value
  into the generated config skeleton, so the same port is read back on
  every start, including after a reboot — only the keypair is ever
  self-provisioned at runtime, the port is not.
- `interface_name` — defaults to `wganchor<N>` (see above), overridable.
- `relay_ips` — list of secondary IPs relayed through this one tunnel
  (e.g. `["203.0.113.20"]`). A list, not a single value, because multiple
  relay IPs through the *same* tunnel are expected to be normal (see
  "Multiple instances" above) — each entry gets its own VPS-side route
  (`ip route replace <ip>/32 dev wganchor<N>`) and its own `/32` entry in
  the VPS-side peer's `AllowedIPs`. This reimplements `wg-quick`'s own
  `AllowedIPs`-derived routing behavior manually, since the Go
  implementation shells out to `ip`/`wg` directly rather than invoking
  `wg-quick`. The home/client-side peer's `AllowedIPs` is **not** scoped to
  `relay_ips` at all — it's always `0.0.0.0/0` regardless of how many relay
  IPs are configured (WireGuard's own cryptokey routing drops any outbound
  packet whose destination isn't covered by the sending peer's
  `AllowedIPs`); see "Client-side policy routing" below for how the client
  avoids that wide `AllowedIPs` becoming a hijacked default route. Adding a
  second Vultr secondary IP later is a one-line config change (append to
  the list), not a schema or interface change.
- `persistent_keepalive` — defaults to `25`, overridable.

This schema is additive by design (JSON was chosen specifically to make
schema growth cheap) — new fields extend it rather than restructure it.

## Client-side policy routing: table/priority formula

Because the client-side peer's `AllowedIPs` is always `0.0.0.0/0` (see
above) but must **not** become a kernel-wide default route on a shared,
multi-purpose home machine, the client never lets `wg-quick`-style
`AllowedIPs`-derived routing run at all. Instead, for each `relay_ips`
entry the client:

1. Assigns the address to the interface (`ip addr replace <ip>/32 dev
   wganchor<N>`) — this alone makes the address locally bindable, via the
   kernel's automatic scope-host "local" route.
2. Adds a policy route so traffic *sourced from* that address goes out
   through the tunnel regardless of destination: an `ip rule from <ip>
   table <table>` entry, plus `ip route replace default dev wganchor<N>
   table <table>`.

**Table ID and rule priority are derived deterministically from the
instance number**, reusing the already-collision-checked listen-port
formula (`60217 + N`) rather than a second constant:

- `table = 60217 + N`
- `priority = 20217 + N` (i.e. `(60217 + N) - 40000`)

Instance `0` gives table `60217`, priority `20217`. Every valid instance
number (`0`–`5318`, per the `--instance` bounds check) stays clear of the
kernel's own reserved priorities (`0`, `32766`, `32767`) by construction.
