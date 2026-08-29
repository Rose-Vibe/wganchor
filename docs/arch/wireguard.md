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

## Multiple interfaces: `wganchor0`, `wganchor1`, ...

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

**Update: built now, not deferred.** The user has asked for real
`--instance` support from the get-go rather than reserved-but-unbuilt
naming, so the bootstrap sprint's Go skeleton implements the `--instance
<N>` flag itself (default `0`), and uses it to compute the config path,
default interface name, and default `listen_port` per the formula above.
This is pure logic — no live tunnel, no second VPS needed to write or
unit-test it, since the skeleton only parses config and no-ops either way.

What still requires a second VPS, and is *not* happening in the bootstrap
sprint regardless: `install`/`uninstall` and the templated systemd units
are sprint 2 work independent of multi-instance (the bootstrap skeleton
was never going to build those — see `config-and-lifecycle.md`), and
*live, end-to-end validation of two independent tunnels running at once*
needs an actual second, independent VPS to relay from. The user has
offered to provision one on request — ask when implementation actually
reaches that validation point (likely sprint 2, once real WireGuard
automation and `install` exist), rather than assuming it's unavailable or
skipping the test.

## Keys

Generated the same way: `wg genkey` / `wg pubkey`, shelled out — no
`golang.org/x/crypto/curve25519` dependency, for the same reasons as
above. Storage location and file-mode enforcement are already decided in
`docs/arch/config-and-lifecycle.md`.

**The private key must never appear as a command-line argument.** Any
process's argv is readable by other users via `/proc/<pid>/cmdline` — this
is exactly why `wg genkey` writes to stdout and `wg set ... private-key`
takes a *file path* rather than accepting the key inline. Easy to get
wrong if the PoC's shell commands are copied without this in mind — worth
stating explicitly since the doc above describes the translation as
"almost direct."

**Confirmed during the wireguard-automation sprint's implementation: use
`wg set <iface> private-key /dev/stdin`, not a temp file.** A `0600` temp
file (e.g. under the OS temp dir) was tried first and rejected: this
Ubuntu VPS ships an AppArmor profile (`/etc/apparmor.d/wg`) that confines
`/usr/bin/wg` to only open files under `/etc/wireguard/` — a temp file
anywhere else fails with `fopen: Permission denied`, confirmed empirically
against the real VPS, not a flaky/transient error (a similar-looking
`wg-quick` "Permission denied" during the bootstrap PoC was likely the
same underlying confinement, encountered via a different code path).
`wg set <iface> private-key /dev/stdin` (key piped over stdin) sidesteps
the confinement entirely — the key never touches disk at all, which is
strictly better than the temp-file approach even where AppArmor doesn't
confine `wg`, and doesn't require writing anything (even transiently)
under `/etc/wireguard/`, which this project deliberately never touches
(see "Interface name and port" above).

Who generates them: the subcommand that first needs a keypair generates
one if the config doesn't already have it (i.e. `wganchor server` and
`wganchor client` each self-provision on first run) rather than a
separate `keygen` step — one less subcommand, and matches "config file
loading, then act on it" being the only thing the bootstrap-sprint
skeleton needs to do. A dedicated `keygen`/`init` subcommand can be added
later if key rotation or pre-provisioning needs it; not required for v1.

Exchange: manual/file-based, as already decided — whoever sets up the
second side copies the first side's public key and endpoint into their
config by hand. The underlying exchange is still exactly this: a pubkey
and an endpoint landing in the other side's config file, nothing more.
`wganchor pair` (see `docs/sprints/pairing/plan-pairing.md`) automates
*performing* that manual step over SSH (or any user-supplied
`--remote-exec`) — each side's half is still just `wganchor pair
pubkey`/`wganchor pair peer`, runnable by hand exactly as before. There
is still no separate auto-exchange protocol or trust mechanism beyond
WireGuard's own pubkey pairing.

**Known gap, pre-existing but more reachable now that `pair` makes
rewriting `peer_public_key` routine (found reviewing `pair`'s
implementation)**: `ConfigureInterface` only ever *adds* a peer via `wg
set ... peer <new> ...` — there is no code path anywhere that removes a
peer no longer referenced by config. Practically, this means changing
`peer_public_key` and then re-running `server`/`client` does not swap
the live interface's authorized peer; it adds the new key as an
*additional* authorized peer while the old one remains live and
handshake-capable, with no visible symptom (the old peer's handshake
counter looks exactly as healthy as before). Not a `pair`-specific bug —
`pair` never touches the live interface at all (see above) — but worth
knowing before treating "change the config, then re-run" as equivalent
to "replace who's authorized." Fixing `ConfigureInterface` to prune
stale peers is future work, not part of this plan.

**Related known gap (`relay add`/`remove`, `wganchor relay` sprint)**:
`wganchor watch`'s periodic reconciliation backstop (`internal/watch/watch.go`) only
ever calls the `Reconcile*` routing functions on its interval, never
`ConfigureInterface` — so on the **server** role specifically, if
something external ever reset the live peer's `AllowedIPs` between
`relay add`/`remove` calls, `watch` would not repair that on its own
(only a fresh `relay add`/`remove` or a full `server` bring-up
re-applies it). No evidence this happens in practice, unlike the `ip
rule`-flush behavior `docs/arch/resilience.md` addresses; noted here as a
known gap, not fixed.

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
  and is reflected in the VPS-side peer's `AllowedIPs`, one `/32` per
  entry — this is exactly `wg-quick`'s own `AllowedIPs`-derived routing
  behavior, reimplemented manually since the Go implementation shells out
  to `ip`/`wg` directly rather than invoking `wg-quick`. **Confirmed
  empirically** (bootstrap PoC, then re-confirmed live during the
  wireguard-automation sprint): the home/client-side peer's `AllowedIPs`
  is **not** scoped to `relay_ips` at all — it's always `0.0.0.0/0`,
  independent of how many relay IPs are configured, because WireGuard's
  own cryptokey routing (not just the kernel routing table) drops any
  outbound packet whose destination isn't covered by the sending peer's
  `AllowedIPs`. See "Client-side policy routing" below for how the client
  avoids that wide `AllowedIPs` turning into a hijacked default route.
  Adding a second Vultr secondary IP later is a one-line config change
  (append to the list), not a schema or interface change.
- `persistent_keepalive` — defaults to `25`, overridable.

This is a minimum for the bootstrap sprint's skeleton to parse; later
sprints may add fields as real usage surfaces needs (e.g. explicit MTU
override) — extend, don't restructure, since JSON was chosen specifically
to make additive schema growth cheap.

## Client-side policy routing: table/priority formula

Because the client-side peer's `AllowedIPs` is always `0.0.0.0/0` (see
above) but must **not** become a kernel-wide default route on a shared,
multi-purpose home machine, the client never lets `wg-quick`-style
`AllowedIPs`-derived routing run at all — no equivalent of `wg-quick`'s
`Table = off` is even needed since the Go implementation never adds such a
route in the first place. Instead, for each `relay_ips` entry the client:

1. Assigns the address to the interface (`ip addr replace <ip>/32 dev
   wganchor<N>`) — this alone makes the address locally bindable, via the
   kernel's automatic scope-host "local" route.
2. Adds a policy route so traffic *sourced from* that address goes out
   through the tunnel regardless of destination: an `ip rule from <ip>
   table <table>` entry, plus `ip route replace default dev wganchor<N>
   table <table>`.

**Table ID and rule priority are derived deterministically from the
instance number**, reusing the already-collision-checked listen-port
formula (`60217 + N`) rather than inventing a second collision-prone
constant:

- `table = 60217 + N`
- `priority = 20217 + N` (i.e. `(60217 + N) - 40000`)

Instance `0` reproduces the exact values validated by hand in the
bootstrap PoC (table `60217`, priority `20217`), checked at the time
against `ip rule show` / `ip route show table all` for collision with an
unrelated, pre-existing fwmark-based VPN app on the test machine
(priorities `5210`–`5270`, table `52`) and against the kernel's own
reserved priorities (`0`, `32766`, `32767`). Every valid instance number
(`0`–`5318`, per the `--instance` bounds check) stays clear of all of
these by construction.

## Status

- [x] Interface/peer management approach decided: shell out to `ip`/`wg`.
- [x] Interface name decided: `wganchor<N>` (not `wg0`), `N=0` by default
      and not special-cased, overridable.
- [x] Default listen port decided: `60217 + N` (not `51820`), persisted in
      config (not runtime-only), overridable.
- [x] Multi-interface naming decided (`wganchor0`, `wganchor1`, ...) for
      independent tunnel relationships, as one uniform formula rather than
      a default plus a special case; multiple relay IPs on one tunnel use
      `relay_ips` + peer `AllowedIPs` instead. `--instance` flag built and
      implemented (bootstrap sprint). Live two-VPS validation still
      deferred (second VPS available from the user on request).
- [x] Config schema uses `relay_ips` (list), not a single `relay_ip`.
- [x] Key generation approach decided and implemented: shell out to
      `wg genkey`/`wg pubkey`, self-provisioned on first run
      (wireguard-automation sprint).
- [x] `PersistentKeepalive` interval decided: 25s, home side only.
- [x] Minimum config schema drafted.
- [x] Client-side `AllowedIPs` confirmed as always `0.0.0.0/0` (cryptokey
      routing, not kernel routing, is what a narrow `AllowedIPs` breaks);
      table/priority formula for the client's policy routing decided and
      implemented — see "Client-side policy routing" above.
- [x] Private-key delivery to `wg set` confirmed as `/dev/stdin`, not a
      temp file path — an AppArmor profile on the target VPS confines
      `/usr/bin/wg` to `/etc/wireguard/` only; see "Keys" above.
- [x] Real interface/key/route automation implemented and live-validated
      against the VPS (wireguard-automation sprint): key self-provisioning,
      idempotent interface/peer setup, and idempotent routing
      reconciliation (including removal of a relay IP dropped from
      config) all confirmed working, inbound and outbound, matching the
      bootstrap PoC's results.
