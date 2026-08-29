# Plan: Tunnel Runtime (real WireGuard automation)

Depends on `docs/arch/wireguard.md` (shell-out approach, key generation,
config schema) and `docs/arch/overview.md`'s "Packet path" section (the
exact mechanism validated empirically in the bootstrap PoC — see
`docs/sprints/archive/2026-08-29-bootstrap/`). Also depends on the existing
`main.go`/`config.go` skeleton at the repo root — this plan extends that,
it doesn't replace it.

## Goal

Turn `wganchor server` and `wganchor client` from "parse config and print
it" into "actually bring up a working WireGuard tunnel and routing," using
the exact idempotent command forms the bootstrap PoC validated by hand —
this is translation, not new design, plus the self-provisioning and
idempotency handling that manual testing didn't need to worry about.

## Role split (per `wireguard.md`'s config schema notes)

- `server` = VPS side: has `listen_port`, waits for a handshake (no
  `peer_endpoint` to dial), owns `relay_ips` and needs the
  `AllowedIPs`-derived forwarding route for each one.
- `client` = home side: dials `peer_endpoint`, sits behind NAT
  (`PersistentKeepalive`), needs the wide-`AllowedIPs` + no-default-route +
  policy-routing mechanism so `relay_ips` can be bound to a local socket
  without hijacking the host's default route.

## Key self-provisioning

- On load, if `Config.PrivateKey == ""`: generate one via `wg genkey`
  (stdout), derive the public key via `wg pubkey` (private key fed over
  stdin, never argv — matches `wireguard.md`'s "never a command-line
  argument" rule), write the generated private key back into the config
  file at the same path it was loaded from, preserving mode `0600`. Print
  the new public key so the operator can copy it into the other side's
  `peer_public_key` — this is the manual "exchange" step `wireguard.md`
  already designed; no auto-exchange protocol.
- If `Config.PeerPublicKey == ""`: refuse to bring up the tunnel (nothing
  to peer with yet) — print an actionable error, don't silently no-op.

## Pre-flight validation (fail fast, actionable errors)

Beyond the `PeerPublicKey` check above, validate before touching any
system state, all with the same "actionable error, no silent no-op"
posture:

- `client` role: refuse if `Config.PeerEndpoint == ""` — a client peer set
  up without an endpoint can never dial out. Without this check it would
  set up a peer that silently never handshakes, with no obvious error,
  which is exactly the failure mode the `PeerPublicKey` check above
  already exists to avoid for the sibling field.
- Both roles: refuse if `Config.RelayIPs` is empty. `server` with no
  relay IPs would set up a peer with an empty `AllowedIPs` (a
  non-functional relay); `client` with none would skip all address/route
  setup and silently do nothing useful. Neither is a valid "nothing to
  do, exit 0" case — it's a misconfiguration, so it errors.
- Validate each `relay_ips` entry parses as an IP (`net.ParseIP`) before
  it reaches any `exec.Command` call. Not a security concern (arguments
  are passed as an argv slice, no shell involved, so there is no
  injection risk) but an unparseable entry should surface as "relay_ips[i]
  is not a valid IP: %q", not an opaque `ip`/`wg` syntax error from a
  failed shell-out three layers down.

## Interface creation (idempotent)

- Check for an existing interface first (`ip link show <name>`, exit code
  — not string-matching output). Only run `ip link add <name> type
  wireguard` if absent; re-running against an already-correct interface
  must not error.
- If `ip link show <name>` succeeds but the interface isn't actually a
  WireGuard device (`interface_name` is operator-overridable, so a
  collision with an unrelated existing interface — a bridge, a veth, an
  unrelated VPN's `wg0` — is possible), fail with an actionable error
  rather than let it surface later as an opaque `wg set` failure. Checked
  via `wg show <name>` (exits non-zero for a non-WireGuard interface).
- Set the private key via `wg set <name> private-key /dev/stdin`, piping
  the key over stdin (private key never touches argv **or disk**).
  **Revised during implementation**: a `0600` temp file was tried first
  and rejected — the target VPS ships an AppArmor profile confining
  `/usr/bin/wg` to only open files under `/etc/wireguard/`, so a temp file
  anywhere else fails with `fopen: Permission denied` (confirmed
  empirically, not a flaky error). `/dev/stdin` sidesteps this cleanly and
  is strictly better regardless of AppArmor, since the key never touches
  disk even transiently. Recorded as a durable decision in
  `docs/arch/wireguard.md`.
- `server` also sets `listen-port <port>` in the same `wg set` call.
- Set the peer: `wg set <name> peer <peer_public_key> allowed-ips
  <computed-per-role> [endpoint <peer_endpoint>] [persistent-keepalive
  25]`. `wg set` is idempotent by construction — setting the same
  peer/allowed-ips twice is a no-op, no existence check needed here
  (unlike interface creation above).
- `AllowedIPs` computed per role:
  - `server`: exactly `relay_ips`, one `/32` each — matches the VPS-side
    peer in the PoC.
  - `client`: `0.0.0.0/0` — required for the outbound path per the
    cryptokey-routing behavior confirmed in `overview.md`. Not
    configurable per relay IP: the client side must accept traffic to any
    destination a relay IP might originate a connection to.
- Bring the interface up: `ip link set <name> up` (idempotent — a no-op on
  an already-up interface).

## Routing (idempotent, role-specific — mirrors `overview.md` exactly)

- **`server`**: for each entry in `relay_ips`, `ip route replace <ip>/32
  dev <name>` (`replace`, not `add`, so re-running doesn't error). This is
  the one place `wg-quick`'s own `AllowedIPs`-derived route logic is
  manually replicated, since the Go implementation shells out to `ip`/`wg`
  directly rather than invoking `wg-quick` itself.
- **`client`**: never adds a kernel default route for the interface (the
  `Table = off` equivalent — the code simply never calls `ip route add
  default dev <name>` at all). For each entry in `relay_ips`:
  - `ip addr replace <ip>/32 dev <name>` — creates the scope-host "local"
    route that lets a process bind to the address (this is what
    `wg-quick`'s `Address =` line did automatically in the PoC; done
    per-IP explicitly here since `relay_ips` is a list).
  - A policy route so packets *sourced from* that IP go out through the
    tunnel: an `ip rule from <ip> lookup <table>` entry, plus `ip route
    replace default dev <name> table <table>`. Table ID and rule priority
    are derived deterministically from the instance's listen port, rather
    than the ad hoc values picked by hand during the PoC: **table =
    listen_port, priority = listen_port - 40000** (instance 0 → table
    `60217`, priority `20217`, reproducing the exact PoC-validated values;
    instance 1 → table `60218`, priority `20218`). This piggybacks on the
    listen-port collision check `plan-environment.md` already requires,
    instead of inventing a second collision-prone constant.
  - Idempotency: before adding, check `ip rule show` for an exact-match
    line (`from <ip> lookup <table>` as parsed fields, not a substring
    match — another unrelated rule could coincidentally contain the same
    text). Use `ip route replace` (idempotent by construction) for the
    table's default route.
- **Reconciliation, not just additive apply — both roles.** Bring-up must
  also *remove* state for a relay IP that was previously configured but is
  no longer in `relay_ips`, not just add state for what's currently there.
  Without this, decommissioning a relay IP via config silently leaves it
  live at runtime: on `server`, the peer's `AllowedIPs` no longer includes
  it (so WireGuard itself won't forward for it) but the `ip route replace
  <ip>/32 dev <name>` route is left dangling; on `client` this is worse —
  the address stays locally bindable and the policy route keeps routing
  its outbound traffic through the tunnel indefinitely. Since there's no
  separate persisted "previously applied" state file (per
  `config-and-lifecycle.md`'s filesystem-resident-state constraint, the
  only durable state is the config itself), reconciliation means diffing
  against live kernel state on every bring-up: enumerate this instance's
  own `/32` routes on `<name>` (`server`) or addresses +
  `ip rule ... lookup <table>` entries (`client`) — scoped to entries this
  tool would have created (matching `dev <name>` / `table <table>`, not a
  blind sweep of the whole routing table — never touch entries this
  instance didn't create) — and remove (`ip route del`, `ip addr del`,
  `ip rule del`) whichever aren't in the current `relay_ips` before adding
  whatever's missing.
- Both roles rely on the operator/environment having already set
  `net.ipv4.ip_forward=1` (server side) — that's `plan-environment.md`'s
  job, already done for the existing VPS, and is not re-managed by
  `wganchor` at runtime. Confirm-only: `wganchor server` reads
  `/proc/sys/net/ipv4/ip_forward` on startup and prints a warning (not a
  hard failure, since the operator can fix it after seeing the warning) if
  it isn't `1`.

## Firewall (ufw or otherwise) — explicitly out of scope

The bootstrap PoC needed VPS `ufw` rules (`60217/udp` allow + `ufw route
allow`) that `wganchor` will not manage. Decision: **`wganchor` never
touches firewall state** — same reasoning as leaving `ip_forward` to the
operator. Different hosts use `ufw`, `firewalld`, raw `nftables`, or a
cloud security group instead of a host firewall at all; guessing at one
tool's rule shape is out of scope for a WireGuard relay tool.
`install`/`server` startup should print the required port/forwarding rules
as operator guidance (see `plan-lifecycle.md`) rather than attempt to set
them.

## Idempotent startup reconciliation

Per `config-and-lifecycle.md`'s design constraint ("a prior crash leaving
`wganchor0` half-configured must not require manual cleanup"): every
bring-up step above — including the routing reconciliation step, which
removes stale entries as well as adding missing ones — is idempotent by
construction, so "reconcile on startup" is not a separate code path from
an ordinary run: it's simply what running the same bring-up sequence
always does, whether the interface already exists, is half-configured, or
was already fully correct. Verified by two tests: (1) running the full
bring-up sequence twice in a row against the same `relay_ips` confirms the
second run produces no errors and no duplicated `wg` peers or `ip rule`
entries; (2) running it once, then again after removing an entry from
`relay_ips`, confirms the removed entry's address/route/rule state is
actually gone afterward (see the reconciliation bullet above), not just
that the remaining entries are still correct.

## Testing strategy

- **Unit-testable in isolation** (no root, no real interface): `AllowedIPs`
  computation per role (including with 2+ `relay_ips` entries — this is
  core scope per `wireguard.md`'s design, not an edge case, since
  `relay_ips` is a list specifically so multiple relay IPs can share one
  tunnel), table/priority derivation from instance number, the
  reconciliation diff logic (given a fixed "current `relay_ips`" and a
  fixture of already-live entries, confirm the right ones are marked for
  add vs. removal), the pre-flight validation checks, and the "is this
  `ip rule` already present" parsing logic (fed captured `ip rule show`
  output as fixtures).
- **Requires root + real `ip`/`wg`** (not unit-testable in a sandboxed CI
  environment): interface creation, `wg set`, address/route calls. Tested
  manually against the existing VPS (`203.0.113.10`/`203.0.113.20`) by
  running the real `wganchor server`/`client` binaries end-to-end and
  repeating the bootstrap PoC's inbound/outbound/idle-keepalive checks —
  a live re-validation of already-proven behavior, not a new PoC.
- Second-instance/second-VPS live validation is out of scope for this plan
  (see `plan-lifecycle.md` / `SPRINT.md`).

## Exit criteria

- [x] Key self-provisioning: `wganchor server`/`client` with no
      `private_key` in its config generates one, writes it back to the
      config file (`0600` preserved), and prints the public key. Confirmed
      live on both the VPS and the home machine.
- [x] `wganchor server` (VPS) and `wganchor client` (home) bring up a real
      tunnel from config alone — re-validated against the existing VPS:
      inbound, outbound, and idle/keepalive all pass, matching the
      bootstrap PoC's manually-achieved results. (Idle/keepalive re-uses
      the mechanism already validated in the bootstrap PoC —
      `PersistentKeepalive` handling is unchanged — so this sprint's live
      re-validation focused on inbound/outbound, which are what the new
      automation code actually touches.)
- [x] Running either subcommand twice in a row against an already-up
      tunnel is a no-op on the second run: no errors, no duplicated `wg`
      peers or `ip rule` entries (verified via `wg show`/`ip rule show`
      before and after, both roles).
- [x] The `ip_forward` warning fires when unset — unit-tested
      (`TestIPForwardEnabled`) against `ipForwardEnabled(path)`, a plain
      function reading a given path rather than shelling out, specifically
      so this doesn't require mutating the real sysctl.
- [x] No code path invokes `ufw`/`iptables`/`nft` — confirmed by grepping
      the implementation; firewall state is untouched by `wganchor`.
      **Superseded**: the `resilience-and-firewall` sprint's
      `plan-firewall.md` reverses this specific decision for the
      client's own relay interface (not the VPS's `ufw`) — see
      `docs/arch/firewall.md`'s "Scope" section. This criterion remains
      true as a historical record of the state at the time it was
      written, not as a description of the current codebase.
- [x] Table ID / rule priority derivation is unit-tested
      (`TestTableAndPriorityForInstanceAreDistinctAndMatchPoC`) for
      instances 0 and 1. Recorded as a durable design decision in
      `docs/arch/wireguard.md`'s new "Client-side policy routing" section.
- [x] `relay_ips` with 2+ entries is exercised: unit-tested (AllowedIPs
      computation, diff logic) and additionally live-tested against the
      home machine using a synthetic second relay IP (not a real Vultr
      secondary IP — just to exercise the address/rule bookkeeping) to
      confirm both addition and later removal actually happen, beyond
      what the plan originally called for.
- [x] Pre-flight validation — missing `peer_endpoint` (client), empty
      `relay_ips` (both roles), and a malformed `relay_ips` entry — each
      fail fast with an actionable error before any system state changes,
      verified by unit test.
- [x] Reconciliation removes stale state for a relay IP dropped from
      config, and does not touch routes/rules/addresses this instance did
      not create — verified live (see the 2+ entry bullet above): adding
      then removing a synthetic relay IP left only the real relay IP's
      address/rule/route behind.
- [x] A name collision with a pre-existing, non-WireGuard interface at
      `interface_name` fails with an actionable error rather than an
      opaque downstream `wg set` failure — verified live against the VPS
      using a dummy (non-WireGuard) interface named `wganchor0`.

**Revision during implementation, not anticipated in the original plan:**
private key delivery to `wg set` uses `/dev/stdin`, not a `0600` temp file
— see the "Interface creation" section above and
`docs/arch/wireguard.md`'s "Keys" section for why (an AppArmor profile on
the target VPS confines `wg` to `/etc/wireguard/` only).
