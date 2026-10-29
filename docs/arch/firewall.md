# Firewall: default-deny on the client's public relay interface

Implemented in `internal/firewall/firewall.go`. Covers the
*inbound-on-the-relay-interface* case specifically on the **client**
side — the VPS's own firewall (its `ufw`/system firewall, opening the
WireGuard listen port, allowing forwarding between its public interface
and `wganchor<N>`) remains explicitly out of scope and is the operator's
responsibility (`wganchor install server` prints a reminder) — see
`docs/arch/config-and-lifecycle.md`'s Lifecycle section.

## Motivation

Binding a service to `0.0.0.0` makes it reachable on the wganchor relay IP
automatically (the relay IP is a real local address on the `wganchor<N>`
interface — see `docs/arch/wireguard.md`), with no port-level filtering on
that path by default — reachability there is all-or-nothing per interface.
A home machine can easily already have several unrelated `0.0.0.0`-bound
services (Docker containers, Node processes) that would become
internet-reachable the moment the relay IP comes up, with zero additional
action from the operator and no warning. Exposing a public IP this way is
a much easier way to accidentally expose something than opening one
specific port ever was, so `wganchor` provides a secure-by-default
posture rather than leaving it entirely to the operator to remember.

## Scope: the client's relay interface(s), not the VPS's own firewall

This protects whatever the *client* side binds the relay IP for — the home
machine, or any future non-VPS install. Concretely, the bring-up wiring
(`cmd/wganchor/main.go`'s `run()`) only ever applies the firewall scaffold
and allowed-port state on the `client` role's path, never `server`'s. The
firewall *subcommands* (`enable`/`allow`/`deny`/`disable`) remain
role-agnostic on purpose (no `--role` flag), since an operator could still
choose to run them against a server-role instance; `uninstall
--purge`'s teardown call is correspondingly unconditional on role too.

## Design

### Backend: nftables directly, in a dedicated table — not ufw

The home machine's actual packet filtering is done directly via nftables
by Docker and Tailscale, each in its own dedicated table (`ip filter` with
Docker's `DOCKER-USER` chain, a `ts-input`/`ts-forward` pair for
Tailscale) — `ufw` itself is inactive, and `/etc/nftables.conf`/
`nftables.service` are not the source of truth. Wrapping `ufw` would be
wrong on a machine where `ufw` isn't even running the show; `wganchor`
instead shells out to `nft` directly (the same "no external frameworks"
pattern already used for `ip`/`wg`) and follows the same "own dedicated
table, never touch anyone else's" coexistence pattern Docker and Tailscale
already use.

One shared table for the whole tool, one shared `input` chain hooked once:

```
table ip wganchor
  set wganchor<N>_tcp { type inet_service; flags interval }   # one pair of sets per instance
  set wganchor<N>_udp { type inet_service; flags interval }
  chain input { type filter hook input priority filter; policy accept;
    iifname "wganchor<N>" ct state established,related accept  comment "wganchor-instance-<N>"
    iifname "wganchor<N>" tcp dport @wganchor<N>_tcp accept    comment "wganchor-instance-<N>"
    iifname "wganchor<N>" udp dport @wganchor<N>_udp accept    comment "wganchor-instance-<N>"
    iifname "wganchor<N>" counter drop                         comment "wganchor-instance-<N>"
  }
```

Rules are tagged with a per-instance comment (`wganchor-instance-<N>`) so
they can be found and removed precisely (`nft -a list chain ...`, match by
comment, delete by handle) without touching another instance's rules or
anything Docker/Tailscale-owned — the same "only ever touch what this tool
would have created" discipline `internal/routing/routing.go`'s reconcile
functions already follow for `ip rule`/`ip route`/`ip addr`. Because every
rule is scoped by `iifname "wganchor<N>"` and the base chain's own policy
is `accept`, traffic on every other interface (LAN, Tailscale, Docker
bridges, SSH) is unaffected.

Named sets (`wganchor<N>_tcp`/`_udp`), not one rule per port: adding or
removing an allowed port is `nft add element` / `nft delete element`
against the set, not a rule-handle hunt, and an already-present element is
a no-op — idempotent by construction.

Sets carry `flags interval` so an element can be a range (`{ 8000-8010
}`) as well as an ordinary single port (`{ 8080 }`); a single-port entry
reads back as a bare integer, not a degenerate length-1 range, so its
on-disk/live representation is unchanged from before ranges existed. A set
created by a wganchor binary predating this flag is detected via `nft list
set` output missing `flags interval`; on the next `enable`/`allow`/
bring-up against it, that set and the instance's 4 base rules are deleted
together (never just the migrating set's rule — `nft add rule` only ever
appends at the chain tail, so deleting a single middle rule and re-adding
it later would land it after the still-present terminating `drop` rule and
leave it permanently dead), and the same idempotent scaffold/reconcile
machinery that runs on every bring-up recreates everything, including
re-populating the set(s) from `firewall_allowed_ports`. Self-healing, no
operator action or config migration required.

### Commands: imperative, not fought over by a timer

`allow`/`deny`/`enable`/`disable` are one-off operator actions, not a
background reconcile loop re-diffing against a declared policy on a timer
the way `relay_ips` is. State still needs to *survive a reboot* — see
"Surviving a reboot" below for how that's reconciled with "imperative"
without reintroducing a fighting-the-operator reconcile loop:

- `wganchor firewall enable --instance N` — idempotently ensures the
  table/chain/sets/base rules above exist for that instance. Safe to
  re-run. No `--role` flag — resolving the interface name only needs the
  instance number (the same config/default lookup `server`/`client` use),
  and the mechanism is identical regardless of which role created the
  interface.
- `wganchor firewall allow --instance N --port <port|start-end>/<tcp|udp|both>` —
  adds that port (or port range) to the instance's set(s) and its
  persisted record (below). `/both` is a CLI-layer convenience that
  expands to the tcp and udp specs separately before either reaches
  storage or `nft` — `firewall_allowed_ports` and the nft sets never
  contain the literal word "both", only `tcp`/`udp` entries.
- `wganchor firewall deny --instance N --port <port|start-end>/<tcp|udp|both>` —
  removes it. Exact-spec match only: denying a sub-range of a
  previously-allowed wider range, or a range that doesn't exactly match
  what was allowed, is a no-op.
- `wganchor firewall disable --instance N` — removes exactly this
  instance's rules and sets (by exact comment match, rules before sets —
  nft won't delete a set a rule still references), leaving the shared
  table and other instances' rules alone; drops the table entirely only if
  no instance's rules remain in it (mirrors `removeTemplateIfUnused`'s
  "only remove the shared thing once nothing else depends on it" pattern
  from `internal/lifecycle/lifecycle.go`).

### Surviving a reboot

A reboot destroys the `wganchor<N>` interface; `server`/`client`
re-creates it on restart, which would otherwise re-trigger the
first-time-creation default (empty sets, firewall re-enabled) — silently
discarding whatever the operator had `allow`ed, or silently undoing an
explicit `disable`. Two fields on `Config` (`disable_firewall`,
`firewall_allowed_ports`) record the operator's last-known intent;
`allow`/`deny`/`enable`/`disable` update them alongside the live nftables
state, and the client's bring-up applies them (idempotently, every run)
the same way it already applies `relay_ips`. This is a narrow, deliberate
exception to "not reconciled on a timer" — nothing re-diffs this *between*
bring-ups, but each bring-up converges live state to the last recorded
intent, which is what makes `allow`ed ports and an explicit `disable`
durable across a reboot without wganchor needing to be a continuously-
running process to remember them.

Known gap: `wganchor watch` (the reconciliation companion, see
`resilience.md`) restores `relay_ips`, addresses, routes, and rules on an
externally-detected change, but never re-applies firewall state — that's
outside its scope (it isn't a bring-up). If something external flushes
the whole nftables ruleset, `watch` would faithfully restore a public
relay IP with no filter on it and no re-check until the next real
bring-up. Not addressed yet.

### Default-on for a newly-created interface, with a clear one-time notice

When `EnsureInterface` (`internal/wireguard/iface.go`) creates a
`wganchor<N>` interface for the first time, the client automatically
applies the recorded firewall state for that instance (per "Surviving a
reboot" above: fresh, this means fully locked down except
established/related; after a reboot with prior `allow`ed ports, those
ports specifically) and prints a one-time notice on creation, e.g.:

```
wganchor: new interface wganchor0 — a default-deny firewall was enabled on it automatically.
No inbound ports are open yet. To expose a service: wganchor firewall allow --instance 0 --port 8080/tcp
To turn this off for this instance:                wganchor firewall disable --instance 0
(Firewall state is re-applied on every bring-up, including after a reboot, so allowed ports persist.)
```

The "no inbound ports" line is conditional on whether
`FirewallAllowedPorts` is empty — after a reboot with a previously-
`allow`ed port, the notice instead reads `Allowed inbound ports (restored
from config): 8080/tcp`, so the reprinted notice never asserts something
false about the instance it's describing.

This is deliberately *not* worded as "removes the firewall entirely" — per
"Surviving a reboot," `disable` persists as the recorded intent and is
honored on every future bring-up, but it doesn't prevent a *future*
`firewall enable`/`allow` from turning it back on.

An explicit `--no-firewall` flag on the client skips *applying* the
default (or the persisted intent) for that one invocation — it does not
remove any firewall rules already in place from a prior run. It's useful
for an nft-less host (where applying would fail outright) or a one-off
diagnostic run, but it is not equivalent to "the old, fully-open behavior
right now" on a host that has ever had the firewall enabled: existing
rules are keyed on `iifname` as a plain string and persist across
`--no-firewall` runs, reboots, and interface recreation exactly like any
other rule. `firewall disable` is the actual way to get back to fully
open, since it tears down the live rules and durably records the opt-out.
(`--no-firewall` is also accepted, harmlessly, on `server` — there's
nothing for it to skip there.) `nft` being unavailable, or the scaffold
step otherwise failing, on a fresh client run is a hard, actionable
failure — matching the project's existing precondition-checking posture
(`precheckLifecycle` for `install`/`uninstall`) — not a silent partial
success with the tunnel left open and unfirewalled. It's also checked
*before* the relay IP is ever bound to the interface (not after), so a
failure here never leaves a real, live public IP unfiltered even briefly.

## Guarantees

- `firewall enable`/`allow`/`deny`/`disable` are all idempotent and scoped
  to exactly one instance (comment-matched exactly, not by substring —
  `wganchor-instance-1` is a substring of `wganchor-instance-10`); none
  affects another instance's rules, Docker's rules, or Tailscale's rules.
- A brand-new client interface gets a default-deny firewall automatically,
  with the notice printed once per creation; `--no-firewall` suppresses it
  for that invocation; re-running `client` against an already-existing
  interface within the same boot does not re-trigger the notice.
- Firewall state (allowed ports, or an explicit `disable`) survives an
  interface being torn down and recreated (a reboot, or `ip link delete`
  + re-run), not just a same-boot idempotent re-run.
- `nft` missing, or the scaffold step otherwise failing, on a fresh
  `client` run fails hard and actionably rather than silently leaving the
  tunnel open and unfirewalled.
- The VPS side's own firewall responsibilities are unchanged — this
  feature does not touch `ufw` or attempt to manage the server's
  inbound/forwarding rules.
