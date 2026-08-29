# Firewall: default-deny on the client's public relay interface

Status: design, to be implemented in the `resilience-and-firewall` sprint.
Reverses `plan-tunnel-runtime.md`'s original "firewall explicitly out of
scope" decision for the *inbound-on-the-relay-interface* case
specifically — that decision was about not managing the VPS's own ufw
rules (still out of scope, see below), not about leaving a newly-public
IP on a shared home machine wide open by default.

## Motivation

Confirmed live on the home machine (2026-08-29): binding a service to
`0.0.0.0` makes it reachable on the wganchor relay IP automatically (the
relay IP is a real local address on the `wganchor<N>` interface — see
`docs/arch/wireguard.md`), and there is no port-level filtering on that
path at all — reachability there is currently all-or-nothing per
interface. The home machine this was found on already had several
unrelated `0.0.0.0`-bound services (Docker containers, Node processes)
that became internet-reachable the moment the relay IP came up, with
zero additional action from the operator and no warning. `wganchor`'s
whole purpose is to make a machine's process bind a public IP directly —
that's a much easier way to accidentally expose something than opening
one specific port ever was, so it deserves a secure-by-default posture
wganchor itself provides, not one left entirely to the operator to
remember.

## Scope: the client's relay interface(s), not the VPS's own firewall

This is specifically about protecting whatever the *client* side binds
the relay IP for — the home machine, or any future non-VPS install.

The **server** (VPS) side's own inbound firewall (opening the WireGuard
listen port, allowing forwarding between the public interface and
`wganchor<N>` — see `docs/arch/config-and-lifecycle.md`'s Lifecycle
section) remains explicitly out of scope, unchanged from
`plan-tunnel-runtime.md`'s original decision: that's the VPS's own
`ufw`/system firewall, already documented as the operator's
responsibility, and printed as a reminder by `wganchor install server`.
This feature doesn't touch that.

## Design

### Backend: nftables directly, in a dedicated table — not ufw

Confirmed live (see the `project_home_machine_environment` memory,
recorded during this sprint's planning): the home machine's actual
packet filtering is done directly via nftables by Docker and Tailscale,
each in its own dedicated table (`ip filter` with Docker's `DOCKER-USER`
chain, a `ts-input`/`ts-forward` pair for Tailscale) — `ufw` itself is
inactive, and `/etc/nftables.conf`/`nftables.service` are not the source
of truth. Wrapping `ufw` (as briefly considered) would be actively wrong
on a machine where `ufw` isn't even running the show; shelling out to
`nft` directly (same "no external frameworks" pattern already used for
`ip`/`wg`) and following the same "own dedicated table, never touch
anyone else's" coexistence pattern Docker and Tailscale already use is
both more correct and more portable across machines that do or don't
use `ufw`.

Concretely, one shared table for the whole tool, one shared `input`
chain hooked once:

```
table ip wganchor
  set wganchor<N>_tcp { type inet_service }   # one pair of sets per instance
  set wganchor<N>_udp { type inet_service }
  chain input { type filter hook input priority filter; policy accept;
    iifname "wganchor<N>" ct state established,related accept  comment "wganchor-instance-<N>"
    iifname "wganchor<N>" tcp dport @wganchor<N>_tcp accept    comment "wganchor-instance-<N>"
    iifname "wganchor<N>" udp dport @wganchor<N>_udp accept    comment "wganchor-instance-<N>"
    iifname "wganchor<N>" counter drop                         comment "wganchor-instance-<N>"
  }
```

Rules are tagged with a per-instance comment (`wganchor-instance-<N>`)
so they can be found and removed precisely (`nft -a list chain ...`,
match by comment, delete by handle) without touching another instance's
rules or anything Docker/Tailscale-owned — the same "only ever touch
what this tool would have created" discipline `routing.go`'s reconcile
functions already follow for `ip rule`/`ip route`/`ip addr`. Because the
chain's rules are all scoped by `iifname "wganchor<N>"`, and the base
chain's own policy is `accept`, traffic on every other interface
(LAN, Tailscale, Docker bridges, SSH) is completely unaffected — this
was live-verified when the stopgap version of this exact ruleset was
applied by hand during planning.

Named sets (`wganchor<N>_tcp`/`_udp`), not one rule per port: adding or
removing an allowed port is `nft add element` / `nft delete element`
against the set, not a rule-handle hunt, and an already-present element
is a no-op — idempotent by construction, no extra bookkeeping needed.

### Commands: imperative, not fought over by a timer

Per the user's explicit direction, `allow`/`deny`/`enable`/`disable` are
one-off operator actions, not something a background reconcile loop
re-diffs against a declared policy on a timer the way `relay_ips` is.
State does, however, need to *survive a reboot* — see "Surviving a
reboot" below for how that's reconciled with "imperative" without
reintroducing a fighting-the-operator reconcile loop:

- `wganchor firewall enable --instance N` — idempotently ensures the
  table/chain/sets/base rules above exist for that instance. Safe to
  re-run. No `--role` flag — resolving the interface name only needs the
  instance number (same config/default lookup `server`/`client` already
  use), and the mechanism is identical regardless of which role created
  the interface.
- `wganchor firewall allow --instance N --port <port>/<tcp|udp>` — adds
  that port to the instance's set (and its persisted record, below).
- `wganchor firewall deny --instance N --port <port>/<tcp|udp>` (or a
  clearer name — an implementation-time naming choice) — removes it.
- `wganchor firewall disable --instance N` — removes exactly this
  instance's rules and sets (by exact comment match, rules before sets —
  nft won't delete a set a rule still references), leaving the shared
  table and other instances' rules alone; drops the table entirely only
  if no instance's rules remain in it (mirrors `removeTemplateIfUnused`'s
  "only remove the shared thing once nothing else depends on it" pattern
  from `lifecycle.go`).

### Surviving a reboot

A reboot destroys the `wganchor<N>` interface; `server`/`client`
re-creates it on restart, which would otherwise re-trigger the
first-time-creation default (empty sets, firewall re-enabled) — silently
discarding whatever the operator had `allow`ed, or silently undoing an
explicit `disable`. Docker and Tailscale don't have this problem because
each restores its own ruleset from its own persisted state at its own
startup; wganchor needs the same. Two fields on `Config`
(`disable_firewall`, `firewall_allowed_ports`) record the operator's
last-known intent; `allow`/`deny`/`enable`/`disable` update them
alongside the live nftables state, and `server`/`client`'s bring-up
applies them (idempotently, every run) the same way it already applies
`relay_ips`. This is a narrow, deliberate exception to "not reconciled
on a timer" — nothing re-diffs this *between* bring-ups, but each
bring-up converges live state to the last recorded intent, which is what
makes `allow`ed ports and an explicit `disable` durable across a reboot
without wganchor needing to be a continuously-running process to
remember them.

### Default-on for a newly-created interface, with a clear one-time notice

The dangerous case is exactly the one found live: an operator brings up
a brand-new interface and some already-running (or later-added)
`0.0.0.0`-bound service becomes silently, immediately internet-reachable.
So: when `EnsureInterface` (`iface.go`) creates a `wganchor<N>` interface
for the first time — this requires changing `EnsureInterface`'s signature
to return `(created bool, err error)`, since it currently only returns
`error` — `server`/`client` automatically applies the recorded firewall
state for that instance (per "Surviving a reboot" above: fresh, this
means fully locked down except established/related; after a reboot with
prior `allow`ed ports, this means those ports specifically) and prints a
one-time notice on creation, e.g.:

```
wganchor: new interface wganchor0 — a default-deny firewall was enabled on it automatically.
No inbound ports are open yet. To expose a service: wganchor firewall allow --instance 0 --port 8080/tcp
To turn this off for this instance:                wganchor firewall disable --instance 0
(Firewall state is re-applied on every bring-up, including after a reboot, so allowed ports persist.)
```

Note this is deliberately *not* worded as "removes the firewall
entirely" — per "Surviving a reboot," `disable` persists as the
recorded intent and is honored on every future bring-up, but it doesn't
prevent a *future* `firewall enable`/`allow` from turning it back on.

An explicit `--no-firewall` flag on `server`/`client` skips applying the
default (or the persisted intent) for that one invocation, for an
operator who wants the old, fully-open behavior right now without
changing the durable, recorded choice (`firewall disable` is the durable
opt-out). `nft` being unavailable, or the enable step otherwise failing,
on a fresh `server`/`client` run is a hard, actionable failure — matching
the project's existing precondition-checking posture (`precheckLifecycle`
for `install`/`uninstall`) — not a silent partial success with the tunnel
left open and unfirewalled.

## Exit criteria (elaborated further in the sprint's plan)

- `firewall enable`/`allow`/`deny`/`disable` all idempotent and scoped
  to exactly one instance (comment-matched exactly, not by substring —
  `wganchor-instance-1` is a substring of `wganchor-instance-10`),
  verified not to affect another instance's rules, Docker's rules, or
  Tailscale's rules.
- A brand-new interface gets a default-deny firewall automatically, with
  the notice printed once per creation; `--no-firewall` suppresses it for
  that invocation; re-running `server`/`client` against an already-
  existing interface within the same boot does not re-trigger the notice.
- Firewall state (allowed ports, or an explicit `disable`) survives an
  interface being torn down and recreated (a reboot, or `ip link delete`
  + re-run) — not just a same-boot idempotent re-run.
- `nft` missing, or `enable` otherwise failing, on a fresh `server`/
  `client` run fails hard and actionably rather than silently leaving the
  tunnel open and unfirewalled.
- Live-validated on the home machine: a `0.0.0.0`-bound test service
  confirmed unreachable via the relay IP by default, reachable only
  after an explicit `allow`, and fully open again after `disable` —
  each step verified from a genuine external vantage point (the
  existing VPS), not just locally (loopback-style local delivery does
  not exercise `iifname` matching the way real external traffic does —
  learned live while validating the hand-applied stopgap).
- The VPS side's own firewall responsibilities are unchanged — this
  feature does not touch `ufw` or attempt to manage the server's
  inbound/forwarding rules. This does supersede
  `plan-tunnel-runtime-COMPLETE.md`'s "no code path invokes ufw/iptables/
  nft" exit criterion (client-side only, and only for this specific,
  deliberate security default) — noted there once this ships.
