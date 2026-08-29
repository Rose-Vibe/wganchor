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

### Commands: imperative, not config-managed or reconciled

Per the user's explicit direction: these are one-off operator actions,
not part of the JSON config file and not something the daemon's own
reconcile loop re-applies or fights over on every run. State lives
purely in the live nftables ruleset itself (mirroring how the ip
rule/route/addr state already works — wganchor's reconcile functions
don't "own" a config-declared firewall policy, they just react to
explicit commands):

- `wganchor firewall enable --instance N [--role server|client]` —
  idempotently ensures the table/chain/sets/base rules above exist for
  that instance. Safe to re-run.
- `wganchor firewall allow --instance N --port <port>/<tcp|udp>` — adds
  that port to the instance's set.
- `wganchor firewall deny --instance N --port <port>/<tcp|udp>` (or a
  clearer name — an implementation-time naming choice) — removes it.
- `wganchor firewall disable --instance N` — removes exactly this
  instance's rules and sets (by comment match), leaving the shared table
  and other instances' rules alone; drops the table entirely only if no
  instance's rules remain in it (mirrors `removeTemplateIfUnused`'s
  "only remove the shared thing once nothing else depends on it"
  pattern from `lifecycle.go`).

`role` matters here only in that a firewall for a *server* instance is
plausible too (a VPS could run its own reverse proxy behind the relay
port, for symmetry with the client case) — the mechanism is identical
either way, scoped to that instance's `wganchor<N>` interface.

### Default-on for a newly-created interface, with a clear one-time notice

The dangerous case is exactly the one found live: an operator brings up
a brand-new interface and some already-running (or later-added)
`0.0.0.0`-bound service becomes silently, immediately internet-reachable.
So: when `EnsureInterface` (`iface.go`) creates a `wganchor<N>` interface
for the first time (not on a subsequent idempotent re-run against an
existing interface — `EnsureInterface` already distinguishes "created"
from "already existed"), `server`/`client` automatically calls the
equivalent of `firewall enable` for that instance (no ports allowed yet
— fully locked down except established/related, same as the stopgap
already live-verified on the home machine) and prints an unmissable
one-time notice, e.g.:

```
wganchor: new interface wganchor0 — a default-deny firewall was enabled on it automatically.
No inbound ports are open yet. To expose a service: wganchor firewall allow --instance 0 --port 8080/tcp
To remove this firewall entirely:                  wganchor firewall disable --instance 0
```

An explicit `--no-firewall` flag on `server`/`client` opts out for an
operator who wants the old, fully-open behavior on purpose (matches the
project's general stance of "safe by default, escape hatch available"
rather than "always forced").

## Exit criteria (elaborated further in the sprint's plan)

- `firewall enable`/`allow`/`deny`/`disable` all idempotent and scoped
  to exactly one instance, verified not to affect another instance's
  rules, Docker's rules, or Tailscale's rules.
- A brand-new interface gets a default-deny firewall automatically, with
  the notice printed; `--no-firewall` suppresses it; re-running
  `server`/`client` against an already-existing interface does not
  re-trigger the notice or touch existing firewall state.
- Live-validated on the home machine: a `0.0.0.0`-bound test service
  confirmed unreachable via the relay IP by default, reachable only
  after an explicit `allow`, and fully open again after `disable` —
  each step verified from a genuine external vantage point (the
  existing VPS), not just locally (loopback-style local delivery does
  not exercise `iifname` matching the way real external traffic does —
  learned live while validating the hand-applied stopgap).
- The VPS side's own firewall responsibilities are unchanged — this
  feature does not touch `ufw` or attempt to manage the server's
  inbound/forwarding rules.
