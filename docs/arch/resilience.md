# Resilience: watching for and repairing external routing interference

Status: design, to be implemented in the `resilience-and-firewall` sprint.

## Motivation

Discovered live during the wireguard-automation sprint's second-VPS
validation (see `docs/sprints/archive/2026-08-29-wireguard-automation/`):
on the home machine, something — Tailscale's own log blames
`systemd-networkd` — periodically issues a full `ip rule` flush.
Tailscale has its own logic to detect this and restore its rules
immediately after. wganchor does not: its bring-up
(`server`/`client`, `iface.go`/`routing.go`) is a `Type=oneshot` systemd
unit that runs once and exits (see `docs/arch/config-and-lifecycle.md`).
If the flush happens after bring-up, the interface and address stay up
and `wg show` keeps reporting a healthy handshake (established WireGuard
traffic, including keepalives, doesn't need the policy route) — but any
*new* inbound-initiated connection needing a reply routed back out
through the relay IP silently fails until something re-runs the client's
reconciliation. This was observed twice in one session on the same
machine (once for the real production instance, once for a fresh
throwaway instance minutes after it was created), so it's a recurring
environmental interaction on this machine, not a one-off.

The goal here is not to stop whatever is doing the flushing (out of
scope — it isn't wganchor's own state, and per CLAUDE.md's idempotency
rule the right response to "something else changed state I depend on" is
to notice and repair, not to fight the other tool for ownership). The
goal is for wganchor to notice quickly and repair itself, the same way
Tailscale already does for its own rules, and to say so clearly in its
logs — the exact way reading Tailscale's log line was what made this
bug diagnosable at all.

## Design

Two complementary mechanisms, per the user's own framing: an
event-driven watch for the fast case, and a periodic reconciliation
check as a general backstop.

### A new, separate "watch" process — not folded into `server`/`client`

The existing `server`/`client` subcommands and their `Type=oneshot`
unit are already implemented, reviewed, and live-validated
(`plan-tunnel-runtime.md`, `plan-lifecycle.md`). Rather than changing
their semantics (turning a one-shot bring-up command into a persistent
process would be a behavior change to already-shipped, already-reviewed
code, and would require rethinking the unit's `Type=` all over again),
this adds a new, optional, persistent companion:

```
wganchor watch <server|client> --instance N
```

Run as its own systemd unit (`wganchor-watch-<role>@<N>.service`,
`Type=simple`, `Restart=always`, `After=wganchor-<role>@<N>.service`,
`BindsTo=wganchor-<role>@<N>.service` — the watcher only makes sense
while the bring-up unit is active, and should stop when it stops). Not
installed by default; `wganchor install` gains a `--with-watch` flag (or
similar — exact naming is an implementation detail for the plan) that
also installs and enables the companion unit, matching the "opt-in,
not silently added scope" spirit of what shipped so far.

The watch process does two things in a loop, both triggering exactly the
same reconciliation the daemon already performs on every normal run
(`ReconcileServerRoutes` / `ReconcileClientRouting`, `routing.go`) — no
new reconciliation logic, only a new trigger/loop harness around the
already-reviewed, idempotent functions:

1. **Event-driven**: run `ip monitor rule` as a subprocess (matches the
   project's established pattern of shelling out to `ip`/`wg` rather
   than adding a netlink library dependency — see CLAUDE.md's "no
   external frameworks for simple tasks"), read its stdout line by
   line. On a line indicating a rule deletion that could plausibly be
   this instance's rule (matching this instance's table number or
   priority — see `tableForInstance`/`priorityForInstance` in
   `routing.go`), trigger a reconcile immediately. If the `ip monitor`
   subprocess exits (for any reason), restart it with a short backoff —
   the watcher must not silently stop watching just because its
   subprocess died once.
2. **Periodic backstop**: on a fixed interval (a sane default, e.g. 5
   minutes — exact value is a plan detail, not an architecture
   decision), unconditionally reconcile regardless of whether any event
   fired. This is the general safety net: it doesn't care what caused
   drift (an `ip rule` flush, a stale address, a missing route) because
   it just re-runs the same full reconciliation the daemon already does
   on every normal bring-up.

Only watching `ip rule` events (not also `ip addr`/`ip route`) is a
deliberate, narrower-than-total scope: it's the exact failure mode
already observed, it's cheap, and the periodic backstop already covers
drift in addresses/routes/rules alike regardless of which specific
netlink object type changed. If this turns out to be insufficient later
(e.g. addresses get swept too, independently of a rule flush and between
periodic checks), broadening the watched object types is a small,
additive change — not a reason to build it up front.

### Logging: only log when a fix actually happens

Per the user's explicit ask, mirroring exactly how this bug was found by
reading Tailscale's own log: **log when reconciliation actually changes
something, not on every routine check.** A periodic check that finds
nothing to fix should be silent (or at most a low-noise heartbeat, not a
per-check line) — otherwise the real signal (a rule that got removed and
had to be restored) drowns in five-minute-interval "checked, all fine"
lines.

This requires `ReconcileServerRoutes`/`ReconcileClientRouting`
(`routing.go`) to report back *what* they changed, not just
success/failure as they do today. Proposed: change their return type
from `error` to `(ReconcileResult, error)`, where `ReconcileResult`
records which addresses/routes/rules were added or removed (the
functions already compute exactly this via `diffRelayIPs` internally —
this is a return-value change, not new diffing logic). The existing
`server`/`client` bring-up path (`main.go`) ignores or lightly logs this
on every normal run (nothing changes on a healthy idempotent re-run, so
there's usually nothing to report); the watch loop uses it to decide
whether to log at all, and what to say.

Log lines should make it unambiguous which of the two triggers fired and
what was actually repaired, e.g.:

```
wganchor watch (client, instance 0): rule change detected, reconciling
wganchor watch (client, instance 0): repaired — re-added policy rule for 203.0.113.20 (table 60217)
```

```
wganchor watch (client, instance 0): periodic check, repaired — re-added address 203.0.113.20/32
```

so a future debugging session can `journalctl -u wganchor-watch-client@0`
and immediately see when and why something was fixed, the same way
Tailscale's own log made this bug diagnosable.

## Exit criteria (elaborated further in the sprint's plan)

- A missing client-side `ip rule` for a running instance is detected and
  repaired within a bounded time (the event path) or at worst one
  periodic interval, without operator intervention.
- The watch process survives its own subprocess (`ip monitor`) dying and
  keeps watching.
- Every actual repair is logged clearly enough to answer "when did this
  break and when was it fixed" from `journalctl` alone; routine
  no-op checks are not logged.
- The existing `server`/`client` subcommands and their systemd unit are
  unchanged in behavior — `watch` is a strictly additive, opt-in
  companion.
- Live-validated on the home machine specifically (this is where the
  bug was found), by deliberately reproducing the missing-rule condition
  (`ip rule del ...` by hand) and confirming the watcher repairs it and
  logs correctly, for both the event-driven and periodic paths.
