# Resilience: watching for and repairing external routing interference

Implemented in `internal/watch/watch.go`. Covers `wganchor watch`, a
companion process that detects and repairs routing state another process
on the machine disturbs out from under `wganchor`.

## Problem being solved

On the home machine, something — Tailscale's own logs blame
`systemd-networkd` — periodically issues a full `ip rule` flush. Tailscale
has its own logic to detect this and restore its rules immediately after;
`wganchor` does not on its own, because its bring-up (`server`/`client`,
`internal/wireguard/iface.go`/`internal/routing/routing.go`) is a
`Type=oneshot` systemd unit that runs once and exits (see
`docs/arch/config-and-lifecycle.md`). If the flush happens after bring-up,
the interface and address stay up and `wg show` keeps reporting a healthy
handshake (established WireGuard traffic, including keepalives, doesn't
need the policy route) — but any *new* inbound-initiated connection
needing a reply routed back out through the relay IP silently fails until
something re-runs the client's reconciliation.

`wganchor` does not try to stop whatever causes the flush — it isn't
wganchor's own state, and per CLAUDE.md's idempotency rule the right
response to "something else changed state I depend on" is to notice and
repair, not fight the other tool for ownership. `watch` makes `wganchor`
notice and repair itself quickly, the same way Tailscale already does for
its own rules, and say so clearly in its logs.

## Design

Two complementary mechanisms: an event-driven watch for the fast case, and
a periodic reconciliation check as a general backstop.

### A separate `watch` process — not folded into `server`/`client`

`server`/`client` and their `Type=oneshot` unit keep their existing
semantics (turning a one-shot bring-up command into a persistent process
would be a behavior change to already-shipped code, and would require
rethinking the unit's `Type=` all over again). `watch` is a new, optional,
persistent companion:

```
wganchor watch <server|client> --instance N
```

Runs as its own systemd unit (`wganchor-watch-<role>@<N>.service`,
`Type=simple`, `Restart=always`, `After=wganchor-<role>@<N>.service`,
`BindsTo=wganchor-<role>@<N>.service` — the watcher only makes sense while
the bring-up unit is active, and stops when it stops). **On by default**:
`wganchor install` installs and enables the companion unit automatically,
the same way Tailscale's own resilience is on by default with no manual
step — the point is for wganchor to be self-healing out of the box, not
something an operator has to know to opt into. A `--no-watch` flag on
`install` opts out (matches the same "safe/resilient by default, explicit
escape hatch" posture `docs/arch/firewall.md` independently arrives at
for the default-deny firewall).

The watch process does two things in a loop, both triggering exactly the
same reconciliation the daemon already performs on every normal run
(`ReconcileServerRoutes` / `ReconcileClientRouting`,
`internal/routing/routing.go`) — no new reconciliation logic, only a new
trigger/loop harness around the already-idempotent functions:

1. **Event-driven**: runs `ip monitor rule` as a subprocess (matching the
   project's established pattern of shelling out to `ip`/`wg` rather than
   adding a netlink library dependency), reading its stdout line by line.
   On a line indicating a rule deletion that's this instance's rule
   specifically (matching both this instance's table number *and*
   priority — see `tableForInstance`/`priorityForInstance` in
   `internal/routing/routing.go` — deliberately stricter than "either":
   this tool's own rules always carry both together, and requiring both
   avoids a false trigger on an unrelated rule sharing only one of the two
   numbers), it triggers a reconcile immediately. If the `ip monitor`
   subprocess exits for any reason, it's restarted with a short backoff —
   the watcher must not silently stop watching just because its
   subprocess died once.
2. **Periodic backstop**: on a fixed interval (currently 5 minutes),
   unconditionally reconciles regardless of whether any event fired. This
   is the general safety net: it doesn't care what caused drift (an `ip
   rule` flush, a stale address, a missing route) because it just re-runs
   the same full reconciliation the daemon already does on every normal
   bring-up.

Only `ip rule` events are watched (not also `ip addr`/`ip route`) — a
deliberate, narrower-than-total scope: it's the exact failure mode
observed, it's cheap, and the periodic backstop already covers drift in
addresses/routes/rules alike regardless of which specific netlink object
type changed. If this turns out to be insufficient (e.g. addresses get
swept too, independently of a rule flush and between periodic checks),
broadening the watched object types is a small, additive change.

### Logging: only log when a fix actually happens

Mirroring exactly how this bug was first found by reading Tailscale's own
log: **reconciliation logs only when it actually changes something, not
on every routine check.** A periodic check that finds nothing to fix is
silent (or at most a low-noise heartbeat, never a per-check line) —
otherwise the real signal (a rule that got removed and had to be restored)
drowns in five-minute-interval "checked, all fine" lines.

`ReconcileServerRoutes`/`ReconcileClientRouting`
(`internal/routing/routing.go`) return `(ReconcileResult, error)`, where
`ReconcileResult` records which addresses/routes/rules were added or
removed. The `server`/`client` bring-up path (`cmd/wganchor/main.go`)
ignores or lightly logs this on every normal run (nothing changes on a
healthy idempotent re-run, so there's usually nothing to report); the
watch loop uses it to decide whether to log at all, and what to say.

Log lines make it unambiguous which of the two triggers fired and what
was actually repaired, e.g.:

```
wganchor watch (client, instance 0): rule change detected, reconciling
wganchor watch (client, instance 0): repaired — re-added policy rule for 203.0.113.20 (table 60217)
```

```
wganchor watch (client, instance 0): periodic check, repaired — re-added address 203.0.113.20/32
```

so a debugging session can `journalctl -u wganchor-watch-client@0` and
immediately see when and why something was fixed — the same way reading
Tailscale's own log made the original bug diagnosable.

## Known gaps

- `watch` never re-applies firewall state (see `docs/arch/firewall.md`'s
  "Surviving a reboot" known gap) — if something external flushes the
  whole nftables ruleset, `watch` restores routing but not the firewall.
- `watch` never calls `ConfigureInterface` (see `docs/arch/wireguard.md`'s
  "Known gaps") — `AllowedIPs` drift on the server role isn't covered.

## Guarantees

- A missing client-side `ip rule` for a running instance is detected and
  repaired within a bounded time (the event path) or at worst one
  periodic interval, without operator intervention.
- The watch process survives its own subprocess (`ip monitor`) dying and
  keeps watching.
- Every actual repair is logged clearly enough to answer "when did this
  break and when was it fixed" from `journalctl` alone; routine no-op
  checks are not logged.
- The `server`/`client` subcommands and their systemd unit are unchanged
  in behavior — `watch` is a separate, additive companion process;
  `install` enables it by default (`--no-watch` opts out), so existing
  behavior only changes for a fresh `install`, never for an
  already-installed instance until it's reinstalled.
