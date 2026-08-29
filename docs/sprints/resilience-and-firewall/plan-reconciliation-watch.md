# Plan: Reconciliation watch (`wganchor watch`)

Depends on `docs/arch/resilience.md` (design, already written) and the
already-implemented, already-reviewed `ReconcileServerRoutes`/
`ReconcileClientRouting` in `routing.go`, which this plan reuses without
changing their reconciliation logic.

## Goal

Implement `wganchor watch <server|client> --instance N`: a new, opt-in,
persistent companion process that detects and repairs the exact live bug
found this sprint (an externally-triggered `ip rule` flush silently
breaking new inbound connections while `wg show` still looks healthy),
via an event-driven watch plus a periodic backstop, logging only when it
actually fixes something.

## Step 1: make reconciliation report what it changed

`ReconcileServerRoutes(name string, relayIPs []string) error` and
`ReconcileClientRouting(name string, relayIPs []string, instance int)
error` (`routing.go`) change signature to return a result alongside the
error:

```go
type ReconcileResult struct {
    AddrsAdded, AddrsRemoved     []string
    RoutesAdded, RoutesRemoved   []string
    RulesAdded, RulesRemoved     []string
}

func (r ReconcileResult) Changed() bool { /* true if any slice is non-empty */ }

func ReconcileServerRoutes(name string, relayIPs []string) (ReconcileResult, error)
func ReconcileClientRouting(name string, relayIPs []string, instance int) (ReconcileResult, error)
```

Both functions already compute exactly this via `diffRelayIPs` — this is
a return-value change, not new diffing logic. Update `main.go`'s two call
sites accordingly (the normal bring-up path can ignore the result, or log
it at a low level — a healthy idempotent re-run should almost always
report `Changed() == false`). Update `routing_test.go`'s existing tests
for the new signature; add cases asserting the reported adds/removes
match what was actually diffed (reuse the existing `diffRelayIPs`
fixtures — this is testing the new plumbing, not new logic).

## Step 2: `ip monitor rule` event watching

New file, e.g. `watch.go`:

- `watchRules(ctx context.Context, onEvent func()) error` — starts `ip
  monitor rule` as a subprocess (`exec.CommandContext`, so it's killed
  when `ctx` is cancelled), reads stdout line by line (`bufio.Scanner`).
  On a line indicating a deleted rule (`ip monitor rule`'s output prefixes
  deletions distinctly from a base `ip rule show` line — confirm the
  exact prefix empirically against the installed `iproute2` version
  before parsing; do not guess the format), call `onEvent()`.
- If the subprocess exits for any reason (crashed, `ip` upgraded away
  mid-run, transient error), restart it after a short backoff (e.g. 1s,
  capped) rather than returning — the watcher must not silently stop
  watching. Log a line when restarting (this is itself worth knowing
  about, distinct from "found and fixed drift").
- Filtering to *this instance's* rule specifically (rather than
  reconciling on every unrelated rule change anywhere on the system,
  which would be noisy and wasteful — e.g. Tailscale's own frequent rule
  churn would otherwise trigger a wganchor reconcile every time) — match
  the deleted rule's table or priority against
  `tableForInstance(instance)`/`priorityForInstance(instance)`
  (`routing.go`) before calling `onEvent`. A parse failure on a line
  (unexpected format) should be treated as "don't know, don't trigger" —
  never as "trigger on everything," which would make instance filtering
  pointless — but should also be logged, since it may mean the parser
  needs updating for a newer `iproute2`.

## Step 3: periodic backstop + the watch loop

- `runWatch(role string, instance int, interval time.Duration) error` —
  the command's actual logic:
  - Start `watchRules` in a goroutine; its `onEvent` callback triggers an
    immediate reconcile (see below).
  - A `time.Ticker` at `interval` (default e.g. 5 minutes — a flag,
    `--interval`, can override; document the default in `--help`)
    triggers a periodic reconcile.
  - Both paths call the *same* `reconcileOnce(role, instance) (changed
    bool)` helper — loads the current config fresh each time (so a
    config edit while the watcher is running takes effect, matching the
    "config is the source of truth, reconciled against live state"
    posture already established), calls the appropriate
    `Reconcile*Routes` function, and logs per Step 4.
  - Concurrent triggers (an event fires while a periodic check is
    already running) should not run two reconciles at once against the
    same interface — serialize via a mutex or a single-worker channel;
    reconciliation is idempotent but there's no reason to race it
    against itself.

## Step 4: logging

Per `docs/arch/resilience.md`: log a line only when `ReconcileResult.
Changed()` is true, distinguishing which trigger fired and what was
repaired:

```
wganchor watch (client, instance 0): rule change detected, reconciling
wganchor watch (client, instance 0): repaired — added rule for 203.0.113.20 (table 60217)
```

```
wganchor watch (client, instance 0): periodic check, repaired — added address 203.0.113.20/32
```

A routine periodic check that finds nothing to repair logs nothing (or
at most a single low-frequency heartbeat — a plan-time judgment call, not
an architecture requirement; err toward silence per the user's explicit
ask). Startup and subprocess-restart events are logged unconditionally
(operationally useful, not noise in the same way a five-minute "all
clear" would be).

## Systemd unit and `install` integration

New unit template, `units/wganchor-watch-<role>@.service`
(`//go:embed`, following `units.go`'s existing pattern):

```
[Unit]
Description=wganchor routing-reconciliation watch (instance %i)
After=wganchor-<role>@%i.service
BindsTo=wganchor-<role>@%i.service

[Service]
Type=simple
ExecStart=/usr/local/bin/wganchor watch <role> --instance %i
Restart=always

[Install]
WantedBy=multi-user.target
```

`BindsTo` (not just `After`) so the watcher stops automatically when the
bring-up unit stops — it has nothing to watch once the tunnel it's
watching is down. `wganchor install <role> --instance N --with-watch`
additionally writes/enables this unit (reusing `writeUnitIfChanged`,
`otherEnabledInstanceUnits`, etc. from `lifecycle.go` — this is the same
per-instance-symlink-and-shared-template pattern already implemented,
just for a second unit family). Without `--with-watch`, behavior is
identical to today — this is strictly additive. `uninstall` must also
stop/disable/remove the watch unit for that instance if it was installed
(mirroring the existing unit's handling exactly).

## Exit criteria

- [ ] `ReconcileServerRoutes`/`ReconcileClientRouting` report accurate
      `ReconcileResult`s; existing tests updated, new tests cover
      `Changed()` and non-empty add/remove slices.
- [ ] `wganchor watch` detects an externally-deleted `ip rule` for its
      own instance within a few seconds and repairs it; a rule change for
      an unrelated table/priority does not trigger a reconcile.
- [ ] `wganchor watch` still repairs drift (a manually-deleted address,
      route, or rule) via the periodic backstop even if the event path is
      somehow missed.
- [ ] The `ip monitor rule` subprocess dying is detected and restarted
      without the watch process exiting.
- [ ] Only actual repairs are logged; routine periodic checks that find
      nothing to fix are not.
- [ ] `install --with-watch` / `uninstall` correctly manage the new
      per-instance watch unit, without affecting the existing bring-up
      unit's behavior; omitting `--with-watch` leaves behavior unchanged
      from before this plan.
- [ ] Live-validated on the home machine specifically: deliberately
      delete production instance 0's `ip rule` by hand while `watch` is
      running and confirm it's repaired and logged, for both a fresh
      manual deletion (event path) and by temporarily stopping the event
      path to force the periodic path to be the one that catches it.
