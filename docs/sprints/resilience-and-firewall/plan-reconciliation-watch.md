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

For the address and rule diffs, this is purely a return-value change —
`diffRelayIPs`'s `toAdd`/`toRemove` already are the `AddrsAdded`/
`AddrsRemoved` and `RulesAdded`/`RulesRemoved` values, just not currently
threaded back to the caller.

The client's table-default-route step is not covered by an existing
diff, and needs one: `ReconcileClientRouting` currently ends with an
unconditional `ip route replace default dev <name> table <N>`
(`routing.go:199`) with no prior check of whether the route already
existed. Left as-is, a table-default-route repair (e.g. after something
flushes table `N` outright, not just the `ip rule` pointing at it) would
succeed silently with an empty `ReconcileResult` — invisible to Step 4's
"log only on actual repair" design, and inconsistent with this plan's own
exit criteria (repairing dropped routes, but only logging dropped
rules). Fix: before the `replace`, call `ip route show table <N>` and
check for an existing `default dev <name>` line via a new pure parser
(same style as `parseRouteShowHostRoutes`/`parseAddrShowHostIPs`), e.g.
`hasDefaultRoute(output string, name string) bool`; only report
`"default"` in `RoutesAdded` if it was missing. The `replace` call itself
stays unconditional (still safe/idempotent) — only the reporting is
conditional.

Update `main.go`'s two call sites for the new signature (the normal
bring-up path can ignore the result, or log it at a low level — a
healthy idempotent re-run should almost always report `Changed() ==
false`).

**Test plan, revised** (the original wording — "update
`routing_test.go`'s existing tests for the new signature" — doesn't
actually name a mechanism, and there isn't an easy one: no existing test
calls `ReconcileServerRoutes`/`ReconcileClientRouting` today, and they
can't be unit-tested directly without making `runCmd` mockable, which is
more machinery than this plan needs). Instead:
- Extract "turn diff outputs into a `ReconcileResult`" into a small pure
  helper (e.g. `buildReconcileResult(addrAdd, addrRemove, routeAdd,
  routeRemove, ruleAdd, ruleRemove []string) ReconcileResult`) and unit
  test *that* directly — trivial, no `runCmd` involved.
- Unit test the new `hasDefaultRoute` parser the same way the existing
  parsers are tested (sample `ip route show table N` output fixtures,
  including a fixture with an unrelated route in the same table, to
  confirm it doesn't false-positive).
- `ReconcileServerRoutes`/`ReconcileClientRouting` themselves continue to
  be verified live only, exactly as they are today (`plan-tunnel-runtime-
  COMPLETE.md`) — this plan doesn't change that pattern, only adds a
  reporting layer built from already-testable pure pieces.

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
- This filter must be a pure, unit-testable function — e.g.
  `shouldTrigger(line string, table, priority int) bool` — tested against
  *captured real* `ip monitor rule` output (confirm the exact format
  empirically first, per the note above, and keep a sample in the test
  file). This is the only way to actually verify this exit criterion's
  negative half ("an unrelated rule change does not trigger a reconcile")
  — at runtime, a correct non-trigger and a silent bug that never
  triggers are log-indistinguishable from each other.
- **Server-role asymmetry, worth stating explicitly so it isn't later
  mistaken for a bug**: the server side manages no `ip rule`s at all
  (`ReconcileServerRoutes` only handles `/32` host routes) — so
  `shouldTrigger` can never fire for `wganchor watch server`. Server-side
  drift repair is periodic-only. This matches `docs/arch/resilience.md`'s
  scoping (rule-watching is deliberately narrower than "watch
  everything"), it just needs to be written down here so nobody later
  "fixes" the missing server event path as an oversight.

## Step 3: periodic backstop + the watch loop

- `runWatch(role string, instance int, configPath string, interval
  time.Duration) error` — the command's actual logic:
  - Reconcile once immediately at startup, and once after every
    `watchRules` subprocess (re)start — an event during the startup
    window or a restart's backoff would otherwise be missed until the
    next periodic tick or the next real event; reconciling on (re)start
    closes that gap for free and is idempotent regardless.
  - Start `watchRules` in a goroutine; its `onEvent` callback triggers an
    immediate reconcile.
  - A `time.Ticker` at `interval` (default e.g. 5 minutes — a flag,
    `--interval`, can override; document the default in `--help`)
    triggers a periodic reconcile.
  - All paths call the *same* `reconcileOnce(role string, instance int,
    configPath string) (ReconcileResult, error)` helper — loads the
    current config fresh each time via the existing `loadConfig`
    (`config.go`) (so a config edit while the watcher is running takes
    effect, matching the "config is the source of truth, reconciled
    against live state" posture already established), calls the
    appropriate `Reconcile*Routes` function, and logs per Step 4. If the
    config load fails (e.g. the file was deleted or is mid-write), log
    the error and keep watching — do not exit the watch process over a
    transient/one-off config read failure; the next trigger tries again.
  - `watch` accepts the same `--config` flag `server`/`client` already
    do (`resolveConfigPath`, `main.go`), for the same reasons — parity
    with the commands it's reconciling for, not a new lookup mechanism.
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
WantedBy=wganchor-<role>@%i.service
```

`BindsTo` (not just `After`) so the watcher stops automatically when the
bring-up unit stops — it has nothing to watch once the tunnel it's
watching is down. `WantedBy=wganchor-<role>@%i.service` (the bring-up
unit itself, **not** `multi-user.target`) is the other half of that
pairing: enabling the watch unit creates its symlink under
`wganchor-<role>@<N>.service.wants/` rather than
`multi-user.target.wants/`, so starting the bring-up unit — whether at
boot (it's already `WantedBy=multi-user.target` itself, unchanged) or via
a manual `systemctl start` after a stop — also starts its watcher. With
`BindsTo` alone and `WantedBy=multi-user.target`, a manual
`stop`-then-`start` of the bring-up unit would leave the watcher down
until the next reboot; this fixes that without any change to the
already-shipped bring-up unit template.

This means `otherEnabledInstanceUnits` (`lifecycle.go`) — written for the
bring-up unit's single, shared `multi-user.target.wants/` directory —
needs to widen its search for the watch unit's template-removal-safety
check, since each instance's watch-unit enablement symlink now lives
under a *different*, per-instance wants directory
(`wganchor-<role>@0.service.wants/`, `wganchor-<role>@1.service.wants/`,
...) rather than one shared location. Generalize it to glob across all
`*.wants/` directories under `systemdUnitDir` (e.g.
`filepath.Glob(filepath.Join(systemdUnitDir, "*.wants",
pattern))`) rather than a single hardcoded directory — the bring-up
unit's existing call site keeps working unchanged (its symlinks live
under `multi-user.target.wants/`, which the wider glob still matches),
and the watch unit's per-instance-directory symlinks are now found too.
This is a backward-compatible generalization of an existing helper, not
a new one.

**On by default**, matching `docs/arch/resilience.md`: `wganchor install
<role> --instance N` writes/enables both the bring-up unit and this watch
unit (reusing `writeUnitIfChanged`, `otherEnabledInstanceUnits`, etc. from
`lifecycle.go` — the same per-instance-symlink-and-shared-template
pattern already implemented, just for a second unit family). A new
`--no-watch` flag on `install` skips installing/enabling the watch unit
for an operator who wants the old, watcher-less behavior on purpose.
Since this only takes effect on `install`, an already-installed instance
keeps its current behavior until it's reinstalled — this is not a
behavior change injected into already-running instances. `uninstall`
must always stop/disable/remove the watch unit for that instance if it
was installed, regardless of whether `--no-watch` was passed at install
time (mirroring the existing unit's handling exactly — uninstall doesn't
need to know how it got there, just that it might be there).

## Exit criteria

- [ ] `buildReconcileResult` and `hasDefaultRoute` are unit-tested
      directly (pure functions, no `runCmd` involved); `shouldTrigger` is
      unit-tested against captured real `ip monitor rule` output,
      including a case confirming an unrelated table/priority does *not*
      trigger.
- [ ] `wganchor watch` detects an externally-deleted `ip rule` for its
      own instance within a few seconds and repairs it, including the
      case where the table's default route was dropped along with the
      rule (verifying the `hasDefaultRoute` fix — that repair is reported
      and logged, not silently absorbed).
- [ ] `wganchor watch` still repairs drift via the periodic backstop for
      a drift type the event path structurally cannot see — the table's
      default route being deleted directly (not just the `ip rule`
      pointing at it) is exactly such a case, and doesn't require
      disabling anything to test. (Address deletion is deliberately not
      used for this test on a production instance — it can break already-
      open sockets bound to that address; rule/route-table drift only
      affects new inbound connections.)
- [ ] A reconcile runs at watcher startup and after each `ip monitor
      rule` subprocess restart, not only on events/the periodic tick.
- [ ] The `ip monitor rule` subprocess dying is detected and restarted
      without the watch process exiting.
- [ ] Only actual repairs are logged; routine periodic checks that find
      nothing to fix are not.
- [ ] A config load failure mid-watch (e.g. file deleted) is logged and
      does not stop the watch process; the next trigger retries.
- [ ] `install` / `uninstall` correctly manage the new per-instance watch
      unit by default, without affecting the existing bring-up unit's
      behavior; `--no-watch` at install time skips it, and an
      already-installed instance's behavior is unaffected until it's
      reinstalled. `otherEnabledInstanceUnits`'s widened glob correctly
      finds watch-unit enablement symlinks under their per-instance
      `.wants/` directories, and still finds the bring-up unit's under
      `multi-user.target.wants/`.
- [ ] Stopping and restarting the bring-up unit manually
      (`systemctl stop`/`start wganchor-<role>@N`) also stops and
      restarts its watcher, without a reboot.
- [ ] Live-validated on the home machine specifically, with a short
      `--interval` (e.g. 15s, not the 5-minute default) so any deliberate
      breakage window on the real production instance stays bounded to
      seconds: deliberately delete production instance 0's `ip rule` by
      hand while `watch` is running and confirm it's repaired and logged
      (event path); separately, delete table 60217's default route
      directly and confirm the periodic backstop repairs and logs that
      (since the rule-deletion event path cannot see this drift type).
