# Sprint: Resilience and Firewall

## Purpose

Two gaps found live during the wireguard-automation sprint's closing
validation (2026-08-29), both raised directly by the user immediately
after:

1. wganchor's client-side `ip rule` was found silently missing on the
   home machine — something (Tailscale's own log blames
   `systemd-networkd`) periodically flushes `ip rule` system-wide, and
   wganchor has no self-healing for this the way Tailscale does for its
   own rules. See `docs/arch/resilience.md` and the
   `project_routing_rule_flush_bug` memory.
2. A service bound to `0.0.0.0` on the client machine is automatically
   reachable on the relay IP with no port-level filtering at all — the
   home machine already had several such services exposed with zero
   extra action taken. wganchor currently has no firewall management of
   its own. See `docs/arch/firewall.md`.

Both architecture docs are written; this sprint implements them.

## Scope

1. **Resilience** (`plan-reconciliation-watch.md`): a new
   `wganchor watch <role> --instance N` companion process, installed and
   enabled by default (matching Tailscale's own out-of-the-box
   resilience — `--no-watch` opts out) — watches `ip monitor rule` for
   the fast path, periodic reconciliation as a backstop, logs only when
   it actually repairs something.
2. **Firewall** (`plan-firewall.md`): `wganchor firewall
   enable|allow|deny|disable`, imperative/not config-managed, own
   dedicated nftables table coexisting with Docker/Tailscale's own
   tables, default-enabled (with a one-time notice) the first time a
   `wganchor<N>` interface is created.

## Known state at sprint start (2026-08-29)

- A stopgap default-deny firewall for `wganchor0` on the home machine
  was applied by hand (`nft` directly, table `ip wganchor`) to close the
  live exposure immediately, ahead of the real feature — live-verified
  from the VPS (external vantage point) that it blocks a previously-
  exposed `0.0.0.0`-bound service while leaving the tunnel, SSH, Docker,
  and Tailscale unaffected. This will not survive a reboot until
  `firewall enable`'s logic is implemented and wired into `server`'s
  bring-up path — Docker and Tailscale reapply their own rulesets at
  their own startup the same way; wganchor should do the same.
- The missing `ip rule` for production instance 0 was already manually
  repaired (`wganchor client --instance 0`) once found; this sprint is
  about making that self-healing, not a one-off fix.
- `wganchor` currently builds `server`/`client`/`install`/`uninstall`;
  this sprint adds `watch` and `firewall` as new subcommands.

## Plans

- `plan-reconciliation-watch.md` — the `watch` companion process.
- `plan-firewall.md` — the `firewall` subcommand family and
  default-on-new-interface behavior.

## Exit criteria for the sprint

- [x] Both architecture docs' exit criteria (`docs/arch/resilience.md`,
      `docs/arch/firewall.md`) are met and live-validated on the home
      machine specifically — that's where both problems were found.
- [x] The hand-applied stopgap firewall is superseded by the real feature:
      production instance 0 now runs the reviewed `firewall.go`
      implementation via its actual systemd units
      (`wganchor-client@0.service`, `wganchor-watch-client@0.service`),
      not a hand-run `nft` script — verified by deploying the built
      binary to `/usr/local/bin/wganchor` and restarting both units,
      confirming the same default-deny ruleset re-applies automatically.
- [x] No regression to the already-shipped `server`/`client`/
      `install`/`uninstall` behavior — `watch` and the default-on firewall
      are additive; `--no-firewall` provides an escape hatch. Verified via
      the full test suite plus repeated idempotent live re-runs against
      production instance 0 throughout both plans' implementation.

## Outcome (closed 2026-08-29)

Both plans implemented, reviewed (Fable for plan review, Opus for
implementation review, iterated to approval), and committed:
`74edd91` (reconciliation watch) and `28289bc` (firewall). The
implementation review for the firewall plan caught two blocking exposure
bugs before commit — the firewall being applied after the relay IP was
already bound, and rule-presence matching that ignored `iifname` (so an
`interface_name` change would have silently left the new interface
unfiltered) — both fixed and re-verified live before shipping. See each
plan's own exit-criteria checklist (now renamed `-COMPLETE.md`) for the
full validation record.

The normal CLAUDE.md autonomous pipeline applies throughout, stopping
only for the standard exceptions (architectural conflict, irreversible
consequence, systemic test failure, unsafe/destructive action). Given
both plans touch this specific, currently-live home machine (Docker and
Tailscale both running real workloads), implementation testing should
prefer the existing VPS / a disposable environment first wherever
possible, and treat any change to this machine's live firewall/routing
state with the same care already applied to the stopgap above
(verify from an external vantage point, never assume a local/loopback
check is representative).
