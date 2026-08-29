# Plan: Firewall (`wganchor firewall`, default-on new interface)

Depends on `docs/arch/firewall.md` (design, already written, including
the exact nftables table/chain/set layout) and the
`project_home_machine_environment` memory (confirms nftables, not ufw,
is the real enforcement point on the home machine).

## Goal

Implement `wganchor firewall enable|allow|deny|disable`, and wire
`enable` (with no ports allowed) into `EnsureInterface`'s
first-time-creation path so a brand-new `wganchor<N>` interface is
locked down by default, with a clear one-time notice — closing the live
exposure found this sprint (a `0.0.0.0`-bound service silently reachable
on the relay IP, no port filtering at all) as a durable fix, superseding
the hand-applied stopgap.

## Step 1: nftables primitives (`firewall.go`)

Following the existing `exec.go`/`routing.go` pattern (shell out to a
CLI tool, parse text output where needed, keep every operation scoped to
exactly what this tool would have created):

- `firewallTableExists() bool` — `nft list table ip wganchor` exit code.
- `ensureFirewallTable() error` — idempotently creates `table ip
  wganchor` and its `input` chain (`type filter hook input priority
  filter; policy accept;`) if absent. Never touches any other table.
- `ensureInstanceSets(instance int) error` — idempotently creates
  `wganchor<N>_tcp`/`wganchor<N>_udp` sets (`type inet_service`) if
  absent.
- `ensureInstanceBaseRules(name string, instance int) error` — idempotent:
  check via `nft -a list chain ip wganchor input` (parse for the
  per-instance comment, e.g. `wganchor-instance-<N>`) whether this
  instance's 4 base rules (established/related accept, tcp-set accept,
  udp-set accept, drop) already exist; add any missing ones. This mirrors
  `routing.go`'s existing "diff against live state, only touch what's
  missing/stale" discipline.
- `allowPort(instance int, port int, proto string) error` — `nft add
  element ip wganchor wganchor<N>_<proto> { <port> }`; adding an
  already-present element is a no-op in nft, so this is naturally
  idempotent.
- `denyPort(instance int, port int, proto string) error` — `nft delete
  element ...`; deleting an absent element errors in nft (unlike add) —
  treat "no such element"-shaped errors as a successful no-op, matching
  `lifecycle.go`'s `isUnitNotInstalledOutput` precedent for turning a
  CLI's "already in the state you wanted" error into success.
- `disableInstanceFirewall(instance int) error` — find and delete exactly
  this instance's 4 base rules (by comment, via handles from `nft -a
  list chain ...`) and its 2 sets; if no other instance's rules remain in
  the shared chain (grep for any other `wganchor-instance-` comment),
  drop the whole `ip wganchor` table. Mirrors `lifecycle.go`'s
  `removeTemplateIfUnused` — same "only remove the shared thing once
  nothing else depends on it" shape.
- Parse the exact `ip monitor`/`nft -a list` output formats empirically
  against the installed `nftables` version before writing the parser —
  do not guess the format (same discipline `routing.go`'s
  `parseIPRuleShowForTable` etc. already followed).

## Step 2: subcommands (`main.go`)

```
wganchor firewall enable  --instance N [--role server|client]
wganchor firewall allow   --instance N --port <port>/<tcp|udp>
wganchor firewall deny    --instance N --port <port>/<tcp|udp>
wganchor firewall disable --instance N
```

`--role` on `enable` only matters for resolving the interface name
(`defaultInterfaceName(instance)` or the config's `interface_name` if
set) — the firewall mechanism itself doesn't care which role created the
interface. `--port` parsing: `<port>/<tcp|udp>` (reject anything else
with an actionable error — matches `validate.go`'s existing "fail fast,
actionable error" posture for malformed input).

Preconditions: same `precheckLifecycle`-style root/`nft`-on-`PATH` checks
as `install`/`uninstall` (`exec.LookPath("nft")` instead of
`systemctl`) — reuse the pattern, not necessarily the exact function,
since firewall commands don't need `systemctl` at all.

## Step 3: default-on for a new interface

`iface.go`'s `EnsureInterface` already distinguishes "created" from
"already existed" (that's what currently gates the "generated a new
keypair" style messaging upstream in `main.go`). Thread that boolean out
to `main.go`'s `run()`:

- If `EnsureInterface` reports it created the interface (first time for
  this instance) **and** a new `--no-firewall` flag was not passed:
  call the equivalent of `firewall enable` for this instance (no ports
  allowed) and print the one-time notice from `docs/arch/firewall.md`.
- If the interface already existed (a normal idempotent re-run), do
  nothing new here — don't re-trigger the notice, and don't touch
  existing firewall state (an operator's `allow`ed ports from a previous
  run must survive a plain `server`/`client` re-run untouched).
- `--no-firewall` on `server`/`client`: skip the default-enable entirely
  for operators who want the old, fully-open behavior on purpose.
  Document clearly in `--help` that this is an explicit opt-out of a
  security default, not a neutral flag.

## Step 4: `install`/`uninstall` integration

`install` doesn't need to change — the default-on behavior lives in
`server`/`client`'s own first-run path (Step 3), which `install`'s
`systemctl start` already invokes. `uninstall --purge` should additionally
call `disableInstanceFirewall` for that instance (mirrors the existing
purge step's interface teardown — firewall state for a purged instance
shouldn't linger any more than its `ip rule`s do, which
`purgeClientPolicyRules` already ensures for the routing side).

## Exit criteria

- [ ] `enable`/`allow`/`deny`/`disable` are each idempotent and scoped to
      exactly one instance — verified an operation on instance 1 never
      touches instance 0's rules, and never touches Docker's or
      Tailscale's tables (their rule/packet counters unaffected by a
      wganchor firewall operation).
- [ ] A brand-new interface is locked down by default (established/
      related only) with the notice printed exactly once; re-running
      `server`/`client` against an existing interface does not re-print
      the notice or reset previously-`allow`ed ports.
- [ ] `--no-firewall` suppresses the default-enable entirely.
- [ ] `uninstall --purge` removes that instance's firewall state.
- [ ] Live-validated on the home machine, each step confirmed from the
      real external vantage point (the existing VPS) rather than a local
      curl (loopback delivery doesn't exercise `iifname` matching, as
      found while validating the hand-applied stopgap this sprint):
      a `0.0.0.0`-bound test service unreachable via the relay IP by
      default, reachable after `allow`, unreachable again after `deny`,
      and fully open again after `disable`.
- [ ] The hand-applied stopgap ruleset (table `ip wganchor` on the home
      machine) is either reused as-is by `enable`'s idempotent checks or
      cleanly superseded — no duplicate table/chain left behind.
- [ ] The VPS's own firewall (`ufw`, opened listen port, forwarding
      rules) is untouched by this feature.
