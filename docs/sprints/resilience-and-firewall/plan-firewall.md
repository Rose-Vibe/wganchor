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
  missing/stale" discipline. **Match the comment exactly (quoted, full
  string), never as a substring** — `wganchor-instance-1` is a substring
  of `wganchor-instance-10`, so a naive `strings.Contains` would make
  instance 1's rule-presence check (and, worse, instance-10's cleanup in
  `disableInstanceFirewall` below) match instance 10's rules too. Unit
  test this exact case.
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
  this instance's 4 base rules (by exact comment match, via handles from
  `nft -a list chain ...`) **before** its 2 sets, not after — nft refuses
  to delete a set that a rule still references, so the order matters, not
  just the end state. Then, if no other instance's rules remain in the
  shared chain (a prefix scan for any other `wganchor-instance-` comment
  is fine here, unlike the exact-match requirement above, since this
  check only needs "is anything else still using this table" not "which
  exact instance"), drop the whole `ip wganchor` table. Mirrors
  `lifecycle.go`'s `removeTemplateIfUnused` — same "only remove the
  shared thing once nothing else depends on it" shape. Grant this
  function the same error tolerance already specified for `denyPort`:
  a rule/set/table that's already gone (a previous partial teardown, or
  this instance's firewall was never enabled in the first place — see
  Step 4's `uninstall --purge` integration) is a successful no-op, not an
  error.
- Parse the exact `nft -a list` output format empirically against the
  installed `nftables` version before writing the parser — do not guess
  the format (same discipline `routing.go`'s `parseIPRuleShowForTable`
  etc. already followed).

## Step 2: subcommands (`main.go`)

```
wganchor firewall enable  --instance N
wganchor firewall allow   --instance N --port <port>/<tcp|udp>
wganchor firewall deny    --instance N --port <port>/<tcp|udp>
wganchor firewall disable --instance N
```

No `--role` flag: resolving the interface name only needs the instance
number (`configPathForInstance`/`loadConfig` → `cfg.InterfaceName`, or
`defaultInterfaceName(instance)` if the config doesn't set one — the same
fallback `main.go`'s `run()` already applies), and config lookup itself
is already instance-only (`resolveConfigPath`/`configPathForInstance`,
`config.go`) with no role component in the path. The firewall mechanism
itself doesn't care which role created the interface either way (see
`docs/arch/firewall.md`'s scope section) — a role flag here would be
unused input, not a real parameter.

`--port` parsing: `<port>/<tcp|udp>` (reject anything else with an
actionable error — matches `validate.go`'s existing "fail fast,
actionable error" posture for malformed input).

Preconditions: same `precheckLifecycle`-style root/`nft`-on-`PATH` checks
as `install`/`uninstall` (`exec.LookPath("nft")` instead of
`systemctl`) — reuse the pattern, not necessarily the exact function,
since firewall commands don't need `systemctl` at all.

## Step 3: default-on for a new interface, and surviving a reboot

**Correction to the original draft**: `EnsureInterface` (`iface.go`)
currently returns only `error` — it does *not* already expose a
created-vs-already-existed signal to its caller (the "generated a new
keypair" messaging in `main.go` is gated by `EnsureKeys`'s own
`generated` return, an unrelated function). This step requires changing
`EnsureInterface`'s signature to `(created bool, err error)` and updating
its one call site in `main.go` — a small, mechanical change (the
distinction is already computed internally, via `interfaceExists`, just
not returned), not a "thread an existing value through" as originally
worded.

### Two new config fields, so firewall state survives a reboot

The live-only, imperative design (`docs/arch/firewall.md`) is right for
*how* `allow`/`deny` take effect — no separate reconcile timer fights an
operator's manual `nft` edits between runs. But taken completely
literally it has a real gap: a reboot destroys the interface, and
`server`/`client` re-creating it on restart would see `created == true`
again and re-enable a *default-deny-with-empty-sets* firewall — silently
discarding any ports the operator had `allow`ed, and silently undoing an
explicit `firewall disable`. Docker and Tailscale don't have this
problem because they restore their own rulesets from their own persisted
state at their own startup; wganchor needs the equivalent, or this
feature actively regresses an operator's setup on every reboot.

Add two fields to `Config` (`config.go`):

```go
DisableFirewall      bool     `json:"disable_firewall,omitempty"`
FirewallAllowedPorts []string `json:"firewall_allowed_ports,omitempty"` // e.g. "8080/tcp"
```

- `firewall allow`/`deny` update **both** the live nftables state and
  this list (add/remove the `"<port>/<proto>"` string) — still imperative
  commands, still the only way to change the list; nothing times-based
  reconciles it. `firewall disable` sets `DisableFirewall = true` and
  clears the list; `firewall enable` (run explicitly, not via the
  bring-up default-on path) sets `DisableFirewall = false`.
- `server`/`client`'s bring-up (`main.go`'s `run()`), **on every
  invocation, not just first-time creation**: if `!cfg.DisableFirewall`,
  ensure the base scaffold exists (`ensureFirewallTable`/
  `ensureInstanceSets`/`ensureInstanceBaseRules` — all idempotent no-ops
  if already correct) and ensure the live port sets match
  `cfg.FirewallAllowedPorts` exactly (add missing, remove stale — the
  same `diffRelayIPs`-shaped diff-and-apply already used for addresses/
  routes/rules, applied to a list of `"port/proto"` strings instead of
  IPs). This is the mechanism that makes an `allow`ed port, and a
  `disable`d firewall, actually survive a reboot: bring-up always
  converges live state to match the last-recorded intent, the same way
  it already does for `relay_ips`.
- The **notice** is still gated on `created` specifically (see below),
  not on every bring-up — an operator sees it once per interface
  creation (which, yes, includes every reboot, since the interface is
  re-created each time; that repetition is a feature, not a bug, given
  it's also the moment firewall state gets re-applied) rather than on
  every idempotent re-run against an already-existing interface.

This is a deliberate, narrow adjustment to "not config-managed or
reconciled": the *port list* is persisted and re-applied once per
bring-up so it survives a restart, matching this sprint's own
"resilience, out of the box" goal (see the reconciliation-watch plan) —
but nothing external ever fights or re-diffs it *between* bring-ups the
way `routing.go`'s functions do for `relay_ips` on a timer. If this
tension is judged unacceptable on review, the fallback is to accept
"ports don't survive a reboot, `--no-firewall` is the only durable
choice" as an explicitly documented limitation instead — but that
directly undercuts the sprint's own "shouldn't need to remember to do
anything" goal, so persistence is the recommended path here.

### Wiring `created` to the notice

- If `EnsureInterface` reports `created == true` (first time for this
  instance, including after a reboot) **and** `cfg.DisableFirewall` is
  not set: ensure the firewall scaffold + recorded ports (per above) and
  print a one-time notice. Word it accurately given the above — not "this
  removes the firewall entirely" (that was the original, misleading
  draft wording), but something like:

  ```
  wganchor: new interface wganchor0 — a default-deny firewall was enabled on it automatically.
  No inbound ports are open yet. To expose a service: wganchor firewall allow --instance 0 --port 8080/tcp
  To turn this off for this instance:                wganchor firewall disable --instance 0
  (Firewall state is re-applied on every bring-up, including after a reboot, so allowed ports persist.)
  ```
- If the interface already existed (a normal idempotent re-run within
  the same boot), the notice is not re-printed, but the config-driven
  scaffold/port-set convergence above still runs unconditionally (cheap,
  idempotent, and needed so a mid-session `firewall allow` — run while
  `server`/`client` isn't actively re-invoked — doesn't get silently
  reverted by some *other*, unrelated future re-run either).
- `--no-firewall` on `server`/`client`: equivalent to `DisableFirewall =
  true` for this invocation, without necessarily persisting it (an
  operator wanting a *durable* opt-out should use `firewall disable`,
  which does persist it, per above) — this flag is for "don't do this
  right now," not a second way to set the persisted field. Document
  clearly in `--help` that this is an explicit opt-out of a security
  default, not a neutral flag.

### If `nft` is unavailable, or `enable` fails, during `server`/`client`'s first run

Default-on wires a new hard dependency (`nft` on `PATH`, a working
nftables) into the already-shipped `server`/`client` bring-up path.
Decision: **fail hard with an actionable error**, the same posture
`precheckLifecycle` already applies to `install`/`uninstall` needing
`systemctl` — silently proceeding with the tunnel open and unfirewalled
would defeat the entire point of this feature, and would be a much worse
failure mode than refusing to start. `--no-firewall` is the documented
escape hatch for a host that genuinely can't run nftables.

This knowingly supersedes `plan-tunnel-runtime-COMPLETE.md`'s completed
exit criterion "no code path invokes ufw/iptables/nft" — worth one line
back in that archived plan (or a note in `docs/arch/wireguard.md`)
acknowledging the supersession once this ships, so the archive doesn't
read as contradicted without explanation.

## Step 4: `install`/`uninstall` integration

`install` doesn't need to change — the default-on behavior lives in
`server`/`client`'s own first-run path (Step 3), which `install`'s
`systemctl start` already invokes. `uninstall --purge` should additionally
call `disableInstanceFirewall` for that instance (mirrors the existing
purge step's interface teardown — firewall state for a purged instance
shouldn't linger any more than its `ip rule`s do, which
`purgeClientPolicyRules` already ensures for the routing side). Given
`disableInstanceFirewall`'s error-tolerance requirement from Step 1, this
call must be a graceful no-op — not an error — for every case where this
instance's firewall was never enabled to begin with: a VPS `server`
instance (firewalling is a client-side default, per
`docs/arch/firewall.md`'s scope), an instance installed with
`--no-firewall`/later `firewall disable`d, or a host where `nft` was
never installed at all. `uninstall --purge` must succeed in all of these
cases exactly as it does today.

## Exit criteria

- [ ] `enable`/`allow`/`deny`/`disable` are each idempotent and scoped to
      exactly one instance — verified an operation on instance 1 never
      touches instance 0's rules, and never touches Docker's or
      Tailscale's tables (their rule/packet counters unaffected by a
      wganchor firewall operation).
- [ ] The comment-match logic is exact, not substring — unit-tested with
      an instance-1-vs-instance-10 fixture confirming instance 1's
      enable/disable never matches instance 10's rules.
- [ ] `disableInstanceFirewall` deletes rules before sets, and tolerates
      an already-partially-or-fully-absent table/chain/rules/sets as
      success, not an error.
- [ ] A brand-new interface is locked down by default (established/
      related only) with the notice printed once per interface creation
      (this legitimately includes once per reboot, since the interface
      is re-created each time — not "exactly once ever"); re-running
      `server`/`client` against an existing interface within the same
      boot does not re-print the notice, and does not reset previously-
      `allow`ed ports.
- [ ] `--no-firewall` suppresses the default-enable for that invocation.
- [ ] Firewall state survives a reboot: an `allow`ed port is still open
      after the interface and its firewall scaffold are torn down and
      recreated (simulate via `ip link delete` + re-running `server`/
      `client`, without needing an actual reboot); a `firewall disable`d
      instance stays open across the same simulated recreation.
- [ ] `nft` missing from `PATH` (or `enable` otherwise failing) on
      `server`/`client`'s first run is a hard, actionable failure, not a
      silent partial success — verified no tunnel state is left half-
      configured. `--no-firewall` avoids this failure entirely for a
      host that can't run nftables.
- [ ] `uninstall --purge` removes that instance's firewall state, and is
      a graceful no-op (not an error) for an instance whose firewall was
      never enabled (server role, `--no-firewall`, or `nft` absent).
- [ ] Live-validated on the home machine, each reachability step
      confirmed from the real external vantage point (the existing VPS)
      rather than a local curl (loopback delivery doesn't exercise
      `iifname` matching, as found while validating the hand-applied
      stopgap this sprint): a `0.0.0.0`-bound test service unreachable
      via the relay IP by default, reachable after `allow`, unreachable
      again after `deny`, and fully open again after `disable`.
- [ ] The hand-applied stopgap ruleset (table `ip wganchor` on the home
      machine) is either reused as-is by `enable`'s idempotent checks or
      cleanly superseded — no duplicate table/chain left behind.
- [ ] The VPS's own firewall (`ufw`, opened listen port, forwarding
      rules) is untouched by this feature.
- [ ] `plan-tunnel-runtime-COMPLETE.md`'s "no code path invokes ufw/
      iptables/nft" exit criterion is annotated as superseded by this
      plan, with a pointer here, so the archive stays coherent.
