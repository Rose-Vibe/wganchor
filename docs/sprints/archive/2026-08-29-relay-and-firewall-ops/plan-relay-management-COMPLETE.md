# Plan: `wganchor relay add|remove` — manage `relay_ips` without hand-editing config

Depends on `docs/arch/wireguard.md`'s config schema section (`relay_ips`)
and `docs/arch/config-and-lifecycle.md`'s config-file design. Sibling plan
`plan-firewall-port-specs.md` covers the other two asks from the same
conversation (firewall `/both` and port ranges) — kept separate because
the two touch different code paths and carry independent risk (this one:
a live WireGuard cryptokey-routing subtlety; the other: an nftables set
schema migration).

## Motivation

Today, adding or removing a relay IP means hand-editing
`/etc/wganchor/<N>.json`'s `relay_ips` list, then re-running (or
restarting) `server`/`client` to reconcile. Raised in conversation with
the user: nearly every other operational change (firewall ports, peer
identity) already has a CLI command; `relay_ips` is the one persisted,
frequently-touched field left to manual JSON editing. Decided: add
`wganchor relay add`/`wganchor relay remove`, mirroring the existing
`firewall allow`/`deny` pattern the user is already used to.

## Goal

```
wganchor relay add    <server|client> --instance N --ip <ipv4>
wganchor relay remove <server|client> --instance N --ip <ipv4>
```

Each idempotently updates `relay_ips` in the instance's config and, if
the instance's interface already exists, immediately live-applies the
change (see "Live-apply" below) — so the common case needs no separate
restart. `add`ing an already-present IP, or `remove`ing an absent one, is
a no-op (matching `firewall allow`/`deny`'s existing idempotence).

**Role is a required positional argument** (`relay add server ...` /
`relay add client ...`), unlike `firewall`'s subcommands, which take no
role at all. This isn't a style inconsistency — it's because the two
mechanisms are genuinely different per role:

- `ReconcileServerRoutes` vs. `ReconcileClientRouting` (`routing.go`) are
  different functions with different live-state to converge (kernel host
  routes vs. addresses+policy-rules+routes).
- The **server** role's live WireGuard peer `AllowedIPs` is derived
  directly from `RelayIPs` (`AllowedIPsForRole`, `iface.go:13`) — a stale
  `AllowedIPs` must also be refreshed, not just the kernel route (see
  "Live-apply" below). The **client** role's `AllowedIPs` is always
  `0.0.0.0/0` regardless of `RelayIPs` (`iface.go:14-15`), so nothing
  there needs refreshing.

`firewall`'s commands can stay role-agnostic because their mechanism
(nftables rules scoped by `iifname`) is identical regardless of which
role created the interface. `relay`'s mechanism is not — it needs to know
which role's reconciliation to run, the same reason `install`/`uninstall`/
`watch` already take role positionally.

## Non-goals

- **`relay list`/show.** Not asked for; `wg show <iface>` and reading the
  config file already answer "what's configured/live" — add later if it
  turns out to be needed, not preemptively.
- **Bringing the interface up.** If `--instance N`'s interface doesn't
  exist yet, `relay add`/`remove` still updates the config (so the next
  `wganchor <role>` picks it up) but does not create the interface or run
  a full bring-up itself — that stays `server`/`client`'s job, matching
  `pair run`'s identical "never brings the interface up" boundary.
- **Overlap/dedup validation beyond `ValidateConfig`'s existing checks**
  (valid IPv4, no exact-string duplicate). `relay add` reuses that exact
  check; nothing new is added.
- **Preventing `relay remove` from emptying `relay_ips` to zero.** Not
  restricted — `ValidateConfig` already requires a non-empty list before
  any *bring-up* can succeed, which is the right place to enforce that;
  `relay remove` itself has no reason to refuse an operator's intent to
  temporarily configure zero relay IPs.

## Design

### Config lookup: fixed path, matching `firewall`'s precedent (not `pair`'s)

Like `firewall`, not `pair`: `relay` is a root/system operation
(`configPathForInstance`, `lifecycle.go`) reading and immediately live-
manipulating actual kernel/WireGuard state, not a scriptable primitive
someone might reasonably want to point at a `--config`-overridden test
fixture the way `pair pubkey`/`pair peer` do. No `--config` flag.

### IP validation: extract, don't duplicate

`ValidateConfig` (`validate.go:24-35`) already contains the exact IPv4-
only parse-and-check logic `relay add` needs. Extract it into a shared
`validateRelayIP(ip string) error` that both `ValidateConfig`'s loop and
`RelayAdd` call, rather than writing a second copy that could drift.
`RelayRemove` validates `--ip` through the same helper too, for the same
"reject garbage input with an actionable error" symmetry `FirewallDeny`
already has with `FirewallAllow` (both parse the port spec identically
before dispatch) — not because a malformed IP would otherwise do anything
unsafe (`removeRelayIP` would just no-op, since it wouldn't match any
existing entry), but so an operator's typo on `remove` fails the same
clear way it would on `add`, rather than silently no-op-ing.

### List mutation: pure and unit-testable, mirroring `addPortSpec`/`removePortSpec`

```go
func addRelayIP(list []string, ip string) (updated []string, changed bool)
func removeRelayIP(list []string, ip string) (updated []string, changed bool)
```

Identical shape to `firewall.go`'s `addPortSpec`/`removePortSpec`
(`firewall.go:511-541`) — exact-match presence check, no-op if
add-when-present or remove-when-absent, directly unit-testable with no
config, no root, no `nft`/`ip`/`wg`.

### Ordering: persist first, then best-effort live-apply — the opposite of `firewall allow`'s order, deliberately

`FirewallAllow` (`firewall.go:550-576`) applies live *before* persisting,
and only persists if the live apply succeeded. `relay add`/`remove` does
the opposite — persist first, then attempt to live-apply — for a reason
specific to this field, not a style choice:

`relay_ips` already has an established "config is recorded intent,
reconciled idempotently on every bring-up" pattern (`ReconcileServerRoutes`/
`ReconcileClientRouting` already run this way on every `server`/`client`
invocation) — unlike `firewall`'s deliberately *imperative*, one-off-action
model (see `docs/arch/firewall.md`'s "Commands: imperative, not fought
over by a timer"). `firewall`'s scaffold can also apply live in
essentially every situation (it only needs `nft` on `PATH`, not the
`wganchor<N>` interface to exist yet) — so gating its persist on live-apply
success is nearly always achievable. `relay`'s live-apply, by contrast,
**cannot succeed before the interface exists** (`ip`/`wg` commands
against a nonexistent device just fail), and the interface legitimately
does not exist yet the first time an operator sets up an instance's very
first relay IP, *before* ever running `server`/`client` for the first
time. Gating persistence on live-apply success would make `relay add`
useless for exactly the case it's most needed for. So:

```go
func RelayAdd(role string, instance int, ip string) error {
    cfg, path, err := precheckRelayCmd(instance)   // root + config-must-exist, mirrors precheckFirewallCmd
    // ... validateRelayIP(ip), addRelayIP(cfg.RelayIPs, ip) ...
    if changed {
        cfg.RelayIPs = updated
        if err := persistConfig(cfg, path); err != nil { return err }
    }
    return liveApplyRelay(role, cfg, instance)   // best-effort; see below
}
```

### Live-apply: reuse `ConfigureInterface` + the existing `Reconcile*` functions verbatim

**Interface name must be resolved the same way `run()`/`firewall` already
do, before anything live-state-related happens** (caught in plan review):
`cfg.InterfaceName` can legitimately be blank — it's only filled to a
concrete default inside `run()` (`main.go:410-412`) at bring-up time, not
by `loadConfig` itself, and `wireguard.md`'s config schema explicitly
documents omitting it (falling back to `wganchor<N>`) as valid. This
plan's whole motivation is the hand-edited-JSON path, so a blank
`interface_name` is exactly the kind of config this command must handle
correctly, not just the `install`-generated skeleton (which does fill it
concretely). Reuse `firewallInterfaceName`'s exact fallback pattern
(`firewall.go:479-484`) — or extract it to a shared helper — to resolve
`name` from `cfg` *before* calling `interfaceExists(name)`. Getting this
wrong would silently reproduce the exact bug class this plan exists to
prevent: `interfaceExists("")` would spuriously read as "not up yet" for
an instance whose interface is very much up under its real default name,
so `relay add` would print the deferred-application note while the live
peer's `AllowedIPs` quietly goes stale.

If the (correctly-resolved) interface doesn't exist
(`interfaceExists`, `iface.go:26`), skip live-apply and print a note
(`recorded in /etc/wganchor/<N>.json; run 'wganchor <role> --instance N'
to bring it up`) — mirroring `InstallInstance`'s existing enable/start-split
"note:" precedent (`lifecycle.go:216-222`) for "config succeeded, live
application is deferred."

If it does exist, this is deliberately **not** new nft/wg-manipulation
code — it's the same two calls `main.go`'s `run()` already makes right
after `EnsureInterface`, on the config with its now-updated `RelayIPs`:

- **Server**: call `ConfigureInterface(cfg, "server", name)` again before
  `ReconcileServerRoutes`. This is the one genuinely easy-to-miss
  correctness detail in this whole plan: `ReconcileServerRoutes` only
  touches kernel routes (`ip route replace/del ... dev name`) — it never
  touches the WireGuard peer's `AllowedIPs`. But the server-side peer's
  `AllowedIPs` **is** `RelayIPs` (`AllowedIPsForRole`, `iface.go:13-21`),
  and WireGuard enforces `AllowedIPs` as its own cryptokey-routing
  filter independent of the kernel routing table (the exact mechanism
  `docs/arch/overview.md` documents for the *client* side's outbound
  path). Re-running `ConfigureInterface` is idempotent and safe
  (re-setting the same private key, re-setting the peer with the fresh
  `AllowedIPs`, re-running `ip link set up` on an already-up interface
  are all no-ops or harmless re-applications) and is exactly what
  refreshes the peer's `AllowedIPs` to include a newly-added relay IP —
  without it, a newly-`relay add`ed IP would get a kernel route but
  WireGuard itself would still silently refuse to forward traffic to it.
  Then `ReconcileServerRoutes(name, cfg.RelayIPs)` converges the kernel
  routes the same way a full bring-up would.
- **Client**: call `ReconcileClientRouting(name, cfg.RelayIPs, instance)`
  only — no `ConfigureInterface` re-call needed, since the client's
  `AllowedIPs` is always `0.0.0.0/0` regardless of `RelayIPs` (see
  Goal section above), so nothing there depends on this list.

If live-apply fails after the interface does exist, the config change is
already persisted (recorded intent is preserved regardless), and the
command reports the live error plainly along with "re-run `wganchor
relay ...` (idempotent) or `wganchor <role> --instance N` to retry" —
matching the project's general "actionable error, not a silent partial
success" posture rather than trying to roll back the persisted change.

### CLI

```go
func runRelayCmd(args []string)        // dispatches "add"/"remove"
func runRelayAddCmd(args []string)     // parseLifecycleArgs-style role positional, then --instance/--ip flags
func runRelayRemoveCmd(args []string)  // same shape
```

Reuses `parseLifecycleArgs` (`main.go:363-369`) for the `<server|client>`
positional-plus-remaining-args split, exactly as `install`/`uninstall`/
`watch` already do — no new argument-parsing pattern introduced.

## Interaction with existing subcommands

- `server`/`client`/`install`/`uninstall`/`watch`/`firewall`/`pair` are
  unaffected — `relay` only writes `RelayIPs` via the same `persistConfig`
  those already use, and its live-apply path calls only pre-existing,
  unmodified functions (`ConfigureInterface`, `ReconcileServerRoutes`,
  `ReconcileClientRouting`).
- `wganchor watch`'s periodic backstop already re-runs the same
  `Reconcile*` functions on its own interval — a `relay add`/`remove`
  landing moments before a scheduled watch reconcile is harmless
  (idempotent convergence to the same desired state either way runs it).
  `watch` does **not** currently re-run `ConfigureInterface` on its own
  interval (`reconcileOnce`, `watch.go`, only calls the `Reconcile*`
  functions) — so on the **server** role specifically, if something
  external ever reset the live peer's `AllowedIPs` between `relay add`
  calls, `watch` would not repair that on its own. Out of scope for this
  plan (no evidence this happens, unlike the `ip rule`-flush behavior
  `docs/arch/resilience.md` was written to address) but worth a one-line
  note in `docs/arch/wireguard.md` once this ships.

## Exit criteria

- [x] `addRelayIP`/`removeRelayIP` unit-tested: add when absent, no-op
      add when already present, remove when present, no-op remove when
      absent — mirroring `firewall_test.go`'s existing
      `TestAddPortSpec*`/`TestRemovePortSpec*` coverage exactly.
- [x] `validateRelayIP` (extracted from `ValidateConfig`) unit-tested
      against a valid IPv4, an IPv6 address (rejected), and garbage
      (rejected) — and `ValidateConfig`'s own existing tests
      (`validate_test.go`) still pass unmodified against the extracted
      version, proving the extraction didn't change its behavior.
- [x] `relay add`/`remove` persist `relay_ips` correctly and idempotently
      (mtime-unchanged on a genuine no-op, mirroring the mtime-based
      idempotence tests already established in `pair_test.go`/
      `lifecycle_test.go`) — verified without requiring root or a live
      interface, by testing the persist step independent of live-apply.
      Both add- and remove-side no-ops covered (the remove-side gap
      caught in implementation review).
- [ ] **Deferred, needs a real VPS**: live-verified against the real VPS:
      `relay add` on the **server** side while its interface is already
      up adds a *new* relay IP whose traffic is actually reachable
      end-to-end afterward (external vantage point, not loopback) with
      **no** separate restart — specifically confirming the `AllowedIPs`
      refresh via `ConfigureInterface`, not just the kernel route, since a
      kernel route alone reaching this IP but WireGuard silently dropping
      it would otherwise look identical to success in a route-table-only
      check.
- [ ] **Deferred, needs a real VPS**: live-verified on the client side
      symmetrically: `relay add` while the client's interface is up makes
      the new relay IP locally bindable and reachable without restart.
- [x] `relay add`/`remove` invoked against an instance whose interface
      does **not** yet exist updates the config and prints the deferred-
      application note, without erroring. Unit-tested (client role) via
      `liveApplyRelay` directly; `RelayAdd`/`RelayRemove`/the CLI
      themselves require root so aren't exercised end-to-end by the unit
      suite — acceptable, per implementation review, given the
      constraints of this environment.
- [ ] **Deferred, needs a real VPS/interface**: `relay add` against a
      config with a blank `interface_name` *and* a live interface running
      under the default name live-applies correctly — not deferred —
      proving the blank-name (and, per the listen_port bug caught in
      implementation review, blank-port) fallback resolves before the
      `interfaceExists`/`ConfigureInterface` calls rather than after. The
      resolution itself (`resolveRuntimeDefaults`) is unconditionally
      unit-tested; only the "against a genuinely live interface" half of
      this criterion needs a real environment.
- [x] `relay remove` down to an empty `relay_ips` list succeeds (per
      Non-goals, not artificially restricted); a subsequent full
      `wganchor <role>` bring-up against that now-empty list fails with
      `ValidateConfig`'s existing, unmodified "relay_ips is empty"
      error — confirming this plan didn't loosen that pre-flight check.
      `RelayRemove` also now prints a one-line warning when it empties
      the list, added in implementation review so the operator connects
      the *next* bring-up's failure back to this command.
- [x] `README.md` updated: `relay add`/`remove` documented as the
      recommended way to manage `relay_ips`, with the manual JSON-edit
      path kept as the documented fallback (matching this session's
      existing "automatic first, manual as fallback" documentation
      style for `pair`).

**Implementation review** (Opus, two rounds): approved with no blocking
concerns. Round 1 found two blocking issues — `liveApplyRelay` resolved
`interface_name` but not `listen_port`, which could silently rebind the
server to a random ephemeral port on the hand-edited-JSON population this
plan targets (fixed via a new shared `resolveRuntimeDefaults` helper,
used by both `run()` and `liveApplyRelay`); and the README exit criterion
above, which the reviewer's snapshot predated (already fixed while the
sibling firewall-port-specs milestone was in progress). Five should-fix
items also landed: a genuinely-assertive unit test for the interface-name/
listen-port resolution (the original test passed even against the bug it
was meant to catch), the deferred note now names the interface it looked
for, a guard against feeding `wg` blank key material on the hand-edited-
config path, a recorded (not silent) decision not to re-assert the
client-side firewall scaffold on `relay add`, and a warning when `relay
remove` empties the list. Two cosmetic nits from round 2 also folded in:
`resolveRuntimeDefaults`'s persistence comment narrowed to the caller
that actually relies on it, and `firewallInterfaceName` (firewall.go)
collapsed into a thin delegation to `resolveRuntimeDefaults` rather than
carrying a second copy of the same fallback logic.
