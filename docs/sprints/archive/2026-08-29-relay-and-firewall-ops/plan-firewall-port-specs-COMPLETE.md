# Plan: firewall `--port` improvements — `/both` and ranges

Depends on `docs/arch/firewall.md`. Sibling plan `plan-relay-management.md`
covers the third ask from the same conversation (`wganchor relay
add|remove`) — kept separate; this plan's risk is entirely contained to
`firewall.go`'s port-spec parsing/storage and an nftables set-schema
migration, unrelated to `plan-relay-management.md`'s WireGuard
cryptokey-routing concern.

## Motivation

Raised in conversation with the user: some services need both TCP and
UDP allowed on the same port (DNS/53, HTTP3-QUIC/443, many game servers),
and today that means two separate `firewall allow` invocations with no
single-command way to express "both." Separately: allowing a whole port
range currently means one `firewall allow` call per port, which doesn't
scale for anything wider than a handful of ports.

## Goal

```
wganchor firewall allow --instance N --port 8080/both
wganchor firewall allow --instance N --port 8000-8010/tcp
wganchor firewall allow --instance N --port 8000-8010/both
```

`deny` takes the identical spec shapes.

## Non-goals

- **Defaulting a bare port (no `/proto` at all) to "both."** Considered
  and rejected: a `--port 8080` typo that silently opens *two* protocols
  instead of the one the operator meant is a worse failure mode than
  requiring the explicit word. `/both` is spelled out on purpose.
- **Overlap/merge detection** between a newly-added spec and an already-
  allowed one that overlaps or contains it (e.g. `8080/tcp` already
  allowed, then `8000-8100/tcp` added too — both now coexist as separate
  list entries and separate `nft` set elements). Not validated or
  deduplicated; `nft`'s own behavior on overlapping interval-set elements
  is the source of truth, not a rule this plan tries to pre-enforce.
  (Empirically confirm during implementation whether `nft` accepts
  overlapping intervals silently or errors — either outcome is
  acceptable, since the operator asked for both explicitly, but the
  behavior should be understood and noted here.)
- **`deny`ing a sub-range of a previously-`allow`ed range.** `deny`
  remains exact-spec-match only (removing `8005/tcp` when `8000-8010/tcp`
  is what's actually allowed is a no-op, not a partial split) — the same
  pre-existing limitation single ports already have with duplicate/
  overlapping entries, not a new restriction introduced here.
- **Migrating a table that was created by a wganchor binary predating
  this change, on a host with `nft` unavailable at migration time.**
  Covered the same way every other `nft`-dependent path already is
  (`errNftMissing`) — not a special case.

## Design

### `/both`: CLI-layer expansion only, never reaches storage or `nft`

```go
// expandBothProto returns spec unchanged, or — if spec ends in "/both" —
// the equivalent ["<base>/tcp", "<base>/udp"] pair. Pure, CLI-layer only:
// "both" is never a value parsePortSpec, FirewallAllowedPorts, or any nft
// set element ever needs to understand.
func expandBothProto(spec string) []string
```

`runFirewallCmd`'s `allow`/`deny` cases call this before doing anything
else, then loop over the (one or two) resulting specs, calling the
existing `FirewallAllow`/`FirewallDeny` once per expanded, single-protocol
spec — each already idempotent, so `allow 8080/both` when `8080/tcp` is
already allowed only actually adds `8080/udp`. `parsePortSpec` itself
continues to reject anything that isn't literally `tcp` or `udp` as its
protocol — if `"both"` ever reached it directly (a bug, since the CLI
layer should always expand first), the resulting error message is exactly
as actionable as any other bad protocol value today.

### Ranges: `parsePortSpec` returns a `(start, end)` pair; a single port is `start == end`

```go
// parsePortSpec parses "<port>/<tcp|udp>" or "<start>-<end>/<tcp|udp>".
// A single port normalizes to start == end, so every downstream
// consumer (allowPortRange, currentAllowedPorts, ...) handles both
// shapes uniformly with no separate single-port code path.
func parsePortSpec(spec string) (start, end int, proto string, err error)
```

Validation: `start <= end`, both in `1..65535` (same bounds as today).
`allowPort`/`denyPort` (renamed `allowPortRange`/`denyPortRange`) build the
nft element literal as `{ <port> }` when `start == end`, `{ <start>-<end>
}` otherwise. Stored/compared spec strings follow the same rule
(`fmt.Sprintf("%d/%s", ...)` for a single port, `"%d-%d/%s"` for a genuine
range) — a single port's on-disk/in-memory representation is byte-for-byte
unchanged from today, so no config migration is needed for existing
single-port entries.

### nft sets need `flags interval` to hold range elements — this is a schema change

`ensureInstanceSets` (`firewall.go:62-70`) creates sets as plain
`{ type inet_service; }`. Only a set with `flags interval;` accepts a
range element like `{ 8000-8010 }`.

**Verification spike, step 0 of implementation, go/no-go before writing
anything else in this plan** (caught in plan review — this assumption
was originally buried mid-design as "confirm empirically," which
undersold how load-bearing it is): against the actual `nft` version in
use, confirm (a) a set declared `{ type inet_service; flags interval; }`
accepts range elements like `{ 8000-8010 }`, and (b) the same
interval-flagged set transparently accepts an ordinary single-port
element like `{ 8080 }` with no special casing (i.e., a single port really
is just a length-1 interval as far as `nft` is concerned). If (b) is
false, this plan's "no config migration needed for existing single-port
entries, no need for separate interval/non-interval sets" claims (above)
both need revisiting before proceeding further — do not build the
migration logic below on an unverified assumption.

**Migrating an already-deployed, non-interval set** is the one genuinely
tricky part of this plan. **Corrected in plan review** (the original
draft here proposed deleting and re-adding only the one affected proto's
base rule, which is wrong — see below):

1. `ensureFirewallScaffold` gains a step, before `ensureInstanceSets`,
   that detects a stale-schema set: `nft list set ip wganchor
   <name>`'s output lacking `flags interval` means it predates this
   change (a brand-new set, or an `nft list set` failure because the set
   doesn't exist yet at all, both mean "nothing to migrate" — only an
   *existing* set missing the flag needs it).
2. **If either proto's set needs migrating, delete all 4 of the
   instance's base rules first, not just the rule(s) referencing the
   migrating set(s).** `nft add rule` (used by `ensureInstanceBaseRules`)
   only ever appends at the chain tail — it has no "insert before" by
   comment, only by handle or position (`firewall.go:174-175`'s own
   comment spells this out explicitly). Deleting only the one affected
   rule (e.g. just `tcp`) and letting `ensureInstanceBaseRules` re-append
   it would land the re-added accept rule *after* the still-present
   `drop` rule — a terminating match that already accepts nothing and
   drops everything on that `iifname` — making the re-added accept rule
   permanently dead and every previously-allowed port on that proto
   unreachable. This isn't a hypothetical: it directly contradicts the
   invariant `ensureInstanceBaseRules`'s own comment documents ("It would
   NOT hold if something external deleted only a middle rule... the
   re-added accept would land after the existing drop and never match").
   Fix: reuse `ruleHandlesForInstance` (`firewall.go:233-249` — the same
   full-teardown lookup `disableInstanceFirewall` already uses) to find
   and delete **all four** of the instance's base rules whenever either
   set needs migrating, not a single-kind lookup (no function for "find
   just the tcp rule's handle" exists today, and none needs to be
   written). This briefly leaves the instance's interface with no rules
   at all during an `allow`/`enable`/bring-up call (chain policy is
   `accept`, so traffic is briefly unfiltered) — the same non-atomic-
   command tradeoff `disableInstanceFirewall` already carries for its own
   teardown, just now reachable from an ordinary `allow`/`enable`/
   bring-up too, not only an explicit `disable`. Worth a one-line note in
   the implementation, not a blocker.
3. Delete the stale set(s), then let `ensureInstanceSets` create the
   fresh, interval-flagged one(s) — `ensureInstanceSets` itself gains the
   `flags interval` literal (it is not left unmodified; only its
   *migration-detection* responsibility stays outside it, in step 1 above).
4. **No new reconvergence logic needed beyond the corrected rule
   deletion above.** `ensureInstanceBaseRules` already detects all 4
   missing base rules (via `existingInstanceBaseRuleKinds`) and re-adds
   them in the correct `established → tcp → udp → drop` order, exactly
   as it would for a brand-new instance — and every call site that calls
   `ensureFirewallScaffold` (`FirewallEnable`, `FirewallAllow`,
   `main.go`'s client bring-up) already calls `applyFirewallAllowedPorts`
   immediately afterward, which diffs the (now-empty) live sets against
   `FirewallAllowedPorts` and re-adds every persisted entry. The
   migration is therefore self-healing on the very next
   `enable`/`allow`/bring-up, using entirely pre-existing convergence
   machinery — no call site changes required.

This mirrors `lifecycle.go`'s `writeUnitIfChanged` in spirit (detect a
stale on-disk/on-system artifact that predates a code change, replace it,
let existing reconciliation repopulate it) applied to nft rules/sets
instead of a systemd unit file.

### `FirewallAllow`/`FirewallDeny`: signatures change to carry a range

**Spelled out explicitly here per plan review** (the original draft left
this unstated, even though it's necessary plumbing for the Goal section's
own example commands to work at all):

```go
func FirewallAllow(instance, start, end int, proto string) error
func FirewallDeny(instance, start, end int, proto string) error
```

A single port calls these with `start == end`, matching `parsePortSpec`'s
own normalization. Internally, `FirewallAllow`'s `spec :=
fmt.Sprintf("%d/%s", port, proto)` (today, `firewall.go:558`) becomes the
same range-aware formatter used everywhere else (see "Ranges" above: `"%d/%s"`
when `start == end`, `"%d-%d/%s"` otherwise) — this is the exact string
that gets persisted to `FirewallAllowedPorts` and compared against in
`applyFirewallAllowedPorts`'s diffing, so it must exactly match what
`allowPortRange`/`denyPortRange` write and `parseSetElements` reads back.
`main.go`'s `runFirewallCmd` (today: `parsePortSpec(*port)` →
`(p, proto)` → `FirewallAllow(*instance, p, proto)`) is updated to thread
`(start, end, proto)` through unchanged otherwise — this is a pure
plumbing change to an existing call site, not a new design decision.

### Reading ranges back

`parseSetElements` (`firewall.go:337-354`) currently parses only bare
integers from `nft list set`'s `elements = { ... }` line.
Update it to also recognize a `"<start>-<end>"` token, returning raw
port-or-range strings (not `[]int`) so `currentAllowedPorts`
(`firewall.go:361-376`) can uniformly append `/<proto>` to either shape.
Confirm during implementation that `nft`'s own range-element output
format round-trips exactly against what was written (needed for
`diffRelayIPs`-based string-equality comparison in
`applyFirewallAllowedPorts` to correctly treat a re-read range as
unchanged rather than spuriously re-adding it every bring-up).

## Interaction with existing subcommands

- `server`/`client`'s bring-up path is unaffected except that
  `ensureFirewallScaffold` now self-migrates a stale-schema set the first
  time it runs against one — transparent to the operator, no flag or
  manual step needed.
- Existing single-port `firewall_allowed_ports` entries need no config
  migration (unchanged string format, per "Ranges" above).
- `disableInstanceFirewall`'s existing rules-before-sets deletion order
  is unaffected — this plan's migration reuses that exact same
  constraint, it doesn't introduce a new one.

## Exit criteria

- [x] **Step 0, before anything else**: the `flags interval` spike above
      confirms both (a) range elements and (b) transparent single-port
      elements work as expected against the real `nft` version in use.
      Run by hand (sudo, throwaway tables) against the real nft v1.0.9 on
      this machine: both confirmed — a single port reads back as a bare
      integer, not a degenerate range, and coexists fine with a range
      element in the same set. Also empirically confirmed nft rejects an
      overlapping range add ("interval overlaps with an existing one")
      rather than silently accepting it, and does not auto-merge adjacent
      elements — both good news for this plan's Non-goals and the
      round-trip string-equality requirement below.
- [x] `parsePortSpec` unit-tested: a single port (unchanged externally-
      visible behavior, though its return type gains a second int — the
      existing `TestParsePortSpecValid`-style tests were *edited* to
      match the new signature, not merely added to), a valid range,
      `start > end` (rejected), non-numeric bounds (rejected),
      out-of-1-65535 bounds on either side of a range (rejected).
- [x] `expandBothProto` unit-tested: a plain spec passes through
      unchanged; a `/both` spec expands to exactly the tcp+udp pair with
      the same port-or-range prefix.
- [x] The migration's rule-deletion logic is unit-tested directly
      (`TestRuleHandlesForInstanceForMigration`, exercising the exact
      `ruleHandlesForInstance` call `migrateStaleInstanceSets` makes,
      against the existing `sampleChainListing` fixture's instance-0
      4-rule case), not left to live verification alone.
- [x] `firewall allow --port <spec>/both` and `firewall deny
      --port <spec>/both` live-verified to affect exactly the tcp and udp
      sets, nothing else — confirmed idempotent in both directions
      (`allow 53/tcp` then `allow 53/both` only adds udp; `deny 53/both`
      removes both cleanly with neither side erroring).
- [ ] **Deferred, needs a real VPS and external vantage point**: a range
      is live-verified end-to-end: `allow --port 8000-8010/tcp` makes
      every port in that range (spot-checked, not exhaustively) reachable
      via the relay IP from an external vantage point, and ports outside
      the range remain blocked. Everything checkable from the host itself
      (rule presence, set contents, idempotence) is live-verified; only
      genuine off-machine traffic remains.
- [x] The nft-set migration is live-verified against a pre-existing,
      non-interval-flagged set (hand-crafted with `nft` directly): all 4
      base rules are removed before the stale set is deleted (no "Device
      or resource busy" error), the set is recreated with `flags
      interval`, all 4 base rules are re-added in the correct order —
      confirmed not just present but functioning (the migration path was
      exercised via `firewall deny` against a range that was never
      allowed, specifically to prove the rules aren't dead behind the
      drop rule). A second live pass, added during implementation review,
      also confirmed previously-allowed ports unrelated to the migrating
      range survive the migration — an implementation-review finding, not
      part of the original plan: the first cut of the migration-triggered-
      by-`deny` code path deleted the stale set without repopulating it,
      which would have silently dropped unrelated allowed ports. Fixed by
      calling `applyFirewallAllowedPorts` right after migration-triggered
      recreation, before the actual deny proceeds.
- [x] `currentAllowedPorts`/`parseSetElements` round-trip a range
      correctly: confirmed via the step-0 spike (nft neither merges
      adjacent elements nor renders well-known ports as service names, so
      the persisted string and the read-back string are byte-identical)
      plus `TestParseSetElementsRange`/`TestParseSetElementsWrappedAcrossLines`
      (the latter added in implementation review: nft wraps `elements =
      { ... }` across multiple lines once a set holds enough entries,
      which `parseSetElements` already handled correctly but was
      previously only exercised by single-line fixtures).
- [x] `docs/arch/firewall.md`'s nftables schema snippet updated to
      include `flags interval`, per CLAUDE.md's "update docs/arch/ if the
      change affects architecture" step — not just `README.md`.
- [x] `README.md`'s firewall section, `main.go`'s usage strings, and the
      `<port>/<tcp|udp>`-shaped doc comments in `firewall.go` are all
      updated to reflect `/both` and range support.

**Implementation review** (Opus, two rounds): approved with no blocking
concerns. Round 1 found one blocking issue not anticipated by the plan:
the `flags interval` schema change silently changed nft's "element
already absent" error wording from "No such file or directory" to
"element does not exist" — `isNftAbsentOutput` didn't match the new
wording, so `deny` (single ports included, not just ranges/`/both`)
broke across the board for the documented "denying an absent port is a
no-op" case, including a stuck-state variant where a persisted-but-
never-live entry could never be removed. Fixed by matching both
wordings, with test fixtures for each. Three should-fix items also
landed: `FirewallDeny` now triggers migration too (it didn't, only
`FirewallAllow`/`FirewallEnable` did, via `ensureFirewallScaffold`) —
implemented as a narrower fix than a blunt `ensureFirewallScaffold` call,
since that would have turned `deny` against a never-enabled or explicitly
disabled instance into an unwanted scaffold-creation side effect; unit
tests added for `portRangeElement` and for `parseSetElements` against
nft's real multi-line-wrapped output. A `/both` partial-failure case now
tells the operator which half already applied. A late nit
(`FirewallDeny`'s migration-triggered recreation now also checks
`!cfg.DisableFirewall`, closing a narrow nft-goes-missing-then-reappears
gap) was folded in too.
