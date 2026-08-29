# Plan: split flat `package main` into `cmd/`+`internal/`

Milestone 3 (last) of the `project-standards` sprint (see `SPRINT.md`).
Highest-risk milestone, deliberately done last, after CI
(`plan-ci-and-license-COMPLETE.md`) and linting
(`plan-linting-COMPLETE.md`) are in place to catch regressions.

## Motivation

`wganchor` is ~6000 lines across 12 flat `package main` files at the repo
root. Raised in conversation with the user when discussing what a
"standard" Go repo looks like: the idiomatic shape for a project this
size is `cmd/<binary>/main.go` (thin entrypoint) plus the real logic in
`internal/<pkg>` packages — not `src/` (that's a Java/Node convention),
and not one flat package forever (a defensible choice at smaller sizes,
but wganchor has grown past it: 12 files, several genuinely distinct
concerns, each already documented as its own architecture doc).

**This is a pure refactor.** No behavior change, no CLI/flag change, no
new features, no change to the "single static Linux binary" deliverable.
Exit criteria are entirely about "still does exactly what it did before,
organized differently."

## Investigation: actual coupling (not assumed)

Before picking package boundaries, the real cross-file call graph was
traced (grep for every declared identifier's real call sites, filtering
out doc-comment prose that merely *mentions* another file's function —
this mattered: several apparent couplings turned out to be comments,
not code):

- **False dependencies (comment-only, not real calls) that don't
  constrain the design:** `relay.go` does not call `firewall.go`'s
  `addPortSpec`/`removePortSpec`/`precheckFirewallCmd` — it has its own
  parallel, deliberately-mirrored implementations (its own doc comments
  say "mirrors firewall.go's X"; it doesn't import from it). `pair.go`
  does not call `firewall.go`'s `parsePortSpec`, for the same reason.
  `firewall.go`'s mentions of `isUnitNotInstalledOutput`/
  `removeTemplateIfUnused`/`reconcileOnce` (lifecycle.go/watch.go) are
  also comment-only.
- **The one real near-cycle:** `lifecycle.go` calls `firewall.go`'s
  `disableInstanceFirewall` (during uninstall). `firewall.go` calls
  `lifecycle.go`'s `configPathForInstance`. If `lifecycle.go` and
  `firewall.go` become separate packages, this is a real import cycle.
  **Fix: relocate `configPathForInstance` into the config package**
  (alongside its sibling `resolveConfigPath`, which it obviously belongs
  next to anyway) rather than introducing an interface or merging
  packages. This is the one load-bearing design decision that makes a
  clean package split possible at all — without it, `firewall` and
  `lifecycle` cannot be separate packages. It also fixes a second,
  milder issue the same way: `relay.go` also calls
  `configPathForInstance` (twice), which would otherwise be a `relay` →
  `lifecycle` edge with no real reason to exist — relocating the
  function removes that too.
- **`persistConfig` (currently in keys.go) moves to the config package
  too**, alongside `loadConfig` (its natural counterpart) — not into the
  wireguard-key package it currently sits in file-wise. Reason: it's
  called by `firewall.go`, `lifecycle.go`, `pair.go`, and `relay.go`,
  none of which otherwise need anything from key generation/derivation;
  bundling it with `GenerateKeypair`/`EnsureKeys` would force every one
  of those packages to import a "wireguard keys" package just to persist
  a config write.

## Goal: target package structure

```
cmd/wganchor/main.go        — CLI parsing and command orchestration
                               (was main.go — see note below on run())
internal/config/            — Config type, defaults, path resolution,
                               load/persist, ValidateConfig/validateRelayIP
                               (config.go + validate.go + persistConfig
                               moved from keys.go + configPathForInstance
                               moved from lifecycle.go)
internal/sysexec/           — runCmd/runCmdStdin/commandSucceeds (exec.go,
                               unchanged — already a zero-dependency leaf)
internal/wireguard/         — key generation/derivation + interface/peer
                               configuration (keys.go minus persistConfig,
                               + iface.go)
internal/routing/           — policy routing, ip rule/route parsing,
                               ip_forward check (routing.go, unchanged)
internal/firewall/          — nftables management (firewall.go, unchanged)
internal/lifecycle/         — install/uninstall + systemd unit templates
                               (lifecycle.go + units.go; units/ directory
                               moves to internal/lifecycle/units/ — see
                               go:embed note below)
internal/relay/             — relay add/remove (relay.go, unchanged)
internal/pair/               — pairing (pair.go, unchanged)
internal/watch/              — resilience/self-healing loop (watch.go,
                               unchanged)
```

Dependency graph (verified acyclic once the two relocations above are
done):

```
config, sysexec        — leaves, no internal deps
wireguard   → config, sysexec
routing     → config, sysexec
firewall    → config, sysexec, routing
lifecycle   → config, sysexec, wireguard, routing, firewall
relay       → config, wireguard, routing
pair        → config, wireguard
watch       → config, routing
cmd/wganchor → all of the above
```

Two corrections from the first draft, found during plan review:
`routing` → `config` was missing (`tableForInstance`/
`priorityForInstance` call `defaultListenPort`) — `routing` still also
depends on `sysexec` as originally drawn, it calls `runCmd` directly for
every `ip route`/`ip rule`/`ip addr` operation. And `relay`, `pair`, and
`watch` do **not** call `sysexec` directly, despite the first draft
claiming they did: `pair.go`'s `runRemote` and `watch.go`'s
`watchRules` deliberately call `exec.Command` directly rather than
reusing `sysexec.RunCmd`'s buffer-both-streams contract (`pair.go`
documents why: ssh needs an interactive tty), and `relay.go` only
reaches `sysexec` transitively, through `wireguard`/`routing`.

Nine `internal/` packages, one `cmd/` package. Each maps either 1:1 to an
existing `docs/arch/*.md` document (`firewall` → `firewall.md`, `watch` →
`resilience.md`, `wireguard`+`routing`+`config` → `wireguard.md`,
`lifecycle` → `config-and-lifecycle.md`) or to a self-contained CLI
feature added since those docs were written (`relay`, `pair`) — not an
arbitrary per-file split. `sysexec` is the one package that doesn't map
to a doc; it's kept standalone (rather than folded into `config` or
`wireguard`) specifically because six unrelated packages need it and
none of them should have to import an unrelated package just to shell
out to `ip`/`wg`/`nft`/`systemctl`.

Considered and rejected: merging `routing` into `wireguard` (both are
"network state," per `docs/arch/wireguard.md` covering both). Rejected
because `firewall`, `lifecycle`, `relay`, and `watch` all need `routing`
but have no reason to depend on `wireguard`'s key-management code — that
merge would force four packages to import key-generation logic they
never call.

### Exported-symbol renaming

Many currently-lowercase identifiers are called across file boundaries
today (legal within one `package main`) and must be exported once they
cross a package boundary — e.g. `resolveRuntimeDefaults` →
`config.ResolveRuntimeDefaults`, `defaultListenPort` →
`config.DefaultListenPort`, `interfaceExists` →
`wireguard.InterfaceExists`, `diffRelayIPs` → `routing.DiffRelayIPs`.
Follow Go's no-stutter convention (`config.PathForInstance`, not
`config.ConfigPathForInstance`) — this is real API-naming work, not a
mechanical capitalize-everything pass. Conversely, anything not
referenced outside its new package stays unexported (e.g.
`isWireGuardInterface`, `isNftAbsentOutput`) — don't export defensively.

The export surface is larger than the above examples: `cmd/wganchor`
alone will need `routing.CheckIPForward`/`routing.IPForwardWarning` and
several `firewall` exports (`ensureFirewallScaffold`,
`applyFirewallAllowedPorts`, `nftAvailable`, `errNftMissing`,
`expandBothProto`, `parsePortSpec`) beyond what's already capitalized.
Note in particular that `errNftMissing` becomes an exported error var —
name it `firewall.ErrNftMissing` (Go's `Err*` convention for exported
sentinel errors), not just a capitalized `NftMissing`. Module path is
`wganchor` (`go.mod`), so these become e.g. `wganchor/internal/firewall`.

### `run()` stays in `cmd/wganchor`

`main.go`'s `run()` is genuine bring-up orchestration, not just flag
parsing: it has an order-sensitive security invariant (the firewall
scaffold must exist before `ReconcileClientRouting` runs, or a newly-up
interface is briefly unfiltered — `run()`'s own comments document why).
That orchestration logic stays in `cmd/wganchor` as-is; it does not get
a tenth `internal/` package (an `internal/bringup` package would violate
the no-new-abstractions non-goal for something that isn't reused
elsewhere and isn't a natural library boundary). `cmd/wganchor` calling
into `internal/config`, `internal/firewall`, and `internal/routing` in
the right order *is* the orchestration — it doesn't need to be
extracted into its own package to count as "internal package logic
instead of CLI glue."

### `go:embed` directory move

`units.go`'s four `//go:embed` directives resolve paths relative to the
source file's own directory, not the module root. Moving `units.go` into
`internal/lifecycle/` requires moving `units/` to
`internal/lifecycle/units/` in the same commit — an embed path can't
reach outside its package directory with `../`.

### Test migration

Per-file test coupling was traced twice — once in this plan's first
draft, and again during plan review specifically to check the first
pass's own claims, which caught two factual errors in exactly the
comment-vs-call trap this plan's methodology section warns about
applied to itself:

- **`validate_test.go` does not call `RelayAdd`/`RelayRemove`.** (First
  draft claimed it did, to justify an "end-to-end relay-validation"
  test move — that test doesn't exist; the only `RelayAdd`/`RelayRemove`
  mention in the file is a doc comment.) Every test in the file is a
  plain `ValidateConfig`/`validateRelayIP` unit test. It moves wholesale
  into `internal/config`'s test suite, unchanged — no split needed.
- **`relay_test.go` cannot be an external `package relay_test`.** (First
  draft's proposed fix for a coupling problem that doesn't exist this
  way.) It tests unexported `relay` identifiers directly — `addRelayIP`,
  `removeRelayIP`, `applyRelayListChange`, `liveApplyRelay` — which an
  external test package can't reach. It stays an ordinary internal
  `package relay` test, freely importing `config` and `wireguard` (the
  same direction `relay`'s production code already imports them — no
  cycle question even arises). It calls `interfaceExists`
  (`wireguard.InterfaceExists` post-move), not `ConfigureInterface` as
  the first draft said.

Net effect: **no test in the repo actually needs the external-`_test`-
package device.** The general rule below is kept as guidance for
whatever this pass didn't catch, but neither of the two cases it was
originally written to justify turns out to need it.

General rule: a test stays (or moves) with the package whose API it's
actually exercising. If a test genuinely needs to import a downstream
package that itself imports the package under test (not encountered
above, but plausible elsewhere), Go permits that via an external
`_test` package (`package <pkg>_test`) — test binaries are compiled
separately, so this isn't a production import cycle, but it only works
for tests that use exclusively *exported* API of the package under test.

**Real cross-test-file coupling to handle:** `relay_test.go` uses
`newTestConfig()`, a small `Config`-constructing helper defined in
`pair_test.go`. Once `relay` and `pair` are separate packages, `relay`'s
tests need their own copy of it (or promote it to an exported test
helper somewhere both can reach) — trivial, but a real move, unlike the
two invented ones above.

## Non-goals

- **Any behavior change.** Pure refactor; the CLI's flags, output, and
  runtime behavior must be identical before and after.
- **Any change to the module path or the single-binary build output.**
  `go build ./cmd/wganchor` (or an updated root build command, see exit
  criteria) still produces one static `wganchor` binary.
- **Introducing interfaces, dependency injection, or other abstraction
  beyond what's needed to resolve the one real cycle found above.** The
  cycle is fixed by relocating two functions to their natural home, not
  by adding an abstraction layer.
- **Renaming CLI subcommands, flags, or config fields.** Out of scope —
  this is an internal code-organization change only.
- **A shared `internal/testutil` package.** The one known duplication
  (`newTestConfig()`, needed by both `relay`'s and `pair`'s tests once
  they split, see Test migration above) is small enough to just copy;
  promote it to a shared package only if implementation finds more
  duplication than that.
- **Revisiting milestone 2's linter configuration**, beyond fixing
  whatever new findings the restructuring itself surfaces (expected:
  `revive`'s exported-symbol-needs-a-doc-comment rule will fire on many
  of the newly-exported identifiers above — this was already flagged as
  expected fallout in `plan-linting-COMPLETE.md`'s non-goals).

## Implementation review

Plan review (Fable, 2 rounds) approved after fixing two blocking issues
(both in the Test migration section — see the corrections baked
directly into that section above) and folding in graph corrections,
export-surface notes, and the `run()`-stays-in-`cmd` clarification.

Implementation was delegated to a fork given the scale (12 files → 9
packages + cmd, ~330 tool calls, ~27 minutes) — executed bottom-up per
the plan's dependency order, verifying `go build ./...` after each
package extraction.

Implementation review (Opus) approved with 1 should-fix + several nits,
after the single most thorough verification pass in this sprint:
normalized diffs of every moved file against its pre-refactor version in
git history (confirmed every non-comment change across the entire
refactor is an identifier rename — zero logic changes), a full
function-inventory reconciliation (130 old → 129 new, fully accounted
for), an exported-symbol collision check across all nine packages, and a
**differential test against a binary built from the pre-refactor HEAD**:
21 CLI invocations (usage, bad subcommands, bad ports/protos/IPs,
missing configs, out-of-range instances, key derivation from a scratch
private key), 21/21 byte-identical stdout+stderr and exit codes.

Should-fix: four newly-exported functions had name-stutter revive didn't
catch (it only fires on a package-name *prefix* match) —
`firewall.EnsureFirewallScaffold`, `firewall.ApplyFirewallAllowedPorts`,
`firewall.DisableInstanceFirewall`, `watch.RunWatch`. Renamed to
`EnsureScaffold`/`ApplyAllowedPorts`/`DisableInstance`/`Run`. Fixed nits:
three stale flat-filename comments; the `/etc/wganchor` literal
consolidated into one exported `config.Dir` constant (was duplicated
between `config.go` and `lifecycle.go`); `.claude/` added to
`.gitignore`. One suggested nit (separate stdlib/local imports with a
blank line via `goimports -local`) was tried and reverted:
`golangci-lint fmt` (this project's canonical, CI-enforced formatter)
undid it — `gofumpt` classifies `wganchor/internal/...` as stdlib
because the module path (`wganchor`) has no dot in its first segment,
so it deliberately keeps local imports ungrouped. Root-caused and
confirmed by the reviewer in a scratch repro; not worth fighting the
formatter for a module path change that's explicitly out of scope.

The reviewer also flagged a legitimate safety question mid-review — it
couldn't verify from its own vantage point that the fork's manual smoke
test had actually avoided instance 0 (a config-resolution mistake there
could have triggered `EnsureKeys` to silently rotate the live production
private key). Confirmed directly: the scratch config existed at a
throwaway path outside `/etc/wganchor`, and instance 0's public key and
live handshake were checked and found unchanged both before and after.

## Exit criteria

- [x] `cmd/wganchor/main.go` exists and contains CLI parsing and
      command orchestration only, no direct syscall/exec logic (see
      "`run()` stays in `cmd/wganchor`" above for what "orchestration"
      includes); the nine `internal/` packages exist per the structure
      above.
- [x] `go build ./cmd/wganchor` (or equivalent) produces a working
      binary; `README.md`'s Build section updated (`go build -o
      wganchor ./cmd/wganchor` — the root `go build -o wganchor .` stopped
      working, confirmed: "no Go files in .").
- [x] No import cycles; `go build ./...` and `go vet ./...` clean.
- [x] `go test ./...` passes — including `validate_test.go`'s move into
      `internal/config` and `relay_test.go`'s `newTestConfig()`
      duplication, per Test migration above.
- [x] `go test -race ./...` passes.
- [x] `golangci-lint run` clean (0 issues) — including new findings the
      restructuring itself surfaces. The gosec test-file exclusion was
      empirically confirmed still live: running gosec with exclusions
      disabled surfaces findings in `internal/*/*_test.go`, zero with
      the exclusion in place.
- [x] `units/` directory relocated to `internal/lifecycle/units/`;
      `go:embed` confirmed resolving correctly (all 4 service files
      byte-identical to their pre-move versions).
- [x] `docs/arch/*.md` updated wherever they reference old flat file
      paths to the new package paths.
- [x] Manual smoke test on a non-production instance: built the new
      binary, ran `wganchor pair pubkey --config <scratch path>` against
      a throwaway config outside `/etc/wganchor` — self-provisioned a
      real keypair via `wg genkey`/`wg pubkey`, printed the public key,
      persisted it with correct 0600 mode. Instance 0 confirmed
      untouched (unchanged public key, live healthy handshake, both
      checked directly before and after).
