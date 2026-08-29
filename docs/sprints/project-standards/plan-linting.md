# Plan: `golangci-lint` in CI and locally

Milestone 2 of the `project-standards` sprint (see `SPRINT.md`). Depends
on milestone 1 (`plan-ci-and-license-COMPLETE.md`) being in place — this
adds a step to the CI workflow it created rather than building CI from
scratch.

## Motivation

`wganchor` currently only runs `gofmt`/`go vet` locally and in CI — no
linter beyond that. Raised in conversation with the user when discussing
what a "standard, high-quality" Go repo needs. Researched current (2026)
Go tooling before committing to a choice (see below); `golangci-lint`
remains the de facto standard meta-linter with no credible newer
replacement, so there's no real alternatives analysis needed here beyond
"which linters within it."

## Goal

### Tool choice

- **`golangci-lint` v2** (current stable: `v2.13.2`), pinned explicitly
  — not `latest` — so a future golangci-lint release adding a stricter
  default check can't silently turn CI red on an unrelated commit.
- **`golangci-lint-action@v9`** (current major; supports golangci-lint
  ≥2.1.0, so no version-compatibility gap against the pin above).
- **`gofumpt`**, wired as a *formatter* (v2's formatters/linters split),
  not a linter — a strict, deterministic superset of `gofmt` (running
  `gofmt` after `gofumpt` is always a no-op), so this doesn't conflict
  with the existing `gofmt` CI step.

### Config (`.golangci.yml`, v2 schema)

Linters:
- Default set: `errcheck`, `govet`, `ineffassign`, `staticcheck` (v2
  absorbed `gosimple`/`stylecheck` into this one), `unused`. Implemented
  as `linters.default: standard` rather than spelling the five out
  explicitly — a deviation from this plan's original wording, kept
  because it can't silently drift out of sync if a future golangci-lint
  release changes what "standard" means, whereas an explicit list would
  quietly stop matching upstream's default.
- `revive` — modern, configurable successor to the deprecated `golint`;
  general code-quality/style checks.
- `gosec` — security-focused static analysis. Specifically relevant to
  this codebase: `wganchor` shells out to `ip`/`nft`/`wg`
  (`exec.go`/`firewall.go`/`iface.go`) and does raw network/interface
  manipulation as root — exactly gosec's risk class (command
  construction, permissions, etc.).

Formatters: `gofumpt`.

Deliberately **not** enabling golangci-lint's `all`/exhaustive presets —
picking a specific, justified set instead of "turn everything on and
suppress the noise," which would just trade one kind of scope creep
(a bloated `.golangci.yml` full of exclusions) for another.

`revive` is left on its default rule set with no per-rule config — a
deliberate choice for a first pass (tune it later if it proves noisy or
under-strict), not an oversight.

**Config-level exclusions for categorical false-positive classes**
(distinct from the "no blanket exclusions" rule below, which is about
individual findings): golangci-lint v2 removed v1's implicit default
exclusions, so two categories need an explicit, comment-justified
exclusion in `.golangci.yml` or they'd force dozens of scattered
`//nolint`s for something that isn't a real per-site judgment call:

- ~~**`errcheck` on `fmt.Fprint*` to stdout/stderr.** `main.go` alone has
  ~66 such calls (usage text, status output); repo-wide, ~75.~~
  **Correction, found during implementation: this premise was wrong.**
  errcheck's own built-in default exclusions already cover plain
  `fmt.Fprint*(os.Stdout|os.Stderr, ...)` — confirmed empirically
  (removing errcheck's *defaults*, not just the absence of a config
  block, is what actually surfaces those ~75 calls as findings; without
  the config block, only 2 unrelated issues remained). No config-level
  exclusion is needed or was ultimately added for this class. The two
  real sites that did need attention — `fmt.Fprintf(notices, ...)` in
  `pair.go`, where `notices` is an `io.Writer` parameter rather than
  `os.Stderr` directly — are one-off, not categorical, and are handled
  at their call sites (`_, _ = fmt.Fprintf(...)`), not in config.
- **`gosec` on test-file scratch-file permissions.** `routing_test.go`,
  `lifecycle_test.go`, and `config_test.go` legitimately write test
  fixtures with `0644`/`0755` — add a path-scoped exclusion rule (e.g.
  `exclusions.rules` matching `_test\.go$` for the relevant `gosec`
  sub-checks) rather than one `//nolint` per test file.

Everything else — e.g. `gosec`'s `G204` on `exec.go`'s `exec.Command`
call sites, or `G306` on `lifecycle.go`'s intentional `0644` systemd-unit
writes — is a one-off judgment call about a specific line, and stays a
targeted `//nolint: <linter> // reason` at that line, per the rule below.

**Discovered during implementation, not anticipated by this plan:**
golangci-lint's default report caps (`max-issues-per-linter: 50`,
`max-same-issues: 3`) silently truncated the *displayed* findings during
triage — never the exit code, so CI was never at risk, but it's a real
triage trap: fixing the 3 visible instances of an issue class reads as
"class done" while a 4th instance sits unreported. `.golangci.yml` sets
both to `0` (unlimited) so every consumer — local runs, CI, a future
contributor or agent — sees the same complete report; the alternative
(passing `--max-same-issues=0` etc. as CLI flags) would make local and
CI output disagree, a worse version of the same trap.

### CI wiring

Add a new step to `.github/workflows/ci.yml`, after the existing
`go vet` step and before `go build`/`go test` (fail fast on style/security
issues before spending time on the slower build+`-race` test step):

```yaml
- uses: golangci/golangci-lint-action@v9
  with:
    version: v2.13.2
```

The existing `gofmt`/`go vet` steps stay as-is (see Non-goals) — this is
purely additive.

### Local workflow

- Document install + run commands (`go install
  github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2`,
  `golangci-lint run`, `golangci-lint fmt`) somewhere a contributor (or
  agent) will actually find them — CLAUDE.md's existing lint-fix loop
  already says "Run linter"; this milestone is what makes that step
  concrete instead of just meaning `go vet`. Update that line in
  CLAUDE.md to name `golangci-lint` explicitly.
- Get the existing codebase to a clean `golangci-lint run` (fix real
  flagged issues; where a flagged pattern is intentional and specific to
  one call site — e.g. a deliberate `exec.Command` with an
  internally-controlled argument list that `gosec` can't statically
  prove safe — justify it with a `//nolint: <linter> // reason` comment
  at that site; categorical false-positive classes go in
  `.golangci.yml` instead, per the config section above).
- Run `golangci-lint fmt` once as part of adopting `gofumpt`, and expect
  (not just tolerate) a real, mechanical diff from it: `gofumpt` is
  stricter than `gofmt` and will rewrite things like octal literal
  `0644` → `0o644` across `lifecycle.go` and several tests. This stays
  fully `gofmt`-compatible (the existing `gofmt` CI step is unaffected
  by it), but it's a genuine formatting commit, not a no-op — call it
  out as such rather than folding it silently into the "fix lint issues"
  commit.

## Non-goals

- **Folding `gofmt`/`go vet` CI steps into golangci-lint's built-in
  equivalents.** golangci-lint already runs `govet` and can format-check
  via `gofumpt`, so the existing dedicated steps are partly redundant —
  but collapsing them is a CI-workflow redesign, not "add a linter," and
  risks losing the already-verified-working fail-closed gofmt check for
  an unverified equivalent. Revisit later if it bugs anyone.
- **Enabling `all`/exhaustive linter presets**, or any linter beyond the
  agreed set (default five + `revive` + `gosec`). More linters can be
  added later, one at a time, each independently justified — not as a
  first pass.
- **Editor integration, pre-commit hooks, or auto-fix-on-save.** Not
  asked for.
- **`cmd/`+`internal/` restructuring.** Milestone 3. Expected side note,
  not a defect of this milestone: splitting into `internal/` packages
  will likely surface *new* `revive`/`staticcheck` findings that don't
  exist today (exported-symbol doc comments, package comments) — normal
  fallout of that later structural change, not something to pre-empt
  here.

## Exit criteria

- [x] `.golangci.yml` exists (v2 schema): linters = default set (via
      `linters.default: standard`) + `revive` + `gosec`; formatters =
      `gofumpt`.
- [x] `golangci-lint run` passes cleanly against the current codebase —
      every real issue fixed (19 findings, none categorical beyond the
      one `gosec`/test-files exclusion rule that survived review; the
      originally-planned `errcheck` exclusion was found unnecessary
      during implementation review and removed, see Config section
      above); every remaining suppression a targeted `//nolint` with a
      reason, verified 1:1 against actual findings by implementation
      review.
- [x] `go test -race ./...` still passes after all lint/format fixes —
      re-verified locally (uncached), confirmed unaffected by
      implementation review.
- [x] `.github/workflows/ci.yml` runs `golangci-lint` via
      `golangci-lint-action@v9`, version-pinned to `v2.13.2`, positioned
      after `go vet` and before `go build`.
- [x] CLAUDE.md's lint-fix loop names `golangci-lint` explicitly instead
      of referring to "the linter" generically.
- [ ] A push triggers and passes the new CI step live on GitHub, with no
      unexpected annotations (learned from milestone 1: check the
      Actions run output, not just "the YAML looks right"). Pending: to
      be checked immediately after this commit is pushed.
- [x] README documents the local install/run commands (new "Linting"
      subsection under "Build").

## Implementation review

Plan review (Fable, 2 rounds) approved with should-fixes folded in
directly (see the strikethrough correction and notes in the Config
section above) before implementation began.

Implementation review (Opus) approved with 2 should-fixes, both fixed
before commit:
1. A `//nolint:gosec` justification on `config.go:112` incorrectly
   claimed the candidate path was built only from a fixed directory and
   a validated int — it's actually the operator's `--config` flag or
   `$XDG_CONFIG_HOME` (via `os.UserConfigDir`). Not a security bug (root
   already controls its own environment; `loadConfig` still gates on
   mode 0600), but the comment was factually wrong and is now corrected.
2. The plan's `errcheck` exclusion rationale (~75 stdout/stderr calls
   needing suppression) was wrong — errcheck's own built-in defaults
   already cover plain `os.Stdout`/`os.Stderr` writes, confirmed
   empirically. The config block was removed entirely; the two real
   sites needing attention (`fmt.Fprintf(notices, ...)` in `pair.go`,
   where `notices` is an `io.Writer` parameter) are handled individually
   instead, so a future `fmt.Fprintf` to a real file or socket will
   still be flagged rather than silently exempted.

Implementation review also verified, via targeted checks: all 6 `gosec`
G204 (`exec.Command`) sites only ever pass hardcoded binary names with
internally-constructed args (traced all 38 call sites across the
codebase); `pair.go`'s `runRemote` — the one site where a value crosses
a real shell boundary (ssh) — is doubly justified, since the one
non-operator-typed value reaching its argv (`localPub`) is
format-validated (base64 + length) before use; all `gofumpt` octal
rewrites (`0644`→`0o644` etc.) are value-preserving with no semantic
change; and every `errcheck` blank-identifier fix was independently
confirmed to not swallow a real error (the `flag.ExitOnError` FlagSets
genuinely cannot return a `Parse` error; the `defer func() { _ =
os.Remove(...) }()` closure rewrite doesn't change behavior since the
captured variable is never reassigned after declaration).

Also discovered and fixed during implementation, not anticipated by the
plan: golangci-lint's default report caps (`max-issues-per-linter: 50`,
`max-same-issues: 3`) were silently truncating displayed findings during
triage (never the exit code) — disabled in `.golangci.yml`'s new
`issues:` section so local runs, CI, and future contributors/agents all
see a complete report.
