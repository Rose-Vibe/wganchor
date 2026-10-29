# Plan: tag-triggered release builds

## Why

There's currently no way to get a `wganchor` binary other than cloning
and building it yourself. CLAUDE.md's "builds to a single static Linux
binary" already makes this an easy thing to distribute as a download;
nothing does that yet. Modeled on `open-legacy-rpc`'s `publish.yml`
pattern (run the same checks the PR/push CI runs, then build/publish),
but for a Go CLI the equivalent of "publish to npm/PyPI" is "attach
binaries to a GitHub Release" — there's no separate registry to publish
to.

## Tooling: GoReleaser, not a hand-rolled build matrix

GoReleaser is the de facto standard for this in the Go ecosystem: one
config file drives cross-compilation, checksums, changelog generation,
and GitHub Release creation with attached assets. It's a CI-time build
tool, not a runtime dependency of the binary itself, so it doesn't
conflict with CLAUDE.md's "no external frameworks for simple tasks" (that
rule is about what ships *inside* `wganchor`, not what builds it).

Scope deliberately narrower than GoReleaser's usual default: **`linux/amd64`
and `linux/arm64` only.** This is Linux-only software by design (WireGuard
interface creation, `nft`/`ip`/systemd) — building `darwin`/`windows`
binaries that can't actually run `wganchor server`/`client` would be
actively misleading to anyone who downloads one. (`linux/arm` for 32-bit
Pi-class devices is a plausible one-line future addition; not added now —
no evidence anyone needs it yet.)

## Scope

- `.goreleaser.yaml`:
  - `project_name: wganchor`, set explicitly — otherwise GoReleaser infers
    it from the working directory/git remote, and this checkout's
    directory is `ip-relay`, which would produce `ip-relay_*` archive
    names.
  - `builds`: one build, `main: ./cmd/wganchor`, `binary: wganchor`
    (explicit, same reason as `project_name`), `goos: [linux]`,
    `goarch: [amd64, arm64]`, `env: [CGO_ENABLED=0]` (matches "single
    static binary"). `flags: [-trimpath]`, `mod_timestamp: '{{
    .CommitTimestamp }}'` for reproducible builds, and `ldflags: ["-s -w
    -X main.version={{.Version}}"]` — custom `ldflags` *replace*
    GoReleaser's defaults rather than adding to them, and the defaults
    include `-X main.version=...`; keep that one explicitly rather than
    silently drop it, even though there's no `main.version` var for it to
    land in yet (an unmatched `-X` target is a no-op, not a build error),
    so the future `--version` follow-up (see Out of scope) gets it for
    free instead of needing to touch this file again.
  - `archives`: `tar.gz`, including `LICENSE` and `README.md` alongside
    the binary.
  - `checksum`: `name_template: 'checksums.txt'` — GoReleaser's own
    default template is `<project>_<version>_checksums.txt`; set this
    explicitly so the exit criterion below ("a `checksums.txt` is
    attached") is actually what ships.
  - `release.prerelease: auto` — **set explicitly**, not relied on as a
    default. GoReleaser's `release.prerelease` default is `false`; `auto`
    (infer from whether the tag looks like a pre-release, e.g.
    `v0.2.0-rc1`) has to be opted into.
  - `changelog`: generated from commit messages since the previous tag;
    exclude, by regex, commits matching `^docs:`, `^plan:`, `^ci:`, or
    containing `close out` — this project's actual commit history uses
    all of those for bookkeeping/doc-only changes (not just `docs:`),
    and none of them are user-facing. Because this is the project's
    *first* tag, `v0.1.0`'s auto-generated notes would otherwise be the
    entire commit history. `release.header` in `.goreleaser.yaml` applies
    to *every* release, not just one tag, so don't put permanent,
    v0.1.0-specific prose there. A one-off `--release-header <file>` on a
    local `goreleaser release` invocation doesn't work either: pushing
    the `v0.1.0` tag triggers `release.yml`'s CI job immediately, which
    publishes the Release with the generic, filtered changelog alone
    before any local run could get there first — and a local run
    afterward would just hit an already-existing Release. Simplest
    correct mechanism: let CI publish `v0.1.0` exactly as it would any
    other tag, then once it's live, `gh release edit v0.1.0 --notes-file
    <file>` to prepend a short hand-written paragraph ahead of the
    filtered changelog GoReleaser already generated — a plain edit of
    the published Release's notes, not a second GoReleaser invocation.
    Subsequent tags rely on the filtered auto-changelog alone, with no
    header override.
- **Split `ci.yml` into a reusable `_checks.yml` + a thin `ci.yml`
  caller**, mirroring `open-legacy-rpc`'s structure: move the existing
  gofmt/vet/golangci-lint/build/test-race steps into
  `.github/workflows/_checks.yml` (`on: workflow_call`), and have
  `ci.yml` call it via `uses: ./.github/workflows/_checks.yml`. Pure
  refactor — the steps themselves don't change, only which file they live
  in — but it's what lets the release workflow reuse the same checks
  without duplicating them. **This does change the reported check
  context name**: a job that `uses:` a reusable workflow reports as
  `<caller job id> / <called job id>` (e.g. `checks / test`), not the
  bare `test` it reports today. Record the resulting name here once
  implemented, and update `plan-repo-automation.md`'s ruleset to
  reference the compound name — do not assume milestone 3 can keep using
  `test` unchanged.
- `.github/workflows/release.yml`:
  - Trigger: `push: tags: ['v*.*.*']`, plus `workflow_dispatch` (no input)
    for testing the workflow without needing a real tag. No `dry_run`
    toggle: unlike `open-legacy-rpc`'s npm/PyPI publish (which has no
    snapshot mode and genuinely needs a dry-run flag to distinguish "build
    only" from "build and publish"), GoReleaser's own `--snapshot` mode
    already is the dry run, so `workflow_dispatch` always runs in snapshot
    mode — one fewer input, one fewer edge case (a hypothetical
    `dry_run=false` dispatch on a branch would fail outright with no tag
    to release from).
  - No `concurrency` block on this workflow — unlike `ci.yml`, where
    cancelling a superseded run is correct, cancelling a release run
    partway through uploading Release assets would leave a tag with a
    half-published Release. Two tags pushed in quick succession should
    both run to completion, not race each other.
  - `checks` job: `uses: ./.github/workflows/_checks.yml`.
  - `release` job (`needs: checks`, `permissions: contents: write`):
    - `actions/checkout@v5` with `fetch-depth: 0` — GoReleaser needs full
      git history and all tags for version detection and changelog
      generation; `ci.yml`'s shallow checkout is fine for tests but would
      break this job.
    - `goreleaser/goreleaser-action` with the pinned GoReleaser version,
      `env: GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}` (required for the
      action to create the Release and upload assets — not covered by
      the job's `permissions:` block alone).
    - On a real tag push: `goreleaser release --clean`.
    - On `workflow_dispatch`: `goreleaser release --clean --snapshot`
      (snapshot mode implies skipping publish/announce, and — unlike
      `--skip=publish` alone — also skips the validation step that
      otherwise fails outright on an untagged commit with "git doesn't
      contain any tags").
    - Optionally `actions/upload-artifact` the snapshot `dist/` on the
      `workflow_dispatch` path, so a human can actually inspect the
      arm64 build without a local run.
- `.gitignore`: add `/dist/` — both a local `goreleaser release
  --snapshot` run (see Exit criteria) and the CI job write build output
  there; today's `.gitignore` only covers `/wganchor`.
- **Operational rule: a pushed `v*` tag is never moved, deleted, or
  re-created.** `proxy.golang.org`/`sum.golang.org` cache a tag's
  resolved commit and checksum the first time anything fetches it;
  moving the tag afterward makes `go install .../wganchor@vX.Y.Z` fail
  with a checksum mismatch for every user who already fetched it, not
  just a cosmetic inconsistency. If checks fail on a pushed tag (the
  `release` job simply never runs, via `needs: checks`) or a release
  otherwise needs correcting, fix forward with a new patch tag — never
  reuse the broken one. Document this rule in the README's new release
  section (see below). Separately, note for later: a `v2.0.0+` release
  needs a `/v2` suffix on the module path (Go's own major-version-suffix
  convention) — out of scope for this plan, but worth knowing before
  anyone casually tags a `v2.0.0`.
- `README.md`: add a short "Download a release" section pointing at the
  GitHub Releases page, naming the two archive names
  (`wganchor_<version>_linux_amd64.tar.gz` /
  `..._linux_arm64.tar.gz`) and `checksums.txt`, with the one-line
  verification command (`sha256sum --check` scoped to the one line
  matching the downloaded archive), alongside the tag-immutability rule
  above.

## Out of scope

- Docker image, Homebrew tap, `.deb`/`.rpm` packages — not requested;
  revisit only if the `go install`/download-the-binary options turn out
  to be insufficient.
- Code signing / provenance attestation — GitHub Artifact Attestations
  and GoReleaser's cosign integration both exist and could be added
  later; deferred for now, not ruled out as unsupported.
- Any change to version numbering scheme beyond "a `v*.*.*` tag is a
  release" — this project has cut zero releases so far, so there's no
  existing scheme to preserve or migrate.
- **A `wganchor version`/`--version` command.** None exists today
  (confirmed: no version flag or subcommand in `cmd/wganchor/main.go`),
  which means a release binary currently has no way to report what
  version it is — a real operability gap for a tool that installs itself
  into `/usr/local/bin` and is now being versioned for the first time.
  Deliberately left out of *this* plan (it's a small Go code change, not
  CI/release config, and this milestone's review pipeline is scoped to
  infra), but flagged here as a near-term follow-up worth its own small
  plan: `debug.ReadBuildInfo()` covers `go install @vX` builds for free,
  and GoReleaser's default `-X main.version=...` ldflag covers the
  GitHub-Release binaries, so both distribution paths are coverable with
  one small addition.

## Exit criteria

- `goreleaser check` passes against `.goreleaser.yaml`.
- A local `goreleaser release --snapshot --clean` run succeeds, and `file
  dist/*/wganchor` reports no dynamic interpreter (statically linked) for
  both the amd64 and arm64 outputs — this directly verifies the "single
  static Linux binary" architectural claim survives the release pipeline,
  not just that the workflow YAML is well-formed.
- `ci.yml` and `release.yml` both call the same `_checks.yml`. The
  resulting check context name (expected `checks / test`, confirmed once
  implemented) is recorded here and carried into `plan-repo-automation.md`'s
  ruleset — explicitly *not* assumed to still be the bare `test` name
  `ci.yml` reports today.
- A `workflow_dispatch` snapshot run completes successfully (build +
  archive + checksum, no Release created) before any real tag is pushed.
- `README.md` documents downloading a release and the tag-immutability
  rule.
- Live-verified: pushing an actual tag (`v0.1.0`, the project's first
  release) produces a GitHub Release with two platform archives and a
  `checksums.txt` attached, with `gh release edit v0.1.0 --notes-file
  <file>` applied afterward so the published notes read as a short
  hand-written paragraph followed by the filtered changelog, not the
  full raw commit history on its own, and `go install
  github.com/Rose-Vibe/wganchor/cmd/wganchor@v0.1.0` resolves cleanly
  against that tag (ties back to `plan-module-path.md`'s exit criterion).
