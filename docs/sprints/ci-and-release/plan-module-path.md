# Plan: fix the module path

## Why

`go.mod` currently declares `module wganchor` — a short, non-path module
name. That's valid for a module that's only ever built from a local
checkout (which is all this project has done so far), but it breaks the
one thing a short name can't do: resolve through the Go module proxy.
`go install github.com/Rose-Vibe/wganchor/cmd/wganchor@latest` needs the
module's declared path to match where it's actually hosted, so with
today's `go.mod` that command fails outright — Go has no way to map
`wganchor` to a VCS location. Fixing the module path is what makes `go
install` work as a zero-infrastructure distribution channel, which the
release-builds milestone and the "anything else to publish" question both
depend on.

No new Go dependency, no behavior change — this is a rename, not a
feature.

## Scope

- `go.mod`: `module wganchor` → `module github.com/Rose-Vibe/wganchor`.
- Every internal import rewritten from `wganchor/internal/<pkg>` to
  `github.com/Rose-Vibe/wganchor/internal/<pkg>`. Confirmed scope: 15
  files currently import this way (`cmd/wganchor/main.go` plus files
  across `internal/*_test.go` and sibling-package imports within
  `internal/`) — `grep -rl '"wganchor/internal' --include="*.go" .` is the
  exact list to rewrite; re-run after editing to confirm zero matches
  remain.
- `README.md`'s `## Build` section: add a `go install
  github.com/Rose-Vibe/wganchor/cmd/wganchor@latest` line alongside the
  existing `go build -o wganchor ./cmd/wganchor` instruction, noting it
  resolves a tagged release once one exists (see `plan-release-builds.md`)
  and otherwise resolves the latest commit on `main`. Prefix **both**
  documented commands with `CGO_ENABLED=0 ` — confirmed during plan review
  that the current, undecorated `go build -o wganchor ./cmd/wganchor`
  produces a *dynamically* linked binary (`net`'s cgo resolver gets
  linked in whenever a C toolchain is present and `CGO_ENABLED` isn't
  forced), contradicting README's and CLAUDE.md's "single static binary"
  claim. Pre-existing bug, not caused by this rename, but this plan is
  already touching that exact line — fix it here rather than leave it
  stale next to a newly-added `go install` command that would inherit the
  same problem. (`plan-release-builds.md`'s GoReleaser config must set
  `CGO_ENABLED=0` for the same reason — that's already in its scope,
  cross-referenced here so the two plans don't silently diverge on it.)
- Every one of the 15 import blocks is today a single merged group (no
  blank line between stdlib and `wganchor/internal/...`), because
  gofumpt treats the dotless `wganchor` as stdlib-like. **After the
  rename, gofumpt will split each block into two groups (stdlib, then
  `github.com/Rose-Vibe/wganchor/internal/...`) separated by a blank
  line — this is the correct, expected diff, not drift to avoid.**
  golangci-lint v2's `run` reports formatter diffs as failures, so the
  rename isn't done until `golangci-lint fmt` has been run and its result
  committed; the implementation reviewer should expect "import path text
  change + one inserted blank line per file," not a bare text-only diff.
  (`golangci-lint` is not currently on `PATH` in this environment — install
  it per the version pinned in README's existing linting section before
  relying on `golangci-lint run`/`fmt` locally.)
- Nothing else changes: no package renames, no file moves, no other logic
  touched.

## Out of scope

- Tagging an actual release (`plan-release-builds.md`'s job).
- Any change to `internal/config.Dir` or other string constants unrelated
  to Go import paths (e.g. `/etc/wganchor` stays exactly as-is — that's a
  filesystem path, not a Go module path, and renaming the module must not
  touch it).

## Exit criteria

- `go.mod` declares `module github.com/Rose-Vibe/wganchor`.
- Zero remaining matches for `"wganchor/internal` (the old-style import)
  anywhere in the tree, scoped to `*.go` files only — `docs/sprints/
  archive/.../plan-restructuring-COMPLETE.md` mentions the old path too,
  but that's historical record and must not be touched.
- `golangci-lint fmt` applied and committed (expected diff per file: the
  import-path text change, plus one inserted blank line splitting stdlib
  from the new `github.com/Rose-Vibe/wganchor/internal/...` group — see
  "Scope" above).
- `gofmt -l .` empty, `go vet ./...` clean, `golangci-lint run` clean,
  `go build ./...` and `go test -race ./...` both pass.
- `README.md` documents the `go install` path.
- Live-verified once pushed, in this order, against a throwaway module
  cache (`GOMODCACHE=$(mktemp -d)`) to rule out a local cache masking a
  resolution failure:
  1. `CGO_ENABLED=0 go install
     github.com/Rose-Vibe/wganchor/cmd/wganchor@<pushed-sha>` — resolves
     immediately and is the real proof the module path works.
  2. `CGO_ENABLED=0 go install
     github.com/Rose-Vibe/wganchor/cmd/wganchor@latest` — resolves the
     latest pseudo-version of `main`. If this fails while (1) succeeded,
     don't treat it as a plan failure outright: retry with `GOPROXY=direct`
     first, since `proxy.golang.org` can briefly cache a pre-fix lookup for
     this module path. Only a failure that persists under `GOPROXY=direct`
     is a real break. (Both commands are prefixed with `CGO_ENABLED=0` so
     the verification runs the exact commands README documents, and so
     step 3 below isn't checking a binary built a different way than what
     a user would actually run.)
  3. Built binaries from both confirmed static (`file` reports no dynamic
     interpreter), per the `CGO_ENABLED=0` fix above.
