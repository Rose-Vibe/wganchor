# Plan: LICENSE + GitHub Actions CI

Milestone 1 of the `project-standards` sprint (see `SPRINT.md`). Lowest-risk
milestone in the sprint: adds a license file and a CI workflow, touches no
existing Go source.

## Motivation

`wganchor` was just pushed to its first GitHub repo (`Corecii/wganchor`,
private). It has no `LICENSE` file and nothing runs `gofmt`/`go vet`/
`go build`/`go test` automatically on push or PR — CI/license absence
were the two concrete "not standard yet" gaps identified when the user
asked about project structure and quality.

## Goal

### LICENSE

Add `LICENSE` at the repo root: standard MIT license text, copyright
line `Copyright (c) 2026 Rose Asenbauer` (current year, per user).

### CI workflow

Add `.github/workflows/ci.yml`, triggered on `push` to `main` and on
`pull_request` (any branch). Single job, since there's nothing to
matrix (one Go version pinned via `go.mod`, one OS — Linux, since the
tool is Linux-only per `docs/arch/` and does raw netlink/`ip`/`nft`/`wg`
things that don't exist on other runners):

1. `actions/checkout@v4`
2. `actions/setup-go@v5` with `go-version-file: go.mod`
3. `gofmt -l .` — fail the step if it prints any filenames (i.e., any
   file isn't already gofmt-clean). Mirrors the local lint-fix loop's
   first step (CLAUDE.md).
4. `go vet ./...`
5. `go build ./...`
6. `go test ./...`

No `golangci-lint` step yet — that's milestone 2 (`plan-linting.md`),
deliberately scoped out here so this milestone stays a pure "wire up
what already exists" change with nothing new to configure or tune.

No cross-compilation/release step — out of scope; this plan is CI
(verify), not CD (ship). Releasing binaries can be its own future plan
if/when the user wants it.

## Non-goals

- **golangci-lint / any new linter.** Milestone 2.
- **Restructuring `cmd/`+`internal/`.** Milestone 3.
- **Release automation (goreleaser, tagged binary builds).** Not asked
  for; adding it preemptively would be scope creep for a "add CI and
  LICENSE" ask.
- **Branch protection / required-status-check GitHub repo settings.**
  That's a repo-settings change via the GitHub UI/API, not a code
  change — out of scope for this plan; mention it to the user as a
  manual follow-up if they want CI to actually gate merges.
- **Multi-OS or multi-Go-version CI matrix.** The tool is single-platform
  (Linux) and the repo pins one Go version; a matrix would test
  configurations nobody runs.

## Exit criteria

- [x] `LICENSE` exists at repo root, MIT text, `Copyright (c) 2026 Rose
      Asenbauer`.
- [x] `.github/workflows/ci.yml` exists, runs fmt-check/vet/build/test,
      triggers on push-to-main and pull_request.
- [x] Workflow YAML is valid (`actionlint` or equivalent, or at minimum
      confirmed to parse/run successfully once pushed). Validated with
      `python3 -c "import yaml; yaml.safe_load(...)"` (`actionlint` not
      installed on this machine); implementation review additionally
      confirmed the gofmt-check step actually fails on unformatted code
      by testing the exact snippet against a deliberately-unformatted
      scratch file.
- [ ] A push to `main` (or a test PR) actually triggers and passes the
      workflow on GitHub — verified live, not just "the YAML looks
      right," since a typo'd trigger or step that silently never runs
      would defeat the whole point. Pending: to be checked immediately
      after this commit is pushed.
- [x] README mentions the license (a one-line "License" section, or a
      badge) — a repo with a `LICENSE` file but no mention of it in the
      README is an easy thing to miss when standardizing. Added as
      `## License` at the end of README.md, matching the doc's existing
      style.

## Implementation review

Plan review (Fable) approved with two should-fix notes (workflow
`permissions: contents: read`; the gofmt step needed a nonempty-output
wrapper since `gofmt -l .` alone always exits 0) and optional nits
(action version bumps, `-race`, a `concurrency` group) — both should-fixes
and the `-race`/concurrency-group nits were folded into the
implementation; the action-version-bump nit was left as-is (v4/v5 still
resolve fine).

Implementation review (Opus) approved with no blocking concerns: verified
the LICENSE text is genuine unmangled MIT boilerplate, both should-fixes
are functionally correct (empirically re-tested the gofmt-failure wrapper
against a scratch unformatted file), workflow step order matches the
plan, README addition fits existing style/placement, and scope stayed
within this milestone (no golangci-lint, no restructuring, no release
automation). Left as take-or-leave nits: the `test` job id may read
better as `ci`/`build` if branch protection is added later;
`cancel-in-progress: true` also cancels in-flight `main` runs, not just
PR runs, on rapid pushes — acceptable for a single-dev private repo.
