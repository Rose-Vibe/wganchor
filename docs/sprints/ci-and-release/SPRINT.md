# Sprint: ci-and-release

Raised in conversation with the user after reviewing `Rose-Vibe/open-legacy-rpc`'s
CI setup as a reference for what a mature repo's GitHub automation looks
like (reusable checks workflow, tag-triggered release/publish job,
dependabot with auto-merge for low-risk updates). `wganchor` has none of
this yet: CI exists (`.github/workflows/ci.yml`) but there's no branch
protection enforcing it, no dependabot, no release artifacts, and
`go.mod`'s module path (`wganchor`, not `github.com/Rose-Vibe/wganchor`)
means `go install .../cmd/wganchor@latest` doesn't resolve.

Three ordered milestones:

1. **`plan-module-path.md`** — fix `go.mod`'s module path so the Go module
   proxy can resolve this module by its real location. Lowest risk: a
   mechanical import-path rename, no behavior change, but touches every
   file that imports an `internal/` package (15 files).
2. **`plan-release-builds.md`** — add a GoReleaser-based workflow,
   triggered on `v*.*.*` tags, that cross-builds static `linux/amd64` +
   `linux/arm64` binaries and attaches them (plus checksums) to a GitHub
   Release. Requires splitting `ci.yml`'s checks into a reusable workflow
   first, so the release job can run the same checks before building —
   same pattern `open-legacy-rpc` uses for its own `publish.yml`.
3. **`plan-repo-automation.md`** — the GitHub-config half: a ruleset
   requiring CI to pass before a PR merges into `main`, the repo's
   native auto-merge setting turned on, a workflow that auto-merges only
   Dependabot's patch/minor PRs (gated on `github.actor ==
   'dependabot[bot]'`, never on a label or title — that gate is what
   keeps a PR from anyone else from being auto-merged), and
   `dependabot.yml` itself (`github-actions` ecosystem; `gomod` too, as a
   currently-no-op future-proofing — `go.mod` has zero third-party
   dependencies today by design, so there's nothing for a Go-ecosystem
   dependabot to actually update yet). Ends with live verification on
   GitHub that each piece is actually in effect, per the user's explicit
   ask — this is not done until it's confirmed working on GitHub, not
   just committed.

Milestones 1 and 2 touch code/CI config and go through the normal
plan-review/implementation-review pipeline. Milestone 3 is primarily
live `gh` CLI operations against the GitHub repo itself (rulesets, repo
settings, dependabot config) in the specific order the user asked for —
ruleset, then auto-merge, then dependabot — because auto-merging a PR is
only meaningful once a required check exists to gate it on, and turning
on dependabot last means the first PRs it opens land into an
already-working auto-merge pipeline rather than a half-built one.
