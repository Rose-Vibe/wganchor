# Sprint: project-standards

Raised in conversation with the user after pushing `wganchor` to its first
GitHub repo (`Corecii/wganchor`, private): the project had no CI, no
LICENSE, and had grown past a single-file script into ~6000 lines across
12 flat `package main` files with no linter beyond `go vet`. This sprint
brings the repo up to a standard, high-quality baseline in three ordered
milestones — each is its own plan, reviewed and implemented independently,
because each carries different risk and the user asked for them in this
order:

1. **`plan-ci-and-license.md`** — add a `LICENSE` (MIT, copyright Rose
   Asenbauer) and a GitHub Actions CI workflow (fmt/vet/build/test on
   push and PR). Lowest risk: no changes to the Go code itself.
2. **`plan-linting.md`** — introduce `golangci-lint` (or equivalent),
   wired into both CI and the local lint-fix loop, fix whatever it
   flags. Not yet planned in detail — do that when milestone 1 is
   committed. Medium risk: may surface real (if minor) code issues to
   fix.
3. **`plan-restructuring.md`** — split the flat `package main` into
   `cmd/wganchor/main.go` + `internal/<pkg>` packages. Not yet planned in
   detail. Highest risk: touches every file's package boundary and
   import graph; do this last, once CI and lint are already in place to
   catch regressions.

Milestones are sequential, not parallel — do not start milestone 2's plan
until milestone 1 is implemented, reviewed, and committed (and likewise
for 3 after 2), since each milestone's tooling is meant to protect the
next one.
