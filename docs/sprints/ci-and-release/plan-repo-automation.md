# Plan: branch protection, auto-merge, dependabot — and proving it's live

## Why

CI already runs on every push to `main` and every PR, but nothing
enforces it — a red run doesn't block a merge, it's purely informational.
There's also no dependabot, so pinned GitHub Action versions in
`ci.yml`/`release.yml` can go stale unnoticed. `open-legacy-rpc` already
solves both with a ruleset + auto-merge-for-dependabot workflow +
`dependabot.yml`; this plan brings the same three pieces to `wganchor`, in
the order the user asked for: ruleset, then auto-merge, then dependabot —
because auto-merging a PR is pointless without a required check to gate
it on, and turning dependabot on before auto-merge exists would just mean
every dependency PR sits there needing a manual merge.

**Direct question to answer**: how do we make sure only Dependabot's PRs
get auto-merged, not anyone else's? The first draft of this plan answered
"gate the job on `if: github.actor == 'dependabot[bot]'`" and called that
*the* security boundary. Plan review (against live data read from both
`Rose-Vibe/wganchor` and the reference `Rose-Vibe/open-legacy-rpc` via
`gh api`) found that's wrong on two counts, corrected below:

1. The `if:` check is real but isn't what stops a malicious fork PR from
   auto-merging itself — this workflow triggers on `pull_request`, not
   `pull_request_target`, and GitHub forces a **read-only** `GITHUB_TOKEN`
   for `pull_request` runs triggered from a fork of a public repo,
   regardless of the workflow's own `permissions:` block. That forced
   read-only token is what actually makes `gh pr merge --auto` fail for a
   fork PR even if the `if:` line were deleted from the workflow file a
   fork PR brings with it (which it can, since `pull_request` runs the
   workflow *as checked out from the PR*). The required-status-check
   ruleset (below) is the second layer: it applies to every merge,
   regardless of actor. `dependabot/fetch-metadata`'s own default
   behavior is the third: it only populates outputs, and succeeds, when
   the PR's author *and every commit in it* are Dependabot's — otherwise
   it fails closed.
2. The `if:` check is still worth keeping — as hygiene (skip noisy
   failed/no-op runs for the common case, catch a human pushing a commit
   directly onto a Dependabot branch triggering a `synchronize` event
   under their own identity) — not as the thing doing the actual
   security work. Rewritten below with this corrected.

**Invariant that must never be violated, because it's exactly what would
reopen the hole above**: this workflow's trigger stays `pull_request`,
never `pull_request_target` (the standard "fix" for the read-only-token
annoyance, and precisely the wrong fix here — it hands a fork PR a
privileged token while still checking out that PR's own code), and
`dependabot/fetch-metadata`'s `skip-verification`/`skip-commit-verification`
inputs stay at their default (`false`).

## Scope

### 1. Branch protection, via two rulesets (not legacy branch-protection rules)

**Two separate rulesets, not one** — found necessary during plan review:
a single ruleset with both "block force-push/deletion" and "require a
passing check to merge" rules, carrying one admin bypass actor so the
maintainer's existing direct-push workflow still works, would have that
bypass apply to *all* of the ruleset's rules at once — including the
force-push/deletion protection, which defeats the point of adding it in
the first place on a now-public repo (this is exactly
`open-legacy-rpc`'s own situation: its one ruleset's admin bypass covers
everything in it). Splitting avoids that:

- **`main-history`** — `deletion`, `non_fast_forward` (blocks force
  pushes). **No bypass actors at all.** A future legitimate force-push
  requires a deliberate edit to this ruleset first, which is the point;
  it does not affect this project's existing direct-push workflow, since
  fast-forward pushes were never what these two rules restrict.
- **`main-merge-gate`** — `required_status_checks` (naming the check
  context `ci.yml` actually reports — see "Check context name" below)
  with `strict_required_status_checks_policy: false` (a Dependabot PR
  that falls behind `main` due to unrelated commits landing should not
  be forced to rebase before it can merge — Dependabot won't necessarily
  rebase a non-conflicting PR on its own, so `strict: true` risks
  auto-merge silently stalling rather than failing loudly), plus a
  `pull_request` rule (`required_approving_review_count: 0` — mirrors
  `open-legacy-rpc`'s own ruleset). **One bypass actor**: the repo's
  admin role, `bypass_mode: always` — confirmed necessary, see below.
  This is what keeps every non-admin write path (a human contributor,
  Dependabot) going through a PR with a passing check, while leaving the
  maintainer's/this project's own direct-push-to-`main` workflow working
  exactly as it does today.

**Why a "require a pull request" rule is included after all** (the first
draft of this plan omitted it, reasoning that required-status-checks
alone is a merge-time-only gate that doesn't touch direct pushes — that
reasoning doesn't survive scrutiny): there's no confirmed GitHub
documentation stating required-status-checks is merge-only in rulesets,
and the reference repo's own `main` ruleset (read live via `gh api`)
pairs `required_status_checks` with a `pull_request` rule *and* an
explicit `bypass_actors: [{actor_type: "RepositoryRole", actor_id: 5,
bypass_mode: "always"}]` entry — its own direct-to-`main` commits land
*because of* that bypass, not because required-status-checks was never
going to apply to them. Treat "a direct push to `main` with no
passing check-run on that exact commit gets rejected" as the expected
behavior, not a maybe, and build the bypass in from the start rather
than discover the hard way that a routine push is suddenly rejected.
`RepositoryRole`'s numeric `actor_id` for built-in roles is a platform
constant, not a per-repo lookup (`maintain=2`, `write=4`, `admin=5` —
same on every repo; only *custom* org roles get their own IDs, which
doesn't apply here). So "confirm rather than copy blindly" doesn't mean
hunting for a lookup endpoint — it means: POST the ruleset, then read
`bypass_actors` back via `gh api
repos/Rose-Vibe/wganchor/rulesets/<id>` and confirm it shows `actor_id:
5` as expected, then let the direct-push test (below) be the actual
proof.

**JSON bodies to POST** (`gh api -X POST
repos/Rose-Vibe/wganchor/rulesets --input <file>.json`, run twice, once
per ruleset — **not** `gh ruleset create`, which doesn't exist in the
installed `gh`, 2.92.0, which only has `gh ruleset check`/`list`/`view`):

```json
{
  "name": "main-history",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
  "bypass_actors": [],
  "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]
}
```

```json
{
  "name": "main-merge-gate",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
  "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [{"context": "<name read from check-runs, see 'Check context name' below>"}]
      }
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "allowed_merge_methods": ["merge", "squash", "rebase"]
      }
    }
  ]
}
```

**One field that would silently break auto-merge if gotten wrong**:
`pull_request.parameters.allowed_merge_methods` must include `"squash"`
(or just omit the field entirely for GitHub's default of all three) —
`auto-merge.yml` merges with `--squash`, and a ruleset that only
allowed, say, `merge`/`rebase` would make every auto-merge attempt fail
silently against the ruleset, not against the workflow.

Verify what's actually in effect afterward with `gh api
repos/Rose-Vibe/wganchor/rules/branches/main` (the effective-rules
endpoint, not just reading back the two ruleset objects themselves —
this is what actually governs a push to `main`).

**Forward-looking caveat, documentation only — nothing to fix now**: a
same-repo PR from a write collaborator runs `auto-merge.yml` with a
write-scoped token and could, in principle, edit the workflow from
their own branch. With `required_approving_review_count: 0` today and a
write collaborator already able to enable auto-merge on their own PR
regardless, this adds no actual exposure. It would matter the day a
required-review count above `0` gets added to `main-merge-gate`: at
that point, this workflow's `pull_request-write` token could be used by
a write collaborator as a self-approval vector (e.g. `gh pr review
--approve`), and this workflow would need re-reviewing before that
change ships. `Rose-Vibe/wganchor` has no collaborators beyond the
admin today, so this is a note for later, not current work.

### 2. Turn on auto-merge

- Enable the repository setting (`gh api -X PATCH repos/Rose-Vibe/wganchor
  -f allow_auto_merge=true`, or `gh repo edit --enable-auto-merge`) — this
  is what makes `gh pr merge --auto` (and the "Enable auto-merge" button)
  available at all; confirmed currently `false` on `Rose-Vibe/wganchor`,
  as expected pre-milestone. Also confirm `allow_squash_merge` is `true`
  (confirmed already, live) — the workflow below merges with `--squash`,
  so this has to stay enabled.
- Add `.github/workflows/auto-merge.yml`, modeled on `open-legacy-rpc`'s
  version but with the gating corrected per "Why" above:
  - Trigger: `pull_request`, types `[opened, synchronize, reopened]`.
    **Never `pull_request_target`** (see the invariant above).
  - `permissions: contents: write, pull-requests: write`. (Confirmed this
    works for Dependabot-triggered runs specifically — GitHub honors a
    workflow's own `permissions:` key for `pull_request` events
    Dependabot itself triggers, unlike the forced-read-only case for a
    fork PR; the reference repo's PR #2 demonstrably auto-merged this
    way.)
  - Job-level `if: github.actor == 'dependabot[bot]' &&
    github.event.pull_request.user.login == 'dependabot[bot]'` —
    checking both the triggering actor and the PR's actual author is
    strictly stronger than either alone, for free. This is hygiene (see
    "Why"), not the security boundary.
  - `dependabot/fetch-metadata@v2` (`skip-verification`/
    `skip-commit-verification` left at their defaults — see invariant) to
    read the update's semver type; fails closed (non-zero exit, no
    outputs) for anything that isn't a pure-Dependabot PR.
  - Auto-merge (`gh pr merge --auto --squash`) only for
    `version-update:semver-patch` or `version-update:semver-minor`; a
    major-version bump is deliberately left for manual review. Note:
    re-running this on a later `synchronize` event when auto-merge is
    already enabled on the PR may make `gh pr merge --auto` exit
    non-zero (already-enabled isn't an error GitHub treats as fatal, but
    the CLI may); treat that specific case as non-blocking noise, not a
    real failure, when reading workflow run results.

**Known behavior, not a bug**: a PR merged via auto-merge (using
`GITHUB_TOKEN`) does not trigger `ci.yml`'s `push`-triggered run on
`main` — confirmed against the reference repo's own merged PR #2, whose
resulting merge commit has zero workflow runs against it. The PR's own
check run (the thing `required_status_checks` actually gated on) is the
only verification that ever happens for that commit. This is a GitHub
platform behavior (automated pushes via the default token don't
re-trigger `push`-event workflows), not something this plan's config
controls or should try to work around.

### 3. Turn on dependabot

`.github/dependabot.yml`:

- `package-ecosystem: github-actions`, `directory: /`, weekly, labeled
  `dependencies`.
- `package-ecosystem: gomod`, `directory: /`, weekly, labeled
  `dependencies`. `go.mod` has zero third-party dependencies today by
  design, so this produces no PRs right now — a no-op added so it's not
  a forgotten step later, not scope creep (zero ongoing cost).

**Decision (made by the user when this tradeoff was surfaced): re-pin to
commit SHA.** Today's Action pins (`checkout@v5`, `setup-go@v6`,
`golangci-lint-action@v9`, and `goreleaser-action` once
`plan-release-builds.md` lands) are *floating major-version tags*.
Dependabot's `github-actions` ecosystem only opens a PR when the pinned
tag itself needs to move — a floating major tag absorbs patch/minor
upstream changes silently, with no PR, and Dependabot only PRs a *major*
bump, which this workflow's auto-merge step deliberately excludes. Left
as-is, the auto-merge path this milestone builds would be correct but
almost never actually exercised.

**Scope addition**: re-pin every third-party Action reference —
`ci.yml`'s/`_checks.yml`'s `actions/checkout`, `actions/setup-go`,
`golangci/golangci-lint-action`; `release.yml`'s
`goreleaser/goreleaser-action`; `auto-merge.yml`'s
`dependabot/fetch-metadata` — to the full commit SHA currently resolved
by each version tag, with a trailing `# vX.Y.Z` comment for
readability (the same form Dependabot itself writes and maintains for
SHA-pinned Actions, so future bumps look like an ordinary version-comment
update, not a mystery hash change). This is the standard supply-chain
hardening for a public repo's CI (a floating tag is a mutable reference
an upstream account compromise could repoint; a SHA is not), and it's
what makes Dependabot actually open patch/minor PRs that flow through
auto-merge — which is also the only way to get a same-day *positive*
live-verification of the auto-merge path (see Exit criteria) rather than
waiting for a real bump to eventually happen.

**Resolution recipe — must peel annotated tags, not just read the ref.**
A tag can be lightweight (the ref points straight at a commit) or
annotated (the ref points at a tag *object*, which itself points at a
commit) — `uses: owner/repo@<sha>` requires the commit SHA; passing an
annotated tag's object SHA fails at workflow-run time with "unable to
find version". Confirmed live: `golangci/golangci-lint-action@v9` is
annotated (its ref resolves to tag-object `db9de0f...`, not the commit;
the real commit is `ba0d7d2...`). The naive `git ls-remote
refs/tags/<version>` / `gh api repos/<o>/<r>/git/refs/tags/<version>`
recipe this plan originally specified returns exactly the wrong SHA for
an annotated tag, so always peel regardless of which kind a given tag
turns out to be:

```
ref=$(gh api repos/$OWNER/$REPO/git/ref/tags/$TAG --jq .object.sha)
typ=$(gh api repos/$OWNER/$REPO/git/ref/tags/$TAG --jq .object.type)
[ "$typ" = tag ] && ref=$(gh api repos/$OWNER/$REPO/git/tags/$ref --jq .object.sha)
gh api repos/$OWNER/$REPO/commits/$ref --jq .sha   # must succeed and print a 40-hex commit SHA — that's the one `uses:` gets
```

(`git ls-remote`'s equivalent is reading the `^{}`-suffixed peeled line
for the tag, never the plain one.) Use the full 40-character SHA in
`uses:`, never an abbreviation. The trailing `# vX.Y.Z` comment must be
the full semver tag the floating major currently resolves to (e.g.
`# v9.1.4`, not `# v9`) — list candidate tags with `gh api
repos/$OWNER/$REPO/git/matching-refs/tags/$MAJOR.`, pick the highest,
and resolve *that* (peeled, as above) for the actual pin. Comment and
pin must agree exactly — that's the form Dependabot expects when it
rewrites both together on a future bump.

**Expect the first Dependabot run to open mostly major-bump PRs, not
patch/minor ones** — checked live, every one of these five Actions is
currently a major version behind upstream (e.g. `checkout` v5→v7,
`setup-go` v6→v7, `goreleaser-action` v6→v7, `fetch-metadata` v2→v3).
Auto-merge correctly leaves all of those for manual review, so don't
read an unmerged first batch as auto-merge failing — it's working as
designed. This also means the same-day positive-path test (see Exit
criteria) is nearly free without any artificial downgrade: check what
`golangci-lint-action`'s `v9` currently resolves to before pinning it;
if it's already behind the latest `v9.x.y` patch, the very first
Dependabot run should produce a real patch/minor PR that auto-merges on
its own.

**Optional, one-time complement — not required**: `gh api
repos/Rose-Vibe/wganchor/actions/permissions` currently shows
`sha_pinning_required: false`. Flipping it (`gh api -X PUT
repos/Rose-Vibe/wganchor/actions/permissions -F enabled=true -f
allowed_actions=all -F sha_pinning_required=true`) turns a future
floating-tag regression into a workflow-parse failure instead of
something only a code review would catch — a natural complement to the
user's re-pinning decision. Local `uses: ./.github/workflows/_checks.yml`
references are unaffected by this policy. Include it or leave it for
later, at the implementer's discretion.

### 4. Live verification on GitHub (not done until this passes)

- **Ruleset effect, read from the effective-rules endpoint**, not just
  the ruleset objects: `gh api repos/Rose-Vibe/wganchor/rules/branches/main`
  shows both rulesets' rules in effect.
- **An actual direct push to `main`, made after both rulesets exist**
  (not a hypothetical "it'll probably still work") — confirms the admin
  bypass actually covers this project's existing direct-push workflow. No
  separate throwaway push is needed for this: section order already
  puts both rulesets live before `auto-merge.yml`/`dependabot.yml` get
  committed, so *that* commit's push is the test — watch it for
  `GH013: Repository rule violations...` rather than treating it as a
  routine push. If it's rejected, the fix is to correct the bypass-actor
  configuration on `main-merge-gate` — **never** to loosen or remove
  `main-history`'s rules to work around it; the two
  rulesets are deliberately independent for exactly this reason.
- `allow_auto_merge: true` and `allow_squash_merge: true` both confirmed
  via `gh api repos/Rose-Vibe/wganchor`.
- `grep -r pull_request_target .github/` returns nothing — a cheap,
  permanent mechanical check that the invariant above hasn't been
  violated, worth re-running any time `auto-merge.yml` is touched again.
- **Negative path**: open a real, harmless PR that is **not** from
  Dependabot (e.g. any small follow-up change still pending in this
  sprint), confirm the auto-merge workflow run shows the job skipped (the
  `if:` evaluated false). This tests the hygiene `if:` only — it cannot
  exercise the fork-PR case (there's no second account to open a fork PR
  from), so the actual protection against a malicious fork relies on the
  documented `pull_request`-forces-read-only-token behavior above, not on
  an empirical test this plan can run. State that limitation plainly
  rather than imply the negative-PR test proves more than it does. After
  this test, either merge the throwaway PR normally through the PR UI
  (which also exercises `main-merge-gate`'s required check end-to-end) or
  close it — don't leave it open indefinitely.
- **Positive path**: a real Dependabot PR auto-merging. Since the SHA
  re-pin above is already part of this milestone's scope (not a maybe),
  this is expected to be verifiable same-day: after re-pinning and
  pushing `dependabot.yml`, trigger a manual "Check for updates" click
  in the GitHub web UI (no `gh` CLI equivalent exists for forcing this),
  and watch a real patch/minor PR actually get auto-merged. One
  exception the SHA re-pin doesn't cover: `golangci-lint-action`'s
  `version: v2.13.2` *input* (a plain workflow string, not an Action
  reference) isn't tracked by any Dependabot ecosystem configured here
  — worth knowing so "what Dependabot covers" has no surprise gaps; bump
  it by hand if it ever needs to move.
- **Check context name**: read the real, post-refactor name from the
  API rather than assume `checks / test` — `gh api
  repos/Rose-Vibe/wganchor/commits/<sha>/check-runs --jq
  '.check_runs[].name'` against a commit that actually ran the reusable
  workflow. Use that exact string in `main-merge-gate`.

**Optional hardening, not required**: scope the required check to only
be satisfiable by GitHub Actions itself (pin the check's
`integration_id`), so a status posted by some other integration with a
matching name string can't substitute. Low priority; note it here rather
than build it, since nothing currently posts a same-named check from
anywhere else.

## Exit criteria

- `main-history` and `main-merge-gate` both active on `main`, confirmed
  via the effective-rules endpoint, not just the ruleset objects.
- An actual direct push to `main`, made after both rulesets exist,
  succeeds.
- `allow_auto_merge` and `allow_squash_merge` both `true` on the repo.
- `auto-merge.yml` live; `grep -r pull_request_target .github/` empty;
  confirmed to skip the merge step for a non-Dependabot same-repo PR (one
  PR proves the hygiene `if:` works for that case, not "any actor" in
  general) — with the fork-PR case's protection documented as resting on
  GitHub's forced read-only token for `pull_request` runs from forks,
  not on an empirical test.
- `dependabot.yml` live for `github-actions` and `gomod`; every
  third-party Action reference re-pinned to a commit SHA with a trailing
  version comment, per the user's decision above.
- The required check's context name was read from a real check-run via
  the API, not assumed.
- All of the above confirmed via `gh api`/real pushes/real PRs, not just
  "the files are committed" — per the user's explicit ask that this
  isn't done until it's working on GitHub.
