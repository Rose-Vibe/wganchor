# wganchor

Go tool for exposing a VPS's public IP as a locally-bindable network interface
on a home machine. Uses WireGuard with a provider-assigned secondary IP on the
VPS — no "don't deliver locally" routing tricks required. Apps on the home
machine bind to the public IP directly; traffic is tunneled through WireGuard.

## Architecture

See `docs/arch/` for design documents.
See `docs/sprints/` for the sprint plan.

## Development Workflow

Every significant unit of work follows this pipeline. Do not skip steps.

**This pipeline is autonomous.** When the user says to work through N sprints or
tasks, proceed through all of them without asking for confirmation between steps.
The plan-review and implementation-review loops are the quality gates — trust them.
Only stop and ask the user if:

- A fundamental architectural conflict or ambiguity arises that the reviewer cannot resolve
- A decision has significant irreversible consequences not covered by existing plans
- Tests reveal a systemic issue that suggests the plan itself is wrong
- Something would be unsafe or destructive

Do not pause to show progress, ask "should I continue?", or request approval
between milestones. The user will interrupt if they want to redirect.

**Checking on spawned reviewer agents:** tail the agent's transcript under
`~/.claude/projects/<project>/<session>/subagents/agent-<name>-*.jsonl` and
read the `assistant`-role `text` blocks directly. Do not poll with `SendMessage`
to ask "are you done" — only send a message when you have new information or a
new instruction to give.

### Step 1: Plan

Write or update a plan document in `docs/sprints/<sprint-name>/plan-<name>.md`
describing what will be built, why, and what the exit criteria are. Plans
reference the relevant section of the architecture docs.

**Do NOT use EnterPlanMode.** Write plans as documents in `docs/sprints/` directly.

### Step 2: Plan Review

Spawn a Fable-model agent to review the plan. The reviewer should:

- Check consistency with the architecture docs
- Identify missing edge cases or exit criteria
- Flag over-engineering or scope creep
- Suggest concrete improvements

Iterate on the plan until the reviewer approves with no blocking concerns. Send
follow-ups to the _same_ agent (via `SendMessage`) rather than spawning a fresh
one. Reuse is scoped to the current milestone — spawn a fresh reviewer for each
new milestone's plan.

### Step 3: Implement

Implement the plan. Write code and tests.

Before requesting review, run the lint fix loop:

```
LOOP: Lint Fix
├── Fix known lint/format issues
├── Run formatter (gofmt / cargo fmt)
├── Run type/build check → on failure, restart loop
└── Run linter (`golangci-lint run`) → on failure, restart loop
```

### Step 4: Implementation Review

Spawn an Opus-model agent to review the implementation. The reviewer should:

- Read the plan and the diff
- Check that the implementation matches the plan
- Look for correctness bugs, missing edge cases, and architectural violations
- Verify test coverage of the exit criteria
- Flag anything that should be fixed before committing

Iterate until the reviewer approves. Same agent reuse rule — fresh reviewer per
milestone, not per iteration within a milestone.

### Step 5: Test and Commit

- Update `docs/arch/` if the change affects architecture
- Run the test suite
- Ensure all tests pass
- Commit with format: `feature: concise title` for planned work, or just a concise title otherwise. Body: bulleted list of changes, short.

## Context Recovery

After every compaction or session start, read `docs/arch/` to regain
system-level context before exploring the codebase.

### When to Use Workflows

For steps that involve fan-out (reviewing multiple dimensions in parallel,
running multiple independent checks), use the Workflow tool. Workflows require
explicit opt-in — say "use a workflow" or "ultracode" when requesting.

## Conventions

- Go: standard formatting (`gofmt`), no external frameworks for simple tasks
- Builds to a single static Linux binary — keep it that way
- VPS-side and client-side config managed by the same binary (`server`/`client` subcommands)
- All network interface manipulation must be idempotent and safe to re-run
